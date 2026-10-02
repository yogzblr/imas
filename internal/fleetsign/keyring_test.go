package fleetsign

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"filippo.io/edwards25519"
)

func keyringJSON(t *testing.T, keys ...PublicKey) []byte {
	t.Helper()
	obj := make(map[string]string, len(keys))
	for _, k := range keys {
		obj[strconv.Itoa(k.Version)] = base64.StdEncoding.EncodeToString(k.Key)
	}
	b, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeKeyring(t *testing.T, data []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fleet-signing-keys.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadKeyring_RoundTrip(t *testing.T) {
	pub1, priv1 := newTestKey(t, 1)
	pub2, priv2 := newTestKey(t, 2)
	path := writeKeyring(t, keyringJSON(t, pub1, pub2), 0o644)
	ring, err := LoadKeyring(path)
	if err != nil {
		t.Fatalf("LoadKeyring: %v", err)
	}
	if ids := ring.KeyIDs(); len(ids) != 2 || ids[0] != 1 || ids[1] != 2 {
		t.Fatalf("KeyIDs = %v", ids)
	}
	for v, priv := range map[int]ed25519.PrivateKey{1: priv1, 2: priv2} {
		if err := ring.Verify(signForTest(t, priv, v, testManifest())); err != nil {
			t.Errorf("v%d: %v", v, err)
		}
	}
}

func TestParseKeyring_Strict(t *testing.T) {
	pub, _ := newTestKey(t, 1)
	b64 := base64.StdEncoding.EncodeToString(pub.Key)
	cases := map[string]string{
		"empty file":         ``,
		"empty ring":         `{}`,
		"not an object":      `["` + b64 + `"]`,
		"null":               `null`,
		"duplicate id":       `{"1":"` + b64 + `","1":"` + b64 + `"}`,
		"number value":       `{"1":12}`,
		"object value":       `{"1":{"x":"` + b64 + `"}}`,
		"trailing data":      `{"1":"` + b64 + `"} {}`,
		"trailing garbage":   `{"1":"` + b64 + `"}x`,
		"id zero":            `{"0":"` + b64 + `"}`,
		"id negative":        `{"-1":"` + b64 + `"}`,
		"id leading zero":    `{"01":"` + b64 + `"}`,
		"id with v":          `{"v1":"` + b64 + `"}`,
		"id with plus":       `{"+1":"` + b64 + `"}`,
		"id not a number":    `{"gw-2026":"` + b64 + `"}`,
		"key not base64":     `{"1":"not base64!"}`,
		"key unpadded":       `{"1":"` + strings.TrimRight(b64, "=") + `"}`,
		"key url-safe":       `{"1":"` + base64.URLEncoding.EncodeToString(pub.Key) + `"}`,
		"key short":          `{"1":"` + base64.StdEncoding.EncodeToString(pub.Key[:31]) + `"}`,
		"key long":           `{"1":"` + base64.StdEncoding.EncodeToString(append(pub.Key, 0)) + `"}`,
		"all-zero key":       `{"1":"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `"}`,
		"JWKS is not a ring": `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + base64.RawURLEncoding.EncodeToString(pub.Key) + `","kid":"1"}]}`,
	}
	for name, in := range cases {
		if _, err := ParseKeyring([]byte(in)); err == nil {
			t.Errorf("%s: ParseKeyring(%s) accepted", name, in)
		}
	}
	many := make([]string, 0, maxKeyringKeys+1)
	for i := 1; i <= maxKeyringKeys+1; i++ {
		k, _ := newTestKey(t, i)
		many = append(many, `"`+strconv.Itoa(i)+`":"`+base64.StdEncoding.EncodeToString(k.Key)+`"`)
	}
	if _, err := ParseKeyring([]byte("{" + strings.Join(many, ",") + "}")); err == nil {
		t.Errorf("ring of %d keys accepted", len(many))
	}
	if _, err := ParseKeyring(bytes.Repeat([]byte(" "), maxKeyringFile+1)); err == nil {
		t.Error("oversized keyring accepted")
	}
	// Whitespace around the object is fine.
	if _, err := ParseKeyring([]byte("\n  {\"1\": \"" + b64 + "\"}\n")); err != nil {
		t.Errorf("formatted keyring refused: %v", err)
	}
}

func TestLoadKeyring_FileChecks(t *testing.T) {
	pub, _ := newTestKey(t, 1)
	good := keyringJSON(t, pub)
	if _, err := LoadKeyring(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("missing file accepted")
	}
	if _, err := LoadKeyring(t.TempDir()); err == nil {
		t.Error("directory accepted")
	}
	if runtime.GOOS == "windows" {
		return
	}
	for _, mode := range []os.FileMode{0o664, 0o646, 0o666, 0o622} {
		if _, err := LoadKeyring(writeKeyring(t, good, mode)); err == nil {
			t.Errorf("mode %v accepted", mode)
		}
	}
	for _, mode := range []os.FileMode{0o644, 0o640, 0o600, 0o444} {
		if _, err := LoadKeyring(writeKeyring(t, good, mode)); err != nil {
			t.Errorf("mode %v refused: %v", mode, err)
		}
	}
}

// With a small-order public key, crypto/ed25519.Verify accepts forged
// signatures. Prove it for the all-zero key (the placeholder most likely
// to be shipped by mistake), then that every small-order and
// non-canonical encoding is refused.
func TestCheckPublicKey_RefusesWeakKeys(t *testing.T) {
	zero := make(ed25519.PublicKey, 32)
	forged := false
	// Signature R = 00..00 (an order-4 point), S = 0: Verify computes
	// R' = -[k]A, which is R for about one message in four.
	for i := 0; i < 64 && !forged; i++ {
		m := testManifest()
		m.FileName = "imas-sprout_" + strings.Repeat("x", i) + ".deb"
		msg, _ := m.Message()
		forged = ed25519.Verify(zero, msg, make([]byte, 64))
	}
	if !forged {
		t.Fatal("expected crypto/ed25519 to accept a forgery under the all-zero key; the premise of checkPublicKey changed")
	}
	if _, err := NewKeySet([]PublicKey{{Version: 1, Key: zero}}); err == nil {
		t.Fatal("NewKeySet accepted the all-zero key")
	}

	for _, y := range smallOrderY {
		for _, sign := range []byte{0, 0x80} {
			k := append(ed25519.PublicKey(nil), y[:]...)
			k[31] |= sign
			if err := checkPublicKey(k); !errors.Is(err, errWeakKey) {
				t.Errorf("small-order key %x accepted", k)
			}
		}
	}
	for _, nc := range []string{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p + 1
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // y = 2^255 - 1
	} {
		k, _ := hex.DecodeString(nc)
		if err := checkPublicKey(k); !errors.Is(err, errWeakKey) {
			t.Errorf("non-canonical key %s accepted", nc)
		}
	}
	for i := 0; i < 32; i++ {
		pub, _ := newTestKey(t, 1)
		if err := checkPublicKey(pub.Key); err != nil {
			t.Fatalf("real key %x refused: %v", pub.Key, err)
		}
	}
}

// smallOrderY is a hard-coded list; rederive it from the curve so a typo
// can't open a hole. The torsion subgroup is generated by the torsion
// component of any point P: P - [8^-1 mod l]([8]P).
func TestSmallOrderY_MatchesCurve(t *testing.T) {
	var eb [64]byte
	eb[0] = 8
	eight, _ := new(edwards25519.Scalar).SetUniformBytes(eb[:])
	inv := new(edwards25519.Scalar).Invert(eight)
	id := edwards25519.NewIdentityPoint()

	var gen *edwards25519.Point
	for i := 2; i < 1000 && gen == nil; i++ {
		var b [32]byte
		b[0] = byte(i)
		p, err := new(edwards25519.Point).SetBytes(b[:])
		if err != nil {
			continue
		}
		prime := new(edwards25519.Point).ScalarMult(inv, new(edwards25519.Point).MultByCofactor(p))
		tor := new(edwards25519.Point).Subtract(p, prime)
		t4 := new(edwards25519.Point).Add(tor, tor)
		t4.Add(t4, t4)
		if t4.Equal(id) == 0 { // order 8
			gen = tor
		}
	}
	if gen == nil {
		t.Fatal("no order-8 point found")
	}
	want := map[[32]byte]bool{}
	cur := edwards25519.NewIdentityPoint()
	for k := 0; k < 8; k++ {
		var y [32]byte
		copy(y[:], cur.Bytes())
		y[31] &= 0x7f
		want[y] = true
		cur = new(edwards25519.Point).Add(cur, gen)
	}
	if cur.Equal(id) != 1 {
		t.Fatal("generator is not of order 8")
	}
	got := map[[32]byte]bool{}
	for _, y := range smallOrderY {
		got[y] = true
	}
	if len(got) != len(want) {
		t.Fatalf("smallOrderY has %d distinct y, curve has %d", len(got), len(want))
	}
	for y := range want {
		if !got[y] {
			t.Errorf("small-order y %x missing from smallOrderY", y)
		}
	}
}

func TestParseManifest_Strict(t *testing.T) {
	_, priv := newTestKey(t, 1)
	signed := signForTest(t, priv, 1, testManifest())
	good, _ := json.Marshal(signed)
	if _, err := ParseManifest(good); err != nil {
		t.Fatalf("ParseManifest(%s): %v", good, err)
	}
	withField := func(extra string) string {
		return strings.TrimSuffix(string(good), "}") + "," + extra + "}"
	}
	without := func(field string) string {
		var obj map[string]any
		_ = json.Unmarshal(good, &obj)
		delete(obj, field)
		b, _ := json.Marshal(obj)
		return string(b)
	}
	cases := map[string]string{
		"not JSON":              `version=v2.4.1`,
		"array":                 `[` + string(good) + `]`,
		"duplicate field":       withField(`"version":"v9.9.9"`),
		"case-folded duplicate": withField(`"VERSION":"v9.9.9"`),
		"unknown field":         withField(`"allow_downgrade":"true"`),
		"url field":             withField(`"artifact_url":"https://evil.example.com/x"`),
		"number value":          strings.Replace(string(good), `"os":"linux"`, `"os":1`, 1),
		"null value":            strings.Replace(string(good), `"os":"linux"`, `"os":null`, 1),
		"missing signature":     without("signature"),
		"missing min version":   without("min_sprout_version"),
		"trailing data":         string(good) + `{}`,
		"invalid field":         strings.Replace(string(good), `"os":"linux"`, `"os":"Linux"`, 1),
		"oversized":             string(good) + strings.Repeat(" ", maxManifestJSON),
	}
	for name, in := range cases {
		if _, err := ParseManifest([]byte(in)); !errors.Is(err, ErrInvalidManifest) {
			t.Errorf("%s: ParseManifest(%.80s...) = %v, want ErrInvalidManifest", name, in, err)
		}
	}
	// An empty signature parses (it is a well-formed manifest) but never
	// verifies.
	unsigned := strings.Replace(string(good), signed.Signature, "", 1)
	m, err := ParseManifest([]byte(unsigned))
	if err != nil {
		t.Fatalf("ParseManifest(unsigned): %v", err)
	}
	ring, _ := NewKeyring([]PublicKey{{Version: 1, Key: priv.Public().(ed25519.PublicKey)}})
	if err := ring.Verify(m); !errors.Is(err, ErrMissingSignature) {
		t.Fatalf("Verify(unsigned) = %v, want ErrMissingSignature", err)
	}
}
