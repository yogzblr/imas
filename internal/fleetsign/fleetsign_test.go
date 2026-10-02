package fleetsign

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const testChecksum = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

func testManifest() Manifest {
	return Manifest{
		Version:          "v2.4.1",
		OS:               "linux",
		Arch:             "amd64",
		FileName:         "imas-sprout_2.4.1_amd64.deb",
		ChecksumSHA256:   testChecksum,
		MinSproutVersion: "v2.0.0",
	}
}

// signForTest plays cmd/fleetreleaser's role with a local key, so the
// verify path is tested against a real Ed25519 signature over the real
// canonical message. It returns m with Signature set.
func signForTest(t *testing.T, priv ed25519.PrivateKey, keyVersion int, m Manifest) Manifest {
	t.Helper()
	msg, err := m.Message()
	if err != nil {
		t.Fatalf("Message: %v", err)
	}
	m.Signature = EncodeSignature(keyVersion, ed25519.Sign(priv, msg))
	return m
}

func newTestKey(t *testing.T, version int) (PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return PublicKey{Version: version, Key: pub}, priv
}

// The canonical message is fixed byte for byte: fleetreleaser signs it
// and every sprout rebuilds it, so any change here is a fleet-wide
// signature break and must be deliberate.
func TestMessage_Canonical(t *testing.T) {
	msg, err := testManifest().Message()
	if err != nil {
		t.Fatalf("Message: %v", err)
	}
	want := "v2.4.1|linux|amd64|imas-sprout_2.4.1_amd64.deb|" + testChecksum + "|v2.0.0"
	if string(msg) != want {
		t.Fatalf("Message = %q, want %q", msg, want)
	}
	// The signature is never part of what is signed.
	m := testManifest()
	m.Signature = EncodeSignature(1, make([]byte, ed25519.SignatureSize))
	if again, _ := m.Message(); string(again) != want {
		t.Fatalf("Message with a signature set = %q", again)
	}
}

// No URL anywhere: not in the type, not in the message.
func TestManifest_HasNoURL(t *testing.T) {
	typ := reflect.TypeOf(Manifest{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if strings.Contains(strings.ToLower(f.Name+f.Tag.Get("json")), "url") {
			t.Errorf("Manifest field %s (%s) looks like a URL", f.Name, f.Tag.Get("json"))
		}
	}
	msg, _ := testManifest().Message()
	if strings.Contains(string(msg), "://") {
		t.Errorf("message %q carries a URL", msg)
	}
}

func TestMessage_RejectsAmbiguousOrInvalidFields(t *testing.T) {
	cases := map[string]func(*Manifest){
		"empty version":               func(m *Manifest) { m.Version = "" },
		"empty os":                    func(m *Manifest) { m.OS = "" },
		"empty arch":                  func(m *Manifest) { m.Arch = "" },
		"empty file_name":             func(m *Manifest) { m.FileName = "" },
		"empty checksum":              func(m *Manifest) { m.ChecksumSHA256 = "" },
		"empty min_sprout_version":    func(m *Manifest) { m.MinSproutVersion = "" },
		"pipe in version":             func(m *Manifest) { m.Version = "v2.4.1|x" },
		"pipe in os":                  func(m *Manifest) { m.OS = "linux|amd64" },
		"pipe in arch":                func(m *Manifest) { m.Arch = "amd64|" },
		"pipe in file_name":           func(m *Manifest) { m.FileName = "a|b.deb" },
		"pipe in checksum":            func(m *Manifest) { m.ChecksumSHA256 = testChecksum[:63] + "|" },
		"pipe in min_sprout_version":  func(m *Manifest) { m.MinSproutVersion = "v2.0.0|" },
		"newline in version":          func(m *Manifest) { m.Version = "v2.4.1\n" },
		"NUL in file_name":            func(m *Manifest) { m.FileName = "a\x00.deb" },
		"DEL in os":                   func(m *Manifest) { m.OS = "linux\x7f" },
		"C1 control in arch":          func(m *Manifest) { m.Arch = "amd\u008564" },
		"tab in min_sprout_version":   func(m *Manifest) { m.MinSproutVersion = "v2.0.0\t" },
		"version without v":           func(m *Manifest) { m.Version = "2.4.1" },
		"version shorthand":           func(m *Manifest) { m.Version = "v2.4" },
		"version with build metadata": func(m *Manifest) { m.Version = "v2.4.1+abc" },
		"version not semver":          func(m *Manifest) { m.Version = "latest" },
		"version too long":            func(m *Manifest) { m.Version = "v2.4.1-" + strings.Repeat("a", maxVersionLen) },
		"min_sprout_version invalid":  func(m *Manifest) { m.MinSproutVersion = "v2" },
		"min above version":           func(m *Manifest) { m.MinSproutVersion = "v2.4.2" },
		"uppercase os":                func(m *Manifest) { m.OS = "Linux" },
		"space in arch":               func(m *Manifest) { m.Arch = "amd 64" },
		"os too long":                 func(m *Manifest) { m.OS = strings.Repeat("l", maxOSArchLen+1) },
		"path in file_name":           func(m *Manifest) { m.FileName = "../../etc/passwd" },
		"slash in file_name":          func(m *Manifest) { m.FileName = "pool/main/imas.deb" },
		"backslash in file_name":      func(m *Manifest) { m.FileName = "..\\imas.msi" },
		"dot file_name":               func(m *Manifest) { m.FileName = ".." },
		"query in file_name":          func(m *Manifest) { m.FileName = "imas.deb?x=1" },
		"percent in file_name":        func(m *Manifest) { m.FileName = "imas%2f.deb" },
		"colon in file_name":          func(m *Manifest) { m.FileName = "c:imas.msi" },
		"file_name too long":          func(m *Manifest) { m.FileName = strings.Repeat("a", maxFileNameLen+1) },
		"uppercase checksum":          func(m *Manifest) { m.ChecksumSHA256 = strings.ToUpper(testChecksum) },
		"short checksum":              func(m *Manifest) { m.ChecksumSHA256 = testChecksum[:62] },
		"non-hex checksum":            func(m *Manifest) { m.ChecksumSHA256 = strings.Repeat("z", 64) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := testManifest()
			mutate(&m)
			if _, err := m.Message(); !errors.Is(err, ErrInvalidManifest) {
				t.Fatalf("Message error = %v, want ErrInvalidManifest", err)
			}
		})
	}
}

func TestMessage_AcceptsRealPackageNames(t *testing.T) {
	for _, m := range []Manifest{
		{Version: "v2.4.1", OS: "linux", Arch: "arm64", FileName: "imas-sprout-2.4.1-1.aarch64.rpm"},
		{Version: "v2.5.0-rc.1", OS: "linux", Arch: "amd64", FileName: "imas-sprout_2.5.0~rc.1_amd64.deb", MinSproutVersion: "v2.5.0-rc.1"},
		{Version: "v2.4.1", OS: "windows", Arch: "amd64", FileName: "imas-sprout_2.4.1_windows_amd64.msi"},
		{Version: "v3.0.0", OS: "linux", Arch: "386", FileName: "imas-sprout_3.0.0+git1_i386.deb"},
	} {
		m.ChecksumSHA256 = testChecksum
		if m.MinSproutVersion == "" {
			m.MinSproutVersion = "v2.0.0"
		}
		if err := m.Validate(); err != nil {
			t.Errorf("%+v: %v", m, err)
		}
	}
}

func TestSignatureEncoding_RoundTrip(t *testing.T) {
	sig := make([]byte, ed25519.SignatureSize)
	sig[0] = 7
	enc := EncodeSignature(3, sig)
	if !strings.HasPrefix(enc, "v3:") {
		t.Fatalf("EncodeSignature = %q, want v3: prefix", enc)
	}
	v, got, err := DecodeSignature(enc)
	if err != nil || v != 3 || string(got) != string(sig) {
		t.Fatalf("DecodeSignature = %d, %x, %v", v, got, err)
	}
}

func TestDecodeSignature_Malformed(t *testing.T) {
	good := EncodeSignature(1, make([]byte, ed25519.SignatureSize))
	for _, s := range []string{
		"garbage", "1:" + good[3:], "v:" + good[3:], "v0:" + good[3:], "v01:" + good[3:], "v-1:" + good[3:],
		"v1:not base64!", "v1:" + good[3:len(good)-8], "vault:v1:" + good[3:],
	} {
		if _, _, err := DecodeSignature(s); !errors.Is(err, ErrMalformedSignature) {
			t.Errorf("DecodeSignature(%q) = %v, want ErrMalformedSignature", s, err)
		}
	}
}

func TestVerify_RoundTrip(t *testing.T) {
	pub, priv := newTestKey(t, 1)
	ks, err := NewKeySet([]PublicKey{pub})
	if err != nil {
		t.Fatalf("NewKeySet: %v", err)
	}
	signed := signForTest(t, priv, 1, testManifest())
	if err := ks.Verify(signed); err != nil {
		t.Fatalf("KeySet.Verify: %v", err)
	}
	ring, err := NewKeyring([]PublicKey{pub})
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	if err := ring.Verify(signed); err != nil {
		t.Fatalf("Keyring.Verify: %v", err)
	}
	// And through the JSON a sprout actually receives.
	body, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseManifest(body)
	if err != nil {
		t.Fatalf("ParseManifest(%s): %v", body, err)
	}
	if parsed != signed {
		t.Fatalf("ParseManifest = %+v, want %+v", parsed, signed)
	}
	if err := ring.Verify(parsed); err != nil {
		t.Fatalf("Keyring.Verify after JSON round trip: %v", err)
	}
}

// Every signed field is bound by the signature: changing any one of them
// after signing — to another value that is itself perfectly valid — is
// refused as ErrInvalidSignature, for both the Transit key set and the
// shipped keyring.
func TestVerify_TamperOfEveryField(t *testing.T) {
	pub, priv := newTestKey(t, 1)
	ks, _ := NewKeySet([]PublicKey{pub})
	ring, _ := NewKeyring([]PublicKey{pub})
	signed := signForTest(t, priv, 1, testManifest())

	tampered := map[string]func(*Manifest){
		"version":   func(m *Manifest) { m.Version = "v2.4.2" },
		"os":        func(m *Manifest) { m.OS = "windows" },
		"arch":      func(m *Manifest) { m.Arch = "arm64" },
		"file_name": func(m *Manifest) { m.FileName = "imas-sprout_2.4.1_arm64.deb" },
		"checksum_sha256": func(m *Manifest) {
			m.ChecksumSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		},
		"min_sprout_version": func(m *Manifest) { m.MinSproutVersion = "v2.1.0" },
	}
	// The table must cover every signed field, so a field added to
	// Manifest without a tamper case fails here.
	for _, kv := range signed.fields() {
		if _, ok := tampered[kv.name]; !ok {
			t.Errorf("no tamper case for signed field %q", kv.name)
		}
	}
	for name, mutate := range tampered {
		m := signed
		mutate(&m)
		if err := m.Validate(); err != nil {
			t.Fatalf("%s: tampered manifest should still be well-formed: %v", name, err)
		}
		if err := ks.Verify(m); !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("%s: KeySet.Verify = %v, want ErrInvalidSignature", name, err)
		}
		if err := ring.Verify(m); !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("%s: Keyring.Verify = %v, want ErrInvalidSignature", name, err)
		}
	}
	// The signature itself: one bit flipped.
	m := signed
	_, raw, _ := DecodeSignature(m.Signature)
	raw[0] ^= 1
	m.Signature = EncodeSignature(1, raw)
	if err := ring.Verify(m); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("flipped signature bit: Keyring.Verify = %v, want ErrInvalidSignature", err)
	}
}

// A farmer (or anything between fleetreleaser and the sprout) lowering a
// manifest's min_sprout_version — to let a sprout below the supported
// floor take an update it can't safely take — breaks the signature.
// Raising it (to strand sprouts) does too.
func TestVerify_MinSproutVersionDowngradeRefused(t *testing.T) {
	pub, priv := newTestKey(t, 1)
	ring, _ := NewKeyring([]PublicKey{pub})
	m := testManifest()
	m.MinSproutVersion = "v2.3.0"
	signed := signForTest(t, priv, 1, m)
	if err := ring.Verify(signed); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	for _, floor := range []string{"v2.2.9", "v2.0.0", "v0.0.0", "v2.3.0-rc.1", "v2.3.1"} {
		changed := signed
		changed.MinSproutVersion = floor
		if err := ring.Verify(changed); !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("min_sprout_version %s -> %s: Verify = %v, want ErrInvalidSignature", m.MinSproutVersion, floor, err)
		}
	}
}

func TestVerify_WrongKeyRefused(t *testing.T) {
	pub, _ := newTestKey(t, 1)
	_, otherPriv := newTestKey(t, 1)
	ks, _ := NewKeySet([]PublicKey{pub})
	ring, _ := NewKeyring([]PublicKey{pub})
	signed := signForTest(t, otherPriv, 1, testManifest())
	if err := ks.Verify(signed); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("KeySet.Verify = %v, want ErrInvalidSignature", err)
	}
	if err := ring.Verify(signed); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Keyring.Verify = %v, want ErrInvalidSignature", err)
	}
}

// Key rotation: during the overlap the ring ships both key versions and
// accepts a manifest signed by either; each signature is checked only
// against the key its "v<N>:" prefix names; once a version leaves the
// ring its signatures are refused.
func TestKeyring_RotationTwoKeys(t *testing.T) {
	pub1, priv1 := newTestKey(t, 1)
	pub2, priv2 := newTestKey(t, 2)
	ring, err := NewKeyring([]PublicKey{pub2, pub1})
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	if ids := ring.KeyIDs(); len(ids) != 2 || ids[0] != 1 || ids[1] != 2 {
		t.Fatalf("KeyIDs = %v, want [1 2]", ids)
	}
	old := signForTest(t, priv1, 1, testManifest())
	next := testManifest()
	next.Version = "v2.5.0"
	next = signForTest(t, priv2, 2, next)
	for name, m := range map[string]Manifest{"signed by v1": old, "signed by v2": next} {
		if err := ring.Verify(m); err != nil {
			t.Errorf("%s: Verify = %v", name, err)
		}
	}
	// A v2 key's signature labelled as v1 (or the reverse) is refused:
	// the label picks the key, it is not a hint to try them all.
	mislabelled := testManifest()
	msg, _ := mislabelled.Message()
	mislabelled.Signature = EncodeSignature(1, ed25519.Sign(priv2, msg))
	if err := ring.Verify(mislabelled); !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("v2 signature labelled v1: Verify = %v, want ErrInvalidSignature", err)
	}
	// v1 retired from the ring.
	retired, _ := NewKeyring([]PublicKey{pub2})
	if err := retired.Verify(old); !errors.Is(err, ErrUnknownKeyVersion) {
		t.Errorf("v1 signature after retiring v1: Verify = %v, want ErrUnknownKeyVersion", err)
	}
	if err := retired.Verify(next); err != nil {
		t.Errorf("v2 signature after retiring v1: Verify = %v", err)
	}
}

// An un-migrated fleet_versions row has signature = "": that is a
// refusal, never a fallback to checksum-only trust.
func TestVerify_MissingSignatureRefused(t *testing.T) {
	pub, _ := newTestKey(t, 1)
	ks, _ := NewKeySet([]PublicKey{pub})
	ring, _ := NewKeyring([]PublicKey{pub})
	if err := ks.Verify(testManifest()); !errors.Is(err, ErrMissingSignature) {
		t.Fatalf("KeySet.Verify = %v, want ErrMissingSignature", err)
	}
	if err := ring.Verify(testManifest()); !errors.Is(err, ErrMissingSignature) {
		t.Fatalf("Keyring.Verify = %v, want ErrMissingSignature", err)
	}
}

// A validly signed manifest with an invalid field can't exist (the signer
// refuses to build its message), but a verifier must still refuse one
// rather than verify bytes it would have had to normalize.
func TestVerify_InvalidFieldRefusedBeforeSignature(t *testing.T) {
	pub, priv := newTestKey(t, 1)
	ring, _ := NewKeyring([]PublicKey{pub})
	m := signForTest(t, priv, 1, testManifest())
	m.ChecksumSHA256 = strings.ToUpper(m.ChecksumSHA256)
	if err := ring.Verify(m); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("Verify = %v, want ErrInvalidManifest", err)
	}
}

func TestVerify_UnknownKeyVersionRefused(t *testing.T) {
	pub, priv := newTestKey(t, 1)
	ks, _ := NewKeySet([]PublicKey{pub})
	if err := ks.Verify(signForTest(t, priv, 2, testManifest())); !errors.Is(err, ErrUnknownKeyVersion) {
		t.Fatalf("Verify = %v, want ErrUnknownKeyVersion", err)
	}
}

func TestVerify_EmptyKeySetRefused(t *testing.T) {
	_, priv := newTestKey(t, 1)
	signed := signForTest(t, priv, 1, testManifest())
	if err := KeySet(nil).Verify(signed); !errors.Is(err, ErrNoKeys) {
		t.Fatalf("Verify = %v, want ErrNoKeys", err)
	}
	if err := (Keyring{}).Verify(signed); !errors.Is(err, ErrNoKeys) {
		t.Fatalf("zero Keyring Verify = %v, want ErrNoKeys", err)
	}
	// A KeySet built by hand with a truncated key must fail, not panic.
	bad := KeySet{{Version: 1, Key: ed25519.PublicKey{1, 2, 3}}}
	if err := bad.Verify(signed); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify with truncated key = %v, want ErrInvalidSignature", err)
	}
}

func TestNewKeySet_Validation(t *testing.T) {
	k1, _ := newTestKey(t, 1)
	if _, err := NewKeySet(nil); !errors.Is(err, ErrNoKeys) {
		t.Errorf("empty: %v", err)
	}
	if _, err := NewKeySet([]PublicKey{k1, k1}); err == nil {
		t.Error("duplicate version accepted")
	}
	if _, err := NewKeySet([]PublicKey{{Version: 0, Key: k1.Key}}); err == nil {
		t.Error("version 0 accepted")
	}
	if _, err := NewKeySet([]PublicKey{{Version: 1, Key: k1.Key[:10]}}); err == nil {
		t.Error("short key accepted")
	}
	k2, _ := newTestKey(t, 2)
	ks, err := NewKeySet([]PublicKey{k2, k1})
	if err != nil || ks[0].Version != 1 || ks[1].Version != 2 {
		t.Errorf("NewKeySet not sorted: %+v, %v", ks, err)
	}
}

// TestNoSigningCodeInPackage keeps this package's shape honest: it is
// imported by farmer, saasapi and sprout, none of which may sign. The
// real enforcement is OpenBao policy (cmd/fleetreleaser's
// TestOpenBaoEnforcesReadOnlyFleetKey); this only catches someone copying
// gatewayjwt's sign method in here by accident.
func TestNoSigningCodeInPackage(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"/sign/", "ed25519.Sign(", "ed25519.PrivateKey", "/rotate"} {
			if strings.Contains(string(src), forbidden) {
				t.Errorf("%s contains %q: fleetsign must stay verify-only", f, forbidden)
			}
		}
	}
}
