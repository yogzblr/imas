package fleetsign

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// The tests make their own throwaway keys: no private key is checked in.

const (
	sumDeb = "1111111111111111111111111111111111111111111111111111111111111111"
	sumRPM = "2222222222222222222222222222222222222222222222222222222222222222"
	sumMSI = "3333333333333333333333333333333333333333333333333333333333333333"
)

var testChecksumsTxt = []byte(sumDeb + "  imas-sprout_2.4.1_linux_amd64.deb\n" +
	sumRPM + "  imas-sprout_2.4.1_linux_amd64.rpm\n" +
	sumMSI + "  imas-sprout-2.4.1-windows-x64.msi\n" +
	testChecksum + "  imas_2.4.1_linux_amd64.tar.gz\n")

// newEntity makes an Ed25519 (EdDSA) OpenPGP key created at created,
// expiring after lifetime (0: never).
func newEntity(t *testing.T, created time.Time, lifetime time.Duration) *openpgp.Entity {
	t.Helper()
	e, err := openpgp.NewEntity("imas release test", "", "release@example.invalid", &packet.Config{
		Algorithm:       packet.PubKeyAlgoEdDSA,
		Time:            func() time.Time { return created },
		KeyLifetimeSecs: uint32(lifetime / time.Second),
	})
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	return e
}

// armoredPublic is what gpg --armor --export writes for es.
func armoredPublic(t *testing.T, es ...*openpgp.Entity) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range es {
		if err := e.Serialize(w); err != nil {
			t.Fatalf("Serialize: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func ring(t *testing.T, es ...*openpgp.Entity) ArmoredKeyring {
	t.Helper()
	k, err := ParseArmoredKeyring(armoredPublic(t, es...))
	if err != nil {
		t.Fatalf("ParseArmoredKeyring: %v", err)
	}
	return k
}

// detachSign is gpg --detach-sign over txt by e, at the time at.
func detachSign(t *testing.T, e *openpgp.Entity, txt []byte, at time.Time) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := openpgp.DetachSign(&buf, e, bytes.NewReader(txt), &packet.Config{Time: func() time.Time { return at }}); err != nil {
		t.Fatalf("DetachSign: %v", err)
	}
	return buf.Bytes()
}

func TestVerifyChecksums(t *testing.T) {
	now := time.Now()
	signer := newEntity(t, now.Add(-time.Hour), 0)
	other := newEntity(t, now.Add(-time.Hour), 0)
	sig := detachSign(t, signer, testChecksumsTxt, now.Add(-time.Minute))

	// Expired: created two days ago, valid for an hour, signed while valid.
	expired := newEntity(t, now.Add(-48*time.Hour), time.Hour)
	expiredSig := detachSign(t, expired, testChecksumsTxt, now.Add(-47*time.Hour-30*time.Minute))

	// Revoked after it signed, for a reason other than compromise, so
	// only a revocation check made at "now" catches it.
	revoked := newEntity(t, now.Add(-time.Hour), 0)
	revokedSig := detachSign(t, revoked, testChecksumsTxt, now.Add(-30*time.Minute))
	if err := revoked.RevokeKey(packet.KeySuperseded, "rotated", &packet.Config{Time: func() time.Time { return now.Add(-10 * time.Minute) }}); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}

	var armored bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&armored, signer, bytes.NewReader(testChecksumsTxt), nil); err != nil {
		t.Fatal(err)
	}
	var textMode bytes.Buffer
	if err := openpgp.DetachSignText(&textMode, signer, bytes.NewReader(testChecksumsTxt), nil); err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(testChecksumsTxt)
	tampered[3] ^= 0x01

	cases := []struct {
		name string
		ring ArmoredKeyring
		txt  []byte
		sig  []byte
		want error // nil: verifies
		// wantMsg, if set, must appear in the error: the reason, not
		// just the class, for the cases a wrong reason would hide.
		wantMsg string
	}{
		{"valid", ring(t, signer), testChecksumsTxt, sig, nil, ""},
		{"one byte changed", ring(t, signer), tampered, sig, ErrBadSignature, ""},
		{"trailing newline added", ring(t, signer), append(bytes.Clone(testChecksumsTxt), '\n'), sig, ErrBadSignature, ""},
		{"signed by a key not in the ring", ring(t, other), testChecksumsTxt, sig, ErrBadSignature, "unknown"},
		{"empty keyring", ArmoredKeyring{}, testChecksumsTxt, sig, ErrNoKeys, ""},
		{"rotation: second key signed", ring(t, other, signer), testChecksumsTxt, sig, nil, ""},
		{"rotation: first key signed", ring(t, signer, other), testChecksumsTxt, sig, nil, ""},
		{"expired key still verifies", ring(t, expired), testChecksumsTxt, expiredSig, nil, ""},
		{"revoked key refused", ring(t, revoked), testChecksumsTxt, revokedSig, ErrBadSignature, "revoked"},
		{"truncated signature", ring(t, signer), testChecksumsTxt, sig[:len(sig)-5], ErrBadSignature, ""},
		{"armored signature", ring(t, signer), testChecksumsTxt, armored.Bytes(), nil, ""},
		{"armored, not a signature block", ring(t, signer), testChecksumsTxt, armoredPublic(t, signer), ErrBadSignature, ""},
		{"text-mode signature", ring(t, signer), testChecksumsTxt, textMode.Bytes(), ErrBadSignature, "binary document"},
		{"empty signature", ring(t, signer), testChecksumsTxt, nil, ErrBadSignature, ""},
		{"garbage signature", ring(t, signer), testChecksumsTxt, []byte("not a signature"), ErrBadSignature, ""},
		{"empty checksums.txt", ring(t, signer), nil, sig, ErrBadChecksums, ""},
		{"oversize checksums.txt", ring(t, signer), bytes.Repeat([]byte("a"), MaxChecksumsTxt+1), sig, ErrChecksumsTooLarge, ""},
		{"oversize signature", ring(t, signer), testChecksumsTxt, append(bytes.Clone(sig), make([]byte, MaxChecksumsSig)...), ErrChecksumsTooLarge, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.ring.VerifyChecksums(tc.txt, tc.sig)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("VerifyChecksums = %v, want success", err)
				}
				return
			}
			if !errors.Is(err, tc.want) || !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("VerifyChecksums = %v, want %v (%q)", err, tc.want, tc.wantMsg)
			}
		})
	}
}

func TestParseArmoredKeyring(t *testing.T) {
	now := time.Now()
	a, b := newEntity(t, now, 0), newEntity(t, now, 0)

	if k, err := ParseArmoredKeyring(armoredPublic(t, a, b)); err != nil || k.Len() != 2 {
		t.Fatalf("one block, two keys: %d keys, %v", k.Len(), err)
	}
	concat := append(append([]byte("comment before\n"), armoredPublic(t, a)...), armoredPublic(t, b)...)
	if k, err := ParseArmoredKeyring(concat); err != nil || k.Len() != 2 {
		t.Fatalf("two blocks: %d keys, %v", k.Len(), err)
	}

	var priv bytes.Buffer
	w, _ := armor.Encode(&priv, openpgp.PrivateKeyType, nil)
	if err := a.SerializePrivate(w, nil); err != nil {
		t.Fatal(err)
	}
	w.Close()
	var privAsPublic bytes.Buffer
	w, _ = armor.Encode(&privAsPublic, openpgp.PublicKeyType, nil)
	if err := a.SerializePrivate(w, nil); err != nil {
		t.Fatal(err)
	}
	w.Close()

	for name, in := range map[string][]byte{
		"empty":                         nil,
		"not armored":                   []byte("{}"),
		"private key block":             priv.Bytes(),
		"private key in a public block": privAsPublic.Bytes(),
		"oversize":                      append(armoredPublic(t, a), make([]byte, maxArmoredKeyring)...),
	} {
		if _, err := ParseArmoredKeyring(in); err == nil {
			t.Errorf("%s: ParseArmoredKeyring succeeded", name)
		}
	}
	if _, err := ParseArmoredKeyring(nil); !errors.Is(err, ErrNoKeys) {
		t.Errorf("empty keyring = %v, want ErrNoKeys", err)
	}
}

func TestLoadArmoredKeyring_FileChecks(t *testing.T) {
	data := armoredPublic(t, newEntity(t, time.Now(), 0))
	dir := t.TempDir()
	good := filepath.Join(dir, "fleet-signing-keys.asc")
	if err := os.WriteFile(good, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if k, err := LoadArmoredKeyring(good); err != nil || k.Len() != 1 {
		t.Fatalf("LoadArmoredKeyring = %d keys, %v", k.Len(), err)
	}
	if _, err := LoadArmoredKeyring(filepath.Join(dir, "missing.asc")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file = %v", err)
	}
	if _, err := LoadArmoredKeyring(dir); err == nil {
		t.Error("a directory loaded as a keyring")
	}
	if runtime.GOOS != "windows" {
		writable := filepath.Join(dir, "writable.asc")
		if err := os.WriteFile(writable, data, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(writable, 0o666); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadArmoredKeyring(writable); err == nil {
			t.Error("a world-writable keyring loaded")
		}
	}
}

// TestRepoReleaseKeyring: the repo's gpg-public-key.asc, which the
// packages ship as /etc/imas/fleet-signing-keys.asc (D21), parses and
// holds at least one usable key, so a bad key change fails here and not on
// the fleet.
func TestRepoReleaseKeyring(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "gpg-public-key.asc"))
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParseArmoredKeyring(data)
	if err != nil {
		t.Fatalf("gpg-public-key.asc: %v", err)
	}
	if k.Len() < 1 {
		t.Fatal("gpg-public-key.asc holds no key")
	}
}

func TestParseChecksums(t *testing.T) {
	c, err := ParseChecksums(testChecksumsTxt)
	if err != nil {
		t.Fatalf("ParseChecksums: %v", err)
	}
	if c.Len() != 4 {
		t.Errorf("Len = %d, want 4", c.Len())
	}
	if s, ok := c.Sum("imas-sprout-2.4.1-windows-x64.msi"); !ok || s != sumMSI {
		t.Errorf("Sum(msi) = %q, %v", s, ok)
	}
	if _, ok := c.Sum("imas-sprout_2.4.1_linux_arm64.deb"); ok {
		t.Error("Sum of an unlisted file succeeded")
	}
	if _, ok := c.Sum("imas-sprout_2.4.1_linux_amd64.de"); ok {
		t.Error("Sum matched a prefix")
	}

	trailing := append(bytes.Clone(testChecksumsTxt), "\n\n\n"...)
	if c, err := ParseChecksums(trailing); err != nil || c.Len() != 4 {
		t.Errorf("trailing blank lines: %d entries, %v", c.Len(), err)
	}

	line := func(name string) string { return sumDeb + "  " + name + "\n" }
	bad := map[string]string{
		"empty file":         "",
		"only blank lines":   "\n\n",
		"duplicate name":     line("a.deb") + sumRPM + "  a.deb\n",
		"uppercase hash":     strings.ToUpper(sumDeb[:1]) + "A" + sumDeb[2:] + "  a.deb\n",
		"one-space":          sumDeb + " a.deb\n",
		"three spaces":       sumDeb + "   a.deb\n",
		"binary marker":      sumDeb + " *a.deb\n",
		"short hash":         sumDeb[:63] + "  a.deb\n",
		"name with /":        line("dir/a.deb"),
		"name ..":            line(".."),
		"name with ../":      line("../a.deb"),
		"name with %":        line("a%2f.deb"),
		"name with space":    line("a b.deb"),
		"name with \\":       line("a\\b.deb"),
		"hidden name":        line(".a.deb"),
		"CRLF":               sumDeb + "  a.deb\r\n",
		"leading space":      " " + line("a.deb"),
		"blank-looking line": line("a.deb") + " \n",
		"too long name":      line(strings.Repeat("a", maxFileNameLen+1)),
		"good then bad":      line("a.deb") + "garbage\n",
	}
	for name, in := range bad {
		if _, err := ParseChecksums([]byte(in)); !errors.Is(err, ErrBadChecksums) {
			t.Errorf("%s: ParseChecksums = %v, want ErrBadChecksums", name, err)
		}
	}
	if _, err := ParseChecksums(bytes.Repeat([]byte("\n"), MaxChecksumsTxt+1)); !errors.Is(err, ErrChecksumsTooLarge) {
		t.Errorf("oversize: %v", err)
	}
}

func TestExpectedFileName(t *testing.T) {
	good := []struct{ version, os, arch, pkg, want string }{
		{"v2.4.1", "linux", "amd64", "deb", "imas-sprout_2.4.1_linux_amd64.deb"},
		{"v2.4.1", "linux", "arm64", "deb", "imas-sprout_2.4.1_linux_arm64.deb"},
		{"v2.4.1", "linux", "386", "deb", "imas-sprout_2.4.1_linux_386.deb"},
		{"v2.4.1", "linux", "amd64", "rpm", "imas-sprout_2.4.1_linux_amd64.rpm"},
		{"v2.4.1", "linux", "arm64", "rpm", "imas-sprout_2.4.1_linux_arm64.rpm"},
		{"v2.4.1", "windows", "amd64", "msi", "imas-sprout-2.4.1-windows-x64.msi"},
		{"v2.4.1", "windows", "386", "msi", "imas-sprout-2.4.1-windows-x86.msi"},
		{"v2.4.1", "windows", "arm64", "msi", "imas-sprout-2.4.1-windows-arm64.msi"},
		{"v0.1.0-rc.5", "linux", "amd64", "deb", "imas-sprout_0.1.0-rc.5_linux_amd64.deb"},
		{"v0.1.0-rc.5", "windows", "amd64", "msi", "imas-sprout-0.1.0-rc.5-windows-x64.msi"},
	}
	for _, tc := range good {
		got, err := ExpectedFileName(tc.version, tc.os, tc.arch, tc.pkg)
		if err != nil || got != tc.want {
			t.Errorf("ExpectedFileName(%s, %s, %s, %s) = %q, %v; want %q", tc.version, tc.os, tc.arch, tc.pkg, got, err, tc.want)
		}
	}
	bad := [][4]string{
		{"", "linux", "amd64", "deb"},
		{"2.4.1", "linux", "amd64", "deb"},
		{"v2.4", "linux", "amd64", "deb"},
		{"v2.4.1+build", "linux", "amd64", "deb"},
		{"V2.4.1", "linux", "amd64", "deb"},
		{"v2.4.1", "", "amd64", "deb"},
		{"v2.4.1", "linux", "", "deb"},
		{"v2.4.1", "linux", "amd64", ""},
		{"v2.4.1", "linux", "AMD64", "deb"},
		{"v2.4.1", "linux", "../x", "deb"},
		{"v2.4.1", "linux", "amd64", "apk"},
		{"v2.4.1", "linux", "amd64", "msi"},
		{"v2.4.1", "windows", "amd64", "deb"},
		{"v2.4.1", "darwin", "amd64", "rpm"},
	}
	for _, in := range bad {
		if got, err := ExpectedFileName(in[0], in[1], in[2], in[3]); !errors.Is(err, ErrInvalidManifest) {
			t.Errorf("ExpectedFileName(%q) = %q, %v; want ErrInvalidManifest", in, got, err)
		}
	}
}

func testWireManifest(sig []byte) Manifest {
	return Manifest{
		Version: "v2.4.1", OS: "linux", Arch: "amd64", PackageType: "deb", MinSproutVersion: "v2.0.0",
		ChecksumsTxt: string(testChecksumsTxt), ChecksumsSig: base64.StdEncoding.EncodeToString(sig),
	}
}

func TestParseManifest(t *testing.T) {
	sig := []byte{0x88, 0x01, 0x02}
	good, err := json.Marshal(testWireManifest(sig))
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]any
	if err := json.Unmarshal(good, &keys); err != nil || len(keys) != 7 {
		t.Fatalf("Manifest marshals to %d keys (%v), want the 7 of the wire contract", len(keys), err)
	}
	m, err := ParseManifest(good)
	if err != nil {
		t.Fatalf("ParseManifest(%s): %v", good, err)
	}
	if m.ChecksumsTxt != string(testChecksumsTxt) || !bytes.Equal(m.Signature(), sig) || m.PackageType != "deb" {
		t.Errorf("ParseManifest = %+v", m)
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
	replace := func(old, new string) string { return strings.Replace(string(good), old, new, 1) }
	b64sig := base64.StdEncoding.EncodeToString(sig)
	cases := map[string]string{
		"not JSON":              `version=v2.4.1`,
		"array":                 `[` + string(good) + `]`,
		"duplicate field":       withField(`"version":"v9.9.9"`),
		"case-folded duplicate": withField(`"VERSION":"v9.9.9"`),
		"file_name key":         withField(`"file_name":"imas-sprout_2.4.1_linux_amd64.deb"`),
		"checksum_sha256 key":   withField(`"checksum_sha256":"` + sumDeb + `"`),
		"signature key":         withField(`"signature":"v1:AAAA"`),
		"url key":               withField(`"artifact_url":"https://evil.example.com/x"`),
		"number value":          replace(`"os":"linux"`, `"os":1`),
		"null value":            replace(`"os":"linux"`, `"os":null`),
		"missing checksums_sig": without("checksums_sig"),
		"missing checksums_txt": without("checksums_txt"),
		"missing package_type":  without("package_type"),
		"missing min version":   without("min_sprout_version"),
		"trailing data":         string(good) + `{}`,
		"uppercase os":          replace(`"os":"linux"`, `"os":"Linux"`),
		"unknown package type":  replace(`"package_type":"deb"`, `"package_type":"apk"`),
		"non-canonical version": replace(`"version":"v2.4.1"`, `"version":"2.4.1"`),
		"min above version":     replace(`"min_sprout_version":"v2.0.0"`, `"min_sprout_version":"v3.0.0"`),
		"empty checksums_txt":   replace(`"checksums_txt":"`+jsonEscape(string(testChecksumsTxt))+`"`, `"checksums_txt":""`),
		"empty checksums_sig":   replace(`"checksums_sig":"`+b64sig+`"`, `"checksums_sig":""`),
		"unpadded base64":       replace(`"checksums_sig":"`+b64sig+`"`, `"checksums_sig":"`+base64.RawStdEncoding.EncodeToString([]byte{1, 2})+`"`),
		"url-safe base64":       replace(`"checksums_sig":"`+b64sig+`"`, `"checksums_sig":"-_8A"`),
		"oversized":             string(good) + strings.Repeat(" ", maxManifestJSON),
	}
	for name, in := range cases {
		if _, err := ParseManifest([]byte(in)); !errors.Is(err, ErrInvalidManifest) {
			t.Errorf("%s: ParseManifest(%.80s...) = %v, want ErrInvalidManifest", name, in, err)
		}
	}

	bigTxt := testWireManifest(sig)
	bigTxt.ChecksumsTxt = strings.Repeat("a", MaxChecksumsTxt+1)
	bigSig := testWireManifest(make([]byte, MaxChecksumsSig+1))
	for name, m := range map[string]Manifest{"checksums_txt": bigTxt, "checksums_sig": bigSig} {
		b, _ := json.Marshal(m)
		if _, err := ParseManifest(b); !errors.Is(err, ErrChecksumsTooLarge) {
			t.Errorf("oversize %s: ParseManifest = %v, want ErrChecksumsTooLarge", name, err)
		}
	}
}

func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}
