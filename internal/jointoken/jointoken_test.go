package jointoken

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

var testPub = [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

func testFP() string {
	sum := sha256.Sum256(testPub[:])
	return hex.EncodeToString(sum[:])
}

func TestFingerprintIsSHA256OfRawKey(t *testing.T) {
	if got := Fingerprint(&testPub); got != testFP() {
		t.Fatalf("Fingerprint = %s, want %s", got, testFP())
	}
	got, err := FingerprintB64(base64.StdEncoding.EncodeToString(testPub[:]))
	if err != nil || got != testFP() {
		t.Fatalf("FingerprintB64 = %s, %v; want %s", got, err, testFP())
	}
	for _, bad := range []string{"", "not base64!", base64.StdEncoding.EncodeToString(testPub[:31])} {
		if _, err := FingerprintB64(bad); err == nil {
			t.Errorf("FingerprintB64(%q) accepted", bad)
		}
	}
}

func TestFormatAndParseRoundTrip(t *testing.T) {
	tok, err := Format("ek_abc", "c2VjcmV0LXNlY3JldA", testFP())
	if err != nil {
		t.Fatal(err)
	}
	if want := "ek_abc.c2VjcmV0LXNlY3JldA." + testFP(); tok != want {
		t.Fatalf("Format = %q, want %q", tok, want)
	}
	p, err := Parse(tok)
	if err != nil {
		t.Fatal(err)
	}
	if p.KeyID != "ek_abc" || p.Secret != "c2VjcmV0LXNlY3JldA" || p.Fingerprint != testFP() {
		t.Fatalf("Parse = %+v", p)
	}
	if p.String() != tok || p.Credential() != "ek_abc.c2VjcmV0LXNlY3JldA" {
		t.Fatalf("String/Credential = %q/%q", p.String(), p.Credential())
	}
}

// A token minted before fingerprints existed still parses exactly as
// before: everything after the first '.' is the secret.
func TestParseLegacyToken(t *testing.T) {
	for in, want := range map[string]Token{
		"ek_abc.secret":         {KeyID: "ek_abc", Secret: "secret"},
		"ek_abc.sec.ret":        {KeyID: "ek_abc", Secret: "sec.ret"},
		"ek_abc.secret." + "ab": {KeyID: "ek_abc", Secret: "secret.ab"},
		// Upper-case hex is not a fingerprint: part of the secret.
		"ek_abc.secret." + strings.ToUpper(testFP()): {KeyID: "ek_abc", Secret: "secret." + strings.ToUpper(testFP())},
	} {
		got, err := Parse(in)
		if err != nil || got != want {
			t.Errorf("Parse(%q) = %+v, %v; want %+v", in, got, err, want)
		}
		if got.String() != in {
			t.Errorf("Parse(%q).String() = %q", in, got.String())
		}
	}
}

func TestParseRefusesMalformed(t *testing.T) {
	for _, in := range []string{"", "ek_abc", ".secret", "ek_abc.", "ek_abc.." + testFP(), "ek abc.secret", "ek_abc.secret\n"} {
		if _, err := Parse(in); !errors.Is(err, ErrMalformed) {
			t.Errorf("Parse(%q) = %v, want ErrMalformed", in, err)
		}
	}
	// A key ID followed directly by a fingerprint has no secret.
	if p, err := Parse("ek_abc." + testFP()); err != nil || p.Fingerprint != "" || p.Secret != testFP() {
		t.Errorf("Parse(key.fingerprint) = %+v, %v; want the fingerprint read as a legacy secret", p, err)
	}
}

func TestFormatRefusesBadParts(t *testing.T) {
	for _, c := range []struct{ id, secret, fp string }{
		{"", "s", testFP()}, {"k", "", testFP()}, {"k.x", "s", testFP()}, {"k", "s.x", testFP()},
		{"k", "s", ""}, {"k", "s", testFP()[:63]}, {"k", "s", strings.ToUpper(testFP())},
	} {
		if _, err := Format(c.id, c.secret, c.fp); err == nil {
			t.Errorf("Format(%q, %q, %q) accepted", c.id, c.secret, c.fp)
		}
	}
}
