package harness

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestJWTHelpers(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	tok, err := ForgeEdDSA(map[string]any{"sub": "u", "exp": exp, "tenant_id": "t_a"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := DecodeClaims(tok)
	if err != nil || ClaimString(c, "tenant_id") != "t_a" || ClaimString(c, "missing") != "" {
		t.Errorf("claims %v %v", c, err)
	}
	if got, err := ExpiresAt(tok); err != nil || got.Unix() != exp {
		t.Errorf("exp %v %v", got, err)
	}
	hdr, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
	if !strings.Contains(string(hdr), `"alg":"EdDSA"`) {
		t.Errorf("header %s", hdr)
	}

	bad := TamperSignature(tok)
	p, q := strings.Split(tok, "."), strings.Split(bad, ".")
	if p[0] != q[0] || p[1] != q[1] || p[2] == q[2] || len(q) != 3 {
		t.Errorf("TamperSignature changed more than the signature")
	}
	if TamperSignature("abc") != "abcx" {
		t.Error("a non-JWT is still altered")
	}

	for _, s := range []string{"a.b", "a.!!!.c", "a." + base64.RawURLEncoding.EncodeToString([]byte("[1]")) + ".c"} {
		if _, err := DecodeClaims(s); err == nil {
			t.Errorf("%q should not decode", s)
		}
	}
	if _, err := ExpiresAt("a." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x"}`)) + ".c"); err == nil {
		t.Error("no exp should fail")
	}
	// Padded segments, as some tools print them, still decode.
	if _, err := DecodeSegment(base64.URLEncoding.EncodeToString([]byte(`{"a":1}`))); err != nil {
		t.Errorf("padded segment: %v", err)
	}
}

func TestScenarioWhere(t *testing.T) {
	sc := Begin(t, "C1")
	if sc.Where() != "[C1]" {
		t.Errorf("%q", sc.Where())
	}
	sc.Step("post %s", "the batch")
	sp := sc.ForSprout(t, Sprout{VM: "t2-win", Tenant: 2, OS: OSWindows})
	if got := sp.Where(); got != "[C1 os=windows tenant=2 vm=t2-win step=post the batch]" {
		t.Errorf("%q", got)
	}
	tn := sc.ForTenant(t, 1)
	tn.Step("x")
	if got := tn.Where(); got != "[C1 tenant=1 step=x]" || sc.Step0() != "post the batch" {
		t.Errorf("%q, parent step %q", got, sc.Step0())
	}
	t.Run("skipped", func(t *testing.T) {
		Begin(t, "X5").Skipf("because %s", "reasons")
	})
	if n := Nonce(12); len(n) != 12 || n[0] < 'a' || n[0] > 'z' || strings.ToLower(n) != n {
		t.Errorf("Nonce %q", n)
	}
}
