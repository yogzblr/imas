package sealedwiretest

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/yogzblr/imas/internal/payloadbox"
)

const testJWT = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ3ZWItMDEifQ.c2ln"

func validEnvelope(t *testing.T) []byte {
	t.Helper()
	env := payloadbox.Envelope{V: payloadbox.Version, Copies: []payloadbox.Sealed{{Nonce: make([]byte, 24), Box: make([]byte, 32)}}}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCheckSealedEnvelope(t *testing.T) {
	env := validEnvelope(t)
	if err := CheckSealedEnvelope(env); err != nil {
		t.Fatalf("valid envelope refused: %v", err)
	}
	v := strconv.Itoa(payloadbox.Version)
	extra := strings.TrimSuffix(string(env), "}") + `,"x":1}`
	bad := map[string]string{
		"extra field":   extra,
		"trailing data": string(env) + `{}`,
		"wrong version": strings.Replace(string(env), `"v":`, `"v":9`, 1),
		"no copies":     `{"v":` + v + `,"s":[]}`,
		"short nonce":   `{"v":` + v + `,"s":[{"n":"AAAA","c":"` + strings.Repeat("A", 44) + `"}]}`,
		"short box":     `{"v":` + v + `,"s":[{"n":"` + strings.Repeat("A", 32) + `","c":"AAAA"}]}`,
	}
	for name, raw := range bad {
		if err := CheckSealedEnvelope([]byte(raw)); err == nil {
			t.Errorf("%s: accepted %s", name, raw)
		}
	}
}

func TestFindJWT(t *testing.T) {
	if got, ok := FindJWT("Bearer " + testJWT + ";"); !ok || got != testJWT {
		t.Errorf("FindJWT in a longer string = %q, %v", got, ok)
	}
	for _, s := range []string{"a.b.c", "web-01.example.com", "eyJ", "eyJhYmMi.x.y", strings.Repeat("eyJ+/", 10)} {
		if _, ok := FindJWT(s); ok {
			t.Errorf("FindJWT(%q) matched", s)
		}
	}
}

func TestJWTInJSON(t *testing.T) {
	env := string(validEnvelope(t))
	if _, found, err := JWTInJSON([]byte(env)); err != nil || found {
		t.Errorf("clean envelope: found=%v err=%v", found, err)
	}
	for name, leaky := range map[string]string{
		"value":         `{"sealed":` + env + `,"jwt":"` + testJWT + `"}`,
		"key":           `{"` + testJWT + `":1}`,
		"duplicate key": `{"sealed":"` + testJWT + `","sealed":` + env + `}`,
	} {
		if got, found, err := JWTInJSON([]byte(leaky)); err != nil || !found || got != testJWT {
			t.Errorf("%s: got %q found=%v err=%v", name, got, found, err)
		}
	}
	if _, _, err := JWTInJSON([]byte(`{"a" 1}`)); err == nil {
		t.Error("malformed JSON gave no error")
	}
}

func TestDecodeStrict(t *testing.T) {
	var v struct {
		A int `json:"a"`
	}
	if err := DecodeStrict([]byte(`{"a":1}`), &v); err != nil || v.A != 1 {
		t.Errorf("DecodeStrict = %v, %+v", err, v)
	}
	for _, s := range []string{`{"a":1,"b":2}`, `{"a":1} {}`} {
		if err := DecodeStrict([]byte(s), &v); err == nil {
			t.Errorf("DecodeStrict(%s) accepted", s)
		}
	}
}
