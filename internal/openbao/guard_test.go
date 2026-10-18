package openbao

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestValidatePath(t *testing.T) {
	ok := []string{"a", "a/b", "a b/c?d", "secret/data/app", "sys", "a/sys", "auth2/x", "a%2eb", "a.b/..c/d.."}
	for _, p := range ok {
		if err := ValidatePath(p); err != nil {
			t.Errorf("ValidatePath(%q) = %v, want nil", p, err)
		}
	}
	bad := []string{
		"", "/", "a//b", "a/", "/a", ".", "..", "a/./b", "a/../b",
		// percent-encoded once, twice and in mixed case
		"%2e", "%2E%2E", "a/%2e%2e/b", "a/%252e%252e/b", "a/.%2e/b", "%25252e",
		// a segment that decodes to a separator
		"a%2fb", "a/%2F../b", "a%252Fb", `a\b`, "a%5cb",
	}
	for _, p := range bad {
		if err := ValidatePath(p); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("ValidatePath(%q) = %v, want ErrInvalidPath", p, err)
		}
	}
}

func TestValidateMountPath(t *testing.T) {
	for _, p := range []string{"secret/app", "kv/sys", "kv/auth/x", "authx/y", "system/a"} {
		if err := ValidateMountPath(p); err != nil {
			t.Errorf("ValidateMountPath(%q) = %v, want nil", p, err)
		}
	}
	for _, p := range []string{
		"auth/token/lookup-self", "sys/health", "identity/entity", "AUTH/x", "Sys/x",
		"%61uth/token", "%2561uth/x", "%73ys", "identity", "../auth/x", "secret/../sys",
	} {
		if err := ValidateMountPath(p); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("ValidateMountPath(%q) = %v, want ErrInvalidPath", p, err)
		}
	}
}

func TestCheckAddr(t *testing.T) {
	for _, c := range []struct {
		addr  string
		allow bool
		ok    bool
	}{
		{"https://bao.example.com:8200", false, true},
		{"HTTPS://bao.example.com", false, true},
		{"http://bao.example.com:8200", false, false},
		{"http://bao.example.com:8200", true, true},
		{"unix:///run/bao.sock", true, false},
		{"ftp://bao.example.com", true, false},
		{"https://", false, false},
		{"bao.example.com:8200", true, false},
	} {
		err := CheckAddr(c.addr, "X_ADDR", "X_ALLOW_INSECURE", c.allow)
		if (err == nil) != c.ok {
			t.Errorf("CheckAddr(%q, allow=%v) = %v, want ok=%v", c.addr, c.allow, err, c.ok)
		}
	}
	err := CheckAddr("http://bao:8200", "X_ADDR", "X_ALLOW_INSECURE", false)
	if err == nil || !strings.Contains(err.Error(), "X_ALLOW_INSECURE=true") || !strings.Contains(err.Error(), "X_ADDR") {
		t.Fatalf("refusal must name both settings, got %v", err)
	}
}

type countingTransport struct{ n int }

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.n++
	return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
}

type closeRecorder struct {
	io.Reader
	closed bool
}

func (c *closeRecorder) Close() error { c.closed = true; return nil }

func TestPinTransport(t *testing.T) {
	base := &countingTransport{}
	rt, err := PinTransport(base, "https://Bao.Example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"https://bao.example.com/v1/x", "https://BAO.example.com:443/v1/y"} {
		req, _ := http.NewRequest(http.MethodGet, u, nil)
		if _, err := rt.RoundTrip(req); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	if base.n != 2 {
		t.Fatalf("base saw %d requests, want 2", base.n)
	}
	for _, u := range []string{
		"http://bao.example.com/v1/x",       // scheme
		"https://bao.example.com:8443/v1/x", // port
		"https://evil.example.com/v1/x",     // host
		"https://bao.example.com.evil.example/v1/x",
	} {
		body := &closeRecorder{Reader: strings.NewReader("secret body")}
		req, _ := http.NewRequest(http.MethodPost, u, body)
		_, err := rt.RoundTrip(req)
		if !errors.Is(err, ErrOtherHost) {
			t.Fatalf("%s: err = %v, want ErrOtherHost", u, err)
		}
		if !body.closed {
			t.Errorf("%s: request body not closed", u)
		}
		if strings.Contains(err.Error(), "/v1/x") {
			t.Errorf("%s: error names the request path: %v", u, err)
		}
	}
	if base.n != 2 {
		t.Fatalf("a refused request reached the base transport (%d)", base.n)
	}
	if _, err := PinTransport(base, "unix:///sock"); err == nil {
		t.Fatal("PinTransport accepted a unix address")
	}
	if o, ok := canonicalOrigin(&url.URL{Scheme: "http", Host: "[::1]"}); !ok || o != "http://[::1]:80" {
		t.Fatalf("canonicalOrigin([::1]) = %q, %v", o, ok)
	}
}
