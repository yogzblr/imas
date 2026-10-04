package openbao

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestNew_TransportSettings checks the settings New puts on the official
// client's transport: the sprout's proxy settings, the hot-reloading
// client certificate, no keep-alives, and the 30 second bound with no
// retries.
func TestNew_TransportSettings(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	genCert(t, certPath, keyPath)

	p, err := New("https://vault.example.com:8200", certPath, keyPath, "", "", "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(p.Close)

	cfg := p.client.CloneConfig()
	tr, ok := cfg.HttpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T", cfg.HttpClient.Transport)
	}
	if tr.Proxy == nil || reflect.ValueOf(tr.Proxy).Pointer() != reflect.ValueOf(http.ProxyFromEnvironment).Pointer() {
		t.Error("transport does not use http.ProxyFromEnvironment")
	}
	if !tr.DisableKeepAlives {
		t.Error("keep-alives are on; a rotated client certificate would not be presented on a reused connection")
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.GetClientCertificate == nil {
		t.Fatal("no GetClientCertificate: the client certificate would not hot-reload")
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify is set")
	}
	if len(tr.TLSClientConfig.Certificates) != 0 {
		t.Error("a static client certificate is set alongside the watcher")
	}
	if cfg.MaxRetries != 0 {
		t.Errorf("MaxRetries = %d, want 0", cfg.MaxRetries)
	}
	if cfg.Timeout != requestTimeout || cfg.HttpClient.Timeout != requestTimeout {
		t.Errorf("timeouts = %v/%v, want %v", cfg.Timeout, cfg.HttpClient.Timeout, requestTimeout)
	}
}

// recordingVault answers like mockVault and records the headers each
// request arrived with.
type recordingVault struct {
	mu         sync.Mutex
	loginToken []string // X-Vault-Token on login requests
	namespaces []string // X-Vault-Namespace on every request
}

func (v *recordingVault) handler(w http.ResponseWriter, r *http.Request) {
	v.mu.Lock()
	v.namespaces = append(v.namespaces, r.Header.Get("X-Vault-Namespace"))
	if strings.HasPrefix(r.URL.Path, "/v1/auth/") {
		v.loginToken = append(v.loginToken, r.Header.Get("X-Vault-Token"))
	}
	v.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if strings.HasPrefix(r.URL.Path, "/v1/auth/") {
		_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "login-token", "lease_duration": 60}})
		return
	}
	if r.Header.Get("X-Vault-Token") != "login-token" {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]any{"k": "v"}}})
}

// TestIgnoresVaultAndBaoEnvironment sets the variables the official
// client reads in DefaultConfig/ReadEnvironment, as a customer host might
// for its own tools, and checks none of them reaches a request.
func TestIgnoresVaultAndBaoEnvironment(t *testing.T) {
	for _, prefix := range []string{"VAULT_", "BAO_"} {
		t.Setenv(prefix+"TOKEN", "ambient-token")
		t.Setenv(prefix+"NAMESPACE", "ambient-ns")
		t.Setenv(prefix+"ADDR", "http://127.0.0.1:1")
		t.Setenv(prefix+"MAX_RETRIES", "5")
		t.Setenv(prefix+"SKIP_VERIFY", "true")
	}
	v := &recordingVault{}
	srv := httptest.NewServer(http.HandlerFunc(v.handler))
	t.Cleanup(srv.Close)
	p := newWithTransport(srv.URL, "cert", "", http.DefaultTransport)

	if got, err := p.Get(t.Context(), "sdb://openbao/secret/app#k"); err != nil || got != "v" {
		t.Fatalf("Get = %q, %v", got, err)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, tok := range v.loginToken {
		if tok != "" {
			t.Errorf("login carried X-Vault-Token %q", tok)
		}
	}
	for _, ns := range v.namespaces {
		if ns != "" {
			t.Errorf("request carried X-Vault-Namespace %q", ns)
		}
	}
	if p.client.MaxRetries() != 0 {
		t.Errorf("MaxRetries = %d", p.client.MaxRetries())
	}

	// SKIP_VERIFY must not turn TLS verification off: a provider without
	// a CA bundle must refuse httptest's self-signed server.
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(v.handler))
	t.Cleanup(tlsSrv.Close)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	genCert(t, certPath, keyPath)
	tp, err := New(tlsSrv.URL, certPath, keyPath, "", "", "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(tp.Close)
	if _, err := tp.Get(t.Context(), "sdb://openbao/secret/app#k"); err == nil {
		t.Fatal("Get against an untrusted server certificate succeeded")
	}
}

// TestErrorsCarryNoSecrets checks the error strings a failed Get returns
// (which internal/cook wraps into a step's result) for tokens, secret
// values and non-OpenBao response bodies.
func TestErrorsCarryNoSecrets(t *testing.T) {
	const (
		token  = "hvs.sprout-login-token"
		secret = "the-db-password"
		echo   = "proxy echo: X-Vault-Token: " + token
	)
	var mode string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		m := mode
		mu.Unlock()
		if strings.HasPrefix(r.URL.Path, "/v1/auth/") {
			if m == "login-html" {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write([]byte("<html>" + echo + "</html>"))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": token, "lease_duration": 3600}})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		v1 := !strings.Contains(r.URL.Path, "/data/")
		switch {
		case (m == "absent-then-403" || m == "absent-then-html") && !v1:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{}})
			return
		case m == "absent-then-403":
			m = "read-403"
		case m == "absent-then-html":
			m = "read-html"
		}
		switch m {
		case "read-html":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(echo))
		case "read-403":
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]any{"user": "app", "password": secret}}})
		}
	}))
	t.Cleanup(srv.Close)

	cases := []struct {
		mode, ref string
		want      string // a substring the error must still carry
	}{
		{"login-html", "sdb://openbao/secret/app#password", "status 502"},
		{"read-html", "sdb://openbao/secret/app#password", "status 500"},
		{"read-403", "sdb://openbao/secret/app#password", "permission denied"},
		{"absent-then-403", "sdb://openbao/secret/app#password", "secret/data/app (KV v2): status 404 (not found); then secret/app (KV v1): status 403 (forbidden): permission denied"},
		{"absent-then-html", "sdb://openbao/secret/app#password", "secret/app (KV v1): status 500"},
		{"", "sdb://openbao/secret/app#missing", "missing"},
		{"", "sdb://openbao/secret/app", "#field"},
	}
	for _, tc := range cases {
		t.Run(tc.mode+tc.ref, func(t *testing.T) {
			mu.Lock()
			mode = tc.mode
			mu.Unlock()
			p := newWithTransport(srv.URL, "cert", "", http.DefaultTransport)
			_, err := p.Get(t.Context(), tc.ref)
			if err == nil {
				t.Fatal("expected an error")
			}
			msg := err.Error()
			for _, leak := range []string{token, secret, "proxy echo", "<html>"} {
				if strings.Contains(msg, leak) {
					t.Errorf("error %q contains %q", msg, leak)
				}
			}
			if !strings.Contains(msg, tc.want) {
				t.Errorf("error %q lacks %q", msg, tc.want)
			}
		})
	}
}

// TestForbiddenDropsCachedToken: a token the server stopped honouring
// before its lease ran out (revoked, or the server restarted with a new
// token store) is replaced on the next Get, not reused until expiry.
func TestForbiddenDropsCachedToken(t *testing.T) {
	m := &mockVault{secretData: map[string]any{"password": "hunter2"}}
	var mu sync.Mutex
	forbid := false
	inner := m.handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		f := forbid
		forbid = false
		mu.Unlock()
		if f && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
			return
		}
		inner(w, r)
	}))
	t.Cleanup(srv.Close)
	p := newWithTransport(srv.URL, "cert", "", http.DefaultTransport)

	const ref = "sdb://openbao/secret/myapp/db"
	if _, err := p.Get(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	forbid = true
	mu.Unlock()
	_, err := p.Get(t.Context(), ref)
	if !errors.Is(err, ErrReadFailed) || statusCode(err) != http.StatusForbidden {
		t.Fatalf("Get while forbidden = %v, want ErrReadFailed with status 403", err)
	}
	if _, err := p.Get(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	if m.loginCalls != 2 {
		t.Errorf("logins = %d, want 2 (a fresh login after the 403)", m.loginCalls)
	}
}

// TestLoginErrorWrapsSentinel keeps the sentinel errors callers match on.
func TestLoginErrorWrapsSentinel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"invalid certificate or no client certificate supplied"}})
	}))
	t.Cleanup(srv.Close)
	p := newWithTransport(srv.URL, "cert", "", http.DefaultTransport)
	_, err := p.Get(t.Context(), "sdb://openbao/secret/app")
	if !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("err = %v, want ErrLoginFailed", err)
	}
	if !strings.Contains(err.Error(), "invalid certificate") {
		t.Errorf("err = %q, want OpenBao's own message kept", err)
	}
}

// TestRequestTimeout: a server that never answers fails the Get within
// the context's deadline rather than hanging.
func TestRequestTimeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	t.Cleanup(func() { close(block); srv.Close() })
	p := newWithTransport(srv.URL, "cert", "", http.DefaultTransport)
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := p.Get(ctx, "sdb://openbao/secret/app"); err == nil {
		t.Fatal("expected an error")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("Get took %v", d)
	}
}
