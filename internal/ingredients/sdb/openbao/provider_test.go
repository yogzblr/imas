package openbao

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/ingredients/sdb"
)

// mockVault is a minimal stand-in for an OpenBao/Vault server: it accepts
// any cert-auth login and serves a fixed KV v2 (or, when kvv1 is set,
// KV v1) secret.
type mockVault struct {
	loginCalls int
	kvv1       bool
	secretData map[string]any
	loginRole  string // observed "name" field of the last login request, if any
}

func (m *mockVault) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/auth/"):
			m.loginCalls++
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			m.loginRole = body["name"]
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{
					"client_token":   "test-token",
					"lease_duration": 3600,
				},
			})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/secret/"):
			if r.Header.Get("X-Vault-Token") != "test-token" {
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if m.kvv1 {
				if strings.Contains(r.URL.Path, "/data/") {
					w.WriteHeader(http.StatusNotFound)
					_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{}})
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"data": m.secretData})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"data": m.secretData, "metadata": map[string]any{}},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func newTestProvider(t *testing.T, m *mockVault) (*Provider, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(m.handler())
	t.Cleanup(srv.Close)
	p := newWithTransport(srv.URL, "cert", "", http.DefaultTransport)
	return p, srv
}

func TestGet_KVv2_SingleField(t *testing.T) {
	m := &mockVault{secretData: map[string]any{"password": "hunter2"}}
	p, _ := newTestProvider(t, m)

	got, err := p.Get(t.Context(), "sdb://openbao/secret/myapp/db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hunter2" {
		t.Errorf("got %q, want %q", got, "hunter2")
	}
	if m.loginCalls != 1 {
		t.Errorf("expected exactly 1 login call, got %d", m.loginCalls)
	}
}

func TestGet_KVv2_NonStringFieldIsJSONEncoded(t *testing.T) {
	m := &mockVault{secretData: map[string]any{"port": 5432}}
	p, _ := newTestProvider(t, m)

	got, err := p.Get(t.Context(), "sdb://openbao/secret/myapp/db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "5432" {
		t.Errorf("got %q, want %q", got, "5432")
	}
}

func TestGet_KVv2_ExplicitField(t *testing.T) {
	m := &mockVault{secretData: map[string]any{"user": "admin", "password": "hunter2"}}
	p, _ := newTestProvider(t, m)

	got, err := p.Get(t.Context(), "sdb://openbao/secret/myapp/db#password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hunter2" {
		t.Errorf("got %q, want %q", got, "hunter2")
	}
}

func TestGet_KVv2_AmbiguousWithoutField(t *testing.T) {
	m := &mockVault{secretData: map[string]any{"user": "admin", "password": "hunter2"}}
	p, _ := newTestProvider(t, m)

	_, err := p.Get(t.Context(), "sdb://openbao/secret/myapp/db")
	if err == nil {
		t.Fatal("expected an error for an ambiguous multi-field secret")
	}
}

func TestGet_KVv1Fallback(t *testing.T) {
	m := &mockVault{kvv1: true, secretData: map[string]any{"password": "legacy-secret"}}
	p, _ := newTestProvider(t, m)

	got, err := p.Get(t.Context(), "sdb://openbao/secret/myapp/db#password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "legacy-secret" {
		t.Errorf("got %q, want %q", got, "legacy-secret")
	}
}

func TestGet_TokenIsCachedAcrossCalls(t *testing.T) {
	m := &mockVault{secretData: map[string]any{"password": "hunter2"}}
	p, _ := newTestProvider(t, m)

	for i := 0; i < 3; i++ {
		if _, err := p.Get(t.Context(), "sdb://openbao/secret/myapp/db"); err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
	}
	if m.loginCalls != 1 {
		t.Errorf("expected token reuse across calls (1 login), got %d logins", m.loginCalls)
	}
}

func TestGet_ReloginAfterTokenExpiry(t *testing.T) {
	m := &mockVault{secretData: map[string]any{"password": "hunter2"}}
	p, _ := newTestProvider(t, m)

	if _, err := p.Get(t.Context(), "sdb://openbao/secret/myapp/db"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Force the cached token to look expired.
	p.tokenMu.Lock()
	p.tokenExpiry = time.Now().Add(-time.Second)
	p.tokenMu.Unlock()

	if _, err := p.Get(t.Context(), "sdb://openbao/secret/myapp/db"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.loginCalls != 2 {
		t.Errorf("expected a re-login after expiry, got %d logins", m.loginCalls)
	}
}

func TestGet_AuthRolePassedToLogin(t *testing.T) {
	m := &mockVault{secretData: map[string]any{"password": "hunter2"}}
	srv := httptest.NewServer(m.handler())
	t.Cleanup(srv.Close)
	p := newWithTransport(srv.URL, "cert", "my-role", http.DefaultTransport)

	if _, err := p.Get(t.Context(), "sdb://openbao/secret/myapp/db"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.loginRole != "my-role" {
		t.Errorf("expected login role %q, got %q", "my-role", m.loginRole)
	}
}

func TestGet_MalformedPathRejected(t *testing.T) {
	m := &mockVault{secretData: map[string]any{"password": "hunter2"}}
	p, _ := newTestProvider(t, m)

	if _, err := p.Get(t.Context(), "sdb://openbao/onlyonesegment"); err == nil {
		t.Fatal("expected an error for a ref missing a mount/path split")
	}
}

func TestRegisteredThroughDispatcher(t *testing.T) {
	m := &mockVault{secretData: map[string]any{"password": "hunter2"}}
	p, _ := newTestProvider(t, m)

	if err := sdb.RegisterProvider("openbao-test-dispatch", p); err != nil {
		t.Fatalf("registering test provider: %v", err)
	}

	got, err := sdb.Get(t.Context(), "sdb://openbao-test-dispatch/secret/myapp/db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hunter2" {
		t.Errorf("got %q, want %q", got, "hunter2")
	}
}
