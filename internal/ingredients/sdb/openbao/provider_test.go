package openbao

import (
	"encoding/json"
	"errors"
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
	// leaseSeconds is the login token's lease_duration; 0 means 3600.
	leaseSeconds int
}

func (m *mockVault) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/auth/"):
			m.loginCalls++
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			m.loginRole = body["name"]
			lease := m.leaseSeconds
			if lease == 0 {
				lease = 3600
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{
					"client_token":   "test-token",
					"lease_duration": lease,
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

// TestGet_ReadErrorNamesEveryPathTried: an absent KV v2 secret falls
// back to KV v1, and the error says what both reads returned, so a
// refused fallback doesn't read as only "permission denied". The lookup
// order is unchanged: KV v2 first, KV v1 only after a 404.
func TestGet_ReadErrorNamesEveryPathTried(t *testing.T) {
	statuses := map[string]int{}
	var order []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/v1/auth/") {
			_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "t", "lease_duration": 3600}})
			return
		}
		order = append(order, r.URL.Path)
		code, ok := statuses[r.URL.Path]
		if !ok {
			code = http.StatusNotFound
		}
		w.WriteHeader(code)
		errs := []string{}
		if code == http.StatusForbidden {
			errs = []string{"permission denied"}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": errs})
	}))
	t.Cleanup(srv.Close)
	p := newWithTransport(srv.URL, "cert", "", http.DefaultTransport)

	for _, tc := range []struct {
		name     string
		statuses map[string]int
		want     string
		paths    []string
		status   int
	}{
		{
			name:     "absent, fallback refused",
			statuses: map[string]int{"/v1/kv/app/db": http.StatusForbidden},
			want:     "openbao secret read failed: tried kv/data/app/db (KV v2): status 404 (not found); then kv/app/db (KV v1): status 403 (forbidden): permission denied",
			paths:    []string{"/v1/kv/data/app/db", "/v1/kv/app/db"},
			status:   http.StatusForbidden,
		},
		{
			name:   "absent from both",
			want:   "openbao secret read failed: tried kv/data/app/db (KV v2): status 404 (not found); then kv/app/db (KV v1): status 404 (not found)",
			paths:  []string{"/v1/kv/data/app/db", "/v1/kv/app/db"},
			status: http.StatusNotFound,
		},
		{
			name:     "KV v2 refused: no fallback",
			statuses: map[string]int{"/v1/kv/data/app/db": http.StatusForbidden},
			want:     "openbao secret read failed: tried kv/data/app/db (KV v2): status 403 (forbidden): permission denied",
			paths:    []string{"/v1/kv/data/app/db"},
			status:   http.StatusForbidden,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			statuses, order = tc.statuses, nil
			_, err := p.Get(t.Context(), "sdb://openbao/kv/app/db#password")
			if err == nil || err.Error() != tc.want {
				t.Fatalf("err = %v\nwant %s", err, tc.want)
			}
			if !errors.Is(err, ErrReadFailed) {
				t.Errorf("err is not ErrReadFailed")
			}
			if got := statusCode(err); got != tc.status {
				t.Errorf("statusCode = %d, want %d (the last read's)", got, tc.status)
			}
			if strings.Join(order, " ") != strings.Join(tc.paths, " ") {
				t.Errorf("reads = %v, want %v", order, tc.paths)
			}
		})
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
	// A 1s lease is cached for 0.9s (renewed at 90%).
	m := &mockVault{secretData: map[string]any{"password": "hunter2"}, leaseSeconds: 1}
	p, _ := newTestProvider(t, m)

	if _, err := p.Get(t.Context(), "sdb://openbao/secret/myapp/db"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	time.Sleep(time.Second)

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
