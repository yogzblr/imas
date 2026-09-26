package gcpsm

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yogzblr/imas/internal/ingredients/sdb"
)

type mockGCP struct {
	tokenCalls int
	secrets    map[string]string // "project/secret/version" -> raw value
}

func (m *mockGCP) metadataHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		m.tokenCalls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-access-token",
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	}
}

func (m *mockGCP) smHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-access-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// path: /v1/projects/<project>/secrets/<secret>/versions/<version>:access
		key := strings.TrimPrefix(r.URL.Path, "/v1/projects/")
		key = strings.Replace(key, "/secrets/", "/", 1)
		key = strings.Replace(key, "/versions/", "/", 1)
		key = strings.TrimSuffix(key, ":access")
		val, ok := m.secrets[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": key,
			"payload": map[string]string{
				"data": base64.StdEncoding.EncodeToString([]byte(val)),
			},
		})
	}
}

func newTestProvider(t *testing.T, m *mockGCP) *Provider {
	t.Helper()
	meta := httptest.NewServer(m.metadataHandler())
	t.Cleanup(meta.Close)
	sm := httptest.NewServer(m.smHandler())
	t.Cleanup(sm.Close)
	p := New(meta.URL, http.DefaultClient)
	p.smBaseURL = sm.URL
	return p
}

func TestGet_DefaultsToLatestVersion(t *testing.T) {
	m := &mockGCP{secrets: map[string]string{"my-project/db-password/latest": "hunter2"}}
	p := newTestProvider(t, m)

	got, err := p.Get(t.Context(), "sdb://gcpsm/my-project/db-password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hunter2" {
		t.Errorf("got %q, want %q", got, "hunter2")
	}
}

func TestGet_ExplicitVersion(t *testing.T) {
	m := &mockGCP{secrets: map[string]string{"my-project/db-password/3": "old-value"}}
	p := newTestProvider(t, m)

	got, err := p.Get(t.Context(), "sdb://gcpsm/my-project/db-password/3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "old-value" {
		t.Errorf("got %q, want %q", got, "old-value")
	}
}

func TestGet_JSONSecretWithField(t *testing.T) {
	m := &mockGCP{secrets: map[string]string{"my-project/db-creds/latest": `{"user":"admin","password":"hunter2"}`}}
	p := newTestProvider(t, m)

	got, err := p.Get(t.Context(), "sdb://gcpsm/my-project/db-creds#password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hunter2" {
		t.Errorf("got %q, want %q", got, "hunter2")
	}
}

func TestGet_TokenCachedAcrossCalls(t *testing.T) {
	m := &mockGCP{secrets: map[string]string{"p/a/latest": "1", "p/b/latest": "2"}}
	p := newTestProvider(t, m)

	if _, err := p.Get(t.Context(), "sdb://gcpsm/p/a"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := p.Get(t.Context(), "sdb://gcpsm/p/b"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.tokenCalls != 1 {
		t.Errorf("expected token reuse (1 metadata call), got %d", m.tokenCalls)
	}
}

func TestGet_MissingSecret(t *testing.T) {
	m := &mockGCP{secrets: map[string]string{}}
	p := newTestProvider(t, m)

	if _, err := p.Get(t.Context(), "sdb://gcpsm/p/nope"); err == nil {
		t.Fatal("expected an error for a missing secret")
	}
}

func TestGet_MalformedRef(t *testing.T) {
	m := &mockGCP{secrets: map[string]string{}}
	p := newTestProvider(t, m)

	if _, err := p.Get(t.Context(), "sdb://gcpsm/onlyproject"); err == nil {
		t.Fatal("expected an error for a ref missing a secret name")
	}
}

func TestRegisteredThroughDispatcher(t *testing.T) {
	m := &mockGCP{secrets: map[string]string{"p/a/latest": "1"}}
	p := newTestProvider(t, m)

	if err := sdb.RegisterProvider("gcpsm-test-dispatch", p); err != nil {
		t.Fatalf("registering test provider: %v", err)
	}
	got, err := sdb.Get(t.Context(), "sdb://gcpsm-test-dispatch/p/a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "1" {
		t.Errorf("got %q, want %q", got, "1")
	}
}
