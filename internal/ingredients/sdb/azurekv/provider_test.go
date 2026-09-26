package azurekv

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yogzblr/imas/internal/ingredients/sdb"
)

type mockAzure struct {
	tokenCalls int
	secrets    map[string]string // secretName[/version] -> raw value
}

func (m *mockAzure) imdsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.tokenCalls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token": "test-access-token",
			"expires_in":   "3600",
		})
	}
}

func (m *mockAzure) kvHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-access-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		key := strings.TrimPrefix(r.URL.Path, "/secrets/")
		val, ok := m.secrets[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": val})
	}
}

func newTestProvider(t *testing.T, m *mockAzure) *Provider {
	t.Helper()
	imds := httptest.NewServer(m.imdsHandler())
	t.Cleanup(imds.Close)
	kv := httptest.NewServer(m.kvHandler())
	t.Cleanup(kv.Close)
	p := New(imds.URL, http.DefaultClient)
	p.kvBaseURL = kv.URL
	return p
}

func TestGet_PlainSecret(t *testing.T) {
	m := &mockAzure{secrets: map[string]string{"db-password": "hunter2"}}
	p := newTestProvider(t, m)

	got, err := p.Get(t.Context(), "sdb://azurekv/myvault/db-password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hunter2" {
		t.Errorf("got %q, want %q", got, "hunter2")
	}
}

func TestGet_VersionedSecret(t *testing.T) {
	m := &mockAzure{secrets: map[string]string{"db-password/abc123": "old-value"}}
	p := newTestProvider(t, m)

	got, err := p.Get(t.Context(), "sdb://azurekv/myvault/db-password/abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "old-value" {
		t.Errorf("got %q, want %q", got, "old-value")
	}
}

func TestGet_JSONSecretWithField(t *testing.T) {
	m := &mockAzure{secrets: map[string]string{"db-creds": `{"user":"admin","password":"hunter2"}`}}
	p := newTestProvider(t, m)

	got, err := p.Get(t.Context(), "sdb://azurekv/myvault/db-creds#password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hunter2" {
		t.Errorf("got %q, want %q", got, "hunter2")
	}
}

func TestGet_TokenCachedAcrossCalls(t *testing.T) {
	m := &mockAzure{secrets: map[string]string{"a": "1", "b": "2"}}
	p := newTestProvider(t, m)

	if _, err := p.Get(t.Context(), "sdb://azurekv/myvault/a"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := p.Get(t.Context(), "sdb://azurekv/myvault/b"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.tokenCalls != 1 {
		t.Errorf("expected token reuse (1 IMDS call), got %d", m.tokenCalls)
	}
}

func TestGet_MissingSecret(t *testing.T) {
	m := &mockAzure{secrets: map[string]string{}}
	p := newTestProvider(t, m)

	if _, err := p.Get(t.Context(), "sdb://azurekv/myvault/nope"); err == nil {
		t.Fatal("expected an error for a missing secret")
	}
}

func TestGet_MalformedRef(t *testing.T) {
	m := &mockAzure{secrets: map[string]string{}}
	p := newTestProvider(t, m)

	if _, err := p.Get(t.Context(), "sdb://azurekv/onlyvault"); err == nil {
		t.Fatal("expected an error for a ref missing a secret name")
	}
}

func TestRegisteredThroughDispatcher(t *testing.T) {
	m := &mockAzure{secrets: map[string]string{"a": "1"}}
	p := newTestProvider(t, m)

	if err := sdb.RegisterProvider("azurekv-test-dispatch", p); err != nil {
		t.Fatalf("registering test provider: %v", err)
	}
	got, err := sdb.Get(t.Context(), "sdb://azurekv-test-dispatch/myvault/a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "1" {
		t.Errorf("got %q, want %q", got, "1")
	}
}
