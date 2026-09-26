package awssm

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/ingredients/sdb"
)

type mockAWS struct {
	tokenCalls    int
	roleListCalls int
	roleCredCalls int
	secrets       map[string]string // SecretId -> SecretString
}

func (m *mockAWS) imdsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/latest/api/token":
			m.tokenCalls++
			_, _ = w.Write([]byte("test-imds-token"))
		case r.Method == http.MethodGet && r.URL.Path == "/latest/meta-data/iam/security-credentials/":
			if r.Header.Get("X-aws-ec2-metadata-token") != "test-imds-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			m.roleListCalls++
			_, _ = w.Write([]byte("my-instance-role\n"))
		case r.Method == http.MethodGet && r.URL.Path == "/latest/meta-data/iam/security-credentials/my-instance-role":
			if r.Header.Get("X-aws-ec2-metadata-token") != "test-imds-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			m.roleCredCalls++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"AccessKeyId":     "AKIDTEST",
				"SecretAccessKey": "secretkey",
				"Token":           "sessiontoken",
				"Expiration":      time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func (m *mockAWS) smHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Amz-Target") != "secretsmanager.GetSecretValue" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIDTEST/") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req struct {
			SecretId string
		}
		_ = json.Unmarshal(body, &req)
		val, ok := m.secrets[req.SecretId]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"Name":         req.SecretId,
			"SecretString": val,
		})
	}
}

func newTestProvider(t *testing.T, m *mockAWS) *Provider {
	t.Helper()
	imds := httptest.NewServer(m.imdsHandler())
	t.Cleanup(imds.Close)
	sm := httptest.NewServer(m.smHandler())
	t.Cleanup(sm.Close)
	p := New(imds.URL, http.DefaultClient)
	p.smEndpoint = sm.URL
	return p
}

func TestGet_PlainSecret(t *testing.T) {
	m := &mockAWS{secrets: map[string]string{"prod/db": "hunter2"}}
	p := newTestProvider(t, m)

	got, err := p.Get(t.Context(), "sdb://awssm/us-east-1/prod/db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hunter2" {
		t.Errorf("got %q, want %q", got, "hunter2")
	}
	if m.tokenCalls != 1 || m.roleListCalls != 1 || m.roleCredCalls != 1 {
		t.Errorf("unexpected IMDS call counts: token=%d list=%d creds=%d", m.tokenCalls, m.roleListCalls, m.roleCredCalls)
	}
}

func TestGet_JSONSecretWithField(t *testing.T) {
	m := &mockAWS{secrets: map[string]string{"prod/db": `{"username":"admin","password":"hunter2"}`}}
	p := newTestProvider(t, m)

	got, err := p.Get(t.Context(), "sdb://awssm/us-east-1/prod/db#password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hunter2" {
		t.Errorf("got %q, want %q", got, "hunter2")
	}
}

func TestGet_CredsCachedAcrossCalls(t *testing.T) {
	m := &mockAWS{secrets: map[string]string{"a": "1", "b": "2"}}
	p := newTestProvider(t, m)

	if _, err := p.Get(t.Context(), "sdb://awssm/us-east-1/a"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := p.Get(t.Context(), "sdb://awssm/us-east-1/b"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.roleCredCalls != 1 {
		t.Errorf("expected creds reuse (1 IMDS role-creds call), got %d", m.roleCredCalls)
	}
}

func TestGet_MissingSecret(t *testing.T) {
	m := &mockAWS{secrets: map[string]string{}}
	p := newTestProvider(t, m)

	if _, err := p.Get(t.Context(), "sdb://awssm/us-east-1/nope"); err == nil {
		t.Fatal("expected an error for a missing secret")
	}
}

func TestGet_MalformedRef(t *testing.T) {
	m := &mockAWS{secrets: map[string]string{}}
	p := newTestProvider(t, m)

	if _, err := p.Get(t.Context(), "sdb://awssm/onlyregion"); err == nil {
		t.Fatal("expected an error for a ref missing a secret id")
	}
}

func TestGet_SecretIDWithSlashes(t *testing.T) {
	m := &mockAWS{secrets: map[string]string{"team/service/db-password": "hunter2"}}
	p := newTestProvider(t, m)

	got, err := p.Get(t.Context(), "sdb://awssm/us-east-1/team/service/db-password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hunter2" {
		t.Errorf("got %q, want %q", got, "hunter2")
	}
}

func TestRegisteredThroughDispatcher(t *testing.T) {
	m := &mockAWS{secrets: map[string]string{"a": "1"}}
	p := newTestProvider(t, m)

	if err := sdb.RegisterProvider("awssm-test-dispatch", p); err != nil {
		t.Fatalf("registering test provider: %v", err)
	}
	got, err := sdb.Get(t.Context(), "sdb://awssm-test-dispatch/us-east-1/a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "1" {
		t.Errorf("got %q, want %q", got, "1")
	}
}
