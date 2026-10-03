package openbaokv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const testToken = "s.test-token"

// mockKV is a minimal in-memory KV v2 engine behind an httptest server:
// GET/POST /v1/<mount>/data/<path>, token-checked, recording every request.
type mockKV struct {
	mount string

	mu       sync.Mutex
	secrets  map[string]map[string]any
	versions map[string]int
	requests []mockRequest
}

type mockRequest struct {
	Method string
	Path   string // raw (escaped) URL path
	Token  string
	Body   map[string]any
}

func newMockKV(mount string) *mockKV {
	return &mockKV{
		mount:    mount,
		secrets:  map[string]map[string]any{},
		versions: map[string]int{},
	}
}

func (m *mockKV) start(t *testing.T) *httptest.Server {
	t.Helper()
	prefix := "/v1/" + m.mount + "/data/"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := mockRequest{Method: r.Method, Path: r.URL.EscapedPath(), Token: r.Header.Get("X-Vault-Token")}
		if r.Body != nil {
			b, _ := io.ReadAll(r.Body)
			if len(b) > 0 {
				_ = json.Unmarshal(b, &rec.Body)
			}
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		m.requests = append(m.requests, rec)

		if rec.Token != testToken {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"errors":["permission denied"]}`))
			return
		}
		if !strings.HasPrefix(r.URL.Path, prefix) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"errors":["no handler for route"]}`))
			return
		}
		key := strings.TrimPrefix(r.URL.Path, prefix)
		switch r.Method {
		case http.MethodGet:
			data, ok := m.secrets[key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"errors":[]}`))
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"data":     data,
				"metadata": map[string]any{"version": m.versions[key]},
			}})
		case http.MethodPost:
			data, ok := rec.Body["data"].(map[string]any)
			if !ok {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"errors":["no data provided"]}`))
				return
			}
			m.secrets[key] = data
			m.versions[key]++
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"version": m.versions[key]}})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func (m *mockKV) snapshot() []mockRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]mockRequest(nil), m.requests...)
}

func setupTokenEnv(t *testing.T, addr, mount string) {
	t.Helper()
	t.Setenv(EnvOpenBaoAddr, addr)
	t.Setenv(EnvOpenBaoKVMount, mount)
	t.Setenv(EnvOpenBaoAuthMethod, AuthMethodToken)
	t.Setenv(EnvOpenBaoToken, testToken)
	t.Setenv(EnvOpenBaoCACert, "")
}

func newTestClient(t *testing.T, m *mockKV) *Client {
	t.Helper()
	ts := m.start(t)
	setupTokenEnv(t, ts.URL, m.mount)
	c, err := NewClientFromEnv()
	if err != nil {
		t.Fatalf("NewClientFromEnv: %v", err)
	}
	return c
}

func TestWriteThenRead_RoundTrip(t *testing.T) {
	m := newMockKV("secret")
	c := newTestClient(t, m)
	ctx := context.Background()

	v, err := c.Write(ctx, "imas/saasapi/nats-user", map[string]string{"jwt": "eyJ.x.y", "public_key": "UABC"})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if v != 1 {
		t.Errorf("version = %d, want 1", v)
	}
	got, err := c.Read(ctx, "imas/saasapi/nats-user")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got["jwt"] != "eyJ.x.y" || got["public_key"] != "UABC" || len(got) != 2 {
		t.Errorf("Read = %v", got)
	}

	reqs := m.snapshot()
	if len(reqs) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(reqs))
	}
	w := reqs[0]
	if w.Method != http.MethodPost || w.Path != "/v1/secret/data/imas/saasapi/nats-user" {
		t.Errorf("write went to %s %s", w.Method, w.Path)
	}
	// KV v2 wants {"data": {...}} — not the fields at the top level.
	if data, ok := w.Body["data"].(map[string]any); !ok || data["jwt"] != "eyJ.x.y" {
		t.Errorf("write body = %v, want the fields nested under \"data\"", w.Body)
	}
	if r := reqs[1]; r.Method != http.MethodGet || r.Path != "/v1/secret/data/imas/saasapi/nats-user" {
		t.Errorf("read went to %s %s", r.Method, r.Path)
	}
}

func TestRead_NotFoundIsNilNil(t *testing.T) {
	c := newTestClient(t, newMockKV("secret"))
	got, err := c.Read(context.Background(), "does/not/exist")
	if err != nil || got != nil {
		t.Fatalf("Read = (%v, %v), want (nil, nil)", got, err)
	}
}

func TestRead_DropsNonStringFields(t *testing.T) {
	m := newMockKV("secret")
	m.secrets["p"] = map[string]any{"jwt": "a", "n": 3.0, "nested": map[string]any{"x": "y"}}
	c := newTestClient(t, m)
	got, err := c.Read(context.Background(), "p")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != 1 || got["jwt"] != "a" {
		t.Errorf("Read = %v, want only the string field", got)
	}
}

func TestCustomMount(t *testing.T) {
	m := newMockKV("platform-kv")
	c := newTestClient(t, m)
	if c.Mount() != "platform-kv" {
		t.Errorf("Mount = %q", c.Mount())
	}
	if _, err := c.Write(context.Background(), "a/b", map[string]string{"k": "v"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if p := m.snapshot()[0].Path; p != "/v1/platform-kv/data/a/b" {
		t.Errorf("path = %q", p)
	}
}

func TestDefaultMountIsSecret(t *testing.T) {
	t.Setenv(EnvOpenBaoAddr, "http://127.0.0.1:1")
	t.Setenv(EnvOpenBaoKVMount, "")
	t.Setenv(EnvOpenBaoAuthMethod, "")
	t.Setenv(EnvOpenBaoToken, "x")
	c, err := NewClientFromEnv()
	if err != nil {
		t.Fatalf("NewClientFromEnv: %v", err)
	}
	if c.Mount() != "secret" {
		t.Errorf("Mount = %q, want secret", c.Mount())
	}
}

func TestWrongTokenRejected(t *testing.T) {
	m := newMockKV("secret")
	ts := m.start(t)
	setupTokenEnv(t, ts.URL, "secret")
	t.Setenv(EnvOpenBaoToken, "not-the-real-token")
	c, err := NewClientFromEnv()
	if err != nil {
		t.Fatalf("NewClientFromEnv: %v", err)
	}
	_, err = c.Write(context.Background(), "p", map[string]string{"k": "v"})
	if !errors.Is(err, ErrWriteFailed) || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("expected ErrWriteFailed carrying the 403 and OpenBao's error text, got %v", err)
	}
	if _, err := c.Read(context.Background(), "p"); !errors.Is(err, ErrReadFailed) {
		t.Fatalf("expected ErrReadFailed, got %v", err)
	}
}

func TestInvalidPathsRejectedBeforeAnyRequest(t *testing.T) {
	m := newMockKV("secret")
	c := newTestClient(t, m)
	for _, p := range []string{"", "/", "a//b", "a/../b", "./a", "a/.."} {
		if _, err := c.Write(context.Background(), p, map[string]string{"k": "v"}); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("Write(%q): expected ErrInvalidPath, got %v", p, err)
		}
		if _, err := c.At(p); !errors.Is(err, ErrInvalidPath) {
			t.Errorf("At(%q): expected ErrInvalidPath, got %v", p, err)
		}
	}
	if n := len(m.snapshot()); n != 0 {
		t.Errorf("expected no requests for invalid paths, got %d", n)
	}
}

func TestPathSegmentsEscaped(t *testing.T) {
	m := newMockKV("secret")
	c := newTestClient(t, m)
	if _, err := c.Write(context.Background(), "a b/c?d", map[string]string{"k": "v"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if p := m.snapshot()[0].Path; p != "/v1/secret/data/a%20b/c%3Fd" {
		t.Errorf("path = %q, want each segment escaped", p)
	}
}

func TestSecretAt(t *testing.T) {
	m := newMockKV("secret")
	c := newTestClient(t, m)
	s, err := c.At("/imas/saasapi/")
	if err != nil {
		t.Fatalf("At: %v", err)
	}
	if s.Path() != "imas/saasapi" {
		t.Errorf("Path = %q", s.Path())
	}
	ctx := context.Background()
	if got, err := s.Read(ctx); err != nil || got != nil {
		t.Fatalf("Read before write = (%v, %v)", got, err)
	}
	if err := s.Write(ctx, map[string]string{"jwt": "j"}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got, err := s.Read(ctx); err != nil || got["jwt"] != "j" {
		t.Fatalf("Read after write = (%v, %v)", got, err)
	}
}

func TestWrite_ServerErrorSurfaced(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"errors":["storage backend unavailable"]}`))
	}))
	t.Cleanup(ts.Close)
	setupTokenEnv(t, ts.URL, "secret")
	c, err := NewClientFromEnv()
	if err != nil {
		t.Fatalf("NewClientFromEnv: %v", err)
	}
	_, err = c.Write(context.Background(), "p", map[string]string{"k": "v"})
	if !errors.Is(err, ErrWriteFailed) || !strings.Contains(err.Error(), "storage backend unavailable") {
		t.Fatalf("got %v", err)
	}
}

// --- configuration -------------------------------------------------------

func TestNewClientFromEnv_MissingAddr(t *testing.T) {
	t.Setenv(EnvOpenBaoAddr, "")
	if _, err := NewClientFromEnv(); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

func TestNewClientFromEnv_MissingToken(t *testing.T) {
	t.Setenv(EnvOpenBaoAddr, "http://127.0.0.1:1")
	t.Setenv(EnvOpenBaoAuthMethod, AuthMethodToken)
	t.Setenv(EnvOpenBaoToken, "")
	if _, err := NewClientFromEnv(); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

func TestNewClientFromEnv_MissingK8sRole(t *testing.T) {
	t.Setenv(EnvOpenBaoAddr, "http://127.0.0.1:1")
	t.Setenv(EnvOpenBaoAuthMethod, AuthMethodKubernetes)
	t.Setenv(EnvOpenBaoK8sRole, "")
	if _, err := NewClientFromEnv(); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

func TestNewClientFromEnv_UnknownAuthMethod(t *testing.T) {
	t.Setenv(EnvOpenBaoAddr, "http://127.0.0.1:1")
	t.Setenv(EnvOpenBaoAuthMethod, "carrier-pigeon")
	_, err := NewClientFromEnv()
	if !errors.Is(err, ErrNotConfigured) || !strings.Contains(err.Error(), "carrier-pigeon") {
		t.Fatalf("expected ErrNotConfigured naming the bad value, got %v", err)
	}
}

func TestNewClientFromEnv_InvalidMount(t *testing.T) {
	t.Setenv(EnvOpenBaoAddr, "http://127.0.0.1:1")
	t.Setenv(EnvOpenBaoKVMount, "a/../b")
	t.Setenv(EnvOpenBaoToken, "x")
	if _, err := NewClientFromEnv(); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

func TestNewClientFromEnv_BadCACert(t *testing.T) {
	t.Setenv(EnvOpenBaoAddr, "http://127.0.0.1:1")
	t.Setenv(EnvOpenBaoToken, "x")
	t.Setenv(EnvOpenBaoCACert, filepath.Join(t.TempDir(), "missing.pem"))
	if _, err := NewClientFromEnv(); err == nil {
		t.Fatal("expected an error for a missing CA bundle")
	}
	notPEM := filepath.Join(t.TempDir(), "not.pem")
	if err := os.WriteFile(notPEM, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvOpenBaoCACert, notPEM)
	if _, err := NewClientFromEnv(); err == nil || !strings.Contains(err.Error(), "no certificates") {
		t.Fatalf("expected a no-certificates error, got %v", err)
	}
}

// --- Kubernetes auth -------------------------------------------------------

func writeK8sJWT(t *testing.T, contents string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func setupK8sEnv(t *testing.T, addr, jwtPath string) {
	t.Helper()
	t.Setenv(EnvOpenBaoAddr, addr)
	t.Setenv(EnvOpenBaoKVMount, "secret")
	t.Setenv(EnvOpenBaoAuthMethod, AuthMethodKubernetes)
	t.Setenv(EnvOpenBaoK8sRole, "imas-saasapi-cred-publisher")
	t.Setenv(EnvOpenBaoK8sMount, "")
	t.Setenv(EnvOpenBaoK8sJWTPath, jwtPath)
	t.Setenv(EnvOpenBaoCACert, "")
}

func TestKubernetesAuth_LoginThenWriteWithIssuedToken(t *testing.T) {
	jwtPath := writeK8sJWT(t, "sa-jwt\n")
	var loginCalls int32
	var gotLogin map[string]string
	var gotWriteToken string
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/kubernetes/login", func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&loginCalls, 1)
		json.NewDecoder(r.Body).Decode(&gotLogin)
		fmt.Fprintf(w, `{"auth":{"client_token":"tok-%d","lease_duration":3600,"renewable":true}}`, n)
	})
	mux.HandleFunc("/v1/secret/data/p", func(w http.ResponseWriter, r *http.Request) {
		gotWriteToken = r.Header.Get("X-Vault-Token")
		w.Write([]byte(`{"data":{"version":1}}`))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	setupK8sEnv(t, ts.URL, jwtPath)

	c, err := NewClientFromEnv()
	if err != nil {
		t.Fatalf("NewClientFromEnv: %v", err)
	}
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := c.Write(ctx, "p", map[string]string{"k": "v"}); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if gotLogin["role"] != "imas-saasapi-cred-publisher" || gotLogin["jwt"] != "sa-jwt" {
		t.Errorf("login body = %v", gotLogin)
	}
	if gotWriteToken != "tok-1" {
		t.Errorf("write used token %q, want the login's tok-1", gotWriteToken)
	}
	if n := atomic.LoadInt32(&loginCalls); n != 1 {
		t.Errorf("expected the token to be cached across writes (1 login), got %d", n)
	}

	// Re-login before expiry is internal/openbao's, tested there
	// (TestKubernetesAuth_ReLoginNearExpiry).
}

func TestKubernetesAuth_JWTFileMissingOrEmpty(t *testing.T) {
	setupK8sEnv(t, "http://127.0.0.1:1", filepath.Join(t.TempDir(), "nope"))
	c, err := NewClientFromEnv()
	if err != nil {
		t.Fatalf("NewClientFromEnv: %v", err)
	}
	if _, err := c.Write(context.Background(), "p", nil); !errors.Is(err, ErrK8sJWTUnavailable) {
		t.Fatalf("missing file: expected ErrK8sJWTUnavailable, got %v", err)
	}

	setupK8sEnv(t, "http://127.0.0.1:1", writeK8sJWT(t, "  \n"))
	c, err = NewClientFromEnv()
	if err != nil {
		t.Fatalf("NewClientFromEnv: %v", err)
	}
	if _, err := c.Read(context.Background(), "p"); !errors.Is(err, ErrK8sJWTUnavailable) {
		t.Fatalf("empty file: expected ErrK8sJWTUnavailable, got %v", err)
	}
}

func TestKubernetesAuth_LoginRejected(t *testing.T) {
	var kvCalls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/kubernetes/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"errors":["service account name not authorized"]}`))
	})
	mux.HandleFunc("/v1/secret/data/p", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&kvCalls, 1)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	setupK8sEnv(t, ts.URL, writeK8sJWT(t, "sa-jwt"))

	c, err := NewClientFromEnv()
	if err != nil {
		t.Fatalf("NewClientFromEnv: %v", err)
	}
	_, err = c.Write(context.Background(), "p", map[string]string{"k": "v"})
	if !errors.Is(err, ErrK8sAuthFailed) || !errors.Is(err, ErrWriteFailed) {
		t.Fatalf("expected ErrWriteFailed wrapping ErrK8sAuthFailed, got %v", err)
	}
	if !strings.Contains(err.Error(), "service account name not authorized") {
		t.Errorf("expected OpenBao's error text preserved, got %v", err)
	}
	if atomic.LoadInt32(&kvCalls) != 0 {
		t.Error("KV endpoint was called despite the login failing")
	}
}

func TestKubernetesAuth_LoginMissingToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/kubernetes/login", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"auth":null}`))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	setupK8sEnv(t, ts.URL, writeK8sJWT(t, "sa-jwt"))

	c, err := NewClientFromEnv()
	if err != nil {
		t.Fatalf("NewClientFromEnv: %v", err)
	}
	if _, err := c.Read(context.Background(), "p"); !errors.Is(err, ErrK8sAuthFailed) {
		t.Fatalf("expected ErrK8sAuthFailed, got %v", err)
	}
}

func TestKubernetesAuth_CustomMount(t *testing.T) {
	var hit bool
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/k8s-prod/login", func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.Write([]byte(`{"auth":{"client_token":"t","lease_duration":60}}`))
	})
	mux.HandleFunc("/v1/secret/data/p", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	setupK8sEnv(t, ts.URL, writeK8sJWT(t, "sa-jwt"))
	t.Setenv(EnvOpenBaoK8sMount, "k8s-prod")

	c, err := NewClientFromEnv()
	if err != nil {
		t.Fatalf("NewClientFromEnv: %v", err)
	}
	if _, err := c.Read(context.Background(), "p"); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !hit {
		t.Error("expected login at /v1/auth/k8s-prod/login")
	}
}
