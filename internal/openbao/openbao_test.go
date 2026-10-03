package openbao

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const prefix = "IMAS_OBTEST_OPENBAO_"

var testEnv = EnvWithPrefix(prefix)

var (
	errTestNotConfigured = errors.New("obtest: not configured")
	errTestJWT           = errors.New("obtest: jwt unavailable")
	errTestAuth          = errors.New("obtest: auth failed")
)

var testErrs = Errors{NotConfigured: errTestNotConfigured, K8sJWTUnavailable: errTestJWT, K8sAuthFailed: errTestAuth}

// recorded is one request a stub saw.
type recorded struct {
	Method, Path, Query, Token, Namespace, Request, ContentType string
	Body                                                        map[string]any
}

type stub struct {
	mu   sync.Mutex
	reqs []recorded
}

func (s *stub) record(r *http.Request) recorded {
	rec := recorded{
		Method: r.Method, Path: r.URL.EscapedPath(), Query: r.URL.RawQuery,
		Token: r.Header.Get("X-Vault-Token"), Namespace: r.Header.Get("X-Vault-Namespace"),
		Request: r.Header.Get("X-Vault-Request"), ContentType: r.Header.Get("Content-Type"),
	}
	if b, _ := io.ReadAll(r.Body); len(b) > 0 {
		_ = json.Unmarshal(b, &rec.Body)
	}
	s.mu.Lock()
	s.reqs = append(s.reqs, rec)
	s.mu.Unlock()
	return rec
}

func (s *stub) all() []recorded {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recorded(nil), s.reqs...)
}

// clearAmbient blanks every variable the official client would read if
// it were built from api.DefaultConfig, plus this test identity's own.
func clearAmbient(t *testing.T) {
	t.Helper()
	for _, k := range []string{"ADDR", "CACERT", "AUTH_METHOD", "TOKEN", "K8S_ROLE", "K8S_MOUNT", "K8S_JWT_PATH", "NAMESPACE"} {
		t.Setenv(prefix+k, "")
	}
}

func setTokenEnv(t *testing.T, addr, token string) {
	t.Helper()
	clearAmbient(t)
	t.Setenv(testEnv.Addr, addr)
	t.Setenv(testEnv.Token, token)
}

func writeJWT(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func setK8sEnv(t *testing.T, addr, jwtPath string) {
	t.Helper()
	clearAmbient(t)
	t.Setenv(testEnv.Addr, addr)
	t.Setenv(testEnv.AuthMethod, AuthMethodKubernetes)
	t.Setenv(testEnv.K8sRole, "imas-role")
	t.Setenv(testEnv.K8sJWTPath, jwtPath)
}

func TestEnvWithPrefix(t *testing.T) {
	e := EnvWithPrefix("IMAS_CERTS_OPENBAO_")
	want := Env{
		Addr: "IMAS_CERTS_OPENBAO_ADDR", CACert: "IMAS_CERTS_OPENBAO_CACERT",
		AuthMethod: "IMAS_CERTS_OPENBAO_AUTH_METHOD", Token: "IMAS_CERTS_OPENBAO_TOKEN",
		K8sRole: "IMAS_CERTS_OPENBAO_K8S_ROLE", K8sMount: "IMAS_CERTS_OPENBAO_K8S_MOUNT",
		K8sJWTPath: "IMAS_CERTS_OPENBAO_K8S_JWT_PATH", Namespace: "IMAS_CERTS_OPENBAO_NAMESPACE",
	}
	if e != want {
		t.Fatalf("EnvWithPrefix = %+v, want %+v", e, want)
	}
}

func TestNewFromEnv_ConfigErrors(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"missing addr", map[string]string{}, prefix + "ADDR is required"},
		{"missing token", map[string]string{"ADDR": "http://127.0.0.1:1"},
			prefix + "TOKEN is required when " + prefix + "AUTH_METHOD=token (or unset)"},
		{"missing k8s role", map[string]string{"ADDR": "http://127.0.0.1:1", "AUTH_METHOD": "kubernetes"},
			prefix + "K8S_ROLE is required when " + prefix + "AUTH_METHOD=kubernetes"},
		{"unknown method", map[string]string{"ADDR": "http://127.0.0.1:1", "AUTH_METHOD": "carrier-pigeon"},
			`unknown ` + prefix + `AUTH_METHOD "carrier-pigeon"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearAmbient(t)
			for k, v := range tc.env {
				t.Setenv(prefix+k, v)
			}
			_, err := NewFromEnv(testEnv, testErrs)
			if !errors.Is(err, errTestNotConfigured) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want errTestNotConfigured containing %q", err, tc.want)
			}
		})
	}
}

func TestNewFromEnv_DefaultSentinels(t *testing.T) {
	clearAmbient(t)
	if _, err := NewFromEnv(testEnv, Errors{}); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

func TestNewFromEnv_CACert(t *testing.T) {
	setTokenEnv(t, "http://127.0.0.1:1", "tok")
	t.Setenv(testEnv.CACert, filepath.Join(t.TempDir(), "missing.pem"))
	if _, err := NewFromEnv(testEnv, testErrs); err == nil || !strings.Contains(err.Error(), "reading OpenBao CA bundle") {
		t.Fatalf("missing CA file: got %v", err)
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(testEnv.CACert, bad)
	if _, err := NewFromEnv(testEnv, testErrs); err == nil || !strings.Contains(err.Error(), "no certificates found") {
		t.Fatalf("bad CA file: got %v", err)
	}
}

// TestCACertVerifiesTLS proves the CA bundle is what OpenBao's TLS is
// checked against: the stub's certificate is refused without it and
// accepted with it.
func TestCACertVerifiesTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":{"ok":true}}`))
	}))
	defer srv.Close()

	setTokenEnv(t, srv.URL, "tok")
	c, err := NewFromEnv(testEnv, testErrs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(t.Context(), "x", nil); err == nil {
		t.Fatal("expected a TLS verification failure without the CA bundle")
	}

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(testEnv.CACert, caFile)
	c, err = NewFromEnv(testEnv, testErrs)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := c.Read(t.Context(), "x", nil)
	if err != nil {
		t.Fatalf("with the CA bundle: %v", err)
	}
	if secret.Data["ok"] != true {
		t.Fatalf("unexpected data %v", secret.Data)
	}
}

// TestIgnoresAmbientBaoAndVaultVariables: an identity is configured only
// by its own IMAS_*_OPENBAO_* block. BAO_TOKEN, BAO_NAMESPACE,
// BAO_SKIP_VERIFY and BAO_ADDR (and their VAULT_* spellings) in the
// environment must change nothing.
func TestIgnoresAmbientBaoAndVaultVariables(t *testing.T) {
	var s stub
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.record(r)
		w.Write([]byte(`{}`))
	}))
	defer tlsSrv.Close()

	for _, p := range []string{"BAO_", "VAULT_"} {
		t.Setenv(p+"TOKEN", "ambient-token")
		t.Setenv(p+"NAMESPACE", "ambient-ns")
		t.Setenv(p+"SKIP_VERIFY", "true")
		t.Setenv(p+"ADDR", "http://127.0.0.1:1")
		t.Setenv(p+"MAX_RETRIES", "5")
	}
	setTokenEnv(t, tlsSrv.URL, "own-token")
	c, err := NewFromEnv(testEnv, testErrs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(t.Context(), "x", nil); err == nil {
		t.Fatal("BAO_SKIP_VERIFY must not disable TLS verification")
	}
	if n := len(s.all()); n != 0 {
		t.Fatalf("expected no request to complete, got %d", n)
	}

	var plain stub
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plain.record(r)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	t.Setenv(testEnv.Addr, srv.URL)
	c, err = NewFromEnv(testEnv, testErrs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(t.Context(), "x", nil); err != nil {
		t.Fatal(err)
	}
	got := plain.all()
	if len(got) != 1 || got[0].Token != "own-token" || got[0].Namespace != "" {
		t.Fatalf("request went out as %+v; want own-token and no namespace", got)
	}
}

func TestStaticToken_RequestShape(t *testing.T) {
	var s stub
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.record(r)
		w.Write([]byte(`{"data":{"version":3}}`))
	}))
	defer srv.Close()
	setTokenEnv(t, srv.URL+"/", "static-tok")
	c, err := NewFromEnv(testEnv, testErrs)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	if _, err := c.Read(ctx, "secret/data/a b", url.Values{"version": {"2"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Post(ctx, "transit/sign/k", map[string]string{"input": "aGk="}); err != nil {
		t.Fatal(err)
	}
	secret, err := c.Put(ctx, "secret/data/p", map[string]any{"data": map[string]string{"k": "v"}})
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Version int `json:"version"`
	}
	if err := DecodeData(secret, &out); err != nil || out.Version != 3 {
		t.Fatalf("DecodeData = %+v, %v", out, err)
	}

	got := s.all()
	if len(got) != 3 {
		t.Fatalf("expected 3 requests, got %d", len(got))
	}
	want := []struct{ method, path, query string }{
		{http.MethodGet, "/v1/secret/data/a%20b", "version=2"},
		{http.MethodPost, "/v1/transit/sign/k", ""},
		{http.MethodPut, "/v1/secret/data/p", ""},
	}
	for i, w := range want {
		r := got[i]
		if r.Method != w.method || r.Path != w.path || r.Query != w.query {
			t.Errorf("request %d = %s %s?%s, want %s %s?%s", i, r.Method, r.Path, r.Query, w.method, w.path, w.query)
		}
		if r.Token != "static-tok" || r.Request != "true" {
			t.Errorf("request %d: token %q, X-Vault-Request %q", i, r.Token, r.Request)
		}
	}
	if got[1].ContentType != "application/json" || got[1].Body["input"] != "aGk=" {
		t.Errorf("POST body/content type: %+v", got[1])
	}
}

func TestNamespaceHeader(t *testing.T) {
	var s stub
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := s.record(r)
		if strings.HasSuffix(rec.Path, "/login") {
			w.Write([]byte(`{"auth":{"client_token":"k8s-tok","lease_duration":3600}}`))
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	setK8sEnv(t, srv.URL, writeJWT(t, "sa-jwt"))
	t.Setenv(testEnv.Namespace, "/tenant-a/")
	c, err := NewFromEnv(testEnv, testErrs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(t.Context(), "x", nil); err != nil {
		t.Fatal(err)
	}
	for _, r := range s.all() {
		if r.Namespace != "tenant-a" {
			t.Errorf("%s %s: namespace %q, want tenant-a", r.Method, r.Path, r.Namespace)
		}
	}
}

func TestNoRetries(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"errors":["storage backend unavailable"]}`))
	}))
	defer srv.Close()
	setTokenEnv(t, srv.URL, "tok")
	c, err := NewFromEnv(testEnv, testErrs)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Post(t.Context(), "transit/sign/k", map[string]string{})
	if StatusCode(err) != 500 || err.Error() != "status 500: storage backend unavailable" {
		t.Fatalf("got %v", err)
	}
	if got := n.Load(); got != 1 {
		t.Fatalf("expected exactly 1 attempt, got %d", got)
	}
}

func TestStatusErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/missing":
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"errors":[]}`))
		case "/v1/denied":
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"errors":["1 error occurred:\n\t* permission denied\n\n"]}`))
		case "/v1/raw":
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte(`upstream down`))
		case "/v1/pem":
			w.Write([]byte("-----BEGIN CERTIFICATE-----\n"))
		case "/v1/empty":
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()
	setTokenEnv(t, srv.URL, "tok")
	c, err := NewFromEnv(testEnv, testErrs)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	if _, err := c.Read(ctx, "missing", nil); !IsNotFound(err) {
		t.Errorf("missing: expected IsNotFound, got %v", err)
	}
	_, err = c.Read(ctx, "denied", nil)
	if StatusCode(err) != 403 || !strings.Contains(err.Error(), "status 403") || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("denied: got %v", err)
	}
	if _, err := c.Read(ctx, "raw", nil); err == nil || err.Error() != "status 502: upstream down" {
		t.Errorf("raw: got %v", err)
	}
	if b, err := c.ReadRaw(ctx, "pem"); err != nil || !strings.HasPrefix(string(b), "-----BEGIN") {
		t.Errorf("ReadRaw: %q, %v", b, err)
	}
	if _, err := c.ReadRaw(ctx, "missing"); !IsNotFound(err) {
		t.Errorf("ReadRaw missing: got %v", err)
	}
	if s, err := c.Put(ctx, "empty", map[string]string{}); s != nil || err != nil {
		t.Errorf("204: got %v, %v", s, err)
	}
	if StatusCode(errors.New("x")) != 0 || StatusCode(nil) != 0 {
		t.Error("StatusCode of a non-OpenBao error should be 0")
	}
}

func TestKubernetesAuth_LoginOnceThenCache(t *testing.T) {
	var s stub
	var logins atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := s.record(r)
		if rec.Path == "/v1/auth/k8s-custom/login" {
			n := logins.Add(1)
			fmt.Fprintf(w, `{"auth":{"client_token":"tok-%d","lease_duration":3600,"renewable":true}}`, n)
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	setK8sEnv(t, srv.URL, writeJWT(t, "  sa-jwt\n"))
	t.Setenv(testEnv.K8sMount, "k8s-custom")
	c, err := NewFromEnv(testEnv, testErrs)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	for range 3 {
		if _, err := c.Read(ctx, "x", nil); err != nil {
			t.Fatal(err)
		}
	}
	if n := logins.Load(); n != 1 {
		t.Fatalf("expected 1 login for 3 requests, got %d", n)
	}
	got := s.all()
	login := got[0]
	if login.Method != http.MethodPost || login.Token != "" || login.Body["role"] != "imas-role" || login.Body["jwt"] != "sa-jwt" {
		t.Fatalf("login request = %+v", login)
	}
	for _, r := range got[1:] {
		if r.Token != "tok-1" {
			t.Fatalf("request after login carried token %q, want tok-1", r.Token)
		}
	}
}

func TestKubernetesAuth_ReLoginNearExpiry(t *testing.T) {
	var s stub
	var logins atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := s.record(r)
		if strings.HasSuffix(rec.Path, "/login") {
			n := logins.Add(1)
			fmt.Fprintf(w, `{"auth":{"client_token":"tok-%d","lease_duration":3600}}`, n)
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	setK8sEnv(t, srv.URL, writeJWT(t, "sa-jwt"))
	c, err := NewFromEnv(testEnv, testErrs)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	tok1, err := c.Token(ctx)
	if err != nil || tok1 != "tok-1" {
		t.Fatalf("first Token = %q, %v", tok1, err)
	}
	// 20% of a 3600s lease is held back.
	c.authMu.Lock()
	if left := time.Until(c.authExpiry); left < 47*time.Minute || left > 48*time.Minute {
		t.Errorf("cached for %s, want ~48m (80%% of 1h)", left)
	}
	c.authExpiry = time.Now().Add(-time.Second)
	c.authMu.Unlock()

	if _, err := c.Read(ctx, "x", nil); err != nil {
		t.Fatal(err)
	}
	got := s.all()
	if n := logins.Load(); n != 2 {
		t.Fatalf("expected 2 logins, got %d", n)
	}
	// The second login must not present the expired token.
	if got[1].Token != "" {
		t.Errorf("re-login carried token %q", got[1].Token)
	}
	if last := got[len(got)-1]; last.Token != "tok-2" {
		t.Errorf("request after re-login carried %q, want tok-2", last.Token)
	}
}

func TestKubernetesAuth_JWTFileProblems(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { n.Add(1) }))
	defer srv.Close()
	for name, path := range map[string]string{
		"missing": filepath.Join(t.TempDir(), "does-not-exist"),
		"empty":   writeJWT(t, "   \n"),
	} {
		t.Run(name, func(t *testing.T) {
			setK8sEnv(t, srv.URL, path)
			c, err := NewFromEnv(testEnv, testErrs)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Read(t.Context(), "x", nil); !errors.Is(err, errTestJWT) {
				t.Fatalf("expected the JWT sentinel, got %v", err)
			}
		})
	}
	if got := n.Load(); got != 0 {
		t.Fatalf("expected no request to OpenBao, got %d", got)
	}
}

func TestKubernetesAuth_LoginFailures(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
		want   string
	}{
		"refused":   {http.StatusBadRequest, `{"errors":["invalid role name \"imas-role\""]}`, `status 400: invalid role name "imas-role"`},
		"forbidden": {http.StatusForbidden, `{"errors":["permission denied"]}`, "status 403: permission denied"},
		"no token":  {http.StatusOK, `{"auth":null}`, "no auth.client_token"},
		"empty 200": {http.StatusOK, ``, "no auth.client_token"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			setK8sEnv(t, srv.URL, writeJWT(t, "sa-jwt"))
			c, err := NewFromEnv(testEnv, testErrs)
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Token(t.Context())
			if !errors.Is(err, errTestAuth) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want errTestAuth containing %q", err, tc.want)
			}
		})
	}
}

// TestKubernetesAuth_LoginStatusIsNotTheRequestStatus: callers branch on
// a request's status (404 = absent, 400 = check-and-set lost). A login
// refused with that same status must not be mistaken for it.
func TestKubernetesAuth_LoginStatusIsNotTheRequestStatus(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusBadRequest, http.StatusConflict} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var kv atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/login") {
					w.WriteHeader(status)
					w.Write([]byte(`{"errors":["no handler for route"]}`))
					return
				}
				kv.Add(1)
			}))
			defer srv.Close()
			setK8sEnv(t, srv.URL, writeJWT(t, "sa-jwt"))
			c, err := NewFromEnv(testEnv, testErrs)
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Put(t.Context(), "secret/data/p", map[string]any{})
			if !errors.Is(err, errTestAuth) || !strings.Contains(err.Error(), "no handler for route") {
				t.Fatalf("got %v, want errTestAuth with OpenBao's message", err)
			}
			if StatusCode(err) != 0 || IsNotFound(err) {
				t.Fatalf("login status leaked as the request's: StatusCode = %d", StatusCode(err))
			}
			if kv.Load() != 0 {
				t.Fatal("request sent despite the failed login")
			}
		})
	}
}

func TestKubernetesAuth_Unreachable(t *testing.T) {
	setK8sEnv(t, "http://127.0.0.1:1", writeJWT(t, "sa-jwt"))
	c, err := NewFromEnv(testEnv, testErrs)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, err := c.Token(ctx); !errors.Is(err, errTestAuth) {
		t.Fatalf("expected the auth sentinel, got %v", err)
	}
}

func TestClose(t *testing.T) {
	setTokenEnv(t, "http://127.0.0.1:1", "tok")
	c, err := NewFromEnv(testEnv, testErrs)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	c.Close()
}
