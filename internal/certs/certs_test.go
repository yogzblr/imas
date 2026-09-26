package certs

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/config"
)

// setupTLSConfigDir sets config globals to use a temp directory for TLS
// cert tests, and resets any OpenBao lease tracked by a previous test.
func setupTLSConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	config.RootCA = filepath.Join(dir, "rootCA.pem")
	config.CertFile = filepath.Join(dir, "cert.pem")
	config.KeyFile = filepath.Join(dir, "key.pem")
	config.CertHosts = []string{"localhost", "127.0.0.1"}
	config.FarmerOrganization = "imas-test"
	config.CertificateValidTime = 24 * time.Hour
	rememberLease("")
	return dir
}

// setupNKeyConfigDir sets config globals to use a temp directory for NKey tests.
func setupNKeyConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	config.NKeyFarmerPrivFile = filepath.Join(dir, "farmer.nkey")
	config.NKeyFarmerPubFile = filepath.Join(dir, "farmer.pub")
	config.NKeySproutPrivFile = filepath.Join(dir, "sprout.nkey")
	config.NKeySproutPubFile = filepath.Join(dir, "sprout.pub")
	return dir
}

// --- OpenBao integration test scaffolding -----------------------------
//
// These tests need a running OpenBao (or Vault-API-compatible) dev
// server. Start one locally with:
//
//	bao server -dev -dev-root-token-id=root
//
// and the tests will find it at http://127.0.0.1:8200 by default; point
// them elsewhere with IMAS_CERTS_TEST_OPENBAO_ADDR /
// IMAS_CERTS_TEST_OPENBAO_TOKEN. Each test mounts its own throwaway PKI
// backend (unmounted on cleanup) so tests don't interfere with each
// other or require any pre-existing server configuration. When no dev
// server is reachable, these tests skip rather than fail, so `go test
// ./...` still passes in environments without OpenBao available.

const (
	testOpenBaoAddrEnv  = "IMAS_CERTS_TEST_OPENBAO_ADDR"
	testOpenBaoTokenEnv = "IMAS_CERTS_TEST_OPENBAO_TOKEN"
)

func obAdminRequest(t *testing.T, addr, token, method, path string, body any) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal openbao admin request body: %v", err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, addr+path, reader)
	if err != nil {
		t.Fatalf("build openbao admin request: %v", err)
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("openbao admin request %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		t.Fatalf("openbao admin request %s %s failed: status %d: %s", method, path, resp.StatusCode, string(data))
	}
}

// resolveTestOpenBaoServer resolves the local OpenBao dev server address
// and root token to use for integration tests (defaulting to
// http://127.0.0.1:8200 / "root", overridable via
// IMAS_CERTS_TEST_OPENBAO_ADDR / IMAS_CERTS_TEST_OPENBAO_TOKEN), and skips
// the calling test if no dev server is reachable there.
func resolveTestOpenBaoServer(t *testing.T) (addr, token string) {
	t.Helper()
	addr = os.Getenv(testOpenBaoAddrEnv)
	if addr == "" {
		addr = "http://127.0.0.1:8200"
	}
	token = os.Getenv(testOpenBaoTokenEnv)
	if token == "" {
		token = "root"
	}

	healthClient := http.Client{Timeout: 2 * time.Second}
	resp, err := healthClient.Get(addr + "/v1/sys/health")
	if err != nil {
		t.Skipf("no local OpenBao dev server reachable at %s (start one with "+
			"`bao server -dev -dev-root-token-id=%s`): %v", addr, token, err)
	}
	resp.Body.Close()
	return addr, token
}

// setupOpenBaoPKI mounts a fresh PKI secrets engine and a permissive test
// role on a local OpenBao dev server, points the certs package at it via
// the IMAS_CERTS_OPENBAO_* environment variables, and skips the test if
// no dev server is reachable.
func setupOpenBaoPKI(t *testing.T) {
	t.Helper()
	addr, token := resolveTestOpenBaoServer(t)

	mount := fmt.Sprintf("pki-imas-test-%d", time.Now().UnixNano())
	role := "imas-test"

	obAdminRequest(t, addr, token, http.MethodPost, "/v1/sys/mounts/"+mount, map[string]string{"type": "pki"})
	t.Cleanup(func() {
		req, err := http.NewRequest(http.MethodDelete, addr+"/v1/sys/mounts/"+mount, nil)
		if err != nil {
			return
		}
		req.Header.Set("X-Vault-Token", token)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	})
	obAdminRequest(t, addr, token, http.MethodPost, "/v1/sys/mounts/"+mount+"/tune",
		map[string]string{"max_lease_ttl": "720h"})
	obAdminRequest(t, addr, token, http.MethodPost, "/v1/"+mount+"/root/generate/internal",
		map[string]string{"common_name": "imas-test-root", "ttl": "720h"})
	// Permissive role: these tests exercise the certs package's OpenBao
	// client, not OpenBao's own domain/IP allowlisting policy.
	obAdminRequest(t, addr, token, http.MethodPost, "/v1/"+mount+"/roles/"+role, map[string]any{
		"allow_any_name":    true,
		"allow_ip_sans":     true,
		"allow_subdomains":  true,
		"enforce_hostnames": false,
		"max_ttl":           "24h",
		"ttl":               "1h",
		"generate_lease":    true,
	})

	t.Setenv(EnvOpenBaoAddr, addr)
	t.Setenv(EnvOpenBaoToken, token)
	t.Setenv(EnvOpenBaoPKIMount, mount)
	t.Setenv(EnvOpenBaoRole, role)
}

// setupOpenBaoTLS combines setupTLSConfigDir and setupOpenBaoPKI for the
// common case of a test that needs both.
func setupOpenBaoTLS(t *testing.T) string {
	t.Helper()
	dir := setupTLSConfigDir(t)
	setupOpenBaoPKI(t)
	return dir
}

// --- Kubernetes auth test scaffolding -----------------------------------
//
// OpenBao's kubernetes auth method validates a login by (1) optionally
// checking the JWT's signature locally against configured pem_keys (these
// tests configure none, which is one of OpenBao's own supported modes --
// see internal/builtin/credential/kubernetes/path_login.go's
// parseAndValidateJWT in a local openbao/openbao checkout: "we don't
// verify the signature if we aren't configured with public keys"), then
// (2) unconditionally calling the Kubernetes API's TokenReview endpoint
// to confirm the token is still live. (2) is real cluster infrastructure
// this repo has no access to, so these tests fake just that one HTTP
// endpoint (newFakeK8sTokenReviewServer) and point a real local OpenBao
// dev server's kubernetes_host at it. Every other part of the flow --
// OpenBao itself, this package's login/token-refresh code, the resulting
// token actually being used for PKI calls -- is genuine, not mocked.

// newFakeK8sTokenReviewServer starts a local HTTP server implementing
// just enough of the Kubernetes TokenReview API
// (POST /apis/authentication.k8s.io/v1/tokenreviews) for OpenBao's
// kubernetes auth method to complete a login against it. It always
// reports the token as authenticated for the given identity, regardless
// of the token's actual signature (verified against a live OpenBao dev
// server: OpenBao only checks the signature itself when pem_keys is
// configured -- these tests don't -- so this mirrors a real, supported
// OpenBao configuration, not a shortcut around one).
func newFakeK8sTokenReviewServer(t *testing.T, namespace, name, uid string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/apis/authentication.k8s.io/v1/tokenreviews", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"kind":       "TokenReview",
			"apiVersion": "authentication.k8s.io/v1",
			"status": map[string]any{
				"authenticated": true,
				"user": map[string]any{
					"username": fmt.Sprintf("system:serviceaccount:%s:%s", namespace, name),
					"uid":      uid,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// writeFixtureK8sJWT builds a JWT shaped like a Kubernetes projected
// service account token -- enough for OpenBao's kubernetes auth backend
// to parse the claims it needs (namespace/serviceaccount name/uid) -- and
// writes it to a temp file, returning the path. Its signature is garbage;
// see newFakeK8sTokenReviewServer's doc comment for why that's fine here.
func writeFixtureK8sJWT(t *testing.T, namespace, name, uid string) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal JWT fixture segment: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := enc(map[string]string{"alg": "RS256", "typ": "JWT"})
	payload := enc(map[string]any{
		"iss": "kubernetes/serviceaccount",
		"kubernetes.io": map[string]any{
			"namespace":      namespace,
			"serviceaccount": map[string]any{"name": name, "uid": uid},
		},
	})
	sig := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte("x"), 32))
	jwt := header + "." + payload + "." + sig

	path := filepath.Join(t.TempDir(), "sa-token")
	if err := os.WriteFile(path, []byte(jwt), 0o600); err != nil {
		t.Fatalf("write fixture SA JWT: %v", err)
	}
	return path
}

// setupOpenBaoKubernetesAuth enables and configures OpenBao's kubernetes
// auth method on a real local OpenBao dev server, pointed at a fake local
// TokenReview server (see newFakeK8sTokenReviewServer), and creates a
// role bound to a fixture service account. It returns the auth mount and
// role names and a path to a fixture SA JWT for that service account,
// ready to plug into IMAS_CERTS_OPENBAO_K8S_*.
func setupOpenBaoKubernetesAuth(t *testing.T, addr, token string) (mount, role, jwtPath string) {
	t.Helper()
	const namespace = "default"
	const saName = "imas"
	const saUID = "11111111-1111-1111-1111-111111111111"

	reviewSrv := newFakeK8sTokenReviewServer(t, namespace, saName, saUID)

	// disable_local_ca_jwt=true (rather than relying on OpenBao reading
	// /var/run/secrets/kubernetes.io/serviceaccount/{ca.crt,token} off its
	// own local disk, which doesn't exist in this sandbox either) requires
	// kubernetes_ca_cert to be set; the fake TokenReview server is plain
	// HTTP, so this cert is never actually used to verify anything, only
	// to satisfy that config-time requirement.
	fakeCACertPEM := generateFixtureCAPEM(t)

	mount = fmt.Sprintf("kubernetes-imas-test-%d", time.Now().UnixNano())
	role = "imas-test"

	// setupOpenBaoPKI mounts PKI backends at "pki-imas-test-<nanotime>";
	// grant this login's token access to that whole family of test mounts
	// (rather than "default", which has no PKI access at all) so the
	// resulting token can actually complete a certificate issuance, not
	// just a login.
	obAdminRequest(t, addr, token, http.MethodPut, "/v1/sys/policies/acl/imas-test-pki-access", map[string]string{
		"policy": `
path "pki-imas-test-*" {
  capabilities = ["create", "read", "update", "list"]
}
path "sys/leases/renew" {
  capabilities = ["update"]
}
`,
	})

	obAdminRequest(t, addr, token, http.MethodPost, "/v1/sys/auth/"+mount, map[string]string{"type": "kubernetes"})
	t.Cleanup(func() {
		req, err := http.NewRequest(http.MethodDelete, addr+"/v1/sys/auth/"+mount, nil)
		if err != nil {
			return
		}
		req.Header.Set("X-Vault-Token", token)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	})
	obAdminRequest(t, addr, token, http.MethodPost, "/v1/auth/"+mount+"/config", map[string]any{
		"kubernetes_host":      reviewSrv.URL,
		"disable_local_ca_jwt": true,
		"kubernetes_ca_cert":   string(fakeCACertPEM),
	})
	obAdminRequest(t, addr, token, http.MethodPost, "/v1/auth/"+mount+"/role/"+role, map[string]any{
		"bound_service_account_names":      []string{saName},
		"bound_service_account_namespaces": []string{namespace},
		"policies":                         []string{"imas-test-pki-access"},
		"ttl":                              "1h",
	})

	jwtPath = writeFixtureK8sJWT(t, namespace, saName, saUID)
	return mount, role, jwtPath
}

// TestGenCertKubernetesAuthOpenBao exercises the entire kubernetes-auth
// path for real: a genuine login against a real OpenBao dev server (only
// the Kubernetes TokenReview call behind it is faked), the resulting
// token actually being used to fetch the CA and issue a certificate, all
// through the public GenCert entry point -- the same one the static-token
// tests above use, proving both auth methods reach the same PKI logic.
func TestGenCertKubernetesAuthOpenBao(t *testing.T) {
	setupOpenBaoTLS(t)
	addr := os.Getenv(EnvOpenBaoAddr)
	token := os.Getenv(EnvOpenBaoToken)

	k8sMount, k8sRole, jwtPath := setupOpenBaoKubernetesAuth(t, addr, token)

	// Blank the static token entirely to prove this path doesn't fall
	// back to it.
	t.Setenv(EnvOpenBaoToken, "")
	t.Setenv(EnvOpenBaoAuthMethod, AuthMethodKubernetes)
	t.Setenv(EnvOpenBaoK8sMount, k8sMount)
	t.Setenv(EnvOpenBaoK8sRole, k8sRole)
	t.Setenv(EnvOpenBaoK8sJWTPath, jwtPath)

	if err := GenCert(); err != nil {
		t.Fatalf("GenCert via kubernetes auth failed: %v", err)
	}
	if _, err := os.Stat(config.CertFile); err != nil {
		t.Fatalf("cert file should exist: %v", err)
	}
	if _, err := os.Stat(config.KeyFile); err != nil {
		t.Fatalf("key file should exist: %v", err)
	}
	if _, err := os.Stat(config.RootCA); err != nil {
		t.Fatalf("CA cert file should exist: %v", err)
	}
}

// TestObClientKubernetesAuthInvalidRoleOpenBao verifies, against a real
// OpenBao dev server, that logging in against a role that doesn't exist
// fails clearly -- this happens before OpenBao would even attempt a
// TokenReview call, so no fake Kubernetes API is needed for this one.
func TestObClientKubernetesAuthInvalidRoleOpenBao(t *testing.T) {
	addr, token := resolveTestOpenBaoServer(t)
	mount := fmt.Sprintf("kubernetes-imas-test-%d", time.Now().UnixNano())
	obAdminRequest(t, addr, token, http.MethodPost, "/v1/sys/auth/"+mount, map[string]string{"type": "kubernetes"})
	t.Cleanup(func() {
		req, err := http.NewRequest(http.MethodDelete, addr+"/v1/sys/auth/"+mount, nil)
		if err != nil {
			return
		}
		req.Header.Set("X-Vault-Token", token)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	})
	jwtPath := writeFixtureK8sJWT(t, "default", "imas", "11111111-1111-1111-1111-111111111111")

	t.Setenv(EnvOpenBaoAddr, addr)
	t.Setenv(EnvOpenBaoAuthMethod, AuthMethodKubernetes)
	t.Setenv(EnvOpenBaoK8sMount, mount)
	t.Setenv(EnvOpenBaoK8sRole, "does-not-exist")
	t.Setenv(EnvOpenBaoK8sJWTPath, jwtPath)
	t.Setenv(EnvOpenBaoRole, "pki-role-unused")

	client, err := newClientFromEnv()
	if err != nil {
		t.Fatalf("newClientFromEnv: %v", err)
	}
	_, err = client.currentToken(context.Background())
	if !errors.Is(err, ErrK8sAuthFailed) {
		t.Fatalf("expected ErrK8sAuthFailed, got %v", err)
	}
	if !strings.Contains(err.Error(), "invalid role name") {
		t.Fatalf("expected OpenBao's own 'invalid role name' message, got: %v", err)
	}
}

// TestObClientKubernetesAuthUnreachableK8sAPIOpenBao verifies, against a
// real OpenBao dev server, what happens when OpenBao's own TokenReview
// call can't reach kubernetes_host at all (nothing listens on
// 127.0.0.1:1, so the connection is refused immediately).
func TestObClientKubernetesAuthUnreachableK8sAPIOpenBao(t *testing.T) {
	addr, token := resolveTestOpenBaoServer(t)
	mount := fmt.Sprintf("kubernetes-imas-test-%d", time.Now().UnixNano())
	obAdminRequest(t, addr, token, http.MethodPost, "/v1/sys/auth/"+mount, map[string]string{"type": "kubernetes"})
	t.Cleanup(func() {
		req, err := http.NewRequest(http.MethodDelete, addr+"/v1/sys/auth/"+mount, nil)
		if err != nil {
			return
		}
		req.Header.Set("X-Vault-Token", token)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	})
	fakeCACertPEM := generateFixtureCAPEM(t)
	obAdminRequest(t, addr, token, http.MethodPost, "/v1/auth/"+mount+"/config", map[string]any{
		"kubernetes_host":      "http://127.0.0.1:1",
		"disable_local_ca_jwt": true,
		"kubernetes_ca_cert":   string(fakeCACertPEM),
	})
	obAdminRequest(t, addr, token, http.MethodPost, "/v1/auth/"+mount+"/role/imas-test", map[string]any{
		"bound_service_account_names":      []string{"imas"},
		"bound_service_account_namespaces": []string{"default"},
		"policies":                         []string{"default"},
		"ttl":                              "1h",
	})
	jwtPath := writeFixtureK8sJWT(t, "default", "imas", "11111111-1111-1111-1111-111111111111")

	t.Setenv(EnvOpenBaoAddr, addr)
	t.Setenv(EnvOpenBaoAuthMethod, AuthMethodKubernetes)
	t.Setenv(EnvOpenBaoK8sMount, mount)
	t.Setenv(EnvOpenBaoK8sRole, "imas-test")
	t.Setenv(EnvOpenBaoK8sJWTPath, jwtPath)
	t.Setenv(EnvOpenBaoRole, "pki-role-unused")

	client, err := newClientFromEnv()
	if err != nil {
		t.Fatalf("newClientFromEnv: %v", err)
	}
	_, err = client.currentToken(context.Background())
	if !errors.Is(err, ErrK8sAuthFailed) {
		t.Fatalf("expected ErrK8sAuthFailed, got %v", err)
	}
	// Honesty note (see also the PR description): OpenBao's kubernetes
	// auth backend collapses every post-JWT-parse login failure --
	// including this one, where OpenBao's own TokenReview call couldn't
	// even connect -- into a generic "permission denied" response
	// (internal/builtin/credential/kubernetes/path_login.go's pathLogin
	// maps any lookup() error to logical.ErrPermissionDenied). Verified
	// directly against a live OpenBao dev server: this is OpenBao's own
	// behavior, not a gap in this client. So an unreachable
	// kubernetes_host is NOT distinguishable from an invalid/rejected JWT
	// by OpenBao's response text alone -- both read "permission denied".
	// Only ErrK8sJWTUnavailable (this process's own SA token file being
	// unreadable, checked before any request to OpenBao is made) is
	// reliably distinguishable as a category from "OpenBao rejected it".
	if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("expected OpenBao's 'permission denied' response, got: %v", err)
	}
}

// --- Kubernetes auth unit tests against a fake OpenBao server -----------

func setupK8sAuthEnv(t *testing.T, addr, jwtPath, role string) {
	t.Helper()
	t.Setenv(EnvOpenBaoAddr, addr)
	t.Setenv(EnvOpenBaoAuthMethod, AuthMethodKubernetes)
	t.Setenv(EnvOpenBaoK8sRole, role)
	t.Setenv(EnvOpenBaoK8sJWTPath, jwtPath)
	t.Setenv(EnvOpenBaoRole, "pki-role-unused")
}

func TestObClientKubernetesTokenCachedBetweenCalls(t *testing.T) {
	jwtPath := writeFixtureK8sJWT(t, "default", "imas", "uid-1")
	var loginCalls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/kubernetes/login", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&loginCalls, 1)
		w.Write([]byte(`{"auth":{"client_token":"tok-1","lease_duration":3600,"renewable":true}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	setupK8sAuthEnv(t, srv.URL, jwtPath, "test-role")

	client, err := newClientFromEnv()
	if err != nil {
		t.Fatalf("newClientFromEnv: %v", err)
	}
	ctx := context.Background()
	tok1, err := client.currentToken(ctx)
	if err != nil {
		t.Fatalf("first currentToken: %v", err)
	}
	if tok1 != "tok-1" {
		t.Fatalf("expected tok-1, got %q", tok1)
	}
	tok2, err := client.currentToken(ctx)
	if err != nil {
		t.Fatalf("second currentToken: %v", err)
	}
	if tok2 != "tok-1" {
		t.Fatalf("expected cached tok-1, got %q", tok2)
	}
	if calls := atomic.LoadInt32(&loginCalls); calls != 1 {
		t.Fatalf("expected exactly 1 login call for 2 currentToken calls, got %d", calls)
	}
}

func TestObClientKubernetesTokenReLoginNearExpiry(t *testing.T) {
	jwtPath := writeFixtureK8sJWT(t, "default", "imas", "uid-1")
	var loginCalls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/kubernetes/login", func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&loginCalls, 1)
		fmt.Fprintf(w, `{"auth":{"client_token":"tok-%d","lease_duration":3600,"renewable":true}}`, n)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	setupK8sAuthEnv(t, srv.URL, jwtPath, "test-role")

	client, err := newClientFromEnv()
	if err != nil {
		t.Fatalf("newClientFromEnv: %v", err)
	}
	ctx := context.Background()
	tok1, err := client.currentToken(ctx)
	if err != nil {
		t.Fatalf("first currentToken: %v", err)
	}
	if tok1 != "tok-1" {
		t.Fatalf("expected tok-1, got %q", tok1)
	}

	// Simulate the cached token having fallen within its safety margin,
	// without waiting a real hour for a 3600s lease to run down.
	client.authMu.Lock()
	client.authExpiry = time.Now().Add(-time.Second)
	client.authMu.Unlock()

	tok2, err := client.currentToken(ctx)
	if err != nil {
		t.Fatalf("second currentToken: %v", err)
	}
	if tok2 != "tok-2" {
		t.Fatalf("expected a fresh token (tok-2) after simulated near-expiry, got %q", tok2)
	}
	if calls := atomic.LoadInt32(&loginCalls); calls != 2 {
		t.Fatalf("expected exactly 2 login calls, got %d", calls)
	}
}

func TestObClientKubernetesJWTFileMissing(t *testing.T) {
	setupK8sAuthEnv(t, "http://127.0.0.1:0", filepath.Join(t.TempDir(), "does-not-exist"), "test-role")

	client, err := newClientFromEnv()
	if err != nil {
		t.Fatalf("newClientFromEnv: %v", err)
	}
	_, err = client.currentToken(context.Background())
	if !errors.Is(err, ErrK8sJWTUnavailable) {
		t.Fatalf("expected ErrK8sJWTUnavailable, got %v", err)
	}
}

func TestObClientKubernetesJWTFileEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty-token")
	if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("write empty token file: %v", err)
	}
	setupK8sAuthEnv(t, "http://127.0.0.1:0", path, "test-role")

	client, err := newClientFromEnv()
	if err != nil {
		t.Fatalf("newClientFromEnv: %v", err)
	}
	_, err = client.currentToken(context.Background())
	if !errors.Is(err, ErrK8sJWTUnavailable) {
		t.Fatalf("expected ErrK8sJWTUnavailable, got %v", err)
	}
}

func TestObClientKubernetesLoginNon200(t *testing.T) {
	jwtPath := writeFixtureK8sJWT(t, "default", "imas", "uid-1")
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/kubernetes/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"errors":["permission denied"]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	setupK8sAuthEnv(t, srv.URL, jwtPath, "test-role")

	client, err := newClientFromEnv()
	if err != nil {
		t.Fatalf("newClientFromEnv: %v", err)
	}
	_, err = client.currentToken(context.Background())
	if !errors.Is(err, ErrK8sAuthFailed) {
		t.Fatalf("expected ErrK8sAuthFailed, got %v", err)
	}
}

func TestObClientKubernetesLoginMissingToken(t *testing.T) {
	jwtPath := writeFixtureK8sJWT(t, "default", "imas", "uid-1")
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/kubernetes/login", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"auth":null}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	setupK8sAuthEnv(t, srv.URL, jwtPath, "test-role")

	client, err := newClientFromEnv()
	if err != nil {
		t.Fatalf("newClientFromEnv: %v", err)
	}
	_, err = client.currentToken(context.Background())
	if !errors.Is(err, ErrK8sAuthFailed) {
		t.Fatalf("expected ErrK8sAuthFailed, got %v", err)
	}
}

func TestNewClientFromEnvMissingK8sRole(t *testing.T) {
	t.Setenv(EnvOpenBaoAddr, "http://127.0.0.1:8200")
	t.Setenv(EnvOpenBaoAuthMethod, AuthMethodKubernetes)
	t.Setenv(EnvOpenBaoK8sRole, "")
	t.Setenv(EnvOpenBaoRole, "pki-role-unused")

	_, err := newClientFromEnv()
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

func TestNewClientFromEnvUnknownAuthMethod(t *testing.T) {
	t.Setenv(EnvOpenBaoAddr, "http://127.0.0.1:8200")
	t.Setenv(EnvOpenBaoAuthMethod, "bogus")
	t.Setenv(EnvOpenBaoRole, "pki-role-unused")

	_, err := newClientFromEnv()
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("expected error to name the bad AUTH_METHOD value, got: %v", err)
	}
}

func TestGenCACertOpenBao(t *testing.T) {
	setupOpenBaoTLS(t)

	if err := genCACert(); err != nil {
		t.Fatalf("genCACert failed: %v", err)
	}

	certBytes, err := os.ReadFile(config.RootCA)
	if err != nil {
		t.Fatalf("failed to read CA cert: %v", err)
	}
	block, _ := pem.Decode(certBytes)
	if block == nil {
		t.Fatal("failed to decode CA cert PEM")
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("expected CERTIFICATE PEM block, got %s", block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}
	if !cert.IsCA {
		t.Fatal("fetched certificate should be a CA")
	}
}

func TestGenCACertIdempotentOpenBao(t *testing.T) {
	setupOpenBaoTLS(t)

	if err := genCACert(); err != nil {
		t.Fatalf("genCACert failed: %v", err)
	}
	orig, err := os.ReadFile(config.RootCA)
	if err != nil {
		t.Fatalf("failed to read CA cert: %v", err)
	}

	if err := genCACert(); err != nil {
		t.Fatalf("genCACert second call failed: %v", err)
	}
	again, err := os.ReadFile(config.RootCA)
	if err != nil {
		t.Fatalf("failed to read CA cert after second call: %v", err)
	}

	if !bytes.Equal(orig, again) {
		t.Fatal("genCACert should fetch the same stable CA certificate on each call")
	}
}

func TestGenCertOpenBao(t *testing.T) {
	setupOpenBaoTLS(t)

	if err := GenCert(); err != nil {
		t.Fatalf("GenCert failed: %v", err)
	}

	certBytes, err := os.ReadFile(config.CertFile)
	if err != nil {
		t.Fatalf("failed to read server cert: %v", err)
	}
	block, _ := pem.Decode(certBytes)
	if block == nil {
		t.Fatal("failed to decode server cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse server certificate: %v", err)
	}
	if cert.IsCA {
		t.Fatal("server certificate should not be a CA")
	}

	foundLocalhost := false
	for _, name := range cert.DNSNames {
		if name == "localhost" {
			foundLocalhost = true
		}
	}
	if !foundLocalhost {
		t.Fatal("server cert should have localhost in DNSNames")
	}
	foundIP := false
	for _, ip := range cert.IPAddresses {
		if ip.String() == "127.0.0.1" {
			foundIP = true
		}
	}
	if !foundIP {
		t.Fatal("server cert should have 127.0.0.1 in IPAddresses")
	}

	keyBytes, err := os.ReadFile(config.KeyFile)
	if err != nil {
		t.Fatalf("failed to read server key: %v", err)
	}
	if block, _ := pem.Decode(keyBytes); block == nil {
		t.Fatal("failed to decode server key PEM")
	}
	info, err := os.Stat(config.KeyFile)
	if err != nil {
		t.Fatalf("failed to stat key file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected key file permissions 0600, got %o", info.Mode().Perm())
	}

	caBytes, err := os.ReadFile(config.RootCA)
	if err != nil {
		t.Fatalf("failed to read CA cert: %v", err)
	}
	caBlock, _ := pem.Decode(caBytes)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		t.Fatalf("server cert should verify against the OpenBao-issued CA: %v", err)
	}
}

func TestGenCertIdempotentOpenBao(t *testing.T) {
	setupOpenBaoTLS(t)

	if err := GenCert(); err != nil {
		t.Fatalf("GenCert failed: %v", err)
	}
	orig, err := os.ReadFile(config.CertFile)
	if err != nil {
		t.Fatalf("failed to read original cert: %v", err)
	}

	if err := GenCert(); err != nil {
		t.Fatalf("GenCert second call failed: %v", err)
	}
	again, err := os.ReadFile(config.CertFile)
	if err != nil {
		t.Fatalf("failed to read cert after second call: %v", err)
	}
	if !bytes.Equal(orig, again) {
		t.Fatal("GenCert should be idempotent when a cert and key already exist — it should not call OpenBao again")
	}
}

func TestGenCertDNSOnlyOpenBao(t *testing.T) {
	setupOpenBaoTLS(t)
	config.CertHosts = []string{"example.com", "foo.example.com"}

	if err := GenCert(); err != nil {
		t.Fatalf("GenCert failed: %v", err)
	}
	certBytes, err := os.ReadFile(config.CertFile)
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}
	block, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}
	if len(cert.IPAddresses) != 0 {
		t.Fatalf("expected no IP SANs for DNS-only hosts, got %v", cert.IPAddresses)
	}
	if len(cert.DNSNames) != 2 {
		t.Fatalf("expected 2 DNS SANs, got %d: %v", len(cert.DNSNames), cert.DNSNames)
	}
}

func TestGenCertIPOnlyOpenBao(t *testing.T) {
	setupOpenBaoTLS(t)
	config.CertHosts = []string{"10.0.0.1", "10.0.0.2"}

	if err := GenCert(); err != nil {
		t.Fatalf("GenCert failed: %v", err)
	}
	certBytes, err := os.ReadFile(config.CertFile)
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}
	block, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}
	if len(cert.DNSNames) != 0 {
		t.Fatalf("expected no DNS SANs for IP-only hosts, got %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 2 {
		t.Fatalf("expected 2 IP SANs, got %d: %v", len(cert.IPAddresses), cert.IPAddresses)
	}
}

func TestGenCertEmptyHostsOpenBao(t *testing.T) {
	setupOpenBaoTLS(t)
	config.CertHosts = []string{}

	if err := GenCert(); err != nil {
		t.Fatalf("GenCert failed: %v", err)
	}
	certBytes, err := os.ReadFile(config.CertFile)
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}
	block, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}
	if len(cert.DNSNames) != 0 {
		t.Fatalf("expected no DNS SANs, got %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 0 {
		t.Fatalf("expected no IP SANs, got %v", cert.IPAddresses)
	}
}

func TestRotateTLSCertsNoRotationNeededOpenBao(t *testing.T) {
	setupOpenBaoTLS(t)
	config.CertHosts = []string{"localhost"}
	config.CertificateValidTime = 1 * time.Hour

	if err := GenCert(); err != nil {
		t.Fatalf("GenCert failed: %v", err)
	}
	orig, err := os.ReadFile(config.CertFile)
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}

	rotated, err := RotateTLSCerts(1 * time.Minute)
	if err != nil {
		t.Fatalf("RotateTLSCerts error: %v", err)
	}
	if rotated {
		t.Fatal("expected no rotation when the cert is still well within its validity window")
	}
	again, err := os.ReadFile(config.CertFile)
	if err != nil {
		t.Fatalf("failed to read cert after rotation check: %v", err)
	}
	if !bytes.Equal(orig, again) {
		t.Fatal("cert should not have changed")
	}
}

func TestRotateTLSCertsReissuesWhenDueOpenBao(t *testing.T) {
	setupOpenBaoTLS(t)
	config.CertHosts = []string{"localhost"}
	// Short-lived cert so it's immediately within any sane rotation threshold.
	config.CertificateValidTime = 30 * time.Second

	if err := GenCert(); err != nil {
		t.Fatalf("GenCert failed: %v", err)
	}
	orig, err := os.ReadFile(config.CertFile)
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}

	// Threshold far exceeds the cert's ~30s validity, so rotation is due.
	// OpenBao's PKI engine reports the resulting lease as non-renewable
	// (verified against a live dev server), so this exercises the
	// renew-fails-then-reissue path end to end against real OpenBao.
	rotated, err := RotateTLSCerts(1 * time.Hour)
	if err != nil {
		t.Fatalf("RotateTLSCerts error: %v", err)
	}
	if !rotated {
		t.Fatal("expected rotation when the cert is due to expire")
	}
	again, err := os.ReadFile(config.CertFile)
	if err != nil {
		t.Fatalf("failed to read cert after rotation: %v", err)
	}
	if bytes.Equal(orig, again) {
		t.Fatal("cert should have changed after rotation")
	}

	block, _ := pem.Decode(again)
	if block == nil {
		t.Fatal("new cert should be valid PEM")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("new cert should be parseable: %v", err)
	}
}

func TestRotateTLSCertsMissingCertOpenBao(t *testing.T) {
	setupOpenBaoTLS(t)
	config.CertHosts = []string{"localhost"}

	rotated, err := RotateTLSCerts(1 * time.Hour)
	if err != nil {
		t.Fatalf("RotateTLSCerts error: %v", err)
	}
	if !rotated {
		t.Fatal("expected rotation when cert doesn't exist")
	}
	if _, err := os.Stat(config.CertFile); err != nil {
		t.Fatalf("cert file should exist after rotation: %v", err)
	}
}

func TestRotateTLSCertsCorruptPEMOpenBao(t *testing.T) {
	setupOpenBaoTLS(t)
	config.CertHosts = []string{"localhost"}

	if err := os.WriteFile(config.CertFile, []byte("not a pem"), 0o644); err != nil {
		t.Fatalf("failed to write corrupt cert: %v", err)
	}

	rotated, err := RotateTLSCerts(1 * time.Hour)
	if err != nil {
		t.Fatalf("RotateTLSCerts error: %v", err)
	}
	if !rotated {
		t.Fatal("expected rotation when cert PEM is corrupt")
	}
	certBytes, err := os.ReadFile(config.CertFile)
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}
	if block, _ := pem.Decode(certBytes); block == nil {
		t.Fatal("new cert should be valid PEM")
	}
}

func TestRotateTLSCertsInvalidDEROpenBao(t *testing.T) {
	setupOpenBaoTLS(t)
	config.CertHosts = []string{"localhost"}

	badPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not valid DER")})
	if err := os.WriteFile(config.CertFile, badPEM, 0o644); err != nil {
		t.Fatalf("failed to write bad cert: %v", err)
	}

	rotated, err := RotateTLSCerts(1 * time.Hour)
	if err != nil {
		t.Fatalf("RotateTLSCerts error: %v", err)
	}
	if !rotated {
		t.Fatal("expected rotation when cert DER is invalid")
	}
}

// TestRotateTLSCertsReadError doesn't need a live OpenBao server: the
// failure happens before any OpenBao call is made.
func TestRotateTLSCertsReadError(t *testing.T) {
	setupTLSConfigDir(t)

	if err := os.MkdirAll(config.CertFile, 0o755); err != nil {
		t.Fatalf("failed to create dir as CertFile: %v", err)
	}

	_, err := RotateTLSCerts(1 * time.Hour)
	if err == nil {
		t.Fatal("expected error when cert file cannot be read")
	}
}

func TestGenCertNotConfigured(t *testing.T) {
	setupTLSConfigDir(t)
	t.Setenv(EnvOpenBaoAddr, "")
	t.Setenv(EnvOpenBaoToken, "")
	t.Setenv(EnvOpenBaoRole, "")

	err := GenCert()
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

// --- Unit tests against a fake OpenBao HTTP server ---------------------
//
// These don't need a real dev server: they exercise error handling and
// the lease-renewal decision in RotateTLSCerts directly against a
// httptest fake, including the "OpenBao successfully renews the lease"
// branch that a stock PKI role (see TestRotateTLSCertsReissuesWhenDueOpenBao)
// never actually takes.

func generateFixtureCAPEM(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate fixture CA key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"imas-test-fixture"}},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create fixture CA cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func generateFixtureLeafPEM(t *testing.T, validFor time.Duration) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate fixture leaf key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(validFor),
		DNSNames:              []string{"localhost"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create fixture leaf cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func issueResponseFixtureJSON(t *testing.T, certPEM, keyPEM, leaseID string) []byte {
	t.Helper()
	resp := issueResponse{
		LeaseID:       leaseID,
		LeaseDuration: 3600,
		Data:          issueData{Certificate: certPEM, PrivateKey: keyPEM},
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal fixture issue response: %v", err)
	}
	return b
}

func TestGenCertCAFetchFails(t *testing.T) {
	dir := setupTLSConfigDir(t)
	_ = dir

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pki/ca/pem", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Setenv(EnvOpenBaoAddr, srv.URL)
	t.Setenv(EnvOpenBaoToken, "test-token")
	t.Setenv(EnvOpenBaoPKIMount, "pki")
	t.Setenv(EnvOpenBaoRole, "test-role")

	err := GenCert()
	if !errors.Is(err, ErrCAFetchFailed) {
		t.Fatalf("expected ErrCAFetchFailed, got %v", err)
	}
}

func TestGenCertIssueFails(t *testing.T) {
	setupTLSConfigDir(t)
	fixtureCA := generateFixtureCAPEM(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pki/ca/pem", func(w http.ResponseWriter, r *http.Request) {
		w.Write(fixtureCA)
	})
	mux.HandleFunc("/v1/pki/issue/test-role", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"errors":["boom"]}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Setenv(EnvOpenBaoAddr, srv.URL)
	t.Setenv(EnvOpenBaoToken, "test-token")
	t.Setenv(EnvOpenBaoPKIMount, "pki")
	t.Setenv(EnvOpenBaoRole, "test-role")

	err := GenCert()
	if !errors.Is(err, ErrIssueFailed) {
		t.Fatalf("expected ErrIssueFailed, got %v", err)
	}
}

func TestGenCertCertFileUnwritable(t *testing.T) {
	dir := setupTLSConfigDir(t)
	fixtureCA := generateFixtureCAPEM(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pki/ca/pem", func(w http.ResponseWriter, r *http.Request) {
		w.Write(fixtureCA)
	})
	mux.HandleFunc("/v1/pki/issue/test-role", func(w http.ResponseWriter, r *http.Request) {
		w.Write(issueResponseFixtureJSON(t, "CERTDATA", "KEYDATA", "lease-1"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	readonlyDir := filepath.Join(dir, "readonly")
	if err := os.MkdirAll(readonlyDir, 0o755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}
	config.CertFile = filepath.Join(readonlyDir, "cert.pem")
	if err := os.Chmod(readonlyDir, 0o555); err != nil {
		t.Fatalf("failed to chmod: %v", err)
	}
	defer os.Chmod(readonlyDir, 0o755)

	t.Setenv(EnvOpenBaoAddr, srv.URL)
	t.Setenv(EnvOpenBaoToken, "test-token")
	t.Setenv(EnvOpenBaoPKIMount, "pki")
	t.Setenv(EnvOpenBaoRole, "test-role")

	if err := GenCert(); err == nil {
		t.Fatal("GenCert should fail when the cert file cannot be written")
	}
}

func TestGenCertKeyFileUnwritable(t *testing.T) {
	dir := setupTLSConfigDir(t)
	fixtureCA := generateFixtureCAPEM(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pki/ca/pem", func(w http.ResponseWriter, r *http.Request) {
		w.Write(fixtureCA)
	})
	mux.HandleFunc("/v1/pki/issue/test-role", func(w http.ResponseWriter, r *http.Request) {
		w.Write(issueResponseFixtureJSON(t, "CERTDATA", "KEYDATA", "lease-1"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	readonlyDir := filepath.Join(dir, "readonly")
	if err := os.MkdirAll(readonlyDir, 0o755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}
	config.KeyFile = filepath.Join(readonlyDir, "key.pem")
	if err := os.Chmod(readonlyDir, 0o555); err != nil {
		t.Fatalf("failed to chmod: %v", err)
	}
	defer os.Chmod(readonlyDir, 0o755)

	t.Setenv(EnvOpenBaoAddr, srv.URL)
	t.Setenv(EnvOpenBaoToken, "test-token")
	t.Setenv(EnvOpenBaoPKIMount, "pki")
	t.Setenv(EnvOpenBaoRole, "test-role")

	if err := GenCert(); err == nil {
		t.Fatal("GenCert should fail when the key file cannot be written")
	}
}

func TestRotateTLSCertsLeaseRenewedSkipsReissue(t *testing.T) {
	setupTLSConfigDir(t)
	config.CertHosts = []string{"localhost"}
	config.CertificateValidTime = time.Hour

	// Seed a near-expiry "current" certificate. RotateTLSCerts only needs
	// to parse it for NotAfter here; the renewal decision happens before
	// any reissue (and thus before any chain-of-trust check) would occur.
	certPEM := generateFixtureLeafPEM(t, 30*time.Second)
	if err := os.WriteFile(config.CertFile, certPEM, 0o644); err != nil {
		t.Fatalf("failed to write fixture cert: %v", err)
	}
	if err := os.WriteFile(config.KeyFile, []byte("dummy"), 0o600); err != nil {
		t.Fatalf("failed to write fixture key: %v", err)
	}

	renewCalled := false
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/leases/renew", func(w http.ResponseWriter, r *http.Request) {
		renewCalled = true
		w.Write([]byte(`{"lease_id":"pki/issue/test-role/abc","lease_duration":7200,"renewable":true}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Setenv(EnvOpenBaoAddr, srv.URL)
	t.Setenv(EnvOpenBaoToken, "test-token")
	t.Setenv(EnvOpenBaoPKIMount, "pki")
	t.Setenv(EnvOpenBaoRole, "test-role")

	rememberLease("pki/issue/test-role/abc")
	t.Cleanup(func() { rememberLease("") })

	// Threshold (1h) far exceeds the fixture cert's ~30s remaining
	// validity, so rotation is due; OpenBao's fake renewal response grants
	// far more than the threshold, so no reissue should happen.
	rotated, err := RotateTLSCerts(1 * time.Hour)
	if err != nil {
		t.Fatalf("RotateTLSCerts error: %v", err)
	}
	if rotated {
		t.Fatal("expected no rotation when OpenBao renews the lease past the threshold")
	}
	if !renewCalled {
		t.Fatal("expected RotateTLSCerts to attempt an OpenBao lease renewal")
	}
	after, err := os.ReadFile(config.CertFile)
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}
	if !bytes.Equal(after, certPEM) {
		t.Fatal("cert should not have been rewritten when the lease was successfully renewed")
	}
}

func TestRotateTLSCertsLeaseRenewalFailsReissues(t *testing.T) {
	setupTLSConfigDir(t)
	config.CertHosts = []string{"localhost"}
	config.CertificateValidTime = time.Hour

	certPEM := generateFixtureLeafPEM(t, 30*time.Second)
	if err := os.WriteFile(config.CertFile, certPEM, 0o644); err != nil {
		t.Fatalf("failed to write fixture cert: %v", err)
	}
	if err := os.WriteFile(config.KeyFile, []byte("dummy"), 0o600); err != nil {
		t.Fatalf("failed to write fixture key: %v", err)
	}

	fixtureCA := generateFixtureCAPEM(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/leases/renew", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"errors":["lease is not renewable"]}`))
	})
	mux.HandleFunc("/v1/pki/ca/pem", func(w http.ResponseWriter, r *http.Request) {
		w.Write(fixtureCA)
	})
	mux.HandleFunc("/v1/pki/issue/test-role", func(w http.ResponseWriter, r *http.Request) {
		w.Write(issueResponseFixtureJSON(t, "NEWCERTPEM", "NEWKEYPEM", "lease-2"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Setenv(EnvOpenBaoAddr, srv.URL)
	t.Setenv(EnvOpenBaoToken, "test-token")
	t.Setenv(EnvOpenBaoPKIMount, "pki")
	t.Setenv(EnvOpenBaoRole, "test-role")

	rememberLease("pki/issue/test-role/abc")
	t.Cleanup(func() { rememberLease("") })

	rotated, err := RotateTLSCerts(1 * time.Hour)
	if err != nil {
		t.Fatalf("RotateTLSCerts error: %v", err)
	}
	if !rotated {
		t.Fatal("expected reissue when OpenBao reports the lease can't be renewed")
	}
	newCert, err := os.ReadFile(config.CertFile)
	if err != nil {
		t.Fatalf("failed to read cert: %v", err)
	}
	if string(newCert) != "NEWCERTPEM" {
		t.Fatalf("expected reissued certificate content, got %q", string(newCert))
	}
}

// --- NKey tests (unrelated to OpenBao; unchanged) -----------------------

func TestGenNKeyFarmer(t *testing.T) {
	setupNKeyConfigDir(t)

	if err := GenNKey(true); err != nil {
		t.Fatalf("GenNKey(true) failed: %v", err)
	}

	// Verify pub key file was created
	pubBytes, err := os.ReadFile(config.NKeyFarmerPubFile)
	if err != nil {
		t.Fatalf("failed to read farmer pub key: %v", err)
	}
	if len(pubBytes) == 0 {
		t.Fatal("farmer pub key file is empty")
	}
	if pubBytes[0] != 'U' {
		t.Fatalf("expected NATS user public key starting with 'U', got %c", pubBytes[0])
	}

	// Verify priv key file was created
	privBytes, err := os.ReadFile(config.NKeyFarmerPrivFile)
	if err != nil {
		t.Fatalf("failed to read farmer priv key: %v", err)
	}
	if len(privBytes) == 0 {
		t.Fatal("farmer priv key file is empty")
	}
	if privBytes[0] != 'S' {
		t.Fatalf("expected NATS seed starting with 'S', got %c", privBytes[0])
	}

	// Verify file permissions
	info, err := os.Stat(config.NKeyFarmerPrivFile)
	if err != nil {
		t.Fatalf("failed to stat farmer priv key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected priv key permissions 0600, got %o", info.Mode().Perm())
	}
	info, err = os.Stat(config.NKeyFarmerPubFile)
	if err != nil {
		t.Fatalf("failed to stat farmer pub key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected pub key permissions 0600, got %o", info.Mode().Perm())
	}
}

func TestGenNKeySprout(t *testing.T) {
	setupNKeyConfigDir(t)

	if err := GenNKey(false); err != nil {
		t.Fatalf("GenNKey(false) failed: %v", err)
	}

	pubBytes, err := os.ReadFile(config.NKeySproutPubFile)
	if err != nil {
		t.Fatalf("failed to read sprout pub key: %v", err)
	}
	if len(pubBytes) == 0 {
		t.Fatal("sprout pub key file is empty")
	}
	if pubBytes[0] != 'U' {
		t.Fatalf("expected NATS user public key starting with 'U', got %c", pubBytes[0])
	}

	privBytes, err := os.ReadFile(config.NKeySproutPrivFile)
	if err != nil {
		t.Fatalf("failed to read sprout priv key: %v", err)
	}
	if len(privBytes) == 0 {
		t.Fatal("sprout priv key file is empty")
	}
}

func TestGenNKeyIdempotent(t *testing.T) {
	setupNKeyConfigDir(t)

	if err := GenNKey(true); err != nil {
		t.Fatalf("GenNKey(true) failed: %v", err)
	}

	origPub, err := os.ReadFile(config.NKeyFarmerPubFile)
	if err != nil {
		t.Fatalf("failed to read original pub key: %v", err)
	}

	// Call again — should not regenerate
	if err := GenNKey(true); err != nil {
		t.Fatalf("GenNKey(true) second call failed: %v", err)
	}

	newPub, err := os.ReadFile(config.NKeyFarmerPubFile)
	if err != nil {
		t.Fatalf("failed to read pub key after second call: %v", err)
	}
	if string(origPub) != string(newPub) {
		t.Fatal("GenNKey should be idempotent — key changed on second call")
	}
}

func TestGenNKeyFarmerAndSproutDistinct(t *testing.T) {
	setupNKeyConfigDir(t)

	if err := GenNKey(true); err != nil {
		t.Fatalf("GenNKey(true) failed: %v", err)
	}
	if err := GenNKey(false); err != nil {
		t.Fatalf("GenNKey(false) failed: %v", err)
	}

	farmerPub, err := os.ReadFile(config.NKeyFarmerPubFile)
	if err != nil {
		t.Fatalf("failed to read farmer pub key: %v", err)
	}
	sproutPub, err := os.ReadFile(config.NKeySproutPubFile)
	if err != nil {
		t.Fatalf("failed to read sprout pub key: %v", err)
	}
	if string(farmerPub) == string(sproutPub) {
		t.Fatal("farmer and sprout NKeys should be distinct")
	}
}

func TestGenNKeyUnwritablePubDir(t *testing.T) {
	dir := t.TempDir()
	readonlyDir := filepath.Join(dir, "readonly")
	if err := os.MkdirAll(readonlyDir, 0o755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}
	// Use 0o555 so stat works but write fails.
	if err := os.Chmod(readonlyDir, 0o555); err != nil {
		t.Fatalf("failed to chmod: %v", err)
	}
	defer os.Chmod(readonlyDir, 0o755)

	config.NKeyFarmerPrivFile = filepath.Join(readonlyDir, "farmer.nkey")
	config.NKeyFarmerPubFile = filepath.Join(readonlyDir, "farmer.pub")

	err := GenNKey(true)
	if err == nil {
		t.Fatal("GenNKey should fail when pub key directory is not writable")
	}
}

func TestGenNKeyUnwritablePrivDir(t *testing.T) {
	dir := t.TempDir()
	writableDir := t.TempDir()
	readonlyDir := filepath.Join(dir, "readonly")
	if err := os.MkdirAll(readonlyDir, 0o755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}

	// Pub goes to writable dir, priv to read-only dir
	config.NKeyFarmerPubFile = filepath.Join(writableDir, "farmer.pub")
	config.NKeyFarmerPrivFile = filepath.Join(readonlyDir, "farmer.nkey")

	if err := os.Chmod(readonlyDir, 0o555); err != nil {
		t.Fatalf("failed to chmod: %v", err)
	}
	defer os.Chmod(readonlyDir, 0o755)

	err := GenNKey(true)
	if err == nil {
		t.Fatal("GenNKey should fail when priv key directory is not writable")
	}
}

func TestGetPubNKeyFarmer(t *testing.T) {
	setupNKeyConfigDir(t)

	if err := GenNKey(true); err != nil {
		t.Fatalf("GenNKey(true) failed: %v", err)
	}

	pubKey, err := GetPubNKey(true)
	if err != nil {
		t.Fatalf("GetPubNKey(true) failed: %v", err)
	}
	if len(pubKey) == 0 {
		t.Fatal("GetPubNKey returned empty string")
	}
	if pubKey[0] != 'U' {
		t.Fatalf("expected NATS user public key starting with 'U', got %c", pubKey[0])
	}
}

func TestGetPubNKeySprout(t *testing.T) {
	setupNKeyConfigDir(t)

	if err := GenNKey(false); err != nil {
		t.Fatalf("GenNKey(false) failed: %v", err)
	}

	pubKey, err := GetPubNKey(false)
	if err != nil {
		t.Fatalf("GetPubNKey(false) failed: %v", err)
	}
	if len(pubKey) == 0 {
		t.Fatal("GetPubNKey returned empty string")
	}
}

func TestGetPubNKeyMissing(t *testing.T) {
	setupNKeyConfigDir(t)

	_, err := GetPubNKey(true)
	if err == nil {
		t.Fatal("GetPubNKey should fail when key file doesn't exist")
	}
}

func TestGenNKeySeedData(t *testing.T) {
	setupNKeyConfigDir(t)

	if err := GenNKey(true); err != nil {
		t.Fatalf("GenNKey(true) failed: %v", err)
	}

	privBytes, err := os.ReadFile(config.NKeyFarmerPrivFile)
	if err != nil {
		t.Fatalf("failed to read priv key: %v", err)
	}
	if len(privBytes) < 4 {
		t.Fatal("private key seed too short")
	}
	if privBytes[0] != 'S' {
		t.Fatalf("expected seed starting with S, got %c", privBytes[0])
	}
	if privBytes[1] != 'U' {
		t.Fatalf("expected user seed (SU...), got S%c", privBytes[1])
	}
}

func TestGenNKeyStatErrorNotENOENT(t *testing.T) {
	// Cover the branch: os.Stat returns an error that is NOT os.IsNotExist.
	// This happens when the parent directory has no execute permission (EACCES).
	dir := t.TempDir()
	noExecDir := filepath.Join(dir, "noexec")
	if err := os.MkdirAll(noExecDir, 0o755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}

	config.NKeyFarmerPrivFile = filepath.Join(noExecDir, "subdir", "farmer.nkey")
	config.NKeyFarmerPubFile = filepath.Join(dir, "farmer.pub")

	// Remove execute permission from noExecDir — os.Stat on the nested path
	// returns EACCES (not ENOENT).
	if err := os.Chmod(noExecDir, 0o600); err != nil {
		t.Fatalf("failed to chmod: %v", err)
	}
	defer os.Chmod(noExecDir, 0o755)

	err := GenNKey(true)
	if err == nil {
		t.Fatal("GenNKey should fail when stat returns non-ENOENT error")
	}
}

func TestGenNKeyWritePubFails(t *testing.T) {
	// Cover GenNKey error when pub key write fails but stat returns ENOENT.
	// Dir has read+execute (so stat can see file doesn't exist) but no write.
	dir := t.TempDir()
	noWriteDir := filepath.Join(dir, "nowrite")
	if err := os.MkdirAll(noWriteDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Priv file in writable dir so stat returns ENOENT.
	config.NKeyFarmerPrivFile = filepath.Join(dir, "farmer.nkey")
	// Pub file in read-only dir so write fails.
	config.NKeyFarmerPubFile = filepath.Join(noWriteDir, "farmer.pub")

	if err := os.Chmod(noWriteDir, 0o555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer os.Chmod(noWriteDir, 0o755)

	err := GenNKey(true)
	if err == nil {
		t.Fatal("GenNKey should fail when pub key write fails")
	}
}

func TestGenNKeyWritePrivFails(t *testing.T) {
	// Cover GenNKey error when priv key write fails after pub succeeds.
	// Both are in different dirs: priv dir is read-only, pub dir is writable.
	dir := t.TempDir()
	noWriteDir := filepath.Join(dir, "nowrite")
	if err := os.MkdirAll(noWriteDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Priv file in read-only dir — stat returns ENOENT (file doesn't exist,
	// but dir is readable so stat can check).
	config.NKeyFarmerPrivFile = filepath.Join(noWriteDir, "farmer.nkey")
	// Pub file in writable dir — write succeeds.
	config.NKeyFarmerPubFile = filepath.Join(dir, "farmer.pub")

	if err := os.Chmod(noWriteDir, 0o555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer os.Chmod(noWriteDir, 0o755)

	err := GenNKey(true)
	if err == nil {
		t.Fatal("GenNKey should fail when priv key write fails")
	}
}
