package openbao

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	api "github.com/openbao/openbao/api/v2"
)

// TestRealServer runs the provider against a real OpenBao or HashiCorp
// Vault server, which must listen on TLS (a client certificate is only
// presented over TLS). It is skipped unless these are set:
//
//	IMAS_TEST_SDB_OPENBAO_ADDR    https://127.0.0.1:8200
//	IMAS_TEST_SDB_OPENBAO_TOKEN   a root token, to set the server up
//	IMAS_TEST_SDB_OPENBAO_CACERT  the CA bundle for the server's TLS
//
// For example, with a dev server's generated TLS:
//
//	bao server -dev -dev-tls -dev-root-token-id=root -dev-tls-cert-dir=/tmp/bao
//	vault server -dev -dev-tls -dev-root-token-id=root -dev-tls-cert-dir=/tmp/vault
//	IMAS_TEST_SDB_OPENBAO_ADDR=https://127.0.0.1:8200 IMAS_TEST_SDB_OPENBAO_TOKEN=root \
//	  IMAS_TEST_SDB_OPENBAO_CACERT=/tmp/bao/vault-ca.pem \
//	  go test ./internal/ingredients/sdb/openbao -run TestRealServer -v
//
// It enables a cert auth method and KV v2 and KV v1 mounts under random
// names, trusts two client CAs through two roles, reads secrets, then
// rotates the client certificate from one CA to the other under the
// running provider after the server stops trusting the first, and
// removes everything it created.
func TestRealServer(t *testing.T) {
	addr := os.Getenv("IMAS_TEST_SDB_OPENBAO_ADDR")
	rootToken := os.Getenv("IMAS_TEST_SDB_OPENBAO_TOKEN")
	caFile := os.Getenv("IMAS_TEST_SDB_OPENBAO_CACERT")
	if addr == "" || rootToken == "" || caFile == "" {
		t.Skip("IMAS_TEST_SDB_OPENBAO_ADDR, _TOKEN and _CACERT not set; this test needs a real OpenBao or Vault on TLS")
	}
	admin := newRealAdmin(t, addr, rootToken, caFile)
	t.Logf("server: %s", admin.version())

	sfx := randSuffix(t)
	authMount := "sdbcert-" + sfx
	kv2, kv1, denied := "sdbkv2-"+sfx, "sdbkv1-"+sfx, "sdbdenied-"+sfx
	policy := "sdb-" + sfx

	admin.call(http.MethodPost, "sys/auth/"+authMount, map[string]any{"type": "cert"})
	t.Cleanup(func() { admin.call(http.MethodDelete, "sys/auth/"+authMount, nil) })
	for _, m := range []struct {
		path    string
		version string
	}{{kv2, "2"}, {kv1, "1"}, {denied, "2"}} {
		admin.call(http.MethodPost, "sys/mounts/"+m.path, map[string]any{"type": "kv", "options": map[string]string{"version": m.version}})
		mount := m.path
		t.Cleanup(func() { admin.call(http.MethodDelete, "sys/mounts/"+mount, nil) })
	}
	admin.call(http.MethodPut, "sys/policies/acl/"+policy, map[string]any{
		"policy": `path "` + kv2 + `/data/*" { capabilities = ["read"] }
path "` + kv1 + `/*" { capabilities = ["read"] }`,
	})
	t.Cleanup(func() { admin.call(http.MethodDelete, "sys/policies/acl/"+policy, nil) })

	caA, caB := newTestCA(t, "customer CA A"), newTestCA(t, "customer CA B")
	for role, ca := range map[string]*testCA{"role-a": caA, "role-b": caB} {
		admin.call(http.MethodPost, "auth/"+authMount+"/certs/"+role, map[string]any{
			"certificate":    string(ca.pem),
			"token_policies": []string{policy},
			"token_ttl":      "1h",
		})
	}

	// KV v2 waits for its mount to be upgraded; retry the first write.
	writeEventually(t, admin, kv2+"/data/app/db", map[string]any{"data": map[string]any{"password": "pw-kv2", "port": 5432}})
	admin.call(http.MethodPost, kv1+"/app/db", map[string]any{"password": "pw-kv1"})
	writeEventually(t, admin, denied+"/data/app/db", map[string]any{"data": map[string]any{"password": "pw-denied"}})

	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	writeClientCert(t, caA, certPath, keyPath, "sprout-a")

	p, err := newWithCertWatch(addr, certPath, keyPath, caFile, authMount, "", 20*time.Millisecond)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(p.Close)

	get := func(ref string) (string, error) { return p.Get(t.Context(), "sdb://openbao/"+ref) }
	mustGet := func(ref, want string) {
		t.Helper()
		got, err := get(ref)
		if err != nil {
			t.Fatalf("Get %s: %v", ref, err)
		}
		if got != want {
			t.Fatalf("Get %s = %q, want %q", ref, got, want)
		}
	}

	mustGet(kv2+"/app/db#password", "pw-kv2")
	mustGet(kv2+"/app/db#port", "5432")
	mustGet(kv1+"/app/db", "pw-kv1")

	// A named role, as IMAS_SDB_OPENBAO_ROLE sets it.
	pr, err := newWithCertWatch(addr, certPath, keyPath, caFile, authMount, "role-a", time.Hour)
	if err != nil {
		t.Fatalf("New with role: %v", err)
	}
	t.Cleanup(pr.Close)
	if got, err := pr.Get(t.Context(), "sdb://openbao/"+kv2+"/app/db#password"); err != nil || got != "pw-kv2" {
		t.Fatalf("Get with role-a = %q, %v", got, err)
	}

	// Errors: the server's own message, never the token or a value.
	token, err := p.tokens.Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ ref, want string }{
		{denied + "/app/db#password", "permission denied"},
		{kv2 + "/app/db#nope", "nope"},
		{kv2 + "/app/db", "#field"},
		// Absent from KV v2 reads as "not KV v2" (a 404 either way), so
		// the KV v1 fallback answers: a 404, or the 403 here, since the
		// policy grants no v1-style path on the KV v2 mount.
		{kv2 + "/app/absent", ErrReadFailed.Error()},
	} {
		_, err := get(tc.ref)
		if err == nil {
			t.Fatalf("Get %s: expected an error", tc.ref)
		}
		msg := err.Error()
		if !strings.Contains(msg, tc.want) {
			t.Errorf("Get %s: error %q lacks %q", tc.ref, msg, tc.want)
		}
		for _, leak := range []string{token, "pw-kv2", "pw-denied", "5432"} {
			if strings.Contains(msg, leak) {
				t.Errorf("Get %s: error %q leaks %q", tc.ref, msg, leak)
			}
		}
	}
	// The 403 above dropped the cached token; the next Get logs in again.
	mustGet(kv2+"/app/db#password", "pw-kv2")

	// Rotation. The customer stops trusting CA A: a fresh login with the
	// old certificate is now refused.
	admin.call(http.MethodDelete, "auth/"+authMount+"/certs/role-a", nil)
	p.tokens.Invalidate()
	if _, err := get(kv2 + "/app/db#password"); !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("Get with the untrusted certificate = %v, want ErrLoginFailed", err)
	}
	// They drop a certificate from CA B in place of the old files; the
	// running provider picks it up.
	writeClientCert(t, caB, certPath, keyPath, "sprout-b")
	deadline := time.Now().Add(10 * time.Second)
	for {
		got, err := get(kv2 + "/app/db#password")
		if err == nil {
			if got != "pw-kv2" {
				t.Fatalf("Get after rotation = %q", got)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Get still failing 10s after rotation: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	mustGet(kv1+"/app/db", "pw-kv1")
}

type realAdmin struct {
	t     *testing.T
	c     *api.Client
	token string
}

func newRealAdmin(t *testing.T, addr, token, caFile string) *realAdmin {
	t.Helper()
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatalf("no certificates in %s", caFile)
	}
	cfg := api.NewConfig()
	cfg.Address = strings.TrimRight(addr, "/")
	cfg.MaxRetries = 0
	cfg.HttpClient.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool
	c, err := api.NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.ClearToken()
	return &realAdmin{t: t, c: c, token: token}
}

func (a *realAdmin) do(method, path string, body any) (int, error) {
	r := a.c.NewRequest(method, "/v1/"+path)
	r.ClientToken = a.token
	if body != nil {
		if err := r.SetJSONBody(body); err != nil {
			return 0, err
		}
	}
	resp, err := a.c.RawRequestWithContext(context.Background(), r)
	if resp == nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, err
}

func (a *realAdmin) call(method, path string, body any) {
	a.t.Helper()
	if status, err := a.do(method, path, body); err != nil {
		a.t.Fatalf("%s %s: status %d: %v", method, path, status, err)
	}
}

func (a *realAdmin) version() string {
	s, err := a.c.Sys().Health()
	if err != nil {
		return "unknown (" + err.Error() + ")"
	}
	return s.Version
}

func writeEventually(t *testing.T, a *realAdmin, path string, body any) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, err := a.do(http.MethodPost, path, body)
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("POST %s: %v", path, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func randSuffix(t *testing.T) string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}
