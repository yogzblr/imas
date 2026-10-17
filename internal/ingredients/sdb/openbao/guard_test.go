package openbao

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yogzblr/imas/internal/ingredients/sdb"
	"github.com/yogzblr/imas/internal/openbao"
)

// TestRedirectToAnotherHostRefused (L17): a redirect of the login or of
// a read to another scheme, host or port sends nothing there, so the
// other host never sees the login request, the token or the client
// certificate.
func TestRedirectToAnotherHostRefused(t *testing.T) {
	var hits atomic.Int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte(`{"auth":{"client_token":"stolen","lease_duration":60},"data":{"data":{"k":"v"}}}`))
	}))
	t.Cleanup(evil.Close)
	evilPort := evil.URL[strings.LastIndex(evil.URL, ":")+1:]

	for _, redirectLogin := range []bool{true, false} {
		for name, target := range map[string]string{
			"other port": evil.URL,
			"other host": "http://localhost:" + evilPort,
		} {
			t.Run(name, func(t *testing.T) {
				m := &mockVault{secretData: map[string]any{"k": "v"}}
				inner := m.handler()
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					isLogin := strings.HasPrefix(r.URL.Path, "/v1/auth/")
					if isLogin == redirectLogin {
						http.Redirect(w, r, target+r.URL.Path, http.StatusTemporaryRedirect)
						return
					}
					inner(w, r)
				}))
				t.Cleanup(srv.Close)
				p := newWithTransport(srv.URL, "cert", "", http.DefaultTransport)
				_, err := p.Get(t.Context(), "sdb://openbao/secret/app#k")
				if !errors.Is(err, openbao.ErrOtherHost) {
					t.Fatalf("Get: err = %v, want ErrOtherHost", err)
				}
				if strings.Contains(err.Error(), "test-token") {
					t.Fatalf("error carries the token: %v", err)
				}
				if n := hits.Load(); n != 0 {
					t.Fatalf("the other host received %d requests", n)
				}
			})
		}
	}
}

// TestUnfollowedRedirectIsAnError: a 3xx the client does not follow
// (here a 308 with an empty body) is an error, not an empty secret.
func TestUnfollowedRedirectIsAnError(t *testing.T) {
	m := &mockVault{secretData: map[string]any{"k": "v"}}
	inner := m.handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/secret/") {
			w.Header().Set("Location", "/v1/elsewhere")
			w.WriteHeader(http.StatusPermanentRedirect)
			return
		}
		inner(w, r)
	}))
	t.Cleanup(srv.Close)
	p := newWithTransport(srv.URL, "cert", "", http.DefaultTransport)
	_, err := p.Get(t.Context(), "sdb://openbao/secret/app#k")
	if !errors.Is(err, ErrReadFailed) || statusCode(err) != http.StatusPermanentRedirect {
		t.Fatalf("err = %v, want ErrReadFailed with status 308", err)
	}
}

// TestRefPathValidated (L21): a ref whose path could leave its mount or
// name a reserved tree is refused before any request, login included.
func TestRefPathValidated(t *testing.T) {
	var requests atomic.Int32
	m := &mockVault{secretData: map[string]any{"k": "v"}}
	inner := m.handler()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		inner(w, r)
	}))
	t.Cleanup(srv.Close)
	p := newWithTransport(srv.URL, "cert", "", http.DefaultTransport)

	for _, ref := range []string{
		"sdb://openbao/secret/a/../../auth/token/lookup-self#id",
		"sdb://openbao/secret/./app",
		"sdb://openbao/secret//app",
		"sdb://openbao/secret/app/",
		"sdb://openbao//secret/app",
		"sdb://openbao/auth/token/lookup-self#id",
		"sdb://openbao/sys/health",
		"sdb://openbao/identity/entity/name/x",
		"sdb://openbao/SYS/health",
		"sdb://openbao/secret/%2e%2e/%2e%2e/auth/token/lookup-self",
		"sdb://openbao/secret/%252e%252e/x",
		"sdb://openbao/%61uth/token/lookup-self",
		"sdb://openbao/%2561uth/token/lookup-self",
		"sdb://openbao/secret/a%252fb",
		"sdb://openbao/onlyonesegment",
	} {
		if _, err := p.Get(t.Context(), ref); !errors.Is(err, sdb.ErrInvalidRef) {
			t.Errorf("Get(%q) = %v, want ErrInvalidRef", ref, err)
		}
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("%d requests sent for refused refs", n)
	}
	// Names that only contain a reserved word or dots still resolve.
	for _, ref := range []string{"sdb://openbao/secret/sys#k", "sdb://openbao/secret/auth/a.b#k", "sdb://openbao/secret/..app#k"} {
		if got, err := p.Get(t.Context(), ref); err != nil || got != "v" {
			t.Errorf("Get(%q) = %q, %v", ref, got, err)
		}
	}
}

// TestInsecureAddrRefused (I2): New takes https:// only; FromEnv takes
// http:// only with IMAS_SDB_OPENBAO_ALLOW_INSECURE=true, and the refusal
// names that variable.
func TestInsecureAddrRefused(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	genCert(t, certPath, keyPath)

	if _, err := New("http://vault.example.com:8200", certPath, keyPath, "", "", ""); !errors.Is(err, ErrNotConfigured) || !strings.Contains(err.Error(), EnvAllowInsecure) {
		t.Fatalf("New(http) = %v, want ErrNotConfigured naming %s", err, EnvAllowInsecure)
	}

	t.Setenv(EnvAddr, "http://vault.example.com:8200")
	t.Setenv(EnvClientCert, certPath)
	t.Setenv(EnvClientKey, keyPath)
	for _, v := range []string{"", "false", "0"} {
		t.Setenv(EnvAllowInsecure, v)
		if _, err := FromEnv(); !errors.Is(err, ErrNotConfigured) || !strings.Contains(err.Error(), EnvAllowInsecure+"=true") {
			t.Fatalf("FromEnv(http, %s=%q) = %v", EnvAllowInsecure, v, err)
		}
	}
	t.Setenv(EnvAllowInsecure, "maybe")
	if _, err := FromEnv(); !errors.Is(err, ErrNotConfigured) || !strings.Contains(err.Error(), EnvAllowInsecure) {
		t.Fatalf("FromEnv with a malformed %s = %v", EnvAllowInsecure, err)
	}
	t.Setenv(EnvAllowInsecure, "true")
	p, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv(http, allowed) = %v", err)
	}
	p.Close()

	t.Setenv(EnvAllowInsecure, "")
	t.Setenv(EnvAddr, "ftp://vault.example.com")
	if _, err := FromEnv(); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("FromEnv(ftp) = %v", err)
	}
}
