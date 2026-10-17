package openbao

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// recorder is a second server, the one a hostile redirect points at. It
// counts every request that reaches it.
func recorder(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte(`{"auth":{"client_token":"stolen","lease_duration":3600},"data":{"version":1}}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// redirector answers every request with status to target+path.
func redirector(t *testing.T, status int, target func(r *http.Request) string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target(r), status)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestRedirectToAnotherHostRefused (L17): a node or ingress that
// redirects to another scheme, host or port gets nothing sent there:
// no token, no body, no kubernetes login JWT.
func TestRedirectToAnotherHostRefused(t *testing.T) {
	evil, hits := recorder(t)
	evilPort := evil.URL[strings.LastIndex(evil.URL, ":")+1:]
	targets := map[string]func(srv string) string{
		"other port": func(string) string { return evil.URL },
		// localhost reaches the same listener as 127.0.0.1: only the
		// host name differs.
		"other host": func(string) string { return "http://localhost:" + evilPort },
		"other scheme": func(srv string) string {
			return "https://" + strings.TrimPrefix(srv, "http://")
		},
	}
	for name, target := range targets {
		for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect} {
			t.Run(name+"/"+http.StatusText(status), func(t *testing.T) {
				var srvURL string
				srv := redirector(t, status, func(r *http.Request) string { return target(srvURL) + r.URL.Path })
				srvURL = srv.URL

				setTokenEnv(t, srv.URL, "platform-token")
				c, err := NewFromEnv(testEnv, testErrs)
				if err != nil {
					t.Fatal(err)
				}
				_, err = c.Put(t.Context(), "secret/data/tenant", map[string]any{"data": map[string]string{"priv": "box-private-key"}})
				if !errors.Is(err, ErrOtherHost) {
					t.Fatalf("Put: err = %v, want ErrOtherHost", err)
				}
				if strings.Contains(err.Error(), "platform-token") || strings.Contains(err.Error(), "box-private-key") {
					t.Fatalf("error carries the token or body: %v", err)
				}

				setK8sEnv(t, srv.URL, writeJWT(t, "sa-jwt"))
				c, err = NewFromEnv(testEnv, testErrs)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := c.Token(t.Context()); !errors.Is(err, errTestAuth) || !strings.Contains(err.Error(), ErrOtherHost.Error()) {
					t.Fatalf("login: err = %v, want errTestAuth naming the refused host", err)
				}
				if n := hits.Load(); n != 0 {
					t.Fatalf("the other host received %d requests", n)
				}
			})
		}
	}
}

// TestRedirectSameHostOneHop: a redirect on the configured host is
// followed once, with the token and body; a second one is not followed,
// and an unfollowed 3xx is an error, never an empty success (L19).
func TestRedirectSameHostOneHop(t *testing.T) {
	var s stub
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := s.record(r)
		switch rec.Path {
		case "/v1/old":
			http.Redirect(w, r, "/v1/new", http.StatusTemporaryRedirect)
		case "/v1/new":
			w.Write([]byte(`{"data":{"version":2}}`))
		case "/v1/hop1":
			http.Redirect(w, r, "/v1/hop2", http.StatusTemporaryRedirect)
		case "/v1/hop2":
			http.Redirect(w, r, "/v1/new", http.StatusTemporaryRedirect)
		}
	}))
	defer srv.Close()
	setTokenEnv(t, srv.URL, "tok")
	c, err := NewFromEnv(testEnv, testErrs)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := c.Put(t.Context(), "old", map[string]string{"k": "v"})
	if err != nil || secret == nil || secret.Data["version"] == nil {
		t.Fatalf("same-host redirect: %v, %v", secret, err)
	}
	got := s.all()
	if len(got) != 2 || got[1].Path != "/v1/new" || got[1].Token != "tok" || got[1].Body["k"] != "v" {
		t.Fatalf("requests = %+v", got)
	}

	_, err = c.Put(t.Context(), "hop1", map[string]string{"k": "v"})
	if StatusCode(err) != http.StatusTemporaryRedirect {
		t.Fatalf("two hops: err = %v, want a *StatusError 307", err)
	}
	if n := len(s.all()); n != 4 {
		t.Fatalf("two hops: %d requests in total, want 4 (the second redirect not followed)", n)
	}
}

// TestUnfollowedRedirectIsAnError (L19): the official client counts 200
// to 399 as success. A 3xx it does not follow (308, 300, 303, 304) must
// be a *StatusError, not (nil, nil), on every method and on ReadRaw.
func TestUnfollowedRedirectIsAnError(t *testing.T) {
	for _, status := range []int{http.StatusPermanentRedirect, http.StatusMultipleChoices, http.StatusSeeOther, http.StatusNotModified} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if status != http.StatusNotModified {
					w.Header().Set("Location", "/v1/elsewhere")
				}
				w.WriteHeader(status)
			}))
			defer srv.Close()
			setTokenEnv(t, srv.URL, "tok")
			c, err := NewFromEnv(testEnv, testErrs)
			if err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			calls := map[string]func() error{
				"Put":    func() error { _, err := c.Put(ctx, "p", map[string]string{}); return err },
				"Post":   func() error { _, err := c.Post(ctx, "p", map[string]string{}); return err },
				"Read":   func() error { _, err := c.Read(ctx, "p", nil); return err },
				"Delete": func() error { _, err := c.Delete(ctx, "p"); return err },
				"ReadRaw": func() error {
					_, err := c.ReadRaw(ctx, "p")
					return err
				},
			}
			for name, call := range calls {
				err := call()
				if StatusCode(err) != status {
					t.Errorf("%s: err = %v, want *StatusError %d", name, err, status)
				}
				var se *StatusError
				if errors.As(err, &se) && se.Unwrap() != nil {
					t.Errorf("%s: Unwrap() = %v, want nil for a status the client counted as success", name, se.Unwrap())
				}
			}
		})
	}
}

// TestKubernetesLoginIgnoresAmbientVariables (L18): the kubernetes login
// client is built with DisableEnvironment like the request client, so
// BAO_NAMESPACE / VAULT_NAMESPACE and BAO_TOKEN never reach a login, and
// a malformed BAO_* or VAULT_* variable does not stop the client being
// built.
func TestKubernetesLoginIgnoresAmbientVariables(t *testing.T) {
	var s stub
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := s.record(r)
		if strings.HasSuffix(rec.Path, "/login") {
			w.Write([]byte(`{"auth":{"client_token":"own-login","lease_duration":3600}}`))
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	for _, p := range []string{"BAO_", "VAULT_"} {
		t.Setenv(p+"TOKEN", "ambient-token")
		t.Setenv(p+"NAMESPACE", "ambient-ns")
		t.Setenv(p+"ADDR", "http://127.0.0.1:1")
		// Malformed: each fails api.DefaultConfig's ReadEnvironment.
		t.Setenv(p+"MAX_RETRIES", "many")
		t.Setenv(p+"SKIP_VERIFY", "perhaps")
		t.Setenv(p+"CLIENT_TIMEOUT", "soon")
		t.Setenv(p+"DISABLE_REDIRECTS", "sometimes")
		t.Setenv(p+"RATE_LIMIT", "fast")
		t.Setenv(p+"HTTP_PROXY", "::not a url")
	}
	for _, ns := range []string{"", "own-ns"} {
		t.Run("namespace="+ns, func(t *testing.T) {
			s.mu.Lock()
			s.reqs = nil
			s.mu.Unlock()
			setK8sEnv(t, srv.URL, writeJWT(t, "sa-jwt"))
			t.Setenv(testEnv.Namespace, ns)
			c, err := NewFromEnv(testEnv, testErrs)
			if err != nil {
				t.Fatalf("NewFromEnv with malformed ambient variables: %v", err)
			}
			if _, err := c.Read(t.Context(), "x", nil); err != nil {
				t.Fatal(err)
			}
			got := s.all()
			if len(got) != 2 {
				t.Fatalf("requests = %+v, want a login and a read", got)
			}
			login, read := got[0], got[1]
			if !strings.HasSuffix(login.Path, "/login") || login.Token != "" || login.Namespace != ns {
				t.Fatalf("login went out as %+v; want no token and namespace %q", login, ns)
			}
			if read.Token != "own-login" || read.Namespace != ns {
				t.Fatalf("read went out as %+v; want own-login and namespace %q", read, ns)
			}
		})
	}
}

// TestInsecureAddrRefused (I2): an http:// address is refused unless
// <prefix>ALLOW_INSECURE is true, and the refusal names that variable.
func TestInsecureAddrRefused(t *testing.T) {
	setTokenEnv(t, "http://openbao.example:8200", "tok")
	t.Setenv(testEnv.AllowInsecure, "")
	_, err := NewFromEnv(testEnv, testErrs)
	if !errors.Is(err, errTestNotConfigured) || !strings.Contains(err.Error(), testEnv.AllowInsecure+"=true") {
		t.Fatalf("unset: err = %v, want errTestNotConfigured naming %s", err, testEnv.AllowInsecure)
	}
	t.Setenv(testEnv.AllowInsecure, "false")
	if _, err := NewFromEnv(testEnv, testErrs); !errors.Is(err, errTestNotConfigured) {
		t.Fatalf("false: err = %v", err)
	}
	t.Setenv(testEnv.AllowInsecure, "yes please")
	if _, err := NewFromEnv(testEnv, testErrs); !errors.Is(err, errTestNotConfigured) || !strings.Contains(err.Error(), testEnv.AllowInsecure) {
		t.Fatalf("malformed: err = %v", err)
	}
	t.Setenv(testEnv.AllowInsecure, "true")
	if _, err := NewFromEnv(testEnv, testErrs); err != nil {
		t.Fatalf("true: %v", err)
	}
	t.Setenv(testEnv.AllowInsecure, "")
	t.Setenv(testEnv.Addr, "https://openbao.example:8200")
	if _, err := NewFromEnv(testEnv, testErrs); err != nil {
		t.Fatalf("https: %v", err)
	}
	t.Setenv(testEnv.Addr, "unix:///run/openbao.sock")
	if _, err := NewFromEnv(testEnv, testErrs); !errors.Is(err, errTestNotConfigured) {
		t.Fatalf("unix: err = %v", err)
	}
}
