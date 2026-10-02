package sproutrelease

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testToken = "operator-token-0123456789abcdef0123456789abcdef"

const testRequest = `{
  "version": "v1.2.3",
  "channel": "stable",
  "min_sprout_version": "v1.0.0",
  "packages": [
    {"os": "linux", "arch": "amd64", "package_type": "deb", "file_name": "imas-sprout_1.2.3_linux_amd64.deb", "checksum_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
  ]
}
`

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func certPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

type answer struct {
	code int
	body string
}

// saasapi stands in for the operator plane: it checks every request and
// gives the answers in turn, repeating the last.
type saasapi struct {
	srv   *httptest.Server
	calls atomic.Int32
	ca    string
}

func newSaasapi(t *testing.T, answers ...answer) *saasapi {
	t.Helper()
	s := &saasapi{}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(s.calls.Add(1)) - 1
		a := answers[min(n, len(answers)-1)]
		b, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.Path != RegisterPath || r.Header.Get("Authorization") != "Bearer "+testToken ||
			r.Header.Get("Content-Type") != "application/json" || string(b) != testRequest {
			t.Errorf("request %s %s, Authorization %q, Content-Type %q, body %q", r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), b)
		}
		if a.code >= 300 && a.code < 400 {
			w.Header().Set("Location", "https://elsewhere.example/steal")
		}
		w.WriteHeader(a.code)
		io.WriteString(w, a.body)
	}))
	t.Cleanup(s.srv.Close)
	s.ca = writeFile(t, "ca.crt", certPEM(s.srv.Certificate().Raw))
	return s
}

type result struct {
	code           int
	stdout, stderr string
	sleeps         []time.Duration
}

func opts(t *testing.T, url, ca string) options {
	return options{
		saasapiURL: url, requestFile: writeFile(t, "request.json", testRequest),
		tokenFile: writeFile(t, "token", testToken+"\n"), caFile: ca,
		attempts: 4, initialBackoff: 5 * time.Second, maxBackoff: 12 * time.Second, requestTimeout: 10 * time.Second,
	}
}

func runWith(t *testing.T, o options) result {
	t.Helper()
	var out, errb bytes.Buffer
	var r result
	r.code = run(context.Background(), o, &out, &errb, func(_ context.Context, d time.Duration) error {
		r.sleeps = append(r.sleeps, d)
		return nil
	})
	r.stdout, r.stderr = out.String(), errb.String()
	if strings.Contains(r.stdout+r.stderr, testToken) {
		t.Error("the operator token was printed")
	}
	return r
}

func TestRegister(t *testing.T) {
	conflict := `{"error":"release_conflict","message":"version v1.2.3 is registered for linux/amd64/deb with a different file_name or checksum_sha256; releases are immutable, register a new version"}`
	for _, tc := range []struct {
		name     string
		answers  []answer
		code     int
		calls    int32
		sleeps   []time.Duration
		inStderr []string
		stdout   string
	}{
		{"registered", []answer{{201, `{"created":1,"packages":[{}]}`}}, 0, 1, nil, []string{"sprout release v1.2.3 registered (1 new of 1 package(s))"}, `{"created":1,"packages":[{}]}`},
		{"idempotent re-run", []answer{{200, `{"created":0}`}}, 0, 1, nil, []string{"already registered with these contents"}, `{"created":0}`},
		{"conflict is final and prints the mismatch", []answer{{409, conflict}}, 2, 1, nil, []string{
			"REFUSED (409)", "release_conflict: version v1.2.3 is registered for linux/amd64/deb",
			"this chart sent:", "version v1.2.3, min_sprout_version v1.0.0, channel stable",
			"linux/amd64/deb  imas-sprout_1.2.3_linux_amd64.deb  sha256:aaaa",
		}, ""},
		{"revoked is final", []answer{{409, `{"error":"version_revoked","message":"revoked"}`}}, 2, 1, nil, []string{"REFUSED (409)", "version_revoked"}, ""},
		{"bad request is final", []answer{{400, `{"error":"invalid_release","message":"bad","details":{"field":"x"}}`}}, 2, 1, nil, []string{`REFUSED (HTTP 400), not retrying: invalid_release: bad {"field":"x"}`}, ""},
		{"unauthorized is final", []answer{{401, `{"error":"unauthorized","message":"unauthorized"}`}}, 2, 1, nil, []string{"REFUSED (HTTP 401)"}, ""},
		{"signing refused is final", []answer{{422, `{"error":"signing_refused"}`}}, 2, 1, nil, []string{"REFUSED (HTTP 422)"}, ""},
		{"plain-text 404 is final", []answer{{404, "404 page not found\n"}}, 2, 1, nil, []string{"REFUSED (HTTP 404), not retrying: 404 page not found"}, ""},
		{"a redirect is not followed", []answer{{302, ""}}, 2, 1, nil, []string{"REFUSED (HTTP 302)"}, ""},
		{"retries 5xx with backoff, then succeeds", []answer{{503, `{"error":"signing_unavailable"}`}, {502, "bad gateway"}, {500, ""}, {201, `{}`}}, 0, 4,
			[]time.Duration{5 * time.Second, 10 * time.Second, 12 * time.Second},
			[]string{"attempt 1/4: HTTP 503: signing_unavailable; retrying in 5s", "attempt 2/4: HTTP 502: bad gateway", "attempt 3/4: HTTP 500: (empty body); retrying in 12s", "registered"}, "{}"},
		{"retries 408 and 429", []answer{{408, ""}, {429, ""}, {200, `{}`}}, 0, 3, []time.Duration{5 * time.Second, 10 * time.Second}, []string{"HTTP 408", "HTTP 429"}, "{}"},
		{"gives up", []answer{{500, `{"error":"internal_error"}`}}, 1, 4, []time.Duration{5 * time.Second, 10 * time.Second, 12 * time.Second}, []string{"giving up after 4 attempt(s); last: HTTP 500: internal_error"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSaasapi(t, tc.answers...)
			r := runWith(t, opts(t, s.srv.URL, s.ca))
			if r.code != tc.code || s.calls.Load() != tc.calls || !slices.Equal(r.sleeps, tc.sleeps) {
				t.Errorf("exit %d after %d calls, sleeps %v; want %d after %d, sleeps %v\nstderr:\n%s", r.code, s.calls.Load(), r.sleeps, tc.code, tc.calls, tc.sleeps, r.stderr)
			}
			for _, want := range tc.inStderr {
				if !strings.Contains(r.stderr, want) {
					t.Errorf("stderr lacks %q:\n%s", want, r.stderr)
				}
			}
			if strings.TrimSpace(r.stdout) != tc.stdout {
				t.Errorf("stdout %q, want %q", r.stdout, tc.stdout)
			}
		})
	}
}

func TestRegisterTransport(t *testing.T) {
	t.Run("unreachable is retried", func(t *testing.T) {
		s := newSaasapi(t, answer{201, ""})
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		dead := "https://" + ln.Addr().String()
		ln.Close()
		r := runWith(t, opts(t, dead, s.ca))
		if r.code != 1 || len(r.sleeps) != 3 || !strings.Contains(r.stderr, "saasapi not reachable") || !strings.Contains(r.stderr, "giving up after 4 attempt(s)") {
			t.Errorf("exit %d, sleeps %v:\n%s", r.code, r.sleeps, r.stderr)
		}
	})
	t.Run("untrusted certificate is final", func(t *testing.T) {
		s := newSaasapi(t, answer{201, ""})
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "other CA"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		r := runWith(t, opts(t, s.srv.URL, writeFile(t, "other.crt", certPEM(der))))
		if r.code != 2 || s.calls.Load() != 0 || len(r.sleeps) != 0 || !strings.Contains(r.stderr, "does not verify") {
			t.Errorf("exit %d after %d calls:\n%s", r.code, s.calls.Load(), r.stderr)
		}
	})
	t.Run("wrong host name is final", func(t *testing.T) {
		// The test certificate is for 127.0.0.1 and example.com, not localhost.
		s := newSaasapi(t, answer{201, ""})
		r := runWith(t, opts(t, strings.Replace(s.srv.URL, "127.0.0.1", "localhost", 1), s.ca))
		if r.code != 2 || s.calls.Load() != 0 || !strings.Contains(r.stderr, "does not verify") {
			t.Errorf("exit %d after %d calls:\n%s", r.code, s.calls.Load(), r.stderr)
		}
	})
	t.Run("proxy settings are ignored", func(t *testing.T) {
		t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
		t.Setenv("https_proxy", "http://127.0.0.1:1")
		t.Setenv("NO_PROXY", "")
		t.Setenv("no_proxy", "")
		s := newSaasapi(t, answer{201, `{}`})
		if r := runWith(t, opts(t, s.srv.URL, s.ca)); r.code != 0 || s.calls.Load() != 1 {
			t.Errorf("exit %d after %d calls:\n%s", r.code, s.calls.Load(), r.stderr)
		}
	})
}

// Every local problem is final (exit 2) and sends nothing.
func TestRegisterConfigErrors(t *testing.T) {
	s := newSaasapi(t, answer{201, ""})
	for _, tc := range []struct {
		name, want string
		edit       func(*options)
	}{
		{"http URL", "want https://host[:port]", func(o *options) { o.saasapiURL = strings.Replace(s.srv.URL, "https", "http", 1) }},
		{"URL with a path", "want https://host[:port]", func(o *options) { o.saasapiURL = s.srv.URL + RegisterPath }},
		{"URL with credentials", "want https://host[:port]", func(o *options) { o.saasapiURL = strings.Replace(s.srv.URL, "https://", "https://u:p@", 1) }},
		{"no request file", "request:", func(o *options) { o.requestFile = filepath.Join(t.TempDir(), "missing") }},
		{"unknown field", `unknown field "artifact_url"`, func(o *options) {
			o.requestFile = writeFile(t, "r.json", strings.Replace(testRequest, `"channel"`, `"artifact_url": "x", "channel"`, 1))
		}},
		{"no packages", "at least one package", func(o *options) {
			o.requestFile = writeFile(t, "r.json", `{"version":"v1.2.3","channel":"stable","min_sprout_version":"v1.0.0","packages":[]}`)
		}},
		{"no min_sprout_version", "min_sprout_version", func(o *options) {
			o.requestFile = writeFile(t, "r.json", strings.Replace(testRequest, `"min_sprout_version": "v1.0.0",`, "", 1))
		}},
		{"two JSON values", "more than one JSON value", func(o *options) { o.requestFile = writeFile(t, "r.json", testRequest+"{}") }},
		{"empty token", "operator token", func(o *options) { o.tokenFile = writeFile(t, "t", "") }},
		{"short token", "at least 32 characters", func(o *options) { o.tokenFile = writeFile(t, "t", "short") }},
		{"token with a space", "no whitespace", func(o *options) { o.tokenFile = writeFile(t, "t", testToken[:20]+" "+testToken[20:]) }},
		{"CA not PEM", "holds no PEM certificate", func(o *options) { o.caFile = writeFile(t, "ca", "not a cert") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := opts(t, s.srv.URL, s.ca)
			tc.edit(&o)
			r := runWith(t, o)
			if r.code != 2 || !strings.Contains(r.stderr, tc.want) {
				t.Errorf("exit %d, stderr:\n%s\nwant %q", r.code, r.stderr, tc.want)
			}
		})
	}
	if n := s.calls.Load(); n != 0 {
		t.Errorf("%d request(s) sent despite a local error", n)
	}
}

func TestParse(t *testing.T) {
	for k, v := range map[string]string{
		EnvSaaSAPIURL: "https://saasapi-operator:8443", EnvRequestFile: "/r", EnvTokenFile: "/t", EnvCAFile: "/c",
		EnvAttempts: "3", EnvInitialBackoff: "2s", EnvMaxBackoff: "9s", EnvRequestTimeout: "77s",
	} {
		t.Setenv(k, v)
	}
	var errb bytes.Buffer
	o, code := parse(nil, &errb)
	want := options{"https://saasapi-operator:8443", "/r", "/t", "/c", 3, 2 * time.Second, 9 * time.Second, 77 * time.Second}
	if code != -1 || o != want {
		t.Errorf("parse from env = %+v, %d; want %+v\n%s", o, code, want, errb.String())
	}
	o, code = parse([]string{"-attempts", "5", "-ca-file", "/other"}, &errb)
	if code != -1 || o.attempts != 5 || o.caFile != "/other" {
		t.Errorf("flags don't override the environment: %+v", o)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-attempts", "0"}, "-attempts"},
		{[]string{"-initial-backoff", "5"}, "-initial-backoff"},
		{[]string{"-max-backoff", "-1s"}, "-max-backoff"},
		{[]string{"extra"}, "unexpected arguments"},
		{[]string{"-saasapi-url", ""}, "-saasapi-url is required"},
	} {
		errb.Reset()
		if _, code := parse(tc.args, &errb); code != 2 || !strings.Contains(errb.String(), tc.want) {
			t.Errorf("%v: code %d, stderr %q, want %q", tc.args, code, errb.String(), tc.want)
		}
	}
}
