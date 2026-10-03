// Package openbao implements the sdb.SecretProvider for OpenBao and
// customer-managed HashiCorp Vault, authenticating via a customer-supplied
// client certificate (cert auth) rather than any credential imas controls.
//
// Requests go through the official OpenBao Go client,
// github.com/openbao/openbao/api/v2 (MPL-2.0, used unmodified; accepted by
// docs/design/requirements.md item 21), which speaks the same HTTP API as
// HashiCorp Vault. It does not use internal/openbao, the server-side
// wrapper: that package configures an identity from an
// IMAS_<NAME>_OPENBAO_* block and authenticates with a static token or
// kubernetes auth, while this provider runs on customer sprouts against
// the customer's own server with a client certificate. What it keeps from
// before the migration:
//
//   - the client certificate is presented through an sdb.CertWatcher, and
//     keep-alives are off, so a rotated certificate is used from the next
//     request on without a sprout restart;
//   - the cert-auth login token is cached in an sdb.TokenCache until 90%
//     of its lease has passed;
//   - no BAO_* or VAULT_* variable is read (api.NewConfig, never
//     api.DefaultConfig), so a customer's VAULT_TOKEN, VAULT_SKIP_VERIFY or
//     VAULT_NAMESPACE meant for other tools never reaches this provider;
//   - a 30 second timeout and no retries;
//   - the sdb://openbao/<mount>/<path>[#field] syntax, read as KV v2 and,
//     when that path isn't KV v2 (a 404 included), as KV v1. A failed
//     read names each path tried and what it returned.
//
// HTTP(S)_PROXY and NO_PROXY apply (http.ProxyFromEnvironment), as for
// the sprout's other HTTP clients.
//
// Errors carry OpenBao's own "errors" strings and HTTP status, never a
// token, a secret value or a response body that isn't OpenBao's JSON.
//
// FLAG FOR SECURITY REVIEW: every customer secret resolved on a sprout
// passes through here.
package openbao

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	api "github.com/openbao/openbao/api/v2"

	"github.com/yogzblr/imas/internal/ingredients/sdb"
	"github.com/yogzblr/imas/internal/log"
)

const backendName = "openbao"

// requestTimeout bounds every request, login included.
const requestTimeout = 30 * time.Second

// Environment variables configuring the default, self-registered
// provider instance. All but the address and cert/key pair are optional.
const (
	EnvAddr       = "IMAS_SDB_OPENBAO_ADDR"
	EnvClientCert = "IMAS_SDB_OPENBAO_CLIENT_CERT"
	EnvClientKey  = "IMAS_SDB_OPENBAO_CLIENT_KEY"
	EnvCACert     = "IMAS_SDB_OPENBAO_CACERT"
	EnvAuthMount  = "IMAS_SDB_OPENBAO_AUTH_MOUNT" // default "cert"
	EnvAuthRole   = "IMAS_SDB_OPENBAO_ROLE"       // optional cert auth role name
)

var (
	ErrNotConfigured = errors.New("openbao sdb provider not configured")
	ErrLoginFailed   = errors.New("openbao cert login failed")
	ErrReadFailed    = errors.New("openbao secret read failed")
)

// Provider is the sdb.SecretProvider implementation for OpenBao/Vault
// cert-authenticated access.
type Provider struct {
	Addr      string
	AuthMount string // e.g. "cert", mounted path of the cert auth method
	AuthRole  string // optional named role for auth/<mount>/login

	client  *api.Client // never holds a token: each request carries its own
	tokens  sdb.TokenCache
	watcher *sdb.CertWatcher // nil when built with newWithTransport
}

// Compile-time interface check.
var _ sdb.SecretProvider = (*Provider)(nil)

// New builds a Provider that authenticates with the given client
// certificate/key (hot-reloaded via an sdb.CertWatcher so a rotated cert
// is picked up without a restart) and, optionally, verifies the server
// against caCertFile instead of the system trust store.
func New(addr, certFile, keyFile, caCertFile, authMount, authRole string) (*Provider, error) {
	return newWithCertWatch(addr, certFile, keyFile, caCertFile, authMount, authRole, 0)
}

// newWithCertWatch is New with the CertWatcher's polling interval (0 for
// sdb.DefaultCertWatchInterval), so tests can rotate a cert quickly.
func newWithCertWatch(addr, certFile, keyFile, caCertFile, authMount, authRole string, interval time.Duration) (*Provider, error) {
	if addr == "" || certFile == "" || keyFile == "" {
		return nil, ErrNotConfigured
	}
	var pool *x509.CertPool
	if caCertFile != "" {
		pem, err := os.ReadFile(caCertFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA bundle: %w", err)
		}
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in CA bundle %s", caCertFile)
		}
	}
	watcher, err := sdb.NewCertWatcher(certFile, keyFile, interval)
	if err != nil {
		return nil, err
	}

	cfg := api.NewConfig()
	if cfg.Error != nil {
		watcher.Close()
		return nil, fmt.Errorf("%w: %w", ErrNotConfigured, cfg.Error)
	}
	// NewConfig's transport: go-cleanhttp's pooled transport with a TLS
	// 1.2 minimum and HTTP/2 configured. Only the settings below differ.
	transport := cfg.HttpClient.Transport.(*http.Transport)
	transport.Proxy = http.ProxyFromEnvironment
	transport.TLSClientConfig.GetClientCertificate = watcher.GetClientCertificate
	if pool != nil {
		transport.TLSClientConfig.RootCAs = pool
	}
	// Cert rotation is only observed on a fresh TLS handshake. Secret
	// reads are infrequent enough (recipe execution, not a hot loop)
	// that trading away connection reuse for "the very next request
	// after rotation uses the new cert" is the right default.
	transport.DisableKeepAlives = true

	p, err := newWithConfig(addr, authMount, authRole, cfg)
	if err != nil {
		watcher.Close()
		return nil, err
	}
	p.watcher = watcher
	return p, nil
}

// newWithTransport builds a Provider whose requests go through transport
// instead of a client-certificate one, for tests against a plain
// httptest server.
func newWithTransport(addr, authMount, authRole string, transport http.RoundTripper) *Provider {
	cfg := api.NewConfig()
	cfg.HttpClient.Transport = transport
	p, err := newWithConfig(addr, authMount, authRole, cfg)
	if err != nil {
		panic(err)
	}
	return p
}

func newWithConfig(addr, authMount, authRole string, cfg *api.Config) (*Provider, error) {
	if authMount == "" {
		authMount = "cert"
	}
	addr = strings.TrimRight(addr, "/")
	cfg.Address = addr
	cfg.Timeout = requestTimeout
	cfg.HttpClient.Timeout = requestTimeout
	cfg.MaxRetries = 0
	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotConfigured, err)
	}
	// NewClient reads no environment with NewConfig's DisableEnvironment;
	// clear anyway, so only the login token is ever sent.
	client.ClearToken()
	client.ClearNamespace()

	p := &Provider{
		Addr:      addr,
		AuthMount: strings.Trim(authMount, "/"),
		AuthRole:  authRole,
		client:    client,
	}
	p.tokens.Fetch = p.login
	return p, nil
}

// Close stops the client certificate watcher. The registered provider
// lives as long as the sprout and never needs it.
func (p *Provider) Close() {
	if p.watcher != nil {
		p.watcher.Close()
	}
}

// FromEnv builds a Provider from the Env* variables, for use by init()
// self-registration. It returns (nil, nil) when the minimum required
// variables aren't set, so registration is silently skipped rather than
// failing sprout startup for customers who don't use OpenBao.
func FromEnv() (*Provider, error) {
	addr := os.Getenv(EnvAddr)
	cert := os.Getenv(EnvClientCert)
	key := os.Getenv(EnvClientKey)
	if addr == "" && cert == "" && key == "" {
		return nil, nil
	}
	return New(addr, cert, key, os.Getenv(EnvCACert), os.Getenv(EnvAuthMount), os.Getenv(EnvAuthRole))
}

func init() {
	p, err := FromEnv()
	if err != nil {
		log.Warnf("sdb/openbao: not registering provider: %v", err)
		return
	}
	if p == nil {
		return
	}
	if err := sdb.RegisterProvider(backendName, p); err != nil {
		log.Warnf("sdb/openbao: %v", err)
	}
}

// login authenticates via the cert auth method over the already-mTLS'd
// connection. It is the TokenCache's Fetch, which keeps the token until
// 90% of its lease has passed.
func (p *Provider) login(ctx context.Context) (string, time.Duration, error) {
	body := map[string]string{}
	if p.AuthRole != "" {
		body["name"] = p.AuthRole
	}
	secret, err := p.request(ctx, "", http.MethodPost, "auth/"+p.AuthMount+"/login", body)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %w", ErrLoginFailed, err)
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return "", 0, fmt.Errorf("%w: %s", ErrLoginFailed, joinWarnings(secret))
	}
	return secret.Auth.ClientToken, time.Duration(secret.Auth.LeaseDuration) * time.Second, nil
}

// Get implements sdb.SecretProvider. ref is
// sdb://openbao/<mount>/<path...>[#field]; the secret is read as KV v2
// (falling back to KV v1's flatter shape if the path isn't KV v2-mounted).
func (p *Provider) Get(ctx context.Context, ref string) (string, error) {
	_, u, err := sdb.ParseRef(ref)
	if err != nil {
		return "", err
	}
	mount, secretPath, err := splitMountAndPath(u.Path)
	if err != nil {
		return "", err
	}

	token, err := p.tokens.Get(ctx)
	if err != nil {
		return "", err
	}

	fields, err := p.readKV(ctx, token, mount, secretPath)
	if err != nil {
		// A token revoked or expired early on the server answers 403;
		// log in afresh on the next Get rather than until the cached
		// lease runs out.
		if statusCode(err) == http.StatusForbidden {
			p.tokens.Invalidate()
		}
		return "", err
	}
	return sdb.SelectField(fields, u.Fragment)
}

func splitMountAndPath(uriPath string) (mount, secretPath string, err error) {
	trimmed := strings.Trim(uriPath, "/")
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("%w: expected sdb://openbao/<mount>/<path>, got path %q", sdb.ErrInvalidRef, uriPath)
	}
	return parts[0], parts[1], nil
}

// readKV reads the secret as KV v2 and, when that path doesn't answer
// as KV v2 (a 404, or a 2xx without KV v2's data.data), as KV v1. A
// failure names every path tried and what each returned, so an absent
// secret whose KV v1 fallback is refused doesn't read as only
// "permission denied".
func (p *Provider) readKV(ctx context.Context, token, mount, secretPath string) (map[string]string, error) {
	v2 := kvAttempt{kind: "KV v2", path: mount + "/data/" + secretPath}
	fields, err := p.readKVv2(ctx, token, v2.path)
	if err == nil {
		return fields, nil
	}
	v2.err = err
	if !errors.Is(err, errNotKVv2) {
		return nil, &readError{attempts: []kvAttempt{v2}}
	}
	v1 := kvAttempt{kind: "KV v1", path: mount + "/" + secretPath}
	fields, err = p.readKVv1(ctx, token, v1.path)
	if err == nil {
		return fields, nil
	}
	v1.err = err
	return nil, &readError{attempts: []kvAttempt{v2, v1}}
}

// errNotKVv2 marks a KV v2 read whose answer means "try KV v1". It
// always wraps what the server returned, for readError's message.
var errNotKVv2 = errors.New("not a kv-v2 secret")

func (p *Provider) readKVv2(ctx context.Context, token, path string) (map[string]string, error) {
	secret, err := p.request(ctx, token, http.MethodGet, path, nil)
	if statusCode(err) == http.StatusNotFound {
		return nil, fmt.Errorf("%w: %w", errNotKVv2, err)
	}
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("%w: %s", errNotKVv2, joinWarnings(secret))
	}
	data, ok := secret.Data["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: no data.data in the response", errNotKVv2)
	}
	return stringify(data), nil
}

func (p *Provider) readKVv1(ctx context.Context, token, path string) (map[string]string, error) {
	secret, err := p.request(ctx, token, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, errors.New(joinWarnings(secret))
	}
	return stringify(secret.Data), nil
}

// kvAttempt is one read readKV made: the API path (no address, no
// token), which KV version it was read as, and what came back.
type kvAttempt struct {
	kind, path string
	err        error
}

// readError is a failed secret read. It is ErrReadFailed, and it wraps
// the last attempt's error, so statusCode reports the status that
// decided the outcome (a 403 on the KV v1 fallback still drops the
// cached token, as before). Its message lists every attempt, built only
// from paths, statuses and OpenBao's own "errors" and "warnings".
type readError struct {
	attempts []kvAttempt
}

func (e *readError) Error() string {
	parts := make([]string, len(e.attempts))
	for i, a := range e.attempts {
		msg := a.err.Error()
		if errors.Is(a.err, errNotKVv2) {
			msg = strings.TrimPrefix(msg, errNotKVv2.Error()+": ")
		}
		parts[i] = fmt.Sprintf("%s (%s): %s", a.path, a.kind, msg)
	}
	return fmt.Sprintf("%s: tried %s", ErrReadFailed, strings.Join(parts, "; then "))
}

func (e *readError) Unwrap() []error {
	return []error{ErrReadFailed, e.attempts[len(e.attempts)-1].err}
}

// request sends method /v1/<path> as token ("" for none) with body, if
// not nil, as JSON, and parses the response. A 2xx with an empty body
// returns (nil, nil).
func (p *Provider) request(ctx context.Context, token, method, path string, body any) (*api.Secret, error) {
	r := p.client.NewRequest(method, "/v1/"+strings.TrimLeft(path, "/"))
	r.ClientToken = token
	if body != nil {
		if err := r.SetJSONBody(body); err != nil {
			return nil, fmt.Errorf("encoding request: %w", err)
		}
		r.Headers.Set("Content-Type", "application/json")
	}
	resp, err := p.client.RawRequestWithContext(ctx, r)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, responseError(err)
	}
	// The client follows one redirect and treats any other 3xx as
	// success; only a 2xx carries a secret.
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &statusError{code: resp.StatusCode}
	}
	secret, err := api.ParseSecret(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return secret, nil
}

// statusError is a non-2xx answer. Its message is the status and
// OpenBao's "errors" strings only: a body that isn't OpenBao's JSON (a
// proxy's or load balancer's error page, which might echo the request
// and its token) is left out, as is the request URL.
type statusError struct {
	code   int
	errors []string
}

func (e *statusError) Error() string {
	status := fmt.Sprintf("status %d", e.code)
	if text := http.StatusText(e.code); text != "" {
		status += " (" + strings.ToLower(text) + ")"
	}
	if len(e.errors) == 0 {
		return status
	}
	return status + ": " + strings.Join(e.errors, "; ")
}

func responseError(err error) error {
	var re *api.ResponseError
	if !errors.As(err, &re) {
		return err
	}
	se := &statusError{code: re.StatusCode}
	if !re.RawError {
		se.errors = re.Errors
	}
	return se
}

// statusCode returns the HTTP status of a *statusError in err's chain, or 0.
func statusCode(err error) int {
	var se *statusError
	if errors.As(err, &se) {
		return se.code
	}
	return 0
}

// joinWarnings describes a 2xx response that lacked what was asked for,
// using only its warnings (never its data).
func joinWarnings(secret *api.Secret) string {
	if secret == nil || len(secret.Warnings) == 0 {
		return "empty response"
	}
	return strings.Join(secret.Warnings, "; ")
}

func stringify(m map[string]any) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		switch val := v.(type) {
		case string:
			out[k] = val
		default:
			// Numbers arrive as json.Number (the client decodes with
			// UseNumber) and marshal back to their literal text.
			b, err := json.Marshal(val)
			if err != nil {
				continue
			}
			out[k] = string(b)
		}
	}
	return out
}
