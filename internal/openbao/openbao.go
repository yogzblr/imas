// Package openbao builds imas's server-side OpenBao clients on the
// official Go client, github.com/openbao/openbao/api/v2 (MPL-2.0, used
// unmodified; accepted by docs/design/requirements.md item 21).
//
// Every farmer, saasapi and fleetreleaser OpenBao identity (TLS issuance
// in internal/certs, tenant box keys in internal/pki, the gateway signer
// in internal/gatewayjwt, the read-only fleet key in internal/fleetsign,
// the KV writer in internal/openbaokv, and cmd/fleetreleaser's signer)
// is configured from its own IMAS_<NAME>_OPENBAO_* environment block and
// built here, so they share one implementation of:
//
//   - the client itself: built from api.NewConfig, which ignores every
//     BAO_* and VAULT_* environment variable (BAO_TOKEN, BAO_SKIP_VERIFY,
//     BAO_NAMESPACE, ...), so an identity is configured only by its own
//     block and never by something ambient in the pod;
//   - auth: a static token, or OpenBao's kubernetes auth method (login
//     with the pod's service account JWT), re-logging in once less than
//     20% of the login's lease remains;
//   - the optional CA bundle that verifies OpenBao's own TLS;
//   - a 30 second timeout and no retries, as before the migration;
//   - the X-Vault-Namespace header, when <prefix>NAMESPACE is set;
//   - errors: a non-2xx answer becomes a *StatusError reading
//     "status <code>: <OpenBao's errors>".
//
// It starts no goroutines. A Client used for one operation should be
// closed (Close) to release its idle connections.
//
// internal/ingredients/sdb/openbao (the sprout-side sdb:// provider)
// does not use this package: it runs on customer sprouts against the
// customer's own server, with a client certificate.
//
// FLAG FOR SECURITY REVIEW: every OpenBao token imas holds passes
// through here.
package openbao

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	api "github.com/openbao/openbao/api/v2"
)

// Recognized values of an <prefix>AUTH_METHOD variable.
const (
	AuthMethodToken      = "token"
	AuthMethodKubernetes = "kubernetes"
)

const (
	// DefaultK8sMount is the kubernetes auth method's default mount.
	DefaultK8sMount = "kubernetes"
	// DefaultK8sJWTPath is where Kubernetes projects a pod's service
	// account token by default.
	DefaultK8sJWTPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

	// requestTimeout bounds every request, as each hand-rolled client's
	// http.Client.Timeout did.
	requestTimeout = 30 * time.Second

	// authTokenSafetyMargin is the fraction of a kubernetes-auth login's
	// lease_duration reserved as a safety margin: a token is replaced once
	// less than this fraction of its lease remains.
	authTokenSafetyMargin = 5 // 1/5 = 20%
)

// Default sentinel errors, used for any of Errors left nil.
var (
	ErrNotConfigured     = errors.New("openbao: client not configured")
	ErrK8sJWTUnavailable = errors.New("openbao: kubernetes auth: could not read service account token")
	ErrK8sAuthFailed     = errors.New("openbao: kubernetes auth login failed")
)

// Env names one identity's environment variables. Addr is required;
// the rest are read as their comments say.
type Env struct {
	Addr       string // required
	CACert     string // optional PEM bundle verifying OpenBao's TLS
	AuthMethod string // "token" (default) or "kubernetes"
	Token      string // required when AuthMethod is "token"
	K8sRole    string // required when AuthMethod is "kubernetes"
	K8sMount   string // default DefaultK8sMount
	K8sJWTPath string // default DefaultK8sJWTPath
	Namespace  string // optional; sets X-Vault-Namespace on every request
}

// EnvWithPrefix is the Env every identity uses: prefix followed by ADDR,
// CACERT, AUTH_METHOD, TOKEN, K8S_ROLE, K8S_MOUNT, K8S_JWT_PATH and
// NAMESPACE (e.g. prefix "IMAS_CERTS_OPENBAO_").
func EnvWithPrefix(prefix string) Env {
	return Env{
		Addr:       prefix + "ADDR",
		CACert:     prefix + "CACERT",
		AuthMethod: prefix + "AUTH_METHOD",
		Token:      prefix + "TOKEN",
		K8sRole:    prefix + "K8S_ROLE",
		K8sMount:   prefix + "K8S_MOUNT",
		K8sJWTPath: prefix + "K8S_JWT_PATH",
		Namespace:  prefix + "NAMESPACE",
	}
}

// Errors are the sentinels a caller's errors wrap, so each package keeps
// its own (certs.ErrK8sAuthFailed, gatewayjwt.ErrNotConfigured, ...).
type Errors struct {
	// NotConfigured wraps a missing or invalid setting.
	NotConfigured error
	// K8sJWTUnavailable wraps a service account JWT that couldn't be
	// read: a local problem, and no login was attempted.
	K8sJWTUnavailable error
	// K8sAuthFailed wraps OpenBao refusing (or not answering) the login.
	K8sAuthFailed error
}

func (e Errors) withDefaults() Errors {
	if e.NotConfigured == nil {
		e.NotConfigured = ErrNotConfigured
	}
	if e.K8sJWTUnavailable == nil {
		e.K8sJWTUnavailable = ErrK8sJWTUnavailable
	}
	if e.K8sAuthFailed == nil {
		e.K8sAuthFailed = ErrK8sAuthFailed
	}
	return e
}

// Client is one OpenBao identity: an official client plus the token it
// currently authenticates with. Safe for concurrent use.
type Client struct {
	api   *api.Client // requests; its token is set per request
	login *api.Client // kubernetes logins only; never holds a token
	errs  Errors

	httpClient *http.Client // shared by api and login

	authMethod  string
	staticToken string

	k8sRole    string
	k8sMount   string
	k8sJWTPath string

	authMu     sync.Mutex
	authToken  string
	authExpiry time.Time
}

// NewFromEnv builds a Client from the variables env names, read now
// (not cached: tests point an identity at a local server by changing
// its environment). Nothing is sent to OpenBao until the first request.
func NewFromEnv(env Env, errs Errors) (*Client, error) {
	errs = errs.withDefaults()
	addr := os.Getenv(env.Addr)
	if addr == "" {
		return nil, fmt.Errorf("%w: %s is required", errs.NotConfigured, env.Addr)
	}
	authMethod := os.Getenv(env.AuthMethod)
	if authMethod == "" {
		authMethod = AuthMethodToken
	}
	c := &Client{errs: errs, authMethod: authMethod}

	switch authMethod {
	case AuthMethodToken:
		c.staticToken = os.Getenv(env.Token)
		if c.staticToken == "" {
			return nil, fmt.Errorf("%w: %s is required when %s=%s (or unset)",
				errs.NotConfigured, env.Token, env.AuthMethod, AuthMethodToken)
		}
	case AuthMethodKubernetes:
		c.k8sRole = os.Getenv(env.K8sRole)
		if c.k8sRole == "" {
			return nil, fmt.Errorf("%w: %s is required when %s=%s",
				errs.NotConfigured, env.K8sRole, env.AuthMethod, AuthMethodKubernetes)
		}
		c.k8sMount = strings.Trim(os.Getenv(env.K8sMount), "/")
		if c.k8sMount == "" {
			c.k8sMount = DefaultK8sMount
		}
		c.k8sJWTPath = os.Getenv(env.K8sJWTPath)
		if c.k8sJWTPath == "" {
			c.k8sJWTPath = DefaultK8sJWTPath
		}
	default:
		// An explicit, unrecognized method is a configuration mistake:
		// refuse rather than run with a different one than asked for.
		return nil, fmt.Errorf("%w: unknown %s %q (want %q or %q)",
			errs.NotConfigured, env.AuthMethod, authMethod, AuthMethodToken, AuthMethodKubernetes)
	}

	// api.NewConfig, never api.DefaultConfig: the latter reads BAO_*/VAULT_*
	// variables, including BAO_SKIP_VERIFY and BAO_TOKEN.
	cfg := api.NewConfig()
	if cfg.Error != nil {
		return nil, fmt.Errorf("%w: %w", errs.NotConfigured, cfg.Error)
	}
	cfg.Address = strings.TrimRight(addr, "/")
	cfg.Timeout = requestTimeout
	cfg.HttpClient.Timeout = requestTimeout
	cfg.MaxRetries = 0
	if caFile := os.Getenv(env.CACert); caFile != "" {
		pemBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("reading OpenBao CA bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("no certificates found in OpenBao CA bundle %s", caFile)
		}
		// Only RootCAs: NewConfig's TLS config already has MinVersion
		// TLS 1.2 and the HTTP/2 ALPN protocols.
		cfg.HttpClient.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool
	}

	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", errs.NotConfigured, env.Addr, err)
	}
	// NewClient reads no environment with DisableEnvironment set; clear
	// anyway, so nothing but this identity's own token is ever sent.
	client.ClearToken()
	client.ClearNamespace()
	if ns := strings.Trim(os.Getenv(env.Namespace), "/"); ns != "" {
		client.SetNamespace(ns)
	}
	login, err := client.Clone() // shares the transport; CloneToken is off
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errs.NotConfigured, err)
	}
	login.ClearToken()
	if ns := client.Namespace(); ns != "" {
		login.SetNamespace(ns)
	}
	c.api, c.login, c.httpClient = client, login, cfg.HttpClient
	return c, nil
}

// Close releases the client's idle connections. For a Client built for
// one operation; a long-lived one never needs it.
func (c *Client) Close() {
	c.httpClient.CloseIdleConnections()
}

// Token returns a token currently valid for this identity: the static
// token, or for kubernetes auth the cached login token, logging in again
// first once less than 20% of its lease remains. Every request calls
// it, so a request after a long idle period never fires with a token
// that expired meanwhile. No goroutine renews in the background.
//
// Re-login rather than auth/token/renew-self: a renewal can't outlive
// the role's max TTL anyway, and each login re-reads the projected
// service account JWT the kubelet rotates.
func (c *Client) Token(ctx context.Context) (string, error) {
	if c.authMethod == AuthMethodToken {
		return c.staticToken, nil
	}
	c.authMu.Lock()
	defer c.authMu.Unlock()
	if c.authToken != "" && time.Now().Before(c.authExpiry) {
		return c.authToken, nil
	}
	return c.k8sLoginLocked(ctx)
}

// k8sLoginLocked logs in to the kubernetes auth method (POST
// auth/<mount>/login with {"role", "jwt"}) and caches the token until
// 80% of its lease has passed. Callers must hold c.authMu.
func (c *Client) k8sLoginLocked(ctx context.Context) (string, error) {
	jwtBytes, err := os.ReadFile(c.k8sJWTPath)
	if err != nil {
		return "", fmt.Errorf("%w: reading %s: %w", c.errs.K8sJWTUnavailable, c.k8sJWTPath, err)
	}
	jwt := strings.TrimSpace(string(jwtBytes))
	if jwt == "" {
		return "", fmt.Errorf("%w: %s is empty", c.errs.K8sJWTUnavailable, c.k8sJWTPath)
	}
	secret, err := do(ctx, c.login, "", http.MethodPost, "auth/"+c.k8sMount+"/login", nil,
		map[string]string{"role": c.k8sRole, "jwt": jwt})
	if err != nil {
		// %v, not %w: the login's HTTP status must never read as the
		// status of the request it was logging in for (StatusCode,
		// IsNotFound), or a refused login could pass for "secret absent"
		// or a lost check-and-set.
		return "", fmt.Errorf("%w: %v", c.errs.K8sAuthFailed, err)
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return "", fmt.Errorf("%w: response had no auth.client_token", c.errs.K8sAuthFailed)
	}
	lease := time.Duration(secret.Auth.LeaseDuration) * time.Second
	c.authToken = secret.Auth.ClientToken
	c.authExpiry = time.Now().Add(lease - lease/authTokenSafetyMargin)
	return c.authToken, nil
}

// Read is GET /v1/<path>?<query>. A 404 is a *StatusError (see
// IsNotFound), not (nil, nil).
func (c *Client) Read(ctx context.Context, path string, query url.Values) (*api.Secret, error) {
	return c.Request(ctx, http.MethodGet, path, query, nil)
}

// Put is PUT /v1/<path> with body as JSON.
func (c *Client) Put(ctx context.Context, path string, body any) (*api.Secret, error) {
	return c.Request(ctx, http.MethodPut, path, nil, body)
}

// Post is POST /v1/<path> with body as JSON. OpenBao treats POST and PUT
// alike; each caller keeps the method it always sent, so stubs and
// captured traffic written against it still match.
func (c *Client) Post(ctx context.Context, path string, body any) (*api.Secret, error) {
	return c.Request(ctx, http.MethodPost, path, nil, body)
}

// Request sends one request as this identity and parses the response.
// body, if not nil, is sent as JSON. A 2xx with an empty body (204)
// returns (nil, nil).
func (c *Client) Request(ctx context.Context, method, path string, query url.Values, body any) (*api.Secret, error) {
	token, err := c.Token(ctx)
	if err != nil {
		return nil, err
	}
	return do(ctx, c.api, token, method, path, query, body)
}

// ReadRaw is GET /v1/<path> for endpoints that answer with something
// other than a JSON secret (PKI's ca/pem), returning the body.
func (c *Client) ReadRaw(ctx context.Context, path string) ([]byte, error) {
	token, err := c.Token(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := send(ctx, c.api, token, http.MethodGet, path, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	return data, nil
}

// send makes one request. The 30 second bound comes from the client's
// own configuration: RawRequestWithContext applies Config.Timeout to the
// context, and HttpClient.Timeout covers reading the body.
func send(ctx context.Context, client *api.Client, token, method, path string, query url.Values, body any) (*api.Response, error) {
	r := client.NewRequest(method, "/v1/"+strings.TrimLeft(path, "/"))
	r.ClientToken = token
	for k, vs := range query {
		for _, v := range vs {
			r.Params.Add(k, v)
		}
	}
	if body != nil {
		if err := r.SetJSONBody(body); err != nil {
			return nil, fmt.Errorf("encoding request: %w", err)
		}
		r.Headers.Set("Content-Type", "application/json")
	}
	resp, err := client.RawRequestWithContext(ctx, r)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return nil, statusError(err)
	}
	return resp, nil
}

func do(ctx context.Context, client *api.Client, token, method, path string, query url.Values, body any) (*api.Secret, error) {
	resp, err := send(ctx, client, token, method, path, query, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	secret, err := api.ParseSecret(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return secret, nil
}

// StatusError is a non-2xx answer from OpenBao.
type StatusError struct {
	StatusCode int
	// Errors is OpenBao's "errors" array, or the raw body when it wasn't
	// JSON.
	Errors []string

	err *api.ResponseError
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("status %d: %s", e.StatusCode, strings.Join(e.Errors, "; "))
}

func (e *StatusError) Unwrap() error { return e.err }

func statusError(err error) error {
	var re *api.ResponseError
	if errors.As(err, &re) {
		return &StatusError{StatusCode: re.StatusCode, Errors: re.Errors, err: re}
	}
	return err
}

// StatusCode returns the HTTP status of a *StatusError in err's chain,
// or 0.
func StatusCode(err error) int {
	var se *StatusError
	if errors.As(err, &se) {
		return se.StatusCode
	}
	return 0
}

// IsNotFound reports whether err is OpenBao answering 404.
func IsNotFound(err error) bool { return StatusCode(err) == http.StatusNotFound }

// DecodeData decodes secret.Data into out (a pointer to a struct with
// json tags), so callers keep typed views of a response. Numbers in
// secret.Data are json.Number and decode into int fields.
func DecodeData(secret *api.Secret, out any) error {
	if secret == nil || secret.Data == nil {
		return nil
	}
	b, err := json.Marshal(secret.Data)
	if err != nil {
		return fmt.Errorf("decoding response data: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("decoding response data: %w", err)
	}
	return nil
}
