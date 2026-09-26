// Package openbaokv is a minimal client for OpenBao's KV v2 secrets
// engine: read and write one secret's data at a caller-supplied path.
// Its one consumer today is `farmer publish-saasapi-credential`
// (cmd/farmer), which pushes the SaaS API's freshly-minted NATS User JWT
// into OpenBao for External Secrets Operator to deliver to the saasapi
// Deployment. See docs/design/imas-internal-api-account.md's "JWT ->
// OpenBao hand-off".
//
// FLAG FOR SECURITY REVIEW: this is the only code in the repo that
// *writes* to OpenBao. The OpenBao identity it authenticates as (see
// EnvOpenBaoAuthMethod) must be a dedicated one, used only by that
// subcommand's Kubernetes Job, and must never be granted to farmer's
// long-running server process. deploy/farmer/README.md states the exact
// policy boundary.
//
// Like internal/certs (tls.go) and internal/gatewayjwt (obtransit.go),
// this talks to OpenBao's HTTP API over raw net/http: the official client
// (github.com/openbao/openbao/api, github.com/hashicorp/vault/api) is
// MPL-2.0 licensed, which conflicts with this repo's Apache-2.0/MIT-only
// dependency constraint (see CLAUDE.md).
//
// This is now the third near-identical hand-rolled OpenBao client. The
// auth-method plumbing (static token or Kubernetes auth, env-var driven,
// token caching with a 20% safety margin) deliberately mirrors
// internal/certs/tls.go's obClient and internal/gatewayjwt's
// obTransitClient line for line rather than being factored out into a
// shared package in the same change: both of those clients sit on
// security-reviewed paths (TLS issuance, the DMZ gateway signer), and
// refactoring them in a change whose own review focus is a new OpenBao
// write policy would widen that review for no functional gain. Extracting
// a shared internal/openbaoclient auth helper across all three is the
// natural follow-up.
package openbaokv

import (
	"bytes"
	"context"
	"crypto/tls"
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
)

// Environment variables configuring the OpenBao KV v2 client. Addr is
// always required; which of the rest matter depends on AuthMethod. Named
// IMAS_SAASAPI_CRED_OPENBAO_* rather than reusing internal/certs's
// IMAS_CERTS_OPENBAO_* or internal/gatewayjwt's IMAS_GATEWAY_OPENBAO_*:
// this is a distinct OpenBao identity (the only one with KV write access)
// and must never share an env block — or an auth role — with farmer's
// long-running process.
const (
	EnvOpenBaoAddr       = "IMAS_SAASAPI_CRED_OPENBAO_ADDR"
	EnvOpenBaoKVMount    = "IMAS_SAASAPI_CRED_OPENBAO_KV_MOUNT" // default "secret"
	EnvOpenBaoCACert     = "IMAS_SAASAPI_CRED_OPENBAO_CACERT"   // optional, verify OpenBao's own TLS
	EnvOpenBaoAuthMethod = "IMAS_SAASAPI_CRED_OPENBAO_AUTH_METHOD"

	// EnvOpenBaoToken is the bearer token used when AuthMethod is "token" (the default).
	EnvOpenBaoToken = "IMAS_SAASAPI_CRED_OPENBAO_TOKEN"

	// EnvOpenBaoK8sRole/EnvOpenBaoK8sMount/EnvOpenBaoK8sJWTPath configure
	// OpenBao's kubernetes auth method, used when AuthMethod is "kubernetes".
	EnvOpenBaoK8sRole    = "IMAS_SAASAPI_CRED_OPENBAO_K8S_ROLE"
	EnvOpenBaoK8sMount   = "IMAS_SAASAPI_CRED_OPENBAO_K8S_MOUNT"    // default "kubernetes"
	EnvOpenBaoK8sJWTPath = "IMAS_SAASAPI_CRED_OPENBAO_K8S_JWT_PATH" // default defaultK8sJWTPath
)

// Recognized values for IMAS_SAASAPI_CRED_OPENBAO_AUTH_METHOD.
const (
	AuthMethodToken      = "token"
	AuthMethodKubernetes = "kubernetes"
)

const (
	defaultKVMount    = "secret"
	defaultK8sJWTPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

// authTokenSafetyMargin is the fraction of a kubernetes-auth login's
// lease_duration reserved as a safety margin (same convention as
// internal/certs/tls.go and internal/gatewayjwt/obtransit.go).
const authTokenSafetyMargin = 5 // 1/5 = 20%

var (
	ErrNotConfigured = errors.New("openbaokv: openbao kv client not configured")
	ErrInvalidPath   = errors.New("openbaokv: invalid kv path")
	ErrReadFailed    = errors.New("openbaokv: openbao kv read failed")
	ErrWriteFailed   = errors.New("openbaokv: openbao kv write failed")

	ErrK8sJWTUnavailable = errors.New("openbaokv: openbao kubernetes auth: could not read service account token")
	ErrK8sAuthFailed     = errors.New("openbaokv: openbao kubernetes auth login failed")
)

// Client is a minimal client for the subset of OpenBao's HTTP API this
// package needs: KV v2's GET and POST /v1/<mount>/data/<path>.
type Client struct {
	addr       string
	mount      string // KV v2 secrets engine mount, default "secret"
	httpClient *http.Client

	authMethod  string
	staticToken string

	k8sRole    string
	k8sMount   string
	k8sJWTPath string

	authMu     sync.Mutex
	authToken  string
	authExpiry time.Time
}

// NewClientFromEnv builds a Client from the Env* variables above, read
// fresh on every call rather than cached at package init (same rationale
// as internal/certs/tls.go's newClientFromEnv: tests routinely change the
// environment to point at a local server).
func NewClientFromEnv() (*Client, error) {
	addr := os.Getenv(EnvOpenBaoAddr)
	if addr == "" {
		return nil, fmt.Errorf("%w: %s is required", ErrNotConfigured, EnvOpenBaoAddr)
	}
	mount := strings.Trim(os.Getenv(EnvOpenBaoKVMount), "/")
	if mount == "" {
		mount = defaultKVMount
	}
	if err := validatePath(mount); err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrNotConfigured, EnvOpenBaoKVMount, err)
	}
	authMethod := os.Getenv(EnvOpenBaoAuthMethod)
	if authMethod == "" {
		authMethod = AuthMethodToken
	}

	c := &Client{
		addr:       strings.TrimRight(addr, "/"),
		mount:      mount,
		authMethod: authMethod,
	}

	switch authMethod {
	case AuthMethodToken:
		token := os.Getenv(EnvOpenBaoToken)
		if token == "" {
			return nil, fmt.Errorf("%w: %s is required when %s=%s (or unset)",
				ErrNotConfigured, EnvOpenBaoToken, EnvOpenBaoAuthMethod, AuthMethodToken)
		}
		c.staticToken = token
	case AuthMethodKubernetes:
		k8sRole := os.Getenv(EnvOpenBaoK8sRole)
		if k8sRole == "" {
			return nil, fmt.Errorf("%w: %s is required when %s=%s",
				ErrNotConfigured, EnvOpenBaoK8sRole, EnvOpenBaoAuthMethod, AuthMethodKubernetes)
		}
		c.k8sRole = k8sRole
		c.k8sMount = os.Getenv(EnvOpenBaoK8sMount)
		if c.k8sMount == "" {
			c.k8sMount = "kubernetes"
		}
		c.k8sJWTPath = os.Getenv(EnvOpenBaoK8sJWTPath)
		if c.k8sJWTPath == "" {
			c.k8sJWTPath = defaultK8sJWTPath
		}
	default:
		return nil, fmt.Errorf("%w: unknown %s %q (want %q or %q)",
			ErrNotConfigured, EnvOpenBaoAuthMethod, authMethod, AuthMethodToken, AuthMethodKubernetes)
	}

	var transport http.RoundTripper = http.DefaultTransport
	if caFile := os.Getenv(EnvOpenBaoCACert); caFile != "" {
		pemBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("reading OpenBao CA bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("no certificates found in OpenBao CA bundle %s", caFile)
		}
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		}
	}
	c.httpClient = &http.Client{Transport: transport, Timeout: 30 * time.Second}
	return c, nil
}

// Mount is the KV v2 mount this client reads and writes under.
func (c *Client) Mount() string { return c.mount }

// currentToken mirrors internal/certs/tls.go's (*obClient).currentToken.
func (c *Client) currentToken(ctx context.Context) (string, error) {
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

type k8sLoginAuth struct {
	ClientToken   string `json:"client_token"`
	LeaseDuration int    `json:"lease_duration"`
	Renewable     bool   `json:"renewable"`
}

type k8sLoginResponse struct {
	Auth   *k8sLoginAuth `json:"auth"`
	Errors []string      `json:"errors"`
}

// k8sLoginLocked mirrors internal/certs/tls.go's
// (*obClient).k8sLoginLocked. Callers must hold c.authMu.
func (c *Client) k8sLoginLocked(ctx context.Context) (string, error) {
	jwtBytes, err := os.ReadFile(c.k8sJWTPath)
	if err != nil {
		return "", fmt.Errorf("%w: reading %s: %w", ErrK8sJWTUnavailable, c.k8sJWTPath, err)
	}
	jwt := strings.TrimSpace(string(jwtBytes))
	if jwt == "" {
		return "", fmt.Errorf("%w: %s is empty", ErrK8sJWTUnavailable, c.k8sJWTPath)
	}

	reqBody, err := json.Marshal(map[string]string{"role": c.k8sRole, "jwt": jwt})
	if err != nil {
		return "", fmt.Errorf("%w: encoding request: %w", ErrK8sAuthFailed, err)
	}
	reqURL := fmt.Sprintf("%s/v1/auth/%s/login", c.addr, c.k8sMount)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrK8sAuthFailed, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrK8sAuthFailed, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("%w: reading response: %w", ErrK8sAuthFailed, err)
	}
	var lr k8sLoginResponse
	if resp.StatusCode != http.StatusOK {
		_ = json.Unmarshal(data, &lr)
		return "", fmt.Errorf("%w: status %d: %s", ErrK8sAuthFailed, resp.StatusCode, strings.Join(lr.Errors, "; "))
	}
	if err := json.Unmarshal(data, &lr); err != nil {
		return "", fmt.Errorf("%w: decoding response: %w", ErrK8sAuthFailed, err)
	}
	if lr.Auth == nil || lr.Auth.ClientToken == "" {
		return "", fmt.Errorf("%w: response had no auth.client_token: %s", ErrK8sAuthFailed, strings.Join(lr.Errors, "; "))
	}

	c.authToken = lr.Auth.ClientToken
	margin := time.Duration(lr.Auth.LeaseDuration) * time.Second / authTokenSafetyMargin
	c.authExpiry = time.Now().Add(time.Duration(lr.Auth.LeaseDuration)*time.Second - margin)
	return c.authToken, nil
}

// validatePath rejects a mount or secret path that is empty, has empty
// segments, or contains "." / ".." segments. OpenBao's policy language
// matches on the literal request path, so a path that a proxy or the
// server could normalize to something else is refused outright rather
// than escaped.
func validatePath(p string) error {
	if p == "" {
		return fmt.Errorf("%w: empty", ErrInvalidPath)
	}
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "":
			return fmt.Errorf("%w: %q has an empty segment", ErrInvalidPath, p)
		case ".", "..":
			return fmt.Errorf("%w: %q has a %q segment", ErrInvalidPath, p, seg)
		}
	}
	return nil
}

// dataURL is KV v2's data endpoint for secretPath under c.mount, with
// each path segment escaped.
func (c *Client) dataURL(secretPath string) (string, error) {
	secretPath = strings.Trim(secretPath, "/")
	if err := validatePath(secretPath); err != nil {
		return "", err
	}
	segs := strings.Split(c.mount+"/data/"+secretPath, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return c.addr + "/v1/" + strings.Join(segs, "/"), nil
}

type kvReadResponse struct {
	Data *struct {
		Data map[string]any `json:"data"`
	} `json:"data"`
	Errors []string `json:"errors"`
}

type kvErrorResponse struct {
	Errors []string `json:"errors"`
}

// Read returns the latest version of the secret at secretPath, keeping
// only its string-valued fields. A secret that doesn't exist — or whose
// latest version is soft-deleted or destroyed, which KV v2 also answers
// with 404 — is reported as (nil, nil), not an error.
func (c *Client) Read(ctx context.Context, secretPath string) (map[string]string, error) {
	reqURL, err := c.dataURL(secretPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}
	token, err := c.currentToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadFailed, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: reading response: %w", ErrReadFailed, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		var er kvErrorResponse
		_ = json.Unmarshal(body, &er)
		return nil, fmt.Errorf("%w: status %d: %s", ErrReadFailed, resp.StatusCode, strings.Join(er.Errors, "; "))
	}
	var rr kvReadResponse
	if err := json.Unmarshal(body, &rr); err != nil {
		return nil, fmt.Errorf("%w: decoding response: %w", ErrReadFailed, err)
	}
	if rr.Data == nil || rr.Data.Data == nil {
		return nil, nil
	}
	out := make(map[string]string, len(rr.Data.Data))
	for k, v := range rr.Data.Data {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out, nil
}

type kvWriteResponse struct {
	Data struct {
		Version int `json:"version"`
	} `json:"data"`
	Errors []string `json:"errors"`
}

// Write stores data as a new version of the secret at secretPath (KV v2
// POST /v1/<mount>/data/<path>), replacing every field of the previous
// version, and returns the version number OpenBao assigned.
func (c *Client) Write(ctx context.Context, secretPath string, data map[string]string) (int, error) {
	reqURL, err := c.dataURL(secretPath)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrWriteFailed, err)
	}
	token, err := c.currentToken(ctx)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrWriteFailed, err)
	}
	reqBody, err := json.Marshal(map[string]any{"data": data})
	if err != nil {
		return 0, fmt.Errorf("%w: encoding request: %w", ErrWriteFailed, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(reqBody))
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrWriteFailed, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrWriteFailed, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("%w: reading response: %w", ErrWriteFailed, err)
	}
	var wr kvWriteResponse
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		_ = json.Unmarshal(body, &wr)
		return 0, fmt.Errorf("%w: status %d: %s", ErrWriteFailed, resp.StatusCode, strings.Join(wr.Errors, "; "))
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &wr); err != nil {
			return 0, fmt.Errorf("%w: decoding response: %w", ErrWriteFailed, err)
		}
	}
	return wr.Data.Version, nil
}

// Secret binds a Client to one secret path, for callers (such as
// pki.PublishSaaSAPICredential) that only ever read and write a single
// secret.
type Secret struct {
	c    *Client
	path string
}

// At returns a Secret for secretPath, validated up front so a bad path
// fails before anything is minted or sent.
func (c *Client) At(secretPath string) (*Secret, error) {
	secretPath = strings.Trim(secretPath, "/")
	if err := validatePath(secretPath); err != nil {
		return nil, err
	}
	return &Secret{c: c, path: secretPath}, nil
}

// Path is the secret path (relative to the client's mount).
func (s *Secret) Path() string { return s.path }

// Read is (*Client).Read at s's path.
func (s *Secret) Read(ctx context.Context) (map[string]string, error) {
	return s.c.Read(ctx, s.path)
}

// Write is (*Client).Write at s's path, discarding the version number.
func (s *Secret) Write(ctx context.Context, data map[string]string) error {
	_, err := s.c.Write(ctx, s.path, data)
	return err
}
