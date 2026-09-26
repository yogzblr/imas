// Package gatewayjwt mints and serves the "gateway JWT" — a standard
// alg:EdDSA companion token to the NATS User JWT workstream B already
// builds (internal/pki/jwtusers.go), signed by a single platform-wide
// OpenBao Transit Ed25519 key rather than any tenant's Account signing
// key. See docs/design/imas-envoy-enrollment-design.md and the
// "Gateway JWT Companion Token" implementation brief this package was
// built from.
//
// Why a second token at all: the NATS User JWT's JOSE header carries
// "alg":"ed25519-nkey" (github.com/nats-io/jwt/v2, see header.go's
// AlgorithmNkey) — a NATS-specific value no standard JOSE library,
// including Envoy's jwt_authn filter, recognizes. Relabeling it after
// signing isn't an option either: the JWS signature covers the header
// bytes. The gateway JWT carries the same subject/tenant/sprout claims in
// a genuinely standard EdDSA JWS envelope instead, for the two
// Envoy-gated surfaces (the wss:// upgrade and the recipe-download
// route) — nats-server keeps validating the native-format token,
// unaffected.
//
// FLAG FOR SECURITY REVIEW — this package's signer is the trust anchor
// for both Envoy-gated DMZ routes.
package gatewayjwt

// This file talks to OpenBao/Vault's Transit secrets engine over raw
// net/http, the same way internal/certs (tls.go) and
// internal/ingredients/sdb/openbao (provider.go) already do. Their header
// comments explain why: the official client
// (github.com/openbao/openbao/api, github.com/hashicorp/vault/api) is
// MPL-2.0 licensed, which conflicts with this repo's Apache-2.0/MIT-only
// dependency constraint (see CLAUDE.md) — confirmed against both of those
// packages' own doc comments before writing this one, rather than
// re-adding the dependency an earlier draft of this brief called for.
//
// The auth-method plumbing below (static token or Kubernetes auth,
// env-var driven, token caching with a safety margin) intentionally
// mirrors internal/certs/tls.go's obClient almost line for line — that
// type is unexported and PKI-endpoint-specific, so it isn't reusable
// as-is, but the pattern is worth keeping identical rather than
// inventing a third shape for the same problem. A future refactor
// extracting a shared "OpenBao HTTP auth" helper across
// internal/certs/internal/gatewayjwt would be reasonable but is out of
// this package's scope.
import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Environment variables configuring the OpenBao Transit client used to
// sign gateway JWTs. Addr is always required; which of the rest matter
// depends on AuthMethod. Named IMAS_GATEWAY_OPENBAO_* rather than reusing
// internal/certs's IMAS_CERTS_OPENBAO_* names: this is a distinct OpenBao
// connection (Transit, not PKI), plausibly pointed at a different address
// or auth role than the TLS cert client.
const (
	EnvOpenBaoAddr         = "IMAS_GATEWAY_OPENBAO_ADDR"
	EnvOpenBaoTransitMount = "IMAS_GATEWAY_OPENBAO_TRANSIT_MOUNT" // default "transit"
	EnvOpenBaoCACert       = "IMAS_GATEWAY_OPENBAO_CACERT"        // optional, verify OpenBao's own TLS
	EnvOpenBaoAuthMethod   = "IMAS_GATEWAY_OPENBAO_AUTH_METHOD"   // "token" (default) or "kubernetes"

	// EnvOpenBaoToken is the bearer token used when AuthMethod is "token" (the default).
	EnvOpenBaoToken = "IMAS_GATEWAY_OPENBAO_TOKEN"

	// EnvOpenBaoK8sRole/EnvOpenBaoK8sMount/EnvOpenBaoK8sJWTPath configure
	// OpenBao's kubernetes auth method, used when AuthMethod is "kubernetes".
	EnvOpenBaoK8sRole    = "IMAS_GATEWAY_OPENBAO_K8S_ROLE"
	EnvOpenBaoK8sMount   = "IMAS_GATEWAY_OPENBAO_K8S_MOUNT"    // default "kubernetes"
	EnvOpenBaoK8sJWTPath = "IMAS_GATEWAY_OPENBAO_K8S_JWT_PATH" // default defaultK8sJWTPath
)

// Recognized values for IMAS_GATEWAY_OPENBAO_AUTH_METHOD.
const (
	AuthMethodToken      = "token"
	AuthMethodKubernetes = "kubernetes"
)

const defaultK8sJWTPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// authTokenSafetyMargin is the fraction of a kubernetes-auth login's
// lease_duration reserved as a safety margin (same convention as
// internal/certs/tls.go).
const authTokenSafetyMargin = 5 // 1/5 = 20%

var (
	ErrNotConfigured = errors.New("gatewayjwt: openbao transit client not configured")
	ErrSignFailed    = errors.New("gatewayjwt: openbao transit sign failed")
	ErrReadKeyFailed = errors.New("gatewayjwt: openbao transit key read failed")

	ErrK8sJWTUnavailable = errors.New("gatewayjwt: openbao kubernetes auth: could not read service account token")
	ErrK8sAuthFailed     = errors.New("gatewayjwt: openbao kubernetes auth login failed")
)

// obTransitClient is a minimal client for the subset of OpenBao's HTTP
// API this package needs: transit/sign/<key> and transit/keys/<key>.
type obTransitClient struct {
	addr       string
	mount      string // Transit secrets engine mount, default "transit"
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

// newTransitClientFromEnv builds an obTransitClient from the Env*
// variables above, called fresh on every GatewaySigner construction
// rather than cached at package init (same rationale as
// internal/certs/tls.go's newClientFromEnv: tests routinely change the
// environment to point at a local dev instance).
func newTransitClientFromEnv() (*obTransitClient, error) {
	addr := os.Getenv(EnvOpenBaoAddr)
	if addr == "" {
		return nil, fmt.Errorf("%w: %s is required", ErrNotConfigured, EnvOpenBaoAddr)
	}
	mount := os.Getenv(EnvOpenBaoTransitMount)
	if mount == "" {
		mount = "transit"
	}
	authMethod := os.Getenv(EnvOpenBaoAuthMethod)
	if authMethod == "" {
		authMethod = AuthMethodToken
	}

	c := &obTransitClient{
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

// currentToken mirrors internal/certs/tls.go's (*obClient).currentToken.
func (c *obTransitClient) currentToken(ctx context.Context) (string, error) {
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
func (c *obTransitClient) k8sLoginLocked(ctx context.Context) (string, error) {
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

type transitSignResponse struct {
	Data struct {
		Signature  string `json:"signature"`
		KeyVersion int    `json:"key_version"`
	} `json:"data"`
	Errors []string `json:"errors"`
}

// sign calls Transit's POST /v1/<mount>/sign/<keyName>, signing input
// (the exact bytes to be signed — no local hashing; Ed25519 signs the
// message directly) and returning the raw signature bytes plus the key
// version Transit signed with.
func (c *obTransitClient) sign(ctx context.Context, keyName string, input []byte) (sig []byte, keyVersion int, err error) {
	token, err := c.currentToken(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrSignFailed, err)
	}

	reqBody, err := json.Marshal(map[string]string{
		"input": base64.StdEncoding.EncodeToString(input),
	})
	if err != nil {
		return nil, 0, fmt.Errorf("%w: encoding request: %w", ErrSignFailed, err)
	}
	reqURL := fmt.Sprintf("%s/v1/%s/sign/%s", c.addr, c.mount, keyName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrSignFailed, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrSignFailed, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: reading response: %w", ErrSignFailed, err)
	}
	var sr transitSignResponse
	if resp.StatusCode != http.StatusOK {
		_ = json.Unmarshal(data, &sr)
		return nil, 0, fmt.Errorf("%w: status %d: %s", ErrSignFailed, resp.StatusCode, strings.Join(sr.Errors, "; "))
	}
	if err := json.Unmarshal(data, &sr); err != nil {
		return nil, 0, fmt.Errorf("%w: decoding response: %w", ErrSignFailed, err)
	}
	// Transit's signature field is "<prefix>:v<version>:<base64>" (the
	// prefix word is "vault" on both Vault and OpenBao — OpenBao kept it
	// for wire compatibility). Take the last ':'-delimited segment rather
	// than assuming the exact prefix, and trust data.key_version (a
	// separate JSON field) for the version rather than parsing it back
	// out of this string.
	parts := strings.Split(sr.Data.Signature, ":")
	if len(parts) < 3 {
		return nil, 0, fmt.Errorf("%w: unexpected signature format %q", ErrSignFailed, sr.Data.Signature)
	}
	raw, err := base64.StdEncoding.DecodeString(parts[len(parts)-1])
	if err != nil {
		return nil, 0, fmt.Errorf("%w: decoding signature: %w", ErrSignFailed, err)
	}
	return raw, sr.Data.KeyVersion, nil
}

type transitKeyVersionInfo struct {
	PublicKey    string `json:"public_key"`
	CreationTime string `json:"creation_time"`
}

type transitReadKeyResponse struct {
	Data struct {
		Type                 string                           `json:"type"`
		Keys                 map[string]transitKeyVersionInfo `json:"keys"`
		MinEncryptionVersion int                              `json:"min_encryption_version"`
		LatestVersion        int                              `json:"latest_version"`
	} `json:"data"`
	Errors []string `json:"errors"`
}

// transitKeyInfo is readKey's parsed result.
type transitKeyInfo struct {
	Type                 string
	Versions             map[int]transitKeyVersionInfo
	MinEncryptionVersion int
	LatestVersion        int
}

// readKey calls Transit's GET /v1/<mount>/keys/<keyName>, returning every
// key version and version metadata (base64 public key, creation time) plus
// the key's current min_encryption_version/latest_version.
func (c *obTransitClient) readKey(ctx context.Context, keyName string) (*transitKeyInfo, error) {
	token, err := c.currentToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadKeyFailed, err)
	}

	reqURL := fmt.Sprintf("%s/v1/%s/keys/%s", c.addr, c.mount, keyName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadKeyFailed, err)
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadKeyFailed, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: reading response: %w", ErrReadKeyFailed, err)
	}
	var rr transitReadKeyResponse
	if resp.StatusCode != http.StatusOK {
		_ = json.Unmarshal(data, &rr)
		return nil, fmt.Errorf("%w: status %d: %s", ErrReadKeyFailed, resp.StatusCode, strings.Join(rr.Errors, "; "))
	}
	if err := json.Unmarshal(data, &rr); err != nil {
		return nil, fmt.Errorf("%w: decoding response: %w", ErrReadKeyFailed, err)
	}

	versions := make(map[int]transitKeyVersionInfo, len(rr.Data.Keys))
	for k, v := range rr.Data.Keys {
		n, convErr := strconv.Atoi(k)
		if convErr != nil {
			return nil, fmt.Errorf("%w: unexpected key version %q", ErrReadKeyFailed, k)
		}
		versions[n] = v
	}
	return &transitKeyInfo{
		Type:                 rr.Data.Type,
		Versions:             versions,
		MinEncryptionVersion: rr.Data.MinEncryptionVersion,
		LatestVersion:        rr.Data.LatestVersion,
	}, nil
}

// parseTransitEd25519PublicKey decodes the public_key Transit's
// keys/<key> read returns for an ed25519 key version: the raw 32-byte
// key in standard base64. Transit uses PEM only for ECDSA and RSA keys,
// never for Ed25519 (see testdata/openbao-v2.7.0/transit-keys.json, a
// captured real response).
func parseTransitEd25519PublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("gatewayjwt: Transit public key is not standard base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("gatewayjwt: Transit public key is %d bytes, want %d (Ed25519)", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}
