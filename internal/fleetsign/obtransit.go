package fleetsign

// This file is a READ-ONLY OpenBao Transit client for the
// imas-fleet-signing key, used by farmer (to serve the key's public half
// and to re-check a release's signature before dispatching a
// self_update) and by saasapi (to check a catalog row's signature before
// building a rollout). It is a copy of internal/gatewayjwt/obtransit.go's
// hand-rolled HTTP client pattern — raw net/http, static-token or
// Kubernetes auth, token caching with a 20% safety margin — for the same
// reason every other OpenBao client in this repo is hand-rolled: the
// official client (github.com/openbao/openbao/api,
// github.com/hashicorp/vault/api) is MPL-2.0, which CLAUDE.md's
// Apache-2.0/MIT-only rule disallows as a dependency.
//
// Deliberately NOT copied: gatewayjwt's sign method. The only request
// this client can make against Transit is GET <mount>/keys/<key>. The
// sign-capable copy of this pattern lives in cmd/fleetreleaser, a
// separate binary with its own OpenBao identity. Whether farmer's and
// saasapi's tokens *can* sign is decided by their OpenBao policy
// (deploy/fleetreleaser/policies/imas-fleet-verify.hcl), which is what
// actually enforces the split — see cmd/fleetreleaser's
// TestOpenBaoEnforcesReadOnlyFleetKey.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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

// Environment variables configuring the read-only Transit client. Named
// IMAS_FLEETSIGN_OPENBAO_* rather than reusing IMAS_GATEWAY_OPENBAO_*:
// farmer's gateway identity holds sign capability on imas-gateway-jwt,
// and this identity must hold none on anything. Keeping the env blocks
// apart keeps the tokens apart. cmd/fleetreleaser's signer uses its own
// IMAS_FLEETRELEASER_OPENBAO_* block and never reads these.
const (
	EnvOpenBaoAddr         = "IMAS_FLEETSIGN_OPENBAO_ADDR"
	EnvOpenBaoTransitMount = "IMAS_FLEETSIGN_OPENBAO_TRANSIT_MOUNT" // default "transit"
	EnvOpenBaoCACert       = "IMAS_FLEETSIGN_OPENBAO_CACERT"        // optional, verify OpenBao's own TLS
	EnvOpenBaoAuthMethod   = "IMAS_FLEETSIGN_OPENBAO_AUTH_METHOD"   // "token" (default) or "kubernetes"

	// EnvOpenBaoToken is the bearer token used when AuthMethod is "token" (the default).
	EnvOpenBaoToken = "IMAS_FLEETSIGN_OPENBAO_TOKEN"

	// EnvOpenBaoK8sRole/EnvOpenBaoK8sMount/EnvOpenBaoK8sJWTPath configure
	// OpenBao's kubernetes auth method, used when AuthMethod is "kubernetes".
	EnvOpenBaoK8sRole    = "IMAS_FLEETSIGN_OPENBAO_K8S_ROLE"
	EnvOpenBaoK8sMount   = "IMAS_FLEETSIGN_OPENBAO_K8S_MOUNT"    // default "kubernetes"
	EnvOpenBaoK8sJWTPath = "IMAS_FLEETSIGN_OPENBAO_K8S_JWT_PATH" // default defaultK8sJWTPath

	// EnvTransitKeyName overrides DefaultTransitKeyName.
	EnvTransitKeyName = "IMAS_FLEETSIGN_TRANSIT_KEY"
)

// Recognized values for IMAS_FLEETSIGN_OPENBAO_AUTH_METHOD.
const (
	AuthMethodToken      = "token"
	AuthMethodKubernetes = "kubernetes"
)

const defaultK8sJWTPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// authTokenSafetyMargin mirrors internal/gatewayjwt/obtransit.go's.
const authTokenSafetyMargin = 5 // 1/5 = 20%

var (
	ErrNotConfigured = errors.New("fleetsign: openbao transit client not configured")
	ErrReadKeyFailed = errors.New("fleetsign: openbao transit key read failed")

	ErrK8sJWTUnavailable = errors.New("fleetsign: openbao kubernetes auth: could not read service account token")
	ErrK8sAuthFailed     = errors.New("fleetsign: openbao kubernetes auth login failed")
)

// obTransitClient is a read-only client for Transit's GET
// /v1/<mount>/keys/<key>.
type obTransitClient struct {
	addr       string
	mount      string
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

// newTransitClientFromEnv mirrors internal/gatewayjwt's: read fresh on
// every construction so tests can point it at a local server.
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

// currentToken mirrors internal/gatewayjwt/obtransit.go's.
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

type k8sLoginResponse struct {
	Auth *struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
	} `json:"auth"`
	Errors []string `json:"errors"`
}

// k8sLoginLocked mirrors internal/gatewayjwt/obtransit.go's. Callers must
// hold c.authMu.
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

type transitReadKeyResponse struct {
	Data struct {
		Type string `json:"type"`
		Keys map[string]struct {
			PublicKey string `json:"public_key"`
		} `json:"keys"`
		// MinEncryptionVersion is the floor for producing NEW signatures —
		// a signer-side concern. Decoded but deliberately not used here.
		MinEncryptionVersion int `json:"min_encryption_version"`
		// MinDecryptionVersion is the floor Transit's own /verify honors,
		// and the one readKeySet filters on.
		MinDecryptionVersion int `json:"min_decryption_version"`
		LatestVersion        int `json:"latest_version"`
	} `json:"data"`
	Errors []string `json:"errors"`
}

// readKeySet calls Transit's GET /v1/<mount>/keys/<keyName> and returns
// every key version Transit itself would still verify with: those at or
// above min_decryption_version, sorted ascending. That is the floor
// Transit's own /verify honors for signing keys. min_encryption_version
// is only the floor for producing NEW signatures (cmd/fleetreleaser's
// concern) and is always >= min_decryption_version, so flooring on it
// here would drop versions Transit still accepts and turn every rotation
// grace period into false verification failures. This intentionally
// differs from internal/gatewayjwt's (*GatewaySigner).PublicKeys, which
// floors its JWKS on min_encryption_version; the version-sorted
// {version, public key} shape is the same.
//
// Every verifier of a fleet release (farmer's self_update re-check,
// saasapi's dispatch check, the enrollment pin, and the live key set
// sprouts fetch on imas.sprouts.<id>.fleetsigningkeys) uses this one
// selection, so they all agree on which versions are valid.
//
// Consequence, and an OPERATIONAL CONSTRAINT: raising
// imas-fleet-signing's min_decryption_version retires every version below
// it for verification — on every sprout, in farmer and in saasapi. Never
// raise it past a version that signed a release still named as
// approved_version in any tenant's saas.tenant_update_policy. (Raising
// min_encryption_version alone only stops NEW signatures with the older
// versions; it doesn't retire anything for verification.) Nothing in
// this repo bumps either floor or retires versions automatically; that
// stays an operator decision (deploy/fleetreleaser/README.md, "Rotating
// the key").
func (c *obTransitClient) readKeySet(ctx context.Context, keyName string) (KeySet, error) {
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
	if rr.Data.Type != "ed25519" {
		return nil, fmt.Errorf("%w: Transit key %q is type %q, want ed25519", ErrReadKeyFailed, keyName, rr.Data.Type)
	}
	// A floor of 0 is Transit's "no restriction" sentinel: treat it as 1,
	// the same handling PublicKeys gives min_encryption_version.
	minVersion := rr.Data.MinDecryptionVersion
	if minVersion < 1 {
		minVersion = 1
	}
	keys := make([]PublicKey, 0, len(rr.Data.Keys))
	for k, v := range rr.Data.Keys {
		version, convErr := strconv.Atoi(k)
		if convErr != nil {
			return nil, fmt.Errorf("%w: unexpected key version %q", ErrReadKeyFailed, k)
		}
		if version < minVersion {
			continue
		}
		pub, perr := ParseTransitEd25519PublicKey(v.PublicKey)
		if perr != nil {
			return nil, fmt.Errorf("%w: key version %d: %w", ErrReadKeyFailed, version, perr)
		}
		keys = append(keys, PublicKey{Version: version, Key: pub})
	}
	return NewKeySet(keys)
}

// ParseTransitEd25519PublicKey decodes the public_key Transit's
// keys/<key> read returns for an ed25519 key version: the raw 32-byte
// key in standard base64. Transit uses PEM only for ECDSA and RSA keys,
// never for Ed25519 (see testdata/openbao-v2.7.0/transit-keys.json, a
// captured real response).
func ParseTransitEd25519PublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("fleetsign: Transit public key is not standard base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("fleetsign: Transit public key is %d bytes, want %d (Ed25519)", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// ParseEd25519PublicKeyPEM is kept for cmd/fleetreleaser's key-set
// read. It parses what real Transit returns (ParseTransitEd25519PublicKey)
// and, only so that caller's PEM test fixture keeps passing, also a PEM
// SubjectPublicKeyInfo block.
//
// Deprecated: use ParseTransitEd25519PublicKey. Remove once
// cmd/fleetreleaser's caller and its fixture move to it.
func ParseEd25519PublicKeyPEM(s string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return ParseTransitEd25519PublicKey(s)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("fleetsign: parsing Transit public key: %w", err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("fleetsign: Transit key is not an Ed25519 public key (got %T)", pub)
	}
	return edPub, nil
}

// keySetCacheTTL bounds how often a TransitKeySource hits Transit, same
// value and rationale as internal/gatewayjwt's transitPublicKeyCacheTTL.
const keySetCacheTTL = 60 * time.Second

// TransitKeySource serves the imas-fleet-signing public keys from
// OpenBao Transit, read-only, cached in-process for keySetCacheTTL.
type TransitKeySource struct {
	client  *obTransitClient
	keyName string

	mu    sync.Mutex
	at    time.Time
	cache KeySet
}

// NewTransitKeySourceFromEnv builds a TransitKeySource from the
// IMAS_FLEETSIGN_OPENBAO_* environment variables. The key name is
// IMAS_FLEETSIGN_TRANSIT_KEY, defaulting to DefaultTransitKeyName.
func NewTransitKeySourceFromEnv() (*TransitKeySource, error) {
	client, err := newTransitClientFromEnv()
	if err != nil {
		return nil, err
	}
	keyName := os.Getenv(EnvTransitKeyName)
	if keyName == "" {
		keyName = DefaultTransitKeyName
	}
	return &TransitKeySource{client: client, keyName: keyName}, nil
}

// KeyName returns the Transit key this source reads.
func (s *TransitKeySource) KeyName() string { return s.keyName }

// KeySet returns the key versions Transit would still verify with.
func (s *TransitKeySource) KeySet(ctx context.Context) (KeySet, error) {
	s.mu.Lock()
	if s.cache != nil && time.Since(s.at) < keySetCacheTTL {
		ks := s.cache
		s.mu.Unlock()
		return ks, nil
	}
	s.mu.Unlock()

	ks, err := s.client.readKeySet(ctx, s.keyName)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.cache, s.at = ks, time.Now()
	s.mu.Unlock()
	return ks, nil
}

// Verify checks r's signature against the key set Transit currently
// serves.
func (s *TransitKeySource) Verify(ctx context.Context, r Release, signature string) error {
	ks, err := s.KeySet(ctx)
	if err != nil {
		return err
	}
	return ks.Verify(r, signature)
}
