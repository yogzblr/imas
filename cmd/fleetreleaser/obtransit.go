package main

// The sign-capable OpenBao Transit client for imas-fleet-signing — the
// only one in the repo. A copy of internal/gatewayjwt/obtransit.go's
// hand-rolled HTTP client pattern (raw net/http, static-token or
// Kubernetes auth, token caching with a 20% safety margin): the official
// OpenBao/Vault Go client is MPL-2.0, which CLAUDE.md's
// Apache-2.0/MIT-only rule disallows as a dependency.
//
// It lives in package main on purpose. internal/fleetsign, which farmer,
// saasapi and sprout import, holds only the read-only half of this
// pattern; nothing importable carries a Transit sign call for this key.
// That is hygiene, not the security boundary: the boundary is that only
// this binary's OpenBao identity has a policy granting
// transit/sign/imas-fleet-signing (deploy/fleetreleaser/).
//
// FLAG FOR SECURITY REVIEW.

import (
	"bytes"
	"context"
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

	"github.com/yogzblr/imas/internal/fleetsign"
)

// Environment variables for fleetreleaser's own OpenBao identity. A
// distinct prefix from farmer's IMAS_GATEWAY_OPENBAO_* and farmer's and
// saasapi's IMAS_FLEETSIGN_OPENBAO_*, so the signing token can't end up in
// either of their env blocks by copy-paste.
const (
	EnvOpenBaoAddr         = "IMAS_FLEETRELEASER_OPENBAO_ADDR"
	EnvOpenBaoTransitMount = "IMAS_FLEETRELEASER_OPENBAO_TRANSIT_MOUNT" // default "transit"
	EnvOpenBaoCACert       = "IMAS_FLEETRELEASER_OPENBAO_CACERT"
	EnvOpenBaoAuthMethod   = "IMAS_FLEETRELEASER_OPENBAO_AUTH_METHOD" // "token" (default) or "kubernetes"
	EnvOpenBaoToken        = "IMAS_FLEETRELEASER_OPENBAO_TOKEN"
	EnvOpenBaoK8sRole      = "IMAS_FLEETRELEASER_OPENBAO_K8S_ROLE"
	EnvOpenBaoK8sMount     = "IMAS_FLEETRELEASER_OPENBAO_K8S_MOUNT"    // default "kubernetes"
	EnvOpenBaoK8sJWTPath   = "IMAS_FLEETRELEASER_OPENBAO_K8S_JWT_PATH" // default defaultK8sJWTPath

	// EnvTransitKeyName overrides fleetsign.DefaultTransitKeyName.
	EnvTransitKeyName = "IMAS_FLEETRELEASER_TRANSIT_KEY"
)

const (
	authMethodToken      = "token"
	authMethodKubernetes = "kubernetes"
	defaultK8sJWTPath    = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	// authTokenSafetyMargin mirrors internal/gatewayjwt/obtransit.go's.
	authTokenSafetyMargin = 5 // 1/5 = 20%
)

var (
	errNotConfigured = errors.New("fleetreleaser: openbao transit client not configured")
	errSignFailed    = errors.New("fleetreleaser: openbao transit sign failed")
	errReadKeyFailed = errors.New("fleetreleaser: openbao transit key read failed")
	errK8sAuthFailed = errors.New("fleetreleaser: openbao kubernetes auth login failed")
)

// obTransitClient is a minimal client for transit/sign/<key> and
// transit/keys/<key>.
type obTransitClient struct {
	addr       string
	mount      string
	keyName    string
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

func newTransitClientFromEnv() (*obTransitClient, error) {
	addr := os.Getenv(EnvOpenBaoAddr)
	if addr == "" {
		return nil, fmt.Errorf("%w: %s is required", errNotConfigured, EnvOpenBaoAddr)
	}
	c := &obTransitClient{
		addr:       strings.TrimRight(addr, "/"),
		mount:      os.Getenv(EnvOpenBaoTransitMount),
		keyName:    os.Getenv(EnvTransitKeyName),
		authMethod: os.Getenv(EnvOpenBaoAuthMethod),
	}
	if c.mount == "" {
		c.mount = "transit"
	}
	if c.keyName == "" {
		c.keyName = fleetsign.DefaultTransitKeyName
	}
	if c.authMethod == "" {
		c.authMethod = authMethodToken
	}
	switch c.authMethod {
	case authMethodToken:
		c.staticToken = os.Getenv(EnvOpenBaoToken)
		if c.staticToken == "" {
			return nil, fmt.Errorf("%w: %s is required when %s=%s (or unset)",
				errNotConfigured, EnvOpenBaoToken, EnvOpenBaoAuthMethod, authMethodToken)
		}
	case authMethodKubernetes:
		c.k8sRole = os.Getenv(EnvOpenBaoK8sRole)
		if c.k8sRole == "" {
			return nil, fmt.Errorf("%w: %s is required when %s=%s",
				errNotConfigured, EnvOpenBaoK8sRole, EnvOpenBaoAuthMethod, authMethodKubernetes)
		}
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
			errNotConfigured, EnvOpenBaoAuthMethod, c.authMethod, authMethodToken, authMethodKubernetes)
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
		transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	}
	c.httpClient = &http.Client{Transport: transport, Timeout: 30 * time.Second}
	return c, nil
}

// currentToken mirrors internal/gatewayjwt/obtransit.go's.
func (c *obTransitClient) currentToken(ctx context.Context) (string, error) {
	if c.authMethod == authMethodToken {
		return c.staticToken, nil
	}
	c.authMu.Lock()
	defer c.authMu.Unlock()
	if c.authToken != "" && time.Now().Before(c.authExpiry) {
		return c.authToken, nil
	}
	jwtBytes, err := os.ReadFile(c.k8sJWTPath)
	if err != nil {
		return "", fmt.Errorf("%w: reading %s: %w", errK8sAuthFailed, c.k8sJWTPath, err)
	}
	jwt := strings.TrimSpace(string(jwtBytes))
	if jwt == "" {
		return "", fmt.Errorf("%w: %s is empty", errK8sAuthFailed, c.k8sJWTPath)
	}
	var lr struct {
		Auth *struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
		Errors []string `json:"errors"`
	}
	status, err := c.do(ctx, http.MethodPost, "auth/"+c.k8sMount+"/login", "", map[string]string{"role": c.k8sRole, "jwt": jwt}, &lr)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errK8sAuthFailed, err)
	}
	if status != http.StatusOK || lr.Auth == nil || lr.Auth.ClientToken == "" {
		return "", fmt.Errorf("%w: status %d: %s", errK8sAuthFailed, status, strings.Join(lr.Errors, "; "))
	}
	c.authToken = lr.Auth.ClientToken
	lease := time.Duration(lr.Auth.LeaseDuration) * time.Second
	c.authExpiry = time.Now().Add(lease - lease/authTokenSafetyMargin)
	return c.authToken, nil
}

// do sends one JSON request to /v1/<path> and decodes the response body
// into out whatever the status, returning the status for the caller to
// judge (OpenBao puts its "errors" array in non-2xx bodies too).
func (c *obTransitClient) do(ctx context.Context, method, path, token string, body, out any) (int, error) {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, fmt.Errorf("encoding request: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.addr+"/v1/"+path, reqBody)
	if err != nil {
		return 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, fmt.Errorf("reading response: %w", err)
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil && resp.StatusCode == http.StatusOK {
			return resp.StatusCode, fmt.Errorf("decoding response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

// sign calls POST /v1/<mount>/sign/<key> over input (Ed25519 signs the
// message directly, no prehash) and returns the raw signature and the
// key version Transit used.
func (c *obTransitClient) sign(ctx context.Context, input []byte) ([]byte, int, error) {
	token, err := c.currentToken(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", errSignFailed, err)
	}
	var sr struct {
		Data struct {
			Signature  string `json:"signature"`
			KeyVersion int    `json:"key_version"`
		} `json:"data"`
		Errors []string `json:"errors"`
	}
	status, err := c.do(ctx, http.MethodPost, c.mount+"/sign/"+c.keyName, token,
		map[string]string{"input": base64.StdEncoding.EncodeToString(input)}, &sr)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", errSignFailed, err)
	}
	if status != http.StatusOK {
		return nil, 0, fmt.Errorf("%w: status %d: %s", errSignFailed, status, strings.Join(sr.Errors, "; "))
	}
	// "<prefix>:v<version>:<base64>"; take the last segment and trust the
	// separate key_version field, as internal/gatewayjwt does.
	parts := strings.Split(sr.Data.Signature, ":")
	if len(parts) < 3 || sr.Data.KeyVersion < 1 {
		return nil, 0, fmt.Errorf("%w: unexpected signature format %q", errSignFailed, sr.Data.Signature)
	}
	raw, err := base64.StdEncoding.DecodeString(parts[len(parts)-1])
	if err != nil {
		return nil, 0, fmt.Errorf("%w: decoding signature: %w", errSignFailed, err)
	}
	return raw, sr.Data.KeyVersion, nil
}

// keySet calls GET /v1/<mount>/keys/<key>, for verifying a signature
// right after Transit produced it and before it is returned
// (signAndVerify), and once at startup to fail fast on a key this
// identity can't read or that isn't Ed25519.
func (c *obTransitClient) keySet(ctx context.Context) (fleetsign.KeySet, error) {
	token, err := c.currentToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errReadKeyFailed, err)
	}
	var rr struct {
		Data struct {
			Type string `json:"type"`
			Keys map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
			// MinDecryptionVersion is the floor Transit's own /verify
			// honors; see the filter below.
			MinDecryptionVersion int `json:"min_decryption_version"`
		} `json:"data"`
		Errors []string `json:"errors"`
	}
	status, err := c.do(ctx, http.MethodGet, c.mount+"/keys/"+c.keyName, token, nil, &rr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errReadKeyFailed, err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d: %s", errReadKeyFailed, status, strings.Join(rr.Errors, "; "))
	}
	if rr.Data.Type != "ed25519" {
		return nil, fmt.Errorf("%w: Transit key %q is type %q, want ed25519", errReadKeyFailed, c.keyName, rr.Data.Type)
	}
	// Same floor as every verifier (fleetsign's readKeySet):
	// min_decryption_version, the floor Transit's own /verify honors, with
	// 0 meaning unrestricted. A signature Transit has just produced is
	// always by a version >= min_encryption_version >=
	// min_decryption_version, so the post-sign self-verify always finds
	// its key.
	minVersion := rr.Data.MinDecryptionVersion
	if minVersion < 1 {
		minVersion = 1
	}
	keys := make([]fleetsign.PublicKey, 0, len(rr.Data.Keys))
	for k, v := range rr.Data.Keys {
		version, err := strconv.Atoi(k)
		if err != nil {
			return nil, fmt.Errorf("%w: unexpected key version %q", errReadKeyFailed, k)
		}
		if version < minVersion {
			continue
		}
		pub, err := fleetsign.ParseEd25519PublicKeyPEM(v.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("%w: key version %d: %w", errReadKeyFailed, version, err)
		}
		keys = append(keys, fleetsign.PublicKey{Version: version, Key: pub})
	}
	return fleetsign.NewKeySet(keys)
}
