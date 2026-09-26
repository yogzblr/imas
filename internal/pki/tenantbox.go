// Tenant X25519 keypair custody for
// docs/design/imas-payload-encryption-design.md (workstream J): "one
// tenant keypair (farmer-side, OpenBao-custodied private key)".
//
// FLAG FOR SECURITY REVIEW per the task brief. This file used to be an
// interim, locally-generated placeholder (see git history) so the
// enrollment response could return a real tenant_x25519_pub before this
// workstream's custody piece was built; it now holds tenant_priv in
// OpenBao, following the same hand-rolled-HTTP-client pattern already
// established by internal/certs/tls.go (PKI secrets engine) and
// internal/gatewayjwt/obtransit.go (Transit secrets engine) — see either
// file's header comment for why: the official OpenBao/Vault Go client
// (github.com/openbao/openbao/api, github.com/hashicorp/vault/api) is
// MPL-2.0 licensed, which conflicts with this repo's Apache-2.0/MIT-only
// dependency constraint (CLAUDE.md).
//
// Unlike those two files, this one talks to OpenBao's **KV v2** secrets
// engine rather than PKI or Transit: OpenBao's Transit engine has sign
// (ed25519, used by gatewayjwt) and symmetric-encrypt operations, but no
// X25519/Curve25519 Diffie-Hellman primitive to compute a NaCl `box`
// shared secret without the private key ever leaving Transit. Getting
// genuine "private key never leaves OpenBao" custody for a NaCl-box
// operation would need Transit to grow that primitive first (it doesn't
// have one today) — tracked as a follow-up, not blocking this workstream.
// What this file gives instead: tenant_priv's *durable, at-rest* copy
// lives in OpenBao (versioned, access-logged, ACL'd), not as a plaintext
// file on farmer's own disk; it is read into farmer's process memory
// on demand to perform a box operation, the same transiting-through-the-
// process model internal/certs/tls.go already accepts for the TLS leaf
// private key OpenBao's PKI engine issues.
package pki

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// Environment variables configuring the OpenBao KV v2 client used to
// custody the tenant's X25519 keypair. Addr is always required; which of
// the rest matter depends on AuthMethod. Named IMAS_TENANTBOX_OPENBAO_*
// rather than reusing internal/certs's or internal/gatewayjwt's prefixes:
// this is a distinct OpenBao connection (KV, not PKI or Transit),
// plausibly pointed at a different address, mount, or auth role.
const (
	EnvTenantBoxOpenBaoAddr       = "IMAS_TENANTBOX_OPENBAO_ADDR"
	EnvTenantBoxOpenBaoKVMount    = "IMAS_TENANTBOX_OPENBAO_KV_MOUNT" // default "secret", must be KV v2
	EnvTenantBoxOpenBaoKVPath     = "IMAS_TENANTBOX_OPENBAO_KV_PATH"  // default "imas/tenant-x25519"
	EnvTenantBoxOpenBaoCACert     = "IMAS_TENANTBOX_OPENBAO_CACERT"   // optional, verify OpenBao's own TLS
	EnvTenantBoxOpenBaoAuthMethod = "IMAS_TENANTBOX_OPENBAO_AUTH_METHOD"

	// EnvTenantBoxOpenBaoToken is the bearer token used when AuthMethod is
	// "token" (the default).
	EnvTenantBoxOpenBaoToken = "IMAS_TENANTBOX_OPENBAO_TOKEN"

	// EnvTenantBoxOpenBaoK8s* configure OpenBao's kubernetes auth method,
	// used when AuthMethod is "kubernetes".
	EnvTenantBoxOpenBaoK8sRole    = "IMAS_TENANTBOX_OPENBAO_K8S_ROLE"
	EnvTenantBoxOpenBaoK8sMount   = "IMAS_TENANTBOX_OPENBAO_K8S_MOUNT"    // default "kubernetes"
	EnvTenantBoxOpenBaoK8sJWTPath = "IMAS_TENANTBOX_OPENBAO_K8S_JWT_PATH" // default defaultTenantBoxK8sJWTPath
)

// Recognized values for IMAS_TENANTBOX_OPENBAO_AUTH_METHOD.
const (
	TenantBoxAuthMethodToken      = "token"
	TenantBoxAuthMethodKubernetes = "kubernetes"
)

const defaultTenantBoxK8sJWTPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// tenantBoxAuthTokenSafetyMargin mirrors internal/certs/tls.go's
// authTokenSafetyMargin.
const tenantBoxAuthTokenSafetyMargin = 5 // 1/5 = 20%

var (
	ErrTenantBoxNotConfigured = errors.New("pki: tenant box OpenBao client not configured")
	ErrTenantBoxReadFailed    = errors.New("pki: tenant box OpenBao KV read failed")
	ErrTenantBoxWriteFailed   = errors.New("pki: tenant box OpenBao KV write failed")

	ErrTenantBoxK8sJWTUnavailable = errors.New("pki: tenant box OpenBao kubernetes auth: could not read service account token")
	ErrTenantBoxK8sAuthFailed     = errors.New("pki: tenant box OpenBao kubernetes auth login failed")
)

// obKVClient is a minimal client for the subset of OpenBao's HTTP API this
// file needs: KV v2's data endpoint (GET/PUT with check-and-set).
type obKVClient struct {
	addr       string
	mount      string
	path       string
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

// newTenantBoxClientFromEnv builds an obKVClient from the Env* variables
// above, called fresh on every operation (not cached at package init) so
// tests can point it at a local mock server by changing the environment,
// same rationale as internal/certs/tls.go's newClientFromEnv.
func newTenantBoxClientFromEnv() (*obKVClient, error) {
	addr := os.Getenv(EnvTenantBoxOpenBaoAddr)
	if addr == "" {
		return nil, fmt.Errorf("%w: %s is required", ErrTenantBoxNotConfigured, EnvTenantBoxOpenBaoAddr)
	}
	mount := os.Getenv(EnvTenantBoxOpenBaoKVMount)
	if mount == "" {
		mount = "secret"
	}
	path := os.Getenv(EnvTenantBoxOpenBaoKVPath)
	if path == "" {
		path = "imas/tenant-x25519"
	}
	authMethod := os.Getenv(EnvTenantBoxOpenBaoAuthMethod)
	if authMethod == "" {
		authMethod = TenantBoxAuthMethodToken
	}

	c := &obKVClient{
		addr:       strings.TrimRight(addr, "/"),
		mount:      mount,
		path:       strings.Trim(path, "/"),
		authMethod: authMethod,
	}

	switch authMethod {
	case TenantBoxAuthMethodToken:
		token := os.Getenv(EnvTenantBoxOpenBaoToken)
		if token == "" {
			return nil, fmt.Errorf("%w: %s is required when %s=%s (or unset)",
				ErrTenantBoxNotConfigured, EnvTenantBoxOpenBaoToken, EnvTenantBoxOpenBaoAuthMethod, TenantBoxAuthMethodToken)
		}
		c.staticToken = token
	case TenantBoxAuthMethodKubernetes:
		k8sRole := os.Getenv(EnvTenantBoxOpenBaoK8sRole)
		if k8sRole == "" {
			return nil, fmt.Errorf("%w: %s is required when %s=%s",
				ErrTenantBoxNotConfigured, EnvTenantBoxOpenBaoK8sRole, EnvTenantBoxOpenBaoAuthMethod, TenantBoxAuthMethodKubernetes)
		}
		c.k8sRole = k8sRole
		c.k8sMount = os.Getenv(EnvTenantBoxOpenBaoK8sMount)
		if c.k8sMount == "" {
			c.k8sMount = "kubernetes"
		}
		c.k8sJWTPath = os.Getenv(EnvTenantBoxOpenBaoK8sJWTPath)
		if c.k8sJWTPath == "" {
			c.k8sJWTPath = defaultTenantBoxK8sJWTPath
		}
	default:
		return nil, fmt.Errorf("%w: unknown %s %q (want %q or %q)",
			ErrTenantBoxNotConfigured, EnvTenantBoxOpenBaoAuthMethod, authMethod, TenantBoxAuthMethodToken, TenantBoxAuthMethodKubernetes)
	}

	var transport http.RoundTripper = http.DefaultTransport
	if caFile := os.Getenv(EnvTenantBoxOpenBaoCACert); caFile != "" {
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
func (c *obKVClient) currentToken(ctx context.Context) (string, error) {
	if c.authMethod == TenantBoxAuthMethodToken {
		return c.staticToken, nil
	}
	c.authMu.Lock()
	defer c.authMu.Unlock()
	if c.authToken != "" && time.Now().Before(c.authExpiry) {
		return c.authToken, nil
	}
	return c.k8sLoginLocked(ctx)
}

type tenantBoxK8sLoginAuth struct {
	ClientToken   string `json:"client_token"`
	LeaseDuration int    `json:"lease_duration"`
}

type tenantBoxK8sLoginResponse struct {
	Auth   *tenantBoxK8sLoginAuth `json:"auth"`
	Errors []string               `json:"errors"`
}

// k8sLoginLocked mirrors internal/certs/tls.go's (*obClient).k8sLoginLocked.
// Callers must hold c.authMu.
func (c *obKVClient) k8sLoginLocked(ctx context.Context) (string, error) {
	jwtBytes, err := os.ReadFile(c.k8sJWTPath)
	if err != nil {
		return "", fmt.Errorf("%w: reading %s: %w", ErrTenantBoxK8sJWTUnavailable, c.k8sJWTPath, err)
	}
	jwt := strings.TrimSpace(string(jwtBytes))
	if jwt == "" {
		return "", fmt.Errorf("%w: %s is empty", ErrTenantBoxK8sJWTUnavailable, c.k8sJWTPath)
	}

	reqBody, err := json.Marshal(map[string]string{"role": c.k8sRole, "jwt": jwt})
	if err != nil {
		return "", fmt.Errorf("%w: encoding request: %w", ErrTenantBoxK8sAuthFailed, err)
	}
	reqURL := fmt.Sprintf("%s/v1/auth/%s/login", c.addr, c.k8sMount)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrTenantBoxK8sAuthFailed, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrTenantBoxK8sAuthFailed, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("%w: reading response: %w", ErrTenantBoxK8sAuthFailed, err)
	}
	var lr tenantBoxK8sLoginResponse
	if resp.StatusCode != http.StatusOK {
		_ = json.Unmarshal(data, &lr)
		return "", fmt.Errorf("%w: status %d: %s", ErrTenantBoxK8sAuthFailed, resp.StatusCode, strings.Join(lr.Errors, "; "))
	}
	if err := json.Unmarshal(data, &lr); err != nil {
		return "", fmt.Errorf("%w: decoding response: %w", ErrTenantBoxK8sAuthFailed, err)
	}
	if lr.Auth == nil || lr.Auth.ClientToken == "" {
		return "", fmt.Errorf("%w: response had no auth.client_token: %s", ErrTenantBoxK8sAuthFailed, strings.Join(lr.Errors, "; "))
	}

	c.authToken = lr.Auth.ClientToken
	margin := time.Duration(lr.Auth.LeaseDuration) * time.Second / tenantBoxAuthTokenSafetyMargin
	c.authExpiry = time.Now().Add(time.Duration(lr.Auth.LeaseDuration)*time.Second - margin)
	return c.authToken, nil
}

type kvV2GetResponse struct {
	Data struct {
		Data map[string]string `json:"data"`
	} `json:"data"`
	Errors []string `json:"errors"`
}

// readKeypair reads the tenant keypair from OpenBao's KV v2 data endpoint.
// found is false (with a nil error) when the secret has never been
// written — the expected state on a brand new farmer, not an error.
func (c *obKVClient) readKeypair(ctx context.Context) (pub, priv *[32]byte, found bool, err error) {
	token, err := c.currentToken(ctx)
	if err != nil {
		return nil, nil, false, fmt.Errorf("%w: %w", ErrTenantBoxReadFailed, err)
	}
	reqURL := fmt.Sprintf("%s/v1/%s/data/%s", c.addr, c.mount, c.path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, nil, false, fmt.Errorf("%w: %w", ErrTenantBoxReadFailed, err)
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, false, fmt.Errorf("%w: %w", ErrTenantBoxReadFailed, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, false, fmt.Errorf("%w: reading response: %w", ErrTenantBoxReadFailed, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, false, fmt.Errorf("%w: status %d: %s", ErrTenantBoxReadFailed, resp.StatusCode, string(data))
	}
	var gr kvV2GetResponse
	if err := json.Unmarshal(data, &gr); err != nil {
		return nil, nil, false, fmt.Errorf("%w: decoding response: %w", ErrTenantBoxReadFailed, err)
	}
	if gr.Data.Data == nil {
		// A soft-deleted or destroyed KV v2 version: metadata exists but
		// the version has no data. Treat the same as "never written".
		return nil, nil, false, nil
	}
	pubB64, pubOK := gr.Data.Data["pub"]
	privB64, privOK := gr.Data.Data["priv"]
	if !pubOK || !privOK {
		return nil, nil, false, fmt.Errorf("%w: stored secret is missing pub/priv fields", ErrTenantBoxReadFailed)
	}
	pubBytes, err := decodeBoxKeyHalf(pubB64)
	if err != nil {
		return nil, nil, false, fmt.Errorf("%w: pub: %w", ErrTenantBoxReadFailed, err)
	}
	privBytes, err := decodeBoxKeyHalf(privB64)
	if err != nil {
		return nil, nil, false, fmt.Errorf("%w: priv: %w", ErrTenantBoxReadFailed, err)
	}
	return pubBytes, privBytes, true, nil
}

type kvV2PutResponse struct {
	Errors []string `json:"errors"`
}

// writeKeypairIfAbsent writes pub/priv to OpenBao's KV v2 data endpoint
// with check-and-set version 0 — "create only if this path has never had
// a version written" — so two farmer processes racing to bootstrap the
// tenant keypair for the first time can't stomp on each other; the loser
// gets created=false (not an error) and should re-read instead.
func (c *obKVClient) writeKeypairIfAbsent(ctx context.Context, pub, priv *[32]byte) (created bool, err error) {
	token, err := c.currentToken(ctx)
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrTenantBoxWriteFailed, err)
	}
	body, err := json.Marshal(map[string]any{
		"options": map[string]any{"cas": 0},
		"data": map[string]string{
			"pub":  base64.StdEncoding.EncodeToString(pub[:]),
			"priv": base64.StdEncoding.EncodeToString(priv[:]),
		},
	})
	if err != nil {
		return false, fmt.Errorf("%w: encoding request: %w", ErrTenantBoxWriteFailed, err)
	}
	reqURL := fmt.Sprintf("%s/v1/%s/data/%s", c.addr, c.mount, c.path)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, reqURL, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrTenantBoxWriteFailed, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrTenantBoxWriteFailed, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("%w: reading response: %w", ErrTenantBoxWriteFailed, err)
	}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		return true, nil
	case http.StatusBadRequest, http.StatusConflict:
		// The check-and-set guard rejected this write, almost always
		// because a concurrent bootstrap already created version 1.
		// Not an error: the caller re-reads and uses whichever keypair
		// won.
		return false, nil
	default:
		var pr kvV2PutResponse
		_ = json.Unmarshal(data, &pr)
		return false, fmt.Errorf("%w: status %d: %s", ErrTenantBoxWriteFailed, resp.StatusCode, strings.Join(pr.Errors, "; "))
	}
}

func decodeBoxKeyHalf(b64 string) (*[32]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("invalid encoding: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("expected 32 bytes, got %d", len(raw))
	}
	var out [32]byte
	copy(out[:], raw)
	return &out, nil
}

var (
	tenantBoxMu   sync.Mutex
	tenantBoxPub  *[32]byte
	tenantBoxPriv *[32]byte
)

// resetTenantX25519KeypairCache clears the in-process cache so the next
// call re-fetches from OpenBao. Test-only.
func resetTenantX25519KeypairCache() {
	tenantBoxMu.Lock()
	defer tenantBoxMu.Unlock()
	tenantBoxPub, tenantBoxPriv = nil, nil
}

// ensureTenantX25519Keypair returns the tenant's NaCl box keypair,
// bootstrapping it in OpenBao (generating and persisting it, guarded by a
// check-and-set create) on first use. Safe to call repeatedly and
// concurrently; cached in-process after the first successful call so
// every subsequent box operation this farmer performs doesn't round-trip
// to OpenBao.
func ensureTenantX25519Keypair() (pub, priv *[32]byte, err error) {
	tenantBoxMu.Lock()
	defer tenantBoxMu.Unlock()

	if tenantBoxPub != nil {
		return tenantBoxPub, tenantBoxPriv, nil
	}

	client, err := newTenantBoxClientFromEnv()
	if err != nil {
		return nil, nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	existingPub, existingPriv, found, err := client.readKeypair(ctx)
	if err != nil {
		return nil, nil, err
	}
	if found {
		tenantBoxPub, tenantBoxPriv = existingPub, existingPriv
		return tenantBoxPub, tenantBoxPriv, nil
	}

	newPub, newPriv, genErr := box.GenerateKey(rand.Reader)
	if genErr != nil {
		return nil, nil, genErr
	}
	created, err := client.writeKeypairIfAbsent(ctx, newPub, newPriv)
	if err != nil {
		return nil, nil, err
	}
	if created {
		tenantBoxPub, tenantBoxPriv = newPub, newPriv
		return tenantBoxPub, tenantBoxPriv, nil
	}

	// Lost the create race to another process: re-read whichever keypair
	// won rather than using the one just generated locally and discarded.
	existingPub, existingPriv, found, err = client.readKeypair(ctx)
	if err != nil {
		return nil, nil, err
	}
	if !found {
		return nil, nil, fmt.Errorf("pki: tenant X25519 keypair vanished immediately after a lost create race")
	}
	tenantBoxPub, tenantBoxPriv = existingPub, existingPriv
	return tenantBoxPub, tenantBoxPriv, nil
}

// GetTenantX25519PublicKey returns the tenant's NaCl box public key,
// standard-base64-encoded, for inclusion in the enrollment response
// (cloudxp-machine-manager-api-design.md §3.2).
func GetTenantX25519PublicKey() (string, error) {
	pub, _, err := ensureTenantX25519Keypair()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub[:]), nil
}

// GetTenantX25519KeyPair returns the tenant's raw NaCl box keypair for use
// by internal/natsapi's shared encrypt/decrypt helper: priv to seal
// payloads addressed to a sprout and to open payloads received from one
// (see docs/design/imas-payload-encryption-design.md's "one tenant key
// still gives per-sprout-specific encryption").
func GetTenantX25519KeyPair() (pub, priv *[32]byte, err error) {
	return ensureTenantX25519Keypair()
}
