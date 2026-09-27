// Tenant X25519 keypair custody for
// docs/design/imas-payload-encryption-design.md (workstream J): "one
// tenant keypair (farmer-side, OpenBao-custodied private key)" per
// tenant, rotated on a schedule as the accepted mitigation for static
// NaCl box keys having no forward secrecy.
//
// FLAG FOR SECURITY REVIEW per the task brief. tenant_priv is held in
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
//
// Layout. Each tenant's keypair is one KV v2 secret,
// <mount>/data/<base>/tenants/<tenant_id> (fields pub, priv, origin and,
// on a severing rotation, severed), where <base> is
// IMAS_TENANTBOX_OPENBAO_KV_PATH. A rotation writes a new KV v2 version
// of the same secret (check-and-set on the current version), so the
// secret's version history *is* the tenant's key history: the current
// version seals new traffic; the version before it keeps sealing and
// opening for a grace window (tenantBoxGrace) while sprouts re-pin; and
// every retained earlier version back to the last severing rotation
// signs a continuity proof (TenantKeyContinuity) that lets a sprout
// pinned to it move to the current key. tenant_id is validated
// (IsValidTenantID: [0-9A-Za-z_-]) before it is ever used in a path.
//
// Migration from one keypair per deployment. Before this layout, every
// tenant shared one keypair at <base> itself, and every sprout enrolled
// then pinned its public key; a sprout exits on a pin mismatch
// (ErrTenantKeyMismatch), and sprouts built before continuity proofs
// can't re-pin at all. So the first time a tenant's own secret is
// needed and doesn't exist yet (ensureTenantKeySet), the legacy keypair
// is *adopted* — copied into the tenant's secret as its version 1,
// origin "adopted-legacy" — if the legacy secret exists and the tenant
// already has at least one sprout box key on record (only a sprout that
// enrolled against the shared key can have one before the tenant's own
// secret exists: Enroll reads the tenant key before recording the
// sprout's). Every other tenant gets a freshly generated keypair. An
// adopted tenant is still sharing a private key with other tenants until
// its first rotation (RotateTenantX25519Keypair), which an operator runs
// once the tenant's sprouts run a build that verifies continuity proofs;
// see docs/design/imas-payload-encryption-design.md, "As built".
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
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/config"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/payloadbox"
)

// Environment variables configuring the OpenBao KV v2 client used to
// custody tenant X25519 keypairs. Addr is always required; which of the
// rest matter depends on AuthMethod. Named IMAS_TENANTBOX_OPENBAO_*
// rather than reusing internal/certs's or internal/gatewayjwt's prefixes:
// this is a distinct OpenBao connection (KV, not PKI or Transit),
// plausibly pointed at a different address, mount, or auth role.
const (
	EnvTenantBoxOpenBaoAddr    = "IMAS_TENANTBOX_OPENBAO_ADDR"
	EnvTenantBoxOpenBaoKVMount = "IMAS_TENANTBOX_OPENBAO_KV_MOUNT" // default "secret", must be KV v2
	// EnvTenantBoxOpenBaoKVPath is the base path: tenants' secrets live
	// under <base>/tenants/, and <base> itself is the legacy
	// one-per-deployment keypair, read (never written) for migration.
	EnvTenantBoxOpenBaoKVPath     = "IMAS_TENANTBOX_OPENBAO_KV_PATH" // default "imas/tenant-x25519"
	EnvTenantBoxOpenBaoCACert     = "IMAS_TENANTBOX_OPENBAO_CACERT"  // optional, verify OpenBao's own TLS
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

// tenantBoxTenantsDir is the path segment under the base path that holds
// one secret per tenant.
const tenantBoxTenantsDir = "tenants"

// Values of a tenant secret's "origin" field: how that version's keypair
// came to be. Informational (an operator reading OpenBao can see which
// tenants still share the legacy keypair); nothing branches on it.
const (
	tenantBoxOriginGenerated     = "generated"
	tenantBoxOriginAdoptedLegacy = "adopted-legacy"
	tenantBoxOriginRotated       = "rotated"
)

// maxTenantBoxPredecessors bounds how many earlier versions of a tenant's
// secret are read (and sign continuity proofs): OpenBao's KV v2 keeps 10
// versions by default, and a sprout pinned further back than this has
// been offline through that many rotations.
const maxTenantBoxPredecessors = 8

var (
	ErrTenantBoxNotConfigured = errors.New("pki: tenant box OpenBao client not configured")
	ErrTenantBoxReadFailed    = errors.New("pki: tenant box OpenBao KV read failed")
	ErrTenantBoxWriteFailed   = errors.New("pki: tenant box OpenBao KV write failed")

	ErrTenantBoxK8sJWTUnavailable = errors.New("pki: tenant box OpenBao kubernetes auth: could not read service account token")
	ErrTenantBoxK8sAuthFailed     = errors.New("pki: tenant box OpenBao kubernetes auth login failed")

	// ErrTenantBoxRotationConflict means another rotation (or first
	// creation) of the same tenant's keypair landed between reading the
	// current version and writing the next one. Nothing was written;
	// re-read and decide again.
	ErrTenantBoxRotationConflict = errors.New("pki: tenant box keypair changed concurrently; rotation not written")
)

// obKVClient is a minimal client for the subset of OpenBao's HTTP API this
// file needs: KV v2's data endpoint (GET, optionally of one version, and
// PUT with check-and-set).
type obKVClient struct {
	addr       string
	mount      string
	path       string // base path; see EnvTenantBoxOpenBaoKVPath
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

func (c *obKVClient) legacyPath() string { return c.path }

func (c *obKVClient) tenantPath(tenantID string) string {
	return c.path + "/" + tenantBoxTenantsDir + "/" + tenantID
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

// tenantBoxKey is one version of a tenant's keypair as read from OpenBao.
type tenantBoxKey struct {
	pub, priv *[32]byte
	version   int
	created   time.Time
	// severed marks a version written by a severing rotation: no
	// continuity proof, and no grace, reaches back past it.
	severed bool
	origin  string
}

type kvV2GetResponse struct {
	Data struct {
		Data     map[string]string `json:"data"`
		Metadata struct {
			Version     int    `json:"version"`
			CreatedTime string `json:"created_time"`
		} `json:"metadata"`
	} `json:"data"`
	Errors []string `json:"errors"`
}

// readKeypair reads one version of the keypair at path from OpenBao's KV
// v2 data endpoint; version 0 means the current one. found is false (with
// a nil error) when that version doesn't exist or has been deleted or
// destroyed — the expected state for a tenant whose keypair has never
// been written, not an error.
func (c *obKVClient) readKeypair(ctx context.Context, path string, version int) (key *tenantBoxKey, found bool, err error) {
	token, err := c.currentToken(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %w", ErrTenantBoxReadFailed, err)
	}
	reqURL := fmt.Sprintf("%s/v1/%s/data/%s", c.addr, c.mount, path)
	if version > 0 {
		reqURL += "?" + url.Values{"version": {strconv.Itoa(version)}}.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %w", ErrTenantBoxReadFailed, err)
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %w", ErrTenantBoxReadFailed, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, fmt.Errorf("%w: reading response: %w", ErrTenantBoxReadFailed, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("%w: status %d: %s", ErrTenantBoxReadFailed, resp.StatusCode, string(data))
	}
	var gr kvV2GetResponse
	if err := json.Unmarshal(data, &gr); err != nil {
		return nil, false, fmt.Errorf("%w: decoding response: %w", ErrTenantBoxReadFailed, err)
	}
	if gr.Data.Data == nil {
		// A soft-deleted or destroyed KV v2 version: metadata exists but
		// the version has no data. Treat the same as "never written".
		return nil, false, nil
	}
	pubB64, pubOK := gr.Data.Data["pub"]
	privB64, privOK := gr.Data.Data["priv"]
	if !pubOK || !privOK {
		return nil, false, fmt.Errorf("%w: stored secret is missing pub/priv fields", ErrTenantBoxReadFailed)
	}
	pub, err := decodeBoxKeyHalf(pubB64)
	if err != nil {
		return nil, false, fmt.Errorf("%w: pub: %w", ErrTenantBoxReadFailed, err)
	}
	priv, err := decodeBoxKeyHalf(privB64)
	if err != nil {
		return nil, false, fmt.Errorf("%w: priv: %w", ErrTenantBoxReadFailed, err)
	}
	// A pub that isn't priv's public half would have farmer hand sprouts
	// a key it can't open anything under.
	if derived, err := curve25519.X25519(priv[:], curve25519.Basepoint); err != nil || !bytes.Equal(derived, pub[:]) {
		return nil, false, fmt.Errorf("%w: stored pub does not match stored priv", ErrTenantBoxReadFailed)
	}
	key = &tenantBoxKey{
		pub: pub, priv: priv,
		version: gr.Data.Metadata.Version,
		severed: gr.Data.Data["severed"] == "true",
		origin:  gr.Data.Data["origin"],
	}
	if version > 0 && key.version == 0 {
		key.version = version
	}
	if t, err := time.Parse(time.RFC3339Nano, gr.Data.Metadata.CreatedTime); err == nil {
		key.created = t
	}
	return key, true, nil
}

type kvV2PutResponse struct {
	Errors []string `json:"errors"`
}

// writeKeypair writes pub/priv as a new version of path, with KV v2
// check-and-set on cas: 0 means "only if this path has never had a
// version written", N means "only if the current version is N". So two
// farmer processes racing to create, or to rotate, the same tenant's
// keypair can't stomp on each other; the loser gets written=false (not an
// error) and should re-read instead.
func (c *obKVClient) writeKeypair(ctx context.Context, path string, pub, priv *[32]byte, cas int, fields map[string]string) (written bool, err error) {
	token, err := c.currentToken(ctx)
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrTenantBoxWriteFailed, err)
	}
	data := map[string]string{
		"pub":  base64.StdEncoding.EncodeToString(pub[:]),
		"priv": base64.StdEncoding.EncodeToString(priv[:]),
	}
	for k, v := range fields {
		data[k] = v
	}
	body, err := json.Marshal(map[string]any{
		"options": map[string]any{"cas": cas},
		"data":    data,
	})
	if err != nil {
		return false, fmt.Errorf("%w: encoding request: %w", ErrTenantBoxWriteFailed, err)
	}
	reqURL := fmt.Sprintf("%s/v1/%s/data/%s", c.addr, c.mount, path)
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
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("%w: reading response: %w", ErrTenantBoxWriteFailed, err)
	}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		return true, nil
	case http.StatusBadRequest, http.StatusConflict:
		// The check-and-set guard rejected this write, almost always
		// because a concurrent create or rotation got there first. Not an
		// error: the caller re-reads and uses whichever keypair won.
		return false, nil
	default:
		var pr kvV2PutResponse
		_ = json.Unmarshal(respBody, &pr)
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

// tenantBoxKeySet is everything farmer needs from one tenant's secret.
type tenantBoxKeySet struct {
	current tenantBoxKey
	// previous holds the retained earlier versions the current one
	// continues from, newest first. It skips deleted or destroyed
	// versions, stops at (after including) the last severing rotation's
	// version, and holds at most maxTenantBoxPredecessors.
	previous []tenantBoxKey
	loaded   time.Time
}

// tenantHasSproutBoxKeys reports whether any sprout of tenantID has a box
// public key on record — the adoption test ensureTenantKeySet applies.
// A variable so tests can stub the store.
var tenantHasSproutBoxKeys = func(tenantID string) (bool, error) {
	if db == nil {
		return false, errors.New("pki: store not initialised")
	}
	var n int64
	if err := db.Model(&sproutBoxKeyRow{}).Where("tenant_id = ?", tenantID).Limit(1).Count(&n).Error; err != nil {
		return false, err
	}
	return n > 0, nil
}

// ensureTenantKeySet reads tenantID's key set from OpenBao, creating the
// tenant's secret first if it has never been written (see this file's
// header for the adopt-or-generate rule).
func (c *obKVClient) ensureTenantKeySet(ctx context.Context, tenantID string) (*tenantBoxKeySet, error) {
	path := c.tenantPath(tenantID)
	current, found, err := c.readKeypair(ctx, path, 0)
	if err != nil {
		return nil, err
	}
	if !found {
		pub, priv, origin, err := c.initialKeypair(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		if _, err := c.writeKeypair(ctx, path, pub, priv, 0, map[string]string{"origin": origin}); err != nil {
			return nil, err
		}
		// Written or lost the create race, re-read whichever won rather
		// than trusting the local copy.
		current, found, err = c.readKeypair(ctx, path, 0)
		if err != nil {
			return nil, err
		}
		if !found {
			// Either it vanished right after being created, or its current
			// version was deleted in OpenBao (so the create was refused):
			// fail closed rather than guess which key sprouts have pinned.
			return nil, fmt.Errorf("pki: tenant %s X25519 keypair not readable after creating it (is its current version deleted in OpenBao?)", tenantID)
		}
		if current.origin == tenantBoxOriginAdoptedLegacy {
			log.Noticef("tenantbox: tenant %s adopted the legacy shared X25519 keypair (it has sprouts pinned to it); rotate it once its sprouts verify continuity proofs", tenantID)
		}
	}
	set := &tenantBoxKeySet{current: *current, loaded: time.Now()}
	if current.severed {
		return set, nil
	}
	for v := current.version - 1; v >= 1 && v >= current.version-maxTenantBoxPredecessors; v-- {
		prev, found, err := c.readKeypair(ctx, path, v)
		if err != nil {
			return nil, err
		}
		if !found {
			// Deleted or destroyed (or pruned past max_versions): an
			// operator's way of retiring one version. Keep walking.
			continue
		}
		if *prev.pub != *current.pub {
			set.previous = append(set.previous, *prev)
		}
		if prev.severed {
			break
		}
	}
	return set, nil
}

// initialKeypair picks the first keypair for tenantID: the legacy shared
// one if the tenant has sprouts that can only have pinned it, else fresh.
func (c *obKVClient) initialKeypair(ctx context.Context, tenantID string) (pub, priv *[32]byte, origin string, err error) {
	legacy, found, err := c.readKeypair(ctx, c.legacyPath(), 0)
	if err != nil {
		return nil, nil, "", err
	}
	if found {
		pinned, err := tenantHasSproutBoxKeys(tenantID)
		if err != nil {
			// Guessing "no" here would strand every sprout pinned to the
			// legacy key; fail closed and let the caller retry.
			return nil, nil, "", fmt.Errorf("pki: checking whether tenant %s has enrolled sprouts: %w", tenantID, err)
		}
		if pinned {
			return legacy.pub, legacy.priv, tenantBoxOriginAdoptedLegacy, nil
		}
	}
	pub, priv, err = box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}
	return pub, priv, tenantBoxOriginGenerated, nil
}

// tenantBoxCacheTTL bounds how long a replica keeps using a tenant key
// set before re-reading it, and so how long after a rotation on another
// replica this one notices. tenantBoxStaleLimit is how long a cached set
// is still served while OpenBao can't be reached. Variables for tests.
var (
	tenantBoxCacheTTL   = time.Minute
	tenantBoxStaleLimit = 15 * time.Minute
)

type tenantBoxEntry struct {
	mu  sync.Mutex
	set *tenantBoxKeySet
}

var (
	tenantBoxCacheMu sync.Mutex
	tenantBoxCache   = map[string]*tenantBoxEntry{}
)

// resetTenantX25519KeypairCache clears the in-process cache so the next
// call re-fetches from OpenBao. Test-only.
func resetTenantX25519KeypairCache() {
	tenantBoxCacheMu.Lock()
	defer tenantBoxCacheMu.Unlock()
	tenantBoxCache = map[string]*tenantBoxEntry{}
}

// InvalidateTenantBoxKeys drops tenantID's cached key set, so the next
// use re-reads OpenBao: after a rotation on this replica, and when a
// sprout's payload doesn't open under the cached keys (it may have
// re-pinned to a key another replica rotated to).
func InvalidateTenantBoxKeys(tenantID string) {
	tenantBoxCacheMu.Lock()
	defer tenantBoxCacheMu.Unlock()
	delete(tenantBoxCache, tenantID)
}

func tenantBoxEntryFor(tenantID string) *tenantBoxEntry {
	tenantBoxCacheMu.Lock()
	defer tenantBoxCacheMu.Unlock()
	e, ok := tenantBoxCache[tenantID]
	if !ok {
		e = &tenantBoxEntry{}
		tenantBoxCache[tenantID] = e
	}
	return e
}

// loadTenantKeySet returns tenantID's key set, from the cache while it's
// younger than tenantBoxCacheTTL. Safe to call concurrently; one load
// per tenant at a time.
func loadTenantKeySet(tenantID string) (*tenantBoxKeySet, error) {
	if !IsValidTenantID(tenantID) {
		return nil, fmt.Errorf("pki: invalid tenant id %q", tenantID)
	}
	e := tenantBoxEntryFor(tenantID)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.set != nil && time.Since(e.set.loaded) < tenantBoxCacheTTL {
		return e.set, nil
	}
	client, err := newTenantBoxClientFromEnv()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	set, err := client.ensureTenantKeySet(ctx, tenantID)
	if err != nil {
		if e.set != nil && time.Since(e.set.loaded) < tenantBoxStaleLimit {
			log.Warnf("tenantbox: re-reading tenant %s X25519 keys failed, still using the copy read %s ago: %v",
				tenantID, time.Since(e.set.loaded).Round(time.Second), err)
			return e.set, nil
		}
		return nil, err
	}
	e.set = set
	return set, nil
}

// tenantBoxGrace is how long after a rotation the previous tenant keypair
// keeps sealing and opening sprout traffic. At least one gateway JWT
// lifetime, so every sprout that is online refreshes (and re-pins,
// RefreshGatewayJWT) inside it; and at least config.BoxKeyGraceDuration,
// the same overlap a sprout's own box key rotation gets.
func tenantBoxGrace() time.Duration {
	return max(config.BoxKeyGraceDuration, config.GatewayJWTTTL)
}

// TenantBoxKey is one of a tenant's X25519 keypairs.
type TenantBoxKey struct {
	Pub, Priv *[32]byte
	Version   int
}

// TenantBoxKeys returns the tenant keypairs farmer seals sprout payloads
// under and opens them with: the current one first and, while the grace
// window after a non-severing rotation is open, the previous one.
func TenantBoxKeys(tenantID string) ([]TenantBoxKey, error) {
	set, err := loadTenantKeySet(tenantID)
	if err != nil {
		return nil, err
	}
	keys := []TenantBoxKey{{Pub: set.current.pub, Priv: set.current.priv, Version: set.current.version}}
	if len(set.previous) > 0 && !set.current.created.IsZero() && time.Since(set.current.created) < tenantBoxGrace() {
		p := set.previous[0]
		keys = append(keys, TenantBoxKey{Pub: p.pub, Priv: p.priv, Version: p.version})
	}
	return keys, nil
}

// GetTenantX25519PublicKey returns tenantID's current NaCl box public
// key, standard-base64-encoded, for the enrollment and refresh responses
// (cloudxp-machine-manager-api-design.md §3.2).
func GetTenantX25519PublicKey(tenantID string) (string, error) {
	set, err := loadTenantKeySet(tenantID)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(set.current.pub[:]), nil
}

// tenantKeyContinuityBody is a continuity proof's authenticated body.
type tenantKeyContinuityBody struct {
	// To is the tenant public key (standard base64) the sprout should pin
	// in place of whichever key the proof opened under.
	To string `json:"to"`
}

// TenantKeyContinuity returns a payloadbox envelope proving, to the
// sprout sproutID whose box public key is sproutPub, that tenantID's
// current public key succeeds each retained earlier one: one copy per
// earlier version, each sealed under that version's private key, all
// carrying the current public key. A sprout pinned to any of those
// versions opens its copy with its pinned key, which only that version's
// private key (or the sprout itself) could have sealed, and re-pins
// (RefreshGatewayJWT). nil when there is nothing to continue from.
//
// Continuity reaches back through every retained version up to the last
// severing rotation, not just the grace window: a sprout that was off
// for a month re-pins on its first refresh. To cut a compromised version
// off, rotate with sever (or delete that version in OpenBao); its
// sprouts then fail their pin check and must be re-enrolled.
func TenantKeyContinuity(tenantID, sproutID, sproutPub string) (json.RawMessage, error) {
	set, err := loadTenantKeySet(tenantID)
	if err != nil {
		return nil, err
	}
	if len(set.previous) == 0 {
		return nil, nil
	}
	sp, err := DecodeBoxPubKey(sproutPub)
	if err != nil {
		return nil, err
	}
	msg, err := payloadbox.NewMessage(payloadbox.PurposeTenantKeyContinuity, sproutID, "",
		tenantKeyContinuityBody{To: base64.StdEncoding.EncodeToString(set.current.pub[:])})
	if err != nil {
		return nil, err
	}
	pairs := make([]payloadbox.KeyPair, 0, len(set.previous))
	for _, p := range set.previous {
		pairs = append(pairs, payloadbox.KeyPair{PeerPub: sp, Priv: p.priv})
	}
	return payloadbox.Seal(msg, pairs)
}

// TenantKeyRotation describes a completed RotateTenantX25519Keypair.
type TenantKeyRotation struct {
	TenantID        string `json:"tenant_id"`
	PreviousVersion int    `json:"previous_version"`
	Version         int    `json:"version"`
	// Pub is the new public key, standard base64.
	Pub     string `json:"pub"`
	Severed bool   `json:"severed"`
}

// RotateTenantX25519Keypair generates a new keypair for tenantID and
// writes it as the next version of the tenant's secret, check-and-set on
// the version it read (ErrTenantBoxRotationConflict if another write got
// there first). The design doc's accepted mitigation for static keys
// having no forward secrecy: rotate on a schedule, bounding what a
// leaked tenant_priv can decrypt to traffic since the last rotation.
//
// Without sever, the previous keypair keeps working for tenantBoxGrace
// and every retained earlier one still signs continuity proofs, so
// sprouts move to the new key on their next refresh with no gap. With
// sever (suspected exposure), neither: the old keys stop being used at
// once, and sprouts pinned to them fail their next refresh's pin check
// and must be re-enrolled. Either way, sprouts built before continuity
// proofs exit on their next refresh (ErrTenantKeyMismatch); upgrade
// them first.
func RotateTenantX25519Keypair(tenantID string, sever bool) (*TenantKeyRotation, error) {
	if !IsValidTenantID(tenantID) {
		return nil, fmt.Errorf("pki: invalid tenant id %q", tenantID)
	}
	e := tenantBoxEntryFor(tenantID)
	e.mu.Lock()
	defer e.mu.Unlock()
	client, err := newTenantBoxClientFromEnv()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	set, err := client.ensureTenantKeySet(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	fields := map[string]string{"origin": tenantBoxOriginRotated}
	if sever {
		fields["severed"] = "true"
	}
	written, err := client.writeKeypair(ctx, client.tenantPath(tenantID), pub, priv, set.current.version, fields)
	if err != nil {
		return nil, err
	}
	// Drop the cache either way: on a conflict, what's cached is stale.
	e.set = nil
	if !written {
		return nil, ErrTenantBoxRotationConflict
	}
	log.Noticef("tenantbox: rotated tenant %s X25519 keypair from version %d (severed=%t)", tenantID, set.current.version, sever)
	return &TenantKeyRotation{
		TenantID:        tenantID,
		PreviousVersion: set.current.version,
		Version:         set.current.version + 1,
		Pub:             base64.StdEncoding.EncodeToString(pub[:]),
		Severed:         sever,
	}, nil
}
