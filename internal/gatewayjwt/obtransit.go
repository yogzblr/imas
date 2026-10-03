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

// This file is the Transit client behind GatewaySigner: sign and key
// reads for the gateway key. The client is internal/openbao (the
// official OpenBao Go client), which owns auth, TLS and error decoding
// for every server-side OpenBao identity.
import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/yogzblr/imas/internal/openbao"
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
	EnvOpenBaoK8sJWTPath = "IMAS_GATEWAY_OPENBAO_K8S_JWT_PATH" // default openbao.DefaultK8sJWTPath

	// EnvOpenBaoNamespace optionally sets the X-Vault-Namespace header.
	EnvOpenBaoNamespace = "IMAS_GATEWAY_OPENBAO_NAMESPACE"
)

// Recognized values for IMAS_GATEWAY_OPENBAO_AUTH_METHOD.
const (
	AuthMethodToken      = openbao.AuthMethodToken
	AuthMethodKubernetes = openbao.AuthMethodKubernetes
)

var openBaoEnv = openbao.Env{
	Addr:       EnvOpenBaoAddr,
	CACert:     EnvOpenBaoCACert,
	AuthMethod: EnvOpenBaoAuthMethod,
	Token:      EnvOpenBaoToken,
	K8sRole:    EnvOpenBaoK8sRole,
	K8sMount:   EnvOpenBaoK8sMount,
	K8sJWTPath: EnvOpenBaoK8sJWTPath,
	Namespace:  EnvOpenBaoNamespace,
}

var (
	ErrNotConfigured = errors.New("gatewayjwt: openbao transit client not configured")
	ErrSignFailed    = errors.New("gatewayjwt: openbao transit sign failed")
	ErrReadKeyFailed = errors.New("gatewayjwt: openbao transit key read failed")

	ErrK8sJWTUnavailable = errors.New("gatewayjwt: openbao kubernetes auth: could not read service account token")
	ErrK8sAuthFailed     = errors.New("gatewayjwt: openbao kubernetes auth login failed")
)

// obTransitClient is a client for transit/sign/<key> and
// transit/keys/<key>.
type obTransitClient struct {
	ob    *openbao.Client
	mount string // Transit secrets engine mount, default "transit"
}

// newTransitClientFromEnv builds an obTransitClient from the Env*
// variables above, called fresh on every GatewaySigner construction
// rather than cached at package init (tests change the environment to
// point at a local server).
func newTransitClientFromEnv() (*obTransitClient, error) {
	ob, err := openbao.NewFromEnv(openBaoEnv, openbao.Errors{
		NotConfigured:     ErrNotConfigured,
		K8sJWTUnavailable: ErrK8sJWTUnavailable,
		K8sAuthFailed:     ErrK8sAuthFailed,
	})
	if err != nil {
		return nil, err
	}
	mount := os.Getenv(EnvOpenBaoTransitMount)
	if mount == "" {
		mount = "transit"
	}
	return &obTransitClient{ob: ob, mount: mount}, nil
}

type transitSignData struct {
	Signature  string `json:"signature"`
	KeyVersion int    `json:"key_version"`
}

// sign calls Transit's POST /v1/<mount>/sign/<keyName>, signing input
// (the exact bytes to be signed — no local hashing; Ed25519 signs the
// message directly) and returning the raw signature bytes plus the key
// version Transit signed with.
func (c *obTransitClient) sign(ctx context.Context, keyName string, input []byte) (sig []byte, keyVersion int, err error) {
	secret, err := c.ob.Post(ctx, c.mount+"/sign/"+keyName, map[string]string{
		"input": base64.StdEncoding.EncodeToString(input),
	})
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrSignFailed, err)
	}
	var sd transitSignData
	if err := openbao.DecodeData(secret, &sd); err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrSignFailed, err)
	}
	// Transit's signature field is "<prefix>:v<version>:<base64>" (the
	// prefix word is "vault" on both Vault and OpenBao — OpenBao kept it
	// for wire compatibility). Take the last ':'-delimited segment rather
	// than assuming the exact prefix, and trust data.key_version (a
	// separate JSON field) for the version rather than parsing it back
	// out of this string.
	parts := strings.Split(sd.Signature, ":")
	if len(parts) < 3 {
		return nil, 0, fmt.Errorf("%w: unexpected signature format %q", ErrSignFailed, sd.Signature)
	}
	raw, err := base64.StdEncoding.DecodeString(parts[len(parts)-1])
	if err != nil {
		return nil, 0, fmt.Errorf("%w: decoding signature: %w", ErrSignFailed, err)
	}
	return raw, sd.KeyVersion, nil
}

type transitKeyVersionInfo struct {
	PublicKey    string `json:"public_key"`
	CreationTime string `json:"creation_time"`
}

type transitReadKeyData struct {
	Type                 string                           `json:"type"`
	Keys                 map[string]transitKeyVersionInfo `json:"keys"`
	MinEncryptionVersion int                              `json:"min_encryption_version"`
	LatestVersion        int                              `json:"latest_version"`
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
	secret, err := c.ob.Read(ctx, c.mount+"/keys/"+keyName, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadKeyFailed, err)
	}
	var rd transitReadKeyData
	if err := openbao.DecodeData(secret, &rd); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadKeyFailed, err)
	}

	versions := make(map[int]transitKeyVersionInfo, len(rd.Keys))
	for k, v := range rd.Keys {
		n, convErr := strconv.Atoi(k)
		if convErr != nil {
			return nil, fmt.Errorf("%w: unexpected key version %q", ErrReadKeyFailed, k)
		}
		versions[n] = v
	}
	return &transitKeyInfo{
		Type:                 rd.Type,
		Versions:             versions,
		MinEncryptionVersion: rd.MinEncryptionVersion,
		LatestVersion:        rd.LatestVersion,
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
