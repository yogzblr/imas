package fleetsign

// This file is a READ-ONLY OpenBao Transit client for the
// imas-fleet-signing key, used by farmer (to re-check a release's
// signature before serving an update manifest or dispatching a
// self_update) and by saasapi (to check a catalog row's signature before
// building a rollout). The client is internal/openbao (the official
// OpenBao Go client), which owns auth, TLS and error decoding.
//
// Deliberately absent: a sign method. The only request this package
// makes against Transit is GET <mount>/keys/<key>. The sign-capable
// client lives in cmd/fleetreleaser, a
// separate binary with its own OpenBao identity. Whether farmer's and
// saasapi's tokens *can* sign is decided by their OpenBao policy
// (deploy/fleetreleaser/policies/imas-fleet-verify.hcl), which is what
// actually enforces the split — see cmd/fleetreleaser's
// TestOpenBaoEnforcesReadOnlyFleetKey.

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/yogzblr/imas/internal/openbao"
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
	EnvOpenBaoK8sJWTPath = "IMAS_FLEETSIGN_OPENBAO_K8S_JWT_PATH" // default openbao.DefaultK8sJWTPath

	// EnvOpenBaoNamespace optionally sets the X-Vault-Namespace header.
	EnvOpenBaoNamespace = "IMAS_FLEETSIGN_OPENBAO_NAMESPACE"

	// EnvTransitKeyName overrides DefaultTransitKeyName.
	EnvTransitKeyName = "IMAS_FLEETSIGN_TRANSIT_KEY"
)

// Recognized values for IMAS_FLEETSIGN_OPENBAO_AUTH_METHOD.
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
	ErrNotConfigured = errors.New("fleetsign: openbao transit client not configured")
	ErrReadKeyFailed = errors.New("fleetsign: openbao transit key read failed")

	ErrK8sJWTUnavailable = errors.New("fleetsign: openbao kubernetes auth: could not read service account token")
	ErrK8sAuthFailed     = errors.New("fleetsign: openbao kubernetes auth login failed")
)

// obTransitClient is a read-only client for Transit's GET
// /v1/<mount>/keys/<key>.
type obTransitClient struct {
	ob    *openbao.Client
	mount string
}

// newTransitClientFromEnv reads the environment fresh on every
// construction so tests can point it at a local server.
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

// transitReadKeyData is the data of Transit's keys/<key> read.
type transitReadKeyData struct {
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
// Every Transit-side verifier of a fleet release (farmer's update
// manifest endpoint and self_update re-check, saasapi's release
// registration and dispatch checks) uses this one selection, so they all
// agree on which versions are valid. A sprout verifies against its
// shipped Keyring instead, which an operator keeps in step with these
// versions (packaging/etc/fleet-signing-keys.md).
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
	secret, err := c.ob.Read(ctx, c.mount+"/keys/"+keyName, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadKeyFailed, err)
	}
	var rd transitReadKeyData
	if err := openbao.DecodeData(secret, &rd); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReadKeyFailed, err)
	}
	if rd.Type != "ed25519" {
		return nil, fmt.Errorf("%w: Transit key %q is type %q, want ed25519", ErrReadKeyFailed, keyName, rd.Type)
	}
	// A floor of 0 is Transit's "no restriction" sentinel: treat it as 1,
	// the same handling PublicKeys gives min_encryption_version.
	minVersion := rd.MinDecryptionVersion
	if minVersion < 1 {
		minVersion = 1
	}
	keys := make([]PublicKey, 0, len(rd.Keys))
	for k, v := range rd.Keys {
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
// SubjectPublicKeyInfo block. New code should call
// ParseTransitEd25519PublicKey; remove this once cmd/fleetreleaser's
// caller and its fixture move to it.
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

// KeySetSource is anything that can report the current fleet signing key
// set. *TransitKeySource is the production implementation.
type KeySetSource interface {
	KeySet(ctx context.Context) (KeySet, error)
}

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

// Verify checks m's signature against the key set Transit currently
// serves.
func (s *TransitKeySource) Verify(ctx context.Context, m Manifest) error {
	ks, err := s.KeySet(ctx)
	if err != nil {
		return err
	}
	return ks.Verify(m)
}
