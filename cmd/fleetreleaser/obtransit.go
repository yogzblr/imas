package main

// The sign-capable OpenBao Transit client for imas-fleet-signing — the
// only one in the repo. The client is internal/openbao (the official
// OpenBao Go client), which owns auth, TLS and error decoding; this file
// keeps the two Transit requests fleetreleaser makes.
//
// It lives in package main on purpose. internal/fleetsign, which farmer,
// saasapi and sprout import, holds only the read-only half; nothing
// importable carries a Transit sign call for this key. That is hygiene,
// not the security boundary: the boundary is that only this binary's
// OpenBao identity has a policy granting transit/sign/imas-fleet-signing
// (deploy/fleetreleaser/).
//
// FLAG FOR SECURITY REVIEW.

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/yogzblr/imas/internal/fleetsign"
	"github.com/yogzblr/imas/internal/openbao"
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
	EnvOpenBaoK8sJWTPath   = "IMAS_FLEETRELEASER_OPENBAO_K8S_JWT_PATH" // default openbao.DefaultK8sJWTPath
	EnvOpenBaoNamespace    = "IMAS_FLEETRELEASER_OPENBAO_NAMESPACE"    // optional X-Vault-Namespace

	// EnvTransitKeyName overrides fleetsign.DefaultTransitKeyName.
	EnvTransitKeyName = "IMAS_FLEETRELEASER_TRANSIT_KEY"
)

const authMethodToken = openbao.AuthMethodToken

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
	errNotConfigured = errors.New("fleetreleaser: openbao transit client not configured")
	errSignFailed    = errors.New("fleetreleaser: openbao transit sign failed")
	errReadKeyFailed = errors.New("fleetreleaser: openbao transit key read failed")
	errK8sAuthFailed = errors.New("fleetreleaser: openbao kubernetes auth login failed")
)

// obTransitClient is a client for transit/sign/<key> and
// transit/keys/<key>.
type obTransitClient struct {
	ob      *openbao.Client
	mount   string
	keyName string
}

func newTransitClientFromEnv() (*obTransitClient, error) {
	ob, err := openbao.NewFromEnv(openBaoEnv, openbao.Errors{
		NotConfigured: errNotConfigured,
		// One sentinel for both, as before: an unreadable service account
		// token is reported as a failed login.
		K8sJWTUnavailable: errK8sAuthFailed,
		K8sAuthFailed:     errK8sAuthFailed,
	})
	if err != nil {
		return nil, err
	}
	c := &obTransitClient{
		ob:      ob,
		mount:   os.Getenv(EnvOpenBaoTransitMount),
		keyName: os.Getenv(EnvTransitKeyName),
	}
	if c.mount == "" {
		c.mount = "transit"
	}
	if c.keyName == "" {
		c.keyName = fleetsign.DefaultTransitKeyName
	}
	return c, nil
}

// sign calls POST /v1/<mount>/sign/<key> over input (Ed25519 signs the
// message directly, no prehash) and returns the raw signature and the
// key version Transit used.
func (c *obTransitClient) sign(ctx context.Context, input []byte) ([]byte, int, error) {
	secret, err := c.ob.Post(ctx, c.mount+"/sign/"+c.keyName,
		map[string]string{"input": base64.StdEncoding.EncodeToString(input)})
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", errSignFailed, err)
	}
	var sd struct {
		Signature  string `json:"signature"`
		KeyVersion int    `json:"key_version"`
	}
	if err := openbao.DecodeData(secret, &sd); err != nil {
		return nil, 0, fmt.Errorf("%w: %w", errSignFailed, err)
	}
	// "<prefix>:v<version>:<base64>"; take the last segment and trust the
	// separate key_version field, as internal/gatewayjwt does.
	parts := strings.Split(sd.Signature, ":")
	if len(parts) < 3 || sd.KeyVersion < 1 {
		return nil, 0, fmt.Errorf("%w: unexpected signature format %q", errSignFailed, sd.Signature)
	}
	raw, err := base64.StdEncoding.DecodeString(parts[len(parts)-1])
	if err != nil {
		return nil, 0, fmt.Errorf("%w: decoding signature: %w", errSignFailed, err)
	}
	return raw, sd.KeyVersion, nil
}

// keySet calls GET /v1/<mount>/keys/<key>, for verifying a signature
// right after Transit produced it and before it is returned
// (signAndVerify), and once at startup to fail fast on a key this
// identity can't read or that isn't Ed25519.
func (c *obTransitClient) keySet(ctx context.Context) (fleetsign.KeySet, error) {
	secret, err := c.ob.Read(ctx, c.mount+"/keys/"+c.keyName, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errReadKeyFailed, err)
	}
	var rd struct {
		Type string `json:"type"`
		Keys map[string]struct {
			PublicKey string `json:"public_key"`
		} `json:"keys"`
		// MinDecryptionVersion is the floor Transit's own /verify
		// honors; see the filter below.
		MinDecryptionVersion int `json:"min_decryption_version"`
	}
	if err := openbao.DecodeData(secret, &rd); err != nil {
		return nil, fmt.Errorf("%w: %w", errReadKeyFailed, err)
	}
	if rd.Type != "ed25519" {
		return nil, fmt.Errorf("%w: Transit key %q is type %q, want ed25519", errReadKeyFailed, c.keyName, rd.Type)
	}
	// Same floor as every verifier (fleetsign's readKeySet):
	// min_decryption_version, the floor Transit's own /verify honors, with
	// 0 meaning unrestricted. A signature Transit has just produced is
	// always by a version >= min_encryption_version >=
	// min_decryption_version, so the post-sign self-verify always finds
	// its key.
	minVersion := rd.MinDecryptionVersion
	if minVersion < 1 {
		minVersion = 1
	}
	keys := make([]fleetsign.PublicKey, 0, len(rd.Keys))
	for k, v := range rd.Keys {
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
