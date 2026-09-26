package gatewayjwt

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"
)

// GatewaySigner wraps OpenBao Transit for the gateway key only — the
// single platform-wide Ed25519 key every gateway JWT is signed with (see
// package doc). The private key never leaves OpenBao: every signature is
// produced via a Transit "sign" call (obtransit.go's (*obTransitClient).sign),
// and this type never holds or constructs an ed25519.PrivateKey.
type GatewaySigner struct {
	client  *obTransitClient
	keyName string

	cacheMu   sync.Mutex
	cacheAt   time.Time
	cacheKeys []TransitKeyVersion
}

// TransitKeyVersion is one version of the gateway Transit key, as
// returned by PublicKeys.
type TransitKeyVersion struct {
	Version   int
	PublicKey ed25519.PublicKey
}

// transitPublicKeyCacheTTL bounds how often PublicKeys hits Transit
// directly. Envoy's own remote_jwks refresh interval (5-10 min, set in
// the Envoy config) already bounds request frequency from that
// direction; this is a second, independent bound so a burst of other
// callers (manual fetches, this package's own MintGatewayJWT looking up
// the current signing version) doesn't hammer Transit.
const transitPublicKeyCacheTTL = 60 * time.Second

// NewGatewaySigner builds a GatewaySigner from the IMAS_GATEWAY_OPENBAO_*
// environment variables (see obtransit.go) and the given Transit key
// name.
func NewGatewaySigner(keyName string) (*GatewaySigner, error) {
	client, err := newTransitClientFromEnv()
	if err != nil {
		return nil, err
	}
	if keyName == "" {
		return nil, fmt.Errorf("%w: empty Transit key name", ErrNotConfigured)
	}
	return &GatewaySigner{client: client, keyName: keyName}, nil
}

// Sign returns a raw Ed25519 signature over signingInput via Transit's
// sign endpoint, and the Transit key version that produced it.
// signingInput is the exact byte sequence to be signed (e.g. a JWS
// signing input, base64url(header)+"."+base64url(payload)) — Ed25519
// signs the message directly, no local hashing.
func (s *GatewaySigner) Sign(ctx context.Context, signingInput []byte) (sig []byte, keyVersion int, err error) {
	return s.client.sign(ctx, s.keyName, signingInput)
}

// PublicKeys returns every Transit key version at or above the key's
// current min_encryption_version, for JWKS serving during a rotation
// overlap window (a gateway JWT signed under an outgoing version must
// keep validating until it ages out). Results are cached in-process for
// transitPublicKeyCacheTTL.
func (s *GatewaySigner) PublicKeys(ctx context.Context) ([]TransitKeyVersion, error) {
	s.cacheMu.Lock()
	if s.cacheKeys != nil && time.Since(s.cacheAt) < transitPublicKeyCacheTTL {
		keys := s.cacheKeys
		s.cacheMu.Unlock()
		return keys, nil
	}
	s.cacheMu.Unlock()

	info, err := s.client.readKey(ctx, s.keyName)
	if err != nil {
		return nil, err
	}
	if info.Type != "ed25519" {
		return nil, fmt.Errorf("gatewayjwt: Transit key %q is type %q, want ed25519", s.keyName, info.Type)
	}

	// min_encryption_version of 0 is Transit's sentinel for "no
	// restriction, always use latest" — treat that the same as 1 (every
	// version in the map), which also matches this method's "serve
	// everything still valid for verification" purpose better than a
	// literal >= 0 would.
	minVersion := info.MinEncryptionVersion
	if minVersion < 1 {
		minVersion = 1
	}

	keys := make([]TransitKeyVersion, 0, len(info.Versions))
	for version, v := range info.Versions {
		if version < minVersion {
			continue
		}
		pub, perr := parseTransitEd25519PublicKey(v.PublicKey)
		if perr != nil {
			return nil, fmt.Errorf("gatewayjwt: Transit key %q version %d: %w", s.keyName, version, perr)
		}
		keys = append(keys, TransitKeyVersion{Version: version, PublicKey: pub})
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Version < keys[j].Version })

	s.cacheMu.Lock()
	s.cacheKeys = keys
	s.cacheAt = time.Now()
	s.cacheMu.Unlock()
	return keys, nil
}

// currentSigningKey returns the highest (most recent) key version and
// its public key — the version MintGatewayJWT signs new tokens with and
// stamps into the JWS "kid" header.
func (s *GatewaySigner) currentSigningKey(ctx context.Context) (TransitKeyVersion, error) {
	keys, err := s.PublicKeys(ctx)
	if err != nil {
		return TransitKeyVersion{}, err
	}
	if len(keys) == 0 {
		return TransitKeyVersion{}, fmt.Errorf("gatewayjwt: Transit key %q has no usable versions", s.keyName)
	}
	return keys[len(keys)-1], nil // PublicKeys returns them sorted ascending
}

// cryptoSignerAdapter implements crypto.Signer over a GatewaySigner for
// exactly one Transit key version, so jwx's jws EdDSA signer (which
// expects a crypto.Signer or raw ed25519.PrivateKey — see
// jws/eddsa.go's isValidEDDSAKey) can drive Transit without this package
// ever exposing or constructing a private key. It exists only for the
// duration of one MintGatewayJWT call.
type cryptoSignerAdapter struct {
	ctx    context.Context
	signer *GatewaySigner
	pub    ed25519.PublicKey
}

func (a *cryptoSignerAdapter) Public() crypto.PublicKey { return a.pub }

// Sign satisfies crypto.Signer. rand and opts are unused: Ed25519
// signing in both crypto/ed25519 and OpenBao Transit is deterministic
// and operates on the message directly (opts is conventionally
// crypto.Hash(0) for Ed25519, per crypto.Signer's own doc). message is
// the JWS signing input jwx hands us — passed straight through to
// Transit.
func (a *cryptoSignerAdapter) Sign(_ io.Reader, message []byte, _ crypto.SignerOpts) ([]byte, error) {
	sig, _, err := a.signer.Sign(a.ctx, message)
	return sig, err
}

var _ crypto.Signer = (*cryptoSignerAdapter)(nil)
