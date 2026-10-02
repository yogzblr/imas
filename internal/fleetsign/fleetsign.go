// Package fleetsign is the sprout release trust root: the Manifest a
// sprout installs from, the one canonical string it is signed over
// (Manifest.Message), the signature encoding stored in
// saas.fleet_versions.signature, and Ed25519 verification against either
// the Keyring shipped in the sprout package (what a sprout trusts) or the
// imas-fleet-signing key versions read from OpenBao Transit (what farmer,
// saasapi and fleetreleaser check against). See
// docs/design/cloudxp-machine-manager-api-design.md §2.5 and §2.6.
//
// The signed message is
//
//	imas-fleet-manifest-v1|version|os|arch|file_name|checksum_sha256|min_sprout_version
//
// (a domain-separation tag, then the fields) and contains no URL: the sprout downloads FileName from the repository
// configured in the sprout itself (requirement 20).
//
// FLAG FOR SECURITY REVIEW. This package is imported by farmer, saasapi
// and sprout, and deliberately contains no signing code at all: the only
// holder of Transit sign capability on imas-fleet-signing is
// cmd/fleetreleaser, a separate binary with its own OpenBao identity.
// That split is enforced by OpenBao policy (deploy/fleetreleaser/), not
// by this package's shape — TestNoSigningCodeInPackage only keeps the
// shape honest.
//
// The JWKS encoding (jwks.go) and JWKSHandler remain for the existing
// enrollment pin and live key fetch only; §2.5 drops both for fleet keys
// and the selfupdate rewrite (FU.2) retires them. Keyring never reads a
// JWKS and never touches the network.
package fleetsign

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// DefaultTransitKeyName is the OpenBao Transit key sprout releases are
// signed with: Ed25519, non-exportable, and distinct from
// internal/gatewayjwt's imas-gateway-jwt key.
const DefaultTransitKeyName = "imas-fleet-signing"

// The one-step job farmer sends a sprout for a self_update action: the
// sprout's selfupdate ingredient (internal/ingredients/selfupdate), method
// apply, with the manifest fields and signature as its properties. Shared
// here so farmer doesn't import the ingredient package to name it.
const (
	SelfUpdateIngredient   = "selfupdate"
	SelfUpdateMethod       = "apply"
	PropVersion            = "version"
	PropChecksumSHA256     = "checksum_sha256"
	PropSignature          = "signature"
	SelfUpdateStepIDPrefix = "selfupdate-"
)

var (
	// ErrInvalidManifest: a field can't be part of a canonical message, so
	// the manifest can be neither signed nor verified.
	ErrInvalidManifest = errors.New("fleetsign: invalid manifest fields")
	// ErrMissingSignature: the row has no signature (for example a
	// fleet_versions row written before the signature column existed).
	// Always a refusal, never a fallback to checksum-only trust.
	ErrMissingSignature = errors.New("fleetsign: manifest has no signature")
	// ErrMalformedSignature: the signature isn't "v<version>:<base64>".
	ErrMalformedSignature = errors.New("fleetsign: malformed signature")
	// ErrUnknownKeyVersion: the signature names a key version the key set
	// or keyring doesn't hold (not shipped, or retired).
	ErrUnknownKeyVersion = errors.New("fleetsign: signature key version not in key set")
	// ErrInvalidSignature: the signature doesn't verify.
	ErrInvalidSignature = errors.New("fleetsign: signature verification failed")
	// ErrNoKeys: the key set is empty.
	ErrNoKeys = errors.New("fleetsign: no fleet signing keys")
)

// EncodeSignature renders a raw Ed25519 signature made by Transit key
// version keyVersion as stored in saas.fleet_versions.signature:
// "v<keyVersion>:<standard base64>". It's Transit's own
// "vault:v<N>:<base64>" format without the product prefix, so the key
// version a verifier must use travels with the signature.
func EncodeSignature(keyVersion int, sig []byte) string {
	return "v" + strconv.Itoa(keyVersion) + ":" + base64.StdEncoding.EncodeToString(sig)
}

// DecodeSignature parses EncodeSignature's format. An empty string is
// ErrMissingSignature, not ErrMalformedSignature, so callers can tell an
// un-migrated row from a corrupted one in their logs; both are refusals.
func DecodeSignature(s string) (keyVersion int, sig []byte, err error) {
	if s == "" {
		return 0, nil, ErrMissingSignature
	}
	ver, b64, ok := strings.Cut(s, ":")
	if !ok || !strings.HasPrefix(ver, "v") {
		return 0, nil, ErrMalformedSignature
	}
	keyVersion, err = strconv.Atoi(ver[1:])
	if err != nil || keyVersion < 1 || ver[1:] != strconv.Itoa(keyVersion) {
		return 0, nil, ErrMalformedSignature
	}
	sig, err = base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return 0, nil, ErrMalformedSignature
	}
	return keyVersion, sig, nil
}

// PublicKey is one version of the imas-fleet-signing Transit key.
type PublicKey struct {
	Version int
	Key     ed25519.PublicKey
}

// KeySet is every imas-fleet-signing key version a verifier trusts,
// sorted by ascending Version.
type KeySet []PublicKey

// NewKeySet validates keys and returns them as a sorted KeySet. It
// rejects an empty set, a non-positive or duplicate version, a key that
// isn't ed25519.PublicKeySize bytes, and a weak key (checkPublicKey).
func NewKeySet(keys []PublicKey) (KeySet, error) {
	if len(keys) == 0 {
		return nil, ErrNoKeys
	}
	seen := make(map[int]bool, len(keys))
	ks := make(KeySet, 0, len(keys))
	for _, k := range keys {
		if k.Version < 1 {
			return nil, fmt.Errorf("fleetsign: key version %d is not positive", k.Version)
		}
		if seen[k.Version] {
			return nil, fmt.Errorf("fleetsign: duplicate key version %d", k.Version)
		}
		if len(k.Key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("fleetsign: key version %d is %d bytes, want %d", k.Version, len(k.Key), ed25519.PublicKeySize)
		}
		if err := checkPublicKey(k.Key); err != nil {
			return nil, fmt.Errorf("fleetsign: key version %d: %w", k.Version, err)
		}
		seen[k.Version] = true
		ks = append(ks, PublicKey{Version: k.Version, Key: append(ed25519.PublicKey(nil), k.Key...)})
	}
	sort.Slice(ks, func(i, j int) bool { return ks[i].Version < ks[j].Version })
	return ks, nil
}

// Verify checks m.Signature (EncodeSignature's format) over m's
// canonical message (Manifest.Message) against the key version the
// signature names. Every failure is an error: there is no path on which a
// missing or bad signature, or an invalid field, is accepted.
func (ks KeySet) Verify(m Manifest) error {
	if len(ks) == 0 {
		return ErrNoKeys
	}
	msg, err := m.Message()
	if err != nil {
		return err
	}
	return ks.verifyMessage(msg, m.Signature)
}

// verifyMessage is the one signature check behind KeySet.Verify and
// Keyring.Verify: decode the signature, pick the key it names, verify.
// Callers build msg with Manifest.Message; it is separate only so the
// captured real-OpenBao signatures (openbao_response_test.go) can be
// checked over the exact bytes they were made over.
func (ks KeySet) verifyMessage(msg []byte, signature string) error {
	keyVersion, sig, err := DecodeSignature(signature)
	if err != nil {
		return err
	}
	for _, k := range ks {
		if k.Version != keyVersion {
			continue
		}
		if len(k.Key) != ed25519.PublicKeySize || !ed25519.Verify(k.Key, msg, sig) {
			return ErrInvalidSignature
		}
		return nil
	}
	return fmt.Errorf("%w: v%d", ErrUnknownKeyVersion, keyVersion)
}
