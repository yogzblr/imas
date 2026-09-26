// Package fleetsign is the verify side of sprout release signing: the
// canonical string a fleet_versions row is signed over, the signature
// encoding stored in saas.fleet_versions.signature, Ed25519 verification
// against a set of imas-fleet-signing public keys, and the JWKS encoding
// those public keys travel in (farmer's ungated
// /v1/.well-known/fleet-signing-jwks.json, the POST /v1/enroll response,
// and the sprout's pinned copy on disk). See
// docs/design/cloudxp-machine-manager-api-design.md §2.5.
//
// FLAG FOR SECURITY REVIEW. This package is imported by farmer, saasapi
// and sprout, and deliberately contains no signing code at all: the only
// holder of Transit sign capability on imas-fleet-signing is
// cmd/fleetreleaser, a separate binary with its own OpenBao identity.
// That split is enforced by OpenBao policy (deploy/fleetreleaser/), not
// by this package's shape — TestNoSigningCodeInPackage only keeps the
// shape honest.
package fleetsign

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
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
// apply, with the release fields and signature as its properties. Shared
// here so farmer doesn't import the ingredient package to name it.
const (
	SelfUpdateIngredient   = "selfupdate"
	SelfUpdateMethod       = "apply"
	PropVersion            = "version"
	PropArtifactURL        = "artifact_url"
	PropChecksumSHA256     = "checksum_sha256"
	PropSignature          = "signature"
	SelfUpdateStepIDPrefix = "selfupdate-"
)

// Field limits, matching saas.fleet_versions' column sizes
// (internal/saasapi/model.go's FleetVersion).
const (
	maxVersionLen     = 64
	maxArtifactURLLen = 2048
)

var (
	// ErrInvalidRelease: a field can't be part of a canonical message, so
	// it can be neither signed nor verified.
	ErrInvalidRelease = errors.New("fleetsign: invalid release fields")
	// ErrMissingSignature: the row has no signature (for example a
	// fleet_versions row written before the signature column existed).
	// Always a refusal, never a fallback to checksum-only trust.
	ErrMissingSignature = errors.New("fleetsign: release has no signature")
	// ErrMalformedSignature: the signature isn't "v<version>:<base64>".
	ErrMalformedSignature = errors.New("fleetsign: malformed signature")
	// ErrUnknownKeyVersion: the signature names a key version the key set
	// doesn't hold (not fetched or pinned, or retired by min_decryption_version).
	ErrUnknownKeyVersion = errors.New("fleetsign: signature key version not in key set")
	// ErrInvalidSignature: the signature doesn't verify.
	ErrInvalidSignature = errors.New("fleetsign: signature verification failed")
	// ErrNoKeys: the key set is empty.
	ErrNoKeys = errors.New("fleetsign: no fleet signing keys")
)

// Release is the signed content of one saas.fleet_versions row.
type Release struct {
	Version        string
	ArtifactURL    string
	ChecksumSHA256 string
}

// Message returns the canonical bytes a release is signed over:
// version|artifact_url|checksum_sha256.
//
// The fields are validated first, and the same rules apply when signing
// and when verifying, so the encoding is unambiguous: no field may be
// empty or contain '|' or a control character, the artifact URL must be
// an absolute https URL without userinfo, and the checksum must be exactly
// 64 lowercase hex characters (callers lowercase it before signing; a
// verifier never normalizes, so an uppercase checksum is refused rather
// than silently matched).
func (r Release) Message() ([]byte, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	return []byte(r.Version + "|" + r.ArtifactURL + "|" + r.ChecksumSHA256), nil
}

func (r Release) validate() error {
	for name, v := range map[string]string{
		"version": r.Version, "artifact_url": r.ArtifactURL, "checksum_sha256": r.ChecksumSHA256,
	} {
		if v == "" {
			return fmt.Errorf("%w: %s is empty", ErrInvalidRelease, name)
		}
		if strings.ContainsRune(v, '|') {
			return fmt.Errorf("%w: %s contains '|'", ErrInvalidRelease, name)
		}
		for _, c := range v {
			if c < 0x20 || c == 0x7f {
				return fmt.Errorf("%w: %s contains a control character", ErrInvalidRelease, name)
			}
		}
	}
	if len(r.Version) > maxVersionLen {
		return fmt.Errorf("%w: version is longer than %d characters", ErrInvalidRelease, maxVersionLen)
	}
	if len(r.ArtifactURL) > maxArtifactURLLen {
		return fmt.Errorf("%w: artifact_url is longer than %d characters", ErrInvalidRelease, maxArtifactURLLen)
	}
	u, err := url.Parse(r.ArtifactURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return fmt.Errorf("%w: artifact_url is not an https URL", ErrInvalidRelease)
	}
	if sum, err := hex.DecodeString(r.ChecksumSHA256); err != nil || len(sum) != 32 ||
		r.ChecksumSHA256 != strings.ToLower(r.ChecksumSHA256) {
		return fmt.Errorf("%w: checksum_sha256 is not 64 lowercase hex characters", ErrInvalidRelease)
	}
	return nil
}

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
// rejects an empty set, a non-positive or duplicate version, and a key
// that isn't ed25519.PublicKeySize bytes.
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
		seen[k.Version] = true
		ks = append(ks, PublicKey{Version: k.Version, Key: append(ed25519.PublicKey(nil), k.Key...)})
	}
	sort.Slice(ks, func(i, j int) bool { return ks[i].Version < ks[j].Version })
	return ks, nil
}

// Verify checks signature (EncodeSignature's format) over r's canonical
// message against the key version it names. Every failure is an error:
// there is no path on which a missing or bad signature is accepted.
func (ks KeySet) Verify(r Release, signature string) error {
	if len(ks) == 0 {
		return ErrNoKeys
	}
	msg, err := r.Message()
	if err != nil {
		return err
	}
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
