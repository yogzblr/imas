package pki

// Sprout-side storage of the enrollment-time imas-fleet-signing public key
// set (design doc §2.5). The sprout receives it once, in POST /v1/enroll's
// fleet_signing_jwks, and keeps it next to its root CA
// (config.SproutRootCA) with the same lifecycle: written the first time,
// never silently replaced afterwards.
//
// FLAG FOR SECURITY REVIEW. This pin is a BOOTSTRAP FALLBACK ONLY, not the
// sprout's root of trust for releases. Releases are verified against the
// key set fetched live from farmer over the SproutRootCA-pinned NATS
// connection (internal/fleetkeys), which follows Transit key rotations;
// this file is consulted only until the first live fetch succeeds, after
// which internal/ingredients/selfupdate (keys.go) marks it superseded and
// never uses it again.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/fleetsign"
)

// ErrFleetKeyAlreadyPinned is returned when a different fleet signing key
// set is already pinned. The pinned file is left untouched.
var ErrFleetKeyAlreadyPinned = errors.New("pki: a different fleet signing key set is already pinned")

// ErrFleetKeyNotPinned is returned when no fleet signing key set has been
// pinned yet. Self-updates are refused until one is.
var ErrFleetKeyNotPinned = errors.New("pki: no fleet signing key set pinned")

// PinFleetSigningKeys validates jwks (fleetsign.ParseJWKS) and writes it
// to config.SproutFleetSigningJWKS if nothing is pinned there yet.
// Pinning the same document again is a no-op; pinning a different one is
// ErrFleetKeyAlreadyPinned. The write is atomic (temp file + rename) so
// a crash can't leave a truncated pin behind.
func PinFleetSigningKeys(jwks []byte) error {
	if _, err := fleetsign.ParseJWKS(jwks); err != nil {
		return err
	}
	path := config.SproutFleetSigningJWKS
	if path == "" {
		return errors.New("pki: sproutfleetsigningjwks is not configured")
	}
	existing, err := os.ReadFile(path)
	switch {
	case err == nil:
		if bytes.Equal(bytes.TrimSpace(existing), bytes.TrimSpace(jwks)) {
			return nil
		}
		return ErrFleetKeyAlreadyPinned
	case !os.IsNotExist(err):
		return fmt.Errorf("pki: reading pinned fleet signing keys: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("pki: creating %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".fleet-signing-jwks-*")
	if err != nil {
		return fmt.Errorf("pki: pinning fleet signing keys: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(jwks); err != nil {
		tmp.Close()
		return fmt.Errorf("pki: pinning fleet signing keys: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("pki: pinning fleet signing keys: %w", err)
	}
	// Public keys: world-readable is fine; only root may replace them.
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		return fmt.Errorf("pki: pinning fleet signing keys: %w", err)
	}
	// os.Link fails if path appeared meanwhile, keeping write-once.
	if err := os.Link(tmpPath, path); err != nil {
		if os.IsExist(err) {
			return PinFleetSigningKeys(jwks)
		}
		return fmt.Errorf("pki: pinning fleet signing keys: %w", err)
	}
	return nil
}

// LoadPinnedFleetSigningKeys reads and validates the pinned key set.
func LoadPinnedFleetSigningKeys() (fleetsign.KeySet, error) {
	path := config.SproutFleetSigningJWKS
	if path == "" {
		return nil, ErrFleetKeyNotPinned
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("%w (%s)", ErrFleetKeyNotPinned, path)
	}
	if err != nil {
		return nil, fmt.Errorf("pki: reading pinned fleet signing keys: %w", err)
	}
	return fleetsign.ParseJWKS(data)
}
