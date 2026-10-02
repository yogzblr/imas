package main

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/fleetsign"
	"github.com/yogzblr/imas/internal/saasapi"
)

// releaseSigner is what publish needs from Transit. *obTransitClient is
// the real one; tests substitute a local key.
type releaseSigner interface {
	sign(ctx context.Context, input []byte) (sig []byte, keyVersion int, err error)
	keySet(ctx context.Context) (fleetsign.KeySet, error)
}

// release is one fleetreleaser run: the fleetsign.Manifest entry it
// signs, and the artifact URL the current saas.fleet_versions row still
// stores. The URL is not signed (the manifest has none); FU.34 drops it,
// and this row write, when fleetreleaser becomes a stateless signing
// service. Until then the row has no os, arch, file_name or
// min_sprout_version columns, so the signature written can only be
// checked by someone who knows those fields, as this run does.
type release struct {
	fleetsign.Manifest
	ArtifactURL string
}

// errInvalidArtifactURL: the artifact URL is not one the row may store.
var errInvalidArtifactURL = errors.New("fleetreleaser: artifact_url is not an https URL")

// validate checks the manifest (fleetsign's canonical-message rules) and
// keeps the check fleetsign made on the artifact URL while it was signed:
// an absolute https URL without userinfo, at most 2048 characters (the
// column size), no control characters.
func (r release) validate() error {
	if err := r.Manifest.Validate(); err != nil {
		return err
	}
	u, err := url.Parse(r.ArtifactURL)
	if err != nil || len(r.ArtifactURL) > 2048 || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		strings.ContainsFunc(r.ArtifactURL, func(c rune) bool { return c < 0x20 || c == 0x7f }) {
		return errInvalidArtifactURL
	}
	return nil
}

// withSignature returns the manifest with signature set, for verifying.
func (r release) withSignature(signature string) fleetsign.Manifest {
	m := r.Manifest
	m.Signature = signature
	return m
}

// outcome is what publish did.
type outcome string

const (
	outcomeInserted   outcome = "inserted"
	outcomeBackfilled outcome = "backfilled"
	outcomeUnchanged  outcome = "unchanged"
)

var (
	// errReleaseConflict: saas.fleet_versions already has this version
	// with different contents. Published releases are immutable; a new
	// build is a new version.
	errReleaseConflict = errors.New("fleetreleaser: version already published with different contents")
	// errExistingSignatureInvalid: the row for this version carries a
	// signature that doesn't verify against the current key set. Nothing
	// is overwritten: that needs a human to look at how it got there.
	errExistingSignatureInvalid = errors.New("fleetreleaser: existing row's signature does not verify; refusing to overwrite")
)

// publish signs rel and makes saas.fleet_versions hold it, signed:
//
//   - no row for rel.Version: sign, verify, insert.
//   - a row with identical fields and no signature (written before the
//     signature column existed): sign, verify, and set only its signature.
//     The fields signed are the ones this run was given, and they must
//     match the row exactly, so backfilling can't bless a row someone
//     else wrote with different contents.
//   - a row with identical fields and a signature that verifies: nothing.
//   - anything else: an error, nothing written.
//
// Every signature is verified against the key set Transit reports before
// it's written, so a canonicalization or key-type mistake fails here
// rather than on every sprout.
func publish(ctx context.Context, db *gorm.DB, s releaseSigner, rel release, notes string, releasedAt time.Time) (outcome, error) {
	if err := rel.validate(); err != nil {
		return "", err
	}
	msg, err := rel.Message()
	if err != nil {
		return "", err
	}

	var existing []saasapi.FleetVersion
	if err := db.WithContext(ctx).Where("version = ?", rel.Version).Limit(1).Find(&existing).Error; err != nil {
		return "", fmt.Errorf("fleetreleaser: looking up version %s: %w", rel.Version, err)
	}
	if len(existing) == 1 {
		row := existing[0]
		if row.ArtifactURL != rel.ArtifactURL || row.ChecksumSHA256 != rel.ChecksumSHA256 {
			return "", fmt.Errorf("%w: %s", errReleaseConflict, rel.Version)
		}
		if row.Signature != "" {
			ks, err := s.keySet(ctx)
			if err != nil {
				return "", err
			}
			if err := ks.Verify(rel.withSignature(row.Signature)); err != nil {
				return "", fmt.Errorf("%w: %s: %w", errExistingSignatureInvalid, rel.Version, err)
			}
			return outcomeUnchanged, nil
		}
	}

	signature, err := signAndVerify(ctx, s, rel, msg)
	if err != nil {
		return "", err
	}

	if len(existing) == 1 {
		// Guarded on the fields just compared and on the signature still
		// being empty, so a concurrent writer can't slip a change in
		// between the read above and this write.
		res := db.WithContext(ctx).Model(&saasapi.FleetVersion{}).
			Where("version = ? AND artifact_url = ? AND checksum_sha256 = ? AND signature = ?",
				rel.Version, rel.ArtifactURL, rel.ChecksumSHA256, "").
			Update("signature", signature)
		if res.Error != nil {
			return "", fmt.Errorf("fleetreleaser: backfilling signature for %s: %w", rel.Version, res.Error)
		}
		if res.RowsAffected != 1 {
			return "", fmt.Errorf("fleetreleaser: row for %s changed while signing; nothing written", rel.Version)
		}
		return outcomeBackfilled, nil
	}

	id, err := newFleetVersionID()
	if err != nil {
		return "", err
	}
	row := saasapi.FleetVersion{
		ID:             id,
		Version:        rel.Version,
		ArtifactURL:    rel.ArtifactURL,
		ChecksumSHA256: rel.ChecksumSHA256,
		Signature:      signature,
		ReleasedAt:     releasedAt.UTC(),
		Notes:          notes,
	}
	if err := db.WithContext(ctx).Create(&row).Error; err != nil {
		return "", fmt.Errorf("fleetreleaser: inserting %s: %w", rel.Version, err)
	}
	return outcomeInserted, nil
}

func signAndVerify(ctx context.Context, s releaseSigner, rel release, msg []byte) (string, error) {
	sig, keyVersion, err := s.sign(ctx, msg)
	if err != nil {
		return "", err
	}
	signature := fleetsign.EncodeSignature(keyVersion, sig)
	ks, err := s.keySet(ctx)
	if err != nil {
		return "", err
	}
	if err := ks.Verify(rel.withSignature(signature)); err != nil {
		return "", fmt.Errorf("fleetreleaser: Transit's signature for %s does not verify against its own key set: %w", rel.Version, err)
	}
	return signature, nil
}

// newFleetVersionID returns an id in the same "<prefix>_<16 lowercase
// base32>" shape internal/saasapi's newID gives every other saas row.
func newFleetVersionID() (string, error) {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("fleetreleaser: generating id: %w", err)
	}
	return "fv_" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)), nil
}
