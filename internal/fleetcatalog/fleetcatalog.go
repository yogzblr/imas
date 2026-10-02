// Package fleetcatalog is farmer's read-only view of the fleet release
// catalog (design doc §2.5, §2.6, §4.3): saas.fleet_versions, the signed
// rows saasapi registers, and saas.tenant_update_policy, the version each
// tenant has approved. Farmer reads both through its own PXC handle and
// its read-only saas grant (§4.1); nothing here writes.
//
// Two farmer paths read it:
//
//   - GET /v1/sprout/update-manifest (internal/api/handlers): one signed
//     row for a sprout's tenant, version, OS, arch and package type
//     (ApprovedManifest);
//   - internal.sprout.action self_update (internal/natsapi): before
//     dispatching, the tenant's approved version (ApprovedVersion) and
//     every row of the target version (ReleaseRows), each re-verified.
//
// Every query is scoped by tenant_id where a tenant is involved (§4
// "Tenant safety").
package fleetcatalog

import (
	"context"
	"database/sql"
	"errors"
	"sync"

	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/fleetsign"
)

// Row is one saas.fleet_versions row: the signed manifest, plus the two
// unsigned columns a reader needs.
type Row struct {
	Manifest    fleetsign.Manifest
	PackageType string
	Revoked     bool
}

// Catalog reads the release catalog.
type Catalog interface {
	// ApprovedManifest returns the row for (version, os, arch,
	// packageType), signature included, only if it is not revoked and
	// version is tenantID's approved_version. found is false for every
	// other case; err is only for a failed read.
	ApprovedManifest(ctx context.Context, tenantID, os, arch, packageType, version string) (m fleetsign.Manifest, found bool, err error)
	// ApprovedVersion returns tenantID's approved_version. ok is false if
	// the tenant has no policy row or approved none.
	ApprovedVersion(ctx context.Context, tenantID string) (version string, ok bool, err error)
	// ReleaseRows returns every row of version, revoked ones included,
	// ordered by OS, arch and package type. None means version isn't
	// registered.
	ReleaseRows(ctx context.Context, version string) ([]Row, error)
}

// SQL is the Catalog over farmer's PXC handle.
type SQL struct{ db *gorm.DB }

// New returns the Catalog over db.
func New(db *gorm.DB) SQL { return SQL{db: db} }

// approvedManifestQuery selects the row in one statement, with tenant_id
// in the same WHERE as the caller-supplied version, os, arch and package
// type (§4 "Tenant safety"): the policy join is what restricts a tenant
// to the one version it approved.
const approvedManifestQuery = `SELECT fv.version, fv.os, fv.arch, fv.file_name,
       fv.checksum_sha256, fv.min_sprout_version, fv.signature
  FROM saas.fleet_versions fv
  JOIN saas.tenant_update_policy p ON p.approved_version = fv.version
 WHERE p.tenant_id = ? AND fv.version = ? AND fv.os = ? AND fv.arch = ?
   AND fv.package_type = ? AND fv.revoked = FALSE`

func (s SQL) ApprovedManifest(ctx context.Context, tenantID, os, arch, packageType, version string) (fleetsign.Manifest, bool, error) {
	var m fleetsign.Manifest
	err := s.db.WithContext(ctx).Raw(approvedManifestQuery, tenantID, version, os, arch, packageType).Row().
		Scan(&m.Version, &m.OS, &m.Arch, &m.FileName, &m.ChecksumSHA256, &m.MinSproutVersion, &m.Signature)
	if errors.Is(err, sql.ErrNoRows) {
		return fleetsign.Manifest{}, false, nil
	}
	if err != nil {
		return fleetsign.Manifest{}, false, err
	}
	return m, true, nil
}

const approvedVersionQuery = `SELECT approved_version FROM saas.tenant_update_policy WHERE tenant_id = ?`

func (s SQL) ApprovedVersion(ctx context.Context, tenantID string) (string, bool, error) {
	var v sql.NullString
	err := s.db.WithContext(ctx).Raw(approvedVersionQuery, tenantID).Row().Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v.String, v.Valid && v.String != "", nil
}

const releaseRowsQuery = `SELECT version, os, arch, package_type, file_name,
       checksum_sha256, min_sprout_version, signature, revoked
  FROM saas.fleet_versions
 WHERE version = ?
 ORDER BY os, arch, package_type`

func (s SQL) ReleaseRows(ctx context.Context, version string) ([]Row, error) {
	rows, err := s.db.WithContext(ctx).Raw(releaseRowsQuery, version).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Row
	for rows.Next() {
		var r Row
		m := &r.Manifest
		if err := rows.Scan(&m.Version, &m.OS, &m.Arch, &r.PackageType, &m.FileName,
			&m.ChecksumSHA256, &m.MinSproutVersion, &m.Signature, &r.Revoked); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

var (
	mu      sync.RWMutex
	current Catalog
)

// Install makes c the catalog farmer's readers use (nil uninstalls it).
// internal/api/handlers.SetReadinessDB, the one place farmer hands over
// its PXC handle, installs New over it.
func Install(c Catalog) {
	mu.Lock()
	current = c
	mu.Unlock()
}

// Current returns the installed catalog, or nil.
func Current() Catalog {
	mu.RLock()
	defer mu.RUnlock()
	return current
}
