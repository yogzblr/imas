// Package props: PXC-backed storage.
//
// Previously props lived in a package-level in-memory map
// (propCache), write-through to one JSON file per sprout on local disk.
// Neither survived a second farmer replica: each replica had its own
// process-local propCache and its own local JSON files, so a SetProp on
// replica A was invisible to a GetProp answered by replica B — the
// cross-replica divergence bug named in docs/design/imas-fork-roadmap.md
// workstream A. This file (plus props.go/static.go) now reads and writes
// straight through to the shared `farmer` schema in PXC on every call, with
// no in-memory cache layered on top, so every replica sees the same state.
//
// tenant_id scoping (workstream A.1, FLAG FOR SECURITY REVIEW): every
// query in this package includes tenant_id in the same WHERE clause as
// sprout_id/name. Full per-request tenant identity (NATS Accounts,
// workstream E) doesn't exist yet, so tenantID() resolves to this farmer
// deployment's own configured tenant (config.FarmerOrganization — the same
// value that already names its NATS Account, see internal/pki/jwtauth.go)
// until per-request tenant context lands.
package props

import (
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/yogzblr/imas/internal/config"
)

// propRow is the `props` table in the farmer schema.
type propRow struct {
	TenantID string    `gorm:"column:tenant_id;primaryKey;size:191"`
	SproutID string    `gorm:"column:sprout_id;primaryKey;size:253"`
	Name     string    `gorm:"column:name;primaryKey;size:191"`
	Value    string    `gorm:"column:value;type:text"`
	Static   bool      `gorm:"column:static;not null;default:false"`
	Expiry   time.Time `gorm:"column:expiry;not null;index"`
}

func (propRow) TableName() string { return "props" }

// Models returns the GORM models this package owns, for callers assembling
// a single AutoMigrate call across the whole farmer schema (see
// cmd/farmer/main.go and internal/pxc).
func Models() []any { return []any{&propRow{}} }

// db is the shared farmer-schema GORM handle. Nil until SetDB is called.
var db *gorm.DB

// SetDB installs the GORM handle this package reads and writes through.
// Call once at startup, after internal/pxc.OpenDB.
func SetDB(d *gorm.DB) { db = d }

// tenantID resolves the current tenant scope for callers with no better
// source today (internal/natsapi's single shared connection,
// boot/SIGHUP-time static-prop loading) — see the package doc comment
// above and docs/design/imas-tenant-context-threading.md.
func tenantID() string {
	if config.FarmerOrganization != "" {
		return config.FarmerOrganization
	}
	return "default"
}

// CurrentTenantID exports tenantID for callers outside this package that
// need it explicitly rather than have it read implicitly — see tenantID's
// doc comment.
func CurrentTenantID() string { return tenantID() }

func upsertProp(row propRow) error {
	return db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "sprout_id"}, {Name: "name"}},
		DoUpdates: clause.AssignmentColumns([]string{"value", "static", "expiry"}),
	}).Create(&row).Error
}
