package pki

// PXC-backed storage for sprout NKey lifecycle state (unaccepted / denied /
// rejected / accepted). Previously each state was a directory under
// config.FarmerPKI/sprouts/<state>/<sproutID>, with the file's content
// holding the raw NKey and its directory holding the sprout's current
// state — so an Accept/Deny/Reject/Unaccept call was an os.Rename, visible
// only to whichever farmer replica had that directory on local disk. That's
// the same cross-replica divergence class as props/store.go (see
// docs/design/imas-fork-roadmap.md workstream A): a sprout accepted on one
// replica could still show up as unaccepted to a request served by
// another. This file reads and writes straight through to the shared
// `farmer` schema in PXC on every call, so every replica agrees on a given
// sprout's state.
//
// tenant_id scoping (workstream A.1, FLAG FOR SECURITY REVIEW): every
// query here includes tenant_id in the same WHERE clause as sprout_id,
// following the same tenantID() seam as internal/props (see its store.go
// doc comment for why this resolves to config.FarmerOrganization rather
// than a per-request value today).

import (
	"errors"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/yogzblr/imas/internal/config"
)

// nkeyRow is the `pki_nkeys` table in the farmer schema. SproutID is part
// of the primary key (not just NKey), so a given sprout ID can hold
// exactly one lifecycle state at a time per tenant — the file-based store
// only enforced that by convention (each Accept/Deny/Reject/Unaccept call
// only ever wrote to one state directory), this makes it structural.
type nkeyRow struct {
	TenantID string `gorm:"column:tenant_id;primaryKey;size:191"`
	SproutID string `gorm:"column:sprout_id;primaryKey;size:253"`
	NKey     string `gorm:"column:nkey;size:191;not null;index"`
	State    string `gorm:"column:state;size:32;not null;index"`
}

func (nkeyRow) TableName() string { return "pki_nkeys" }

const (
	stateUnaccepted = "unaccepted"
	stateAccepted   = "accepted"
	stateDenied     = "denied"
	stateRejected   = "rejected"
)

// tenantRow is the `pki_tenants` table: the durable, replica-shared record
// of which tenants this farmer has provisioned a NATS Account for (see
// tenant.go's ProvisionTenant/DeprovisionTenant). This is what makes
// "FarmerOrganization" dynamic per workstream E — previously the only
// tenant Account this farmer would ever mint was the single one named by
// the static config.FarmerOrganization string, decided once at boot. A row
// here means "the Account exists and, unless Deleted, the bus resolver
// should trust it" — see ConfigureNats (nats.go), which seeds the resolver
// from every non-deleted row here in addition to the legacy single-tenant
// seam's own Account.
// AccountPub is the tenant's NATS Account public key (tenantAccountMaterial.pub
// in tenant.go), filled in once that Account material is first minted. It
// backs TenantIDForAccountPub's reverse lookup — see that function's doc
// comment for why this exists: an Account pubkey is a different identifier
// space than the tenant ID string used everywhere else, and nothing else in
// this schema records the mapping between them.
type tenantRow struct {
	ID         string `gorm:"column:id;primaryKey;size:191"`
	Name       string `gorm:"column:name;size:255;not null"`
	Deleted    bool   `gorm:"column:deleted;not null;default:false;index"`
	CreatedAt  int64  `gorm:"column:created_at;not null"`
	AccountPub string `gorm:"column:account_pub;size:64;index"`
}

func (tenantRow) TableName() string { return "pki_tenants" }

// Models returns the GORM models this package owns, for callers assembling
// a single AutoMigrate call across the whole farmer schema (see
// cmd/farmer/main.go and internal/pxc). sproutBoxKeyRow is workstream J's
// (boxkeys.go); tenantRow is this workstream's.
func Models() []any { return []any{&nkeyRow{}, &tenantRow{}, &sproutBoxKeyRow{}} }

// db is the shared farmer-schema GORM handle. Nil until SetDB is called.
var db *gorm.DB

// SetDB installs the GORM handle this package reads and writes through.
// Call once at startup, after internal/pxc.OpenDB.
func SetDB(d *gorm.DB) { db = d }

// tenantID resolves the current tenant scope for the handful of genuinely
// process-level, boot/SIGHUP-time contexts that still don't have a real
// per-request tenant to thread through (see ReloadNKeys/syncNatsAuth in
// nats.go/jwtusers.go, and tenant.go's own comparisons against "the legacy
// current tenant"). See docs/design/imas-tenant-context-threading.md for
// why every per-message/per-request call site in this package now takes an
// explicit tenantID parameter instead of calling this.
func tenantID() string {
	if config.FarmerOrganization != "" {
		return config.FarmerOrganization
	}
	return "default"
}

// CurrentTenantID exports tenantID for callers outside this package
// (internal/natsapi, internal/api/handlers) that dispatch over the single
// shared NATS connection/HTTP admin API today — see
// docs/design/imas-tenant-context-threading.md: until that connection is
// made genuinely multi-tenant, this legacy seam's value is the only tenant
// actually reachable, so it's the honest value for those callers to pass
// explicitly rather than have it read implicitly inside this package.
func CurrentTenantID() string { return tenantID() }

// currentTenantID is an alias for tenantID(), for callers in tenant.go
// that take an explicit tenant ID as a same-named parameter (shadowing the
// package-level tenantID function within that scope) but still need to
// compare against or fall back to the current-tenant seam's value.
func currentTenantID() string { return tenantID() }

// upsertNKeyRow inserts a new sprout NKey row, or updates its nkey/state in
// place if a row for (tenant, sproutID) already exists.
func upsertNKeyRow(row nkeyRow) error {
	return db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "sprout_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"nkey", "state"}),
	}).Create(&row).Error
}

func setStateInTenant(tenantID, id, state string) error {
	return db.Model(&nkeyRow{}).
		Where("tenant_id = ? AND sprout_id = ?", tenantID, id).
		Update("state", state).Error
}

// SproutIDForNKey looks up the accepted sprout ID owning nkey within
// tenantID. Used by internal/heartbeat to map a NATS connection's
// authenticated pubkey (see $SYS.ACCOUNT.*.CONNECT/DISCONNECT's
// ClientInfo.User) back to a sprout ID, once the event's own ClientInfo.Account
// has been reverse-mapped to a real tenantID via TenantIDForAccountPub.
func SproutIDForNKey(tenantID, nkey string) (string, error) {
	var row nkeyRow
	err := db.Where("tenant_id = ? AND nkey = ? AND state = ?", tenantID, nkey, stateAccepted).First(&row).Error
	if err != nil {
		return "", ErrSproutIDNotFound
	}
	return row.SproutID, nil
}

// SproutIDAndTenantForNKey looks up the accepted sprout ID and its owning
// tenant for nkey, searching across every tenant rather than just the
// current one. This backs Enroll's idempotency check (enroll.go): at that
// point in the enrollment flow the caller's tenant isn't known yet (that
// only comes from decoding the join token, the next step) but nkey_pub
// is — and since NKeys are 256-bit Ed25519 public keys a caller generates
// itself, a match here unambiguously identifies both the sprout and its
// tenant regardless of which tenant issued the join token this replay is
// skipping. FLAG FOR SECURITY REVIEW: this is the one nkey lookup in this
// package that's deliberately NOT tenant-scoped — see enroll.go for why
// that's required here rather than a gap.
func SproutIDAndTenantForNKey(nkey string) (tenantID, sproutID string, err error) {
	var row nkeyRow
	dbErr := db.Where("nkey = ? AND state = ?", nkey, stateAccepted).First(&row).Error
	if dbErr != nil {
		return "", "", ErrSproutIDNotFound
	}
	return row.TenantID, row.SproutID, nil
}

// findNKeyRowInTenant is findNKeyRow parameterized by an explicit tenant
// rather than the package's current-tenant seam — used by the enrollment
// path (enroll.go), which has a real per-request tenant (the enrollment
// key's own TenantID) available.
func findNKeyRowInTenant(tenantID, id string) (*nkeyRow, error) {
	if !IsValidSproutID(id) {
		return nil, ErrSproutIDInvalid
	}
	var row nkeyRow
	if err := db.Where("tenant_id = ? AND sprout_id = ?", tenantID, id).First(&row).Error; err != nil {
		return nil, ErrSproutIDNotFound
	}
	return &row, nil
}

// NKeyExistsInTenant is NKeyExists scoped to an explicit tenant instead of
// the package's current-tenant seam. See findNKeyRowInTenant.
func NKeyExistsInTenant(tenantID, id, nkey string) (registered bool, matches bool) {
	row, err := findNKeyRowInTenant(tenantID, id)
	if err != nil {
		return false, false
	}
	return true, row.NKey == nkey
}

// VerifySproutInTenant is farmer's point-of-effect tenant check for
// control-plane actions dispatched on a caller's say-so
// (internal.sprout.action, cloudxp-machine-manager-api-design.md §2.2):
// it returns nil only if sproutID is an *accepted* sprout whose own stored
// tenant_id is tenantID, and tenantID is a live tenant (the legacy
// current-tenant seam, or a non-deleted pki_tenants row). FLAG FOR
// SECURITY REVIEW.
//
// Every "no" — absent row, a row in another state, a stored tenant_id
// that doesn't match, a deprovisioned tenant — is ErrSproutIDNotFound (or
// ErrTenantNotFound), never a distinguishable authorization error (§4).
// A database error is returned wrapped, never disguised as not-found, so
// a caller can tell "refused" from "couldn't check".
//
// The WHERE clause is already keyed on (tenant_id, sprout_id); the
// explicit comparison of the row's own tenant_id and sprout_id afterwards
// is deliberate, not redundant. PXC's default collations compare strings
// case-insensitively, so the query alone would match tenant "T_1"'s row
// for an asserted "t_1" — and the check must also survive a future edit
// that drops tenant_id from the query.
func VerifySproutInTenant(tenantID, sproutID string) error {
	if !IsValidTenantID(tenantID) {
		return ErrTenantIDInvalid
	}
	if !IsValidSproutID(sproutID) {
		return ErrSproutIDInvalid
	}
	// The legacy tenant has no pki_tenants row (see
	// ListProvisionedTenantIDs); every other tenant must have a live one.
	// Deprovisioning leaves a tenant's pki_nkeys rows in place, so the
	// sprout lookup below alone would still pass for a deleted tenant.
	if tenantID != currentTenantID() {
		trow, err := getTenantRow(tenantID)
		if err != nil {
			return err
		}
		if trow.Deleted || trow.ID != tenantID {
			return ErrTenantNotFound
		}
	}
	var row nkeyRow
	if err := db.Where("tenant_id = ? AND sprout_id = ?", tenantID, sproutID).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrSproutIDNotFound
		}
		return fmt.Errorf("pki: looking up sprout %q in tenant %q: %w", sproutID, tenantID, err)
	}
	if row.TenantID != tenantID || row.SproutID != sproutID || row.State != stateAccepted {
		return ErrSproutIDNotFound
	}
	return nil
}

// insertTenantRowIfAbsent inserts row unless a pki_tenants row with its ID
// already exists, which it leaves untouched, and reports whether it
// inserted. It never changes an existing row: an upsert that reset
// deleted could un-delete a tenant, or wipe the tombstone a concurrent
// DeprovisionTenant on another replica just wrote (see
// deprovisionTenantLocked). Callers re-read the row when nothing was
// inserted.
func insertTenantRowIfAbsent(row tenantRow) (bool, error) {
	res := db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoNothing: true,
	}).Create(&row)
	return res.RowsAffected > 0, res.Error
}

// markTenantDeleted flags a tenant as deprovisioned without removing its
// row — DeprovisionTenant (tenant.go) still needs it around afterward
// (e.g. to refuse re-provisioning silently resurrecting a deleted tenant
// under a stale Account signing key without an explicit re-provision).
func markTenantDeleted(id string) error {
	return db.Model(&tenantRow{}).Where("id = ?", id).Update("deleted", true).Error
}

// getTenantRow looks up a single tenant registry row by ID, including
// deleted ones (callers that care about Deleted check it themselves). It
// returns ErrTenantNotFound only when no row exists; any other database
// error is returned wrapped, never disguised as not-found — callers act on
// "not found" (ensureTenantAccountLocked creates the row; the SaaS API's
// deprovision path treats it as nothing to tear down), which would be
// wrong for a transient lookup failure.
func getTenantRow(id string) (*tenantRow, error) {
	var row tenantRow
	if err := db.Where("id = ?", id).First(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrTenantNotFound
		}
		return nil, fmt.Errorf("pki: looking up tenant %q: %w", id, err)
	}
	return &row, nil
}

// setTenantAccountPub records tenantID's NATS Account public key on its
// pki_tenants row, so TenantIDForAccountPub can reverse it later. Called
// from tenant.go once ensureTenantAccountMaterial has minted or loaded that
// tenant's Account keypair — idempotent, safe to call every time (a
// tenant's Account keypair never changes after it's first minted).
func setTenantAccountPub(id, accountPub string) error {
	return db.Model(&tenantRow{}).Where("id = ?", id).Update("account_pub", accountPub).Error
}

// TenantIDForAccountPub reverse-looks-up which tenant owns a NATS Account
// public key — the mapping internal/heartbeat needs to turn a
// $SYS.ACCOUNT.*.CONNECT/DISCONNECT event's ClientInfo.Account (the
// connecting Account's real pubkey; see docs/design/
// imas-tenant-context-threading.md) into a real tenant ID, instead of the
// process-global tenantID() seam. Handles both the legacy single-tenant
// Account (mat.tenantPub, which isn't itself a pki_tenants row) and every
// dynamically-provisioned tenant (tenant.go's tenantAccountMaterial.pub,
// recorded via setTenantAccountPub).
// GetTenantAccountPub returns tenantID's NATS Account public key, once
// provisioned (see ProvisionTenant) — the id -> pubkey direction of
// TenantIDForAccountPub's reverse lookup. Exported for tests (and any
// future caller) that need to know which Account pubkey a given tenant's
// connections actually authenticate under, e.g. to construct a realistic
// $SYS.ACCOUNT.*.CONNECT event for internal/heartbeat.
func GetTenantAccountPub(tenantID string) (string, error) {
	if tenantID == currentTenantID() {
		if mat, err := ensureNatsAuth(); err == nil {
			return mat.tenantPub, nil
		}
	}
	row, err := getTenantRow(tenantID)
	if err != nil || row.AccountPub == "" {
		return "", ErrTenantNotFound
	}
	return row.AccountPub, nil
}

// ListProvisionedTenantIDs returns every non-deleted tenant ID recorded in
// pki_tenants — every tenant besides the legacy one (CurrentTenantID(),
// which isn't itself a pki_tenants row) that cmd/farmer/main.go's
// ConnectFarmer needs its own dedicated NATS connection for at boot. See
// docs/design/imas-tenant-context-threading.md's Option A.
func ListProvisionedTenantIDs() ([]string, error) {
	var rows []tenantRow
	if err := db.Where("deleted = ?", false).Find(&rows).Error; err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	return ids, nil
}

func TenantIDForAccountPub(accountPub string) (string, error) {
	if accountPub == "" {
		return "", ErrTenantNotFound
	}
	if mat, err := ensureNatsAuth(); err == nil && mat.tenantPub == accountPub {
		return currentTenantID(), nil
	}
	var row tenantRow
	if err := db.Where("account_pub = ? AND deleted = ?", accountPub, false).First(&row).Error; err != nil {
		return "", ErrTenantNotFound
	}
	return row.ID, nil
}
