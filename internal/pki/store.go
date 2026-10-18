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
	"slices"
	"sync/atomic"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/yogzblr/imas/internal/auth"
	"github.com/yogzblr/imas/internal/config"
)

// nkeyRow is the `pki_nkeys` table in the farmer schema. SproutID is part
// of the primary key (not just NKey), so a given sprout ID can hold
// exactly one lifecycle state at a time per tenant — the file-based store
// only enforced that by convention (each Accept/Deny/Reject/Unaccept call
// only ever wrote to one state directory), this makes it structural.
//
// An NKey is held by at most one sprout ID per tenant: (tenant_id, nkey)
// is unique (idx_pki_nkeys_tenant_nkey, migration farmer 00006; security
// review 2026-10, I7), so a lookup by NKey within a tenant has one
// answer. The nkey index alone (idx_pki_nkeys_n_key) serves the one
// lookup that searches every tenant (SproutIDAndTenantForNKey).
type nkeyRow struct {
	TenantID string `gorm:"column:tenant_id;primaryKey;size:191;uniqueIndex:idx_pki_nkeys_tenant_nkey,priority:1"`
	SproutID string `gorm:"column:sprout_id;primaryKey;size:253"`
	NKey     string `gorm:"column:nkey;size:191;not null;index;uniqueIndex:idx_pki_nkeys_tenant_nkey,priority:2"`
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

// revokedNKeyRow is the `pki_revoked_nkeys` table: every sprout NKey a
// tenant has revoked for good by deleting or replacing its sprout
// (retireSproutTx). FLAG FOR SECURITY REVIEW (security review 2026-10,
// H1). Account revocations used to be rebuilt only from pki_nkeys rows in
// unaccepted, denied or rejected, so a deleted row was never revoked and
// its User JWT, which has no exp, stayed valid. This list remembers what
// pki_nkeys no longer holds; every Account rebuild applies it
// (applyRevokedNKeys), and nothing ever removes a row or accepts its NKey
// again.
//
// Keyed on (tenant_id, nkey): a revocation is of a public key on one
// tenant's Account, whichever sprout ID it was under. sprout_id records
// that ID, and its (tenant_id, sprout_id) index serves lookups by sprout;
// it is never queried without tenant_id. revoked_at (Unix seconds) is the
// revocation's time on the Account: User JWTs for the key issued at or
// before it are refused.
type revokedNKeyRow struct {
	TenantID  string `gorm:"column:tenant_id;primaryKey;size:191;index:idx_pki_revoked_nkeys_sprout,priority:1"`
	NKey      string `gorm:"column:nkey;primaryKey;size:191"`
	SproutID  string `gorm:"column:sprout_id;size:253;not null;index:idx_pki_revoked_nkeys_sprout,priority:2"`
	RevokedAt int64  `gorm:"column:revoked_at;not null"`
}

func (revokedNKeyRow) TableName() string { return "pki_revoked_nkeys" }

// Models returns the GORM models this package owns, for callers assembling
// a single AutoMigrate call across the whole farmer schema (see
// cmd/farmer/main.go and internal/pxc). sproutBoxKeyRow is workstream J's
// (boxkeys.go); tenantRow is this workstream's; revokedNKeyRow is SEC.3a's.
// The schema itself comes from internal/migrations' farmer set, whose
// tests check it against these models.
//
// internal/auth's users and CLI box key tables (J.1) are listed here too:
// pki already imports auth, and listing them here is what puts them in
// internal/pxc's Models, which farmer's tests and the migration parity
// test use. SetDB installs auth's handle for the same reason.
func Models() []any {
	return append([]any{&nkeyRow{}, &tenantRow{}, &sproutBoxKeyRow{}, &revokedNKeyRow{}}, auth.Models()...)
}

// db is the shared farmer-schema GORM handle. Nil until SetDB is called.
var db *gorm.DB

// SetDB installs the GORM handle this package reads and writes through,
// and internal/auth's users and CLI box key stores (see Models). Call once
// at startup, after internal/pxc.OpenDB.
func SetDB(d *gorm.DB) {
	db = d
	auth.SetDB(d)
	// A CLI box key imported from farmer's config (the first admin's) gets
	// the same cross-principal check as one registered through the API.
	if d == nil {
		auth.SetBoxKeyClaimCheck(nil)
	} else {
		auth.SetBoxKeyClaimCheck(checkBoxPubUnclaimed)
	}
}

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
// place if a row for (tenant, sproutID) already exists (upsertNKeyRowTx).
func upsertNKeyRow(row nkeyRow) error {
	return db.Transaction(func(tx *gorm.DB) error { return upsertNKeyRowTx(tx, row) })
}

// upsertNKeyRowTx is upsertNKeyRow inside tx. It never writes over another
// sprout's row: an NKey the tenant already holds under another sprout ID
// is refused (errNKeyAmbiguous), as is any write the (tenant_id, nkey)
// index refuses. It is not an INSERT ... ON DUPLICATE KEY UPDATE: MySQL
// applies that update on a conflict with any unique key, so a second
// sprout ID for an NKey would have rewritten the first sprout's row.
func upsertNKeyRowTx(tx *gorm.DB, row nkeyRow) error {
	var held []nkeyRow
	if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("tenant_id = ? AND (sprout_id = ? OR nkey = ?)", row.TenantID, row.SproutID, row.NKey).
		Find(&held).Error; err != nil {
		return err
	}
	exists := false
	for _, h := range held {
		switch {
		case h.SproutID == row.SproutID:
			exists = true
		case h.NKey == row.NKey:
			return fmt.Errorf("pki: tenant %q sprout %q: %w (sprout %q)", row.TenantID, row.SproutID, errNKeyAmbiguous, h.SproutID)
		}
	}
	if exists {
		return tx.Model(&nkeyRow{}).Where("tenant_id = ? AND sprout_id = ?", row.TenantID, row.SproutID).
			Updates(map[string]any{"nkey": row.NKey, "state": row.State}).Error
	}
	return tx.Create(&row).Error
}

// retireSproutTx ends sprout id's credentials in tenantID inside tx, for
// DeleteNKey and AcceptNKey's replace path: it puts the sprout's NKey on
// the tenant's revoked list (unless it is keep, the NKey taking the ID
// over on the replace path), deletes its pki_nkeys row, and revokes every
// one of its box keys. found reports whether a pki_nkeys row existed; the
// box keys are revoked either way. The Account JWT carrying the
// revocation is pushed by the caller's reload, after the commit.
func retireSproutTx(tx *gorm.DB, tenantID, id, keep string) (found bool, err error) {
	var rows []nkeyRow
	if err := tx.Where("tenant_id = ? AND sprout_id = ?", tenantID, id).Find(&rows).Error; err != nil {
		return false, err
	}
	now := time.Now().Unix()
	for _, r := range rows {
		if r.NKey == "" || r.NKey == keep {
			continue
		}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&revokedNKeyRow{
			TenantID: tenantID, NKey: r.NKey, SproutID: id, RevokedAt: now,
		}).Error; err != nil {
			return false, fmt.Errorf("pki: revoking NKey of sprout %q in tenant %q: %w", id, tenantID, err)
		}
	}
	if len(rows) > 0 {
		if err := tx.Where("tenant_id = ? AND sprout_id = ?", tenantID, id).Delete(&nkeyRow{}).Error; err != nil {
			return false, err
		}
	}
	if err := revokeSproutBoxKeysTx(tx, tenantID, id); err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

// isNKeyRevoked reports whether nkey is on tenantID's revoked list.
func isNKeyRevoked(tenantID, nkey string) (bool, error) {
	var n int64
	if err := db.Model(&revokedNKeyRow{}).Where("tenant_id = ? AND nkey = ?", tenantID, nkey).Count(&n).Error; err != nil {
		return false, fmt.Errorf("pki: checking whether an NKey is revoked in tenant %q: %w", tenantID, err)
	}
	return n > 0, nil
}

// revokedNKeys returns tenantID's revoked list as NKey -> revoked_at.
func revokedNKeys(tenantID string) (map[string]int64, error) {
	var rows []revokedNKeyRow
	if err := db.Where("tenant_id = ?", tenantID).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("pki: reading tenant %q's revoked NKeys: %w", tenantID, err)
	}
	out := make(map[string]int64, len(rows))
	for _, r := range rows {
		if r.TenantID == tenantID {
			out[r.NKey] = r.RevokedAt
		}
	}
	return out, nil
}

func setStateInTenant(tenantID, id, state string) error {
	err := db.Model(&nkeyRow{}).
		Where("tenant_id = ? AND sprout_id = ?", tenantID, id).
		Update("state", state).Error
	if err == nil && state != stateAccepted {
		notifySproutLeftAccepted(tenantID, id)
	}
	return err
}

// sproutLeftAcceptedHook is the single subscriber OnSproutLeftAccepted
// installs.
var sproutLeftAcceptedHook atomic.Pointer[func(tenantID, sproutID string)]

// OnSproutLeftAccepted registers fn to be called, synchronously, after a
// sprout of a tenant has been moved out of the accepted state (DenyNKey,
// UnacceptNKey, RejectNKey) or deleted (DeleteNKey). cmd/farmer uses it to
// drop internal/heartbeat's Valkey acceptance marker and presence key at
// once, without internal/pki depending on internal/heartbeat (which imports
// this package). Like OnTenantProvisioned/OnTenantDeprovisioned it keeps
// only the most recently registered callback; nil removes it. fn must not
// block for long: it runs inside the state change.
func OnSproutLeftAccepted(fn func(tenantID, sproutID string)) {
	if fn == nil {
		sproutLeftAcceptedHook.Store(nil)
		return
	}
	sproutLeftAcceptedHook.Store(&fn)
}

func notifySproutLeftAccepted(tenantID, sproutID string) {
	if p := sproutLeftAcceptedHook.Load(); p != nil {
		(*p)(tenantID, sproutID)
	}
}

// SproutIDForNKey looks up the accepted sprout ID owning nkey within
// tenantID. Used by internal/heartbeat to map a NATS connection's
// authenticated pubkey (see $SYS.ACCOUNT.*.CONNECT/DISCONNECT's
// ClientInfo.User) back to a sprout ID, once the event's own ClientInfo.Account
// has been reverse-mapped to a real tenantID via TenantIDForAccountPub.
//
// A database error is returned wrapped, never disguised as
// ErrSproutIDNotFound (I7).
func SproutIDForNKey(tenantID, nkey string) (string, error) {
	row, err := findNKeyRowByNKeyInTenant(tenantID, nkey)
	if err != nil {
		return "", err
	}
	if row.State != stateAccepted {
		return "", ErrSproutIDNotFound
	}
	return row.SproutID, nil
}

// findNKeyRowByNKeyInTenant returns tenantID's pki_nkeys row for nkey, in
// whatever state, keyed on (tenant_id, nkey) (unique: see nkeyRow). No row
// is ErrSproutIDNotFound; a database error is returned wrapped. The
// comparison after the query is deliberate, as in VerifySproutInTenant:
// PXC's default collations compare strings case-insensitively.
func findNKeyRowByNKeyInTenant(tenantID, nkey string) (*nkeyRow, error) {
	if db == nil {
		return nil, errNoStore
	}
	var rows []nkeyRow
	if err := db.Where("tenant_id = ? AND nkey = ?", tenantID, nkey).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("pki: looking up an NKey in tenant %q: %w", tenantID, err)
	}
	rows = slices.DeleteFunc(rows, func(r nkeyRow) bool { return r.TenantID != tenantID || r.NKey != nkey })
	switch len(rows) {
	case 0:
		return nil, ErrSproutIDNotFound
	case 1:
		return &rows[0], nil
	}
	return nil, fmt.Errorf("pki: tenant %q: %w", tenantID, errNKeyAmbiguous)
}

// errNKeyAmbiguous is a lookup by NKey that matched more than one row. It
// is refused, never resolved by picking one.
var errNKeyAmbiguous = errors.New("pki: the NKey is held by more than one sprout")

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
// that's required here rather than a gap. Its callers (the enrollment
// replay and the sealed refresh) have only the NKey: no tenant is known
// before this answers. Where a tenant is known, the lookup is keyed on
// (tenant_id, nkey) instead (findNKeyRowByNKeyInTenant).
//
// It fails closed (security review 2026-10, L10 and I7):
//   - no accepted row is ErrSproutIDNotFound, and only that;
//   - a database error is returned wrapped, never as not-found, so the
//     enrollment path doesn't go on to spend a join-token use;
//   - accepted rows in more than one tenant are refused (errNKeyAmbiguous),
//     never resolved by picking one;
//   - a deprovisioned tenant is ErrTenantDeprovisioned
//     (refuseDeprovisionedTenant), as is a failed check of it.
func SproutIDAndTenantForNKey(nkey string) (tenantID, sproutID string, err error) {
	if db == nil {
		return "", "", errNoStore
	}
	var rows []nkeyRow
	if err := db.Where("nkey = ? AND state = ?", nkey, stateAccepted).Find(&rows).Error; err != nil {
		return "", "", fmt.Errorf("pki: looking up the accepted sprout of an NKey: %w", err)
	}
	rows = slices.DeleteFunc(rows, func(r nkeyRow) bool { return r.NKey != nkey || r.State != stateAccepted })
	switch len(rows) {
	case 0:
		return "", "", ErrSproutIDNotFound
	case 1:
	default:
		return "", "", errNKeyAmbiguous
	}
	if err := refuseDeprovisionedTenant(rows[0].TenantID); err != nil {
		return "", "", err
	}
	return rows[0].TenantID, rows[0].SproutID, nil
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
// (internal.sprout.action, imas-machine-manager-api-design.md §2.2):
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
		if trow.Deleted && trow.ID == tenantID {
			noteDeprovisionedTenant(tenantID) // L11: a fresh lock-out
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

// listDeletedTenantIDs returns every deprovisioned tenant ID in
// pki_tenants, tombstones included (PushAllAccounts skips those that never
// had an Account).
func listDeletedTenantIDs() ([]string, error) {
	var rows []tenantRow
	if err := db.Where("deleted = ?", true).Find(&rows).Error; err != nil {
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
