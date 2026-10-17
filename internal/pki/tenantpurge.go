package pki

// Erasing an offboarded tenant's farmer-side data (S6,
// docs/briefs/S6-tenant-erasure.md): the guards, the farmer-schema rows,
// the sprout JWT bucket prefix, the tombstone's own data and, last, the
// tenant's Transit keys. internal/natsapi's tenant_purge.go runs these in
// order for internal.tenant.purge. FLAG FOR SECURITY REVIEW: these delete
// a tenant's trust material and state for good.
//
// What stays is the tombstone: the pki_tenants row, deleted, with its
// name replaced by the ID, and the tenant's Account JWT in the accounts
// bucket, re-signed locked out from nothing but its public key and the ID.
// Together they refuse any later provision or enrolment for the ID and
// keep the tenant off the bus, on every replica and on a bus node started
// empty, without the tenant's name, signing key or sprout keys.

import (
	"context"
	"errors"
	"fmt"
	"time"

	jwt "github.com/nats-io/jwt/v2"

	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/tenantpurge"
)

// ErrTenantPurgeRefused is a purge farmer refuses before deleting
// anything (S6 decision 5): the legacy current tenant, a tenant with no
// pki_tenants row, or one not marked deleted. An invalid tenant ID is
// ErrTenantIDInvalid.
var ErrTenantPurgeRefused = errors.New("pki: tenant purge refused")

// CheckTenantPurgeable is the purge's guard: tenantID is a valid tenant
// ID, it is not the legacy current tenant (config.FarmerOrganization,
// whose keys sign farmer's own legacy Account), and its pki_tenants row
// exists and is marked deleted, which only a deprovision does. A database
// error is returned as is, never as a refusal.
func CheckTenantPurgeable(tenantID string) error {
	if !IsValidTenantID(tenantID) {
		return ErrTenantIDInvalid
	}
	if tenantID == currentTenantID() {
		return fmt.Errorf("%w: %q is the legacy current tenant", ErrTenantPurgeRefused, tenantID)
	}
	if db == nil {
		return errors.New("pki: no database configured")
	}
	row, err := getTenantRow(tenantID)
	if errors.Is(err, ErrTenantNotFound) {
		return fmt.Errorf("%w: tenant %q has no pki_tenants row", ErrTenantPurgeRefused, tenantID)
	}
	if err != nil {
		return err
	}
	if !row.Deleted {
		return fmt.Errorf("%w: tenant %q is not deprovisioned", ErrTenantPurgeRefused, tenantID)
	}
	return nil
}

// PurgeTenantRows deletes tenantID's rows from every farmer-schema table
// of tenantpurge.FarmerTables, in bounded batches, and returns the count
// per table ("db.<table>"). It stops at the first table that fails,
// returning the counts so far; run again, it finishes. The caller has
// checked CheckTenantPurgeable.
func PurgeTenantRows(ctx context.Context, tenantID string, batch int) (map[string]int64, error) {
	counts := map[string]int64{}
	for _, table := range tenantpurge.FarmerTables {
		n, err := tenantpurge.DeleteRows(ctx, db, table, tenantID, batch)
		counts["db."+table] = n
		if err != nil {
			return counts, err
		}
	}
	return counts, nil
}

// sproutJWTPurgeObjects is the sprout JWT bucket as a purge needs it.
type sproutJWTPurgeObjects interface {
	sproutJWTObjects
	tenantpurge.Objects
}

// PurgeTenantSproutJWTs deletes every object under tenantID/ in the
// private sprout JWT bucket (IMAS_S3_SPROUT_JWT_BUCKET) and returns how
// many. The caller has checked CheckTenantPurgeable.
func PurgeTenantSproutJWTs(ctx context.Context, tenantID string, batch int) (int64, error) {
	objs, err := sproutJWTBucket()
	if err != nil {
		return 0, err
	}
	p, ok := objs.(sproutJWTPurgeObjects)
	if !ok {
		return 0, errors.New("pki: the sprout JWT bucket can't list or delete")
	}
	return tenantpurge.DeleteObjects(ctx, p, tenantID+"/", tenantID, batch)
}

// ScrubTenantTombstone reduces tenantID's tombstone to what keeps it
// locked out: its pki_tenants row's name becomes the ID, and its Account
// JWT is re-signed locked out from minimal claims (its public key, the ID
// as its name, no signing keys, no per-key revocations) and pushed, which
// writes the accounts bucket first. A tenant that never had an Account
// has no JWT to re-sign. Idempotent: run again, it pushes a newer copy of
// the same lock-out. It re-checks CheckTenantPurgeable itself.
func ScrubTenantTombstone(ctx context.Context, tenantID string) error {
	if err := CheckTenantPurgeable(tenantID); err != nil {
		return err
	}
	mat, err := ensureNatsAuth()
	if err != nil {
		return err
	}
	signed, err := scrubTombstoneLocked(ctx, mat, tenantID)
	if err != nil || signed == "" {
		return err
	}
	if err := pushAccountUpdate(mat, signed); err != nil {
		return fmt.Errorf("pki: pushing tenant %q's minimal lock-out: %w", tenantID, err)
	}
	log.Infof("Tenant %q's tombstone scrubbed: minimal locked-out Account JWT pushed to the bus resolver.", tenantID)
	return nil
}

// scrubTombstoneLocked is ScrubTenantTombstone's tenantAuthMu-guarded
// body: it renames the row and signs (and holds) the minimal lock-out,
// leaving the push to the caller. "" means there is no Account to sign.
func scrubTombstoneLocked(ctx context.Context, mat *natsAuthMaterial, tenantID string) (string, error) {
	tenantAuthMu.Lock()
	defer tenantAuthMu.Unlock()

	if err := db.WithContext(ctx).Model(&tenantRow{}).Where("id = ? AND deleted = ?", tenantID, true).
		Update("name", tenantID).Error; err != nil {
		return "", fmt.Errorf("pki: clearing tenant %q's name: %w", tenantID, err)
	}
	row, err := getTenantRow(tenantID)
	if err != nil {
		return "", err
	}
	if !row.Deleted {
		return "", fmt.Errorf("%w: tenant %q is not deprovisioned", ErrTenantPurgeRefused, tenantID)
	}
	if row.AccountPub == "" {
		return "", nil
	}
	// The minimal lock-out must outrank whatever the bus and the bucket
	// hold: a later issued-at than the newest copy (accountrank.Better).
	var prevIAT int64
	if base, _, err := latestAccountJWT(ctx, row.AccountPub, func(*jwt.AccountClaims) bool { return true }); err != nil {
		return "", err
	} else if base != "" {
		if ac, err := jwt.DecodeAccountClaims(base); err == nil {
			prevIAT = ac.IssuedAt
		}
	}
	ac := jwt.NewAccountClaims(row.AccountPub)
	ac.Name = tenantID
	waitPastIssuedAt(prevIAT)
	lockOutAccount(ac, time.Now())
	signed, err := ac.Encode(mat.operatorSigningKP)
	if err != nil {
		return "", fmt.Errorf("pki: signing tenant %q's minimal lock-out: %w", tenantID, err)
	}
	if err := holdAccountJWT(signed, false); err != nil {
		return "", err
	}
	return signed, nil
}

// DestroyTenantKeys permanently deletes tenantID's two Transit keys
// (nats-tsign-<tenant_id>, nats-tacct-<tenant_id>), retired or not, and
// returns how many it deleted. A key already gone is success, and not
// counted. Never the legacy current tenant's (CheckTenantPurgeable is
// re-checked). The purge runs this last: nothing it leaves needs them, as
// the tombstone's lock-out is signed by the operator signing key.
func DestroyTenantKeys(ctx context.Context, tenantID string) (int64, error) {
	if err := CheckTenantPurgeable(tenantID); err != nil {
		return 0, err
	}
	var n int64
	for _, role := range []natsKeyRole{natsKeyTenantSigning, natsKeyTenantAccount} {
		destroyed, err := natsKeys.destroyKey(ctx, natsKeyRef{role: role, tenantID: tenantID})
		if err != nil {
			return n, err
		}
		if destroyed {
			n++
		}
	}
	return n, nil
}
