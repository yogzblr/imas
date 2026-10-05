package pki

import (
	"errors"
	"fmt"

	"gorm.io/gorm"
)

// errNoStore is VerifyGatewaySubject's answer when SetDB was never
// called: a "couldn't check", never a pass.
var errNoStore = errors.New("pki: no farmer database configured")

// VerifyGatewaySubject is farmer's revocation check for a gateway JWT
// (SEC.7c, security review 2026-10-b B3). FLAG FOR SECURITY REVIEW.
// Verifying a gateway JWT's signature, issuer and expiry
// (gatewayjwt.VerifyGatewayJWT) says nothing about whether the sprout
// it names still holds that identity: DeleteNKey and AcceptNKey's
// replace path revoke the NATS User JWT and box keys of the retired
// host, but a gateway JWT minted before then stays valid for
// config.GatewayJWTTTL. This is the check that ends it.
//
// It returns nil only if all of these hold, every lookup keyed on
// tenantID together with nkey or sproutID:
//   - nkey is not on tenantID's revoked list (pki_revoked_nkeys);
//   - tenantID is live: the legacy current-tenant seam, or a
//     non-deleted pki_tenants row;
//   - (tenantID, sproutID) is an accepted pki_nkeys row whose NKey is
//     exactly nkey. After a replace that row holds the new host's NKey,
//     so the old host's token, with the old NKey as sub, fails here even
//     before its revocation is consulted.
//
// Every "no" is ErrNKeyRevoked, ErrSproutIDNotFound or ErrTenantNotFound
// (or the ID validation errors). A database error, or no database at
// all, is returned wrapped and never disguised as not-found, so a caller
// can log "couldn't check" apart from "refused" — and must refuse either
// way.
//
// The row comparisons after each query are deliberate, as in
// VerifySproutInTenant: PXC's default collations compare strings
// case-insensitively, and an NKey must match byte for byte.
func VerifyGatewaySubject(tenantID, sproutID, nkey string) error {
	if !IsValidTenantID(tenantID) {
		return ErrTenantIDInvalid
	}
	if !IsValidSproutID(sproutID) {
		return ErrSproutIDInvalid
	}
	if nkey == "" {
		return ErrSproutIDNotFound
	}
	if db == nil {
		return errNoStore
	}

	revoked, err := isNKeyRevoked(tenantID, nkey)
	if err != nil {
		return err
	}
	if revoked {
		return ErrNKeyRevoked
	}

	// The legacy tenant has no pki_tenants row (see
	// ListProvisionedTenantIDs); every other tenant must have a live one.
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
	if row.TenantID != tenantID || row.SproutID != sproutID || row.State != stateAccepted || row.NKey != nkey {
		return ErrSproutIDNotFound
	}
	return nil
}
