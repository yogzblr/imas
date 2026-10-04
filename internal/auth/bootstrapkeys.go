package auth

// The first admin's CLI box key (owner decision 2026-10-04, PR 93): the
// first admin is registered out of band in farmer's config file, and so is
// their CLI box key, as a boxpub field beside the user's entry:
//
//	users:
//	  admin:
//	    - pubkey: AABC...
//	      username: alice
//	      boxpub: <standard base64 X25519 public key>
//
// FLAG FOR SECURITY REVIEW. LoadPolicy imports each such key once, into
// auth_cli_box_keys under (usersTenantID(), user ID): the deployment-wide
// policy's tenant, the one CLI operators work in (the CLI is for
// operators only, owner decision 2026-10-04). "Once" means only while the
// user has no CLI box key history at all in that tenant: from then on the
// database is authoritative, so a boxpub in the config file never
// overwrites a key the user rotated to, never brings back a retired or
// revoked key, and never adds a second one. A boxpub that differs from the
// active key is logged and ignored. Replicas starting together are fine:
// the schema allows one row per (tenant, user, pub) and one active key,
// so the loser of a race finds the same key active.
//
// An import that fails (a malformed or weak key, one some principal
// already holds, a database error) is logged and skipped; it never stops
// farmer starting. The user then has no box key and can't make sealed
// requests until it's fixed.

import (
	"errors"

	"github.com/taigrr/jety"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/log"
)

// BoxPubConfigField is the config field naming a user's CLI box key.
const BoxPubConfigField = "boxpub"

// boxKeyClaimCheck refuses a box public key some other principal holds or
// that is a farmer-side key (internal/pki's checkBoxPubUnclaimed, which
// pki installs from its SetDB: auth can't import pki). nil checks only the
// CLI key table's own uniqueness.
var boxKeyClaimCheck func(tenantID, pub string) error

// SetBoxKeyClaimCheck installs the cross-principal check bootstrap
// imports run before registering a key.
func SetBoxKeyClaimCheck(f func(tenantID, pub string) error) { boxKeyClaimCheck = f }

// configBoxPubs returns user ID -> boxpub for every rich-format entry in
// the config file's users section that has one. The legacy pubkeys section
// holds bare keys only, so it has none.
func configBoxPubs() map[string]string {
	out := map[string]string{}
	for _, v := range jety.GetStringMap("users") {
		items, ok := v.([]any)
		if !ok {
			continue
		}
		for _, it := range items {
			m, ok := it.(map[string]any)
			if !ok {
				continue
			}
			pk, _ := m["pubkey"].(string)
			bp, _ := m[BoxPubConfigField].(string)
			if pk != "" && bp != "" {
				out[pk] = bp
			}
		}
	}
	return out
}

// importConfigCLIBoxKeys imports configBoxPubs (see the file comment).
func importConfigCLIBoxKeys() {
	if db == nil {
		return
	}
	tenantID := usersTenantID()
	for userID, pub := range configBoxPubs() {
		if err := importConfigCLIBoxKey(tenantID, userID, pub); err != nil {
			log.Errorf("auth: not importing the config file's %s for user %s: %v", BoxPubConfigField, userID, err)
		}
	}
}

func importConfigCLIBoxKey(tenantID, userID, pub string) error {
	var n int64
	if err := db.Model(&cliBoxKeyRow{}).Where("tenant_id = ? AND user_id = ?", tenantID, userID).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		// Imported before, or registered or rotated since: the database
		// is authoritative.
		if active, _, err := ValidCLIBoxKeys(tenantID, userID); err != nil || active != pub {
			log.Warnf("auth: user %s's %s in farmer's config is not their active CLI box key; ignoring it (the database is authoritative once a key is registered)", userID, BoxPubConfigField)
		}
		return nil
	}
	if _, err := DecodeCLIBoxPub(pub); err != nil {
		return err
	}
	if boxKeyClaimCheck != nil {
		if err := boxKeyClaimCheck(tenantID, pub); err != nil {
			return err
		}
	}
	err := db.Transaction(func(tx *gorm.DB) error { return registerCLIBoxKeyTx(tx, tenantID, userID, pub) })
	if err == nil {
		log.Noticef("auth: imported user %s's CLI box key from farmer's config", userID)
		return nil
	}
	// Another replica starting at the same time may have imported it.
	if active, _, verr := ValidCLIBoxKeys(tenantID, userID); verr == nil && active == pub &&
		(errors.Is(err, ErrCLIBoxKeyInUse) || isDuplicate(err)) {
		return nil
	}
	return err
}
