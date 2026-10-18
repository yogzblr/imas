package pki

// CLI admin keys on a tenant's Account (security review 2026-10, I6).
// FLAG FOR SECURITY REVIEW.
//
// syncNatsAuth grants every CLI admin NKey in farmer's config (the
// users.admin entries and the legacy pubkeys.admin list) on the tenant's
// Account (it clears any revocation of it). Nothing used to
// remember those grants, so a key taken out of the config kept them.
// pki_cli_admin_keys (farmer migration 00007) now records each key the
// rebuild grants, and the rebuild revokes a recorded key once it is no
// longer in the config as an admin and is no user at all, neither in the
// config as it reads now nor in the users store (auth.IsCurrentUser): the
// NKey goes on the tenant's revoked list (pki_revoked_nkeys, with an
// empty sprout_id), which every Account rebuild applies and which nothing
// grants past, so the Account is re-signed with the revocation and the
// key stays revoked even if it is put back in the config (use a new key);
// its CLI box keys are retired, so no sealed request opens under them;
// and its row here is deleted.
//
// A config that can't be read, or whose admin entry doesn't parse,
// revokes nothing: only a config read without error that no longer
// names a key removes it.

import (
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/yogzblr/imas/internal/auth"
	log "github.com/yogzblr/imas/internal/log"
)

// cliAdminKeyRow is the `pki_cli_admin_keys` table: a CLI admin NKey the
// Account rebuild granted on tenant_id's Account, since granted_at (Unix
// seconds). Keyed on (tenant_id, nkey).
type cliAdminKeyRow struct {
	TenantID  string `gorm:"column:tenant_id;primaryKey;size:191"`
	NKey      string `gorm:"column:nkey;primaryKey;size:191"`
	GrantedAt int64  `gorm:"column:granted_at;not null"`
}

func (cliAdminKeyRow) TableName() string { return "pki_cli_admin_keys" }

// configuredCLIAdminKeys returns the CLI admin NKeys farmer's config
// names (auth.ConfigAdminKeys: pubkeys.admin and users.admin), and
// whether the config was read cleanly enough to revoke a key it no
// longer names: one that can't be read, or whose admin entries don't
// parse, says nothing.
func configuredCLIAdminKeys() (keys []string, authoritative bool) {
	keys, err := auth.ConfigAdminKeys()
	if err != nil {
		log.Errorf("Could not load the imas cli's NKey(s), please edit the config: %v", err)
		return nil, false
	}
	return keys, true
}

// syncCLIAdminKeys records each of configured on tenantID's list of
// granted CLI admin keys and returns those to grant: every configured key
// not on the tenant's revoked list (revoked). If authoritative, it then
// revokes every recorded key that configured no longer holds and that is
// no current user (auth.IsCurrentUser), putting it on the revoked list and in
// revoked (so the caller's applyRevokedNKeys revokes it on the Account),
// and reports how many it revoked.
func syncCLIAdminKeys(tenantID string, configured []string, authoritative bool, revoked map[string]int64) (grant []string, removed int, err error) {
	now := time.Now().Unix()
	inConfig := map[string]bool{}
	for _, key := range configured {
		inConfig[key] = true
		if _, isRevoked := revoked[key]; isRevoked {
			log.Errorf("CLI admin key %s is in farmer's config but was revoked when it was removed earlier; it stays revoked: register a new key", key)
			continue
		}
		if err := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&cliAdminKeyRow{TenantID: tenantID, NKey: key, GrantedAt: now}).Error; err != nil {
			return nil, 0, fmt.Errorf("pki: recording CLI admin key %s in tenant %q: %w", key, tenantID, err)
		}
		grant = append(grant, key)
	}
	if !authoritative {
		return grant, 0, nil
	}
	var rows []cliAdminKeyRow
	if err := db.Where("tenant_id = ?", tenantID).Find(&rows).Error; err != nil {
		return nil, 0, fmt.Errorf("pki: reading tenant %q's CLI admin keys: %w", tenantID, err)
	}
	for _, r := range rows {
		if r.TenantID != tenantID || inConfig[r.NKey] {
			continue
		}
		user, err := auth.IsCurrentUser(r.NKey)
		if err != nil {
			return nil, 0, fmt.Errorf("pki: checking whether removed CLI admin key %s is still a user: %w", r.NKey, err)
		}
		if user {
			// Moved, not removed: the config (under another role or in
			// the users section) or the users store still has the key. It
			// is no longer granted as a CLI admin key, and not revoked
			// either; its record stays, so a rebuild after it is gone
			// from those too revokes it.
			continue
		}
		if err := revokeCLIAdminKey(tenantID, r.NKey, now); err != nil {
			return nil, 0, err
		}
		revoked[r.NKey] = now
		removed++
		log.Noticef("CLI admin key %s was removed from farmer's config: revoked on tenant %s's Account and its CLI box keys retired", r.NKey, tenantID)
	}
	return grant, removed, nil
}

// revokeCLIAdminKey ends a removed CLI admin key: its CLI box keys are
// retired, then, in one transaction, the NKey goes on tenantID's revoked
// list and its pki_cli_admin_keys row is deleted. A failure leaves the
// row, so the next rebuild tries again.
func revokeCLIAdminKey(tenantID, nkey string, now int64) error {
	if err := auth.RevokeCLIBoxKeys(auth.UsersTenantID(), nkey); err != nil && !errors.Is(err, auth.ErrStoreNotConfigured) {
		return fmt.Errorf("pki: retiring removed CLI admin key %s's CLI box keys: %w", nkey, err)
	}
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&revokedNKeyRow{
			TenantID: tenantID, NKey: nkey, SproutID: "", RevokedAt: now,
		}).Error; err != nil {
			return fmt.Errorf("pki: revoking removed CLI admin key %s in tenant %q: %w", nkey, tenantID, err)
		}
		return tx.Where("tenant_id = ? AND nkey = ?", tenantID, nkey).Delete(&cliAdminKeyRow{}).Error
	})
}
