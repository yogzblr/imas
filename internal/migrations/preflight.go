package migrations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// ErrPreflight is a migration that `migrate up` refused to run because a
// check of the data it would change failed. Nothing was applied: Up runs
// every preflight of the pending migrations before it raises the floor
// or applies anything.
var ErrPreflight = errors.New("migration preflight refused")

// preflight checks, before a migration runs, that the data it changes
// allows it, and returns an error wrapping ErrPreflight that says what
// to fix when it doesn't. db is connected to the schema.
type preflight func(ctx context.Context, db *sql.DB) error

// preflights are the checks per set and version. A migration that would
// fail on existing data (a unique index over duplicate rows) gets one, so
// the refusal names every offending row instead of MySQL's first
// duplicate key.
var preflights = map[string]map[int64]preflight{
	"farmer": {6: checkTenantNKeysUnique},
}

// runPreflights runs the preflight of every migration of s not yet
// applied to db's schema, in version order.
func runPreflights(ctx context.Context, db *sql.DB, s Set) error {
	checks := preflights[s.name]
	if len(checks) == 0 {
		return nil
	}
	applied := map[int64]bool{}
	ok, err := tableExists(ctx, db, VersionTable)
	if err != nil {
		return err
	}
	if ok {
		if applied, err = appliedVersions(ctx, db); err != nil {
			return err
		}
	}
	for _, v := range s.versions {
		check, has := checks[v]
		if !has || applied[v] {
			continue
		}
		if err := check(ctx, db); err != nil {
			return fmt.Errorf("migration %05d: %w", v, err)
		}
	}
	return nil
}

// checkTenantNKeysUnique is farmer 00006's preflight: pki_nkeys must hold
// no two rows with the same (tenant_id, nkey), the index 00006 adds. It
// compares with the column's own collation, as the index will, and names
// every duplicate NKey with its tenant and sprout IDs. A schema without
// pki_nkeys yet (a fresh install, 00001 pending too) passes.
func checkTenantNKeysUnique(ctx context.Context, db *sql.DB) error {
	var tables int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.TABLES"+
		" WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'pki_nkeys'").Scan(&tables); err != nil {
		return fmt.Errorf("looking for pki_nkeys: %w", err)
	}
	if tables == 0 {
		return nil
	}
	rows, err := db.QueryContext(ctx, "SELECT `tenant_id`, `nkey`, GROUP_CONCAT(`sprout_id` ORDER BY `sprout_id` SEPARATOR ', ')"+
		" FROM `pki_nkeys` GROUP BY `tenant_id`, `nkey` HAVING COUNT(*) > 1 ORDER BY `tenant_id`, `nkey`")
	if err != nil {
		return fmt.Errorf("looking for duplicate (tenant_id, nkey) rows in pki_nkeys: %w", err)
	}
	defer rows.Close()
	var dups []string
	for rows.Next() {
		var tenantID, nkey, sprouts string
		if err := rows.Scan(&tenantID, &nkey, &sprouts); err != nil {
			return err
		}
		dups = append(dups, fmt.Sprintf("tenant %s NKey %s held by sprouts %s", tenantID, nkey, sprouts))
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(dups) == 0 {
		return nil
	}
	return fmt.Errorf("%w: pki_nkeys holds %d NKeys under more than one sprout ID of a tenant (%s); "+
		"migration 00006 makes (tenant_id, nkey) unique: delete all but one sprout of each, then run migrate up again",
		ErrPreflight, len(dups), strings.Join(dups, "; "))
}
