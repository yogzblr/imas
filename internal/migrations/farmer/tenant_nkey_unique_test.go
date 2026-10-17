package farmer_test

// Tests for 00006_pki_nkeys_tenant_nkey_unique.sql (T4, security review
// 2026-10, I7). The MySQL one is skipped unless IMAS_TEST_MYSQL_ROOT_DSN
// names a server by its root account, as in revoked_nkeys_one_active_test.go.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"

	"github.com/yogzblr/imas/internal/migrations"
	"github.com/yogzblr/imas/internal/migrations/mysqltest"
)

const tenantNKeyUniqueFile = "00006_pki_nkeys_tenant_nkey_unique.sql"

func TestTenantNKeyUniqueMigrationShape(t *testing.T) {
	b, err := fs.ReadFile(migrations.Farmer.FS(), tenantNKeyUniqueFile)
	if err != nil {
		t.Fatalf("%s is not in the embedded farmer set: %v", tenantNKeyUniqueFile, err)
	}
	body := string(b)
	for _, want := range []string{
		"-- +goose Up",
		"-- +goose NO TRANSACTION",
		"INDEX_NAME = 'idx_pki_nkeys_tenant_nkey'",
		"ADD UNIQUE INDEX `idx_pki_nkeys_tenant_nkey` (`tenant_id`, `nkey`)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("%s lacks %q", tenantNKeyUniqueFile, want)
		}
	}
	if n := strings.Count(body, "PREPARE imas_ddl FROM @imas_ddl;"); n != 1 {
		t.Errorf("%d guarded steps, want 1", n)
	}
	for _, bad := range []string{"DROP ", "DELETE ", "-- +goose Down", "UNIQUE INDEX `idx_pki_nkeys_tenant_nkey` (`nkey`)"} {
		if strings.Contains(body, bad) {
			t.Errorf("%s contains %q", tenantNKeyUniqueFile, bad)
		}
	}
}

// On MySQL, from schema 5 with two sprouts of one tenant holding the same
// NKey: `migrate up` refuses before applying anything or raising the
// floor, and its error names every duplicate; the same NKey in two
// tenants is no duplicate. Once the duplicate is gone it applies, the
// index refuses a second row for a (tenant_id, nkey), and a re-run
// changes nothing.
func TestMySQLTenantNKeyUnique(t *testing.T) {
	cfg := mysqltest.RootConfig(t)
	ctx := context.Background()
	sfx := make([]byte, 4)
	if _, err := rand.Read(sfx); err != nil {
		t.Fatal(err)
	}
	schema := "t_farmer_00006_" + hex.EncodeToString(sfx)
	cfg.DBName = ""
	root := open(t, cfg)
	if _, err := root.ExecContext(ctx, "CREATE DATABASE `"+schema+"`"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Exec("DROP DATABASE IF EXISTS `" + schema + "`") })
	cfg = cfg.Clone()
	cfg.DBName, cfg.ParseTime = schema, true
	db := open(t, cfg)

	p, err := goose.NewProvider(goose.DialectMySQL, db, migrations.Farmer.FS(), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 5); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS `"+migrations.InfoTable+"` (`id` tinyint unsigned NOT NULL,"+
		" `min_compatible_version` bigint NOT NULL, `updated_at` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6), PRIMARY KEY (`id`))"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO `"+migrations.InfoTable+"` (id, min_compatible_version) VALUES (1, 1)"); err != nil {
		t.Fatal(err)
	}
	insert := func(tenant, sprout, nkey, state string) error {
		_, err := db.ExecContext(ctx, "INSERT INTO pki_nkeys (tenant_id, sprout_id, nkey, state) VALUES (?, ?, ?, ?)", tenant, sprout, nkey, state)
		return err
	}
	for _, r := range [][4]string{
		{"t_a", "web-01", "UDUPKEY", "accepted"},
		{"t_a", "web-02", "UDUPKEY", "unaccepted"},
		{"t_a", "db-01", "UONEKEY", "accepted"},
		{"t_b", "web-01", "UDUPKEY", "accepted"}, // another tenant: not a duplicate
	} {
		if err := insert(r[0], r[1], r[2], r[3]); err != nil {
			t.Fatal(err)
		}
	}

	res, err := migrations.Up(ctx, db, migrations.Farmer, t.Logf)
	if !errors.Is(err, migrations.ErrPreflight) || len(res.Applied) != 0 {
		t.Fatalf("up over a duplicate: %+v, %v; want ErrPreflight and nothing applied", res, err)
	}
	for _, want := range []string{"tenant t_a NKey UDUPKEY held by sprouts web-01, web-02", "holds 1 NKeys"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not say %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "t_b") || strings.Contains(err.Error(), "UONEKEY") {
		t.Errorf("refusal %q names a row that is no duplicate", err)
	}
	st, err := migrations.ReadState(ctx, db)
	if err != nil || st.Version != 5 || st.Floor != 1 {
		t.Fatalf("after the refusal: state %+v, %v; want version 5, floor untouched", st, err)
	}

	if _, err := db.ExecContext(ctx, "DELETE FROM pki_nkeys WHERE tenant_id = 't_a' AND sprout_id = 'web-02'"); err != nil {
		t.Fatal(err)
	}
	res, err = migrations.Up(ctx, db, migrations.Farmer, t.Logf)
	if err != nil || len(res.Applied) != 1 || res.Applied[0] != 6 {
		t.Fatalf("up: %+v, %v", res, err)
	}
	check := func(when string) {
		t.Helper()
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE()
			AND TABLE_NAME = 'pki_nkeys' AND INDEX_NAME = 'idx_pki_nkeys_tenant_nkey' AND NON_UNIQUE = 0`).Scan(&n); err != nil || n != 2 {
			t.Errorf("%s: unique index has %d columns, %v", when, n, err)
		}
		if err := insert("t_a", "web-03", "UONEKEY", "rejected"); mysqlErrNumber(err) != 1062 {
			t.Errorf("%s: second row for an NKey in a tenant: %v, want a duplicate-key error", when, err)
		}
		if err := insert("t_c", "web-01", "UONEKEY", "accepted"); err != nil {
			t.Errorf("%s: the same NKey in another tenant: %v", when, err)
		}
		if _, err := db.ExecContext(ctx, "DELETE FROM pki_nkeys WHERE tenant_id = 't_c'"); err != nil {
			t.Fatal(err)
		}
	}
	check("after up")

	// A re-run (goose's record of it lost, as after a failure halfway)
	// changes nothing.
	if _, err := db.ExecContext(ctx, "DELETE FROM `"+migrations.VersionTable+"` WHERE version_id = 6"); err != nil {
		t.Fatal(err)
	}
	if res, err := migrations.Up(ctx, db, migrations.Farmer, t.Logf); err != nil || len(res.Applied) != 1 {
		t.Fatalf("re-run: %+v, %v", res, err)
	}
	check("after a re-run")
}
