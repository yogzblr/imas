package farmer_test

// Tests for 00007_pki_cli_admin_keys.sql (U1, security review 2026-10,
// I6). The MySQL one is skipped unless IMAS_TEST_MYSQL_ROOT_DSN names a
// MySQL-compatible server by its root account, as for 00002. What the
// table is for is tested in internal/pki (cliadminkeys_test.go).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io/fs"
	"strings"
	"testing"

	"github.com/yogzblr/imas/internal/migrations"
	"github.com/yogzblr/imas/internal/migrations/mysqltest"
)

const cliAdminKeysFile = "00007_pki_cli_admin_keys.sql"

func TestCLIAdminKeysMigrationShape(t *testing.T) {
	b, err := fs.ReadFile(migrations.Farmer.FS(), cliAdminKeysFile)
	if err != nil {
		t.Fatalf("%s is not in the embedded farmer set: %v", cliAdminKeysFile, err)
	}
	// Expand only: a farmer built for schema 6 never touches the table.
	if migrations.Farmer.CompatibleFrom() != 2 {
		t.Fatalf("farmer CompatibleFrom = %d, want 2", migrations.Farmer.CompatibleFrom())
	}
	body := string(b)
	for _, want := range []string{
		"-- +goose Up",
		"-- +goose NO TRANSACTION",
		"CREATE TABLE IF NOT EXISTS `pki_cli_admin_keys`",
		"PRIMARY KEY (`tenant_id`,`nkey`)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("%s lacks %q", cliAdminKeysFile, want)
		}
	}
	for _, bad := range []string{"DROP ", "DELETE ", "-- +goose Down", "PRIMARY KEY (`nkey`)"} {
		if strings.Contains(body, bad) {
			t.Errorf("%s contains %q", cliAdminKeysFile, bad)
		}
	}
}

// On MySQL: the table exists after up, a re-run changes nothing, and one
// NKey is one row per tenant, the same NKey in two tenants two rows.
func TestMySQLCLIAdminKeys(t *testing.T) {
	cfg := mysqltest.RootConfig(t)
	ctx := context.Background()
	sfx := make([]byte, 4)
	if _, err := rand.Read(sfx); err != nil {
		t.Fatal(err)
	}
	schema := "t_farmer_00007_" + hex.EncodeToString(sfx)
	cfg.DBName = ""
	root := open(t, cfg)
	if _, err := root.ExecContext(ctx, "CREATE DATABASE `"+schema+"`"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Exec("DROP DATABASE IF EXISTS `" + schema + "`") })
	cfg = cfg.Clone()
	cfg.DBName, cfg.ParseTime = schema, true
	db := open(t, cfg)
	if _, err := migrations.Up(ctx, db, migrations.Farmer, t.Logf); err != nil {
		t.Fatal(err)
	}
	ins := func(tenant, nkey string) error {
		_, err := db.ExecContext(ctx, "INSERT INTO pki_cli_admin_keys (tenant_id, nkey, granted_at) VALUES (?, ?, 1)", tenant, nkey)
		return err
	}
	if err := ins("t_a", "UADMIN"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM `"+migrations.VersionTable+"` WHERE version_id >= 7"); err != nil {
		t.Fatal(err)
	}
	if res, err := migrations.Up(ctx, db, migrations.Farmer, t.Logf); err != nil || len(res.Applied) == 0 || res.Applied[0] != 7 {
		t.Fatalf("re-run: %+v, %v", res, err)
	}
	var n int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM pki_cli_admin_keys").Scan(&n); err != nil || n != 1 {
		t.Fatalf("rows after the re-run: %d, %v; want the one row kept", n, err)
	}
	if err := ins("t_a", "UADMIN"); mysqlErrNumber(err) != 1062 {
		t.Errorf("the same NKey twice in one tenant: %v, want a duplicate-key error", err)
	}
	if err := ins("t_b", "UADMIN"); err != nil {
		t.Errorf("the same NKey in another tenant: %v", err)
	}
}
