package farmer_test

// Tests for 00003_auth_users_and_cli_box_keys.sql (J.1). The MySQL one is
// skipped unless IMAS_TEST_MYSQL_ROOT_DSN names a MySQL-compatible server
// by its root account, as for 00002. The same constraints on sqlite are
// tested in internal/auth (store_test.go).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"

	"github.com/yogzblr/imas/internal/migrations"
)

const authBoxKeysFile = "00003_auth_users_and_cli_box_keys.sql"

func TestAuthCLIBoxKeysMigrationShape(t *testing.T) {
	b, err := fs.ReadFile(migrations.Farmer.FS(), authBoxKeysFile)
	if err != nil {
		t.Fatalf("%s is not in the embedded farmer set: %v", authBoxKeysFile, err)
	}
	if migrations.Farmer.Latest() < 3 {
		t.Fatalf("farmer Latest = %d, want at least 3", migrations.Farmer.Latest())
	}
	// Expand only: a farmer built for schema 2 never touches these.
	if migrations.Farmer.CompatibleFrom() != 2 {
		t.Fatalf("farmer CompatibleFrom = %d, want 2", migrations.Farmer.CompatibleFrom())
	}
	body := string(b)
	for _, want := range []string{
		"-- +goose Up",
		"CREATE TABLE IF NOT EXISTS `auth_users`",
		"PRIMARY KEY (`tenant_id`,`user_id`)",
		"CREATE TABLE IF NOT EXISTS `auth_cli_box_keys`",
		"PRIMARY KEY (`tenant_id`,`user_id`,`pub`)",
		"UNIQUE KEY `idx_auth_cli_box_keys_pub` (`pub`)",
		"UNIQUE KEY `idx_auth_cli_box_keys_one_active` (`tenant_id`,`user_id`,`active_slot`)",
		"status = 'active' AND active_slot IS NOT NULL AND active_slot = 1",
		"INDEX_NAME = 'idx_pki_sprout_box_keys_pub'",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("%s lacks %q", authBoxKeysFile, want)
		}
	}
	for _, bad := range []string{"DROP ", "-- +goose Down", "sprout_id`)"} {
		if strings.Contains(body, bad) {
			t.Errorf("%s contains %q", authBoxKeysFile, bad)
		}
	}
}

// On MySQL: the tables and index exist after up, a re-run changes
// nothing, and the schema allows one active CLI key per (tenant_id,
// user_id) and each pub once across every user and tenant.
func TestMySQLAuthCLIBoxKeys(t *testing.T) {
	dsn := os.Getenv("IMAS_TEST_MYSQL_ROOT_DSN")
	if dsn == "" {
		t.Skip("IMAS_TEST_MYSQL_ROOT_DSN not set; skipping the MySQL tests")
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal("IMAS_TEST_MYSQL_ROOT_DSN: not a valid DSN")
	}
	ctx := context.Background()
	sfx := make([]byte, 4)
	if _, err := rand.Read(sfx); err != nil {
		t.Fatal(err)
	}
	schema := "t_farmer_00003_" + hex.EncodeToString(sfx)
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
	if _, err := db.ExecContext(ctx, "DELETE FROM `"+migrations.VersionTable+"` WHERE version_id >= 3"); err != nil {
		t.Fatal(err)
	}
	if res, err := migrations.Up(ctx, db, migrations.Farmer, t.Logf); err != nil || len(res.Applied) == 0 || res.Applied[0] != 3 {
		t.Fatalf("re-run: %+v, %v", res, err)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE()
		AND TABLE_NAME = 'pki_sprout_box_keys' AND INDEX_NAME = 'idx_pki_sprout_box_keys_pub'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("idx_pki_sprout_box_keys_pub: %d columns, %v", n, err)
	}
	ins := func(tenant, user, pub, status string, slot any) error {
		_, err := db.ExecContext(ctx, "INSERT INTO auth_cli_box_keys (tenant_id, user_id, pub, status, active_slot, created_at) VALUES (?, ?, ?, ?, ?, NOW(3))",
			tenant, user, pub, status, slot)
		return err
	}
	k1 := boxPub(t)
	if err := ins("t_a", "UA", k1, "active", 1); err != nil {
		t.Fatal(err)
	}
	if err := ins("t_a", "UA", boxPub(t), "active", 1); mysqlErrNumber(err) != 1062 {
		t.Errorf("second active key: %v, want a duplicate-key error", err)
	}
	if err := ins("t_a", "UA", boxPub(t), "active", nil); err == nil {
		t.Error("an active key without its slot was stored")
	}
	if err := ins("t_b", "UB", k1, "grace", nil); mysqlErrNumber(err) != 1062 {
		t.Errorf("one pub for two users: %v, want a duplicate-key error", err)
	}
	if err := ins("t_b", "UA", boxPub(t), "active", 1); err != nil {
		t.Errorf("the same user's key in another tenant: %v", err)
	}
}
