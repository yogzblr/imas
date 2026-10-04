package farmer_test

// Tests for 00002_revoked_nkeys_and_one_active_box_key.sql (SEC.3a). The
// MySQL one runs against a real MySQL-compatible server and is skipped
// unless IMAS_TEST_MYSQL_ROOT_DSN names one by its root account, as in
// internal/migrations' own MySQL tests:
//
//	IMAS_TEST_MYSQL_ROOT_DSN='root:pw@tcp(127.0.0.1:3306)/' go test ./internal/migrations/...
//
// The same constraints on sqlite, where farmer's tests AutoMigrate the
// GORM models, are tested in internal/pki (sproutretire_test.go).

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/pressly/goose/v3"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/yogzblr/imas/internal/migrations"
	"github.com/yogzblr/imas/internal/pki"
)

const oneActiveFile = "00002_revoked_nkeys_and_one_active_box_key.sql"

func TestOneActiveMigrationShape(t *testing.T) {
	b, err := fs.ReadFile(migrations.Farmer.FS(), oneActiveFile)
	if err != nil {
		t.Fatalf("%s is not in the embedded farmer set: %v", oneActiveFile, err)
	}
	if migrations.Farmer.Latest() < 2 {
		t.Fatalf("farmer Latest = %d, want at least 2", migrations.Farmer.Latest())
	}
	// A farmer built for schema 1 writes active rows without active_slot,
	// which the CHECK refuses: this is a contract step.
	if migrations.Farmer.CompatibleFrom() < 2 {
		t.Fatalf("farmer CompatibleFrom = %d, want at least 2", migrations.Farmer.CompatibleFrom())
	}
	body := string(b)
	for _, want := range []string{
		"-- +goose Up",
		"CREATE TABLE IF NOT EXISTS `pki_revoked_nkeys`",
		"PRIMARY KEY (`tenant_id`,`nkey`)",
		"KEY `idx_pki_revoked_nkeys_sprout` (`tenant_id`,`sprout_id`)",
		"TABLE_NAME = 'pki_sprout_box_keys' AND COLUMN_NAME = 'active_slot'",
		"ADD COLUMN `active_slot` tinyint DEFAULT NULL",
		"CONSTRAINT_NAME = 'chk_pki_sprout_box_keys_active_slot'",
		"active_slot IS NOT NULL AND active_slot = 1",
		"INDEX_NAME = 'idx_pki_sprout_box_keys_one_active'",
		"ADD UNIQUE INDEX `idx_pki_sprout_box_keys_one_active` (`tenant_id`, `sprout_id`, `active_slot`)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("%s lacks %q", oneActiveFile, want)
		}
	}
	if n := strings.Count(body, "PREPARE imas_ddl FROM @imas_ddl;"); n != 3 {
		t.Errorf("%d guarded steps, want 3", n)
	}
	for _, bad := range []string{"DROP ", "-- +goose Down"} {
		if strings.Contains(body, bad) {
			t.Errorf("%s contains %q", oneActiveFile, bad)
		}
	}
}

func boxPub(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func mysqlErrNumber(err error) uint16 {
	var me *mysql.MySQLError
	if errors.As(err, &me) {
		return me.Number
	}
	return 0
}

// On MySQL, from schema 1 with rows already in it: a sprout with two
// active rows has both revoked (fail closed), a sprout with one keeps it
// with its slot, grace rows get no slot; the schema then allows exactly
// one active row per (tenant_id, sprout_id); a re-run changes nothing;
// the floor rises to 2, so a farmer built for schema 1 is refused; and
// internal/pki's own writes satisfy the constraints.
func TestMySQLOneActiveBoxKey(t *testing.T) {
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
	schema := "t_farmer_00002_" + hex.EncodeToString(sfx)
	cfg.DBName = ""
	root := open(t, cfg)
	if _, err := root.ExecContext(ctx, "CREATE DATABASE `"+schema+"`"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Exec("DROP DATABASE IF EXISTS `" + schema + "`") })
	cfg = cfg.Clone()
	cfg.DBName, cfg.ParseTime = schema, true
	db := open(t, cfg)

	// Schema 1, as a farmer built before this migration left it.
	p, err := goose.NewProvider(goose.DialectMySQL, db, migrations.Farmer.FS(), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(ctx, 1); err != nil {
		t.Fatal(err)
	}
	dupA, dupB, single, graced := boxPub(t), boxPub(t), boxPub(t), boxPub(t)
	for _, r := range [][4]string{
		{"t_a", "web", dupA, "active"},
		{"t_a", "web", dupB, "active"},
		{"t_a", "db", single, "active"},
		{"t_a", "db", graced, "grace"},
		{"t_b", "web", boxPub(t), "active"}, // another tenant's same-named sprout
	} {
		if _, err := db.ExecContext(ctx, "INSERT INTO pki_sprout_box_keys (tenant_id, sprout_id, pub, state) VALUES (?, ?, ?, ?)",
			r[0], r[1], r[2], r[3]); err != nil {
			t.Fatal(err)
		}
	}

	res, err := migrations.Up(ctx, db, migrations.Farmer, t.Logf)
	if err != nil || len(res.Applied) == 0 || res.Applied[0] != 2 {
		t.Fatalf("up: %+v, %v", res, err)
	}

	check := func(when string) {
		t.Helper()
		got := map[string]string{}
		rows, err := db.QueryContext(ctx, "SELECT tenant_id, sprout_id, pub, state, active_slot FROM pki_sprout_box_keys")
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var tenant, sprout, pub, state string
			var slot sql.NullInt64
			if err := rows.Scan(&tenant, &sprout, &pub, &state, &slot); err != nil {
				t.Fatal(err)
			}
			if slot.Valid != (state == "active") || (slot.Valid && slot.Int64 != 1) {
				t.Errorf("%s: %s/%s/%s state %s slot %v", when, tenant, sprout, pub, state, slot)
			}
			got[pub] = state
		}
		rows.Close()
		for pub, want := range map[string]string{dupA: "revoked", dupB: "revoked", single: "active", graced: "grace"} {
			if got[pub] != want {
				t.Errorf("%s: %s is %q, want %q", when, pub, got[pub], want)
			}
		}
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE()
			AND TABLE_NAME = 'pki_sprout_box_keys' AND INDEX_NAME = 'idx_pki_sprout_box_keys_one_active' AND NON_UNIQUE = 0`).Scan(&n); err != nil || n != 3 {
			t.Errorf("%s: unique index has %d columns, %v", when, n, err)
		}
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS WHERE TABLE_SCHEMA = DATABASE()
			AND TABLE_NAME = 'pki_sprout_box_keys' AND CONSTRAINT_NAME = 'chk_pki_sprout_box_keys_active_slot' AND CONSTRAINT_TYPE = 'CHECK'`).Scan(&n); err != nil || n != 1 {
			t.Errorf("%s: %d CHECK constraints, %v", when, n, err)
		}
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()
			AND TABLE_NAME = 'pki_revoked_nkeys'`).Scan(&n); err != nil || n != 1 {
			t.Errorf("%s: pki_revoked_nkeys missing, %v", when, err)
		}
	}
	check("after up")

	// A re-run (goose's record of it lost, as after a failure halfway)
	// changes nothing.
	if _, err := db.ExecContext(ctx, "DELETE FROM `"+migrations.VersionTable+"` WHERE version_id >= 2"); err != nil {
		t.Fatal(err)
	}
	res, err = migrations.Up(ctx, db, migrations.Farmer, t.Logf)
	if err != nil || len(res.Applied) != int(migrations.Farmer.Latest())-1 || res.Applied[0] != 2 {
		t.Fatalf("re-run: %+v, %v", res, err)
	}
	check("after a re-run")

	// The constraints.
	if _, err := db.ExecContext(ctx, "INSERT INTO pki_sprout_box_keys (tenant_id, sprout_id, pub, state, active_slot) VALUES ('t_a', 'db', ?, 'active', 1)", boxPub(t)); mysqlErrNumber(err) != 1062 {
		t.Errorf("second active row: %v, want a duplicate-key error", err)
	}
	// What a farmer built for schema 1 writes: an active row, no slot.
	if _, err := db.ExecContext(ctx, "INSERT INTO pki_sprout_box_keys (tenant_id, sprout_id, pub, state) VALUES ('t_a', 'new', ?, 'active')", boxPub(t)); mysqlErrNumber(err) != 3819 {
		t.Errorf("active row without a slot: %v, want a CHECK violation (3819)", err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO pki_sprout_box_keys (tenant_id, sprout_id, pub, state, active_slot) VALUES ('t_a', 'new', ?, 'grace', 1)", boxPub(t)); mysqlErrNumber(err) != 3819 {
		t.Errorf("grace row with a slot: %v, want a CHECK violation (3819)", err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO pki_revoked_nkeys (tenant_id, nkey, sprout_id, revoked_at) VALUES ('t_a', 'UKEY', 'web', 1), ('t_b', 'UKEY', 'web', 1)"); err != nil {
		t.Errorf("revoked NKeys in two tenants: %v", err)
	}
	if _, err := db.ExecContext(ctx, "INSERT INTO pki_revoked_nkeys (tenant_id, nkey, sprout_id, revoked_at) VALUES ('t_a', 'UKEY', 'db', 2)"); mysqlErrNumber(err) != 1062 {
		t.Errorf("same NKey revoked twice in a tenant: %v, want a duplicate-key error", err)
	}

	// Rolling back: the floor is 2, so `migrate check` refuses a farmer
	// built for schema 1, which would write rows the CHECK refuses. (No
	// Down section: migrations here are forward-only.)
	st, err := migrations.ReadState(ctx, db)
	if err != nil || st.Floor < 2 || st.Version != migrations.Farmer.Latest() {
		t.Fatalf("state %+v, %v", st, err)
	}
	if err := migrations.Farmer.Check(st); err != nil {
		t.Fatalf("this binary against the migrated schema: %v", err)
	}

	// internal/pki's own writes, through GORM on MySQL.
	g, err := gorm.Open(gormmysql.Open(cfg.FormatDSN()), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	pki.SetDB(g)
	t.Cleanup(func() { pki.SetDB(nil) })
	k1, k2 := boxPub(t), boxPub(t)
	if err := pki.RotateSproutBoxKey("t_c", "web", k1, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := pki.RecordSproutBoxKeySubmission("t_c", "web", k1, k2, time.Hour); err != nil {
		t.Fatal(err)
	}
	if active, grace, err := pki.ValidSproutBoxKeys("t_c", "web"); err != nil || active != k2 || len(grace) != 1 || grace[0] != k1 {
		t.Fatalf("ValidSproutBoxKeys: %s %v %v", active, grace, err)
	}
	if active, _, err := pki.ValidSproutBoxKeys("t_a", "db"); err != nil || active != single {
		t.Fatalf("ValidSproutBoxKeys(t_a, db): %s %v", active, err)
	}
	if _, _, err := pki.ValidSproutBoxKeys("t_a", "web"); !errors.Is(err, pki.ErrNoActiveBoxKey) {
		t.Fatalf("the sprout whose duplicate keys were revoked: %v, want ErrNoActiveBoxKey", err)
	}
}

func open(t *testing.T, cfg *mysql.Config) *sql.DB {
	t.Helper()
	c, err := mysql.NewConnector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(c)
	t.Cleanup(func() { db.Close() })
	return db
}
