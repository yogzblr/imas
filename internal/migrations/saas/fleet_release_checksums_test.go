package saas_test

// Tests for 00007_fleet_release_checksums.sql (P22 slice 2). The MySQL one
// runs against a real MySQL-compatible server and is skipped unless
// IMAS_TEST_MYSQL_ROOT_DSN names one by its root account, as in
// rollout_claimed_at_test.go.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/yogzblr/imas/internal/migrations"
	"github.com/yogzblr/imas/internal/saasapi"
)

const releaseChecksumsFile = "00007_fleet_release_checksums.sql"

// releaseChecksumsColumns is the table's columns as information_schema
// describes them on MySQL 8.
var releaseChecksumsColumns = map[string]string{
	"version":       "varchar(64) null=NO",
	"checksums_txt": "mediumtext null=NO",
	"checksums_sig": "text null=NO",
	"created_at":    "datetime(3) null=NO",
}

// The migration is in the embedded set, only adds, is idempotent, keys the
// table on version and leaves fleet_versions.signature alone.
func TestReleaseChecksumsMigrationShape(t *testing.T) {
	b, err := fs.ReadFile(migrations.Saas.FS(), releaseChecksumsFile)
	if err != nil {
		t.Fatalf("%s is not in the embedded saas set: %v", releaseChecksumsFile, err)
	}
	if migrations.Saas.Latest() < 7 {
		t.Fatalf("saas Latest = %d, want at least 7", migrations.Saas.Latest())
	}
	if migrations.Saas.CompatibleFrom() != 1 {
		t.Fatalf("saas CompatibleFrom = %d: an expand-only migration must not raise it", migrations.Saas.CompatibleFrom())
	}
	body := string(b)
	for _, want := range []string{
		"-- +goose Up",
		"CREATE TABLE IF NOT EXISTS `fleet_release_checksums`",
		"`version` varchar(64) NOT NULL",
		"`checksums_txt` mediumtext NOT NULL",
		"`checksums_sig` text NOT NULL",
		"`created_at` datetime(3) NOT NULL",
		"PRIMARY KEY (`version`)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("%s lacks %q", releaseChecksumsFile, want)
		}
	}
	for _, bad := range []string{"DROP ", "-- +goose Down", "ALTER TABLE", "INSERT ", "farmer."} {
		if strings.Contains(body, bad) {
			t.Errorf("%s contains %q: it only adds", releaseChecksumsFile, bad)
		}
	}
}

// On MySQL: the table has its columns; a second row for a version is
// refused; a re-run (goose's record of it lost, as after a failure
// halfway) keeps the row; saasapi's model reads it back.
func TestMySQLReleaseChecksums(t *testing.T) {
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
	schema := "t_saas_00007_" + hex.EncodeToString(sfx)
	cfg.DBName = ""
	root := open(t, cfg)
	if _, err := root.ExecContext(ctx, "CREATE DATABASE `"+schema+"`"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Exec("DROP DATABASE IF EXISTS `" + schema + "`") })
	cfg = cfg.Clone()
	cfg.DBName, cfg.ParseTime = schema, true
	db := open(t, cfg)

	if _, err := migrations.Up(ctx, db, migrations.Saas, t.Logf); err != nil {
		t.Fatal(err)
	}
	check := func(when string) {
		t.Helper()
		rows, err := db.QueryContext(ctx, `SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE FROM information_schema.COLUMNS
			WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'fleet_release_checksums'`)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for rows.Next() {
			var name, typ, null string
			if err := rows.Scan(&name, &typ, &null); err != nil {
				t.Fatal(err)
			}
			got[name] = typ + " null=" + null
		}
		rows.Close()
		for col, want := range releaseChecksumsColumns {
			if got[col] != want {
				t.Errorf("%s: %s is %q, want %q", when, col, got[col], want)
			}
		}
		if len(got) != len(releaseChecksumsColumns) {
			t.Errorf("%s: columns %v", when, got)
		}
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE()
			AND TABLE_NAME = 'fleet_versions' AND COLUMN_NAME = 'signature'`).Scan(&n); err != nil || n != 1 {
			t.Errorf("%s: fleet_versions.signature present %d times, %v; want it kept", when, n, err)
		}
	}
	check("after up")

	txt := strings.Repeat("a", 64) + "  imas-sprout_2.4.1_linux_amd64.deb\n"
	const ins = "INSERT INTO fleet_release_checksums (version, checksums_txt, checksums_sig, created_at) VALUES (?, ?, ?, NOW(3))"
	if _, err := db.ExecContext(ctx, ins, "v2.4.1", txt, "c2ln"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, ins, "v2.4.1", txt, "b3RoZXI="); err == nil {
		t.Error("a second row for v2.4.1 was accepted")
	}

	if _, err := db.ExecContext(ctx, "DELETE FROM `"+migrations.VersionTable+"` WHERE version_id >= 7"); err != nil {
		t.Fatal(err)
	}
	res, err := migrations.Up(ctx, db, migrations.Saas, t.Logf)
	if err != nil || len(res.Applied) != countFrom(t, 7) || res.Applied[0] != 7 {
		t.Fatalf("re-run: %+v, %v", res, err)
	}
	check("after a re-run")

	g, err := gorm.Open(gormmysql.Open(cfg.FormatDSN()), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	var row saasapi.FleetReleaseChecksums
	if err := g.First(&row, "version = ?", "v2.4.1").Error; err != nil || row.ChecksumsTxt != txt || row.ChecksumsSig != "c2ln" ||
		time.Since(row.CreatedAt) > time.Hour {
		t.Fatalf("model read %+v, %v", row, err)
	}
}
