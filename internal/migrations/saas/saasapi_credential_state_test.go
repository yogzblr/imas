package saas_test

// Tests for 00008_saasapi_credential_state.sql (P21 slice 3). The MySQL
// one is skipped unless IMAS_TEST_MYSQL_ROOT_DSN names a MySQL-compatible
// server by its root account, as in rollout_claimed_at_test.go.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"

	"github.com/yogzblr/imas/internal/migrations"
)

const credentialStateFile = "00008_saasapi_credential_state.sql"

// credentialStateColumns is the table's columns as information_schema
// describes them on MySQL 8.
var credentialStateColumns = map[string]string{
	"id":          "tinyint null=NO",
	"current_pub": "varchar(64) null=NO",
	"prev_pub":    "varchar(64) null=YES",
	"rotated_at":  "datetime(3) null=NO",
	"version":     "bigint null=NO",
	"lease_owner": "varchar(128) null=YES",
	"lease_until": "datetime(3) null=YES",
}

// The migration is in the embedded set, only adds, is idempotent, and
// allows one row.
func TestCredentialStateMigrationShape(t *testing.T) {
	b, err := fs.ReadFile(migrations.Saas.FS(), credentialStateFile)
	if err != nil {
		t.Fatalf("%s is not in the embedded saas set: %v", credentialStateFile, err)
	}
	if migrations.Saas.Latest() < 8 {
		t.Fatalf("saas Latest = %d, want at least 8", migrations.Saas.Latest())
	}
	if migrations.Saas.CompatibleFrom() != 1 {
		t.Fatalf("saas CompatibleFrom = %d: an expand-only migration must not raise it", migrations.Saas.CompatibleFrom())
	}
	body := string(b)
	for _, want := range []string{
		"-- +goose Up",
		"CREATE TABLE IF NOT EXISTS `saasapi_credential_state`",
		"PRIMARY KEY (`id`)",
		"CHECK (`id` = 1)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("%s lacks %q", credentialStateFile, want)
		}
	}
	for _, bad := range []string{"DROP ", "-- +goose Down", "ALTER TABLE", "INSERT ", "farmer."} {
		if strings.Contains(body, bad) {
			t.Errorf("%s contains %q", credentialStateFile, bad)
		}
	}
}

// On MySQL: the table has its columns; a second row is refused; a
// rotation's conditional UPDATE on version lets one of two writers win;
// a re-run (goose's record of it lost) keeps the row.
func TestMySQLCredentialState(t *testing.T) {
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
	schema := "t_saas_00008_" + hex.EncodeToString(sfx)
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
			WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'saasapi_credential_state'`)
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
		for col, want := range credentialStateColumns {
			if got[col] != want {
				t.Errorf("%s: %s is %q, want %q", when, col, got[col], want)
			}
		}
		if len(got) != len(credentialStateColumns) {
			t.Errorf("%s: columns %v", when, got)
		}
	}
	check("after up")

	if _, err := db.ExecContext(ctx, "INSERT INTO saasapi_credential_state (id, current_pub, rotated_at, version) VALUES (1, 'UCUR', NOW(3), 1)"); err != nil {
		t.Fatal(err)
	}
	var me *mysql.MySQLError
	if _, err := db.ExecContext(ctx, "INSERT INTO saasapi_credential_state (id, current_pub, rotated_at, version) VALUES (2, 'UOTHER', NOW(3), 1)"); !errors.As(err, &me) || me.Number != 3819 {
		t.Errorf("second row: %v, want a CHECK violation (3819)", err)
	}

	// Two replicas rotate from version 1: the first wins, the second's
	// UPDATE matches no row.
	const rotate = `UPDATE saasapi_credential_state SET prev_pub = current_pub, current_pub = ?, rotated_at = NOW(3), version = version + 1
		WHERE id = 1 AND version = ?`
	for i, c := range []struct {
		pub  string
		want int64
	}{{"UNEW_A", 1}, {"UNEW_B", 0}} {
		r, err := db.ExecContext(ctx, rotate, c.pub, 1)
		if err != nil {
			t.Fatal(err)
		}
		if n, _ := r.RowsAffected(); n != c.want {
			t.Errorf("rotation %d: %d rows, want %d", i, n, c.want)
		}
	}
	var cur, prev string
	var version int64
	if err := db.QueryRowContext(ctx, "SELECT current_pub, prev_pub, version FROM saasapi_credential_state WHERE id = 1").Scan(&cur, &prev, &version); err != nil ||
		cur != "UNEW_A" || prev != "UCUR" || version != 2 {
		t.Fatalf("after rotation: %s %s %d, %v", cur, prev, version, err)
	}

	if _, err := db.ExecContext(ctx, "DELETE FROM `"+migrations.VersionTable+"` WHERE version_id >= 8"); err != nil {
		t.Fatal(err)
	}
	all, err := migrations.Versions(migrations.Saas.FS())
	if err != nil {
		t.Fatal(err)
	}
	want := slices.DeleteFunc(all, func(v int64) bool { return v < 8 })
	res, err := migrations.Up(ctx, db, migrations.Saas, t.Logf)
	if err != nil || !slices.Equal(res.Applied, want) {
		t.Fatalf("re-run: %+v, %v; want %v applied", res, err, want)
	}
	check("after a re-run")
	if err := db.QueryRowContext(ctx, "SELECT current_pub FROM saasapi_credential_state WHERE id = 1").Scan(&cur); err != nil || cur != "UNEW_A" {
		t.Fatalf("re-run changed the row: %s, %v", cur, err)
	}
}
