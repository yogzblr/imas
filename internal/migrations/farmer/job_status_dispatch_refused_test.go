package farmer_test

// Tests for 00008_job_status_dispatch_refused.sql (P29). The MySQL one is
// skipped unless IMAS_TEST_MYSQL_ROOT_DSN names a MySQL-compatible server
// by its root account, as for 00002. What the column is for is tested in
// internal/jobs (status_index_test.go).

import (
	"context"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/migrations"
)

const dispatchRefusedFile = "00008_job_status_dispatch_refused.sql"

func TestDispatchRefusedMigrationShape(t *testing.T) {
	b, err := fs.ReadFile(migrations.Farmer.FS(), dispatchRefusedFile)
	if err != nil {
		t.Fatalf("%s is not in the embedded farmer set: %v", dispatchRefusedFile, err)
	}
	// Expand only: a farmer built for schema 7 never names the column.
	if migrations.Farmer.CompatibleFrom() != 2 {
		t.Fatalf("farmer CompatibleFrom = %d, want 2", migrations.Farmer.CompatibleFrom())
	}
	body := string(b)
	for _, want := range []string{
		"-- +goose Up",
		"-- +goose NO TRANSACTION",
		"FROM information_schema.COLUMNS",
		"COLUMN_NAME = 'dispatch_refused'",
		"ADD COLUMN `dispatch_refused` tinyint(1) NOT NULL DEFAULT ''0''",
		"'DO 0'",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("%s lacks %q", dispatchRefusedFile, want)
		}
	}
	for _, bad := range []string{"DROP ", "DELETE ", "UPDATE ", "-- +goose Down"} {
		if strings.Contains(body, bad) {
			t.Errorf("%s contains %q: it only adds a column", dispatchRefusedFile, bad)
		}
	}
}

// On MySQL: the column is added as the model declares it, a re-run changes
// nothing, and a row the previous release's farmer inserts, naming only
// its own columns, gets dispatch_refused 0.
func TestMySQLDispatchRefused(t *testing.T) {
	db, _ := newSchema(t, "t_farmer_00008_")
	ctx := context.Background()
	if _, err := migrations.Up(ctx, db, migrations.Farmer, t.Logf); err != nil {
		t.Fatal(err)
	}
	column := func(when string) {
		t.Helper()
		var typ, null, def string
		if err := db.QueryRowContext(ctx, `SELECT COLUMN_TYPE, IS_NULLABLE, COLUMN_DEFAULT FROM information_schema.COLUMNS
			WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'job_status' AND COLUMN_NAME = 'dispatch_refused'`).Scan(&typ, &null, &def); err != nil {
			t.Fatalf("%s: %v", when, err)
		}
		if got := typ + " null=" + null + " default=" + def; got != "tinyint(1) null=NO default=0" {
			t.Errorf("%s: dispatch_refused is %q", when, got)
		}
	}
	column("after up")
	if _, err := db.ExecContext(ctx, `INSERT INTO job_status (tenant_id, sprout_id, jid, status, steps_reported, step_failed,
		started, finished, timed_out, updated_at, expired) VALUES ('t_a', 'web-01', 'j1', 'pending', 0, 0, 0, 0, 0, ?, 0)`, time.Now().UTC()); err != nil {
		t.Fatalf("the previous release's insert: %v", err)
	}
	reRunFrom(t, db, 8)
	column("after a re-run")
	var refused int
	if err := db.QueryRowContext(ctx, "SELECT dispatch_refused FROM job_status WHERE tenant_id = 't_a' AND sprout_id = 'web-01' AND jid = 'j1'").Scan(&refused); err != nil || refused != 0 {
		t.Errorf("the previous release's row: dispatch_refused %d, %v; want 0", refused, err)
	}
}
