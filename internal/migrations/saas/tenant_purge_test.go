package saas_test

// Tests for 00010_tenant_purge.sql (S6). The MySQL one is skipped unless
// IMAS_TEST_MYSQL_ROOT_DSN names a MySQL-compatible server by its root
// account, as in rollout_claimed_at_test.go.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io/fs"
	"strings"
	"testing"
	"time"

	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/yogzblr/imas/internal/migrations"
	"github.com/yogzblr/imas/internal/migrations/mysqltest"
	"github.com/yogzblr/imas/internal/saasapi"
	"github.com/yogzblr/imas/internal/tenantpurge"
)

const tenantPurgeFile = "00010_tenant_purge.sql"

// The migration is in the embedded set, adds exactly its three columns
// guarded, backfills only offboarded tenants, and drops nothing.
func TestTenantPurgeMigrationShape(t *testing.T) {
	b, err := fs.ReadFile(migrations.Saas.FS(), tenantPurgeFile)
	if err != nil {
		t.Fatalf("%s is not in the embedded saas set: %v", tenantPurgeFile, err)
	}
	if migrations.Saas.Latest() < 10 {
		t.Fatalf("saas Latest = %d, want at least 10", migrations.Saas.Latest())
	}
	if migrations.Saas.CompatibleFrom() != 1 {
		t.Fatalf("saas CompatibleFrom = %d: an expand-only migration must not raise it", migrations.Saas.CompatibleFrom())
	}
	body := string(b)
	for _, want := range []string{
		"-- +goose Up",
		"ALTER TABLE `tenants` ADD COLUMN `offboarded_at` datetime(3) DEFAULT NULL",
		"ALTER TABLE `tenants` ADD COLUMN `purge_claimed_at` datetime(3) DEFAULT NULL",
		"ALTER TABLE `provisioning_jobs` ADD COLUMN `purge_trigger` varchar(16) NOT NULL DEFAULT ''''",
		"UPDATE `tenants` SET `offboarded_at` = `updated_at`\n  WHERE `status` = 'offboarded' AND `offboarded_at` IS NULL;",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("%s lacks %q", tenantPurgeFile, want)
		}
	}
	if n := strings.Count(body, "PREPARE imas_ddl FROM @imas_ddl;"); n != 3 {
		t.Errorf("%d guarded steps, want 3", n)
	}
	for _, bad := range []string{"DROP ", "-- +goose Down", "MODIFY ", "CHANGE ", "DELETE "} {
		if strings.Contains(body, bad) {
			t.Errorf("%s contains %q", tenantPurgeFile, bad)
		}
	}
}

// On MySQL: the columns arrive with their types; the backfill sets
// offboarded_at from updated_at for offboarded tenants only and leaves a
// value already set; a re-run (goose's record of it lost) changes nothing;
// the previous release's models still insert and update on the new schema
// (a helm rollback of saasapi; migrations are forward-only, so this is
// what rolling back means); and the purge's batched tenant-exact delete
// (tenantpurge.DeleteRows, DELETE ... LIMIT) removes one tenant's rows and
// no other's.
func TestMySQLTenantPurge(t *testing.T) {
	cfg := mysqltest.RootConfig(t)
	ctx := context.Background()
	sfx := make([]byte, 4)
	if _, err := rand.Read(sfx); err != nil {
		t.Fatal(err)
	}
	schema := "t_saas_00010_" + hex.EncodeToString(sfx)
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

	// Back to schema 9, with tenants in every status, then up again.
	for _, stmt := range []string{
		"DELETE FROM `" + migrations.VersionTable + "` WHERE version_id >= 10",
		"ALTER TABLE `tenants` DROP COLUMN `offboarded_at`, DROP COLUMN `purge_claimed_at`",
		"ALTER TABLE `provisioning_jobs` DROP COLUMN `purge_trigger`",
		"INSERT INTO `tenants` (id, name, status, created_at, updated_at) VALUES " +
			"('t_off', 'Off', 'offboarded', '2026-09-01 10:00:00.000', '2026-09-02 11:12:13.456')," +
			"('t_active', 'Active', 'active', '2026-09-01 10:00:00.000', '2026-09-03 10:00:00.000')," +
			"('t_offboarding', 'Going', 'offboarding', '2026-09-01 10:00:00.000', '2026-09-04 10:00:00.000')",
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	res, err := migrations.Up(ctx, db, migrations.Saas, t.Logf)
	if err != nil || len(res.Applied) != countFrom(t, 10) || res.Applied[0] != 10 {
		t.Fatalf("up from 9: %+v, %v", res, err)
	}
	check := func(when string) {
		t.Helper()
		for _, c := range []struct{ table, col, typ, null, def string }{
			{"tenants", "offboarded_at", "datetime(3)", "YES", ""},
			{"tenants", "purge_claimed_at", "datetime(3)", "YES", ""},
			{"provisioning_jobs", "purge_trigger", "varchar(16)", "NO", ""},
		} {
			var typ, null string
			var def *string
			if err := db.QueryRowContext(ctx, `SELECT COLUMN_TYPE, IS_NULLABLE, COLUMN_DEFAULT FROM information_schema.COLUMNS
				WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?`, c.table, c.col).Scan(&typ, &null, &def); err != nil {
				t.Fatalf("%s: %s.%s: %v", when, c.table, c.col, err)
			}
			if typ != c.typ || null != c.null || (def != nil && *def != c.def) || (def == nil && c.null == "NO") {
				t.Errorf("%s: %s.%s is %s null=%s default=%v", when, c.table, c.col, typ, null, def)
			}
		}
		want := map[string]string{"t_off": "2026-09-02 11:12:13.456", "t_active": "", "t_offboarding": ""}
		for id, at := range want {
			var got *string
			if err := db.QueryRowContext(ctx, "SELECT DATE_FORMAT(offboarded_at, '%Y-%m-%d %H:%i:%s.%f') FROM tenants WHERE id = ?", id).Scan(&got); err != nil {
				t.Fatal(err)
			}
			switch {
			case at == "" && got != nil:
				t.Errorf("%s: %s backfilled to %s", when, id, *got)
			case at != "" && (got == nil || !strings.HasPrefix(*got, at)):
				t.Errorf("%s: %s offboarded_at %v, want %s", when, id, got, at)
			}
		}
	}
	check("after up")

	// A value already set is kept by a re-run.
	if _, err := db.ExecContext(ctx, "UPDATE tenants SET offboarded_at = '2026-09-02 11:12:13.456', updated_at = '2026-10-01 00:00:00' WHERE id = 't_off'"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM `"+migrations.VersionTable+"` WHERE version_id >= 10"); err != nil {
		t.Fatal(err)
	}
	if res, err := migrations.Up(ctx, db, migrations.Saas, t.Logf); err != nil || len(res.Applied) != countFrom(t, 10) {
		t.Fatalf("re-run: %+v, %v", res, err)
	}
	check("after a re-run")

	g, err := gorm.Open(gormmysql.Open(cfg.FormatDSN()), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	// The previous release's models (no new fields).
	type tenantS5 struct {
		ID        string    `gorm:"column:id;primaryKey;size:32"`
		Name      string    `gorm:"column:name;size:255;not null"`
		Status    string    `gorm:"column:status;size:32;not null"`
		CreatedAt time.Time `gorm:"column:created_at"`
		UpdatedAt time.Time `gorm:"column:updated_at"`
	}
	type jobS5 struct {
		ID       string `gorm:"column:id;primaryKey;size:36"`
		TenantID string `gorm:"column:tenant_id;size:32;not null"`
		Type     string `gorm:"column:type;size:32;not null"`
		Status   string `gorm:"column:status;size:32;not null"`
	}
	if err := g.Table("tenants").Create(&tenantS5{ID: "t_prev", Name: "Prev", Status: "offboarding"}).Error; err != nil {
		t.Fatalf("previous model's tenant insert: %v", err)
	}
	if err := g.Table("tenants").Where("id = ?", "t_prev").Update("status", "offboarded").Error; err != nil {
		t.Fatalf("previous model's tenant update: %v", err)
	}
	if err := g.Table("provisioning_jobs").Create(&jobS5{ID: "pj_prev", TenantID: "t_prev", Type: "deprovision", Status: "pending"}).Error; err != nil {
		t.Fatalf("previous model's job insert: %v", err)
	}
	var tenant saasapi.Tenant
	if err := g.First(&tenant, "id = ?", "t_prev").Error; err != nil || tenant.OffboardedAt != nil || tenant.PurgeClaimedAt != nil {
		t.Fatalf("current model read the previous release's tenant %+v, %v", tenant, err)
	}
	var job saasapi.ProvisioningJob
	if err := g.First(&job, "id = ?", "pj_prev").Error; err != nil || job.PurgeTrigger != "" {
		t.Fatalf("current model read the previous release's job %+v, %v", job, err)
	}
	// The sweeper's query, on MySQL: t_prev counts from updated_at.
	var due []saasapi.Tenant
	if err := g.Where("status = ?", saasapi.TenantStatusOffboarded).
		Where("COALESCE(offboarded_at, updated_at) <= ?", time.Now().UTC().Add(time.Minute)).
		Where("purge_claimed_at IS NULL OR purge_claimed_at <= ?", time.Now().UTC()).
		Order("id").Find(&due).Error; err != nil {
		t.Fatal(err)
	}
	if len(due) != 2 || due[0].ID != "t_off" || due[1].ID != "t_prev" {
		t.Errorf("due tenants %+v", due)
	}

	// Batched, tenant-exact deletes on MySQL.
	for i := range 7 {
		if err := g.Create(&saasapi.AssetLink{ID: "al_a" + string(rune('0'+i)), TenantID: "t_a", SproutID: "web-0" + string(rune('0'+i)), AssetID: "asset-a" + string(rune('0'+i)), LinkedAt: time.Now()}).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := g.Create(&saasapi.AssetLink{ID: "al_b", TenantID: "t_ab", SproutID: "web-00", AssetID: "asset-b", LinkedAt: time.Now()}).Error; err != nil {
		t.Fatal(err)
	}
	n, err := tenantpurge.DeleteRows(ctx, g, "asset_links", "t_a", 3)
	if err != nil || n != 7 {
		t.Fatalf("DeleteRows = %d, %v", n, err)
	}
	var left int64
	g.Model(&saasapi.AssetLink{}).Where("tenant_id = ?", "t_ab").Count(&left)
	if left != 1 {
		t.Errorf("t_ab has %d asset links left, want 1", left)
	}
}
