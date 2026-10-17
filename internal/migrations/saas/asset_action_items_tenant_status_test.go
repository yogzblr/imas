package saas_test

// Tests for 00009_asset_action_items_tenant_status.sql (S3). The MySQL one
// is skipped unless IMAS_TEST_MYSQL_ROOT_DSN names a MySQL-compatible
// server by its root account, as in rollout_claimed_at_test.go.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io/fs"
	"strings"
	"testing"

	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/yogzblr/imas/internal/migrations"
	"github.com/yogzblr/imas/internal/migrations/mysqltest"
	"github.com/yogzblr/imas/internal/saasapi"
)

const tenantStatusFile = "00009_asset_action_items_tenant_status.sql"

// The migration is in the embedded set, only adds the one index, and
// guards it so a re-run changes nothing.
func TestTenantStatusIndexMigrationShape(t *testing.T) {
	b, err := fs.ReadFile(migrations.Saas.FS(), tenantStatusFile)
	if err != nil {
		t.Fatalf("%s is not in the embedded saas set: %v", tenantStatusFile, err)
	}
	if migrations.Saas.Latest() < 9 {
		t.Fatalf("saas Latest = %d, want at least 9", migrations.Saas.Latest())
	}
	if migrations.Saas.CompatibleFrom() != 1 {
		t.Fatalf("saas CompatibleFrom = %d: an expand-only migration must not raise it", migrations.Saas.CompatibleFrom())
	}
	body := string(b)
	for _, want := range []string{
		"-- +goose Up",
		"TABLE_NAME = 'asset_action_items' AND INDEX_NAME = 'idx_asset_action_items_tenant_status'",
		"ALTER TABLE `asset_action_items` ADD INDEX `idx_asset_action_items_tenant_status` (`tenant_id`, `status`)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("%s lacks %q", tenantStatusFile, want)
		}
	}
	if n := strings.Count(body, "PREPARE imas_ddl FROM @imas_ddl;"); n != 1 {
		t.Errorf("%d guarded steps, want 1", n)
	}
	for _, bad := range []string{"DROP ", "-- +goose Down", "MODIFY ", "CHANGE ", "ADD COLUMN"} {
		if strings.Contains(body, bad) {
			t.Errorf("%s contains %q: it only adds an index", tenantStatusFile, bad)
		}
	}
}

// On MySQL: the index covers (tenant_id, status) in that order; a re-run
// (goose's record of it lost, as after a failure halfway) is a no-op; the
// previous release's item model (saas 00006's columns, no new tag) still
// inserts and updates rows on the new schema, as after a helm rollback of
// saasapi; and the pending count backlog.go runs uses the new index.
func TestMySQLTenantStatusIndex(t *testing.T) {
	cfg := mysqltest.RootConfig(t)
	ctx := context.Background()
	sfx := make([]byte, 4)
	if _, err := rand.Read(sfx); err != nil {
		t.Fatal(err)
	}
	schema := "t_saas_00009_" + hex.EncodeToString(sfx)
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
		rows, err := db.QueryContext(ctx, `SELECT COLUMN_NAME, NON_UNIQUE FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE()
			AND TABLE_NAME = 'asset_action_items' AND INDEX_NAME = 'idx_asset_action_items_tenant_status' ORDER BY SEQ_IN_INDEX`)
		if err != nil {
			t.Fatal(err)
		}
		var cols []string
		for rows.Next() {
			var c string
			var nonUnique int
			if err := rows.Scan(&c, &nonUnique); err != nil {
				t.Fatal(err)
			}
			if nonUnique != 1 {
				t.Errorf("%s: the index is unique", when)
			}
			cols = append(cols, c)
		}
		rows.Close()
		if strings.Join(cols, ",") != "tenant_id,status" {
			t.Errorf("%s: idx_asset_action_items_tenant_status covers %v, want tenant_id,status", when, cols)
		}
	}
	check("after up")

	if _, err := db.ExecContext(ctx, "DELETE FROM `"+migrations.VersionTable+"` WHERE version_id >= 9"); err != nil {
		t.Fatal(err)
	}
	res, err := migrations.Up(ctx, db, migrations.Saas, t.Logf)
	if err != nil || len(res.Applied) != countFrom(t, 9) || res.Applied[0] != 9 {
		t.Fatalf("re-run: %+v, %v", res, err)
	}
	check("after a re-run")

	g, err := gorm.Open(gormmysql.Open(cfg.FormatDSN()), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	type assetActionItemS2 struct {
		BatchID         string `gorm:"column:batch_id;primaryKey;size:32"`
		AssetID         string `gorm:"column:asset_id;primaryKey;size:191"`
		TenantID        string `gorm:"column:tenant_id;size:32;not null"`
		Position        int    `gorm:"column:position;not null"`
		Status          string `gorm:"column:status;size:32;not null;index"`
		PlannedAtTarget bool   `gorm:"column:planned_at_target;not null;default:false"`
	}
	old := g.Table("asset_action_items")
	if err := old.Create(&assetActionItemS2{BatchID: "b_old", AssetID: "a1", TenantID: "t_old", Status: "queued"}).Error; err != nil {
		t.Fatalf("previous model's item insert: %v", err)
	}
	if err := g.Table("asset_action_items").Where("batch_id = ? AND asset_id = ?", "b_old", "a1").
		Update("status", "dispatching").Error; err != nil {
		t.Fatalf("previous model's item update: %v", err)
	}
	var item saasapi.AssetActionItem
	if err := g.First(&item, "batch_id = ? AND asset_id = ?", "b_old", "a1").Error; err != nil ||
		item.TenantID != "t_old" || item.Status != saasapi.ActionItemDispatching {
		t.Fatalf("current model read item %+v, %v", item, err)
	}

	var key string
	var possible, extra any
	var id, rowsN, filtered any
	var selType, table, partitions, typ, keyLen, ref any
	if err := db.QueryRowContext(ctx, "EXPLAIN SELECT COUNT(*) FROM `asset_action_items` WHERE tenant_id = ? AND status IN (?, ?)",
		"t_old", "queued", "dispatching").Scan(&id, &selType, &table, &partitions, &typ, &possible, &key, &keyLen, &ref, &rowsN, &filtered, &extra); err != nil {
		t.Fatal(err)
	}
	if key != "idx_asset_action_items_tenant_status" {
		t.Errorf("the pending count uses key %q, want idx_asset_action_items_tenant_status", key)
	}
}
