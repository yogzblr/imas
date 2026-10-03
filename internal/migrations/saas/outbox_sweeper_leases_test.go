package saas_test

// Tests for 00006_outbox_sweeper_leases.sql. The MySQL one runs against a
// real MySQL-compatible server and is skipped unless
// IMAS_TEST_MYSQL_ROOT_DSN names one by its root account, as in
// rollout_claimed_at_test.go.

import (
	"context"
	"crypto/rand"
	"database/sql"
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

const outboxLeasesFile = "00006_outbox_sweeper_leases.sql"

// outboxColumns is every column the migration adds, as information_schema
// describes it on MySQL 8.
var outboxColumns = map[string]string{
	"provisioning_jobs.last_dispatched_at": "datetime(3) null=YES default=",
	"provisioning_jobs.lease_owner":        "varchar(64) null=NO default=",
	"provisioning_jobs.lease_until":        "datetime(3) null=YES default=",
	"asset_action_batches.lease_owner":     "varchar(64) null=NO default=",
	"asset_action_batches.lease_until":     "datetime(3) null=YES default=",
	"asset_action_items.dispatched_at":     "datetime(3) null=YES default=",
	"asset_action_items.planned_at_target": "tinyint(1) null=NO default=0",
}

// The migration is in the embedded set, is its newest, only adds, and
// guards every step so a re-run changes nothing.
func TestOutboxLeasesMigrationShape(t *testing.T) {
	b, err := fs.ReadFile(migrations.Saas.FS(), outboxLeasesFile)
	if err != nil {
		t.Fatalf("%s is not in the embedded saas set: %v", outboxLeasesFile, err)
	}
	if migrations.Saas.Latest() != 6 {
		t.Fatalf("saas Latest = %d, want 6", migrations.Saas.Latest())
	}
	if migrations.Saas.CompatibleFrom() != 1 {
		t.Fatalf("saas CompatibleFrom = %d: an expand-only migration must not raise it", migrations.Saas.CompatibleFrom())
	}
	body := string(b)
	for col := range outboxColumns {
		table, name, _ := strings.Cut(col, ".")
		if !strings.Contains(body, "TABLE_NAME = '"+table+"' AND COLUMN_NAME = '"+name+"'") ||
			!strings.Contains(body, "ALTER TABLE `"+table+"` ADD COLUMN `"+name+"`") {
			t.Errorf("%s does not add %s guarded by information_schema", outboxLeasesFile, col)
		}
	}
	for _, want := range []string{"-- +goose Up", "INDEX_NAME = 'idx_asset_action_items_status'",
		"ADD INDEX `idx_asset_action_items_status` (`status`)"} {
		if !strings.Contains(body, want) {
			t.Errorf("%s lacks %q", outboxLeasesFile, want)
		}
	}
	if n := strings.Count(body, "PREPARE imas_ddl FROM @imas_ddl;"); n != len(outboxColumns)+1 {
		t.Errorf("%d guarded steps, want %d", n, len(outboxColumns)+1)
	}
	for _, bad := range []string{"DROP ", "-- +goose Down", "MODIFY ", "CHANGE "} {
		if strings.Contains(body, bad) {
			t.Errorf("%s contains %q: it only adds", outboxLeasesFile, bad)
		}
	}
}

// The previous release's models of the three tables, without the new
// columns.
type provisioningJobCL2 struct {
	ID        string    `gorm:"column:id;primaryKey;size:36"`
	TenantID  string    `gorm:"column:tenant_id;size:32;not null;index"`
	Type      string    `gorm:"column:type;size:32;not null"`
	Status    string    `gorm:"column:status;size:32;not null"`
	Attempts  int       `gorm:"column:attempts;not null;default:0"`
	CreatedAt time.Time `gorm:"column:created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
}

func (provisioningJobCL2) TableName() string { return "provisioning_jobs" }

type assetActionBatchCL2 struct {
	ID                string    `gorm:"column:id;primaryKey;size:32"`
	TenantID          string    `gorm:"column:tenant_id;size:32;not null;index"`
	ActionType        string    `gorm:"column:action_type;size:32;not null"`
	ActionParams      string    `gorm:"column:action_params;type:text;not null"`
	RequestedAssetIDs string    `gorm:"column:requested_asset_ids;type:text;not null"`
	CreatedAt         time.Time `gorm:"column:created_at"`
}

func (assetActionBatchCL2) TableName() string { return "asset_action_batches" }

type assetActionItemCL2 struct {
	BatchID   string    `gorm:"column:batch_id;primaryKey;size:32"`
	AssetID   string    `gorm:"column:asset_id;primaryKey;size:191"`
	TenantID  string    `gorm:"column:tenant_id;size:32;not null"`
	Position  int       `gorm:"column:position;not null"`
	Status    string    `gorm:"column:status;size:32;not null"`
	Attempts  int       `gorm:"column:attempts;not null;default:0"`
	CreatedAt time.Time `gorm:"column:created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
}

func (assetActionItemCL2) TableName() string { return "asset_action_items" }

// On MySQL: the columns and index are added as the models declare them; a
// re-run (goose's record of it lost, as after a failure halfway) is a
// no-op; the previous release's models insert and update rows with the
// columns present, which take their defaults (no lease, not dispatched);
// and the current models read those rows.
func TestMySQLOutboxLeases(t *testing.T) {
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
	schema := "t_saas_00006_" + hex.EncodeToString(sfx)
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
		for col, want := range outboxColumns {
			table, name, _ := strings.Cut(col, ".")
			var n int
			var typ, null string
			var def sql.NullString
			if err := db.QueryRowContext(ctx, `SELECT COUNT(*), MAX(COLUMN_TYPE), MAX(IS_NULLABLE), MAX(COLUMN_DEFAULT)
				FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?`,
				table, name).Scan(&n, &typ, &null, &def); err != nil {
				t.Fatal(err)
			}
			if got := typ + " null=" + null + " default=" + def.String; n != 1 || got != want {
				t.Errorf("%s: %s is %q (%d), want %q", when, col, got, n, want)
			}
		}
		var idx []string
		rows, err := db.QueryContext(ctx, `SELECT COLUMN_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE()
			AND TABLE_NAME = 'asset_action_items' AND INDEX_NAME = 'idx_asset_action_items_status' ORDER BY SEQ_IN_INDEX`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var c string
			rows.Scan(&c)
			idx = append(idx, c)
		}
		rows.Close()
		if strings.Join(idx, ",") != "status" {
			t.Errorf("%s: idx_asset_action_items_status covers %v", when, idx)
		}
	}
	check("after up")

	if _, err := db.ExecContext(ctx, "DELETE FROM `"+migrations.VersionTable+"` WHERE version_id >= 6"); err != nil {
		t.Fatal(err)
	}
	res, err := migrations.Up(ctx, db, migrations.Saas, t.Logf)
	if err != nil || len(res.Applied) != int(migrations.Saas.Latest())-5 || res.Applied[0] != 6 {
		t.Fatalf("re-run: %+v, %v", res, err)
	}
	check("after a re-run")

	g, err := gorm.Open(gormmysql.Open(cfg.FormatDSN()), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Create(&provisioningJobCL2{ID: "pj_old", TenantID: "t_old", Type: "provision", Status: "pending"}).Error; err != nil {
		t.Fatalf("previous model's job insert: %v", err)
	}
	if err := g.Model(&provisioningJobCL2{}).Where("id = ?", "pj_old").UpdateColumn("attempts", gorm.Expr("attempts + 1")).Error; err != nil {
		t.Fatal(err)
	}
	if err := g.Create(&assetActionBatchCL2{ID: "b_old", TenantID: "t_old", ActionType: "cmd.run", ActionParams: "{}", RequestedAssetIDs: "[]"}).Error; err != nil {
		t.Fatalf("previous model's batch insert: %v", err)
	}
	if err := g.Create(&assetActionItemCL2{BatchID: "b_old", AssetID: "a1", TenantID: "t_old", Status: "queued"}).Error; err != nil {
		t.Fatalf("previous model's item insert: %v", err)
	}

	var job saasapi.ProvisioningJob
	if err := g.First(&job, "id = ?", "pj_old").Error; err != nil || job.Attempts != 1 || job.LeaseOwner != "" ||
		job.LeaseUntil != nil || job.LastDispatchedAt != nil {
		t.Fatalf("current model read job %+v, %v", job, err)
	}
	var batch saasapi.AssetActionBatch
	if err := g.First(&batch, "id = ?", "b_old").Error; err != nil || batch.LeaseOwner != "" || batch.LeaseUntil != nil {
		t.Fatalf("current model read batch %+v, %v", batch, err)
	}
	var item saasapi.AssetActionItem
	if err := g.First(&item, "batch_id = ? AND asset_id = ?", "b_old", "a1").Error; err != nil || item.DispatchedAt != nil || item.PlannedAtTarget {
		t.Fatalf("current model read item %+v, %v", item, err)
	}
}
