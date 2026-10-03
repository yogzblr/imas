package saas_test

// Tests for 00005_tenant_update_policy_rollout_claimed_at.sql. The MySQL
// ones run against a real MySQL-compatible server and are skipped unless
// IMAS_TEST_MYSQL_ROOT_DSN names one by its root account, as in
// internal/migrations' own MySQL tests:
//
//	IMAS_TEST_MYSQL_ROOT_DSN='root:pw@tcp(127.0.0.1:3306)/' go test ./internal/migrations/...

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

const rolloutClaimedAtFile = "00005_tenant_update_policy_rollout_claimed_at.sql"

// The migration is in the embedded saas set and is guarded
// so a re-run changes nothing: the ALTER is prepared only when
// information_schema has no such column.
func TestRolloutClaimedAtMigrationShape(t *testing.T) {
	b, err := fs.ReadFile(migrations.Saas.FS(), rolloutClaimedAtFile)
	if err != nil {
		t.Fatalf("%s is not in the embedded saas set: %v", rolloutClaimedAtFile, err)
	}
	if migrations.Saas.Latest() < 5 {
		t.Fatalf("saas Latest = %d, want at least 5", migrations.Saas.Latest())
	}
	body := string(b)
	for _, want := range []string{
		"-- +goose Up",
		"FROM information_schema.COLUMNS",
		"COLUMN_NAME = 'rollout_claimed_at'",
		"ADD COLUMN `rollout_claimed_at` datetime(3) DEFAULT NULL",
		"'DO 0'",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("%s lacks %q", rolloutClaimedAtFile, want)
		}
	}
	for _, bad := range []string{"DROP ", "updated_at`"} {
		if strings.Contains(body, bad) {
			t.Errorf("%s contains %q: it only adds a column", rolloutClaimedAtFile, bad)
		}
	}
}

// tenantUpdatePolicyFU6 is saasapi.TenantUpdatePolicy as the previous
// release has it, without rollout_claimed_at.
type tenantUpdatePolicyFU6 struct {
	TenantID           string     `gorm:"column:tenant_id;primaryKey;size:32"`
	ApprovedVersion    *string    `gorm:"column:approved_version;size:64"`
	AutoUpdate         bool       `gorm:"column:auto_update;not null;default:false"`
	RolloutWindowStart *time.Time `gorm:"column:rollout_window_start"`
	RolloutWindowEnd   *time.Time `gorm:"column:rollout_window_end"`
	UpdatedAt          time.Time  `gorm:"column:updated_at"`
}

func (tenantUpdatePolicyFU6) TableName() string { return "tenant_update_policy" }

// On MySQL: the column is added as the model declares it; a re-run of the
// migration (goose's record of it lost, as after a failure halfway) is a
// no-op; and the previous release's model reads and writes the table with
// the column present, leaving it alone.
func TestMySQLRolloutClaimedAt(t *testing.T) {
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
	schema := "t_saas_00005_" + hex.EncodeToString(sfx)
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
	column := func() string {
		t.Helper()
		var typ, null string
		var def sql.NullString
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*), MAX(COLUMN_TYPE), MAX(IS_NULLABLE), MAX(COLUMN_DEFAULT)
			FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tenant_update_policy'
			AND COLUMN_NAME = 'rollout_claimed_at'`).Scan(&n, &typ, &null, &def); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("%d rollout_claimed_at columns", n)
		}
		return typ + " null=" + null + " default=" + def.String
	}
	want := "datetime(3) null=YES default="
	if got := column(); got != want {
		t.Fatalf("rollout_claimed_at is %q, want %q", got, want)
	}

	// goose refuses a gap below the recorded version, so 5 and every later
	// migration are forgotten and re-run together; each is idempotent.
	if _, err := db.ExecContext(ctx, "DELETE FROM `"+migrations.VersionTable+"` WHERE version_id >= 5"); err != nil {
		t.Fatal(err)
	}
	res, err := migrations.Up(ctx, db, migrations.Saas, t.Logf)
	if err != nil || len(res.Applied) != int(migrations.Saas.Latest())-4 || res.Applied[0] != 5 {
		t.Fatalf("re-run: %+v, %v", res, err)
	}
	if got := column(); got != want {
		t.Fatalf("after a re-run rollout_claimed_at is %q, want %q", got, want)
	}

	g, err := gorm.Open(gormmysql.Open(cfg.FormatDSN()), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	version := "v2.4.1"
	if err := g.Create(&tenantUpdatePolicyFU6{TenantID: "t_old", ApprovedVersion: &version, UpdatedAt: time.Now()}).Error; err != nil {
		t.Fatalf("previous model's insert: %v", err)
	}
	var cur saasapi.TenantUpdatePolicy
	if err := g.First(&cur, "tenant_id = ?", "t_old").Error; err != nil || cur.RolloutClaimedAt != nil {
		t.Fatalf("current model read %+v, %v", cur, err)
	}
	claimed := time.Now().UTC().Truncate(time.Millisecond)
	if err := g.Model(&saasapi.TenantUpdatePolicy{}).Where("tenant_id = ?", "t_old").
		UpdateColumn("rollout_claimed_at", claimed).Error; err != nil {
		t.Fatal(err)
	}
	var old tenantUpdatePolicyFU6
	if err := g.First(&old, "tenant_id = ?", "t_old").Error; err != nil || old.ApprovedVersion == nil || *old.ApprovedVersion != version {
		t.Fatalf("previous model read %+v, %v", old, err)
	}
	old.AutoUpdate = true
	if err := g.Save(&old).Error; err != nil {
		t.Fatalf("previous model's Save: %v", err)
	}
	if err := g.First(&cur, "tenant_id = ?", "t_old").Error; err != nil || !cur.AutoUpdate ||
		cur.RolloutClaimedAt == nil || !cur.RolloutClaimedAt.Equal(claimed) {
		t.Fatalf("after the previous model's Save: %+v, %v", cur, err)
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
