package saasapi

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// openIsolatedTestDB opens a sqlite database of its own, deliberately not
// newTestDB's shared-cache one (which other tests reuse). GORM's logger is
// silenced: these tests expect constraint violations, and each one is
// asserted on directly.
func openIsolatedTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "saas.db")),
		&gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatalf("opening isolated test db: %v", err)
	}
	t.Cleanup(func() {
		if sqlDB, err := gdb.DB(); err == nil {
			sqlDB.Close()
		}
	})
	return gdb
}

func newLink(id, tenantID, sproutID, assetID string) AssetLink {
	return AssetLink{ID: id, TenantID: tenantID, SproutID: sproutID, AssetID: assetID, LinkedAt: time.Now().UTC()}
}

func TestOpenDBEmptyDSN(t *testing.T) {
	if _, err := OpenDB(""); err == nil {
		t.Error("expected an error for an empty DSN")
	}
}

// TestAssetLinkModelIndexes: AssetLink's tags make sprout_id unique per
// tenant only, and asset_id unique outright. The PXC schema's indexes come
// from internal/migrations, whose tests check that they match these tags
// and that saas migration 00002 drops the old single-column UNIQUE on
// sprout_id from a database that still has it.
func TestAssetLinkModelIndexes(t *testing.T) {
	gdb := openIsolatedTestDB(t)
	if err := migrateSchema(gdb); err != nil {
		t.Fatalf("migrateSchema: %v", err)
	}
	m := gdb.Migrator()
	for _, name := range []string{"idx_asset_links_sprout_id", "idx_asset_links_tenant_id"} {
		if m.HasIndex(&AssetLink{}, name) {
			t.Fatalf("schema has legacy index %s", name)
		}
	}
	for _, name := range []string{"idx_asset_links_tenant_sprout", "idx_asset_links_asset_id"} {
		if !m.HasIndex(&AssetLink{}, name) {
			t.Fatalf("schema lacks %s", name)
		}
	}
	for _, l := range []AssetLink{
		newLink("al_a", "t_a", "web-01", "asset_a"),
		newLink("al_b", "t_b", "web-01", "asset_b"),
	} {
		if err := gdb.Create(&l).Error; err != nil {
			t.Fatalf("linking %s's web-01: %v", l.TenantID, err)
		}
	}
	for name, dup := range map[string]AssetLink{
		"same tenant, same sprout":   newLink("al_c", "t_a", "web-01", "asset_c"),
		"asset_id in another tenant": newLink("al_d", "t_c", "web-02", "asset_a"),
	} {
		if err := gdb.Create(&dup).Error; err == nil {
			t.Fatalf("%s: schema accepted a duplicate", name)
		}
	}
}
