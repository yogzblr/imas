// Package fleetcatalogtest is a SQLite stand-in for the two saas tables
// farmer reads the release catalog from (internal/fleetcatalog), for
// tests: an in-memory database with an attached "saas" database holding
// fleet_versions and tenant_update_policy in the columns
// internal/migrations/saas gives them, so the production queries'
// schema-qualified names resolve unchanged.
package fleetcatalogtest

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/yogzblr/imas/internal/fleetcatalog"
	"github.com/yogzblr/imas/internal/fleetsign"
)

// Open returns the database, closed when t ends. One connection: ATTACH
// is per-connection.
func Open(t testing.TB) *gorm.DB {
	t.Helper()
	// Only [A-Za-z0-9_-]: the name ends up inside an SQL string literal.
	name := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' {
			return r
		}
		return '_'
	}, t.Name())
	db, err := gorm.Open(sqlite.Open("file:"+name+"-fc?mode=memory&cache=shared"),
		&gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { sqlDB.Close() })
	exec(t, db, `ATTACH DATABASE 'file:`+name+`-fc-saas?mode=memory&cache=shared' AS saas`)
	exec(t, db, `CREATE TABLE saas.fleet_versions (
		id varchar(32) PRIMARY KEY,
		version varchar(64) NOT NULL,
		os varchar(32) NOT NULL,
		arch varchar(32) NOT NULL,
		package_type varchar(16) NOT NULL,
		file_name varchar(255) NOT NULL,
		checksum_sha256 varchar(64) NOT NULL,
		min_sprout_version varchar(64) NOT NULL,
		signature varchar(128) NOT NULL DEFAULT '',
		revoked tinyint(1) NOT NULL DEFAULT 0,
		released_at datetime NOT NULL,
		notes text,
		UNIQUE (version, os, arch, package_type))`)
	exec(t, db, `CREATE TABLE saas.tenant_update_policy (
		tenant_id varchar(32) PRIMARY KEY,
		approved_version varchar(64) DEFAULT NULL,
		auto_update tinyint(1) NOT NULL DEFAULT 0,
		rollout_window_start datetime DEFAULT NULL,
		rollout_window_end datetime DEFAULT NULL,
		updated_at datetime DEFAULT NULL)`)
	return db
}

// AddRow inserts r, as saasapi's release registration would.
func AddRow(t testing.TB, db *gorm.DB, r fleetcatalog.Row) {
	t.Helper()
	m := r.Manifest
	exec(t, db, `INSERT INTO saas.fleet_versions
		(id, version, os, arch, package_type, file_name, checksum_sha256, min_sprout_version, signature, revoked, released_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.Version+"/"+m.OS+"/"+m.Arch+"/"+r.PackageType, m.Version, m.OS, m.Arch, r.PackageType, m.FileName,
		m.ChecksumSHA256, m.MinSproutVersion, m.Signature, r.Revoked, time.Now())
}

// Approve sets tenantID's approved_version (nil: a policy row approving
// nothing).
func Approve(t testing.TB, db *gorm.DB, tenantID string, version *string) {
	t.Helper()
	exec(t, db, `INSERT INTO saas.tenant_update_policy (tenant_id, approved_version, auto_update) VALUES (?, ?, 0)`, tenantID, version)
}

// Revoke marks every row of version revoked, as saasapi's revoke call does.
func Revoke(t testing.TB, db *gorm.DB, version string) {
	t.Helper()
	exec(t, db, `UPDATE saas.fleet_versions SET revoked = 1 WHERE version = ?`, version)
}

// Signed returns a row for version on os/arch/packageType, signed by priv
// as key version 1.
func Signed(t testing.TB, priv ed25519.PrivateKey, version, os, arch, packageType string) fleetcatalog.Row {
	t.Helper()
	m := fleetsign.Manifest{
		Version:          version,
		OS:               os,
		Arch:             arch,
		FileName:         "imas-sprout_" + strings.TrimPrefix(version, "v") + "_" + os + "_" + arch + "." + packageType,
		ChecksumSHA256:   strings.Repeat("ab", 32),
		MinSproutVersion: "v0.1.0",
	}
	msg, err := m.Message()
	if err != nil {
		t.Fatal(err)
	}
	m.Signature = fleetsign.EncodeSignature(1, ed25519.Sign(priv, msg))
	return fleetcatalog.Row{Manifest: m, PackageType: packageType}
}

func exec(t testing.TB, db *gorm.DB, q string, args ...any) {
	t.Helper()
	if err := db.Exec(q, args...).Error; err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}
