// Package fleetcatalogtest is a SQLite stand-in for the two saas tables
// farmer reads the release catalog from (internal/fleetcatalog), for
// tests: an in-memory database with an attached "saas" database holding
// fleet_versions, fleet_release_checksums and tenant_update_policy in the
// columns
// internal/migrations/saas gives them, so the production queries'
// schema-qualified names resolve unchanged.
package fleetcatalogtest

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/yogzblr/imas/internal/fleetcatalog"
	"github.com/yogzblr/imas/internal/fleetsign"
)

// openSeq makes each Open's database its own, also under go test -count.
var openSeq atomic.Int64

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
	}, t.Name()) + fmt.Sprintf("-%d", openSeq.Add(1))
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
	exec(t, db, `CREATE TABLE saas.fleet_release_checksums (
		version varchar(64) PRIMARY KEY,
		checksums_txt mediumtext NOT NULL,
		checksums_sig text NOT NULL,
		created_at datetime NOT NULL)`)
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
	exec(t, db, `INSERT INTO saas.fleet_versions
		(id, version, os, arch, package_type, file_name, checksum_sha256, min_sprout_version, signature, revoked, released_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?)`,
		r.Version+"/"+r.OS+"/"+r.Arch+"/"+r.PackageType, r.Version, r.OS, r.Arch, r.PackageType, r.FileName,
		r.ChecksumSHA256, r.MinSproutVersion, r.Revoked, time.Now())
}

// AddChecksums stores version's checksums.txt and its base64 signature,
// as saasapi's release registration would.
func AddChecksums(t testing.TB, db *gorm.DB, version, checksumsTxt, checksumsSig string) {
	t.Helper()
	exec(t, db, `INSERT INTO saas.fleet_release_checksums (version, checksums_txt, checksums_sig, created_at) VALUES (?, ?, ?, ?)`,
		version, checksumsTxt, checksumsSig, time.Now())
}

// Approve sets tenantID's approved_version (nil: a policy row approving
// nothing).
func Approve(t testing.TB, db *gorm.DB, tenantID string, version *string) {
	t.Helper()
	exec(t, db, `INSERT INTO saas.tenant_update_policy (tenant_id, approved_version, auto_update) VALUES (?, ?, 0)`, tenantID, version)
}

// SetWindow sets tenantID's rollout window on its existing policy row, in
// UTC (nil writes NULL). Setting only one end writes the corrupt row
// saasapi's validation never would.
func SetWindow(t testing.TB, db *gorm.DB, tenantID string, start, end *time.Time) {
	t.Helper()
	utc := func(p *time.Time) any {
		if p == nil {
			return nil
		}
		return p.UTC()
	}
	exec(t, db, `UPDATE saas.tenant_update_policy SET rollout_window_start = ?, rollout_window_end = ? WHERE tenant_id = ?`,
		utc(start), utc(end), tenantID)
}

// WindowCase is one case of the rollout window rule
// (fleetcatalog.RolloutWindowClosed) at a fixed now.
type WindowCase struct {
	Name       string
	Start, End *time.Time // both nil: the policy sets no window
	Closed     bool       // a self_update now is refused rollout_window_closed
	// Corrupt: exactly one end is set. Both services refuse it as a
	// failed policy read (ErrCorruptRolloutWindow), never as no window.
	Corrupt bool
}

// WindowCases is the one table farmer's check (internal/natsapi) and
// saasapi's (policyRefusal) are both tested against, so the two rules
// can't drift. now should be on a whole millisecond:
// saas.tenant_update_policy stores datetime(3).
func WindowCases(now time.Time) []WindowCase {
	at := func(d time.Duration) *time.Time { t := now.Add(d); return &t }
	return []WindowCase{
		{Name: "no window"},
		{Name: "inside", Start: at(-time.Hour), End: at(time.Hour)},
		{Name: "before start", Start: at(time.Minute), End: at(time.Hour), Closed: true},
		{Name: "a millisecond before start", Start: at(time.Millisecond), End: at(time.Hour), Closed: true},
		{Name: "exactly at start", Start: at(0), End: at(time.Hour)},
		{Name: "a millisecond before end", Start: at(-time.Hour), End: at(time.Millisecond)},
		{Name: "exactly at end", Start: at(-time.Hour), End: at(0), Closed: true},
		{Name: "after end", Start: at(-2 * time.Hour), End: at(-time.Hour), Closed: true},
		// now would be inside either half-window: corrupt all the same.
		{Name: "only start set", Start: at(-time.Hour), Corrupt: true},
		{Name: "only end set", End: at(time.Hour), Corrupt: true},
	}
}

// Revoke marks every row of version revoked, as saasapi's revoke call does.
func Revoke(t testing.TB, db *gorm.DB, version string) {
	t.Helper()
	exec(t, db, `UPDATE saas.fleet_versions SET revoked = 1 WHERE version = ?`, version)
}

// Release returns a row for version on os/arch/packageType, named as
// fleetsign.ExpectedFileName names it.
func Release(t testing.TB, version, os, arch, packageType string) fleetcatalog.Row {
	t.Helper()
	name, err := fleetsign.ExpectedFileName(version, os, arch, packageType)
	if err != nil {
		t.Fatal(err)
	}
	return fleetcatalog.Row{
		Version:          version,
		OS:               os,
		Arch:             arch,
		PackageType:      packageType,
		FileName:         name,
		ChecksumSHA256:   strings.Repeat("ab", 32),
		MinSproutVersion: "v0.1.0",
	}
}

func exec(t testing.TB, db *gorm.DB, q string, args ...any) {
	t.Helper()
	if err := db.Exec(q, args...).Error; err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}
