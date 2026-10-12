package farmer_test

// Tests for 00004_state_leases.sql and 00005_sprout_jwt_index.sql (P21
// slice 3). The MySQL ones are skipped unless IMAS_TEST_MYSQL_ROOT_DSN
// names a MySQL-compatible server by its root account, as for 00002.

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"

	"github.com/yogzblr/imas/internal/migrations"
	"github.com/yogzblr/imas/internal/migrations/mysqltest"
)

const (
	stateLeasesFile = "00004_state_leases.sql"
	sproutJWTFile   = "00005_sprout_jwt_index.sql"
)

// jobLeasesColumns and sproutJWTColumns are each table's columns as
// information_schema describes them on MySQL 8.
var jobLeasesColumns = map[string]string{
	"name":        "varchar(128) null=NO",
	"lease_owner": "varchar(128) null=YES",
	"lease_until": "datetime(3) null=YES",
	"last_run_at": "datetime(3) null=YES",
}

var sproutJWTColumns = map[string]string{
	"tenant_id":   "varchar(64) null=NO",
	"sprout_id":   "varchar(253) null=NO",
	"object_key":  "varchar(512) null=YES",
	"user_pubkey": "varchar(64) null=YES",
	"jwt_sha256":  "char(64) null=YES",
	"expires_at":  "datetime(3) null=YES",
	"lease_owner": "varchar(128) null=YES",
	"lease_until": "datetime(3) null=YES",
	"updated_at":  "datetime(3) null=NO",
}

// Both migrations are in the embedded set, only add, and are idempotent;
// no prepared_cooks migration exists (owner decision 2).
func TestStateLeasesMigrationShape(t *testing.T) {
	if migrations.Farmer.Latest() < 5 {
		t.Fatalf("farmer Latest = %d, want at least 5", migrations.Farmer.Latest())
	}
	// Expand only: a farmer built for schema 3 never touches these tables.
	if migrations.Farmer.CompatibleFrom() != 2 {
		t.Fatalf("farmer CompatibleFrom = %d, want 2", migrations.Farmer.CompatibleFrom())
	}
	for file, wants := range map[string][]string{
		stateLeasesFile: {
			"CREATE TABLE IF NOT EXISTS `job_leases`",
			"PRIMARY KEY (`name`)",
			"INSERT IGNORE INTO `job_leases` (`name`) VALUES ('jobs_expiry'), ('cohort_refresher');",
		},
		sproutJWTFile: {
			"CREATE TABLE IF NOT EXISTS `sprout_user_jwt`",
			"PRIMARY KEY (`tenant_id`,`sprout_id`)",
		},
	} {
		b, err := fs.ReadFile(migrations.Farmer.FS(), file)
		if err != nil {
			t.Fatalf("%s is not in the embedded farmer set: %v", file, err)
		}
		body := string(b)
		for _, want := range append(wants, "-- +goose Up") {
			if !strings.Contains(body, want) {
				t.Errorf("%s lacks %q", file, want)
			}
		}
		for _, bad := range []string{"DROP ", "-- +goose Down", "ALTER TABLE", "farmer.", "saas."} {
			if strings.Contains(body, bad) {
				t.Errorf("%s contains %q", file, bad)
			}
		}
	}
	names, err := fs.Glob(migrations.Farmer.FS(), "*prepared_cooks*")
	if err != nil || len(names) != 0 {
		t.Errorf("prepared_cooks migration %v, %v: owner decision 2 says not to build it", names, err)
	}
}

// newSchema creates an empty schema as root, dropped when the test ends,
// and returns a pool on it.
func newSchema(t *testing.T, prefix string) (*sql.DB, *mysql.Config) {
	t.Helper()
	cfg := mysqltest.RootConfig(t)
	sfx := make([]byte, 4)
	if _, err := rand.Read(sfx); err != nil {
		t.Fatal(err)
	}
	schema := prefix + hex.EncodeToString(sfx)
	cfg.DBName = ""
	root := open(t, cfg)
	if _, err := root.Exec("CREATE DATABASE `" + schema + "`"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Exec("DROP DATABASE IF EXISTS `" + schema + "`") })
	cfg = cfg.Clone()
	cfg.DBName, cfg.ParseTime = schema, true
	return open(t, cfg), cfg
}

// checkColumns compares a table's columns with want and its primary key
// with pk.
func checkColumns(t *testing.T, db *sql.DB, when, table string, want map[string]string, pk ...string) {
	t.Helper()
	ctx := context.Background()
	rows, err := db.QueryContext(ctx, `SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_KEY FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]string{}
	var gotPK []string
	for rows.Next() {
		var name, typ, null, key string
		if err := rows.Scan(&name, &typ, &null, &key); err != nil {
			t.Fatal(err)
		}
		got[name] = typ + " null=" + null
		if key == "PRI" {
			gotPK = append(gotPK, name)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for col, w := range want {
		if got[col] != w {
			t.Errorf("%s: %s.%s is %q, want %q", when, table, col, got[col], w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("%s: %s has columns %v, want %v", when, table, got, want)
	}
	if !slices.Equal(gotPK, pk) {
		t.Errorf("%s: %s primary key %v, want %v", when, table, gotPK, pk)
	}
}

// reRunFrom deletes goose's record of version v and later, as after a
// failure halfway, and runs up again: every one of those is re-applied.
func reRunFrom(t *testing.T, db *sql.DB, v int64) {
	t.Helper()
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, "DELETE FROM `"+migrations.VersionTable+"` WHERE version_id >= ?", v); err != nil {
		t.Fatal(err)
	}
	all, err := migrations.Versions(migrations.Farmer.FS())
	if err != nil {
		t.Fatal(err)
	}
	want := slices.DeleteFunc(all, func(x int64) bool { return x < v })
	res, err := migrations.Up(ctx, db, migrations.Farmer, t.Logf)
	if err != nil || !slices.Equal(res.Applied, want) {
		t.Fatalf("re-run from %d: %+v, %v; want %v applied", v, res, err, want)
	}
}

// On MySQL: job_leases exists with its seed rows; the row lease works as
// one conditional UPDATE; a re-run keeps the table, the seed rows and any
// lease held on them.
func TestMySQLStateLeases(t *testing.T) {
	db, _ := newSchema(t, "t_farmer_00004_")
	ctx := context.Background()
	if _, err := migrations.Up(ctx, db, migrations.Farmer, t.Logf); err != nil {
		t.Fatal(err)
	}
	seeds := func(when string) {
		t.Helper()
		checkColumns(t, db, when, "job_leases", jobLeasesColumns, "name")
		var got []string
		rows, err := db.QueryContext(ctx, "SELECT name FROM job_leases ORDER BY name")
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var n string
			rows.Scan(&n)
			got = append(got, n)
		}
		rows.Close()
		if !slices.Equal(got, []string{"cohort_refresher", "jobs_expiry"}) {
			t.Errorf("%s: job_leases rows %v", when, got)
		}
	}
	seeds("after up")

	// The acquire statement of the brief (§2): a free lease is taken, a
	// held one is not, an expired one is taken over.
	const acquire = `UPDATE job_leases SET lease_owner = ?, lease_until = NOW(3) + INTERVAL ? SECOND
		WHERE name = ? AND (lease_owner IS NULL OR lease_until < NOW(3) OR lease_owner = ?)`
	take := func(owner string, secs int) int64 {
		t.Helper()
		r, err := db.ExecContext(ctx, acquire, owner, secs, "jobs_expiry", owner)
		if err != nil {
			t.Fatal(err)
		}
		n, _ := r.RowsAffected()
		return n
	}
	if n := take("replica-a", 120); n != 1 {
		t.Fatalf("free lease: %d rows", n)
	}
	if n := take("replica-b", 120); n != 0 {
		t.Fatalf("held lease taken by another replica: %d rows", n)
	}
	if _, err := db.ExecContext(ctx, "UPDATE job_leases SET lease_until = NOW(3) - INTERVAL 1 SECOND WHERE name = 'jobs_expiry'"); err != nil {
		t.Fatal(err)
	}
	if n := take("replica-b", 120); n != 1 {
		t.Fatalf("expired lease: %d rows", n)
	}
	if _, err := db.ExecContext(ctx, "INSERT IGNORE INTO job_leases (name) VALUES ('pushall:t_0123456789abcdef0123456789ab')"); err != nil {
		t.Fatalf("on-demand pushall row: %v", err)
	}

	reRunFrom(t, db, 4)
	var owner sql.NullString
	if err := db.QueryRowContext(ctx, "SELECT lease_owner FROM job_leases WHERE name = 'jobs_expiry'").Scan(&owner); err != nil || owner.String != "replica-b" {
		t.Fatalf("re-run changed a held lease: %v, %v", owner, err)
	}
	if _, err := db.ExecContext(ctx, "DELETE FROM job_leases WHERE name LIKE 'pushall:%'"); err != nil {
		t.Fatal(err)
	}
	seeds("after a re-run")
}

// On MySQL: sprout_user_jwt is keyed on (tenant_id, sprout_id), so one
// sprout ID in two tenants is two rows and a second row for one sprout is
// refused; the longest sprout ID and object key fit; a re-run changes
// nothing.
func TestMySQLSproutUserJWT(t *testing.T) {
	db, _ := newSchema(t, "t_farmer_00005_")
	ctx := context.Background()
	if _, err := migrations.Up(ctx, db, migrations.Farmer, t.Logf); err != nil {
		t.Fatal(err)
	}
	checkColumns(t, db, "after up", "sprout_user_jwt", sproutJWTColumns, "tenant_id", "sprout_id")

	const ins = `INSERT INTO sprout_user_jwt (tenant_id, sprout_id, object_key, user_pubkey, jwt_sha256, updated_at)
		VALUES (?, ?, ?, ?, ?, NOW(3))`
	sum := strings.Repeat("a", 64)
	key := func(tenant, sprout string) string { return tenant + "/" + sprout + "/" + sum + ".jwt" }
	for _, tenant := range []string{"t_a", "t_b"} {
		if _, err := db.ExecContext(ctx, ins, tenant, "web", key(tenant, "web"), "UPUB", sum); err != nil {
			t.Fatalf("sprout web in %s: %v", tenant, err)
		}
	}
	if _, err := db.ExecContext(ctx, ins, "t_a", "web", key("t_a", "web"), "UPUB2", sum); mysqlErrNumber(err) != 1062 {
		t.Errorf("second row for (t_a, web): %v, want a duplicate-key error", err)
	}
	tenant, long := strings.Repeat("t", 32), strings.Repeat("s", 253)
	if _, err := db.ExecContext(ctx, ins, tenant, long, key(tenant, long), "UPUB", sum); err != nil {
		t.Errorf("longest sprout ID and object key: %v", err)
	}

	// A new sprout's first mint (brief §4.2 step 2): the row is inserted
	// with its key only, before the JWT exists, then the lease is taken
	// with one conditional UPDATE. Two replicas: both inserts succeed (the
	// second is ignored), one lease wins.
	for range 2 {
		if _, err := db.ExecContext(ctx, "INSERT IGNORE INTO sprout_user_jwt (tenant_id, sprout_id) VALUES ('t_a', 'new')"); err != nil {
			t.Fatalf("pending row: %v", err)
		}
	}
	const acquire = `UPDATE sprout_user_jwt SET lease_owner = ?, lease_until = NOW(3) + INTERVAL 30 SECOND
		WHERE tenant_id = 't_a' AND sprout_id = 'new' AND (lease_owner IS NULL OR lease_until < NOW(3) OR lease_owner = ?)`
	for _, c := range []struct {
		owner string
		want  int64
	}{{"replica-a", 1}, {"replica-b", 0}} {
		r, err := db.ExecContext(ctx, acquire, c.owner, c.owner)
		if err != nil {
			t.Fatal(err)
		}
		if n, _ := r.RowsAffected(); n != c.want {
			t.Errorf("%s taking the mint lease: %d rows, want %d", c.owner, n, c.want)
		}
	}
	var pub sql.NullString
	var updated sql.NullTime
	if err := db.QueryRowContext(ctx, "SELECT user_pubkey, updated_at FROM sprout_user_jwt WHERE tenant_id = 't_a' AND sprout_id = 'new'").Scan(&pub, &updated); err != nil ||
		pub.Valid || !updated.Valid {
		t.Errorf("pending row: user_pubkey %v, updated_at %v, %v; want NULL and set", pub, updated, err)
	}

	reRunFrom(t, db, 5)
	checkColumns(t, db, "after a re-run", "sprout_user_jwt", sproutJWTColumns, "tenant_id", "sprout_id")
	var n int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sprout_user_jwt").Scan(&n); err != nil || n != 4 {
		t.Fatalf("rows after a re-run: %d, %v", n, err)
	}
}
