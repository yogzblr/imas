package migrations

// Tests against a real MySQL-compatible server, skipped unless
// IMAS_TEST_MYSQL_ROOT_DSN names one by its root account, e.g. a
// single-node PXC like the one deploy/helm/farmer runs:
//
//	docker run -d --name pxc -p 3306:3306 -e MYSQL_ROOT_PASSWORD=pw \
//	  percona/percona-xtradb-cluster:8.4.8-8.1
//	IMAS_TEST_MYSQL_ROOT_DSN='root:pw@tcp(127.0.0.1:3306)/' go test ./internal/migrations/ ./cmd/migrate/
//
// Each test makes its own schemas and users, named with a random suffix,
// and drops them afterwards.

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/yogzblr/imas/internal/pxc"
	"github.com/yogzblr/imas/internal/saasapi"
)

const envRootDSN = "IMAS_TEST_MYSQL_ROOT_DSN"

func rootConfig(t *testing.T) *mysql.Config {
	t.Helper()
	dsn := os.Getenv(envRootDSN)
	if dsn == "" {
		t.Skipf("%s not set; skipping the MySQL tests", envRootDSN)
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("%s: not a valid DSN", envRootDSN)
	}
	cfg.DBName = ""
	cfg.InterpolateParams = true
	return cfg
}

func openConfig(t *testing.T, cfg *mysql.Config) *sql.DB {
	t.Helper()
	c, err := mysql.NewConnector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(c)
	t.Cleanup(func() { db.Close() })
	return db
}

func suffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// mysqlEnv is one test's schemas and users on the server.
type mysqlEnv struct {
	rootCfg *mysql.Config
	root    *sql.DB
	accts   Accounts
}

func newMySQLEnv(t *testing.T) *mysqlEnv {
	t.Helper()
	rc := rootConfig(t)
	s := suffix(t)
	e := &mysqlEnv{rootCfg: rc, root: openConfig(t, rc), accts: Accounts{
		Farmer: Account{Schema: "t_farmer_" + s, User: "t_farmer_" + s, Password: "f'pw\\\"; -- " + s},
		Saas:   Account{Schema: "t_saas_" + s, User: "t_saas_" + s, Password: "s-pw-" + s},
	}}
	t.Cleanup(func() {
		ctx := context.Background()
		for _, a := range []Account{e.accts.Farmer, e.accts.Saas} {
			e.root.ExecContext(ctx, "DROP DATABASE IF EXISTS `"+a.Schema+"`")
			e.root.ExecContext(ctx, "DROP USER IF EXISTS "+userSpec(a.User))
		}
	})
	return e
}

// as connects as acct's user to acct's schema.
func (e *mysqlEnv) as(t *testing.T, acct Account) *sql.DB {
	t.Helper()
	cfg := e.rootCfg.Clone()
	cfg.User, cfg.Passwd, cfg.DBName, cfg.InterpolateParams = acct.User, acct.Password, acct.Schema, false
	return openConfig(t, cfg)
}

// schemaDB connects as root to a scratch schema (created, and dropped
// afterwards), for tests about DDL rather than privileges.
func (e *mysqlEnv) schemaDB(t *testing.T, name string) *sql.DB {
	t.Helper()
	if _, err := e.root.Exec("CREATE DATABASE `" + name + "`"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.root.Exec("DROP DATABASE IF EXISTS `" + name + "`") })
	cfg := e.rootCfg.Clone()
	cfg.DBName = name
	return openConfig(t, cfg)
}

func (e *mysqlEnv) gormDB(t *testing.T, schema string) *gorm.DB {
	t.Helper()
	cfg := e.rootCfg.Clone()
	cfg.DBName, cfg.ParseTime = schema, true
	g, err := gorm.Open(gormmysql.Open(cfg.FormatDSN()), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if d, err := g.DB(); err == nil {
			d.Close()
		}
	})
	return g
}

// migrateAll is `migrate up` minus the lock: root step, both sets as
// their owners, column grant.
func (e *mysqlEnv) migrateAll(t *testing.T) (farmer, saas UpResult) {
	t.Helper()
	ctx := context.Background()
	if err := Bootstrap(ctx, e.root, e.accts); err != nil {
		t.Fatal(err)
	}
	var err error
	if farmer, err = Up(ctx, e.as(t, e.accts.Farmer), Farmer, t.Logf); err != nil {
		t.Fatal(err)
	}
	if saas, err = Up(ctx, e.as(t, e.accts.Saas), Saas, t.Logf); err != nil {
		t.Fatal(err)
	}
	if err := GrantEnrollmentKeyColumns(ctx, e.root, e.accts); err != nil {
		t.Fatal(err)
	}
	return farmer, saas
}

func mysqlErrNumber(err error) uint16 {
	var me *mysql.MySQLError
	if errors.As(err, &me) {
		return me.Number
	}
	return 0
}

func TestMySQLUpFreshAndAgain(t *testing.T) {
	e := newMySQLEnv(t)
	f, s := e.migrateAll(t)
	if f.From != 0 || f.To != Farmer.Latest() || int64(len(f.Applied)) != Farmer.Latest() {
		t.Fatalf("farmer: %+v", f)
	}
	if s.From != 0 || s.To != Saas.Latest() || int64(len(s.Applied)) != Saas.Latest() {
		t.Fatalf("saas: %+v", s)
	}

	// Everything again: nothing to apply, nothing fails.
	f, s = e.migrateAll(t)
	if len(f.Applied)+len(s.Applied) != 0 {
		t.Fatalf("second run applied %v and %v", f.Applied, s.Applied)
	}

	for _, c := range []struct {
		acct Account
		set  Set
	}{{e.accts.Farmer, Farmer}, {e.accts.Saas, Saas}} {
		st, err := ReadState(context.Background(), e.as(t, c.acct))
		if err != nil {
			t.Fatal(err)
		}
		if st != (State{Version: c.set.Latest(), Floor: c.set.CompatibleFrom()}) {
			t.Fatalf("%s: state %+v", c.set.Name(), st)
		}
		if err := c.set.Check(st); err != nil {
			t.Fatal(err)
		}
	}
}

// TestMySQLGrants: single writer per schema, with exactly the one
// column-level exception (§4.1, §3.3).
func TestMySQLGrants(t *testing.T) {
	e := newMySQLEnv(t)
	e.migrateAll(t)
	ctx := context.Background()
	f, s := e.accts.Farmer, e.accts.Saas
	farmer, saas := e.as(t, f), e.as(t, s)

	if _, err := saas.ExecContext(ctx, "INSERT INTO enrollment_keys (key_id, tenant_id, key_hash, expiry, max_uses) VALUES ('k1', 't1', 'h', NOW() + INTERVAL 1 DAY, 3)"); err != nil {
		t.Fatalf("saas writing its own schema: %v", err)
	}
	if _, err := farmer.ExecContext(ctx, "INSERT INTO props (tenant_id, sprout_id, name, expiry) VALUES ('t1', 's1', 'p', NOW())"); err != nil {
		t.Fatalf("farmer writing its own schema: %v", err)
	}
	for _, q := range []string{
		"SELECT COUNT(*) FROM `" + s.Schema + "`.tenants",
		"SELECT key_hash FROM `" + s.Schema + "`.enrollment_keys",
	} {
		if _, err := farmer.ExecContext(ctx, q); err != nil {
			t.Fatalf("farmer reading saas: %s: %v", q, err)
		}
	}
	if _, err := saas.ExecContext(ctx, "SELECT COUNT(*) FROM `"+f.Schema+"`.pki_nkeys"); err != nil {
		t.Fatalf("saas reading farmer: %v", err)
	}

	r, err := farmer.ExecContext(ctx, "UPDATE `"+s.Schema+"`.enrollment_keys SET used_count = used_count + 1, last_used_at = NOW() WHERE key_id = 'k1' AND used_count < max_uses")
	if err != nil {
		t.Fatalf("farmer redeeming an enrollment key: %v", err)
	}
	if n, _ := r.RowsAffected(); n != 1 {
		t.Fatalf("redemption updated %d rows", n)
	}

	const denied = 1142 // ER_TABLEACCESS_DENIED_ERROR
	const colDenied = 1143
	for who, q := range map[string]struct {
		db  *sql.DB
		sql string
	}{
		"farmer inserting into saas":      {farmer, "INSERT INTO `" + s.Schema + "`.tenants (id, name, status) VALUES ('t', 't', 'x')"},
		"farmer deleting from saas":       {farmer, "DELETE FROM `" + s.Schema + "`.enrollment_keys"},
		"farmer updating key_hash":        {farmer, "UPDATE `" + s.Schema + "`.enrollment_keys SET key_hash = 'x'"},
		"farmer updating revoked":         {farmer, "UPDATE `" + s.Schema + "`.enrollment_keys SET revoked = 0"},
		"farmer altering saas":            {farmer, "ALTER TABLE `" + s.Schema + "`.tenants ADD COLUMN x int"},
		"saas inserting into farmer":      {saas, "INSERT INTO `" + f.Schema + "`.props (tenant_id, sprout_id, name, expiry) VALUES ('a', 'b', 'c', NOW())"},
		"saas updating farmer":            {saas, "UPDATE `" + f.Schema + "`.pki_nkeys SET state = 'x'"},
		"saas dropping a farmer table":    {saas, "DROP TABLE `" + f.Schema + "`.props"},
		"saas writing farmer's lock":      {saas, "DELETE FROM `" + f.Schema + "`." + LockTable},
		"farmer writing saas's versions":  {farmer, "DELETE FROM `" + s.Schema + "`." + VersionTable},
		"farmer raising saas's floor":     {farmer, "UPDATE `" + s.Schema + "`." + InfoTable + " SET min_compatible_version = 99"},
		"saas granting itself on farmer":  {saas, "GRANT INSERT ON `" + f.Schema + "`.* TO " + userSpec(s.User)},
		"farmer granting itself on saas.": {farmer, "GRANT INSERT ON `" + s.Schema + "`.* TO " + userSpec(f.User)},
	} {
		_, err := q.db.ExecContext(ctx, q.sql)
		if n := mysqlErrNumber(err); err == nil || (n != denied && n != colDenied && n != 1044 && n != 1045 && n != 1410) {
			t.Errorf("%s: got %v, want access denied", who, err)
		}
	}
}

// TestMySQLBaselineMatchesGORMModels: the baseline creates exactly the
// tables, columns and indexes AutoMigrate creates from today's models, so
// it's a no-op on any install AutoMigrate kept current.
func TestMySQLBaselineMatchesGORMModels(t *testing.T) {
	e := newMySQLEnv(t)
	s := suffix(t)
	for _, c := range []struct {
		set    Set
		models []any
	}{{Farmer, pxc.Models()}, {Saas, saasapi.Models()}} {
		t.Run(c.set.Name(), func(t *testing.T) {
			viaGoose := "t_goose_" + c.set.Name() + "_" + s
			viaGORM := "t_gorm_" + c.set.Name() + "_" + s
			if _, err := Up(context.Background(), e.schemaDB(t, viaGoose), c.set, t.Logf); err != nil {
				t.Fatal(err)
			}
			e.schemaDB(t, viaGORM)
			if err := e.gormDB(t, viaGORM).AutoMigrate(c.models...); err != nil {
				t.Fatal(err)
			}
			want := describeSchema(t, e.root, viaGORM)
			got := describeSchema(t, e.root, viaGoose)
			for _, own := range []string{VersionTable, InfoTable} {
				got = slices.DeleteFunc(got, func(l string) bool { return strings.HasPrefix(l, own+" ") })
			}
			if d := diffLines(want, got); d != "" {
				t.Fatalf("baseline differs from GORM AutoMigrate (- GORM, + baseline):\n%s", d)
			}
		})
	}
}

// describeSchema lists every column (type, nullability, default, extra)
// and every index column of schema's tables, one sorted line each.
func describeSchema(t *testing.T, root *sql.DB, schema string) []string {
	t.Helper()
	var out []string
	rows, err := root.Query(`SELECT TABLE_NAME, COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COALESCE(COLUMN_DEFAULT, 'NULL'), EXTRA,
		CHARACTER_SET_NAME, COLLATION_NAME
		FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = ?`, schema)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var tbl, col, typ, null, def, extra string
		var cs, coll sql.NullString
		if err := rows.Scan(&tbl, &col, &typ, &null, &def, &extra, &cs, &coll); err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprintf("%s column %s %s null=%s default=%s extra=%q charset=%s/%s", tbl, col, typ, null, def, extra, cs.String, coll.String))
	}
	rows.Close()
	rows, err = root.Query(`SELECT TABLE_NAME, INDEX_NAME, NON_UNIQUE, SEQ_IN_INDEX, COLUMN_NAME
		FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = ?`, schema)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var tbl, idx, col string
		var nonUnique, seq int
		if err := rows.Scan(&tbl, &idx, &nonUnique, &seq, &col); err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprintf("%s index %s non_unique=%d %d:%s", tbl, idx, nonUnique, seq, col))
	}
	rows.Close()
	rows, err = root.Query(`SELECT TABLE_NAME, ENGINE, TABLE_COLLATION FROM information_schema.TABLES WHERE TABLE_SCHEMA = ?`, schema)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var tbl, engine, coll string
		if err := rows.Scan(&tbl, &engine, &coll); err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprintf("%s table engine=%s collation=%s", tbl, engine, coll))
	}
	rows.Close()
	slices.Sort(out)
	return out
}

func diffLines(want, got []string) string {
	var b strings.Builder
	for _, l := range want {
		if !slices.Contains(got, l) {
			fmt.Fprintf(&b, "- %s\n", l)
		}
	}
	for _, l := range got {
		if !slices.Contains(want, l) {
			fmt.Fprintf(&b, "+ %s\n", l)
		}
	}
	return b.String()
}

// TestMySQLExistingInstall: an install AutoMigrate created before
// cmd/migrate existed, including asset_links' two legacy indexes, keeps
// its data, gets every migration recorded, and loses those indexes.
func TestMySQLExistingInstall(t *testing.T) {
	e := newMySQLEnv(t)
	ctx := context.Background()
	if err := Bootstrap(ctx, e.root, e.accts); err != nil {
		t.Fatal(err)
	}
	f, s := e.accts.Farmer, e.accts.Saas
	if err := e.gormDB(t, f.Schema).AutoMigrate(pxc.Models()...); err != nil {
		t.Fatal(err)
	}
	gs := e.gormDB(t, s.Schema)
	if err := gs.AutoMigrate(saasapi.Models()...); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"CREATE UNIQUE INDEX idx_asset_links_sprout_id ON `" + s.Schema + "`.asset_links (sprout_id)",
		"CREATE INDEX idx_asset_links_tenant_id ON `" + s.Schema + "`.asset_links (tenant_id)",
		"INSERT INTO `" + s.Schema + "`.asset_links (id, tenant_id, sprout_id, asset_id, linked_at) VALUES ('al_a', 't_a', 'web-01', 'asset_a', NOW())",
		"INSERT INTO `" + f.Schema + "`.pki_nkeys (tenant_id, sprout_id, nkey, state) VALUES ('t_a', 'web-01', 'UNKEY', 'accepted')",
	} {
		if _, err := e.root.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	// The defect the legacy index causes.
	if _, err := e.root.ExecContext(ctx, "INSERT INTO `"+s.Schema+"`.asset_links (id, tenant_id, sprout_id, asset_id, linked_at) VALUES ('al_b', 't_b', 'web-01', 'asset_b', NOW())"); mysqlErrNumber(err) != 1062 {
		t.Fatalf("legacy schema accepted a second tenant's web-01 (%v); the defect didn't reproduce", err)
	}

	fr, sr := e.migrateAll(t)
	if fr.To != Farmer.Latest() || sr.To != Saas.Latest() {
		t.Fatalf("migrated to %d and %d", fr.To, sr.To)
	}

	var n int
	if err := e.root.QueryRowContext(ctx, "SELECT COUNT(*) FROM `"+f.Schema+"`.pki_nkeys").Scan(&n); err != nil || n != 1 {
		t.Fatalf("farmer's row: %d, %v", n, err)
	}
	if err := e.root.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'asset_links' AND INDEX_NAME IN ('idx_asset_links_sprout_id', 'idx_asset_links_tenant_id')", s.Schema).Scan(&n); err != nil || n != 0 {
		t.Fatalf("legacy indexes left: %d, %v", n, err)
	}
	if _, err := e.root.ExecContext(ctx, "INSERT INTO `"+s.Schema+"`.asset_links (id, tenant_id, sprout_id, asset_id, linked_at) VALUES ('al_b', 't_b', 'web-01', 'asset_b', NOW())"); err != nil {
		t.Fatalf("after migrating, tenant B couldn't link its own web-01: %v", err)
	}
	if _, err := e.root.ExecContext(ctx, "INSERT INTO `"+s.Schema+"`.asset_links (id, tenant_id, sprout_id, asset_id, linked_at) VALUES ('al_c', 't_a', 'web-01', 'asset_c', NOW())"); mysqlErrNumber(err) != 1062 {
		t.Fatalf("(tenant_id, sprout_id) no longer unique: %v", err)
	}
}

// TestMySQLReadStateChangesNothing: what `migrate check` and the services
// run creates no table, even on an empty schema.
func TestMySQLReadStateChangesNothing(t *testing.T) {
	e := newMySQLEnv(t)
	name := "t_empty_" + suffix(t)
	db := e.schemaDB(t, name)
	st, err := ReadState(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if st != (State{}) {
		t.Fatalf("empty schema reads as %+v", st)
	}
	var n int
	if err := e.root.QueryRow("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = ?", name).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d tables after ReadState (%v)", n, err)
	}
	if err := Farmer.Check(st); !errors.Is(err, ErrSchemaBehind) {
		t.Fatalf("Check on an empty schema: %v", err)
	}
}

// TestMySQLAheadAndTooNew: a schema migrated by a newer binary that still
// supports this one is left alone; one whose floor excludes this binary
// is refused by Up as well as Check.
func TestMySQLAheadAndTooNew(t *testing.T) {
	e := newMySQLEnv(t)
	ctx := context.Background()
	db := e.schemaDB(t, "t_ahead_"+suffix(t))
	if _, err := Up(ctx, db, Farmer, t.Logf); err != nil {
		t.Fatal(err)
	}
	next := Farmer.Latest() + 1
	if _, err := db.ExecContext(ctx, "INSERT INTO `"+VersionTable+"` (version_id, is_applied) VALUES (?, 1)", next); err != nil {
		t.Fatal(err)
	}
	res, err := Up(ctx, db, Farmer, t.Logf)
	if err != nil || len(res.Applied) != 0 || res.From != next {
		t.Fatalf("Up on a schema ahead: %+v, %v", res, err)
	}
	st, _ := ReadState(ctx, db)
	if err := Farmer.Check(st); err != nil {
		t.Fatalf("Check on a schema ahead that still supports this binary: %v", err)
	}

	if _, err := db.ExecContext(ctx, "UPDATE `"+InfoTable+"` SET min_compatible_version = ? WHERE id = 1", next); err != nil {
		t.Fatal(err)
	}
	st, _ = ReadState(ctx, db)
	if err := Farmer.Check(st); !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("Check: %v, want ErrSchemaTooNew", err)
	}
	if _, err := Up(ctx, db, Farmer, t.Logf); !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("Up: %v, want ErrSchemaTooNew", err)
	}
	// The floor never drops.
	if err := raiseFloor(ctx, db, 1); err != nil {
		t.Fatal(err)
	}
	if st, _ := ReadState(ctx, db); st.Floor != next {
		t.Fatalf("floor lowered to %d", st.Floor)
	}
}

// TestMySQLBootstrapPasswords: awkward passwords survive the round trip,
// and a re-run with a new password rotates it.
func TestMySQLBootstrapPasswords(t *testing.T) {
	e := newMySQLEnv(t)
	ctx := context.Background()
	if err := Bootstrap(ctx, e.root, e.accts); err != nil {
		t.Fatal(err)
	}
	if err := e.as(t, e.accts.Farmer).PingContext(ctx); err != nil {
		t.Fatalf("logging in with %q: %v", e.accts.Farmer.Password, err)
	}
	old := e.accts.Farmer
	e.accts.Farmer.Password = "rotated-" + suffix(t)
	if err := Bootstrap(ctx, e.root, e.accts); err != nil {
		t.Fatal(err)
	}
	if err := e.as(t, e.accts.Farmer).PingContext(ctx); err != nil {
		t.Fatalf("new password: %v", err)
	}
	if err := e.as(t, old).PingContext(ctx); mysqlErrNumber(err) != 1045 {
		t.Fatalf("old password still works (%v)", err)
	}
}

// TestMySQLBootstrapErrorsCarryNoPassword: a refused CREATE USER (here,
// root without the privilege to create users) reports its error without
// the server's message.
func TestMySQLBootstrapErrorsCarryNoPassword(t *testing.T) {
	e := newMySQLEnv(t)
	ctx := context.Background()
	// A user that can create schemas but not users.
	lim := Account{User: "t_lim_" + suffix(t), Password: "lim-pw"}
	if _, err := e.root.ExecContext(ctx, "CREATE USER "+userSpec(lim.User)+" IDENTIFIED BY ?", lim.Password); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.root.Exec("DROP USER IF EXISTS " + userSpec(lim.User)) })
	if _, err := e.root.ExecContext(ctx, "GRANT CREATE ON *.* TO "+userSpec(lim.User)); err != nil {
		t.Fatal(err)
	}
	cfg := e.rootCfg.Clone()
	cfg.User, cfg.Passwd = lim.User, lim.Password
	err := Bootstrap(ctx, openConfig(t, cfg), e.accts)
	if err == nil {
		t.Fatal("a user without CREATE USER bootstrapped")
	}
	for _, pw := range []string{e.accts.Farmer.Password, e.accts.Saas.Password} {
		if strings.Contains(err.Error(), pw) {
			t.Fatalf("error carries a password: %v", err)
		}
	}
	if !strings.Contains(err.Error(), "message withheld") {
		t.Fatalf("error from a password statement wasn't redacted: %v", err)
	}
}

// TestMySQLLock exercises the lock's SQL: exclusion, release, takeover
// after a lapsed lease, and losing the lock to another run.
func TestMySQLLock(t *testing.T) {
	e := newMySQLEnv(t)
	ctx := context.Background()
	db := e.schemaDB(t, "t_lock_"+suffix(t))
	opts := LockOptions{Lease: 900 * time.Millisecond, Wait: 200 * time.Millisecond, Poll: 50 * time.Millisecond}

	a, ctxA, err := AcquireLock(ctx, db, opts, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := AcquireLock(ctx, db, opts, t.Logf); !errors.Is(err, ErrLockHeld) {
		t.Fatalf("second run: %v, want ErrLockHeld", err)
	}
	// Outlive a's lease: its heartbeat keeps it.
	time.Sleep(2 * opts.Lease)
	if _, _, err := AcquireLock(ctx, db, opts, t.Logf); !errors.Is(err, ErrLockHeld) {
		t.Fatalf("second run after a lease: %v, want ErrLockHeld", err)
	}
	if ctxA.Err() != nil {
		t.Fatalf("holder lost the lock: %v", context.Cause(ctxA))
	}
	if err := a.Release(ctx); err != nil {
		t.Fatal(err)
	}
	b, ctxB, err := AcquireLock(ctx, db, opts, t.Logf)
	if err != nil {
		t.Fatalf("after release: %v", err)
	}

	// Another run takes the row (as a takeover after a stall would).
	if _, err := db.ExecContext(ctx, "UPDATE `"+LockTable+"` SET owner = 'thief' WHERE id = 1"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctxB.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("holder didn't notice losing the lock")
	}
	if !LockLost(ctxB) {
		t.Fatalf("cause %v", context.Cause(ctxB))
	}
	b.Release(ctx) // mustn't delete the thief's row
	var owner string
	if err := db.QueryRowContext(ctx, "SELECT owner FROM `"+LockTable+"` WHERE id = 1").Scan(&owner); err != nil || owner != "thief" {
		t.Fatalf("after the loser's release: owner %q, %v", owner, err)
	}

	// The thief "crashes": its lease lapses and the next run takes over.
	if _, err := db.ExecContext(ctx, "UPDATE `"+LockTable+"` SET expires_at = NOW(6) - INTERVAL 1 SECOND WHERE id = 1"); err != nil {
		t.Fatal(err)
	}
	c, _, err := AcquireLock(ctx, db, opts, t.Logf)
	if err != nil {
		t.Fatalf("takeover of a lapsed lease: %v", err)
	}
	c.Release(ctx)
}

// TestMySQLLockRace: of many runs racing for a free lock, one wins.
func TestMySQLLockRace(t *testing.T) {
	e := newMySQLEnv(t)
	ctx := context.Background()
	db := e.schemaDB(t, "t_race_"+suffix(t))
	store := mysqlLockStore{db}
	if err := store.ensure(ctx); err != nil {
		t.Fatal(err)
	}
	const runs = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	var winners []string
	start := make(chan struct{})
	for i := range runs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			owner := fmt.Sprintf("run-%d", i)
			ok, err := store.tryAcquire(ctx, owner, time.Minute)
			if err != nil {
				t.Errorf("%s: %v", owner, err)
			}
			if ok {
				mu.Lock()
				winners = append(winners, owner)
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	if len(winners) != 1 {
		t.Fatalf("winners %v, want exactly one", winners)
	}
	owner, _, err := store.holder(ctx)
	if err != nil || owner != winners[0] {
		t.Fatalf("holder %q (%v), winner %s", owner, err, winners[0])
	}
}

// TestMySQLWaitForSchema is farmer's and saasapi's startup on install:
// they start before the migration Job, wait, and go on once it's done.
func TestMySQLWaitForSchema(t *testing.T) {
	e := newMySQLEnv(t)
	db := e.schemaDB(t, "t_wait_"+suffix(t))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- WaitForSchema(ctx, db, Saas, t.Logf) }()
	select {
	case err := <-done:
		t.Fatalf("returned before the schema was migrated: %v", err)
	case <-time.After(1500 * time.Millisecond):
	}
	if _, err := Up(ctx, db, Saas, t.Logf); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
