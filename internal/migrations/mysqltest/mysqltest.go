// Package mysqltest gates the tests that need a real MySQL-compatible
// server (the migration sets, cmd/migrate, the lease and sweeper SQL).
//
// IMAS_TEST_MYSQL_ROOT_DSN names the server by its root account, e.g. a
// single-node PXC like the one deploy/helm/farmer runs (CI runs the same
// image as a service, .github/workflows/ci.yml):
//
//	docker run -d --name pxc -p 3306:3306 -e MYSQL_ROOT_PASSWORD=pw \
//	  percona/percona-xtradb-cluster:8.4.8-8.1
//	IMAS_TEST_MYSQL_ROOT_DSN='root:pw@tcp(127.0.0.1:3306)/' go test ./...
//
// Unset, the tests skip. Set, they run, and a DSN that does not parse or a
// server that does not answer fails them: a CI job that sets the variable
// can never pass by skipping.
//
// The tests of one server run one at a time, even across packages (go test
// runs packages in parallel). Each test works in schemas of its own, but on
// PXC a DDL statement is replicated in total order and aborts whatever else
// holds a conflicting dictionary lock at that moment, so another package's
// test fails at random with "Deadlock found" (1213) or "Query execution was
// interrupted" (1317). RootConfig takes a lease row in the schema
// imas_mysqltest for the test's lifetime, the way internal/lease does in
// the product: PXC refuses GET_LOCK in its default strict mode.
package mysqltest

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// EnvRootDSN is the variable that names the server.
const EnvRootDSN = "IMAS_TEST_MYSQL_ROOT_DSN"

// PingTimeout is how long RootConfig waits for the server to answer.
const PingTimeout = 30 * time.Second

// The lease every MySQL test holds while it runs: one row, renewed every
// lockRenew while held, so a test process that dies frees it after lockTTL.
// lockWait is how long a test waits for the tests of other packages.
const (
	lockSchema = "imas_mysqltest"
	lockTable  = "test_lock"
	lockTTL    = 60 * time.Second
	lockRenew  = 15 * time.Second
	lockPoll   = 250 * time.Millisecond
	lockWait   = 5 * time.Minute
)

// RootConfig returns the root account's config with no schema selected. It
// skips t when EnvRootDSN is unset and fails it when the DSN is invalid or
// the server cannot be reached with it.
func RootConfig(t testing.TB) *mysql.Config {
	t.Helper()
	cfg, err := Check(os.Getenv(EnvRootDSN), PingTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		t.Skipf("%s not set; skipping the MySQL tests", EnvRootDSN)
	}
	if err := serialize(t, cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// The process's hold on the lease: taken by the first test that needs it,
// shared by the subtests and helpers of that test (tests of one package
// run one at a time), released when the last of them ends.
var (
	lockMu   sync.Mutex
	lockRefs int
	lockDB   *sql.DB
	lockStop chan struct{}
	lockDone chan struct{}
	holder   string
)

func serialize(t testing.TB, cfg *mysql.Config) error {
	lockMu.Lock()
	defer lockMu.Unlock()
	if lockRefs == 0 {
		db, err := acquire(cfg)
		if err != nil {
			return err
		}
		lockDB, lockStop, lockDone = db, make(chan struct{}), make(chan struct{})
		go renew(db, lockStop, lockDone)
	}
	lockRefs++
	t.Cleanup(func() {
		lockMu.Lock()
		defer lockMu.Unlock()
		if lockRefs--; lockRefs == 0 {
			close(lockStop)
			<-lockDone
			ctx, cancel := context.WithTimeout(context.Background(), PingTimeout)
			defer cancel()
			lockDB.ExecContext(ctx, "DELETE FROM `"+lockSchema+"`.`"+lockTable+"` WHERE id = 1 AND holder = ?", holder)
			lockDB.Close()
			lockDB = nil
		}
	})
	return nil
}

// acquire waits up to lockWait for the lease row and takes it. Every error
// on the way (a deadlock with another package taking it, an abort by a
// replicated DDL) is retried until then.
func acquire(cfg *mysql.Config) (*sql.DB, error) {
	conn, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", EnvRootDSN, err)
	}
	db := sql.OpenDB(conn)
	if holder == "" {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			db.Close()
			return nil, err
		}
		holder = fmt.Sprintf("%d-%s", os.Getpid(), hex.EncodeToString(b))
	}
	deadline := time.Now().Add(lockWait)
	var last error
	for time.Now().Before(deadline) {
		ok, err := tryAcquire(db, lockTable, holder)
		if ok {
			return db, nil
		}
		if err != nil {
			last = err
		}
		time.Sleep(lockPoll)
	}
	db.Close()
	return nil, fmt.Errorf("%s: other MySQL tests held %s.%s for %s (last error: %v)", EnvRootDSN, lockSchema, lockTable, lockWait, last)
}

// tryAcquire takes the lease row of table (in lockSchema) for who, if it
// is free or expired, and reports whether who holds it.
func tryAcquire(db *sql.DB, table, who string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), PingTimeout)
	defer cancel()
	var n int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?", lockSchema, table).Scan(&n); err != nil {
		return false, err
	}
	if n == 0 {
		// Only before the first test on a fresh server: DDL while another
		// test runs would abort it, which is what the lease prevents.
		if _, err := db.ExecContext(ctx, "CREATE DATABASE IF NOT EXISTS `"+lockSchema+"`"); err != nil {
			return false, err
		}
		if _, err := db.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS `"+lockSchema+"`.`"+table+"` (id TINYINT NOT NULL PRIMARY KEY, holder VARCHAR(64) NOT NULL, until DATETIME(3) NOT NULL)"); err != nil {
			return false, err
		}
	}
	// Take the row if it is free or its holder stopped renewing it. The
	// assignments run left to right, so both test the old until.
	ttl := int(lockTTL / time.Second)
	if _, err := db.ExecContext(ctx, "INSERT INTO `"+lockSchema+"`.`"+table+"` (id, holder, until) VALUES (1, ?, NOW(3) + INTERVAL ? SECOND) "+
		"ON DUPLICATE KEY UPDATE holder = IF(until < NOW(3), VALUES(holder), holder), until = IF(until < NOW(3), VALUES(until), until)", who, ttl); err != nil {
		return false, err
	}
	var got string
	if err := db.QueryRowContext(ctx, "SELECT holder FROM `"+lockSchema+"`.`"+table+"` WHERE id = 1").Scan(&got); err != nil {
		return false, err
	}
	return got == who, nil
}

// renew keeps the lease until stop is closed. A failed renewal is retried
// at the next tick; lockTTL leaves room for three.
func renew(db *sql.DB, stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	tick := time.NewTicker(lockRenew)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			ctx, cancel := context.WithTimeout(context.Background(), lockRenew)
			db.ExecContext(ctx, "UPDATE `"+lockSchema+"`.`"+lockTable+"` SET until = NOW(3) + INTERVAL ? SECOND WHERE id = 1 AND holder = ?", int(lockTTL/time.Second), holder)
			cancel()
		}
	}
}

// Check parses dsn and pings the server with it. It returns nil and no
// error for an empty dsn (the tests skip), and an error for a DSN that does
// not parse or a server that does not answer within timeout. The error
// never carries the DSN, which holds the root password.
func Check(dsn string, timeout time.Duration) (*mysql.Config, error) {
	if dsn == "" {
		return nil, nil
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("%s: not a valid DSN", EnvRootDSN)
	}
	cfg.DBName = ""
	conn, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", EnvRootDSN, err)
	}
	db := sql.OpenDB(conn)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("%s is set but the server at %s %s does not answer (the MySQL tests fail rather than skip): %v", EnvRootDSN, cfg.Net, cfg.Addr, err)
	}
	return cfg, nil
}
