package mysqltest

import (
	"database/sql"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

func TestCheckUnsetSkips(t *testing.T) {
	cfg, err := Check("", time.Second)
	if cfg != nil || err != nil {
		t.Fatalf("Check(\"\") = %v, %v; want nil, nil (skip)", cfg, err)
	}
}

func TestCheckInvalidDSNFails(t *testing.T) {
	_, err := Check("root:secretpw@nonsense(", time.Second)
	if err == nil || !strings.Contains(err.Error(), "not a valid DSN") {
		t.Fatalf("err = %v, want not a valid DSN", err)
	}
	if strings.Contains(err.Error(), "secretpw") {
		t.Fatalf("the error carries the password: %v", err)
	}
}

// A set variable naming a server that does not answer is an error, not a
// skip: nothing listens on a port just released.
func TestCheckUnreachableFails(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	cfg, err := Check("root:secretpw@tcp("+addr+")/", 2*time.Second)
	if err == nil || cfg != nil {
		t.Fatalf("Check of an unreachable server = %v, %v; want an error", cfg, err)
	}
	if !strings.Contains(err.Error(), addr) || strings.Contains(err.Error(), "secretpw") {
		t.Fatalf("err = %v, want the address and no password", err)
	}
}

// With the variable set (as in CI), RootConfig returns a usable config.
func TestRootConfig(t *testing.T) {
	cfg := RootConfig(t)
	if cfg.DBName != "" {
		t.Fatalf("DBName = %q, want none selected", cfg.DBName)
	}
	if cfg.Addr == "" || os.Getenv(EnvRootDSN) == "" {
		t.Fatalf("config %+v", cfg)
	}
}

// While a test holds the lease, it is taken; once the test (and its
// subtests) end, it is free again. Another process cannot take it in the
// meantime (TestTryAcquireRespectsHolder).
func TestRootConfigSerializes(t *testing.T) {
	var cfg *mysql.Config
	t.Run("holder", func(t *testing.T) {
		cfg = RootConfig(t)
		t.Run("nested", func(t *testing.T) {
			RootConfig(t) // shares the hold, does not wait for itself
		})
		if !heldByUs(t, cfg) {
			t.Fatal("this process does not hold the lock while a test holds it")
		}
	})
	if cfg == nil {
		t.Skip("skipped")
	}
	// Another package's test process may take the lease the moment it is
	// released (go test runs packages in parallel), so the check is that
	// this process let it go, not that nobody holds it.
	if heldByUs(t, cfg) {
		t.Fatal("this process still holds the lock after the test ended")
	}
}

// heldByUs reports whether this process's holder has the lease now.
func heldByUs(t *testing.T, cfg *mysql.Config) bool {
	t.Helper()
	c, err := mysql.NewConnector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(c)
	defer db.Close()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM `"+lockSchema+"`.`"+lockTable+"` WHERE id = 1 AND holder = ? AND until > NOW(3)", holder).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

// A second holder (another package's test process) does not get the lease
// while it is held, and gets it once the first stops renewing it. On a
// table of its own, so the real lease is not touched.
func TestTryAcquireRespectsHolder(t *testing.T) {
	cfg := RootConfig(t)
	c, err := mysql.NewConnector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(c)
	defer db.Close()
	table := "test_lock_selftest_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	t.Cleanup(func() { db.Exec("DROP TABLE IF EXISTS `" + lockSchema + "`.`" + table + "`") })

	if ok, err := tryAcquire(db, table, "first"); err != nil || !ok {
		t.Fatalf("the free lease was not taken: %v, %v", ok, err)
	}
	if ok, err := tryAcquire(db, table, "first"); err != nil || !ok {
		t.Fatalf("the holder lost its own lease: %v, %v", ok, err)
	}
	if ok, err := tryAcquire(db, table, "second"); err != nil || ok {
		t.Fatalf("a second holder took the held lease: %v, %v", ok, err)
	}
	// The first holder stops renewing: its lease runs out.
	if _, err := db.Exec("UPDATE `" + lockSchema + "`.`" + table + "` SET until = NOW(3) - INTERVAL 1 SECOND WHERE id = 1"); err != nil {
		t.Fatal(err)
	}
	if ok, err := tryAcquire(db, table, "second"); err != nil || !ok {
		t.Fatalf("the expired lease was not taken: %v, %v", ok, err)
	}
	if ok, err := tryAcquire(db, table, "first"); err != nil || ok {
		t.Fatalf("the old holder took it back: %v, %v", ok, err)
	}
}
