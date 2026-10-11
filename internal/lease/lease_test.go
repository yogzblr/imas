package lease

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// The three leased tables as the P21 slice 3 brief's schema defines them,
// cut to the columns the lease touches plus their keys. DATETIME(3) is
// written DATETIME here: the sqlite driver only parses a column back into
// time.Time when its declared type is exactly DATETIME.
var testDDL = []string{
	`CREATE TABLE job_leases (
		name VARCHAR(128) NOT NULL PRIMARY KEY,
		lease_owner VARCHAR(128) NULL,
		lease_until DATETIME NULL,
		last_run_at DATETIME NULL)`,
	`CREATE TABLE sprout_user_jwt (
		tenant_id VARCHAR(64) NOT NULL,
		sprout_id VARCHAR(128) NOT NULL,
		lease_owner VARCHAR(128) NULL,
		lease_until DATETIME NULL,
		PRIMARY KEY (tenant_id, sprout_id))`,
	`CREATE TABLE saasapi_credential_state (
		id TINYINT NOT NULL PRIMARY KEY,
		lease_owner VARCHAR(128) NULL,
		lease_until DATETIME NULL)`,
}

func openTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "lease.db")),
		&gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	// One connection: sqlite serializes writers anyway, and this keeps
	// concurrent tests from failing with "database is locked".
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { sqlDB.Close() })
	for _, ddl := range testDDL {
		if err := gdb.Exec(ddl).Error; err != nil {
			t.Fatal(err)
		}
	}
	return gdb
}

// fakeClock is a settable clock safe for concurrent reads.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func seedJob(t *testing.T, gdb *gorm.DB, name string) {
	t.Helper()
	if err := gdb.Exec("INSERT INTO job_leases (name) VALUES (?)", name).Error; err != nil {
		t.Fatal(err)
	}
}

type leaseCols struct {
	Owner *string
	Until *time.Time
}

func readJob(t *testing.T, gdb *gorm.DB, name string) leaseCols {
	t.Helper()
	var c leaseCols
	if err := gdb.Raw("SELECT lease_owner AS owner, lease_until AS until FROM job_leases WHERE name = ?", name).
		Scan(&c).Error; err != nil {
		t.Fatal(err)
	}
	return c
}

func mustBool(t *testing.T, got bool, err error, want bool, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	if got != want {
		t.Fatalf("%s = %v, want %v", what, got, want)
	}
}

func TestAcquireLiveLeaseRefusedUntilItLapses(t *testing.T) {
	gdb := openTestDB(t)
	clk := newFakeClock()
	ctx := context.Background()
	seedJob(t, gdb, "jobs_expiry")
	a, b := New(gdb, clk.Now), New(gdb, clk.Now)
	key := []any{"jobs_expiry"}
	ttl := 2 * time.Minute

	ok, err := a.Acquire(ctx, JobLeases, key, "replica-a/1", ttl)
	mustBool(t, ok, err, true, "A acquires a never-leased row")
	got := readJob(t, gdb, "jobs_expiry")
	if got.Owner == nil || *got.Owner != "replica-a/1" || got.Until == nil || !got.Until.Equal(clk.Now().Add(ttl)) {
		t.Fatalf("row after acquire = %+v", got)
	}

	ok, err = b.Acquire(ctx, JobLeases, key, "replica-b/1", ttl)
	mustBool(t, ok, err, false, "B acquires A's live lease")

	clk.Advance(ttl) // lease_until == now: not yet lapsed
	ok, err = b.Acquire(ctx, JobLeases, key, "replica-b/1", ttl)
	mustBool(t, ok, err, false, "B acquires at exactly lease_until")

	clk.Advance(time.Millisecond)
	ok, err = b.Acquire(ctx, JobLeases, key, "replica-b/1", ttl)
	mustBool(t, ok, err, true, "B acquires a lapsed lease")

	ok, err = a.Renew(ctx, JobLeases, key, "replica-a/1", ttl)
	mustBool(t, ok, err, false, "A renews after B took the row")
	ok, err = a.Release(ctx, JobLeases, key, "replica-a/1")
	mustBool(t, ok, err, false, "A releases after B took the row")
	if got := readJob(t, gdb, "jobs_expiry"); got.Owner == nil || *got.Owner != "replica-b/1" {
		t.Fatalf("A's release changed B's lease: %+v", got)
	}
}

func TestAcquireBySameOwnerExtends(t *testing.T) {
	gdb := openTestDB(t)
	clk := newFakeClock()
	ctx := context.Background()
	seedJob(t, gdb, "cohort_refresher")
	l := New(gdb, clk.Now)
	key := []any{"cohort_refresher"}

	ok, err := l.Acquire(ctx, JobLeases, key, "o", time.Minute)
	mustBool(t, ok, err, true, "first acquire")
	// Same instant: the UPDATE writes the values the row already holds.
	ok, err = l.Acquire(ctx, JobLeases, key, "o", time.Minute)
	mustBool(t, ok, err, true, "re-acquire in the same millisecond")
	clk.Advance(30 * time.Second)
	ok, err = l.Acquire(ctx, JobLeases, key, "o", time.Minute)
	mustBool(t, ok, err, true, "re-acquire while held")
	if got := readJob(t, gdb, "cohort_refresher"); !got.Until.Equal(clk.Now().Add(time.Minute)) {
		t.Fatalf("lease_until = %v, want %v", got.Until, clk.Now().Add(time.Minute))
	}
}

func TestRenewKeepsLeaseFromOthers(t *testing.T) {
	gdb := openTestDB(t)
	clk := newFakeClock()
	ctx := context.Background()
	seedJob(t, gdb, "j")
	a, b := New(gdb, clk.Now), New(gdb, clk.Now)
	key := []any{"j"}
	ttl := time.Minute

	ok, err := a.Acquire(ctx, JobLeases, key, "a", ttl)
	mustBool(t, ok, err, true, "A acquires")
	for range 5 {
		clk.Advance(ttl / 2)
		ok, err = a.Renew(ctx, JobLeases, key, "a", ttl)
		mustBool(t, ok, err, true, "A renews")
		ok, err = b.Acquire(ctx, JobLeases, key, "b", ttl)
		mustBool(t, ok, err, false, "B acquires a renewed lease")
	}
	// Renewing twice in one millisecond is not a lost lease.
	ok, err = a.Renew(ctx, JobLeases, key, "a", ttl)
	mustBool(t, ok, err, true, "A renews again at the same instant")
}

func TestReleaseFreesRowAtOnce(t *testing.T) {
	gdb := openTestDB(t)
	clk := newFakeClock()
	ctx := context.Background()
	seedJob(t, gdb, "j")
	a, b := New(gdb, clk.Now), New(gdb, clk.Now)
	key := []any{"j"}

	ok, err := a.Acquire(ctx, JobLeases, key, "a", time.Hour)
	mustBool(t, ok, err, true, "A acquires")
	ok, err = b.Release(ctx, JobLeases, key, "b")
	mustBool(t, ok, err, false, "B releases A's lease")
	ok, err = a.Release(ctx, JobLeases, key, "a")
	mustBool(t, ok, err, true, "A releases")
	if got := readJob(t, gdb, "j"); got.Owner != nil || got.Until != nil {
		t.Fatalf("row after release = %+v, want both NULL", got)
	}
	ok, err = a.Renew(ctx, JobLeases, key, "a", time.Hour)
	mustBool(t, ok, err, false, "A renews a released lease")
	ok, err = b.Acquire(ctx, JobLeases, key, "b", time.Hour)
	mustBool(t, ok, err, true, "B acquires right after release")
}

func TestAcquireMissingRow(t *testing.T) {
	gdb := openTestDB(t)
	l := New(gdb, newFakeClock().Now)
	ok, err := l.Acquire(context.Background(), JobLeases, []any{"nope"}, "a", time.Minute)
	mustBool(t, ok, err, false, "acquire a row that doesn't exist")
}

// sprout_id is unique per tenant only: the same sprout_id in two tenants
// is two rows, leased independently.
func TestSproutLeaseKeyedByTenant(t *testing.T) {
	gdb := openTestDB(t)
	clk := newFakeClock()
	ctx := context.Background()
	for _, tenant := range []string{"t1", "t2"} {
		if err := gdb.Exec("INSERT INTO sprout_user_jwt (tenant_id, sprout_id) VALUES (?, ?)", tenant, "web-1").Error; err != nil {
			t.Fatal(err)
		}
	}
	l := New(gdb, clk.Now)
	ok, err := l.Acquire(ctx, SproutUserJWT, []any{"t1", "web-1"}, "a", time.Minute)
	mustBool(t, ok, err, true, "A leases t1/web-1")
	ok, err = l.Acquire(ctx, SproutUserJWT, []any{"t2", "web-1"}, "b", time.Minute)
	mustBool(t, ok, err, true, "B leases t2/web-1")
	ok, err = l.Acquire(ctx, SproutUserJWT, []any{"t1", "web-1"}, "b", time.Minute)
	mustBool(t, ok, err, false, "B leases t1/web-1")
	ok, err = l.Release(ctx, SproutUserJWT, []any{"t2", "web-1"}, "b")
	mustBool(t, ok, err, true, "B releases t2/web-1")
	var owner *string
	if err := gdb.Raw("SELECT lease_owner FROM sprout_user_jwt WHERE tenant_id = ? AND sprout_id = ?", "t1", "web-1").
		Scan(&owner).Error; err != nil {
		t.Fatal(err)
	}
	if owner == nil || *owner != "a" {
		t.Fatalf("t1/web-1 owner = %v after B released t2/web-1, want a", owner)
	}
}

func TestCredentialStateLease(t *testing.T) {
	gdb := openTestDB(t)
	clk := newFakeClock()
	ctx := context.Background()
	if err := gdb.Exec("INSERT INTO saasapi_credential_state (id) VALUES (1)").Error; err != nil {
		t.Fatal(err)
	}
	l := New(gdb, clk.Now)
	ok, err := l.Acquire(ctx, SaasapiCredentialState, []any{1}, "a", time.Minute)
	mustBool(t, ok, err, true, "A leases the credential row")
	ok, err = l.Acquire(ctx, SaasapiCredentialState, []any{1}, "b", time.Minute)
	mustBool(t, ok, err, false, "B leases the credential row")
}

// Of many concurrent claims on one free row exactly one wins.
func TestAcquireConcurrentOneWinner(t *testing.T) {
	gdb := openTestDB(t)
	clk := newFakeClock()
	seedJob(t, gdb, "pushall:t1")
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		won  []string
		errs []error
	)
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			owner := fmt.Sprintf("replica-%d", i)
			ok, err := New(gdb, clk.Now).Acquire(context.Background(), JobLeases, []any{"pushall:t1"}, owner, time.Minute)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
			}
			if ok {
				won = append(won, owner)
			}
		}()
	}
	wg.Wait()
	if len(errs) != 0 {
		t.Fatalf("errors: %v", errs)
	}
	if len(won) != 1 {
		t.Fatalf("winners = %v, want exactly one", won)
	}
	if got := readJob(t, gdb, "pushall:t1"); got.Owner == nil || *got.Owner != won[0] {
		t.Fatalf("row owner = %v, want %s", got.Owner, won[0])
	}
}

func TestInvalidRequestsRefusedBeforeSQL(t *testing.T) {
	gdb := openTestDB(t)
	seedJob(t, gdb, "j")
	l := New(gdb, newFakeClock().Now)
	ctx := context.Background()
	long := strings.Repeat("x", MaxOwnerLen+1)
	cases := []struct {
		name  string
		table Table
		key   []any
		owner string
		ttl   time.Duration
	}{
		{"table not on the allow-list", Table("provisioning_jobs"), []any{"j"}, "a", time.Minute},
		{"injected table name", Table("job_leases; DROP TABLE job_leases"), []any{"j"}, "a", time.Minute},
		{"too few key values", SproutUserJWT, []any{"t1"}, "a", time.Minute},
		{"too many key values", JobLeases, []any{"j", "k"}, "a", time.Minute},
		{"empty owner", JobLeases, []any{"j"}, "", time.Minute},
		{"owner too long", JobLeases, []any{"j"}, long, time.Minute},
		{"zero ttl", JobLeases, []any{"j"}, "a", 0},
		{"negative ttl", JobLeases, []any{"j"}, "a", -time.Second},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, err := l.Acquire(ctx, c.table, c.key, c.owner, c.ttl)
			if ok || !errors.Is(err, ErrInvalid) {
				t.Errorf("Acquire = %v, %v; want false, ErrInvalid", ok, err)
			}
			ok, err = l.Renew(ctx, c.table, c.key, c.owner, c.ttl)
			if ok || !errors.Is(err, ErrInvalid) {
				t.Errorf("Renew = %v, %v; want false, ErrInvalid", ok, err)
			}
			if c.ttl > 0 {
				ok, err = l.Release(ctx, c.table, c.key, c.owner)
				if ok || !errors.Is(err, ErrInvalid) {
					t.Errorf("Release = %v, %v; want false, ErrInvalid", ok, err)
				}
			}
		})
	}
	if got := readJob(t, gdb, "j"); got.Owner != nil {
		t.Fatalf("an invalid request leased the row: %+v", got)
	}
}

func TestDefaultClock(t *testing.T) {
	gdb := openTestDB(t)
	seedJob(t, gdb, "j")
	before := time.Now()
	ok, err := New(gdb, nil).Acquire(context.Background(), JobLeases, []any{"j"}, "a", time.Minute)
	mustBool(t, ok, err, true, "acquire with the default clock")
	got := readJob(t, gdb, "j")
	if got.Until == nil || got.Until.Before(before.Add(time.Minute).Add(-time.Millisecond)) {
		t.Fatalf("lease_until = %v, want about now+1m", got.Until)
	}
}

// MySQL counts changed rows, so an UPDATE writing the values a row already
// holds reports zero rows. sqlite counts matched rows and never does, so
// this forces RowsAffected to 0 after every UPDATE: Acquire and Renew must
// then decide from the row itself, holding only what this owner wrote.
func TestZeroChangedRowsFallsBackToReadingTheRow(t *testing.T) {
	gdb := openTestDB(t)
	var zero atomic.Bool
	if err := gdb.Callback().Update().After("gorm:update").Register("lease_test:zero_rows", func(d *gorm.DB) {
		if zero.Load() {
			d.RowsAffected = 0
		}
	}); err != nil {
		t.Fatal(err)
	}
	clk := newFakeClock()
	ctx := context.Background()
	seedJob(t, gdb, "j")
	l := New(gdb, clk.Now)
	key := []any{"j"}

	ok, err := l.Acquire(ctx, JobLeases, key, "a", time.Minute)
	mustBool(t, ok, err, true, "A acquires")
	zero.Store(true)

	ok, err = l.Acquire(ctx, JobLeases, key, "a", time.Minute)
	mustBool(t, ok, err, true, "A re-acquires, zero rows reported")
	ok, err = l.Renew(ctx, JobLeases, key, "a", time.Minute)
	mustBool(t, ok, err, true, "A renews, zero rows reported")
	clk.Advance(10 * time.Second)
	ok, err = l.Renew(ctx, JobLeases, key, "a", time.Minute)
	mustBool(t, ok, err, true, "A renews later, zero rows reported")
	if got := readJob(t, gdb, "j"); !got.Until.Equal(clk.Now().Add(time.Minute)) {
		t.Fatalf("lease_until = %v, want %v", got.Until, clk.Now().Add(time.Minute))
	}

	ok, err = l.Acquire(ctx, JobLeases, key, "b", time.Minute)
	mustBool(t, ok, err, false, "B acquires A's live lease, zero rows reported")
	ok, err = l.Renew(ctx, JobLeases, key, "b", time.Minute)
	mustBool(t, ok, err, false, "B renews A's lease, zero rows reported")
	if got := readJob(t, gdb, "j"); got.Owner == nil || *got.Owner != "a" {
		t.Fatalf("owner = %v, want a", got.Owner)
	}
}
