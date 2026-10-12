package jobs

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/lease"
)

// TestHourlyJobsRunOnce: four farmer replicas tick the job reaper at the
// same instant against one database. The reaper body runs once per
// interval, job_leases.last_run_at records it, and a tick after the
// interval elapses runs it once more.
func TestHourlyJobsRunOnce(t *testing.T) {
	gdb := newIndexTestDB(t)
	if err := gdb.AutoMigrate(&lease.JobLease{}); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	clock := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	advance := func(d time.Duration) { mu.Lock(); clock = clock.Add(d); mu.Unlock() }

	var runs atomic.Int32
	orig := reapBody
	reapBody = func(*Store, time.Duration) { runs.Add(1) }
	t.Cleanup(func() { reapBody = orig })

	replicas := []*Store{NewStore(), NewStore(), NewStore(), NewStore()}
	tick := func() {
		var wg sync.WaitGroup
		for _, s := range replicas {
			wg.Add(1)
			go func() { defer wg.Done(); s.reapLeased(context.Background(), time.Hour, now) }()
		}
		wg.Wait()
	}
	lastRun := func() time.Time {
		var row lease.JobLease
		if err := gdb.Where("name = ?", reapJobName).Take(&row).Error; err != nil {
			t.Fatal(err)
		}
		if row.LastRunAt == nil {
			return time.Time{}
		}
		return *row.LastRunAt
	}

	tick()
	if got := runs.Load(); got != 1 {
		t.Fatalf("first tick ran the reaper %d times, want 1", got)
	}
	if got := lastRun(); !got.Equal(now()) {
		t.Fatalf("last_run_at = %v, want %v", got, now())
	}

	// Past the lease TTL but within the interval: nobody runs it again.
	advance(lease.JobTTL() + time.Minute)
	tick()
	if got := runs.Load(); got != 1 {
		t.Fatalf("tick within the interval: reaper ran %d times in all, want 1", got)
	}

	advance(reapInterval)
	tick()
	if got := runs.Load(); got != 2 {
		t.Fatalf("tick after the interval: reaper ran %d times in all, want 2", got)
	}
	if got := lastRun(); !got.Equal(now()) {
		t.Fatalf("last_run_at = %v, want %v", got, now())
	}
}

// TestReapLeasedWithoutDatabase: with no database installed the reaper
// runs as before, with no lease.
func TestReapLeasedWithoutDatabase(t *testing.T) {
	var runs atomic.Int32
	orig := reapBody
	reapBody = func(*Store, time.Duration) { runs.Add(1) }
	t.Cleanup(func() { reapBody = orig })
	NewStore().reapLeased(context.Background(), time.Hour, time.Now)
	if runs.Load() != 1 {
		t.Fatalf("reaper ran %d times, want 1", runs.Load())
	}
}
