package lease

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// runReplicas runs one tick of job name on n replicas at once, each with
// its own Leases on gdb, and returns how many ran fn.
func runReplicas(t *testing.T, l []*Leases, name string, ttl, minInterval time.Duration, body func()) int32 {
	t.Helper()
	var ran atomic.Int32
	var wg sync.WaitGroup
	for _, r := range l {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := r.Run(context.Background(), name, ttl, minInterval, func(context.Context) error { body(); return nil })
			if err != nil {
				t.Errorf("Run: %v", err)
			}
			if ok {
				ran.Add(1)
			}
		}()
	}
	wg.Wait()
	return ran.Load()
}

func TestRunOncePerIntervalAcrossReplicas(t *testing.T) {
	gdb := openTestDB(t)
	clk := newFakeClock()
	replicas := make([]*Leases, 4)
	for i := range replicas {
		replicas[i] = New(gdb, clk.Now)
	}
	var bodies atomic.Int32
	body := func() { bodies.Add(1) }
	ttl, interval := 2*time.Minute, time.Hour

	// The row does not exist yet: Run creates it (pushall:<tenant>).
	if n := runReplicas(t, replicas, "pushall:t1", ttl, interval, body); n != 1 || bodies.Load() != 1 {
		t.Fatalf("first tick: %d replicas ran, body ran %d times; want 1", n, bodies.Load())
	}
	start := clk.Now()
	var last JobLease
	if err := gdb.Where("name = ?", "pushall:t1").Take(&last).Error; err != nil {
		t.Fatal(err)
	}
	if last.LastRunAt == nil || !last.LastRunAt.Equal(start) {
		t.Fatalf("last_run_at = %v, want %v", last.LastRunAt, start)
	}
	if last.LeaseOwner != nil {
		t.Fatalf("lease still held after the run: %v", *last.LeaseOwner)
	}

	// Ticks before the interval elapses, even after the TTL: no run.
	clk.Advance(ttl + time.Second)
	if n := runReplicas(t, replicas, "pushall:t1", ttl, interval, body); n != 0 {
		t.Fatalf("tick within the interval: %d replicas ran", n)
	}
	clk.Advance(interval - ttl - 2*time.Second)
	if n := runReplicas(t, replicas, "pushall:t1", ttl, interval, body); n != 0 {
		t.Fatalf("tick 1s before the interval: %d replicas ran", n)
	}

	// The interval has elapsed: exactly one replica runs again.
	clk.Advance(time.Second)
	if n := runReplicas(t, replicas, "pushall:t1", ttl, interval, body); n != 1 || bodies.Load() != 2 {
		t.Fatalf("second interval: %d replicas ran, body ran %d times in all; want 1 and 2", n, bodies.Load())
	}
	if err := gdb.Where("name = ?", "pushall:t1").Take(&last).Error; err != nil {
		t.Fatal(err)
	}
	if !last.LastRunAt.Equal(clk.Now()) {
		t.Fatalf("last_run_at = %v, want %v", last.LastRunAt, clk.Now())
	}
}

func TestRunSkipsWhileAnotherReplicaHoldsLease(t *testing.T) {
	gdb := openTestDB(t)
	clk := newFakeClock()
	ctx := context.Background()
	seedJob(t, gdb, "jobs_expiry")
	a := New(gdb, clk.Now)
	ok, err := a.Acquire(ctx, JobLeases, []any{"jobs_expiry"}, "other-replica", time.Minute)
	mustBool(t, ok, err, true, "other replica acquires")

	ran := false
	ok, err = New(gdb, clk.Now).Run(ctx, "jobs_expiry", time.Minute, 0, func(context.Context) error { ran = true; return nil })
	mustBool(t, ok, err, false, "Run while held")
	if ran {
		t.Fatal("fn ran while another replica held the lease")
	}

	// A holder that died: its lease lapses and the job runs.
	clk.Advance(time.Minute + time.Millisecond)
	ok, err = New(gdb, clk.Now).Run(ctx, "jobs_expiry", time.Minute, 0, func(context.Context) error { ran = true; return nil })
	mustBool(t, ok, err, true, "Run after the holder's lease lapsed")
	if !ran {
		t.Fatal("fn did not run")
	}
}

func TestRunCancelsFnWhenLeaseIsLost(t *testing.T) {
	gdb := openTestDB(t)
	ctx := context.Background()
	ttl := 30 * time.Millisecond
	l := New(gdb, nil)
	ok, err := l.Run(ctx, "cohort_refresher", ttl, 0, func(fctx context.Context) error {
		// Another replica takes the row (as if this one had stalled).
		if err := gdb.Exec("UPDATE job_leases SET lease_owner = 'thief' WHERE name = 'cohort_refresher'").Error; err != nil {
			t.Error(err)
		}
		select {
		case <-fctx.Done():
		case <-time.After(5 * time.Second):
			t.Error("fn's context was not cancelled after the lease was lost")
		}
		return nil
	})
	mustBool(t, ok, err, true, "Run")
	var row JobLease
	if err := gdb.Where("name = ?", "cohort_refresher").Take(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.LeaseOwner == nil || *row.LeaseOwner != "thief" {
		t.Fatalf("Run released a lease it no longer held: owner %v", row.LeaseOwner)
	}
}

func TestRunFailedRunDoesNotCountTowardInterval(t *testing.T) {
	gdb := openTestDB(t)
	clk := newFakeClock()
	ctx := context.Background()
	l := New(gdb, clk.Now)
	ok, err := l.Run(ctx, "pushall:t1", time.Minute, time.Minute, func(context.Context) error { return nil })
	mustBool(t, ok, err, true, "first run")
	first := clk.Now()

	clk.Advance(time.Minute)
	boom := errors.New("bus not ready")
	ok, err = l.Run(ctx, "pushall:t1", time.Minute, time.Minute, func(context.Context) error { return boom })
	if !ok || !errors.Is(err, boom) {
		t.Fatalf("failing run = %v, %v; want true, %v", ok, err, boom)
	}
	var row JobLease
	if err := gdb.Where("name = ?", "pushall:t1").Take(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.LastRunAt == nil || !row.LastRunAt.Equal(first) {
		t.Fatalf("last_run_at after a failed run = %v, want the last good run %v", row.LastRunAt, first)
	}
	// The retry runs at once, with no wait for the interval.
	clk.Advance(time.Second)
	ok, err = l.Run(ctx, "pushall:t1", time.Minute, time.Minute, func(context.Context) error { return nil })
	mustBool(t, ok, err, true, "retry after a failed run")
}

func TestRunNilDBRunsDirectly(t *testing.T) {
	ran := false
	ok, err := Run(context.Background(), nil, "jobs_expiry", time.Minute, time.Hour, func(context.Context) error { ran = true; return nil })
	if err != nil || !ok || !ran {
		t.Fatalf("Run(nil db) = %v, %v; ran %v", ok, err, ran)
	}
}

func TestRunRefusesInvalidArguments(t *testing.T) {
	l := New(openTestDB(t), nil)
	fn := func(context.Context) error { t.Error("fn ran"); return nil }
	long := string(make([]byte, MaxOwnerLen+1))
	for _, tc := range []struct {
		name          string
		ttl, interval time.Duration
	}{
		{"", time.Minute, 0},
		{long, time.Minute, 0},
		{"j", 0, 0},
		{"j", time.Minute, -time.Second},
	} {
		if _, err := l.Run(context.Background(), tc.name, tc.ttl, tc.interval, fn); !errors.Is(err, ErrInvalid) {
			t.Errorf("Run(%q, %s, %s) error = %v, want ErrInvalid", tc.name, tc.ttl, tc.interval, err)
		}
	}
}

func TestJobTTL(t *testing.T) {
	for _, tc := range []struct {
		env  string
		want time.Duration
	}{
		{"", DefaultJobLeaseTTL},
		{"45s", 45 * time.Second},
		{"bogus", DefaultJobLeaseTTL},
		{"-1s", DefaultJobLeaseTTL},
	} {
		t.Setenv(JobLeaseTTLEnv, tc.env)
		if got := JobTTL(); got != tc.want {
			t.Errorf("JobTTL with %q = %s, want %s", tc.env, got, tc.want)
		}
	}
}
