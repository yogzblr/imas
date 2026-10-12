package pki

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/config"
)

// fakePushAllClock replaces pushAllNow with a settable clock.
func fakePushAllClock(t *testing.T) (advance func(time.Duration)) {
	t.Helper()
	var mu sync.Mutex
	now := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	orig := pushAllNow
	pushAllNow = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	t.Cleanup(func() { pushAllNow = orig })
	return func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
}

// TestPushAllLeaseRunsOncePerInterval: four replicas reconnecting at once
// push a tenant's Account once; within 60s nobody pushes it again; after
// that, one replica does.
func TestPushAllLeaseRunsOncePerInterval(t *testing.T) {
	newTestDB(t)
	advance := fakePushAllClock(t)
	var pushes atomic.Int32
	tick := func() {
		var wg sync.WaitGroup
		for range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := leasedPush("t_live", func() error { pushes.Add(1); return nil }); err != nil {
					t.Errorf("leasedPush: %v", err)
				}
			}()
		}
		wg.Wait()
	}

	tick()
	if got := pushes.Load(); got != 1 {
		t.Fatalf("four replicas pushed %d times, want 1", got)
	}
	advance(pushAllMinInterval - time.Second)
	tick()
	if got := pushes.Load(); got != 1 {
		t.Fatalf("within the interval: %d pushes in all, want 1", got)
	}
	advance(time.Second)
	tick()
	if got := pushes.Load(); got != 2 {
		t.Fatalf("after the interval: %d pushes in all, want 2", got)
	}

	// Another tenant has its own lease: unaffected by t_live's.
	if ran, err := leasedPush("t_other", func() error { return nil }); err != nil || !ran {
		t.Fatalf("leasedPush(t_other) = %v, %v; want it to run", ran, err)
	}
}

// TestPushAllLeaseRetriesFailedPush: a push that fails doesn't hold the
// tenant off for the interval, so the next reconnect (or the startup
// retry loop) pushes it again at once.
func TestPushAllLeaseRetriesFailedPush(t *testing.T) {
	newTestDB(t)
	advance := fakePushAllClock(t)
	boom := errors.New("no bus")
	if ran, err := leasedPush("t_live", func() error { return boom }); !ran || !errors.Is(err, boom) {
		t.Fatalf("failing push = %v, %v", ran, err)
	}
	advance(time.Second)
	calls := 0
	if ran, err := leasedPush("t_live", func() error { calls++; return nil }); err != nil || !ran || calls != 1 {
		t.Fatalf("retry = %v, %v (%d calls); want it to run", ran, err, calls)
	}
}

// TestPushAllAccounts_SkipsTenantsPushedWithinInterval: a second
// PushAllAccounts within 60s (another replica's reconnect) pushes only
// the SYS Account; after the interval it pushes every tenant again.
func TestPushAllAccounts_SkipsTenantsPushedWithinInterval(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	advance := fakePushAllClock(t)
	if _, err := ensureNatsAuth(); err != nil {
		t.Fatalf("ensureNatsAuth: %v", err)
	}
	config.FarmerBusURL = "127.0.0.1:1"
	_ = ProvisionTenant("t_live", "Live Co")
	startBusNode(t, t.TempDir())

	n, err := PushAllAccounts()
	if err != nil || n != 3 { // SYS, legacy, t_live
		t.Fatalf("first PushAllAccounts = %d, %v; want 3", n, err)
	}
	advance(10 * time.Second)
	n, err = PushAllAccounts()
	if err != nil || n != 1 { // SYS only
		t.Fatalf("PushAllAccounts within the interval = %d, %v; want 1 (SYS)", n, err)
	}
	advance(pushAllMinInterval)
	n, err = PushAllAccounts()
	if err != nil || n != 3 {
		t.Fatalf("PushAllAccounts after the interval = %d, %v; want 3", n, err)
	}
}
