package migrations

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeLockStore is an in-memory lockStore. refreshErr and refreshLost
// script the heartbeat's view of the database.
type fakeLockStore struct {
	mu          sync.Mutex
	owner       string
	expires     time.Time
	refreshErr  error
	refreshLost bool
	refreshes   int
	released    []string
}

func (f *fakeLockStore) ensure(context.Context) error { return nil }

func (f *fakeLockStore) tryAcquire(_ context.Context, owner string, lease time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.owner != "" && time.Now().Before(f.expires) {
		return false, nil
	}
	f.owner, f.expires = owner, time.Now().Add(lease)
	return true, nil
}

func (f *fakeLockStore) refresh(_ context.Context, owner string, lease time.Duration) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshes++
	if f.refreshErr != nil {
		return false, f.refreshErr
	}
	if f.refreshLost || f.owner != owner {
		return false, nil
	}
	f.expires = time.Now().Add(lease)
	return true, nil
}

func (f *fakeLockStore) release(_ context.Context, owner string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.released = append(f.released, owner)
	if f.owner == owner {
		f.owner = ""
	}
	return nil
}

func (f *fakeLockStore) holder(context.Context) (string, time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.owner, time.Until(f.expires), nil
}

func (f *fakeLockStore) set(fn func(*fakeLockStore)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func nologf(string, ...any) {}

var quickLock = LockOptions{Lease: 300 * time.Millisecond, Wait: 100 * time.Millisecond, Poll: 10 * time.Millisecond}

func TestLockExcludesASecondRun(t *testing.T) {
	store := &fakeLockStore{}
	a, ctxA, err := acquireLock(context.Background(), store, "a", quickLock, nologf)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Release(context.Background())

	_, _, err = acquireLock(context.Background(), store, "b", quickLock, nologf)
	if !errors.Is(err, ErrLockHeld) {
		t.Fatalf("second run got %v, want ErrLockHeld", err)
	}
	// a's heartbeat kept the lease alive throughout.
	if ctxA.Err() != nil {
		t.Fatalf("holder's context ended: %v", context.Cause(ctxA))
	}
}

func TestLockWaitsForRelease(t *testing.T) {
	store := &fakeLockStore{}
	a, _, err := acquireLock(context.Background(), store, "a", quickLock, nologf)
	if err != nil {
		t.Fatal(err)
	}
	time.AfterFunc(30*time.Millisecond, func() { a.Release(context.Background()) })
	opts := quickLock
	opts.Wait = 2 * time.Second
	b, _, err := acquireLock(context.Background(), store, "b", opts, nologf)
	if err != nil {
		t.Fatalf("second run after release: %v", err)
	}
	defer b.Release(context.Background())
	if owner, _, _ := store.holder(context.Background()); owner != "b" {
		t.Fatalf("holder %q, want b", owner)
	}
}

// TestLockTakenOverAfterLease: a holder that stopped heartbeating (here,
// one that never started) loses the lock once its lease ends.
func TestLockTakenOverAfterLease(t *testing.T) {
	store := &fakeLockStore{owner: "crashed", expires: time.Now().Add(50 * time.Millisecond)}
	opts := quickLock
	opts.Wait = 2 * time.Second
	l, _, err := acquireLock(context.Background(), store, "b", opts, nologf)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release(context.Background())
}

func TestLockLostToAnotherRunCancelsContext(t *testing.T) {
	store := &fakeLockStore{}
	l, ctx, err := acquireLock(context.Background(), store, "a", quickLock, nologf)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release(context.Background())
	store.set(func(f *fakeLockStore) { f.owner = "thief" })
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("context not cancelled after the lock was taken")
	}
	if !LockLost(ctx) {
		t.Fatalf("cause %v, want the lock lost", context.Cause(ctx))
	}
	// A context derived from it reports the same.
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	if !LockLost(child) {
		t.Fatal("derived context doesn't report the lost lock")
	}
}

// TestLockHeartbeatErrors: failing heartbeats are retried while the lease
// could still be ours, and the run is stopped once it can't be.
func TestLockHeartbeatErrors(t *testing.T) {
	store := &fakeLockStore{}
	l, ctx, err := acquireLock(context.Background(), store, "a", quickLock, nologf)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release(context.Background())
	start := time.Now()
	store.set(func(f *fakeLockStore) { f.refreshErr = errors.New("connection reset") })
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("context not cancelled after a lease without a heartbeat")
	}
	if elapsed := time.Since(start); elapsed < quickLock.Lease/2 {
		t.Fatalf("gave up after %s, before the lease could have lapsed", elapsed)
	}
	if !LockLost(ctx) {
		t.Fatalf("cause %v, want the lock lost", context.Cause(ctx))
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.refreshes < 2 {
		t.Fatalf("%d heartbeats, want retries before giving up", store.refreshes)
	}
}

func TestLockReleaseIsIdempotentAndNotALoss(t *testing.T) {
	store := &fakeLockStore{}
	l, ctx, err := acquireLock(context.Background(), store, "a", quickLock, nologf)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.Release(cancelled); err != nil { // still releases
		t.Fatal(err)
	}
	if err := l.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.released) != 1 || store.released[0] != "a" {
		t.Fatalf("released %v, want [a] once", store.released)
	}
	if ctx.Err() == nil || LockLost(ctx) {
		t.Fatalf("after Release: err %v, cause %v; want cancelled, not lost", ctx.Err(), context.Cause(ctx))
	}
}

func TestLockOptionsDefaults(t *testing.T) {
	o := LockOptions{}.withDefaults()
	if o.Lease != 30*time.Minute || o.Wait != 15*time.Minute || o.Poll != 5*time.Second {
		t.Fatalf("defaults %+v", o)
	}
}
