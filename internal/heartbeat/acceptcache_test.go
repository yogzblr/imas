package heartbeat

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/pki"
)

// testCache builds a cache with a fake clock, no jitter and a call-counting
// lookup. fail lists "tenant/sprout" pairs the lookup refuses.
type testCache struct {
	*acceptCache
	calls atomic.Int64
	cmu   sync.Mutex
	clock time.Time
	fail  map[string]bool
}

func newTestCache(ttl time.Duration, max int) *testCache {
	tc := &testCache{clock: time.Unix(1_000_000, 0), fail: map[string]bool{}}
	tc.acceptCache = newAcceptCache(ttl, max, func(tenant, sprout string) error {
		tc.calls.Add(1)
		tc.cmu.Lock()
		defer tc.cmu.Unlock()
		if tc.fail[tenant+"/"+sprout] {
			return pki.ErrSproutIDNotFound
		}
		return nil
	})
	tc.now = func() time.Time { tc.cmu.Lock(); defer tc.cmu.Unlock(); return tc.clock }
	tc.jitter = func() float64 { return 0 }
	return tc
}

func (tc *testCache) advance(d time.Duration) {
	tc.cmu.Lock()
	tc.clock = tc.clock.Add(d)
	tc.cmu.Unlock()
}
func (tc *testCache) setFail(tenant, sprout string, v bool) {
	tc.cmu.Lock()
	tc.fail[tenant+"/"+sprout] = v
	tc.cmu.Unlock()
}

// The lifetime must exceed the heartbeat interval, or every heartbeat misses.
func TestAcceptCache_DefaultLifetimeExceedsInterval(t *testing.T) {
	if DefaultAcceptCacheTTL <= Interval {
		t.Fatalf("DefaultAcceptCacheTTL %s must be longer than Interval %s", DefaultAcceptCacheTTL, Interval)
	}
	if DefaultAcceptCacheMax <= 0 {
		t.Fatal("DefaultAcceptCacheMax must be positive")
	}
	if acceptedSprouts.ttl != DefaultAcceptCacheTTL || acceptedSprouts.max != DefaultAcceptCacheMax {
		t.Fatal("production cache does not use the defaults")
	}
}

func TestAcceptCache_HitAvoidsSecondLookup(t *testing.T) {
	c := newTestCache(time.Minute*10, 10)
	for i := 0; i < 5; i++ {
		if err := c.check("t_a", "web-01"); err != nil {
			t.Fatal(err)
		}
		c.advance(time.Minute) // one heartbeat interval
	}
	if n := c.calls.Load(); n != 1 {
		t.Fatalf("lookups = %d, want 1", n)
	}
}

func TestAcceptCache_ExpiryCausesRecheck(t *testing.T) {
	c := newTestCache(10*time.Minute, 10)
	_ = c.check("t_a", "web-01")
	c.advance(10*time.Minute - time.Second)
	_ = c.check("t_a", "web-01")
	if n := c.calls.Load(); n != 1 {
		t.Fatalf("lookups before expiry = %d, want 1", n)
	}
	c.advance(2 * time.Second)
	if err := c.check("t_a", "web-01"); err != nil {
		t.Fatal(err)
	}
	if n := c.calls.Load(); n != 2 {
		t.Fatalf("lookups after expiry = %d, want 2", n)
	}
	// An expired entry that now fails is refused (and so not refreshed).
	c.advance(11 * time.Minute)
	c.setFail("t_a", "web-01", true)
	if err := c.check("t_a", "web-01"); !errors.Is(err, pki.ErrSproutIDNotFound) {
		t.Fatalf("check after expiry and revocation = %v, want ErrSproutIDNotFound", err)
	}
	if c.len() != 0 {
		t.Fatalf("len = %d after the expired entry failed its recheck, want 0", c.len())
	}
}

func TestAcceptCache_JitterOnlyLengthensWithinTenPercent(t *testing.T) {
	for _, j := range []float64{0, 0.5, 0.999999} {
		c := newTestCache(10*time.Minute, 10)
		c.jitter = func() float64 { return j }
		_ = c.check("t_a", "web-01")
		c.acceptCache.mu.Lock()
		exp := c.m[acceptKey{"t_a", "web-01"}].Value.(*acceptEntry).expires
		c.acceptCache.mu.Unlock()
		d := exp.Sub(time.Unix(1_000_000, 0))
		if d < 10*time.Minute || d > 11*time.Minute {
			t.Fatalf("jitter %v: lifetime %s outside [10m, 11m]", j, d)
		}
	}
}

func TestAcceptCache_FailureIsNotCached(t *testing.T) {
	c := newTestCache(10*time.Minute, 10)
	c.setFail("t_a", "web-01", true)
	for i := 0; i < 3; i++ {
		if err := c.check("t_a", "web-01"); !errors.Is(err, pki.ErrSproutIDNotFound) {
			t.Fatalf("check = %v, want ErrSproutIDNotFound", err)
		}
	}
	if n := c.calls.Load(); n != 3 {
		t.Fatalf("lookups = %d, want 3 (every failure re-checked)", n)
	}
	if c.len() != 0 {
		t.Fatalf("len = %d, a failure was cached", c.len())
	}
	// Newly accepted: works at once.
	c.setFail("t_a", "web-01", false)
	if err := c.check("t_a", "web-01"); err != nil {
		t.Fatalf("newly accepted sprout refused: %v", err)
	}
	// A database error is not remembered either.
	c2 := newAcceptCache(time.Minute, 10, func(string, string) error { return fmt.Errorf("db down") })
	if err := c2.check("t_a", "x"); err == nil || c2.len() != 0 {
		t.Fatalf("db error: err=%v len=%d", err, c2.len())
	}
}

func TestAcceptCache_LRUEvictionAtBound(t *testing.T) {
	c := newTestCache(10*time.Minute, 2)
	_ = c.check("t", "a")
	_ = c.check("t", "b")
	_ = c.check("t", "a") // a is now most recent
	_ = c.check("t", "c") // evicts b
	if c.len() != 2 {
		t.Fatalf("len = %d, want 2", c.len())
	}
	before := c.calls.Load()
	_ = c.check("t", "a")
	_ = c.check("t", "c")
	if c.calls.Load() != before {
		t.Fatal("a and c should still be cached")
	}
	_ = c.check("t", "b")
	if c.calls.Load() != before+1 {
		t.Fatal("b should have been evicted and looked up again")
	}
	for i := 0; i < 100; i++ {
		_ = c.check("t", fmt.Sprintf("s%d", i))
	}
	if c.len() != 2 {
		t.Fatalf("len = %d after many inserts, want 2", c.len())
	}
}

func TestAcceptCache_ZeroMaxCachesNothing(t *testing.T) {
	c := newTestCache(time.Minute, 0)
	_ = c.check("t", "a")
	_ = c.check("t", "a")
	if c.calls.Load() != 2 || c.len() != 0 {
		t.Fatalf("calls=%d len=%d, want 2 and 0", c.calls.Load(), c.len())
	}
}

// The same sprout ID in two tenants is two entries: a cached "accepted" in
// one tenant says nothing about the other.
func TestAcceptCache_SameSproutIDInTwoTenantsIsIndependent(t *testing.T) {
	c := newTestCache(10*time.Minute, 10)
	c.setFail("t_a", "web-01", true)
	if err := c.check("t_b", "web-01"); err != nil { // accepted in t_b, cached
		t.Fatal(err)
	}
	if err := c.check("t_a", "web-01"); !errors.Is(err, pki.ErrSproutIDNotFound) {
		t.Fatalf("t_a/web-01 = %v; a cached result from t_b leaked across tenants", err)
	}
	if c.len() != 1 {
		t.Fatalf("len = %d, want 1", c.len())
	}
	c.setFail("t_a", "web-01", false)
	c.setFail("t_b", "web-01", true)
	if err := c.check("t_a", "web-01"); err != nil {
		t.Fatal(err)
	}
	if err := c.check("t_b", "web-01"); err != nil { // still cached positive in t_b
		t.Fatalf("t_b entry not served from its own cache slot: %v", err)
	}
	if c.len() != 2 {
		t.Fatalf("len = %d, want 2 (one entry per tenant)", c.len())
	}
}

func TestAcceptCache_ConcurrentUse(t *testing.T) {
	c := newTestCache(10*time.Minute, 50)
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				_ = c.check(fmt.Sprintf("t%d", g%3), fmt.Sprintf("s%d", i%80))
				if i%100 == 0 {
					c.advance(time.Minute)
				}
			}
		}(g)
	}
	wg.Wait()
	if n := c.len(); n > 50 {
		t.Fatalf("len = %d exceeds the bound 50", n)
	}
	c.acceptCache.mu.Lock()
	defer c.acceptCache.mu.Unlock()
	if len(c.m) != c.ll.Len() {
		t.Fatalf("map (%d) and list (%d) disagree", len(c.m), c.ll.Len())
	}
}

// Through the real handler: the second heartbeat is served from the cache,
// so a sprout unaccepted in between keeps refreshing its presence key until
// the entry expires. This is the staleness the design accepts (presence flag
// only); once the entry lapses the sprout is refused.
func TestHandleHeartbeat_UsesCacheAndAcceptsDocumentedStaleness(t *testing.T) {
	newTestPKIDB(t)
	mr := newTestValkey(t)
	tenant := pki.CurrentTenantID()
	acceptSprout(t, tenant, "web-01", "UHBWEB01")
	var lookups atomic.Int64
	clock := &struct {
		sync.Mutex
		t time.Time
	}{t: time.Unix(1_000_000, 0)}
	acceptedSprouts = newAcceptCache(10*time.Minute, 10, func(ten, id string) error {
		lookups.Add(1)
		return pki.VerifySproutInTenant(ten, id)
	})
	acceptedSprouts.now = func() time.Time { clock.Lock(); defer clock.Unlock(); return clock.t }
	acceptedSprouts.jitter = func() float64 { return 0 }
	subj := pki.SproutHeartbeatSubject("web-01")
	ctx := context.Background()

	handleHeartbeat(tenant, subj)
	mr.FastForward(testTTL)
	if IsOnline(ctx, tenant, "web-01") {
		t.Fatal("key should have lapsed")
	}
	if err := pki.UnacceptNKey(tenant, "web-01", "UHBWEB01"); err != nil {
		t.Fatalf("UnacceptNKey: %v", err)
	}
	handleHeartbeat(tenant, subj)
	if !IsOnline(ctx, tenant, "web-01") || lookups.Load() != 1 {
		t.Fatalf("cached entry not used: online=%v lookups=%d", IsOnline(ctx, tenant, "web-01"), lookups.Load())
	}

	mr.FastForward(testTTL)
	clock.Lock()
	clock.t = clock.t.Add(11 * time.Minute)
	clock.Unlock()
	handleHeartbeat(tenant, subj)
	if IsOnline(ctx, tenant, "web-01") || lookups.Load() != 2 {
		t.Fatalf("after the entry expired the unaccepted sprout must be refused: online=%v lookups=%d", IsOnline(ctx, tenant, "web-01"), lookups.Load())
	}
}
