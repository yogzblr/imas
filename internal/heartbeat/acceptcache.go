package heartbeat

import (
	"container/list"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/yogzblr/imas/internal/pki"
)

// The heartbeat handler asks "is this an accepted sprout of this tenant"
// (pki.VerifySproutInTenant: a pki_tenants read for a non-legacy tenant plus
// a pki_nkeys read, two queries) for every heartbeat. At the 1M-sprout plan
// and a 60 second Interval that is about 16,700 checks a second; this cache
// answers repeats from memory instead.
//
// Rules, all deliberate:
//   - Only positive results are cached. A sprout that is not accepted, an
//     unknown or deprovisioned tenant, an invalid ID or a database error is
//     checked again on the next heartbeat, so a newly accepted sprout works
//     at once and an outage is never remembered.
//   - Keyed on (tenant ID, sprout ID), never the sprout ID alone: sprout IDs
//     are unique per tenant only (CLAUDE.md).
//   - Staleness is ACCEPTED: a sprout that is denied, rejected, unaccepted
//     or deleted, or whose tenant is deprovisioned, can keep refreshing its
//     presence key for up to the entry's lifetime (DefaultAcceptCacheTTL
//     plus up to 10% jitter) on each farmer replica that cached it. That
//     affects only the "connected" flag. Command authority does not depend
//     on it: it is enforced by the NATS User JWT permissions and the Account
//     revocation list, and the CONNECT/DISCONNECT path does not use this
//     cache at all.
//   - pki.VerifySproutInTenant itself is not cached; its other callers keep
//     the live check.

const (
	// DefaultAcceptCacheTTL is how long a positive result is trusted. It
	// must be longer than Interval or the cache never hits (asserted in a
	// test); jitter only ever lengthens it.
	DefaultAcceptCacheTTL = 10 * time.Minute
	// DefaultAcceptCacheMax bounds the entries per farmer replica. Each is
	// a map slot, a list element and a key of two short strings: roughly
	// 200 to 250 bytes with the string data, so about 40 to 50 MB at the
	// default.
	DefaultAcceptCacheMax = 200000
	// acceptCacheJitter is the largest fraction of the lifetime added at
	// random to each entry, so entries made together do not expire together.
	acceptCacheJitter = 0.10
)

type acceptKey struct{ tenantID, sproutID string }

type acceptEntry struct {
	key     acceptKey
	expires time.Time
}

// acceptCache is a bounded, concurrency-safe LRU of positive accepted-sprout
// checks with per-entry expiry.
type acceptCache struct {
	ttl    time.Duration
	max    int
	lookup func(tenantID, sproutID string) error // the live check
	now    func() time.Time
	jitter func() float64 // in [0, 1)

	mu sync.Mutex
	ll *list.List // front = most recently used
	m  map[acceptKey]*list.Element
}

func newAcceptCache(ttl time.Duration, max int, lookup func(tenantID, sproutID string) error) *acceptCache {
	return &acceptCache{
		ttl: ttl, max: max, lookup: lookup,
		now: time.Now, jitter: rand.Float64,
		ll: list.New(), m: make(map[acceptKey]*list.Element),
	}
}

// check returns nil if sproutID is an accepted sprout of tenantID, from the
// cache when a live entry exists, otherwise from the live lookup (caching
// only a nil result). Any error is the live lookup's, uncached.
func (c *acceptCache) check(tenantID, sproutID string) error {
	k := acceptKey{tenantID, sproutID}
	if c.max > 0 {
		c.mu.Lock()
		if el, ok := c.m[k]; ok {
			if c.now().Before(el.Value.(*acceptEntry).expires) {
				c.ll.MoveToFront(el)
				c.mu.Unlock()
				return nil
			}
			c.ll.Remove(el)
			delete(c.m, k)
		}
		c.mu.Unlock()
	}

	if err := c.lookup(tenantID, sproutID); err != nil {
		return err
	}
	if c.max <= 0 {
		return nil
	}

	expires := c.now().Add(c.ttl + time.Duration(float64(c.ttl)*acceptCacheJitter*c.jitter()))
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[k]; ok { // a concurrent check got here first
		el.Value.(*acceptEntry).expires = expires
		c.ll.MoveToFront(el)
		return nil
	}
	c.m[k] = c.ll.PushFront(&acceptEntry{key: k, expires: expires})
	for c.ll.Len() > c.max {
		oldest := c.ll.Back()
		c.ll.Remove(oldest)
		delete(c.m, oldest.Value.(*acceptEntry).key)
	}
	return nil
}

func (c *acceptCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

// acceptedSprouts is the cache handleHeartbeat uses. Tests replace it.
var acceptedSprouts = newAcceptCache(DefaultAcceptCacheTTL, DefaultAcceptCacheMax, pki.VerifySproutInTenant)
