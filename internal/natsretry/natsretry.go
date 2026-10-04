// Package natsretry computes how long a sprout waits before its next
// attempt to reach the bus: exponential backoff with full jitter.
//
// A bus restart disconnects every sprout at the same moment. With a fixed
// wait (the sprout's old nats.ReconnectWait(15s)) they all come back at
// the same moment too, and at 1M sprouts that is a reconnect storm
// against the bus and Envoy, each attempt costing a TLS handshake and a
// JWT check even when it is refused (docs/design/imas-1m-scale-plan.md,
// Phase 2). Full jitter spreads attempt n uniformly over
// [0, min(cap, base*2^(n-1))], so the first retries of a fleet are spread
// across the base window and later ones thin out as the ceiling grows.
//
// Backoff.Delay has the signature of nats.ReconnectDelayHandler. nats.go
// calls it once per pass over the server list with the number of passes
// so far in the current outage, and starts counting from 1 again after
// every successful (re)connect, so the backoff resets on success without
// any state here.
package natsretry

import (
	"math"
	"math/rand/v2"
	"time"
)

// Defaults for the sprout config keys "busreconnectbase" and
// "busreconnectcap".
const (
	DefaultBase = 2 * time.Second
	DefaultCap  = 5 * time.Minute
)

// Backoff is an exponential backoff with full jitter. It holds no
// per-attempt state; the zero value is not usable, use New.
type Backoff struct {
	base, limit time.Duration
	int64n      func(n int64) int64
}

// New returns a Backoff whose ceiling starts at base and doubles with
// every attempt up to cap. A non-positive base or cap falls back to
// DefaultBase or DefaultCap, and a cap below base is raised to base: the
// effective values are Base and Cap.
//
// int64n returns a uniform random number in [0, n), like
// math/rand/v2.Int64N, which is used when int64n is nil. Tests pass a
// seeded source. It must be safe for concurrent use if the Backoff is
// shared between goroutines; rand.Int64N is.
func New(base, limit time.Duration, int64n func(n int64) int64) *Backoff {
	if base <= 0 {
		base = DefaultBase
	}
	if limit <= 0 {
		limit = DefaultCap
	}
	if limit < base {
		limit = base
	}
	if int64n == nil {
		int64n = rand.Int64N
	}
	return &Backoff{base: base, limit: limit, int64n: int64n}
}

// Base is the ceiling of the first attempt's delay.
func (b *Backoff) Base() time.Duration { return b.base }

// Cap is the largest delay Backoff ever returns.
func (b *Backoff) Cap() time.Duration { return b.limit }

// Ceiling is the largest delay attempt (1-based) can get:
// min(Cap, Base*2^(attempt-1)). Attempts below 1 count as 1.
func (b *Backoff) Ceiling(attempt int) time.Duration {
	c := b.base
	for i := 1; i < attempt; i++ {
		if c > b.limit/2 {
			return b.limit
		}
		c *= 2
	}
	return min(c, b.limit)
}

// Delay returns a uniformly random delay in [0, Ceiling(attempt)]. It is
// a nats.ReconnectDelayHandler.
func (b *Backoff) Delay(attempt int) time.Duration {
	c := int64(b.Ceiling(attempt))
	n := c
	if n < math.MaxInt64 {
		n++ // make c itself reachable
	}
	d := b.int64n(n)
	// Guard against an injected source that ignores its bound.
	return time.Duration(max(0, min(d, c)))
}
