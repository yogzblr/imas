package sdb

import (
	"context"
	"sync"
	"time"
)

// TokenCache caches a bearer credential (e.g. a cloud managed-identity
// access token) obtained from a Fetch func, refreshing it once it's within
// margin of expiry. It's shared by the managed-identity-based providers
// (azurekv, awssm, gcpsm), which otherwise duplicate the same
// fetch-cache-refresh shape around three different metadata endpoints.
type TokenCache struct {
	// Fetch obtains a fresh token and how long it's valid for.
	Fetch func(ctx context.Context) (token string, ttl time.Duration, err error)
	// Margin is how far before actual expiry a cached token is treated as
	// stale and refreshed. Defaults to 10% of the last-seen TTL when zero.
	Margin time.Duration

	mu     sync.Mutex
	token  string
	expiry time.Time
	// gen counts Invalidate calls, so a Fetch that started before one
	// does not cache what it fetched afterwards.
	gen uint64
}

// Get returns a cached token, calling Fetch if there is no token yet or
// the cached one is within Margin of its expiry.
func (c *TokenCache) Get(ctx context.Context) (string, error) {
	c.mu.Lock()
	tok := c.token
	valid := tok != "" && time.Now().Before(c.expiry)
	gen := c.gen
	c.mu.Unlock()
	if valid {
		return tok, nil
	}

	tok, ttl, err := c.Fetch(ctx)
	if err != nil {
		return "", err
	}
	margin := c.Margin
	if margin == 0 {
		margin = ttl / 10
	}
	c.mu.Lock()
	// An Invalidate while Fetch ran (a certificate reload) means tok may
	// have been obtained with what was just invalidated: use it for this
	// call, but don't cache it.
	if c.gen == gen {
		c.token = tok
		c.expiry = time.Now().Add(ttl - margin)
	}
	c.mu.Unlock()
	return tok, nil
}

// Invalidate clears the cached token, forcing the next Get to call Fetch.
func (c *TokenCache) Invalidate() {
	c.mu.Lock()
	c.token = ""
	c.gen++
	c.mu.Unlock()
}
