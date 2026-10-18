package sdb

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestTokenCache_FetchesOnceAndReuses(t *testing.T) {
	calls := 0
	c := &TokenCache{
		Fetch: func(context.Context) (string, time.Duration, error) {
			calls++
			return "tok", time.Hour, nil
		},
	}
	for i := 0; i < 3; i++ {
		tok, err := c.Get(t.Context())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tok != "tok" {
			t.Errorf("got %q, want %q", tok, "tok")
		}
	}
	if calls != 1 {
		t.Errorf("expected 1 fetch, got %d", calls)
	}
}

func TestTokenCache_RefreshesAfterExpiry(t *testing.T) {
	calls := 0
	c := &TokenCache{
		Fetch: func(context.Context) (string, time.Duration, error) {
			calls++
			return "tok", time.Millisecond, nil
		},
		Margin: 0,
	}
	if _, err := c.Get(t.Context()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, err := c.Get(t.Context()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 2 {
		t.Errorf("expected a refresh after expiry, got %d fetches", calls)
	}
}

func TestTokenCache_MarginTriggersEarlyRefresh(t *testing.T) {
	calls := 0
	c := &TokenCache{
		Fetch: func(context.Context) (string, time.Duration, error) {
			calls++
			return "tok", 10 * time.Millisecond, nil
		},
		Margin: 9 * time.Millisecond, // leaves only ~1ms of "fresh" life
	}
	if _, err := c.Get(t.Context()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	if _, err := c.Get(t.Context()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 2 {
		t.Errorf("expected the margin to force an early refresh, got %d fetches", calls)
	}
}

func TestTokenCache_PropagatesFetchError(t *testing.T) {
	wantErr := errors.New("boom")
	c := &TokenCache{
		Fetch: func(context.Context) (string, time.Duration, error) {
			return "", 0, wantErr
		},
	}
	_, err := c.Get(t.Context())
	if !errors.Is(err, wantErr) {
		t.Errorf("got error %v, want %v", err, wantErr)
	}
}

func TestTokenCache_Invalidate(t *testing.T) {
	calls := 0
	c := &TokenCache{
		Fetch: func(context.Context) (string, time.Duration, error) {
			calls++
			return "tok", time.Hour, nil
		},
	}
	if _, err := c.Get(t.Context()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c.Invalidate()
	if _, err := c.Get(t.Context()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 2 {
		t.Errorf("expected Invalidate to force a refetch, got %d fetches", calls)
	}
}

// TestTokenCache_InvalidateDuringFetch: a token fetched while Invalidate
// ran (a certificate reload in the middle of a login) is returned to that
// caller but not cached, so the next Get fetches again.
func TestTokenCache_InvalidateDuringFetch(t *testing.T) {
	calls := 0
	var c *TokenCache
	c = &TokenCache{
		Fetch: func(context.Context) (string, time.Duration, error) {
			calls++
			if calls == 1 {
				c.Invalidate()
				return "old-cert-token", time.Hour, nil
			}
			return "new-cert-token", time.Hour, nil
		},
	}
	if tok, err := c.Get(t.Context()); err != nil || tok != "old-cert-token" {
		t.Fatalf("first Get = %q, %v", tok, err)
	}
	if tok, err := c.Get(t.Context()); err != nil || tok != "new-cert-token" {
		t.Fatalf("second Get = %q, %v; want a fresh fetch", tok, err)
	}
	if tok, _ := c.Get(t.Context()); tok != "new-cert-token" || calls != 2 {
		t.Fatalf("third Get = %q after %d fetches; want the cached new-cert-token", tok, calls)
	}
}
