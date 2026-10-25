package harness

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A batch poll whose token expired (UAT Run 2's I.win_shortcut.present:
// "GET batch ...: HTTP 401 unauthorized" after 6m10s) renews it and goes
// on (W11).
func TestAuthedRenewsOnce(t *testing.T) {
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer new" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized","message":"token expired"}`))
			return
		}
		if polls.Add(1) < 2 {
			_, _ = w.Write([]byte(`{"batch_id":"b1","status":"running"}`))
			return
		}
		_, _ = w.Write([]byte(`{"batch_id":"b1","status":"completed"}`))
	}))
	defer srv.Close()
	var renewed atomic.Int32
	tok := func(_ context.Context, renew bool) (string, error) {
		if renew {
			renewed.Add(1)
			return "new", nil
		}
		if renewed.Load() > 0 {
			return "new", nil
		}
		return "old", nil
	}
	c := NewClient(srv.URL, "x", srv.Client()).Authed(tok)
	b, err := c.WaitBatch(context.Background(), "", "t1", "b1", time.Minute)
	if err != nil || b.Status != BatchCompleted {
		t.Fatalf("batch %+v, %v", b, err)
	}
	if renewed.Load() != 1 {
		t.Errorf("renewed %d times, want 1", renewed.Load())
	}
}

// A 401 that a renewed token gets too stays a 401 (a second renewal would
// hide a real refusal), and an explicit token is never renewed: the auth
// scenarios test exactly the token they send.
func TestAuthedRetriesOnlyOnce(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	var renewed atomic.Int32
	tok := func(_ context.Context, renew bool) (string, error) {
		if renew {
			renewed.Add(1)
		}
		return "t", nil
	}
	c := NewClient(srv.URL, "x", srv.Client()).Authed(tok)
	r, err := c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/v1/x"})
	if err != nil || r.Status != http.StatusUnauthorized || calls.Load() != 2 || renewed.Load() != 1 {
		t.Errorf("status %v err %v calls %d renewed %d", r, err, calls.Load(), renewed.Load())
	}
	calls.Store(0)
	r, _ = c.Do(context.Background(), Request{Method: http.MethodGet, Path: "/v1/x", Token: "explicit"})
	if r.Status != http.StatusUnauthorized || calls.Load() != 1 || renewed.Load() != 1 {
		t.Errorf("an explicit token was retried: calls %d renewed %d", calls.Load(), renewed.Load())
	}
	if _, err := NewClient(srv.URL, "x", srv.Client()).Do(context.Background(), Request{Method: http.MethodGet, Path: "/v1/x"}); err != nil {
		t.Errorf("plain client: %v", err)
	}
}

// The cache hands out no token within a minute of its expiry.
func TestTokensRefreshAMinuteEarly(t *testing.T) {
	f, _ := fakeFleet(t)
	c := ctx(t)
	a, err := f.Tokens.Tenant(c, 1, RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := DecodeClaims(a)
	exp, _ := claims["exp"].(float64)
	if exp == 0 {
		t.Fatalf("no exp in %v", claims)
	}
	exptime := time.Unix(int64(exp), 0)
	f.Tokens.now = func() time.Time { return exptime.Add(-61 * time.Second) }
	if b, _ := f.Tokens.Tenant(c, 1, RoleAdmin); b != a {
		t.Error("a token 61 s from expiry should still be served")
	}
	f.Tokens.now = func() time.Time { return exptime.Add(-59 * time.Second) }
	time.Sleep(1100 * time.Millisecond) // a new token gets a new iat
	b, err := f.Tokens.Tenant(c, 1, RoleAdmin)
	if err != nil || b == a {
		t.Errorf("a token 59 s from expiry was served again (%v)", err)
	}
	fn := f.Tokens.TenantFunc(1, RoleAdmin)
	time.Sleep(1100 * time.Millisecond)
	d, err := fn(c, true)
	if err != nil || d == b || !strings.Contains(d, ".") {
		t.Errorf("renew gave the cached token again (%v)", err)
	}
	if e, _ := fn(c, false); e != d {
		t.Error("the renewed token is not the cached one")
	}
}
