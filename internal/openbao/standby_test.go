package openbao

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// The two answers OpenBao 2.6.3's KV v2 gives while a mount enabled
// moments ago upgrades, as captured in UAT HA run 42448281672.
const (
	kvWaitingStandby  = `{"errors":["Waiting for the primary to upgrade from non-versioned to versioned data. This backend will be unavailable for a brief period and will resume service when the primary is finished."]}`
	kvUpgradingActive = `{"errors":["Upgrading from non-versioned to versioned data. This backend will be unavailable for a brief period and will resume service shortly."]}`
)

func shortenWaits(t *testing.T, upgrade, readBack time.Duration) {
	t.Helper()
	oldW, oldB, oldR, oldRB := KVUpgradeWait, kvUpgradeBackoff, ReadBackWindow, readBackBackoff
	KVUpgradeWait, kvUpgradeBackoff, ReadBackWindow, readBackBackoff = upgrade, time.Millisecond, readBack, time.Millisecond
	t.Cleanup(func() { KVUpgradeWait, kvUpgradeBackoff, ReadBackWindow, readBackBackoff = oldW, oldB, oldR, oldRB })
}

// upgradingServer answers the first n requests with body (400), then 200.
func upgradingServer(t *testing.T, n int32, body string) (*Client, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= n {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(body))
			return
		}
		w.Write([]byte(`{"data":{"version":1}}`))
	}))
	t.Cleanup(srv.Close)
	setTokenEnv(t, srv.URL, "tok")
	c, err := NewFromEnv(testEnv, testErrs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c, &calls
}

func TestKVUpgradeIsRetried(t *testing.T) {
	shortenWaits(t, 5*time.Second, time.Second)
	for name, body := range map[string]string{"standby": kvWaitingStandby, "active": kvUpgradingActive} {
		t.Run(name, func(t *testing.T) {
			c, calls := upgradingServer(t, 3, body)
			if _, err := c.Put(t.Context(), "secret/data/p", map[string]any{"data": map[string]string{"k": "v"}}); err != nil {
				t.Fatalf("Put: %v", err)
			}
			if got := calls.Load(); got != 4 {
				t.Fatalf("%d requests, want 4 (three upgrading answers, then the write)", got)
			}
		})
	}
}

func TestKVUpgradeGivesUpAtTheDeadline(t *testing.T) {
	shortenWaits(t, 50*time.Millisecond, time.Second)
	c, calls := upgradingServer(t, 1<<30, kvWaitingStandby)
	_, err := c.Read(t.Context(), "secret/data/p", nil)
	if !IsKVUpgrading(err) {
		t.Fatalf("got %v, want the upgrade answer", err)
	}
	if calls.Load() < 2 {
		t.Fatalf("%d requests: not retried", calls.Load())
	}
}

// Any other 400 (a check-and-set refusal here) is still answered at once.
func TestOther400NotRetried(t *testing.T) {
	shortenWaits(t, 5*time.Second, time.Second)
	c, calls := upgradingServer(t, 1<<30, `{"errors":["check-and-set parameter did not match the current version"]}`)
	_, err := c.Put(t.Context(), "secret/data/p", map[string]any{})
	if StatusCode(err) != 400 || IsKVUpgrading(err) {
		t.Fatalf("got %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("%d requests, want 1", calls.Load())
	}
}

func TestIsKVUpgrading(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("non-versioned to versioned data"), false},
		{&StatusError{StatusCode: 400, Errors: []string{"Waiting for the primary to upgrade from non-versioned to versioned data."}}, true},
		{&StatusError{StatusCode: 400, Errors: []string{"Upgrading from non-versioned to versioned data."}}, true},
		{&StatusError{StatusCode: 500, Errors: []string{"Upgrading from non-versioned to versioned data."}}, false},
		{&StatusError{StatusCode: 400, Errors: []string{"check-and-set parameter did not match"}}, false},
		{&StatusError{StatusCode: 400}, false},
	} {
		if got := IsKVUpgrading(tc.err); got != tc.want {
			t.Errorf("IsKVUpgrading(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

func TestAwaitReadBack(t *testing.T) {
	shortenWaits(t, time.Second, 200*time.Millisecond)
	t.Run("found after a lag", func(t *testing.T) {
		n := 0
		found, err := AwaitReadBack(t.Context(), func(context.Context) (bool, error) { n++; return n == 3, nil })
		if !found || err != nil || n != 3 {
			t.Fatalf("found %v, err %v after %d reads", found, err, n)
		}
	})
	t.Run("never found", func(t *testing.T) {
		start, n := time.Now(), 0
		found, err := AwaitReadBack(t.Context(), func(context.Context) (bool, error) { n++; return false, nil })
		if found || err != nil || n < 2 || time.Since(start) > 2*time.Second {
			t.Fatalf("found %v, err %v, %d reads in %v", found, err, n, time.Since(start))
		}
	})
	t.Run("an error ends it", func(t *testing.T) {
		boom, n := errors.New("boom"), 0
		_, err := AwaitReadBack(t.Context(), func(context.Context) (bool, error) { n++; return false, boom })
		if !errors.Is(err, boom) || n != 1 {
			t.Fatalf("err %v after %d reads", err, n)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := AwaitReadBack(ctx, func(context.Context) (bool, error) { return false, nil })
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err %v", err)
		}
	})
}
