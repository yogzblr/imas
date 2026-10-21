package accountloader

import (
	"context"
	"sync"
	"testing"
	"time"
)

// P30: with the production start-up backoff (500ms doubling to 30s), a
// loader that has waited a long time for farmer's first Accounts still
// polls at most every InitialPollInterval (±20%) while the initial load
// is incomplete, and loads them on the next run once they appear.
func TestInitialLoadPollsFastWhileIncomplete(t *testing.T) {
	tr, b, node := newTrust(t), newBucket(t), newFakeNode()
	cfg := fastConfig(tr, b.src(t), node)
	cfg.Backoff = Backoff{Min: 500 * time.Millisecond, Max: 30 * time.Second}
	cfg.InitialPollInterval = 5 * time.Second

	var mu sync.Mutex
	var waits []time.Duration
	cfg.Sleep = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		waits = append(waits, d)
		mu.Unlock()
		time.Sleep(time.Millisecond)
		return ctx.Err()
	}
	nWaits := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(waits)
	}
	l := newLoader(t, cfg)
	run(t, l)

	// Long enough for the uncapped backoff to reach its 30s maximum.
	waitFor(t, "twenty failed start-up runs", func() bool { return nWaits() >= 20 })
	if l.Ready() || l.Status().State != StateNotInitialised {
		t.Fatalf("state %q with an empty bucket", l.Status().State)
	}
	b.putAccount(t, tr.sysPub, tr.jwt(t, tr.sysPub, 100))
	waitFor(t, "ready", l.Ready)

	mu.Lock()
	defer mu.Unlock()
	for i, d := range waits {
		if d > 6*time.Second {
			t.Fatalf("wait %d was %s, want at most 6s (5s +20%%) during the initial load", i+1, d)
		}
	}
}

func TestInitialWaitCapped(t *testing.T) {
	tr := newTrust(t)
	cfg := fastConfig(tr, nil, nil)
	cfg.Backoff = Backoff{Min: 500 * time.Millisecond, Max: 30 * time.Second}
	cfg.InitialPollInterval = 0 // the default
	cfg.setDefaults()
	l := &Loader{cfg: cfg}
	if cfg.InitialPollInterval != DefaultInitialPollInterval {
		t.Fatalf("InitialPollInterval default %s, want %s", cfg.InitialPollInterval, DefaultInitialPollInterval)
	}
	for attempt := 1; attempt <= 40; attempt++ {
		for range 20 {
			if d := l.initialWait(attempt); d > 6*time.Second {
				t.Fatalf("attempt %d waited %s, want at most 6s", attempt, d)
			}
		}
	}
	// Early attempts keep the short exponential backoff.
	if d := l.initialWait(1); d > 500*time.Millisecond {
		t.Fatalf("attempt 1 waited %s, want at most 500ms", d)
	}
}
