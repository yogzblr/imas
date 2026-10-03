package natsretry

import (
	"math/rand/v2"
	"slices"
	"testing"
	"time"
)

// seeded returns a deterministic int64n, so the statistical tests below
// can't flake.
func seeded(seed uint64) func(n int64) int64 {
	return rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)).Int64N
}

func TestNewDefaultsAndClamps(t *testing.T) {
	for _, tc := range []struct {
		name              string
		base, limit       time.Duration
		wantBase, wantCap time.Duration
	}{
		{"zero", 0, 0, DefaultBase, DefaultCap},
		{"negative", -time.Second, -time.Minute, DefaultBase, DefaultCap},
		{"explicit", time.Second, time.Minute, time.Second, time.Minute},
		{"cap below base", 10 * time.Second, time.Second, 10 * time.Second, 10 * time.Second},
		{"cap below default base", 0, time.Second, DefaultBase, DefaultBase},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := New(tc.base, tc.limit, nil)
			if b.Base() != tc.wantBase || b.Cap() != tc.wantCap {
				t.Errorf("New(%s, %s) = base %s cap %s, want %s and %s", tc.base, tc.limit, b.Base(), b.Cap(), tc.wantBase, tc.wantCap)
			}
		})
	}
}

func TestCeiling(t *testing.T) {
	b := New(2*time.Second, 5*time.Minute, nil)
	want := map[int]time.Duration{
		-3: 2 * time.Second,
		0:  2 * time.Second,
		1:  2 * time.Second,
		2:  4 * time.Second,
		3:  8 * time.Second,
		8:  256 * time.Second,
		9:  5 * time.Minute, // 512s, capped
		50: 5 * time.Minute,
		// Far past where base*2^(n-1) overflows int64.
		1000: 5 * time.Minute,
	}
	for attempt, w := range want {
		if got := b.Ceiling(attempt); got != w {
			t.Errorf("Ceiling(%d) = %s, want %s", attempt, got, w)
		}
	}
}

// TestDelayBounds samples attempts 1 to 50 many times each: every delay
// is within [0, Ceiling(attempt)], none exceeds the cap, the mean grows
// with the ceiling until the cap, and sits near half the cap after it.
func TestDelayBounds(t *testing.T) {
	const samples = 4000
	base, limit := 2*time.Second, 5*time.Minute
	b := New(base, limit, seeded(1))
	means := make([]float64, 51)
	for attempt := 1; attempt <= 50; attempt++ {
		ceil := b.Ceiling(attempt)
		var sum float64
		for range samples {
			d := b.Delay(attempt)
			if d < 0 || d > ceil {
				t.Fatalf("Delay(%d) = %s, outside [0, %s]", attempt, d, ceil)
			}
			if d > limit {
				t.Fatalf("Delay(%d) = %s, above the cap %s", attempt, d, limit)
			}
			sum += float64(d)
		}
		means[attempt] = sum / samples
		// Uniform over [0, ceil]: the mean is ceil/2, and with 4000
		// samples it is within a few percent of it.
		if want := float64(ceil) / 2; means[attempt] < want*0.9 || means[attempt] > want*1.1 {
			t.Errorf("attempt %d: mean delay %s, want about %s", attempt, time.Duration(means[attempt]), time.Duration(want))
		}
		if attempt > 1 && b.Ceiling(attempt) > b.Ceiling(attempt-1) && means[attempt] <= means[attempt-1] {
			t.Errorf("attempt %d: mean delay %s did not grow from attempt %d's %s",
				attempt, time.Duration(means[attempt]), attempt-1, time.Duration(means[attempt-1]))
		}
	}
	if means[50] <= means[1]*10 {
		t.Errorf("mean delay at attempt 50 (%s) is not well above attempt 1's (%s)", time.Duration(means[50]), time.Duration(means[1]))
	}
}

// TestDelayReachesBothEnds checks the jitter is full: a source at its
// extremes gives 0 and exactly the ceiling, and one that ignores its
// bound can't push a delay past the cap or below 0.
func TestDelayReachesBothEnds(t *testing.T) {
	low := New(2*time.Second, time.Minute, func(int64) int64 { return 0 })
	high := New(2*time.Second, time.Minute, func(n int64) int64 { return n - 1 })
	rogue := New(2*time.Second, time.Minute, func(n int64) int64 { return n * 10 })
	negative := New(2*time.Second, time.Minute, func(int64) int64 { return -1 })
	for attempt := 1; attempt <= 50; attempt++ {
		ceil := high.Ceiling(attempt)
		if d := low.Delay(attempt); d != 0 {
			t.Errorf("low source: Delay(%d) = %s, want 0", attempt, d)
		}
		if d := high.Delay(attempt); d != ceil {
			t.Errorf("high source: Delay(%d) = %s, want %s", attempt, d, ceil)
		}
		if d := rogue.Delay(attempt); d != ceil {
			t.Errorf("rogue source: Delay(%d) = %s, want it clamped to %s", attempt, d, ceil)
		}
		if d := negative.Delay(attempt); d != 0 {
			t.Errorf("negative source: Delay(%d) = %s, want it clamped to 0", attempt, d)
		}
	}
}

// TestDelayResetsAfterSuccess: the delay depends only on the attempt
// number nats.go passes, which it restarts at 1 after a successful
// connect (TestNATSRestartsAttemptCountAfterReconnect checks that), so
// the first retry after a long outage is back in the base window.
func TestDelayResetsAfterSuccess(t *testing.T) {
	b := New(2*time.Second, 5*time.Minute, seeded(2))
	for range 1000 {
		for attempt := 1; attempt <= 50; attempt++ {
			b.Delay(attempt)
		}
		if d := b.Delay(1); d > b.Base() {
			t.Fatalf("Delay(1) after a 50-attempt outage = %s, want at most the base %s", d, b.Base())
		}
	}
}

// TestFirstRetrySpread simulates 2000 sprouts, each with its own random
// source, that all lost the bus at the same moment: their first retries
// must spread across the base window, with no more than 15% of them in
// any window a tenth of its length.
func TestFirstRetrySpread(t *testing.T) {
	const sprouts = 2000
	base := DefaultBase
	delays := make([]time.Duration, sprouts)
	for i := range delays {
		delays[i] = New(base, DefaultCap, seeded(uint64(1000+i))).Delay(1)
		if delays[i] < 0 || delays[i] > base {
			t.Fatalf("sprout %d: first delay %s outside [0, %s]", i, delays[i], base)
		}
	}
	slices.Sort(delays)
	slice := base / 10
	maxIn := 0
	// Every window [delays[i], delays[i]+slice] — the busiest window of
	// that length starts at some sprout's delay.
	for i, start := range delays {
		j, _ := slices.BinarySearch(delays, start+slice+1)
		maxIn = max(maxIn, j-i)
	}
	if limit := sprouts * 15 / 100; maxIn > limit {
		t.Errorf("%d of %d sprouts retried within one %s window, want at most %d", maxIn, sprouts, slice, limit)
	}
	// And they cover the window rather than bunching at one end.
	if delays[0] > slice || delays[sprouts-1] < base-slice {
		t.Errorf("first retries span [%s, %s], want close to [0, %s]", delays[0], delays[sprouts-1], base)
	}
	t.Logf("busiest %s window: %d of %d sprouts (%.1f%%)", slice, maxIn, sprouts, 100*float64(maxIn)/sprouts)
}
