package pki

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
)

// recordBusyWaits makes busyWait record each wait instead of sleeping,
// and busyJitter return jitter(n) for a jitter range n.
func recordBusyWaits(t *testing.T, jitter func(n int64) int64) func() []time.Duration {
	t.Helper()
	var mu sync.Mutex
	var waits []time.Duration
	origWait, origJitter := busyWait, busyJitter
	busyWait = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		waits = append(waits, d)
		mu.Unlock()
		return ctx.Err()
	}
	busyJitter = jitter
	t.Cleanup(func() { busyWait, busyJitter = origWait, origJitter })
	return func() []time.Duration {
		mu.Lock()
		defer mu.Unlock()
		return append([]time.Duration(nil), waits...)
	}
}

func noJitter(int64) int64 { return 0 }

func TestParseRetryAfter(t *testing.T) {
	for v, want := range map[string]time.Duration{
		"":                              defaultBusyRetryAfter,
		"7":                             7 * time.Second,
		" 12 ":                          12 * time.Second,
		"60":                            60 * time.Second,
		"61":                            maxBusyRetryAfter,
		"3600":                          maxBusyRetryAfter,
		"0":                             defaultBusyRetryAfter,
		"-3":                            defaultBusyRetryAfter,
		"1.5":                           defaultBusyRetryAfter,
		"soon":                          defaultBusyRetryAfter,
		"Wed, 21 Oct 2026 07:28:00 GMT": defaultBusyRetryAfter,
	} {
		if got := parseRetryAfter(v); got != want {
			t.Errorf("parseRetryAfter(%q) = %s, want %s", v, got, want)
		}
	}
}

func TestBusyDelayJitterIsAtMostTwentyPercent(t *testing.T) {
	var gotN int64
	maxJitter := func(n int64) int64 { gotN = n; return n - 1 }
	if d := busyDelay(5*time.Second, maxJitter); d != 6*time.Second {
		t.Errorf("busyDelay(5s, max jitter) = %s, want 6s", d)
	}
	if gotN != int64(time.Second)+1 {
		t.Errorf("jitter range %d, want [0, 1s]", gotN)
	}
	if d := busyDelay(60*time.Second, noJitter); d != 60*time.Second {
		t.Errorf("busyDelay(60s, no jitter) = %s", d)
	}
	for range 200 {
		d := busyDelay(10*time.Second, cryptoJitter)
		if d < 10*time.Second || d > 12*time.Second {
			t.Fatalf("busyDelay(10s) = %s, outside [10s, 12s]", d)
		}
	}
}

func TestBusyMessage(t *testing.T) {
	got := busyMessage("/v1/enroll", 5500*time.Millisecond)
	if !strings.Contains(got, "server busy or temporarily unavailable, retrying in 5.5s") {
		t.Errorf("busy message %q", got)
	}
	if strings.Contains(got, "token") || strings.Contains(got, "clock") {
		t.Errorf("busy message %q carries the token or clock hint", got)
	}
}

// A 503 on the first request is retried after its Retry-After (5 s when
// absent or invalid, capped at 60 s), and the enrollment then completes.
func TestEnrollSprout_BusyHonoursRetryAfter(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
		want   time.Duration
	}{
		{"seconds", "7", 7 * time.Second},
		{"absent", noRetryAfter, 5 * time.Second},
		{"invalid", "later", 5 * time.Second},
		{"capped", "600", 60 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, _ := setupEnrollTest(t)
			newJWSGatewayMinter(t)
			config.GatewayJWTTTL = time.Hour
			store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}
			setupSproutFiles(t)
			srv := startEnrollServer(t)
			waits := recordBusyWaits(t, noJitter)
			sproutPub, _ := EnsureSproutBoxKey()

			srv.mu.Lock()
			srv.busy = []string{tc.header, tc.header}
			srv.mu.Unlock()
			resp, err := EnrollSprout(t.Context(), pinnedToken(t, "ek_1.s"), "web-01", sproutPub)
			if err != nil || resp.GatewayJWT == "" {
				t.Fatalf("EnrollSprout = %+v, %v; want success after the busy answers", resp, err)
			}
			if got := waits(); len(got) != 2 || got[0] != tc.want || got[1] != tc.want {
				t.Errorf("waited %v, want twice %s", got, tc.want)
			}
			if store.rows["ek_1"].UsedCount != 1 {
				t.Errorf("used_count = %d, want 1", store.rows["ek_1"].UsedCount)
			}
		})
	}
}

// Busy answers stop at the attempt limit, and the error says busy, not
// the token or clock hint.
func TestEnrollSprout_BusyGivesUpAtTheAttemptLimit(t *testing.T) {
	setupEnrollTest(t)
	newJWSGatewayMinter(t)
	setupSproutFiles(t)
	srv := startEnrollServer(t)
	waits := recordBusyWaits(t, noJitter)
	sproutPub, _ := EnsureSproutBoxKey()

	srv.mu.Lock()
	for range enrollStep2Attempts + 3 {
		srv.busy = append(srv.busy, "1")
	}
	srv.mu.Unlock()
	_, err := EnrollSprout(t.Context(), pinnedToken(t, "ek_1.s"), "web-01", sproutPub)
	if !errors.Is(err, ErrFarmerBusy) {
		t.Fatalf("err = %v, want ErrFarmerBusy", err)
	}
	if msg := err.Error(); !strings.Contains(msg, "server busy or temporarily unavailable") || strings.Contains(msg, "join token") || strings.Contains(msg, "clock") {
		t.Errorf("error %q", msg)
	}
	if got := waits(); len(got) != enrollStep2Attempts-1 {
		t.Errorf("waited %d times, want %d", len(got), enrollStep2Attempts-1)
	}
	srv.mu.Lock()
	left := len(srv.busy)
	srv.mu.Unlock()
	if sent := enrollStep2Attempts + 3 - left; sent != enrollStep2Attempts {
		t.Errorf("sent %d requests, want %d", sent, enrollStep2Attempts)
	}
}

// A busy second request waits its Retry-After instead of the step-2
// backoff, and counts towards the same attempt limit.
func TestEnrollSprout_BusySecondRequest(t *testing.T) {
	store, _ := setupEnrollTest(t)
	newJWSGatewayMinter(t)
	config.GatewayJWTTTL = time.Hour
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}
	setupSproutFiles(t)
	srv := startEnrollServer(t)
	waits := recordBusyWaits(t, noJitter)
	if _, err := EnsureSproutBoxKey(); err != nil {
		t.Fatal(err)
	}

	// The first request goes through; the next two are busy.
	origStep := enrollStep2RetryDelay
	enrollStep2RetryDelay = time.Hour // must not be used for a busy answer
	t.Cleanup(func() { enrollStep2RetryDelay = origStep })
	c := &EnrollClient{HTTP: mustNKeyClient(t), FarmerURL: config.FarmerURL}
	kp := loadTestSproutNKey(t)
	priv, err := readBoxPrivKeyFile(config.SproutBoxPrivFile, false)
	if err != nil {
		t.Fatal(err)
	}
	var calls int
	c.Timestamp = func() int64 {
		calls++
		if calls == 2 {
			srv.mu.Lock()
			srv.busy = []string{"9", "9"}
			srv.mu.Unlock()
		}
		return time.Now().Unix()
	}
	resp, err := c.Enroll(t.Context(), pinnedToken(t, "ek_1.s"), "web-01", EnrollKeys{NKey: kp, BoxPriv: priv})
	if err != nil || resp.GatewayJWT == "" {
		t.Fatalf("Enroll = %+v, %v", resp, err)
	}
	if got := waits(); len(got) != 2 || got[0] != 9*time.Second || got[1] != 9*time.Second {
		t.Errorf("waited %v, want 9s twice", got)
	}
}

// Enroll's requests carry strictly increasing timestamps even when its
// timestamp source repeats itself, so farmer's replay cache never sees
// the same signed payload twice.
func TestEnrollClient_TimestampsIncrease(t *testing.T) {
	store, _ := setupEnrollTest(t)
	newJWSGatewayMinter(t)
	config.GatewayJWTTTL = time.Hour
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}
	setupSproutFiles(t)
	srv := startEnrollServer(t)
	if _, err := EnsureSproutBoxKey(); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	c := &EnrollClient{HTTP: mustNKeyClient(t), FarmerURL: config.FarmerURL, Timestamp: func() int64 { return now }}
	priv, err := readBoxPrivKeyFile(config.SproutBoxPrivFile, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Enroll(t.Context(), pinnedToken(t, "ek_1.s"), "web-01", EnrollKeys{NKey: loadTestSproutNKey(t), BoxPriv: priv}); err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	reqs := append([]enrollWireRequest(nil), srv.requests...)
	srv.mu.Unlock()
	if len(reqs) != 2 || reqs[0].Timestamp != now || reqs[1].Timestamp != now+1 {
		t.Errorf("timestamps %d and %d, want %d and %d", reqs[0].Timestamp, reqs[1].Timestamp, now, now+1)
	}
}

func TestEnrollClient_NeedsKeys(t *testing.T) {
	c := &EnrollClient{}
	if _, err := c.Enroll(t.Context(), "ek_1.s", "web-01", EnrollKeys{}); err == nil {
		t.Error("Enroll without keys succeeded")
	}
	if _, err := c.Enroll(t.Context(), "", "web-01", EnrollKeys{}); err == nil {
		t.Error("Enroll without a join token succeeded")
	}
}

// A busy refresh is retried with a freshly sealed request after its
// Retry-After.
func TestRefreshGatewayJWT_BusyHonoursRetryAfter(t *testing.T) {
	store, _ := setupEnrollTest(t)
	newJWSGatewayMinter(t)
	config.GatewayJWTTTL = time.Hour
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}
	setupSproutFiles(t)
	srv := startEnrollServer(t)
	sproutPub, _ := EnsureSproutBoxKey()
	resp, err := EnrollSprout(t.Context(), pinnedToken(t, "ek_1.s"), "web-01", sproutPub)
	if err != nil {
		t.Fatal(err)
	}
	if err := PersistEnrollment(resp); err != nil {
		t.Fatal(err)
	}
	waits := recordBusyWaits(t, noJitter)
	srv.mu.Lock()
	srv.busy = []string{"3", noRetryAfter}
	srv.mu.Unlock()
	if _, err := RefreshGatewayJWT(t.Context()); err != nil {
		t.Fatalf("RefreshGatewayJWT after busy answers: %v", err)
	}
	if got := waits(); len(got) != 2 || got[0] != 3*time.Second || got[1] != 5*time.Second {
		t.Errorf("waited %v, want 3s then 5s", got)
	}
	if srv.refreshCount() != 1 {
		t.Errorf("farmer saw %d refreshes, want 1", srv.refreshCount())
	}

	// Busy every time: gives up at the limit with the busy error.
	srv.mu.Lock()
	srv.busy = make([]string, enrollStep2Attempts)
	for i := range srv.busy {
		srv.busy[i] = "1"
	}
	srv.mu.Unlock()
	_, err = RefreshGatewayJWT(t.Context())
	if !errors.Is(err, ErrFarmerBusy) || IsFatalRefreshError(err) {
		t.Fatalf("err = %v, want a non-fatal ErrFarmerBusy", err)
	}
}

func mustNKeyClient(t *testing.T) *http.Client {
	t.Helper()
	nkeyClientMu.RLock()
	defer nkeyClientMu.RUnlock()
	if nkeyClient == nil {
		t.Fatal("no nkey client")
	}
	return nkeyClient
}

func loadTestSproutNKey(t *testing.T) nkeys.KeyPair {
	t.Helper()
	kp, err := loadSproutNKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kp.Wipe)
	return kp
}
