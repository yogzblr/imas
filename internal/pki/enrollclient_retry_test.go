package pki

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/config"
)

// cancelAfterWaits makes busyWait record each wait without sleeping and
// call cancel once it has recorded n, and returns the recorded waits.
func cancelAfterWaits(t *testing.T, cancel context.CancelFunc, n int) func() []time.Duration {
	t.Helper()
	var mu sync.Mutex
	var waits []time.Duration
	orig := busyWait
	busyWait = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		waits = append(waits, d)
		if len(waits) >= n {
			cancel()
		}
		mu.Unlock()
		return ctx.Err()
	}
	t.Cleanup(func() { busyWait = orig })
	return func() []time.Duration {
		mu.Lock()
		defer mu.Unlock()
		return append([]time.Duration(nil), waits...)
	}
}

// withEnrollSprout swaps EnsureEnrolled's EnrollSprout for one that
// returns the errors of answers in turn (the last one from then on).
func withEnrollSprout(t *testing.T, answers ...error) {
	t.Helper()
	orig := enrollSprout
	i := 0
	enrollSprout = func(context.Context, string, string, string) (*EnrollResponse, error) {
		err := answers[min(i, len(answers)-1)]
		i++
		return nil, err
	}
	t.Cleanup(func() { enrollSprout = orig })
}

// logLines returns the captured log's lines that contain substr.
func logLines(buf *syncBuffer, substr string) []string {
	var out []string
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.Contains(l, substr) {
			out = append(out, l)
		}
	}
	return out
}

// postJSON tells a refusal (401) from a busy or unavailable farmer (503)
// and from anything else.
func TestPostJSONClassifiesStatus(t *testing.T) {
	for _, tc := range []struct {
		status            int
		rejected, busy    bool
		retryAfter        string
		wantRetryAfterDur time.Duration
	}{
		{status: http.StatusUnauthorized, rejected: true},
		{status: http.StatusServiceUnavailable, busy: true, retryAfter: "3", wantRetryAfterDur: 3 * time.Second},
		{status: http.StatusBadGateway},
		{status: http.StatusTooManyRequests},
		{status: http.StatusRequestEntityTooLarge},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.retryAfter != "" {
					w.Header().Set("Retry-After", tc.retryAfter)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"error":"enrollment_failed"}`))
			}))
			t.Cleanup(srv.Close)
			err := postJSON(t.Context(), srv.Client(), srv.URL, "/v1/enroll", struct{}{}, &struct{}{})
			if err == nil {
				t.Fatal("no error")
			}
			if got := errors.Is(err, ErrFarmerRejected); got != tc.rejected {
				t.Errorf("errors.Is(%v, ErrFarmerRejected) = %v, want %v", err, got, tc.rejected)
			}
			if got := errors.Is(err, ErrFarmerBusy); got != tc.busy {
				t.Errorf("errors.Is(%v, ErrFarmerBusy) = %v, want %v", err, got, tc.busy)
			}
			var busy *farmerBusyError
			if tc.busy && (!errors.As(err, &busy) || busy.retryAfter != tc.wantRetryAfterDur) {
				t.Errorf("busy error %v, want Retry-After %s", err, tc.wantRetryAfterDur)
			}
			if tc.rejected && !strings.Contains(err.Error(), "/v1/enroll rejected: HTTP 401") {
				t.Errorf("rejection message %q", err)
			}
		})
	}
}

// A refusal is logged once at error level, naming the token's key_id
// (never its secret) and what to do, and then tried again only at the
// cap, each later refusal a one-line warning: not the endless
// exponential back-off of error lines the rig's sprouts logged.
func TestEnsureEnrolled_RefusalLoggedOnceAndRetriedAtTheCap(t *testing.T) {
	setupSproutFiles(t)
	buf := captureLog(t)
	withEnrollSprout(t, &farmerRejectedError{path: "/v1/enroll", status: http.StatusUnauthorized})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	waits := cancelAfterWaits(t, cancel, 4)

	_, err := EnsureEnrolled(ctx, "ek_bkcc35vfuazndw63.thesecret", "alma-01", "unused", 5*time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("EnsureEnrolled = %v, want the context's error", err)
	}
	got := waits()
	if len(got) != 4 {
		t.Fatalf("waits = %v, want 4", got)
	}
	for _, d := range got {
		if d != maxEnrollRetryDelay {
			t.Errorf("waited %s after a refusal, want the cap %s", d, maxEnrollRetryDelay)
		}
	}
	if strings.Contains(buf.String(), "thesecret") {
		t.Error("the log carries the join token's secret")
	}
	refused := logLines(buf, "refused this sprout's enrollment with join token key_id ek_bkcc35vfuazndw63")
	if len(refused) != 1 || !strings.Contains(refused[0], `"level":"error"`) || !strings.Contains(refused[0], "set a valid join token") {
		t.Errorf("error-level refusal lines = %q, want exactly one", refused)
	}
	still := logLines(buf, "still refused by farmer")
	if len(still) != 3 || !strings.Contains(still[0], `"level":"warn"`) || !strings.Contains(still[2], "(4 refusals in a row)") {
		t.Errorf("repeat refusal lines = %q, want three warnings", still)
	}
}

// A busy or temporarily unavailable farmer is retried with the ordinary
// back-off and logged as a warning, never as a refusal.
func TestEnsureEnrolled_BusyIsRetriedNotRefused(t *testing.T) {
	setupSproutFiles(t)
	buf := captureLog(t)
	withEnrollSprout(t, &farmerBusyError{path: "/v1/enroll", retryAfter: 3 * time.Second})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	waits := cancelAfterWaits(t, cancel, 3)

	if _, err := EnsureEnrolled(ctx, "ek_1.s", "alma-01", "unused", time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("EnsureEnrolled = %v, want the context's error", err)
	}
	if got, want := waits(), []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}; len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Errorf("waits = %v, want %v", got, want)
	}
	if l := logLines(buf, `"level":"error"`); len(l) != 0 {
		t.Errorf("error-level lines for a busy farmer: %q", l)
	}
	if l := logLines(buf, "farmer is busy or temporarily unavailable"); len(l) != 3 {
		t.Errorf("busy lines = %q, want 3", l)
	}
}

// The rig's failure end to end, in process: farmer's enrolment
// transaction deadlocks on every retry of one request, so the sprout gets
// a 503, waits its Retry-After and tries again, and enrols with the same
// single-use join token, which is spent exactly once.
func TestEnrollSprout_DeadlockIsRetriedWithTheSameSingleUseToken(t *testing.T) {
	h := sqliteEnrollTxHarness(t)
	fastDeadlockRetries(t)
	newJWSGatewayMinter(t)
	config.GatewayJWTTTL = time.Hour
	token := h.addKey(t, "ek_bkcc35vfuazndw63", "t_hydbugp7pz2jjd7t", 1)
	setupSproutFiles(t)
	startEnrollServer(t)
	sproutPub, err := EnsureSproutBoxKey()
	if err != nil {
		t.Fatal(err)
	}
	waits := recordBusyWaits(t, noJitter)
	calls := withEnrollTxFault(t, func(call int) error {
		if call <= txRetries {
			return errDeadlock
		}
		return nil
	})

	resp, err := EnrollSprout(t.Context(), pinnedTokenFor(t, token, "t_hydbugp7pz2jjd7t"), "alma-01", sproutPub)
	if err != nil {
		t.Fatalf("EnrollSprout: %v", err)
	}
	if resp.SproutID != "alma-01" || resp.TenantID != "t_hydbugp7pz2jjd7t" {
		t.Errorf("enrolled as %s in %s", resp.SproutID, resp.TenantID)
	}
	if got := waits(); len(got) != 1 || got[0] != 3*time.Second {
		t.Errorf("busy waits = %v, want one of 3s (the 503's Retry-After)", got)
	}
	if calls() != txRetries+1 {
		t.Errorf("enrolment transaction ran %d times, want %d", calls(), txRetries+1)
	}
	if n := h.uses(t, "ek_bkcc35vfuazndw63"); n != 1 {
		t.Errorf("used_count = %d, want 1", n)
	}
}
