package pki

import (
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/valkey-io/valkey-go"
)

// withTestReplayCache installs a replay cache backed by miniredis, an
// in-process Valkey stand-in, and returns it so tests can inspect keys,
// move its clock, or make it fail.
func withTestReplayCache(t *testing.T) *miniredis.Miniredis {
	t.Helper()
	mr := miniredis.RunT(t)
	client, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{mr.Addr()}, DisableCache: true})
	if err != nil {
		t.Fatalf("connecting to miniredis: %v", err)
	}
	t.Cleanup(client.Close)
	orig := replayClient
	SetReplayCacheClient(client)
	t.Cleanup(func() { SetReplayCacheClient(orig) })
	return mr
}

func replayKeys(mr *miniredis.Miniredis) []string {
	var out []string
	for _, k := range mr.Keys() {
		if strings.HasPrefix(k, replayKeyPrefix) {
			out = append(out, k)
		}
	}
	return out
}

// A captured first-time enrollment request, resubmitted verbatim while its
// timestamp is still inside the skew window, reaches the replay path (its
// nkey_pub is now accepted) and must not get a gateway JWT there.
func TestEnroll_ResubmittedFirstEnrollmentRejected(t *testing.T) {
	store, minter := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 5}

	req := signedEnroll(t, testEnrollNKey(t), "ek_1.s", "web-01", testEnrollBoxPub(t))
	if _, err := Enroll(t.Context(), req); err != nil {
		t.Fatalf("first Enroll: %v", err)
	}
	if res, err := Enroll(t.Context(), req); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("resubmitted Enroll = %+v, %v; want ErrEnrollmentFailed", res, err)
	}
	if minter.calls != 1 {
		t.Errorf("gateway JWT mints = %d, want 1", minter.calls)
	}
	if store.rows["ek_1"].UsedCount != 1 {
		t.Errorf("used_count = %d, want 1", store.rows["ek_1"].UsedCount)
	}
}

// A captured replay-path request can't be resubmitted either, while a
// fresh request signed by the same sprout still succeeds.
func TestEnroll_ResubmittedReplayRejected(t *testing.T) {
	store, minter := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}

	kp := testEnrollNKey(t)
	sproutPub := testEnrollBoxPub(t)
	if _, err := Enroll(t.Context(), signedEnroll(t, kp, "ek_1.s", "web-01", sproutPub)); err != nil {
		t.Fatalf("first Enroll: %v", err)
	}
	replay := signedEnroll(t, kp, "bogus.token", "web-01", sproutPub)
	if _, err := Enroll(t.Context(), replay); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if _, err := Enroll(t.Context(), replay); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("resubmitted replay = %v, want ErrEnrollmentFailed", err)
	}
	if _, err := Enroll(t.Context(), signedEnroll(t, kp, "bogus.token", "web-01", sproutPub)); err != nil {
		t.Fatalf("freshly signed replay: %v", err)
	}
	if minter.calls != 3 {
		t.Errorf("gateway JWT mints = %d, want 3 (enroll + 2 fresh replays)", minter.calls)
	}
}

// The cache is keyed on the decoded signature, not the nkey_sig string:
// base64url decoding ignores a final character's unused low bits, so the
// same signature re-encoded with different trailing bits must still be
// caught.
func TestEnroll_ResubmissionWithReencodedSignatureRejected(t *testing.T) {
	store, minter := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}

	kp := testEnrollNKey(t)
	sproutPub := testEnrollBoxPub(t)
	if _, err := Enroll(t.Context(), signedEnroll(t, kp, "ek_1.s", "web-01", sproutPub)); err != nil {
		t.Fatalf("first Enroll: %v", err)
	}
	replay := signedEnroll(t, kp, "bogus.token", "web-01", sproutPub)
	if _, err := Enroll(t.Context(), replay); err != nil {
		t.Fatalf("replay: %v", err)
	}

	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	sig := replay.NKeySig
	last := strings.IndexByte(alphabet, sig[len(sig)-1])
	reencoded := replay
	reencoded.NKeySig = sig[:len(sig)-1] + string(alphabet[last^1])
	a, errA := base64.RawURLEncoding.DecodeString(sig)
	b, errB := base64.RawURLEncoding.DecodeString(reencoded.NKeySig)
	if errA != nil || errB != nil || string(a) != string(b) || reencoded.NKeySig == sig {
		t.Fatalf("test setup: re-encoding didn't produce a different string for the same signature bytes")
	}

	if _, err := Enroll(t.Context(), reencoded); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("re-encoded resubmission = %v, want ErrEnrollmentFailed", err)
	}
	if minter.calls != 2 {
		t.Errorf("gateway JWT mints = %d, want 2", minter.calls)
	}
}

func TestRefreshSprout_ResubmittedRequestRejected(t *testing.T) {
	kp, _, minter := enrolledForRefresh(t)
	req := signedRefresh(t, kp)
	if _, err := RefreshSprout(t.Context(), req); err != nil {
		t.Fatalf("RefreshSprout: %v", err)
	}
	if _, err := RefreshSprout(t.Context(), req); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("resubmitted RefreshSprout = %v, want ErrEnrollmentFailed", err)
	}
	if _, err := RefreshSprout(t.Context(), signedRefresh(t, kp)); err != nil {
		t.Fatalf("freshly signed RefreshSprout: %v", err)
	}
	if minter.calls != 3 {
		t.Errorf("gateway JWT mints = %d, want 3 (enroll + 2 fresh refreshes)", minter.calls)
	}
}

// Requests that fail before their credential checks pass (a throwaway
// NKey with no valid join token, or not an accepted sprout) must not
// write keys: anyone can produce a valid signature with a fresh NKey.
func TestReplayCache_UnauthenticatedRequestsWriteNothing(t *testing.T) {
	store, _ := setupEnrollTest(t)
	mr := withTestReplayCache(t)
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}

	stranger := testEnrollNKey(t)
	for _, token := range []string{"ek_unknown.s", "ek_1.wrong", "malformed"} {
		if _, err := Enroll(t.Context(), signedEnroll(t, stranger, token, "web-01", testEnrollBoxPub(t))); !errors.Is(err, ErrEnrollmentFailed) {
			t.Fatalf("Enroll with %q = %v, want ErrEnrollmentFailed", token, err)
		}
	}
	if _, err := RefreshSprout(t.Context(), signedRefresh(t, stranger)); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("RefreshSprout for a stranger = %v, want ErrEnrollmentFailed", err)
	}
	if keys := replayKeys(mr); len(keys) != 0 {
		t.Errorf("replay cache has %d key(s), want 0: %v", len(keys), keys)
	}
}

// If the claim can't be recorded (Valkey erroring, unreachable, or never
// configured), the request is rejected rather than let through
// unrecorded, and no join-token use is spent.
func TestReplayCache_FailsClosed(t *testing.T) {
	cases := map[string]func(t *testing.T, mr *miniredis.Miniredis){
		"valkey error":       func(_ *testing.T, mr *miniredis.Miniredis) { mr.SetError("ERR injected") },
		"valkey unreachable": func(_ *testing.T, mr *miniredis.Miniredis) { mr.Close() },
		"no client":          func(t *testing.T, _ *miniredis.Miniredis) { SetReplayCacheClient(nil) },
	}
	for name, breakCache := range cases {
		t.Run(name, func(t *testing.T) {
			kp, store, minter := enrolledForRefresh(t)
			store.rows["ek_2"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}
			breakCache(t, withTestReplayCache(t))

			if _, err := RefreshSprout(t.Context(), signedRefresh(t, kp)); !errors.Is(err, ErrEnrollmentFailed) {
				t.Errorf("RefreshSprout = %v, want ErrEnrollmentFailed", err)
			}
			if _, err := Enroll(t.Context(), signedEnroll(t, kp, "bogus.token", "web-01", testEnrollBoxPub(t))); !errors.Is(err, ErrEnrollmentFailed) {
				t.Errorf("replayed Enroll = %v, want ErrEnrollmentFailed", err)
			}
			if _, err := Enroll(t.Context(), signedEnroll(t, testEnrollNKey(t), "ek_2.s", "web-02", testEnrollBoxPub(t))); !errors.Is(err, ErrEnrollmentFailed) {
				t.Errorf("first-time Enroll = %v, want ErrEnrollmentFailed", err)
			}
			if minter.calls != 1 {
				t.Errorf("gateway JWT mints = %d, want 1 (the setup enrollment only)", minter.calls)
			}
			if store.rows["ek_2"].UsedCount != 0 {
				t.Errorf("used_count = %d, want 0: a failed claim must not spend a join-token use", store.rows["ek_2"].UsedCount)
			}
		})
	}
}

func TestClaimSignedPayload(t *testing.T) {
	mr := withTestReplayCache(t)
	now := time.Now()
	withEnrollNow(t, now)
	ts := now.Unix()
	sig := make([]byte, 64)

	if err := claimSignedPayload(t.Context(), []byte("payload-a"), sig, ts); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if err := claimSignedPayload(t.Context(), []byte("payload-a"), sig, ts); !errors.Is(err, errSignatureReplayed) {
		t.Fatalf("second claim of the same request = %v, want errSignatureReplayed", err)
	}
	if err := claimSignedPayload(t.Context(), []byte("payload-b"), sig, ts); err != nil {
		t.Fatalf("claim of a different payload: %v", err)
	}
	otherSig := make([]byte, 64)
	otherSig[0] = 1
	if err := claimSignedPayload(t.Context(), []byte("payload-a"), otherSig, ts); err != nil {
		t.Fatalf("claim of the same payload under a different signature: %v", err)
	}

	// The key lives until the end of the timestamp's skew window plus the
	// clock margin, then Valkey expires it.
	key := replayKey([]byte("payload-a"), sig)
	want := EnrollSigMaxSkew + replayCacheClockMargin
	if got := mr.TTL(key); got != want {
		t.Errorf("TTL = %v, want %v", got, want)
	}
	mr.FastForward(want)
	if mr.Exists(key) {
		t.Error("claim still present after its TTL")
	}
}

// A request signed near the end of its skew window still gets a TTL that
// covers the rest of the window plus the clock margin.
func TestClaimSignedPayload_TTLFromFarmerClock(t *testing.T) {
	mr := withTestReplayCache(t)
	now := time.Now()
	withEnrollNow(t, now)
	ts := now.Add(-EnrollSigMaxSkew + 30*time.Second).Unix()
	if err := claimSignedPayload(t.Context(), []byte("p"), make([]byte, 64), ts); err != nil {
		t.Fatal(err)
	}
	if got, want := mr.TTL(replayKey([]byte("p"), make([]byte, 64))), 30*time.Second+replayCacheClockMargin; got != want {
		t.Errorf("TTL = %v, want %v", got, want)
	}
}

// Concurrent claims of one request: exactly one wins.
func TestClaimSignedPayload_ConcurrentClaimsExactlyOneWins(t *testing.T) {
	withTestReplayCache(t)
	ts := time.Now().Unix()
	var (
		wg   sync.WaitGroup
		wins atomic.Int32
	)
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if claimSignedPayload(t.Context(), []byte("same-payload"), make([]byte, 64), ts) == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := wins.Load(); n != 1 {
		t.Fatalf("%d concurrent claims of one request succeeded, want exactly 1", n)
	}
}

func TestNextSigningTimestamp(t *testing.T) {
	origClock := enrollClock
	t.Cleanup(func() { enrollClock = origClock })
	signingTimestampMu.Lock()
	origLast := lastSigningTimestamp
	signingTimestampMu.Unlock()
	t.Cleanup(func() {
		signingTimestampMu.Lock()
		lastSigningTimestamp = origLast
		signingTimestampMu.Unlock()
	})

	now := time.Unix(1_790_000_000, 0)
	enrollClock = func() time.Time { return now }
	first := nextSigningTimestamp()
	if first < now.Unix() {
		t.Fatalf("first timestamp %d is behind the clock %d", first, now.Unix())
	}
	second := nextSigningTimestamp()
	if second != first+1 {
		t.Errorf("same-second timestamps: %d then %d, want strictly increasing by 1", first, second)
	}

	// The clock moves on: back to tracking it.
	now = now.Add(time.Hour)
	if got := nextSigningTimestamp(); got != now.Unix() {
		t.Errorf("after the clock advanced: %d, want %d", got, now.Unix())
	}

	// The clock is stepped back by at least maxSigningTimestampLead: follow
	// it rather than run ahead of it past farmer's skew window.
	now = now.Add(-time.Hour)
	if got := nextSigningTimestamp(); got != now.Unix() {
		t.Errorf("after the clock stepped back: %d, want %d", got, now.Unix())
	}
}
