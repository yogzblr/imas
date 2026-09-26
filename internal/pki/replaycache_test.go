package pki

import (
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func countSeenSignatures(t *testing.T) int64 {
	t.Helper()
	var n int64
	if err := db.Model(&seenSignatureRow{}).Count(&n).Error; err != nil {
		t.Fatalf("counting pki_seen_signatures: %v", err)
	}
	return n
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

// The cache is keyed on the signed payload, not the nkey_sig string:
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
// write rows: anyone can produce a valid signature with a fresh NKey.
func TestReplayCache_UnauthenticatedRequestsWriteNothing(t *testing.T) {
	store, _ := setupEnrollTest(t)
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
	if n := countSeenSignatures(t); n != 0 {
		t.Errorf("pki_seen_signatures has %d row(s), want 0", n)
	}
}

// If the claim can't be recorded, the request is rejected rather than
// let through unrecorded.
func TestReplayCache_FailsClosedWhenUnrecordable(t *testing.T) {
	kp, _, minter := enrolledForRefresh(t)
	if err := db.Migrator().DropTable(&seenSignatureRow{}); err != nil {
		t.Fatalf("dropping pki_seen_signatures: %v", err)
	}
	if _, err := RefreshSprout(t.Context(), signedRefresh(t, kp)); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("RefreshSprout without a replay cache = %v, want ErrEnrollmentFailed", err)
	}
	if minter.calls != 1 {
		t.Errorf("gateway JWT mints = %d, want 1 (enroll only)", minter.calls)
	}
}

func TestClaimSignedPayload(t *testing.T) {
	setupTestPKI(t)
	ts := time.Now().Unix()
	if err := claimSignedPayload([]byte("payload-a"), ts); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if err := claimSignedPayload([]byte("payload-a"), ts); err == nil {
		t.Fatal("second claim of the same payload succeeded")
	}
	if err := claimSignedPayload([]byte("payload-b"), ts); err != nil {
		t.Fatalf("claim of a different payload: %v", err)
	}

	var row seenSignatureRow
	if err := db.First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if want := ts + int64((EnrollSigMaxSkew+replayCacheClockMargin)/time.Second); row.ExpiresAt != want {
		t.Errorf("expires_at = %d, want %d", row.ExpiresAt, want)
	}
}

// Concurrent claims of one payload: at most one may win. (SQLite may
// also refuse some losers with a lock error rather than a duplicate key;
// either way they fail, which is what matters.)
func TestClaimSignedPayload_ConcurrentClaimsAtMostOneWins(t *testing.T) {
	setupTestPKI(t)
	ts := time.Now().Unix()
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		wins int
	)
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if claimSignedPayload([]byte("same-payload"), ts) == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins > 1 {
		t.Fatalf("%d concurrent claims of one payload succeeded, want at most 1", wins)
	}
}

func TestSweepExpiredSignatures(t *testing.T) {
	setupTestPKI(t)
	now := time.Now()
	withEnrollNow(t, now)
	orig := lastReplaySweep.Load()
	t.Cleanup(func() { lastReplaySweep.Store(orig) })

	rows := []seenSignatureRow{
		{Digest: "expired", ExpiresAt: now.Add(-time.Second).Unix()},
		{Digest: "live", ExpiresAt: now.Add(time.Minute).Unix()},
	}
	if err := db.Create(&rows).Error; err != nil {
		t.Fatal(err)
	}

	// Swept recently: nothing is deleted yet.
	lastReplaySweep.Store(now.Unix())
	sweepExpiredSignatures(now)
	if n := countSeenSignatures(t); n != 2 {
		t.Fatalf("rows after a rate-limited sweep = %d, want 2", n)
	}

	lastReplaySweep.Store(now.Add(-replaySweepInterval).Unix())
	sweepExpiredSignatures(now)
	var left []seenSignatureRow
	if err := db.Find(&left).Error; err != nil {
		t.Fatal(err)
	}
	if len(left) != 1 || left[0].Digest != "live" {
		t.Errorf("rows after sweep = %+v, want only \"live\"", left)
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

	// The clock is stepped back further than maxSigningTimestampLead: follow
	// it rather than run ahead of it past farmer's skew window.
	now = now.Add(-time.Hour)
	if got := nextSigningTimestamp(); got != now.Unix() {
		t.Errorf("after the clock stepped back: %d, want %d", got, now.Unix())
	}
}
