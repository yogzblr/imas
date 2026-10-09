package pki

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// A box key write that fails after the proof and binding were claimed gives
// the binding back, so the sprout's retry (a fresh proof, the same binding)
// records its key. Without that the retry is refused with "already claimed"
// and the sprout has to be enrolled again with a new token.
func TestEnroll_FailedBoxKeyWriteReleasesTheBinding(t *testing.T) {
	store, _ := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}
	kp := testEnrollNKey(t)
	nkeyPub := testNKeyPub(t, kp)
	sproutPub, sproutPriv, _ := box.GenerateKey(rand.Reader)
	first, err := Enroll(t.Context(), signedEnroll(t, kp, "ek_1.s", "web-01", b64(sproutPub)))
	if err != nil {
		t.Fatal(err)
	}

	orig := upsertBoxKeyActive
	calls := 0
	upsertBoxKeyActive = func(tenantID, sproutID, pub string) error {
		calls++
		if calls == 1 {
			return driverError(1213, "Deadlock found when trying to get lock; try restarting transaction")
		}
		return orig(tenantID, sproutID, pub)
	}
	t.Cleanup(func() { upsertBoxKeyActive = orig })

	step2 := func() (*EnrollResult, error) {
		proof := enrollProof(t, first.TenantID, first.SproutID, first.TenantX25519Pub, nkeyPub, b64(sproutPub), sproutPriv)
		return Enroll(t.Context(), provenEnroll(t, kp, b64(sproutPub), proof, first.EnrollBinding))
	}

	if res, err := step2(); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("step 2 with a failing write = %+v, %v; want ErrEnrollmentFailed", res, err)
	}
	if hasActiveBoxKey(t, "t_1", "web-01") {
		t.Fatal("a failed write left a box key")
	}
	res, err := step2()
	if err != nil || res.GatewayJWT == "" {
		t.Fatalf("retry with the same binding = %+v, %v; want a gateway JWT", res, err)
	}
	if !hasActiveBoxKey(t, "t_1", "web-01") {
		t.Fatal("the retry recorded no box key")
	}
	if calls != 2 {
		t.Errorf("%d box key writes, want 2", calls)
	}
}
