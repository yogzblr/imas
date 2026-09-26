package pki

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
)

// signedRefresh builds a RefreshRequest with a valid proof of possession
// for kp at the current time.
func signedRefresh(t *testing.T, kp nkeys.KeyPair) RefreshRequest {
	t.Helper()
	req := RefreshRequest{NKeyPub: testNKeyPub(t, kp), Timestamp: time.Now().Unix()}
	sig, err := kp.Sign(RefreshSigningPayload(req.Timestamp, req.NKeyPub))
	if err != nil {
		t.Fatal(err)
	}
	req.NKeySig = base64.RawURLEncoding.EncodeToString(sig)
	return req
}

// enrolledForRefresh enrolls kp as web-01 in tenant t_1 and returns the
// key store so callers can check no join-token use was spent.
func enrolledForRefresh(t *testing.T) (nkeys.KeyPair, *fakeEnrollmentKeyStore, *fakeGatewayMinter) {
	t.Helper()
	store, minter := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 5}
	kp := testEnrollNKey(t)
	if _, err := Enroll(t.Context(), signedEnroll(t, kp, "ek_1.s", "web-01", testEnrollBoxPub(t))); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	return kp, store, minter
}

func TestRefreshSprout_Success(t *testing.T) {
	kp, store, minter := enrolledForRefresh(t)
	res, err := RefreshSprout(t.Context(), signedRefresh(t, kp))
	if err != nil {
		t.Fatalf("RefreshSprout: %v", err)
	}
	if res.SproutID != "web-01" || res.JWT == "" || res.GatewayJWT == "" || res.TenantX25519Pub == "" {
		t.Errorf("unexpected result %+v", res)
	}
	if minter.calls != 2 {
		t.Errorf("gateway JWT mints = %d, want 2 (enroll + refresh)", minter.calls)
	}
	if store.rows["ek_1"].UsedCount != 1 {
		t.Errorf("used_count = %d, want 1: refresh never touches the join token", store.rows["ek_1"].UsedCount)
	}
}

func TestRefreshSprout_Rejections(t *testing.T) {
	kp, _, minter := enrolledForRefresh(t)
	stranger := testEnrollNKey(t)

	stale := signedRefresh(t, kp)
	stale.Timestamp = time.Now().Add(-EnrollSigMaxSkew - time.Minute).Unix()
	stale = resignRefresh(t, kp, stale)

	wrongSigner := signedRefresh(t, kp)
	wrongSigner.NKeySig = signedRefresh(t, stranger).NKeySig

	// An enrollment signature over the same timestamp and key must not be
	// accepted as a refresh signature: the two payloads are
	// domain-separated.
	crossDomain := signedRefresh(t, kp)
	enrollSig, _ := kp.Sign(EnrollSigningPayload(crossDomain.Timestamp, crossDomain.NKeyPub, "", "", ""))
	crossDomain.NKeySig = base64.RawURLEncoding.EncodeToString(enrollSig)

	cases := map[string]RefreshRequest{
		"unknown nkey_pub":       signedRefresh(t, stranger),
		"stale timestamp":        stale,
		"signature by other key": wrongSigner,
		"enroll-domain sig":      crossDomain,
		"malformed nkey_pub":     {NKeyPub: "not-a-key", Timestamp: time.Now().Unix(), NKeySig: "x"},
		"sig not base64url":      {NKeyPub: testNKeyPub(t, kp), Timestamp: time.Now().Unix(), NKeySig: "***"},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := RefreshSprout(t.Context(), req); !errors.Is(err, ErrEnrollmentFailed) {
				t.Errorf("RefreshSprout = %v, want ErrEnrollmentFailed", err)
			}
		})
	}
	if minter.calls != 1 {
		t.Errorf("gateway JWT mints = %d, want 1: no rejected refresh may mint", minter.calls)
	}
}

// A refresh signature must not be accepted by the enrollment endpoint's
// replay path either.
func TestEnroll_RejectsRefreshSignature(t *testing.T) {
	kp, _, _ := enrolledForRefresh(t)
	req := signedEnroll(t, kp, "ek_1.s", "web-01", testEnrollBoxPub(t))
	refreshSig, _ := kp.Sign(RefreshSigningPayload(req.Timestamp, req.NKeyPub))
	req.NKeySig = base64.RawURLEncoding.EncodeToString(refreshSig)
	if _, err := Enroll(t.Context(), req); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("Enroll accepted a refresh-domain signature: %v", err)
	}
}

func TestRefreshSprout_DeniedSproutRejected(t *testing.T) {
	kp, _, _ := enrolledForRefresh(t)
	if err := DenyNKey("t_1", "web-01"); err != nil {
		t.Fatalf("DenyNKey: %v", err)
	}
	if _, err := RefreshSprout(t.Context(), signedRefresh(t, kp)); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("RefreshSprout for a denied sprout = %v, want ErrEnrollmentFailed", err)
	}
}

func resignRefresh(t *testing.T, kp nkeys.KeyPair, req RefreshRequest) RefreshRequest {
	t.Helper()
	sig, err := kp.Sign(RefreshSigningPayload(req.Timestamp, req.NKeyPub))
	if err != nil {
		t.Fatal(err)
	}
	req.NKeySig = base64.RawURLEncoding.EncodeToString(sig)
	return req
}
