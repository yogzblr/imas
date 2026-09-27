package pki

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/gatewayjwt"
	"github.com/yogzblr/imas/internal/pki/tenantboxtest"
)

// fakeEnrollmentKeyStore is an in-memory stand-in for mysqlEnrollmentKeyStore
// (see enroll.go's doc comment on enrollmentKeyStore for why: this
// package's tests run against SQLite, which can't execute the production
// store's MySQL-specific cross-schema raw SQL).
type fakeEnrollmentKeyStore struct {
	rows map[string]*enrollmentKeyRow
}

func newFakeEnrollmentKeyStore() *fakeEnrollmentKeyStore {
	return &fakeEnrollmentKeyStore{rows: map[string]*enrollmentKeyRow{}}
}

func (f *fakeEnrollmentKeyStore) lookup(keyID string) (*enrollmentKeyRow, error) {
	row, ok := f.rows[keyID]
	if !ok {
		return nil, sql.ErrNoRows
	}
	cp := *row
	return &cp, nil
}

// redeem mirrors the production UPDATE ... WHERE guard (enroll.go's
// mysqlEnrollmentKeyStore.redeem): it only increments used_count when the
// same conditions that WHERE clause checks all still hold.
func (f *fakeEnrollmentKeyStore) redeem(keyID string) (bool, error) {
	row, ok := f.rows[keyID]
	if !ok {
		return false, nil
	}
	if row.Revoked || row.UsedCount >= row.MaxUses || time.Now().UTC().After(row.Expiry) {
		return false, nil
	}
	row.UsedCount++
	return true, nil
}

func withFakeEnrollmentKeyStore(t *testing.T, f *fakeEnrollmentKeyStore) {
	t.Helper()
	orig := enrollKeyStore
	enrollKeyStore = f
	t.Cleanup(func() { enrollKeyStore = orig })
}

// fakeGatewayMinter is an in-memory stand-in for
// *gatewayjwt.GatewaySigner (see gatewayJWTMinter's doc comment in
// enroll.go): tests here shouldn't need a live OpenBao Transit backend
// just to exercise Enroll's control flow. internal/gatewayjwt's own
// tests (mint_test.go) already cover the real signing/JWKS path against
// a mock Transit server and jwx's independent verifier.
type fakeGatewayMinter struct {
	calls int
}

func (f *fakeGatewayMinter) MintGatewayJWT(_ context.Context, claims gatewayjwt.GatewayClaims) (string, error) {
	f.calls++
	return "fake-gateway-jwt-for-" + claims.SproutID, nil
}

func withFakeGatewayMinter(t *testing.T) *fakeGatewayMinter {
	t.Helper()
	f := &fakeGatewayMinter{}
	orig := gatewayMinter
	gatewayMinter = f
	t.Cleanup(func() { gatewayMinter = orig })
	return f
}

func testEnrollNKey(t *testing.T) nkeys.KeyPair {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("create nkey: %v", err)
	}
	return kp
}

func testNKeyPub(t *testing.T, kp nkeys.KeyPair) string {
	t.Helper()
	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatalf("pubkey: %v", err)
	}
	return pub
}

// signedEnroll builds an EnrollRequest carrying a valid proof of
// possession: kp's signature over EnrollSigningPayload at the current
// time, exactly as a real sprout would send it. Its timestamp comes from
// nextSigningTimestamp, as the real client's does, so two calls in the
// same second build two distinct requests rather than one request the
// replay cache would reject the second time.
func signedEnroll(t *testing.T, kp nkeys.KeyPair, joinToken, hostname, sproutPub string) EnrollRequest {
	t.Helper()
	req := EnrollRequest{
		JoinToken: joinToken,
		NKeyPub:   testNKeyPub(t, kp),
		Hostname:  hostname,
		SproutPub: sproutPub,
		Timestamp: nextSigningTimestamp(),
	}
	sig, err := kp.Sign(EnrollSigningPayload(req.Timestamp, req.NKeyPub, req.Hostname, req.SproutPub, req.JoinToken))
	if err != nil {
		t.Fatalf("signing enrollment payload: %v", err)
	}
	req.NKeySig = base64.RawURLEncoding.EncodeToString(sig)
	return req
}

// testEnrollBoxPub returns a syntactically-valid, standard-base64-encoded
// 32-byte X25519 public key for Enroll's sproutPub parameter. Most tests
// in this file only exercise Enroll's control flow, not the box key's
// actual cryptographic use, so a fresh random value is all they need.
func testEnrollBoxPub(t *testing.T) string {
	t.Helper()
	var pub [32]byte
	if _, err := rand.Read(pub[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return base64.StdEncoding.EncodeToString(pub[:])
}

// setupEnrollTest wires up an in-memory PKI store, an empty fake
// enrollment-key store, a fake gateway JWT minter, a miniredis-backed
// replay cache, and a mock OpenBao KV server backing the tenant X25519
// keypair (tenantbox.go no longer has a local-disk fallback) — everything
// Enroll needs besides the test's own key-store rows. Returns both fakes
// so tests can populate rows / assert call counts.
func setupEnrollTest(t *testing.T) (*fakeEnrollmentKeyStore, *fakeGatewayMinter) {
	t.Helper()
	setupTestPKI(t)
	withTestReplayCache(t)
	setupTenantBoxOpenBao(t)
	store := newFakeEnrollmentKeyStore()
	withFakeEnrollmentKeyStore(t, store)
	minter := withFakeGatewayMinter(t)
	return store, minter
}

func TestEnroll_Success(t *testing.T) {
	store, minter := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{
		TenantID: "t_1", KeyHash: hashSecret("supersecret"),
		Expiry: time.Now().Add(time.Hour), MaxUses: 5, UsedCount: 0,
	}

	kp := testEnrollNKey(t)
	result, err := Enroll(t.Context(), signedEnroll(t, kp, "ek_1.supersecret", "web-01", testEnrollBoxPub(t)))
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if result.SproutID != "web-01" {
		t.Errorf("expected sprout id web-01, got %s", result.SproutID)
	}
	if result.JWT == "" {
		t.Error("expected non-empty JWT")
	}
	if result.GatewayJWT == "" {
		t.Error("expected non-empty gateway JWT")
	}
	if result.TenantX25519Pub == "" {
		t.Error("expected non-empty tenant X25519 pubkey")
	}
	if store.rows["ek_1"].UsedCount != 1 {
		t.Errorf("expected used_count 1, got %d", store.rows["ek_1"].UsedCount)
	}
	if minter.calls != 1 {
		t.Errorf("expected exactly 1 gateway JWT mint call, got %d", minter.calls)
	}

	gotTenant, sproutID, err := SproutIDAndTenantForNKey(testNKeyPub(t, kp))
	if err != nil || sproutID != "web-01" || gotTenant != "t_1" {
		t.Errorf("expected sprout web-01 accepted under tenant t_1, got tenant=%q sprout=%q err=%v", gotTenant, sproutID, err)
	}
}

func TestEnroll_NoGatewaySignerConfigured(t *testing.T) {
	setupTestPKI(t)
	store := newFakeEnrollmentKeyStore()
	withFakeEnrollmentKeyStore(t, store)
	store.rows["ek_1"] = &enrollmentKeyRow{KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}

	orig := gatewayMinter
	gatewayMinter = nil
	t.Cleanup(func() { gatewayMinter = orig })

	if _, err := Enroll(t.Context(), signedEnroll(t, testEnrollNKey(t), "ek_1.s", "web-01", testEnrollBoxPub(t))); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected ErrEnrollmentFailed when no gateway signer is configured, got %v", err)
	}
}

func TestEnroll_IdempotentReplayDoesNotConsumeToken(t *testing.T) {
	store, minter := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("supersecret"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}

	kp := testEnrollNKey(t)
	first, err := Enroll(t.Context(), signedEnroll(t, kp, "ek_1.supersecret", "web-01", testEnrollBoxPub(t)))
	if err != nil {
		t.Fatalf("first Enroll: %v", err)
	}

	// Retry with the same nkey_pub but a bogus token: design doc §3.3 step
	// 1 says the idempotency check happens before the token is even
	// looked at, so this should replay the existing identity.
	second, err := Enroll(t.Context(), signedEnroll(t, kp, "bogus.token", "web-01", testEnrollBoxPub(t)))
	if err != nil {
		t.Fatalf("replay Enroll: %v", err)
	}
	if second.JWT != first.JWT || second.SproutID != first.SproutID {
		t.Errorf("expected replay to return identical identity, got %+v vs %+v", first, second)
	}
	if store.rows["ek_1"].UsedCount != 1 {
		t.Errorf("expected replay not to consume a use, used_count=%d", store.rows["ek_1"].UsedCount)
	}
	// The gateway JWT is short-lived by design (see EnrollResult.GatewayJWT),
	// so a replay must still mint a fresh one rather than reusing the
	// first response's.
	if minter.calls != 2 {
		t.Errorf("expected the replay to mint its own gateway JWT (2 total calls), got %d", minter.calls)
	}
}

func TestEnroll_UnknownKeyID(t *testing.T) {
	setupEnrollTest(t)

	if _, err := Enroll(t.Context(), signedEnroll(t, testEnrollNKey(t), "nope.secret", "web-01", testEnrollBoxPub(t))); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected ErrEnrollmentFailed, got %v", err)
	}
}

func TestEnroll_WrongSecret(t *testing.T) {
	store, _ := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{KeyHash: hashSecret("real"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}

	if _, err := Enroll(t.Context(), signedEnroll(t, testEnrollNKey(t), "ek_1.wrong", "web-01", testEnrollBoxPub(t))); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected ErrEnrollmentFailed, got %v", err)
	}
	if store.rows["ek_1"].UsedCount != 0 {
		t.Error("expected wrong secret not to redeem a use")
	}
}

func TestEnroll_Revoked(t *testing.T) {
	store, _ := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1, Revoked: true}

	if _, err := Enroll(t.Context(), signedEnroll(t, testEnrollNKey(t), "ek_1.s", "web-01", testEnrollBoxPub(t))); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected ErrEnrollmentFailed, got %v", err)
	}
}

func TestEnroll_Expired(t *testing.T) {
	store, _ := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{KeyHash: hashSecret("s"), Expiry: time.Now().Add(-time.Hour), MaxUses: 1}

	if _, err := Enroll(t.Context(), signedEnroll(t, testEnrollNKey(t), "ek_1.s", "web-01", testEnrollBoxPub(t))); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected ErrEnrollmentFailed, got %v", err)
	}
}

func TestEnroll_ExhaustedByPriorRedemption(t *testing.T) {
	store, _ := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}

	if _, err := Enroll(t.Context(), signedEnroll(t, testEnrollNKey(t), "ek_1.s", "web-01", testEnrollBoxPub(t))); err != nil {
		t.Fatalf("first enroll: %v", err)
	}
	// A second, different sprout (so idempotency doesn't short-circuit)
	// presenting the same now-exhausted token must fail.
	if _, err := Enroll(t.Context(), signedEnroll(t, testEnrollNKey(t), "ek_1.s", "web-02", testEnrollBoxPub(t))); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected second redemption to fail, got %v", err)
	}
}

func TestEnroll_MalformedToken(t *testing.T) {
	setupEnrollTest(t)

	for _, tok := range []string{"", "nodot", ".nokeyid", "keyid."} {
		if _, err := Enroll(t.Context(), signedEnroll(t, testEnrollNKey(t), tok, "web-01", testEnrollBoxPub(t))); !errors.Is(err, ErrEnrollmentFailed) {
			t.Errorf("token %q: expected ErrEnrollmentFailed, got %v", tok, err)
		}
	}
}

func TestEnroll_InvalidNKey(t *testing.T) {
	setupEnrollTest(t)

	if _, err := Enroll(t.Context(), EnrollRequest{JoinToken: "ek_1.s", NKeyPub: "not-an-nkey", Hostname: "web-01", SproutPub: testEnrollBoxPub(t), Timestamp: time.Now().Unix(), NKeySig: "x"}); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected ErrEnrollmentFailed, got %v", err)
	}
}

func TestEnroll_InvalidHostname(t *testing.T) {
	store, _ := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}

	if _, err := Enroll(t.Context(), signedEnroll(t, testEnrollNKey(t), "ek_1.s", "###bad###", testEnrollBoxPub(t))); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected ErrEnrollmentFailed, got %v", err)
	}
	// A bad hostname is a client-side mistake, not a real redemption — it
	// must not burn the token's one use (sprout ID resolution runs before
	// the atomic redeem; see enroll.go's comment on that ordering).
	if store.rows["ek_1"].UsedCount != 0 {
		t.Errorf("expected invalid hostname not to consume a use, used_count=%d", store.rows["ek_1"].UsedCount)
	}
}

func TestEnroll_InvalidSproutPub(t *testing.T) {
	store, _ := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}

	for _, badPub := range []string{"", "not-base64!!!", "dG9vc2hvcnQ="} { // "tooshort" base64-decoded
		if _, err := Enroll(t.Context(), signedEnroll(t, testEnrollNKey(t), "ek_1.s", "web-01", badPub)); !errors.Is(err, ErrEnrollmentFailed) {
			t.Errorf("sprout_pub %q: expected ErrEnrollmentFailed, got %v", badPub, err)
		}
	}
	// A malformed sprout_pub is a client-side mistake, not a real
	// redemption, and is validated before the join token is even looked
	// at (same ordering rationale as nkeyPub) — so it must not consume
	// the token's one use.
	if store.rows["ek_1"].UsedCount != 0 {
		t.Errorf("expected invalid sprout_pub not to consume a use, used_count=%d", store.rows["ek_1"].UsedCount)
	}
}

// activeBoxKeyForTenant reads sproutID's active pki_sprout_box_keys row
// directly, scoped to an explicit tenant — unlike the exported
// ValidSproutBoxKeys (boxkeys.go), which still reads via the package's
// current-tenant tenantID() seam (internal/natsapi's decrypt helper is its
// only caller today; rescoping it is out of this workstream's stated
// scope). Enroll itself now persists sprout_pub under the enrollment key's
// real tenant (row.TenantID, not tenantID()) — see enroll.go's fix — so
// tests asserting on that need a tenant-scoped read too, or they'd only
// coincidentally pass when the enrollment key's tenant happens to match
// the process-global seam.
func activeBoxKeyForTenant(t *testing.T, tenantID, sproutID string) string {
	t.Helper()
	var row sproutBoxKeyRow
	if err := db.Where("tenant_id = ? AND sprout_id = ? AND state = ?", tenantID, sproutID, boxKeyStateActive).First(&row).Error; err != nil {
		t.Fatalf("reading active box key for tenant %s sprout %s: %v", tenantID, sproutID, err)
	}
	return row.Pub
}

func TestEnroll_PersistsSproutBoxKey(t *testing.T) {
	store, _ := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}

	sproutPub := testEnrollBoxPub(t)
	if _, err := Enroll(t.Context(), signedEnroll(t, testEnrollNKey(t), "ek_1.s", "web-01", sproutPub)); err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	active := activeBoxKeyForTenant(t, "t_1", "web-01")
	if active != sproutPub {
		t.Errorf("expected active box key %q, got %q", sproutPub, active)
	}
}

func TestEnroll_IdempotentReplayReassertsSproutBoxKey(t *testing.T) {
	store, _ := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}

	kp := testEnrollNKey(t)
	sproutPub := testEnrollBoxPub(t)
	if _, err := Enroll(t.Context(), signedEnroll(t, kp, "ek_1.s", "web-01", sproutPub)); err != nil {
		t.Fatalf("first Enroll: %v", err)
	}

	// Replay presents the same sprout_pub again (the sprout only generates
	// its keypair once) — must not error and must leave the stored key
	// unchanged.
	if _, err := Enroll(t.Context(), signedEnroll(t, kp, "bogus.token", "web-01", sproutPub)); err != nil {
		t.Fatalf("replay Enroll: %v", err)
	}
	active := activeBoxKeyForTenant(t, "t_1", "web-01")
	if active != sproutPub {
		t.Errorf("expected active box key unchanged at %q, got %q", sproutPub, active)
	}
}

// withEnrollNow pins Enroll's clock for the duration of the test.
func withEnrollNow(t *testing.T, now time.Time) {
	t.Helper()
	orig := enrollNow
	enrollNow = func() time.Time { return now }
	t.Cleanup(func() { enrollNow = orig })
}

// resign re-signs req with kp after a test has altered its fields, so the
// only thing wrong with it is whatever the test altered deliberately.
func resign(t *testing.T, kp nkeys.KeyPair, req EnrollRequest) EnrollRequest {
	t.Helper()
	sig, err := kp.Sign(EnrollSigningPayload(req.Timestamp, req.NKeyPub, req.Hostname, req.SproutPub, req.JoinToken))
	if err != nil {
		t.Fatalf("signing enrollment payload: %v", err)
	}
	req.NKeySig = base64.RawURLEncoding.EncodeToString(sig)
	return req
}

// TestEnroll_ReplayRequiresProofOfPossession is the regression test for
// the replay path handing a gateway JWT to anyone who knew an enrolled
// sprout's nkey_pub (which is public: Envoy forwards it upstream as
// x-imas-sprout-nkey). Each case submits the victim's real nkey_pub
// without a valid signature from its seed, and must be rejected before
// replayExistingEnrollment mints anything.
func TestEnroll_ReplayRequiresProofOfPossession(t *testing.T) {
	store, minter := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}

	victim := testEnrollNKey(t)
	sproutPub := testEnrollBoxPub(t)
	if _, err := Enroll(t.Context(), signedEnroll(t, victim, "ek_1.s", "web-01", sproutPub)); err != nil {
		t.Fatalf("victim's own enrollment: %v", err)
	}
	mintsAfterEnroll := minter.calls

	attacker := testEnrollNKey(t)
	cases := map[string]func() EnrollRequest{
		"no signature": func() EnrollRequest {
			req := signedEnroll(t, victim, "bogus.token", "web-01", sproutPub)
			req.NKeySig = ""
			return req
		},
		"garbage signature": func() EnrollRequest {
			req := signedEnroll(t, victim, "bogus.token", "web-01", sproutPub)
			req.NKeySig = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
			return req
		},
		"signature not base64url": func() EnrollRequest {
			req := signedEnroll(t, victim, "bogus.token", "web-01", sproutPub)
			req.NKeySig = "!!!"
			return req
		},
		"signed by a different nkey": func() EnrollRequest {
			req := signedEnroll(t, attacker, "bogus.token", "web-01", sproutPub)
			req.NKeyPub = testNKeyPub(t, victim)
			return req
		},
		"victim's signature over different fields": func() EnrollRequest {
			req := signedEnroll(t, victim, "bogus.token", "web-01", sproutPub)
			req.Hostname = "web-02"
			return req
		},
		"victim's signature under a different timestamp": func() EnrollRequest {
			req := signedEnroll(t, victim, "bogus.token", "web-01", sproutPub)
			req.Timestamp--
			return req
		},
		"stale timestamp": func() EnrollRequest {
			req := signedEnroll(t, victim, "bogus.token", "web-01", sproutPub)
			req.Timestamp = time.Now().Add(-EnrollSigMaxSkew - time.Minute).Unix()
			return resign(t, victim, req)
		},
		"future timestamp": func() EnrollRequest {
			req := signedEnroll(t, victim, "bogus.token", "web-01", sproutPub)
			req.Timestamp = time.Now().Add(EnrollSigMaxSkew + time.Minute).Unix()
			return resign(t, victim, req)
		},
		"zero timestamp": func() EnrollRequest {
			req := signedEnroll(t, victim, "bogus.token", "web-01", sproutPub)
			req.Timestamp = 0
			return resign(t, victim, req)
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			if res, err := Enroll(t.Context(), build()); !errors.Is(err, ErrEnrollmentFailed) {
				t.Fatalf("expected ErrEnrollmentFailed, got result=%+v err=%v", res, err)
			}
		})
	}
	if minter.calls != mintsAfterEnroll {
		t.Errorf("rejected replays minted %d gateway JWT(s)", minter.calls-mintsAfterEnroll)
	}
}

// TestEnroll_ReplayWithValidSignatureSucceeds: a sprout that holds its
// seed can still retry and get its identity back, without a valid join
// token, with a timestamp anywhere inside the allowed skew.
func TestEnroll_ReplayWithValidSignatureSucceeds(t *testing.T) {
	store, minter := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}

	kp := testEnrollNKey(t)
	sproutPub := testEnrollBoxPub(t)
	first, err := Enroll(t.Context(), signedEnroll(t, kp, "ek_1.s", "web-01", sproutPub))
	if err != nil {
		t.Fatalf("first Enroll: %v", err)
	}

	// Farmer's clock sits just inside the skew window either side of the
	// sprout's signing time.
	for _, offset := range []time.Duration{EnrollSigMaxSkew - time.Second, -(EnrollSigMaxSkew - time.Second)} {
		req := signedEnroll(t, kp, "bogus.token", "web-01", sproutPub)
		withEnrollNow(t, time.Unix(req.Timestamp, 0).Add(offset))
		replay, err := Enroll(t.Context(), req)
		if err != nil {
			t.Fatalf("replay with farmer clock offset %v: %v", offset, err)
		}
		if replay.SproutID != first.SproutID || replay.JWT != first.JWT {
			t.Errorf("replay returned a different identity: %+v vs %+v", replay, first)
		}
		if replay.GatewayJWT == "" {
			t.Error("expected replay to mint a gateway JWT")
		}
	}
	if minter.calls != 3 {
		t.Errorf("expected 3 gateway JWT mints (enroll + 2 replays), got %d", minter.calls)
	}
	if store.rows["ek_1"].UsedCount != 1 {
		t.Errorf("expected replays not to consume a use, used_count=%d", store.rows["ek_1"].UsedCount)
	}
}

// A first-time enrollment needs proof of possession too: a join-token
// holder must not be able to register a nkey_pub whose seed they don't
// hold (see Enroll's comment). Rejected before the token is redeemed.
func TestEnroll_FirstEnrollmentRequiresProofOfPossession(t *testing.T) {
	store, minter := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}

	victim, attacker := testEnrollNKey(t), testEnrollNKey(t)
	req := signedEnroll(t, attacker, "ek_1.s", "web-01", testEnrollBoxPub(t))
	req.NKeyPub = testNKeyPub(t, victim)
	if _, err := Enroll(t.Context(), req); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected ErrEnrollmentFailed, got %v", err)
	}
	if store.rows["ek_1"].UsedCount != 0 {
		t.Errorf("expected rejected enrollment not to consume a use, used_count=%d", store.rows["ek_1"].UsedCount)
	}
	if minter.calls != 0 {
		t.Errorf("expected no gateway JWT minted, got %d", minter.calls)
	}
	if _, _, err := SproutIDAndTenantForNKey(testNKeyPub(t, victim)); err == nil {
		t.Error("victim's nkey_pub was registered without proof of possession")
	}
}

// Fields are newline-joined in the signed payload, so a newline inside
// one would make the encoding ambiguous; Enroll rejects it even when the
// signature itself is valid.
func TestEnroll_RejectsNewlineInSignedField(t *testing.T) {
	store, _ := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}

	kp := testEnrollNKey(t)
	if _, err := Enroll(t.Context(), signedEnroll(t, kp, "ek_1.s\nx", "web-01", testEnrollBoxPub(t))); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected ErrEnrollmentFailed, got %v", err)
	}
	if store.rows["ek_1"].UsedCount != 0 {
		t.Errorf("expected rejected enrollment not to consume a use, used_count=%d", store.rows["ek_1"].UsedCount)
	}
}

// Each tenant gets its own tenant X25519 key. A tenant whose sprouts
// enrolled against the old one-per-deployment keypair keeps that keypair
// (adopted into its own secret) so their pins still match, and a tenant's
// first enrollment never counts itself towards that: Enroll reads the
// tenant key before recording the sprout's box key.
func TestEnroll_TenantKeysArePerTenantAndAdoptLegacyOnlyForExistingSprouts(t *testing.T) {
	store, _ := setupEnrollTest(t)
	srv := setupTenantBoxOpenBao(t)
	legacyPub, _ := srv.SeedKeypair(t, tenantboxtest.BasePath, nil)
	// A sprout of t_old enrolled before the upgrade, against the legacy key.
	if err := upsertSproutBoxKeyActive("t_old", "pre-upgrade", testEnrollBoxPub(t)); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"t_old", "t_new"} {
		store.rows["ek_"+id] = &enrollmentKeyRow{TenantID: id, KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 5}
	}
	enroll := func(tenant, host string) string {
		t.Helper()
		res, err := Enroll(t.Context(), signedEnroll(t, testEnrollNKey(t), "ek_"+tenant+".s", host, testEnrollBoxPub(t)))
		if err != nil {
			t.Fatalf("Enroll %s/%s: %v", tenant, host, err)
		}
		return res.TenantX25519Pub
	}
	if got := enroll("t_old", "web-01"); got != b64(legacyPub) {
		t.Errorf("existing tenant got %s, want the legacy key it's pinned to", got)
	}
	first := enroll("t_new", "web-01")
	if first == b64(legacyPub) {
		t.Error("a new tenant's first enrollment adopted the shared legacy key")
	}
	if second := enroll("t_new", "web-02"); second != first {
		t.Errorf("second sprout of t_new got %s, want %s", second, first)
	}
}

// After a tenant key rotation, re-issuing an identity carries a
// continuity proof sealed to the sprout's box key under the key it had
// pinned.
func TestEnroll_ReplayAfterRotationCarriesContinuity(t *testing.T) {
	store, _ := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}
	sproutPub, sproutPriv, _ := box.GenerateKey(rand.Reader)

	kp := testEnrollNKey(t)
	first, err := Enroll(t.Context(), signedEnroll(t, kp, "ek_1.s", "web-01", b64(sproutPub)))
	if err != nil {
		t.Fatal(err)
	}
	if first.TenantX25519Continuity != nil {
		t.Errorf("continuity proof before any rotation: %s", first.TenantX25519Continuity)
	}
	rot, err := RotateTenantX25519Keypair("t_1", false)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := Enroll(t.Context(), signedEnroll(t, kp, "bogus.token", "web-01", b64(sproutPub)))
	if err != nil {
		t.Fatal(err)
	}
	if replay.TenantX25519Pub != rot.Pub {
		t.Errorf("replay returned tenant key %s, want the rotated %s", replay.TenantX25519Pub, rot.Pub)
	}
	pinned, _ := DecodeBoxPubKey(first.TenantX25519Pub)
	if to, err := openContinuity(t, replay.TenantX25519Continuity, pinned, sproutPriv, "web-01"); err != nil || to != rot.Pub {
		t.Errorf("continuity proof: %q, %v; want %q", to, err, rot.Pub)
	}
}
