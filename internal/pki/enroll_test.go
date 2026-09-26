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

	"github.com/yogzblr/imas/internal/gatewayjwt"
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

func testEnrollNKey(t *testing.T) string {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("create nkey: %v", err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatalf("pubkey: %v", err)
	}
	return pub
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
// enrollment-key store, a fake gateway JWT minter, and a mock OpenBao KV
// server backing the tenant X25519 keypair (tenantbox.go no longer has a
// local-disk fallback) — everything Enroll needs besides the test's own
// key-store rows. Returns both fakes so tests can populate rows / assert
// call counts.
func setupEnrollTest(t *testing.T) (*fakeEnrollmentKeyStore, *fakeGatewayMinter) {
	t.Helper()
	setupTestPKI(t)
	setupTenantBoxOpenBao(t, newMockKVv2Server(t))
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

	nkeyPub := testEnrollNKey(t)
	result, err := Enroll(t.Context(), "ek_1.supersecret", nkeyPub, "web-01", testEnrollBoxPub(t))
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

	gotTenant, sproutID, err := SproutIDAndTenantForNKey(nkeyPub)
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

	if _, err := Enroll(t.Context(), "ek_1.s", testEnrollNKey(t), "web-01", testEnrollBoxPub(t)); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected ErrEnrollmentFailed when no gateway signer is configured, got %v", err)
	}
}

func TestEnroll_IdempotentReplayDoesNotConsumeToken(t *testing.T) {
	store, minter := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("supersecret"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}

	nkeyPub := testEnrollNKey(t)
	first, err := Enroll(t.Context(), "ek_1.supersecret", nkeyPub, "web-01", testEnrollBoxPub(t))
	if err != nil {
		t.Fatalf("first Enroll: %v", err)
	}

	// Retry with the same nkey_pub but a bogus token: design doc §3.3 step
	// 1 says the idempotency check happens before the token is even
	// looked at, so this should replay the existing identity.
	second, err := Enroll(t.Context(), "bogus.token", nkeyPub, "web-01", testEnrollBoxPub(t))
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

	if _, err := Enroll(t.Context(), "nope.secret", testEnrollNKey(t), "web-01", testEnrollBoxPub(t)); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected ErrEnrollmentFailed, got %v", err)
	}
}

func TestEnroll_WrongSecret(t *testing.T) {
	store, _ := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{KeyHash: hashSecret("real"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}

	if _, err := Enroll(t.Context(), "ek_1.wrong", testEnrollNKey(t), "web-01", testEnrollBoxPub(t)); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected ErrEnrollmentFailed, got %v", err)
	}
	if store.rows["ek_1"].UsedCount != 0 {
		t.Error("expected wrong secret not to redeem a use")
	}
}

func TestEnroll_Revoked(t *testing.T) {
	store, _ := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1, Revoked: true}

	if _, err := Enroll(t.Context(), "ek_1.s", testEnrollNKey(t), "web-01", testEnrollBoxPub(t)); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected ErrEnrollmentFailed, got %v", err)
	}
}

func TestEnroll_Expired(t *testing.T) {
	store, _ := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{KeyHash: hashSecret("s"), Expiry: time.Now().Add(-time.Hour), MaxUses: 1}

	if _, err := Enroll(t.Context(), "ek_1.s", testEnrollNKey(t), "web-01", testEnrollBoxPub(t)); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected ErrEnrollmentFailed, got %v", err)
	}
}

func TestEnroll_ExhaustedByPriorRedemption(t *testing.T) {
	store, _ := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}

	if _, err := Enroll(t.Context(), "ek_1.s", testEnrollNKey(t), "web-01", testEnrollBoxPub(t)); err != nil {
		t.Fatalf("first enroll: %v", err)
	}
	// A second, different sprout (so idempotency doesn't short-circuit)
	// presenting the same now-exhausted token must fail.
	if _, err := Enroll(t.Context(), "ek_1.s", testEnrollNKey(t), "web-02", testEnrollBoxPub(t)); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected second redemption to fail, got %v", err)
	}
}

func TestEnroll_MalformedToken(t *testing.T) {
	setupEnrollTest(t)

	for _, tok := range []string{"", "nodot", ".nokeyid", "keyid."} {
		if _, err := Enroll(t.Context(), tok, testEnrollNKey(t), "web-01", testEnrollBoxPub(t)); !errors.Is(err, ErrEnrollmentFailed) {
			t.Errorf("token %q: expected ErrEnrollmentFailed, got %v", tok, err)
		}
	}
}

func TestEnroll_InvalidNKey(t *testing.T) {
	setupEnrollTest(t)

	if _, err := Enroll(t.Context(), "ek_1.s", "not-an-nkey", "web-01", testEnrollBoxPub(t)); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("expected ErrEnrollmentFailed, got %v", err)
	}
}

func TestEnroll_InvalidHostname(t *testing.T) {
	store, _ := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}

	if _, err := Enroll(t.Context(), "ek_1.s", testEnrollNKey(t), "###bad###", testEnrollBoxPub(t)); !errors.Is(err, ErrEnrollmentFailed) {
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
		if _, err := Enroll(t.Context(), "ek_1.s", testEnrollNKey(t), "web-01", badPub); !errors.Is(err, ErrEnrollmentFailed) {
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
	if _, err := Enroll(t.Context(), "ek_1.s", testEnrollNKey(t), "web-01", sproutPub); err != nil {
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

	nkeyPub := testEnrollNKey(t)
	sproutPub := testEnrollBoxPub(t)
	if _, err := Enroll(t.Context(), "ek_1.s", nkeyPub, "web-01", sproutPub); err != nil {
		t.Fatalf("first Enroll: %v", err)
	}

	// Replay presents the same sprout_pub again (the sprout only generates
	// its keypair once) — must not error and must leave the stored key
	// unchanged.
	if _, err := Enroll(t.Context(), "bogus.token", nkeyPub, "web-01", sproutPub); err != nil {
		t.Fatalf("replay Enroll: %v", err)
	}
	active := activeBoxKeyForTenant(t, "t_1", "web-01")
	if active != sproutPub {
		t.Errorf("expected active box key unchanged at %q, got %q", sproutPub, active)
	}
}
