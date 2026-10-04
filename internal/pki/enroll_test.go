package pki

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/gatewayjwt"
	"github.com/yogzblr/imas/internal/payloadbox"
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
	// J.2: the first request proves only the NKey, which a compromised bus
	// can get signed, so it gets no gateway JWT; the second, with the box
	// key proof, does (TestEnroll_GatewayJWTOnlyWithABoxKeyProof).
	if result.GatewayJWT != "" {
		t.Error("the first enrollment request got a gateway JWT")
	}
	if result.TenantX25519Pub == "" {
		t.Error("expected non-empty tenant X25519 pubkey")
	}
	if store.rows["ek_1"].UsedCount != 1 {
		t.Errorf("expected used_count 1, got %d", store.rows["ek_1"].UsedCount)
	}
	if minter.calls != 0 {
		t.Errorf("expected no gateway JWT mint call, got %d", minter.calls)
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
	// J.2: neither request proved possession of a box key, so neither got
	// a gateway JWT (a compromised bus can get the NKey signature made).
	if first.GatewayJWT != "" || second.GatewayJWT != "" || minter.calls != 0 {
		t.Errorf("gateway JWTs issued without a box key proof: first %q, replay %q, %d mints", first.GatewayJWT, second.GatewayJWT, minter.calls)
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

// enrollProof builds a sprout_pub_proof as the sprout's client does
// (sproutEnrollProof), but sealed with sealer, which a test can make a
// key other than sproutPub's private half.
func enrollProof(t *testing.T, tenantID, sproutID, tenantPubB64, nkeyPub, sproutPubB64 string, sealer *[32]byte) json.RawMessage {
	t.Helper()
	tenantPub, err := DecodeBoxPubKey(tenantPubB64)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := payloadbox.NewMessage(payloadbox.PurposeEnrollProof, tenantID, sproutID, "",
		enrollProofBody{NKeyPub: nkeyPub, SproutPub: sproutPubB64})
	if err != nil {
		t.Fatal(err)
	}
	data, err := payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: tenantPub, Priv: sealer}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// provenEnroll is the second request of a first enrollment: the replay
// path, carrying proof.
func provenEnroll(t *testing.T, kp nkeys.KeyPair, sproutPubB64 string, proof json.RawMessage) EnrollRequest {
	t.Helper()
	req := signedEnroll(t, kp, "bogus.token", "web-01", sproutPubB64)
	req.SproutPubProof = proof
	return req
}

// hasActiveBoxKey reports whether sproutID has an active box key in
// tenantID.
func hasActiveBoxKey(t *testing.T, tenantID, sproutID string) bool {
	t.Helper()
	var n int64
	if err := db.Model(&sproutBoxKeyRow{}).Where("tenant_id = ? AND sprout_id = ? AND state = ?", tenantID, sproutID, boxKeyStateActive).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// The first enrollment issues the identity but records no box key; the
// proven second request records it (security review 2026-10, H3: proof
// of possession of sprout_pub).
func TestEnroll_RecordsSproutBoxKeyOnlyWithProof(t *testing.T) {
	store, _ := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}

	kp := testEnrollNKey(t)
	sproutPub, sproutPriv, _ := box.GenerateKey(rand.Reader)
	first, err := Enroll(t.Context(), signedEnroll(t, kp, "ek_1.s", "web-01", b64(sproutPub)))
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if first.TenantID != "t_1" {
		t.Errorf("TenantID = %q, want t_1", first.TenantID)
	}
	if hasActiveBoxKey(t, "t_1", "web-01") {
		t.Fatal("a box key was recorded without proof of possession")
	}
	if _, _, err := SealToSprout("t_1", "web-01", payloadbox.PurposeCmdRunRequest, "", "x"); !errors.Is(err, ErrNoActiveBoxKey) {
		t.Fatalf("farmer sealed to an unproven box key: %v", err)
	}
	// A replay without proof doesn't record it either.
	if _, err := Enroll(t.Context(), signedEnroll(t, kp, "bogus.token", "web-01", b64(sproutPub))); err != nil {
		t.Fatalf("replay without proof: %v", err)
	}
	if hasActiveBoxKey(t, "t_1", "web-01") {
		t.Fatal("a replay without proof recorded the box key")
	}

	proof := enrollProof(t, "t_1", "web-01", first.TenantX25519Pub, testNKeyPub(t, kp), b64(sproutPub), sproutPriv)
	if _, err := Enroll(t.Context(), provenEnroll(t, kp, b64(sproutPub), proof)); err != nil {
		t.Fatalf("proven Enroll: %v", err)
	}
	if active := activeBoxKeyForTenant(t, "t_1", "web-01"); active != b64(sproutPub) {
		t.Errorf("active box key %q, want %q", active, b64(sproutPub))
	}
	// Retried (the response was lost): the same proof for the same key
	// is a no-op.
	proof = enrollProof(t, "t_1", "web-01", first.TenantX25519Pub, testNKeyPub(t, kp), b64(sproutPub), sproutPriv)
	if _, err := Enroll(t.Context(), provenEnroll(t, kp, b64(sproutPub), proof)); err != nil {
		t.Fatalf("retried proven Enroll: %v", err)
	}
	if active := activeBoxKeyForTenant(t, "t_1", "web-01"); active != b64(sproutPub) {
		t.Errorf("active box key changed to %q", active)
	}
}

// J.2: /v1/enroll issues a gateway JWT only with a box key proof, and
// each proof earns one at most. A compromised bus can get any enrollment
// payload NKey-signed (over a CONNECT nonce), and the replay path never
// checks the join token, so the NKey proof alone must not be enough; and a
// proof copied from an earlier request, with a fresh NKey signature, must
// not earn a second token.
func TestEnroll_GatewayJWTOnlyWithABoxKeyProof(t *testing.T) {
	store, minter := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}
	kp := testEnrollNKey(t)
	nkeyPub := testNKeyPub(t, kp)
	sproutPub, sproutPriv, _ := box.GenerateKey(rand.Reader)

	first, err := Enroll(t.Context(), signedEnroll(t, kp, "ek_1.s", "web-01", b64(sproutPub)))
	if err != nil || first.GatewayJWT != "" {
		t.Fatalf("first Enroll = %+v, %v; want the identity with no gateway JWT", first, err)
	}
	// What the bus can do on its own: an NKey-signed replay, any token.
	busReplay, err := Enroll(t.Context(), signedEnroll(t, kp, "anything.at-all", "web-01", b64(sproutPub)))
	if err != nil || busReplay.GatewayJWT != "" {
		t.Fatalf("NKey-only replay = %+v, %v; want the identity with no gateway JWT", busReplay, err)
	}
	if minter.calls != 0 {
		t.Fatalf("%d gateway JWTs minted for the NKey proof alone", minter.calls)
	}

	proof := enrollProof(t, "t_1", "web-01", first.TenantX25519Pub, nkeyPub, b64(sproutPub), sproutPriv)
	proven, err := Enroll(t.Context(), provenEnroll(t, kp, b64(sproutPub), proof))
	if err != nil || proven.GatewayJWT == "" {
		t.Fatalf("proven Enroll = %+v, %v; want a gateway JWT", proven, err)
	}
	// The same proof under a fresh NKey signature: refused.
	if res, err := Enroll(t.Context(), provenEnroll(t, kp, b64(sproutPub), proof)); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("a reused proof = %+v, %v; want ErrEnrollmentFailed", res, err)
	}
	if minter.calls != 1 {
		t.Errorf("gateway JWT mints = %d, want 1", minter.calls)
	}
	// A fresh proof (what a sprout retrying a lost response sends) works.
	again := enrollProof(t, "t_1", "web-01", first.TenantX25519Pub, nkeyPub, b64(sproutPub), sproutPriv)
	if res, err := Enroll(t.Context(), provenEnroll(t, kp, b64(sproutPub), again)); err != nil || res.GatewayJWT == "" {
		t.Fatalf("a fresh proof = %+v, %v; want a gateway JWT", res, err)
	}
}

// Every proof that isn't exactly right fails the whole request and records
// nothing.
func TestEnroll_RefusesBadSproutPubProofs(t *testing.T) {
	store, _ := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 2}

	kp := testEnrollNKey(t)
	nkeyPub := testNKeyPub(t, kp)
	sproutPub, sproutPriv, _ := box.GenerateKey(rand.Reader)
	_, attackerPriv, _ := box.GenerateKey(rand.Reader)
	first, err := Enroll(t.Context(), signedEnroll(t, kp, "ek_1.s", "web-01", b64(sproutPub)))
	if err != nil {
		t.Fatal(err)
	}
	tp := first.TenantX25519Pub
	otherNKey := testNKeyPub(t, testEnrollNKey(t))
	for name, proof := range map[string]json.RawMessage{
		// The H3 case: the enroller doesn't hold sprout_pub's private key.
		"sealed by a key other than sprout_pub's": enrollProof(t, "t_1", "web-01", tp, nkeyPub, b64(sproutPub), attackerPriv),
		"for another tenant":                      enrollProof(t, "t_2", "web-01", tp, nkeyPub, b64(sproutPub), sproutPriv),
		"for another sprout":                      enrollProof(t, "t_1", "web-02", tp, nkeyPub, b64(sproutPub), sproutPriv),
		"naming another nkey":                     enrollProof(t, "t_1", "web-01", tp, otherNKey, b64(sproutPub), sproutPriv),
		"garbage":                                 json.RawMessage(`{"v":2,"s":[]}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Enroll(t.Context(), provenEnroll(t, kp, b64(sproutPub), proof)); !errors.Is(err, ErrEnrollmentFailed) {
				t.Fatalf("Enroll = %v, want ErrEnrollmentFailed", err)
			}
			if hasActiveBoxKey(t, "t_1", "web-01") {
				t.Fatal("a bad proof recorded a box key")
			}
		})
	}

	// A stale proof.
	t.Run("stale", func(t *testing.T) {
		proof := enrollProof(t, "t_1", "web-01", tp, nkeyPub, b64(sproutPub), sproutPriv)
		if _, err := verifyEnrollProof("t_1", "web-01", nkeyPub, b64(sproutPub), proof); err != nil {
			t.Fatalf("control: %v", err)
		}
		withEnrollNow(t, time.Now().Add(EnrollSigMaxSkew+time.Minute))
		if _, err := verifyEnrollProof("t_1", "web-01", nkeyPub, b64(sproutPub), proof); err == nil {
			t.Fatal("a proof issued long before farmer's clock verified")
		}
	})

	// A proof on a first enrollment (the sprout can't know the tenant key
	// yet) is refused without spending the token.
	kp2 := testEnrollNKey(t)
	req := signedEnroll(t, kp2, "ek_1.s", "web-09", b64(sproutPub))
	req.SproutPubProof = enrollProof(t, "t_1", "web-09", tp, testNKeyPub(t, kp2), b64(sproutPub), sproutPriv)
	if _, err := Enroll(t.Context(), req); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("proof on a first enrollment: %v", err)
	}

	// With a box key recorded, a proof for a different key is refused:
	// replacing a key is a rotation.
	good := enrollProof(t, "t_1", "web-01", tp, nkeyPub, b64(sproutPub), sproutPriv)
	if _, err := Enroll(t.Context(), provenEnroll(t, kp, b64(sproutPub), good)); err != nil {
		t.Fatalf("valid proof: %v", err)
	}
	newPub, newPriv, _ := box.GenerateKey(rand.Reader)
	swap := enrollProof(t, "t_1", "web-01", tp, nkeyPub, b64(newPub), newPriv)
	if _, err := Enroll(t.Context(), provenEnroll(t, kp, b64(newPub), swap)); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("proof for a second box key: %v", err)
	}
	if active := activeBoxKeyForTenant(t, "t_1", "web-01"); active != b64(sproutPub) {
		t.Errorf("active box key changed to %q", active)
	}
}

// H3 (security review 2026-10), the enrollment half: tenant B can't
// register tenant A's sprout box public key (which the bus can learn)
// under its own same-named sprout, because it can't prove possession.
func TestEnroll_AnotherTenantCannotRegisterACopiedBoxKey(t *testing.T) {
	store, _ := setupEnrollTest(t)
	store.rows["ek_a"] = &enrollmentKeyRow{TenantID: "t_a", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}
	store.rows["ek_b"] = &enrollmentKeyRow{TenantID: "t_b", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}

	victimPub, _, _ := box.GenerateKey(rand.Reader)
	_, attackerPriv, _ := box.GenerateKey(rand.Reader)
	kp := testEnrollNKey(t)
	first, err := Enroll(t.Context(), signedEnroll(t, kp, "ek_b.s", "web-01", b64(victimPub)))
	if err != nil {
		t.Fatal(err)
	}
	proof := enrollProof(t, "t_b", "web-01", first.TenantX25519Pub, testNKeyPub(t, kp), b64(victimPub), attackerPriv)
	if _, err := Enroll(t.Context(), provenEnroll(t, kp, b64(victimPub), proof)); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("Enroll with a copied box key = %v, want ErrEnrollmentFailed", err)
	}
	if hasActiveBoxKey(t, "t_b", "web-01") {
		t.Fatal("tenant B registered a box key it doesn't hold")
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
		if replay.GatewayJWT != "" {
			t.Error("a replay with the NKey proof alone got a gateway JWT")
		}
	}
	if minter.calls != 0 {
		t.Errorf("expected no gateway JWT mints without a box key proof, got %d", minter.calls)
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

// Each tenant gets its own tenant X25519 key, freshly generated, even a
// tenant that already has sprouts on record and with a keypair sitting at
// the base path where the deleted legacy one-per-deployment keypair lived
// (security review 2026-10, H3).
func TestEnroll_TenantKeysArePerTenantAndNeverShared(t *testing.T) {
	store, _ := setupEnrollTest(t)
	srv := setupTenantBoxOpenBao(t)
	legacyPub, _ := srv.SeedKeypair(t, tenantboxtest.BasePath, nil)
	if err := upsertSproutBoxKeyActive("t_old", "pre-existing", testEnrollBoxPub(t)); err != nil {
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
	old := enroll("t_old", "web-01")
	first := enroll("t_new", "web-01")
	for _, got := range []string{old, first} {
		if got == b64(legacyPub) {
			t.Error("a tenant was given the keypair at the base path")
		}
	}
	if old == first {
		t.Error("two tenants share a tenant key")
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
	proof := enrollProof(t, "t_1", "web-01", first.TenantX25519Pub, testNKeyPub(t, kp), b64(sproutPub), sproutPriv)
	if _, err := Enroll(t.Context(), provenEnroll(t, kp, b64(sproutPub), proof)); err != nil {
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
