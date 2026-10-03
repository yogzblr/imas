package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/gatewayjwt"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/pki/tenantboxtest"
)

// withFakeTenantBoxOpenBao points pki's tenant X25519 keypair custody
// (internal/pki/tenantbox.go) at a mock OpenBao KV v2 server
// (internal/pki/tenantboxtest) for the duration of the test, and drops the
// test tenant from pki's in-process key cache before and after, so a key
// cached from an earlier test's mock never leaks into this one.
func withFakeTenantBoxOpenBao(t *testing.T) {
	t.Helper()
	tenantboxtest.Start(t)
	pki.InvalidateTenantBoxKeys(pki.CurrentTenantID())
	t.Cleanup(func() { pki.InvalidateTenantBoxKeys(pki.CurrentTenantID()) })
}

// generateTestBoxPub returns a syntactically-valid, standard-base64-encoded
// 32-byte X25519 public key for enrollRequest.SproutPub — its actual value
// is never used cryptographically by these handler-level tests.
func generateTestBoxPub(t *testing.T) string {
	t.Helper()
	var pub [32]byte
	if _, err := rand.Read(pub[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return base64.StdEncoding.EncodeToString(pub[:])
}

// signedEnrollRequest builds an enrollRequest with a valid proof of
// possession for kp's public key, as a real sprout would send it.
func signedEnrollRequest(t *testing.T, kp nkeys.KeyPair, joinToken, hostname, sproutPub string) enrollRequest {
	t.Helper()
	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	req := enrollRequest{JoinToken: joinToken, NKeyPub: pub, Hostname: hostname, SproutPub: sproutPub, Timestamp: time.Now().Unix()}
	sig, err := kp.Sign(pki.EnrollSigningPayload(req.Timestamp, req.NKeyPub, req.Hostname, req.SproutPub, req.JoinToken))
	if err != nil {
		t.Fatalf("signing enrollment payload: %v", err)
	}
	req.NKeySig = base64.RawURLEncoding.EncodeToString(sig)
	return req
}

// acceptedTestNKey creates a user NKey and registers it as the accepted
// sprout "web-01", so a request presenting it takes the replay path.
func acceptedTestNKey(t *testing.T) nkeys.KeyPair {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("create nkey: %v", err)
	}
	pub, _ := kp.PublicKey()
	if err := pki.UnacceptNKey(pki.CurrentTenantID(), "web-01", pub); err != nil {
		t.Fatalf("UnacceptNKey: %v", err)
	}
	if err := pki.AcceptNKey(pki.CurrentTenantID(), "web-01"); err != nil {
		t.Fatalf("AcceptNKey: %v", err)
	}
	return kp
}

// fakeGatewayMinter satisfies pki's unexported gatewayJWTMinter interface
// structurally (Go allows this: the interface type name is unexported,
// but pki.SetGatewaySigner is exported and accepts anything with a
// matching method set). Lets these handler-level tests drive a full
// success response without a live OpenBao Transit backend — see
// internal/pki/enroll_test.go's own fakeGatewayMinter and
// internal/gatewayjwt/mint_test.go for the real signing path's coverage.
type fakeGatewayMinter struct{}

func (fakeGatewayMinter) MintGatewayJWT(_ context.Context, claims gatewayjwt.GatewayClaims) (string, error) {
	return "fake-gateway-jwt-for-" + claims.SproutID, nil
}

// withFakeGatewaySigner installs a fake gateway JWT minter for the
// duration of the test, per the pattern above.
func withFakeGatewaySigner(t *testing.T) {
	t.Helper()
	pki.SetGatewaySigner(fakeGatewayMinter{})
	t.Cleanup(func() { pki.SetGatewaySigner(nil) })
}

func TestEnroll_InvalidJSON(t *testing.T) {
	setupPKIDirs(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader([]byte("not json")))
	w := httptest.NewRecorder()
	Enroll(w, req)

	assertEnrollFailed(t, w)
}

func TestEnroll_MissingFields(t *testing.T) {
	setupPKIDirs(t)

	body, _ := json.Marshal(enrollRequest{JoinToken: "ek_1.secret", NKeyPub: "", Hostname: "web-01"})
	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(body))
	w := httptest.NewRecorder()
	Enroll(w, req)

	assertEnrollFailed(t, w)
}

func TestEnroll_MissingSproutPub(t *testing.T) {
	setupPKIDirs(t)

	nkey := generateTestUserNKey(t)
	body, _ := json.Marshal(enrollRequest{JoinToken: "ek_1.secret", NKeyPub: nkey, Hostname: "web-01"})
	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(body))
	w := httptest.NewRecorder()
	Enroll(w, req)

	assertEnrollFailed(t, w)
}

// A request missing its proof of possession is rejected at the handler,
// before pki.Enroll runs.
func TestEnroll_MissingProofOfPossession(t *testing.T) {
	setupPKIDirs(t)

	kp, _ := nkeys.CreateUser()
	for name, strip := range map[string]func(*enrollRequest){
		"nkey_sig":  func(r *enrollRequest) { r.NKeySig = "" },
		"timestamp": func(r *enrollRequest) { r.Timestamp = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			req := signedEnrollRequest(t, kp, "ek_1.secret", "web-01", generateTestBoxPub(t))
			strip(&req)
			body, _ := json.Marshal(req)
			w := httptest.NewRecorder()
			Enroll(w, httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(body)))
			assertEnrollFailed(t, w)
		})
	}
}

// An already-enrolled sprout's nkey_pub is public (Envoy forwards it as
// x-imas-sprout-nkey). Presenting it with a signature from any other key
// must get the generic failure, not the sprout's identity and a fresh
// gateway JWT.
func TestEnroll_ReplayWithoutValidSignatureRejected(t *testing.T) {
	setupPKIDirs(t)
	withFakeGatewaySigner(t)
	withFakeTenantBoxOpenBao(t)

	victim := acceptedTestNKey(t)
	victimPub, _ := victim.PublicKey()
	attacker, _ := nkeys.CreateUser()

	req := signedEnrollRequest(t, attacker, "irrelevant.token", "web-01", generateTestBoxPub(t))
	req.NKeyPub = victimPub
	body, _ := json.Marshal(req)
	w := httptest.NewRecorder()
	Enroll(w, httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(body)))
	assertEnrollFailed(t, w)
}

func TestEnroll_UnknownToken(t *testing.T) {
	setupPKIDirs(t)

	kp, _ := nkeys.CreateUser()
	body, _ := json.Marshal(signedEnrollRequest(t, kp, "ek_nope.secret", "web-01", generateTestBoxPub(t)))
	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(body))
	w := httptest.NewRecorder()
	Enroll(w, req)

	// No saas.enrollment_keys table exists against this test's SQLite db,
	// so this exercises pki.Enroll's generic-failure path exactly like a
	// real unknown key_id would — same response either way (design §3.4).
	assertEnrollFailed(t, w)
}

// TestEnroll_IdempotentReplaySucceeds drives a full 200 response through
// the handler without needing a real saas.enrollment_keys table: an
// already-accepted nkey_pub, correctly signed for, takes design doc §3.3
// step 1's idempotency path, which never touches the enrollment-key store
// at all.
func TestEnroll_IdempotentReplaySucceeds(t *testing.T) {
	setupPKIDirs(t)
	config.FarmerWSPort = "5407"
	withFakeGatewaySigner(t)
	withFakeTenantBoxOpenBao(t)

	kp := acceptedTestNKey(t)
	nkey, _ := kp.PublicKey()

	body, _ := json.Marshal(signedEnrollRequest(t, kp, "irrelevant.token", "web-01", generateTestBoxPub(t)))
	req := httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(body))
	w := httptest.NewRecorder()
	Enroll(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp enrollSuccessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.SproutID != "web-01" {
		t.Errorf("expected sprout_id web-01, got %q", resp.SproutID)
	}
	if resp.JWT == "" {
		t.Error("expected non-empty jwt")
	}
	if resp.GatewayJWT == "" {
		t.Error("expected non-empty gateway_jwt")
	}
	if resp.NKeyIdentity != nkey {
		t.Errorf("expected nkey_identity %q, got %q", nkey, resp.NKeyIdentity)
	}
	if resp.TenantX25519Pub == "" {
		t.Error("expected non-empty tenant_x25519_pub")
	}
	wantURL := "wss://127.0.0.1:5407"
	if len(resp.NatsURLs) != 1 || resp.NatsURLs[0] != wantURL {
		t.Errorf("expected nats_urls [%q], got %v", wantURL, resp.NatsURLs)
	}
}

func assertEnrollFailed(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
	var resp enrollErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding error response: %v", err)
	}
	if resp.Error != "enrollment_failed" {
		t.Errorf("expected generic enrollment_failed error, got %q", resp.Error)
	}
}

// Enrollment hands out no fleet signing key (a sprout trusts the keyring
// shipped in its package, design doc §2.5), so it neither reads the
// read-only Transit key nor depends on it being configured.
func TestEnroll_NoFleetSigningKeyInResponse(t *testing.T) {
	setupPKIDirs(t)
	withFakeGatewaySigner(t)
	withFakeTenantBoxOpenBao(t)
	SetFleetKeySource(nil)

	kp := acceptedTestNKey(t)
	body, _ := json.Marshal(signedEnrollRequest(t, kp, "irrelevant.token", "web-01", generateTestBoxPub(t)))
	w := httptest.NewRecorder()
	Enroll(w, httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with no fleet key source configured, got %d: %s", w.Code, w.Body.String())
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if v, ok := raw["fleet_signing_jwks"]; ok {
		t.Errorf("response still carries fleet_signing_jwks: %s", v)
	}
}
