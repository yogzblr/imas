package handlers

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/fleetsign"
	"github.com/yogzblr/imas/internal/gatewayjwt"
	"github.com/yogzblr/imas/internal/pki"
)

// withFakeTenantBoxOpenBao points pki's tenant X25519 keypair custody
// (internal/pki/tenantbox.go) at a mock OpenBao KV v2 server for the
// duration of the test, pre-seeded with a freshly-generated keypair so a
// GET always succeeds — these handler-level tests don't need to exercise
// tenantbox.go's bootstrap-race handling, only that Enroll can reach a
// tenant_x25519_pub at all. See internal/pki/tenantbox_test.go's
// mockKVv2Server for the same shape, duplicated here since that type is
// unexported in a different package.
func withFakeTenantBoxOpenBao(t *testing.T) {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating mock tenant keypair: %v", err)
	}
	const token = "test-token"
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/secret/data/imas/tenant-x25519", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != token {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"data": map[string]string{
					"pub":  base64.StdEncoding.EncodeToString(pub[:]),
					"priv": base64.StdEncoding.EncodeToString(priv[:]),
				},
			},
		})
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	t.Setenv(pki.EnvTenantBoxOpenBaoAddr, ts.URL)
	t.Setenv(pki.EnvTenantBoxOpenBaoKVMount, "secret")
	t.Setenv(pki.EnvTenantBoxOpenBaoKVPath, "imas/tenant-x25519")
	t.Setenv(pki.EnvTenantBoxOpenBaoAuthMethod, pki.TenantBoxAuthMethodToken)
	t.Setenv(pki.EnvTenantBoxOpenBaoToken, token)
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

// staticFleetKeys is a fleetsign.KeySetSource over a fixed key set.
type staticFleetKeys struct {
	ks  fleetsign.KeySet
	err error
}

func (s staticFleetKeys) KeySet(context.Context) (fleetsign.KeySet, error) { return s.ks, s.err }

// withFakeFleetKeySource installs a fixed fleet signing key set for the
// duration of the test, standing in for farmer's read-only Transit
// client (internal/fleetsign's own tests cover that client).
func withFakeFleetKeySource(t *testing.T) fleetsign.KeySet {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ks, _ := fleetsign.NewKeySet([]fleetsign.PublicKey{{Version: 1, Key: pub}})
	SetFleetKeySource(staticFleetKeys{ks: ks})
	t.Cleanup(func() { SetFleetKeySource(nil) })
	return ks
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

func TestEnroll_UnknownToken(t *testing.T) {
	setupPKIDirs(t)

	nkey := generateTestUserNKey(t)
	body, _ := json.Marshal(enrollRequest{JoinToken: "ek_nope.secret", NKeyPub: nkey, Hostname: "web-01", SproutPub: generateTestBoxPub(t)})
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
// already-accepted nkey_pub takes design doc §3.3 step 1's idempotency
// path, which never touches the enrollment-key store at all.
func TestEnroll_IdempotentReplaySucceeds(t *testing.T) {
	setupPKIDirs(t)
	config.FarmerWSPort = "5407"
	withFakeGatewaySigner(t)
	withFakeTenantBoxOpenBao(t)
	fleetKeys := withFakeFleetKeySource(t)

	nkey := generateTestUserNKey(t)
	if err := pki.UnacceptNKey(pki.CurrentTenantID(), "web-01", nkey); err != nil {
		t.Fatalf("UnacceptNKey: %v", err)
	}
	if err := pki.AcceptNKey(pki.CurrentTenantID(), "web-01"); err != nil {
		t.Fatalf("AcceptNKey: %v", err)
	}

	body, _ := json.Marshal(enrollRequest{JoinToken: "irrelevant.token", NKeyPub: nkey, Hostname: "web-01", SproutPub: generateTestBoxPub(t)})
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
	// The sprout pins exactly the key set farmer's Transit source reports.
	pinned, err := fleetsign.ParseJWKS(resp.FleetSigningJWKS)
	if err != nil {
		t.Fatalf("fleet_signing_jwks does not parse: %v (%s)", err, resp.FleetSigningJWKS)
	}
	if len(pinned) != 1 || pinned[0].Version != 1 || !pinned[0].Key.Equal(fleetKeys[0].Key) {
		t.Errorf("fleet_signing_jwks = %+v, want %+v", pinned, fleetKeys)
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

// Without the fleet signing key the sprout couldn't pin it, so enrollment
// fails closed — generically, like every other enrollment failure (§3.4)
// — rather than handing out an identity that can never verify an update.
func TestEnroll_FailsClosedWithoutFleetSigningKey(t *testing.T) {
	for name, src := range map[string]fleetsign.KeySetSource{
		"not configured":     nil,
		"Transit unreadable": staticFleetKeys{err: errors.New("permission denied")},
	} {
		t.Run(name, func(t *testing.T) {
			setupPKIDirs(t)
			withFakeGatewaySigner(t)
			withFakeTenantBoxOpenBao(t)
			SetFleetKeySource(src)
			t.Cleanup(func() { SetFleetKeySource(nil) })

			nkey := generateTestUserNKey(t)
			if err := pki.UnacceptNKey(pki.CurrentTenantID(), "web-01", nkey); err != nil {
				t.Fatalf("UnacceptNKey: %v", err)
			}
			if err := pki.AcceptNKey(pki.CurrentTenantID(), "web-01"); err != nil {
				t.Fatalf("AcceptNKey: %v", err)
			}
			body, _ := json.Marshal(enrollRequest{JoinToken: "irrelevant.token", NKeyPub: nkey, Hostname: "web-01", SproutPub: generateTestBoxPub(t)})
			w := httptest.NewRecorder()
			Enroll(w, httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(body)))
			assertEnrollFailed(t, w)
		})
	}
}

func TestFleetSigningJWKS(t *testing.T) {
	SetFleetKeySource(nil)
	w := httptest.NewRecorder()
	FleetSigningJWKS(w, httptest.NewRequest(http.MethodGet, "/v1/.well-known/fleet-signing-jwks.json", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured: status %d, want 503", w.Code)
	}

	ks := withFakeFleetKeySource(t)
	w = httptest.NewRecorder()
	FleetSigningJWKS(w, httptest.NewRequest(http.MethodGet, "/v1/.well-known/fleet-signing-jwks.json", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	got, err := fleetsign.ParseJWKS(w.Body.Bytes())
	if err != nil || len(got) != 1 || !got[0].Key.Equal(ks[0].Key) {
		t.Fatalf("served %s (%v)", w.Body, err)
	}
}
