package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwxjwt "github.com/lestrrat-go/jwx/v2/jwt"
	natsjwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/fleetsign"
	"github.com/yogzblr/imas/internal/pki"
)

const testToken = "ek91cd2a.c2VjcmV0"

type testSprout struct {
	kp        nkeys.KeyPair
	pub       string
	sproutPub string
}

func newTestSprout(t *testing.T) *testSprout {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := kp.PublicKey()
	var box [32]byte
	if _, err := rand.Read(box[:]); err != nil {
		t.Fatal(err)
	}
	return &testSprout{kp: kp, pub: pub, sproutPub: base64.StdEncoding.EncodeToString(box[:])}
}

// enroll POSTs a signed /v1/enroll request the way pki.EnrollSprout does.
func (s *testSprout) enroll(t *testing.T, h http.Handler, token, hostname string, ts int64) *httptest.ResponseRecorder {
	t.Helper()
	sig, err := s.kp.Sign(pki.EnrollSigningPayload(ts, s.pub, hostname, s.sproutPub, token))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(enrollRequest{
		JoinToken: token, NKeyPub: s.pub, Hostname: hostname, SproutPub: s.sproutPub,
		Timestamp: ts, NKeySig: base64.RawURLEncoding.EncodeToString(sig),
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(body)))
	return rec
}

func newTestFarmer(t *testing.T, maxUses int) (*farmer, http.Handler) {
	t.Helper()
	f, err := newFarmer(testToken, maxUses, []string{"tls://imas-farmer:5406"})
	if err != nil {
		t.Fatal(err)
	}
	return f, f.routes()
}

func state(t *testing.T, h http.Handler) State {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/_stub/state", nil))
	var st State
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	return st
}

// TestEnrollResponseIsWhatTheSproutAccepts checks the response against the
// same things the sprout's client validates (validateIdentity and
// validateEnrollResponse in internal/pki/enrollclient.go).
func TestEnrollResponseIsWhatTheSproutAccepts(t *testing.T) {
	_, h := newTestFarmer(t, 1)
	s := newTestSprout(t)
	rec := s.enroll(t, h, testToken, "Web_01", time.Now().Unix())
	if rec.Code != http.StatusOK {
		t.Fatalf("enroll: %d %s", rec.Code, rec.Body)
	}
	var resp pki.EnrollResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.SproutID != "web-01" || !pki.IsValidSproutID(resp.SproutID) {
		t.Errorf("sprout_id = %q, want web-01", resp.SproutID)
	}
	if resp.NKeyIdentity != s.pub {
		t.Errorf("nkey_identity = %q, want %q", resp.NKeyIdentity, s.pub)
	}
	uc, err := natsjwt.DecodeUserClaims(resp.JWT)
	if err != nil || uc.Subject != s.pub {
		t.Errorf("jwt: subject %v, err %v", uc, err)
	}
	gw, err := jwxjwt.ParseInsecure([]byte(resp.GatewayJWT))
	if err != nil || gw.Subject() != s.pub || !gw.Expiration().After(time.Now()) {
		t.Fatalf("gateway_jwt: %v, err %v", gw, err)
	}
	// What the sprout's file client reads from it (pki/fileclient.go).
	for claim, want := range map[string]string{"tenant_id": stubTenantID, "sprout_id": "web-01"} {
		if got, ok := gw.PrivateClaims()[claim]; !ok || got != want {
			t.Errorf("gateway_jwt %s = %v, want %q", claim, got, want)
		}
	}
	if _, err := pki.DecodeBoxPubKey(resp.TenantX25519Pub); err != nil {
		t.Errorf("tenant_x25519_pub: %v", err)
	}
	if _, err := fleetsign.ParseJWKS(resp.FleetSigningJWKS); err != nil {
		t.Errorf("fleet_signing_jwks: %v", err)
	}
	if _, err := pki.ValidateBusURLs(resp.NatsURLs); err != nil {
		t.Errorf("nats_urls: %v", err)
	}
}

func TestReplayDoesNotSpendAUse(t *testing.T) {
	_, h := newTestFarmer(t, 1)
	s := newTestSprout(t)
	now := time.Now().Unix()
	if rec := s.enroll(t, h, testToken, "web-01", now); rec.Code != http.StatusOK {
		t.Fatalf("first enroll: %d", rec.Code)
	}
	// The key is now exhausted, but the same NKey is replayed.
	if rec := s.enroll(t, h, testToken, "web-01", now+1); rec.Code != http.StatusOK {
		t.Fatalf("replayed enroll: %d", rec.Code)
	}
	if st := state(t, h); st.Redemptions != 1 || st.EnrollRequests != 2 {
		t.Errorf("state = %+v, want 1 redemption of 2 requests", st)
	}
	if rec := newTestSprout(t).enroll(t, h, testToken, "web-02", now); rec.Code != http.StatusForbidden {
		t.Errorf("second sprout on an exhausted key: %d, want 403", rec.Code)
	}
}

func TestEnrollFailures(t *testing.T) {
	now := time.Now().Unix()
	for name, tc := range map[string]struct {
		token string
		ts    int64
	}{
		"wrong token":   {"ek91cd2a.wrong", now},
		"stale request": {testToken, now - int64((maxSkew + time.Minute).Seconds())},
	} {
		t.Run(name, func(t *testing.T) {
			_, h := newTestFarmer(t, 5)
			rec := newTestSprout(t).enroll(t, h, tc.token, "web-01", tc.ts)
			if rec.Code != http.StatusForbidden || rec.Body.String() != `{"error":"enrollment_failed"}` {
				t.Errorf("got %d %s, want the generic 403", rec.Code, rec.Body)
			}
		})
	}
	t.Run("resubmitted request", func(t *testing.T) {
		_, h := newTestFarmer(t, 5)
		s := newTestSprout(t)
		if rec := s.enroll(t, h, testToken, "web-01", now); rec.Code != http.StatusOK {
			t.Fatalf("first: %d", rec.Code)
		}
		if rec := s.enroll(t, h, testToken, "web-01", now); rec.Code != http.StatusForbidden {
			t.Errorf("identical resubmission: %d, want 403", rec.Code)
		}
	})
}
