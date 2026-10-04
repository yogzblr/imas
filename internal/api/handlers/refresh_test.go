package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/pki"
)

func signedRefreshBody(t *testing.T, kp nkeys.KeyPair, extra map[string]any) []byte {
	t.Helper()
	pub, _ := kp.PublicKey()
	ts := time.Now().Unix()
	sig, err := kp.Sign(pki.RefreshSigningPayload(ts, pub))
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"nkey_pub": pub, "timestamp": ts, "nkey_sig": base64.RawURLEncoding.EncodeToString(sig)}
	for k, v := range extra {
		body[k] = v
	}
	b, _ := json.Marshal(body)
	return b
}

func TestRefresh_Success(t *testing.T) {
	setupPKIDirs(t)
	withFakeGatewaySigner(t)
	withFakeTenantBoxOpenBao(t)
	kp := acceptedTestNKey(t)
	nkey, _ := kp.PublicKey()

	w := httptest.NewRecorder()
	Refresh(w, httptest.NewRequest(http.MethodPost, "/v1/refresh", bytes.NewReader(signedRefreshBody(t, kp, nil))))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp refreshSuccessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.SproutID != "web-01" || resp.JWT == "" || resp.GatewayJWT == "" || resp.NKeyIdentity != nkey || resp.TenantX25519Pub == "" {
		t.Errorf("unexpected response %+v", resp)
	}
	// The sprout checks this against the tenant it pinned at enrollment
	// (security review 2026-10, H3).
	if want := pki.CurrentTenantID(); resp.TenantID != want {
		t.Errorf("tenant_id = %q, want the sprout's tenant %q", resp.TenantID, want)
	}
}

// The refresh contract has no join_token; a body carrying one (or any
// other unknown field) is a client on the wrong contract and is refused.
func TestRefresh_RejectsJoinTokenField(t *testing.T) {
	setupPKIDirs(t)
	withFakeGatewaySigner(t)
	withFakeTenantBoxOpenBao(t)
	kp := acceptedTestNKey(t)

	w := httptest.NewRecorder()
	body := signedRefreshBody(t, kp, map[string]any{"join_token": "ek_1.secret"})
	Refresh(w, httptest.NewRequest(http.MethodPost, "/v1/refresh", bytes.NewReader(body)))
	assertEnrollFailed(t, w)
}

func TestRefresh_MissingFields(t *testing.T) {
	setupPKIDirs(t)
	for name, body := range map[string]string{
		"empty":        `{}`,
		"no signature": `{"nkey_pub":"UABC","timestamp":1}`,
		"no timestamp": `{"nkey_pub":"UABC","nkey_sig":"x"}`,
		"not json":     `nope`,
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			Refresh(w, httptest.NewRequest(http.MethodPost, "/v1/refresh", bytes.NewReader([]byte(body))))
			assertEnrollFailed(t, w)
		})
	}
}

func TestRefresh_UnenrolledNKeyRejected(t *testing.T) {
	setupPKIDirs(t)
	withFakeGatewaySigner(t)
	withFakeTenantBoxOpenBao(t)
	kp, _ := nkeys.CreateUser()

	w := httptest.NewRecorder()
	Refresh(w, httptest.NewRequest(http.MethodPost, "/v1/refresh", bytes.NewReader(signedRefreshBody(t, kp, nil))))
	assertEnrollFailed(t, w)
}
