package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/pki"
)

// sealedRefreshBody is a POST /v1/refresh body for the sprout
// enrollAgainstHandlers enrolled, sealed now, with extra fields merged in.
func sealedRefreshBody(t *testing.T, s *handlerSprout, extra map[string]any) []byte {
	t.Helper()
	sproutID, err := pki.PinnedSproutID()
	if err != nil {
		t.Fatal(err)
	}
	sealed, _, err := pki.SproutSealedRefresh(sproutID, s.nkeyPub)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"nkey_pub": s.nkeyPub, "sealed": json.RawMessage(sealed)}
	for k, v := range extra {
		body[k] = v
	}
	b, _ := json.Marshal(body)
	return b
}

// nkeySignedRefreshBody is the pre-J.2 refresh body: the NKey seed's
// signature over pki.RefreshSigningPayload, which a compromised bus can
// get made over a CONNECT nonce.
func nkeySignedRefreshBody(t *testing.T, kp nkeys.KeyPair) []byte {
	t.Helper()
	pub, _ := kp.PublicKey()
	ts := time.Now().Unix()
	sig, err := kp.Sign(pki.RefreshSigningPayload(ts, pub))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"nkey_pub": pub, "timestamp": ts, "nkey_sig": base64.RawURLEncoding.EncodeToString(sig)})
	return b
}

func postRefresh(body []byte) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	Refresh(w, httptest.NewRequest(http.MethodPost, "/v1/refresh", bytes.NewReader(body)))
	return w
}

// The answer is the sealed reply and nothing else: no gateway JWT, User
// JWT or identity in the clear for anything between farmer and the
// sprout (Envoy terminates TLS in the DMZ).
func TestRefresh_AnswersOnlySealed(t *testing.T) {
	s := enrollAgainstHandlers(t)
	w := postRefresh(sealedRefreshBody(t, s, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp) != 1 || len(resp["sealed"]) == 0 {
		t.Errorf("response fields = %v, want exactly sealed", keysOf(resp))
	}
	for _, plain := range []string{"gateway_jwt", "eyJ", "web-01", s.nkeyPub, pki.CurrentTenantID()} {
		if strings.Contains(w.Body.String(), plain) {
			t.Errorf("the response carries %q in the clear", plain)
		}
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Owner decision, 2026-10-04: no NKey-only refresh for any sprout, box
// key or not, and no fallback.
func TestRefresh_RefusesTheNKeyProof(t *testing.T) {
	s := enrollAgainstHandlers(t)
	assertEnrollFailed(t, postRefresh(nkeySignedRefreshBody(t, s.kp)))

	// Nor alongside a sealed request: a client on the old contract.
	var old map[string]any
	_ = json.Unmarshal(nkeySignedRefreshBody(t, s.kp), &old)
	assertEnrollFailed(t, postRefresh(sealedRefreshBody(t, s, map[string]any{"timestamp": old["timestamp"], "nkey_sig": old["nkey_sig"]})))
}

// A sprout farmer has no box key for (enrolled before workstream J, or
// never proved one) gets no fallback: it is refused, and re-enrolls.
func TestRefresh_SproutWithNoBoxKeyRefused(t *testing.T) {
	setupPKIDirs(t)
	withFakeGatewaySigner(t)
	withFakeTenantBoxOpenBao(t)
	assertEnrollFailed(t, postRefresh(nkeySignedRefreshBody(t, acceptedTestNKey(t))))
}

// The refresh contract has no join_token; a body carrying one (or any
// other unknown field) is a client on the wrong contract and is refused.
func TestRefresh_RejectsJoinTokenField(t *testing.T) {
	s := enrollAgainstHandlers(t)
	assertEnrollFailed(t, postRefresh(sealedRefreshBody(t, s, map[string]any{"join_token": "ek_1.secret"})))
}

func TestRefresh_MissingFields(t *testing.T) {
	setupPKIDirs(t)
	for name, body := range map[string]string{
		"empty":       `{}`,
		"no sealed":   `{"nkey_pub":"UABC"}`,
		"null sealed": `{"nkey_pub":"UABC","sealed":null}`,
		"no nkey_pub": `{"sealed":{"v":2,"s":[]}}`,
		"not json":    `nope`,
	} {
		t.Run(name, func(t *testing.T) {
			assertEnrollFailed(t, postRefresh([]byte(body)))
		})
	}
}

// Presented under another NKey, a sprout's sealed request is refused:
// farmer looks the sprout up by nkey_pub and opens only under its keys.
func TestRefresh_UnenrolledNKeyRejected(t *testing.T) {
	s := enrollAgainstHandlers(t)
	stranger, _ := nkeys.CreateUser()
	strangerPub, _ := stranger.PublicKey()
	var body map[string]any
	_ = json.Unmarshal(sealedRefreshBody(t, s, nil), &body)
	body["nkey_pub"] = strangerPub
	b, _ := json.Marshal(body)
	assertEnrollFailed(t, postRefresh(b))
}

// A captured refresh request can't be replayed.
func TestRefresh_ReplayRefused(t *testing.T) {
	s := enrollAgainstHandlers(t)
	body := sealedRefreshBody(t, s, nil)
	if w := postRefresh(body); w.Code != http.StatusOK {
		t.Fatalf("first: %d %s", w.Code, w.Body)
	}
	assertEnrollFailed(t, postRefresh(body))
}
