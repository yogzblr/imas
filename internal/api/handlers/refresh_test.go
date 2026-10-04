package handlers

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// sealedRefreshBody is a POST /v1/refresh body for the sprout
// enrollAgainstHandlers enrolled, sealed now, with extra fields merged in.
func sealedRefreshBody(t *testing.T, s *handlerSprout, extra map[string]any) []byte {
	t.Helper()
	b, _ := sealedRefreshBodyWithID(t, s, extra)
	return b
}

// sealedRefreshBodyWithID is sealedRefreshBody, also returning the sealed
// request's message ID, which farmer's reply must name.
func sealedRefreshBodyWithID(t *testing.T, s *handlerSprout, extra map[string]any) ([]byte, string) {
	t.Helper()
	sproutID, err := pki.PinnedSproutID()
	if err != nil {
		t.Fatal(err)
	}
	sealed, msgID, err := pki.SproutSealedRefresh(sproutID, s.nkeyPub)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"nkey_pub": s.nkeyPub, "sealed": json.RawMessage(sealed)}
	for k, v := range extra {
		body[k] = v
	}
	b, _ := json.Marshal(body)
	return b, msgID
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
// sprout (Envoy terminates TLS in the DMZ). The body is exactly
// {"sealed": envelope}, so its only plaintext is that shape's field
// names; no key or string in it is or contains a JWT; and the envelope
// opens under the sprout's box key, as the reply to this request, and
// under no other key. (It used to search the body for "eyJ", which the
// random base64 ciphertext contains in about 1.5% of runs: T.1.)
func TestRefresh_AnswersOnlySealed(t *testing.T) {
	s := enrollAgainstHandlers(t)
	reqBody, msgID := sealedRefreshBodyWithID(t, s, nil)
	w := postRefresh(reqBody)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Sealed json.RawMessage `json:"sealed"`
	}
	if err := decodeStrict(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("the response is not exactly {sealed}: %v: %s", err, w.Body)
	}
	if err := checkSealedEnvelope(resp.Sealed); err != nil {
		t.Fatalf("the response's sealed field: %v", err)
	}
	if jwt, found, err := jwtInJSON(w.Body.Bytes()); err != nil || found {
		t.Errorf("the response carries a JWT in the clear: %q (%v)", jwt, err)
	}

	res := openRefreshReply(t, resp.Sealed, msgID)
	for name, v := range map[string]string{"gateway_jwt": res.GatewayJWT, "jwt": res.JWT} {
		if _, ok := findJWT(v); !ok {
			t.Errorf("sealed %s %q is not recognized as a JWT, so the check above proves nothing", name, v)
		}
		if strings.Contains(w.Body.String(), v) {
			t.Errorf("the response carries the %s in the clear", name)
		}
	}
	if res.SproutID != "web-01" || res.NKeyIdentity != s.nkeyPub || res.TenantID != pki.CurrentTenantID() {
		t.Errorf("unexpected sealed result %+v", res)
	}

	// Under any other box key, or as the reply to another request, it
	// doesn't open.
	tenantPub, sproutPriv, tenantID := sproutReplyKeys(t)
	strangerPub, strangerPriv, _ := box.GenerateKey(rand.Reader)
	want := refreshReplyExpect(tenantID, msgID)
	for name, kp := range map[string]payloadbox.KeyPair{
		"another sprout key": {PeerPub: tenantPub, Priv: strangerPriv},
		"another tenant key": {PeerPub: strangerPub, Priv: sproutPriv},
	} {
		if _, _, err := payloadbox.OpenReply(resp.Sealed, []payloadbox.KeyPair{kp}, want); !errors.Is(err, payloadbox.ErrOpen) {
			t.Errorf("under %s: %v, want payloadbox.ErrOpen", name, err)
		}
	}
	other := want
	other.ReplyTo = "0123456789abcdef0123456789abcdef"
	if _, _, err := payloadbox.OpenReply(resp.Sealed, []payloadbox.KeyPair{{PeerPub: tenantPub, Priv: sproutPriv}}, other); !errors.Is(err, payloadbox.ErrOpen) {
		t.Errorf("as the reply to another request: %v, want payloadbox.ErrOpen", err)
	}
}

// The old assertion, a substring search of the body for "eyJ", fails on
// a sealed reply whose ciphertext happens to encode to it; the new one
// passes it, and still catches a JWT in any plaintext field.
func TestRefresh_SealedCheckIgnoresCiphertextThatLooksLikeJWT(t *testing.T) {
	// `{"` encodes to "eyJ" in standard base64 as in base64url.
	ct := append([]byte(`{"`), bytes.Repeat([]byte{0x5a}, 46)...)
	env := payloadbox.Envelope{V: payloadbox.Version, Copies: []payloadbox.Sealed{{Nonce: make([]byte, 24), Box: ct}}}
	sealed, _ := json.Marshal(env)
	body, _ := json.Marshal(map[string]json.RawMessage{"sealed": sealed})

	if !strings.Contains(string(body), "eyJ") {
		t.Fatalf("crafted body %s doesn't contain eyJ", body)
	}
	// The new checks: exact shape, and no JWT in the clear.
	var resp struct {
		Sealed json.RawMessage `json:"sealed"`
	}
	if err := decodeStrict(body, &resp); err != nil {
		t.Fatal(err)
	}
	if err := checkSealedEnvelope(resp.Sealed); err != nil {
		t.Errorf("crafted ciphertext refused: %v", err)
	}
	if jwt, found, err := jwtInJSON(body); err != nil || found {
		t.Errorf("crafted ciphertext read as a JWT: %q (%v)", jwt, err)
	}

	// A real JWT anywhere in the clear is still caught: in an extra
	// field, inside a longer string, or as a key.
	const jwt = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ3ZWItMDEifQ.c2ln"
	for name, leaky := range map[string]string{
		"extra field":    `{"sealed":` + string(sealed) + `,"gateway_jwt":"` + jwt + `"}`,
		"inside a value": `{"sealed":` + string(sealed) + `,"note":"Bearer ` + jwt + `;"}`,
		"duplicate key":  `{"sealed":"` + jwt + `","sealed":` + string(sealed) + `}`,
		"as a key":       `{"sealed":` + string(sealed) + `,"` + jwt + `":1}`,
		"unpadded sig":   `{"x":"` + strings.TrimSuffix(jwt, "c2ln") + `"}`,
	} {
		if _, found, err := jwtInJSON([]byte(leaky)); err != nil || !found {
			t.Errorf("%s: JWT not found (%v)", name, err)
		}
	}
	// And an extra plaintext field fails the shape check whatever it holds.
	if err := decodeStrict([]byte(`{"sealed":`+string(sealed)+`,"web-01":1}`), &resp); err == nil {
		t.Error("an extra plaintext field passed the shape check")
	}
	// Not a JWT: dots between non-header parts, or base64 with no header.
	for _, s := range []string{"a.b.c", "web-01.example.com", "eyJ", "eyJhYmMi.x.y"} {
		if _, ok := findJWT(s); ok {
			t.Errorf("findJWT(%q) matched", s)
		}
	}
}

// sproutReplyKeys reads the enrolled sprout's pinned tenant key, current
// box private key and pinned tenant ID: what the sprout opens a reply
// with.
func sproutReplyKeys(t *testing.T) (tenantPub, sproutPriv *[32]byte, tenantID string) {
	t.Helper()
	pinned, err := os.ReadFile(config.SproutTenantX25519PubFile)
	if err != nil {
		t.Fatal(err)
	}
	if tenantPub, err = pki.DecodeBoxPubKey(strings.TrimSpace(string(pinned))); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(config.SproutBoxPrivFile)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(priv) != 32 {
		t.Fatalf("sprout box key: %d bytes (%v)", len(priv), err)
	}
	sproutPriv = new([32]byte)
	copy(sproutPriv[:], priv)
	if tenantID, err = pki.SproutTenantID(); err != nil {
		t.Fatal(err)
	}
	return tenantPub, sproutPriv, tenantID
}

func refreshReplyExpect(tenantID, msgID string) payloadbox.ReplyExpect {
	return payloadbox.ReplyExpect{
		Purpose: payloadbox.PurposeRefreshReply, TenantID: tenantID, Principal: "web-01",
		ReplyTo: msgID, Method: pki.RefreshMethod, Subject: pki.RefreshSubject,
	}
}

// openRefreshReply opens sealed under the sprout's keys as the reply to
// msgID and returns its result.
func openRefreshReply(t *testing.T, sealed []byte, msgID string) pki.RefreshResponse {
	t.Helper()
	tenantPub, sproutPriv, tenantID := sproutReplyKeys(t)
	_, body, err := payloadbox.OpenReply(sealed, []payloadbox.KeyPair{{PeerPub: tenantPub, Priv: sproutPriv}}, refreshReplyExpect(tenantID, msgID))
	if err != nil {
		t.Fatalf("the sprout can't open the reply: %v", err)
	}
	if body.Error != "" {
		t.Fatalf("farmer sealed an error: %s", body.Error)
	}
	var res pki.RefreshResponse
	if err := json.Unmarshal(body.Result, &res); err != nil {
		t.Fatal(err)
	}
	return res
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
