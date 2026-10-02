package fleetsign

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// mockTransit serves Transit's GET <mount>/keys/<key> in the response
// shape a real server sends, the same stand-in approach as
// internal/gatewayjwt's mockTransitServer. openbao_response_test.go
// checks this package against captured real OpenBao responses and, when
// IMAS_TEST_OPENBAO_ADDR is set, a live server. Any other path is a 404,
// so a stray request from this read-only client would fail the test.
type mockTransit struct {
	token         string
	keys          []PublicKey
	minEncryption int // floor for new signatures; must NOT limit verification
	minDecryption int // floor Transit's /verify honors
	keyType       string
	reads         atomic.Int32
	otherRequests atomic.Int32
}

func (m *mockTransit) start(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/transit/keys/"+DefaultTransitKeyName {
			m.otherRequests.Add(1)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("X-Vault-Token") != m.token {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
			return
		}
		m.reads.Add(1)
		keys := map[string]any{}
		for _, k := range m.keys {
			// Real Transit returns an ed25519 public_key as standard
			// base64 of the raw 32-byte key, not PEM. See
			// testdata/openbao-v2.7.0/transit-keys.json.
			keys[strconv.Itoa(k.Version)] = map[string]any{
				"name":       "ed25519",
				"public_key": base64.StdEncoding.EncodeToString(k.Key),
			}
		}
		keyType := m.keyType
		if keyType == "" {
			keyType = "ed25519"
		}
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
			"type": keyType, "keys": keys, "min_encryption_version": m.minEncryption,
			"min_decryption_version": m.minDecryption, "latest_version": len(m.keys),
		}})
	}))
	t.Cleanup(ts.Close)
	t.Setenv(EnvOpenBaoAddr, ts.URL)
	t.Setenv(EnvOpenBaoTransitMount, "")
	t.Setenv(EnvOpenBaoAuthMethod, AuthMethodToken)
	t.Setenv(EnvOpenBaoToken, m.token)
	t.Setenv(EnvTransitKeyName, "")
	return ts
}

func TestTransitKeySource_ReadsAndCaches(t *testing.T) {
	k1, priv1 := newTestKey(t, 1)
	k2, _ := newTestKey(t, 2)
	m := &mockTransit{token: "ro-token", keys: []PublicKey{k1, k2}}
	m.start(t)

	src, err := NewTransitKeySourceFromEnv()
	if err != nil {
		t.Fatalf("NewTransitKeySourceFromEnv: %v", err)
	}
	ks, err := src.KeySet(t.Context())
	if err != nil {
		t.Fatalf("KeySet: %v", err)
	}
	if len(ks) != 2 || !ks[0].Key.Equal(k1.Key) || !ks[1].Key.Equal(k2.Key) {
		t.Fatalf("KeySet = %+v", ks)
	}
	if err := src.Verify(t.Context(), signForTest(t, priv1, 1, testManifest())); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got := m.reads.Load(); got != 1 {
		t.Errorf("Transit reads = %d, want 1 (second call cached)", got)
	}
	if got := m.otherRequests.Load(); got != 0 {
		t.Errorf("client made %d requests other than a key read", got)
	}
}

// The case the min_encryption_version floor silently broke: a rotation in
// its grace period. v3 is the only version new signatures may use
// (min_encryption_version=3), but Transit still verifies v1 and v2
// (min_decryption_version=1). Every version down to min_decryption_version
// must be served, including the ones below min_encryption_version, and a
// manifest signed by v1 during the grace period must still verify.
func TestTransitKeySource_RotationGracePeriodServesBelowMinEncryption(t *testing.T) {
	k1, priv1 := newTestKey(t, 1)
	k2, priv2 := newTestKey(t, 2)
	k3, priv3 := newTestKey(t, 3)
	m := &mockTransit{token: "ro-token", keys: []PublicKey{k1, k2, k3}, minEncryption: 3, minDecryption: 1}
	m.start(t)
	src, err := NewTransitKeySourceFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	ks, err := src.KeySet(t.Context())
	if err != nil {
		t.Fatalf("KeySet: %v", err)
	}
	if len(ks) != 3 || ks[0].Version != 1 || ks[1].Version != 2 || ks[2].Version != 3 {
		t.Fatalf("KeySet versions = %+v, want 1, 2, 3 (down to min_decryption_version, not min_encryption_version)", ks)
	}
	for v, priv := range map[int]ed25519.PrivateKey{1: priv1, 2: priv2, 3: priv3} {
		if err := src.Verify(t.Context(), signForTest(t, priv, v, testManifest())); err != nil {
			t.Errorf("v%d signature during the grace period: %v", v, err)
		}
	}
}

// min_decryption_version is what retires a version for verification.
func TestTransitKeySource_HonorsMinDecryptionVersion(t *testing.T) {
	k1, priv1 := newTestKey(t, 1)
	k2, _ := newTestKey(t, 2)
	k3, _ := newTestKey(t, 3)
	m := &mockTransit{token: "ro-token", keys: []PublicKey{k1, k2, k3}, minEncryption: 3, minDecryption: 2}
	m.start(t)
	src, _ := NewTransitKeySourceFromEnv()
	ks, err := src.KeySet(t.Context())
	if err != nil || len(ks) != 2 || ks[0].Version != 2 || ks[1].Version != 3 {
		t.Fatalf("KeySet = %+v, %v; want versions 2, 3", ks, err)
	}
	err = src.Verify(t.Context(), signForTest(t, priv1, 1, testManifest()))
	if !errors.Is(err, ErrUnknownKeyVersion) {
		t.Fatalf("Verify with retired v1 = %v, want ErrUnknownKeyVersion", err)
	}
}

func TestTransitKeySource_Failures(t *testing.T) {
	k1, _ := newTestKey(t, 1)

	m := &mockTransit{token: "right", keys: []PublicKey{k1}}
	m.start(t)
	t.Setenv(EnvOpenBaoToken, "wrong")
	src, _ := NewTransitKeySourceFromEnv()
	if _, err := src.KeySet(t.Context()); !errors.Is(err, ErrReadKeyFailed) {
		t.Errorf("wrong token: %v, want ErrReadKeyFailed", err)
	}

	m2 := &mockTransit{token: "t", keys: []PublicKey{k1}, keyType: "aes256-gcm96"}
	m2.start(t)
	src2, _ := NewTransitKeySourceFromEnv()
	if _, err := src2.KeySet(t.Context()); !errors.Is(err, ErrReadKeyFailed) {
		t.Errorf("non-ed25519 key: %v, want ErrReadKeyFailed", err)
	}
}

func TestNewTransitKeySourceFromEnv_NotConfigured(t *testing.T) {
	t.Setenv(EnvOpenBaoAddr, "")
	if _, err := NewTransitKeySourceFromEnv(); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("missing addr: %v", err)
	}
	t.Setenv(EnvOpenBaoAddr, "http://127.0.0.1:1")
	t.Setenv(EnvOpenBaoAuthMethod, "")
	t.Setenv(EnvOpenBaoToken, "")
	if _, err := NewTransitKeySourceFromEnv(); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("missing token: %v", err)
	}
	t.Setenv(EnvOpenBaoAuthMethod, "carrier-pigeon")
	if _, err := NewTransitKeySourceFromEnv(); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("unknown auth method: %v", err)
	}
	t.Setenv(EnvOpenBaoAuthMethod, AuthMethodKubernetes)
	t.Setenv(EnvOpenBaoK8sRole, "")
	if _, err := NewTransitKeySourceFromEnv(); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("missing k8s role: %v", err)
	}
}

func TestJWKS_RoundTrip(t *testing.T) {
	k1, _ := newTestKey(t, 1)
	k2, _ := newTestKey(t, 2)
	ks, _ := NewKeySet([]PublicKey{k2, k1})
	data, err := ks.MarshalJWKS()
	if err != nil {
		t.Fatalf("MarshalJWKS: %v", err)
	}
	for _, want := range []string{`"kty":"OKP"`, `"crv":"Ed25519"`, `"kid":"1"`, `"kid":"2"`, `"alg":"EdDSA"`, `"use":"sig"`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("JWKS %s missing %s", data, want)
		}
	}
	back, err := ParseJWKS(data)
	if err != nil {
		t.Fatalf("ParseJWKS: %v", err)
	}
	if len(back) != 2 || !back[0].Key.Equal(k1.Key) || !back[1].Key.Equal(k2.Key) {
		t.Fatalf("ParseJWKS = %+v", back)
	}
}

func TestParseJWKS_Strict(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	x := jwkB64(pub)
	d := jwkB64(priv.Seed())
	cases := map[string]string{
		"not json":       `{`,
		"empty set":      `{"keys":[]}`,
		"private key":    `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + x + `","d":"` + d + `","kid":"1"}]}`,
		"no kid":         `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + x + `"}]}`,
		"non-numeric":    `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + x + `","kid":"gw-2026"}]}`,
		"zero kid":       `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + x + `","kid":"0"}]}`,
		"wrong use":      `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + x + `","kid":"1","use":"enc"}]}`,
		"wrong alg":      `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + x + `","kid":"1","alg":"ES256"}]}`,
		"x25519 not sig": `{"keys":[{"kty":"OKP","crv":"X25519","x":"` + x + `","kid":"1"}]}`,
		"duplicate kid":  `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` + x + `","kid":"1"},{"kty":"OKP","crv":"Ed25519","x":"` + x + `","kid":"1"}]}`,
	}
	for name, doc := range cases {
		if _, err := ParseJWKS([]byte(doc)); err == nil {
			t.Errorf("%s: ParseJWKS accepted %s", name, doc)
		}
	}
}

func TestJWKSHandler(t *testing.T) {
	k1, _ := newTestKey(t, 1)
	m := &mockTransit{token: "ro-token", keys: []PublicKey{k1}}
	m.start(t)
	src, _ := NewTransitKeySourceFromEnv()

	rec := httptest.NewRecorder()
	JWKSHandler(src)(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status %d, content-type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	ks, err := ParseJWKS(rec.Body.Bytes())
	if err != nil || len(ks) != 1 || !ks[0].Key.Equal(k1.Key) {
		t.Fatalf("served JWKS = %s (%v)", rec.Body, err)
	}

	t.Setenv(EnvOpenBaoToken, "wrong")
	bad, _ := NewTransitKeySourceFromEnv()
	rec = httptest.NewRecorder()
	JWKSHandler(bad)(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status with failing Transit = %d, want 503", rec.Code)
	}
}

func jwkB64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
