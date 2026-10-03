package fleetsign

// Tests against what a real OpenBao actually returns. mockTransit
// (transit_test.go) once served Ed25519 public keys as PEM, which real
// Transit never does, and that hid a fleet-signing JWKS endpoint (and
// enrollment's fleet_signing_jwks) that failed against every real
// OpenBao.
//
// testdata/openbao-v2.7.0/ holds verbatim response bodies captured from
// an OpenBao v2.7.0 dev server:
//
//	bao server -dev -dev-root-token-id=root &
//	bao secrets enable transit
//	bao write -f transit/keys/imas-fleet-signing type=ed25519
//	bao write -f transit/keys/imas-fleet-signing/rotate
//	curl -H "X-Vault-Token: root" $BAO_ADDR/v1/transit/keys/imas-fleet-signing > transit-keys.json
//	curl -H "X-Vault-Token: root" -d '{"input":"<b64 capturedSignInput>","key_version":N}' \
//	  $BAO_ADDR/v1/transit/sign/imas-fleet-signing > transit-sign-vN.json
//
// Don't regenerate them from Go code or edit them by hand; recapture
// them from a real server. The sign fixtures were captured over the
// pre-FU.0 message (capturedSignInput), not over a Manifest: they prove
// Transit's key and signature encodings round-trip through
// ParseTransitEd25519PublicKey and EncodeSignature, which the message
// change doesn't touch. Recapture them over testManifest().Message()
// when a v2.7.0 server is to hand; TestOpenBaoLive_TransitKeySource
// already signs a Manifest live.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yogzblr/imas/internal/openbao/openbaotest"
)

const realTransitDir = "testdata/openbao-v2.7.0"

// capturedSignInput is the exact input transit-sign-v{1,2}.json were
// signed over: the version|artifact_url|checksum_sha256 message fleetsign
// used before FU.0. It is a fixture, not a format anything accepts.
const capturedSignInput = "v2.4.1|https://artifacts.example.com/sprout-v2.4.1-linux-amd64|" + testChecksum

func readRealTransitFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(realTransitDir, name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return data
}

// transitSignatureToRelease converts a Transit sign response body into
// EncodeSignature's format, the conversion cmd/fleetreleaser performs.
func transitSignatureToRelease(t *testing.T, body []byte) string {
	t.Helper()
	var sr struct {
		Data struct {
			Signature  string `json:"signature"`
			KeyVersion int    `json:"key_version"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &sr); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(sr.Data.Signature, ":")
	sig, err := base64.StdEncoding.DecodeString(parts[len(parts)-1])
	if err != nil {
		t.Fatalf("decoding Transit signature: %v", err)
	}
	return EncodeSignature(sr.Data.KeyVersion, sig)
}

// The regression test: a TransitKeySource reading a real OpenBao key
// response must verify signatures that same OpenBao made, and the JWKS
// handler must serve 200.
func TestTransitKeySource_RealOpenBaoResponse(t *testing.T) {
	body := readRealTransitFixture(t, "transit-keys.json")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/transit/keys/"+DefaultTransitKeyName || r.Header.Get("X-Vault-Token") != "root" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	t.Cleanup(ts.Close)
	t.Setenv(EnvOpenBaoAddr, ts.URL)
	t.Setenv(EnvOpenBaoTransitMount, "")
	t.Setenv(EnvOpenBaoAuthMethod, AuthMethodToken)
	t.Setenv(EnvOpenBaoToken, "root")
	t.Setenv(EnvTransitKeyName, "")

	src, err := NewTransitKeySourceFromEnv()
	if err != nil {
		t.Fatalf("NewTransitKeySourceFromEnv: %v", err)
	}
	ks, err := src.KeySet(t.Context())
	if err != nil {
		t.Fatalf("KeySet from a real OpenBao key read: %v", err)
	}
	if len(ks) != 2 || ks[0].Version != 1 || ks[1].Version != 2 {
		t.Fatalf("KeySet = %+v, want versions 1 and 2", ks)
	}
	for _, name := range []string{"transit-sign-v1.json", "transit-sign-v2.json"} {
		sig := transitSignatureToRelease(t, readRealTransitFixture(t, name))
		if err := ks.verifyMessage([]byte(capturedSignInput), sig); err != nil {
			t.Errorf("%s: OpenBao's own signature doesn't verify: %v", name, err)
		}
		// The same signature is not valid for any Manifest: the old
		// message is not accepted in any form.
		m := testManifest()
		m.Signature = sig
		if err := ks.Verify(m); !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("%s: pre-FU.0 signature accepted for a Manifest: %v", name, err)
		}
	}

	rec := httptest.NewRecorder()
	JWKSHandler(src)(rec, httptest.NewRequest(http.MethodGet, "/v1/.well-known/fleet-signing-jwks.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("fleet-signing JWKS against a real OpenBao key read: status %d: %s", rec.Code, rec.Body.String())
	}
	served, err := ParseJWKS(rec.Body.Bytes())
	if err != nil || len(served) != 2 || !served[0].Key.Equal(ks[0].Key) || !served[1].Key.Equal(ks[1].Key) {
		t.Fatalf("served JWKS = %s (%v)", rec.Body, err)
	}
}

func TestParseTransitEd25519PublicKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseTransitEd25519PublicKey(base64.StdEncoding.EncodeToString(pub))
	if err != nil || !got.Equal(pub) {
		t.Fatalf("raw base64: got %x, %v; want %x", got, err, pub)
	}

	for name, in := range map[string]string{
		"empty":                          "",
		"not base64":                     "not base64!",
		"31 bytes":                       base64.StdEncoding.EncodeToString(pub[:31]),
		"33 bytes":                       base64.StdEncoding.EncodeToString(append(append([]byte{}, pub...), 0)),
		"base64url":                      base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32)),
		"PEM (not what Transit returns)": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA" + base64.StdEncoding.EncodeToString(pub) + "\n-----END PUBLIC KEY-----\n",
	} {
		if _, err := ParseTransitEd25519PublicKey(in); err == nil {
			t.Errorf("%s: accepted %q", name, in)
		}
	}
}

// cmd/fleetreleaser still calls the deprecated ParseEd25519PublicKeyPEM;
// it must accept what real Transit returns.
func TestParseEd25519PublicKeyPEM_AcceptsRealTransitFormat(t *testing.T) {
	var keysResp struct {
		Data struct {
			Keys map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(readRealTransitFixture(t, "transit-keys.json"), &keysResp); err != nil {
		t.Fatal(err)
	}
	for v, k := range keysResp.Data.Keys {
		want, _ := base64.StdEncoding.DecodeString(k.PublicKey)
		got, err := ParseEd25519PublicKeyPEM(k.PublicKey)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("version %s: got %x, %v; want %x", v, got, err, want)
		}
	}
}

// TestOpenBaoLive_TransitKeySource runs the read path against a real
// OpenBao: create and rotate an Ed25519 Transit key, have OpenBao sign a
// release, then read the key set through TransitKeySource, verify, and
// serve the JWKS. It needs an OpenBao (or Vault) it may configure, e.g.
//
//	bao server -dev -dev-root-token-id=root &
//	IMAS_TEST_OPENBAO_ADDR=http://127.0.0.1:8200 IMAS_TEST_OPENBAO_TOKEN=root \
//	  go test ./internal/fleetsign -run TestOpenBaoLive -v
//
// and is skipped otherwise. It mounts Transit at a fresh random path and
// removes the mount when done. The signing here is the test acting as
// cmd/fleetreleaser with the root token; fleetsign itself stays
// verify-only (TestNoSigningCodeInPackage).
func TestOpenBaoLive_TransitKeySource(t *testing.T) {
	addr, rootToken := os.Getenv("IMAS_TEST_OPENBAO_ADDR"), os.Getenv("IMAS_TEST_OPENBAO_TOKEN")
	if addr == "" || rootToken == "" {
		t.Skip("IMAS_TEST_OPENBAO_ADDR and IMAS_TEST_OPENBAO_TOKEN not set; this test needs a real OpenBao")
	}
	addr = strings.TrimRight(addr, "/")
	suffix := make([]byte, 4)
	rand.Read(suffix)
	mount := "fleetsigntest-" + hex.EncodeToString(suffix)

	bao := openbaotest.NewAdmin(t, addr, rootToken)
	admin := bao.Must
	admin(http.MethodPost, "sys/mounts/"+mount, map[string]any{"type": "transit"})
	t.Cleanup(func() { bao.Delete("sys/mounts/" + mount) })
	admin(http.MethodPost, mount+"/keys/"+DefaultTransitKeyName, map[string]any{"type": "ed25519"})
	admin(http.MethodPost, mount+"/keys/"+DefaultTransitKeyName+"/rotate", nil)

	m := testManifest()
	msg, err := m.Message()
	if err != nil {
		t.Fatal(err)
	}
	m.Signature = transitSignatureToRelease(t, admin(http.MethodPost, mount+"/sign/"+DefaultTransitKeyName,
		map[string]any{"input": base64.StdEncoding.EncodeToString(msg)}))

	t.Setenv(EnvOpenBaoAddr, addr)
	t.Setenv(EnvOpenBaoTransitMount, mount)
	t.Setenv(EnvOpenBaoAuthMethod, AuthMethodToken)
	t.Setenv(EnvOpenBaoToken, rootToken)
	t.Setenv(EnvTransitKeyName, "")
	src, err := NewTransitKeySourceFromEnv()
	if err != nil {
		t.Fatalf("NewTransitKeySourceFromEnv: %v", err)
	}
	if err := src.Verify(t.Context(), m); err != nil {
		t.Fatalf("manifest signed by real Transit doesn't verify: %v", err)
	}

	rec := httptest.NewRecorder()
	JWKSHandler(src)(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("fleet-signing JWKS against real OpenBao: status %d: %s", rec.Code, rec.Body.String())
	}
	if served, err := ParseJWKS(rec.Body.Bytes()); err != nil || len(served) != 2 {
		t.Fatalf("served JWKS = %s (%v), want 2 keys", rec.Body, err)
	}
}
