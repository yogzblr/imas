package gatewayjwt

// Tests against what a real OpenBao actually returns, not against this
// package's idea of it. mockTransitServer (mint_test.go) once served
// Ed25519 public keys as PEM, which real Transit never does, and that
// hid a JWKS endpoint that 503'd against every real OpenBao.
//
// testdata/openbao-v2.7.0/ holds verbatim response bodies captured from
// an OpenBao v2.7.0 dev server:
//
//	bao server -dev -dev-root-token-id=root &
//	bao secrets enable transit
//	bao write -f transit/keys/imas-gateway-jwt type=ed25519
//	bao write -f transit/keys/imas-gateway-jwt/rotate
//	curl -H "X-Vault-Token: root" $BAO_ADDR/v1/transit/keys/imas-gateway-jwt > transit-keys.json
//	curl -H "X-Vault-Token: root" -d '{"input":"<b64 realTransitSignInput>","key_version":N}' \
//	  $BAO_ADDR/v1/transit/sign/imas-gateway-jwt > transit-sign-vN.json
//
// Don't regenerate them from Go code or edit them by hand; recapture
// them from a real server.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/yogzblr/imas/internal/openbao/openbaotest"
)

// realTransitSignInput is the message transit-sign-v*.json signed.
const realTransitSignInput = "imas gatewayjwt fixture: signed by OpenBao v2.7.0 Transit"

const realTransitDir = "testdata/openbao-v2.7.0"

func readRealTransitFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(realTransitDir, name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return data
}

// serveRealTransitKeys replays the captured GET keys/<key> body
// byte-for-byte and points NewGatewaySigner at it.
func serveRealTransitKeys(t *testing.T) *GatewaySigner {
	t.Helper()
	body := readRealTransitFixture(t, "transit-keys.json")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/transit/keys/imas-gateway-jwt" || r.Header.Get("X-Vault-Token") != "root" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	t.Cleanup(ts.Close)
	t.Setenv(EnvOpenBaoAddr, ts.URL)
	t.Setenv(EnvOpenBaoTransitMount, "transit")
	t.Setenv(EnvOpenBaoAuthMethod, AuthMethodToken)
	t.Setenv(EnvOpenBaoToken, "root")
	signer, err := NewGatewaySigner("imas-gateway-jwt")
	if err != nil {
		t.Fatalf("NewGatewaySigner: %v", err)
	}
	return signer
}

// The regression test: the JWKS endpoint must serve 200 from a real
// OpenBao key read, and the keys it serves must verify signatures that
// same OpenBao made — not merely decode to 32 bytes.
func TestJWKSHandler_RealOpenBaoResponse(t *testing.T) {
	signer := serveRealTransitKeys(t)

	rec := httptest.NewRecorder()
	JWKSHandler(signer)(rec, httptest.NewRequest(http.MethodGet, "/v1/.well-known/jwks.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("JWKS against a real OpenBao key read: status %d: %s", rec.Code, rec.Body.String())
	}
	set, err := jwk.Parse(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("parsing served JWKS: %v", err)
	}
	if set.Len() != 2 {
		t.Fatalf("served %d keys, want 2 (both captured versions)", set.Len())
	}

	// The served "x" must be exactly the bytes OpenBao reported.
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
	for kid, v := range keysResp.Data.Keys {
		want, err := base64.StdEncoding.DecodeString(v.PublicKey)
		if err != nil {
			t.Fatalf("fixture public_key for version %s is not base64: %v", kid, err)
		}
		if got := servedKey(t, set, kid); !bytes.Equal(got, want) {
			t.Errorf("kid %s: served %x, OpenBao reported %x", kid, got, want)
		}
	}

	for _, name := range []string{"transit-sign-v1.json", "transit-sign-v2.json"} {
		var sr struct {
			Data struct {
				Signature  string `json:"signature"`
				KeyVersion int    `json:"key_version"`
			} `json:"data"`
		}
		if err := json.Unmarshal(readRealTransitFixture(t, name), &sr); err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(sr.Data.Signature, ":")
		sig, err := base64.StdEncoding.DecodeString(parts[len(parts)-1])
		if err != nil {
			t.Fatalf("%s: decoding signature: %v", name, err)
		}
		pub := servedKey(t, set, strings.TrimPrefix(parts[1], "v"))
		if !ed25519.Verify(pub, []byte(realTransitSignInput), sig) {
			t.Errorf("%s: OpenBao's own v%d signature doesn't verify under the served kid %d", name, sr.Data.KeyVersion, sr.Data.KeyVersion)
		}
	}
}

func servedKey(t *testing.T, set jwk.Set, kid string) ed25519.PublicKey {
	t.Helper()
	key, ok := set.LookupKeyID(kid)
	if !ok {
		t.Fatalf("served JWKS has no kid %q", kid)
	}
	var pub ed25519.PublicKey
	if err := key.Raw(&pub); err != nil {
		t.Fatalf("kid %s: %v", kid, err)
	}
	return pub
}

func TestParseTransitEd25519PublicKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseTransitEd25519PublicKey(base64.StdEncoding.EncodeToString(pub))
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
		if _, err := parseTransitEd25519PublicKey(in); err == nil {
			t.Errorf("%s: accepted %q", name, in)
		}
	}
}

// TestOpenBaoLive_JWKSServesMintedTokenKey runs the whole gateway JWT
// path against a real OpenBao: create an Ed25519 Transit key, mint a
// token through Transit, serve the JWKS, and verify the token with jwx
// against it. It needs an OpenBao (or Vault) it may configure, e.g.
//
//	bao server -dev -dev-root-token-id=root &
//	IMAS_TEST_OPENBAO_ADDR=http://127.0.0.1:8200 IMAS_TEST_OPENBAO_TOKEN=root \
//	  go test ./internal/gatewayjwt -run TestOpenBaoLive -v
//
// and is skipped otherwise. It mounts Transit at a fresh random path and
// removes the mount when done. Same env vars as cmd/fleetreleaser's
// TestOpenBaoEnforcesReadOnlyFleetKey.
func TestOpenBaoLive_JWKSServesMintedTokenKey(t *testing.T) {
	addr, rootToken := os.Getenv("IMAS_TEST_OPENBAO_ADDR"), os.Getenv("IMAS_TEST_OPENBAO_TOKEN")
	if addr == "" || rootToken == "" {
		t.Skip("IMAS_TEST_OPENBAO_ADDR and IMAS_TEST_OPENBAO_TOKEN not set; this test needs a real OpenBao")
	}
	addr = strings.TrimRight(addr, "/")
	suffix := make([]byte, 4)
	rand.Read(suffix)
	mount := "gwjwttest-" + hex.EncodeToString(suffix)
	const keyName = "imas-gateway-jwt"

	bao := openbaotest.NewAdmin(t, addr, rootToken)
	admin := func(method, path string, body any) { bao.Must(method, path, body) }
	admin(http.MethodPost, "sys/mounts/"+mount, map[string]any{"type": "transit"})
	t.Cleanup(func() { bao.Delete("sys/mounts/" + mount) })
	admin(http.MethodPost, mount+"/keys/"+keyName, map[string]any{"type": "ed25519"})
	admin(http.MethodPost, mount+"/keys/"+keyName+"/rotate", nil)

	t.Setenv(EnvOpenBaoAddr, addr)
	t.Setenv(EnvOpenBaoTransitMount, mount)
	t.Setenv(EnvOpenBaoAuthMethod, AuthMethodToken)
	t.Setenv(EnvOpenBaoToken, rootToken)
	signer, err := NewGatewaySigner(keyName)
	if err != nil {
		t.Fatalf("NewGatewaySigner: %v", err)
	}

	token, err := MintGatewayJWT(t.Context(), signer, GatewayClaims{
		Subject: "UABCDEF1234567890", TenantID: "t_live", SproutID: "web-01", Expiry: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("MintGatewayJWT via real Transit: %v", err)
	}

	rec := httptest.NewRecorder()
	JWKSHandler(signer)(rec, httptest.NewRequest(http.MethodGet, "/v1/.well-known/jwks.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("JWKS against real OpenBao: status %d: %s", rec.Code, rec.Body.String())
	}
	set, err := jwk.Parse(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("parsing served JWKS: %v", err)
	}
	if set.Len() != 2 {
		t.Errorf("served %d keys, want 2 (both versions)", set.Len())
	}
	if _, err := jwt.Parse([]byte(token), jwt.WithKeySet(set)); err != nil {
		t.Fatalf("token minted by real Transit doesn't verify against the served JWKS: %v", err)
	}
}
