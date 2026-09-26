package gatewayjwt

// Validates this package against jwx's own, independent JOSE
// implementation rather than only its own code — the "round trips
// through a standard JOSE library's own verifier" step from the
// implementation brief. Unit tests can't assume a real OpenBao, so
// mockTransitServer stands in for it: a small httptest.Server
// implementing the same request/response shapes as Transit's
// sign/<key> and keys/<key> endpoints, so obtransit.go's HTTP client
// code is exercised for real, not bypassed. Its response shapes must
// match what a real server sends; openbao_response_test.go checks this
// package against captured real OpenBao responses and, when
// IMAS_TEST_OPENBAO_ADDR is set, a live server.
import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// mockTransitKey is one Ed25519 keypair the mock server can sign with
// and serve the public half of.
type mockTransitKey struct {
	version int
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
}

// mockTransitServer serves the subset of OpenBao/Vault Transit's HTTP API
// this package's obTransitClient uses: POST <mount>/sign/<key> and GET
// <mount>/keys/<key>. Signing happens with real ed25519.Sign, so a
// signature produced through this server is cryptographically identical
// in shape to one a real Transit instance would return — only the key
// custody (in-memory here, HSM/Transit-internal for real) differs.
type mockTransitServer struct {
	t                    *testing.T
	keyName              string
	mount                string
	token                string
	versions             []mockTransitKey
	minEncryptionVersion int
}

func newMockTransitServer(t *testing.T, keyName string, numVersions int) *mockTransitServer {
	t.Helper()
	m := &mockTransitServer{t: t, keyName: keyName, mount: "transit", token: "test-token"}
	for i := 1; i <= numVersions; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generating mock transit key version %d: %v", i, err)
		}
		m.versions = append(m.versions, mockTransitKey{version: i, pub: pub, priv: priv})
	}
	m.minEncryptionVersion = numVersions // Transit-style: sign with the latest by default
	return m
}

func (m *mockTransitServer) latest() mockTransitKey {
	return m.versions[len(m.versions)-1]
}

func (m *mockTransitServer) start() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/"+m.mount+"/sign/"+m.keyName, m.handleSign)
	mux.HandleFunc("/v1/"+m.mount+"/keys/"+m.keyName, m.handleReadKey)
	return httptest.NewServer(mux)
}

func (m *mockTransitServer) handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Vault-Token") != m.token {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var req struct {
		Input string `json:"input"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	input, err := base64.StdEncoding.DecodeString(req.Input)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	key := m.latest()
	sig := ed25519.Sign(key.priv, input)
	resp := map[string]any{
		"data": map[string]any{
			"signature":   "vault:v" + strconv.Itoa(key.version) + ":" + base64.StdEncoding.EncodeToString(sig),
			"key_version": key.version,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (m *mockTransitServer) handleReadKey(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Vault-Token") != m.token {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	keys := map[string]any{}
	for _, v := range m.versions {
		// Real Transit returns an ed25519 public_key as standard base64
		// of the raw 32-byte key, not PEM (PEM is ECDSA/RSA only). See
		// testdata/openbao-v2.7.0/transit-keys.json.
		keys[strconv.Itoa(v.version)] = map[string]any{
			"name":          "ed25519",
			"public_key":    base64.StdEncoding.EncodeToString(v.pub),
			"creation_time": time.Now().UTC().Format(time.RFC3339Nano),
		}
	}
	resp := map[string]any{
		"data": map[string]any{
			"type":                   "ed25519",
			"keys":                   keys,
			"min_encryption_version": m.minEncryptionVersion,
			"latest_version":         m.latest().version,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func newTestGatewaySigner(t *testing.T, srv *mockTransitServer) *GatewaySigner {
	t.Helper()
	ts := srv.start()
	t.Cleanup(ts.Close)
	t.Setenv(EnvOpenBaoAddr, ts.URL)
	t.Setenv(EnvOpenBaoTransitMount, srv.mount)
	t.Setenv(EnvOpenBaoAuthMethod, AuthMethodToken)
	t.Setenv(EnvOpenBaoToken, srv.token)

	signer, err := NewGatewaySigner(srv.keyName)
	if err != nil {
		t.Fatalf("NewGatewaySigner: %v", err)
	}
	return signer
}

// TestMintGatewayJWT_RoundTripsThroughJWX signs a gateway JWT via this
// package, serves its own JWKS document, and verifies the token using
// jwx's own jwt.Parse + jwt.WithKeySet — a completely independent JOSE
// implementation from anything this package wrote. If the header, claim
// encoding, or signature were subtly wrong, this fails the same way a
// real external validator (Envoy's jwt_authn, Keycloak) would reject it.
func TestMintGatewayJWT_RoundTripsThroughJWX(t *testing.T) {
	srv := newMockTransitServer(t, "imas-gateway-jwt", 1)
	signer := newTestGatewaySigner(t, srv)
	ctx := t.Context()

	claims := GatewayClaims{
		Subject:  "UABCDEF1234567890",
		TenantID: "t_test",
		SproutID: "web-01",
		Expiry:   time.Now().Add(time.Hour),
	}
	token, err := MintGatewayJWT(ctx, signer, claims)
	if err != nil {
		t.Fatalf("MintGatewayJWT: %v", err)
	}

	set := jwks(t, signer)

	parsed, err := jwt.Parse([]byte(token), jwt.WithKeySet(set))
	if err != nil {
		t.Fatalf("jwx failed to verify the minted gateway JWT against its own JWKS: %v", err)
	}
	if parsed.Subject() != claims.Subject {
		t.Errorf("sub: got %q, want %q", parsed.Subject(), claims.Subject)
	}
	if parsed.Issuer() != GatewayIssuer {
		t.Errorf("iss: got %q, want %q", parsed.Issuer(), GatewayIssuer)
	}
	if v, ok := parsed.Get("tenant_id"); !ok || v != claims.TenantID {
		t.Errorf("tenant_id: got %v, want %q", v, claims.TenantID)
	}
	if v, ok := parsed.Get("sprout_id"); !ok || v != claims.SproutID {
		t.Errorf("sprout_id: got %v, want %q", v, claims.SproutID)
	}

	// Independently confirm the header actually says what Envoy's
	// jwt_authn needs it to say — this is the exact defect class that
	// motivated this whole package (the NATS User JWT's non-standard
	// "ed25519-nkey" alg).
	msg, err := parseCompactHeader(t, token)
	if err != nil {
		t.Fatalf("parsing compact header: %v", err)
	}
	if msg["alg"] != "EdDSA" {
		t.Errorf(`header "alg": got %v, want "EdDSA"`, msg["alg"])
	}
}

// TestMintGatewayJWT_TamperedSignatureFailsVerification confirms jwx
// rejects a gateway JWT whose payload was altered after signing —
// Envoy's jwt_authn would reject the same token the same way.
func TestMintGatewayJWT_TamperedSignatureFailsVerification(t *testing.T) {
	srv := newMockTransitServer(t, "imas-gateway-jwt", 1)
	signer := newTestGatewaySigner(t, srv)
	ctx := t.Context()

	token, err := MintGatewayJWT(ctx, signer, GatewayClaims{
		Subject: "UABCDEF1234567890", Expiry: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("MintGatewayJWT: %v", err)
	}
	set := jwks(t, signer)

	tampered := token[:len(token)-4] + "AAAA"
	if _, err := jwt.Parse([]byte(tampered), jwt.WithKeySet(set)); err == nil {
		t.Fatal("expected jwx to reject a tampered gateway JWT, got no error")
	}
}

// TestMintGatewayJWT_ExpiredTokenFailsValidation confirms jwt.Validate
// (which jwt.Parse runs by default) rejects an already-expired gateway
// JWT.
func TestMintGatewayJWT_ExpiredTokenFailsValidation(t *testing.T) {
	srv := newMockTransitServer(t, "imas-gateway-jwt", 1)
	signer := newTestGatewaySigner(t, srv)
	ctx := t.Context()

	token, err := MintGatewayJWT(ctx, signer, GatewayClaims{
		Subject: "UABCDEF1234567890", Expiry: time.Now().Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("MintGatewayJWT: %v", err)
	}
	set := jwks(t, signer)

	if _, err := jwt.Parse([]byte(token), jwt.WithKeySet(set)); err == nil {
		t.Fatal("expected jwx to reject an expired gateway JWT, got no error")
	}
}

// TestMintGatewayJWT_RotationOverlap signs with the (new) latest Transit
// key version while an older version is still within
// min_encryption_version's serving window, and confirms a token signed
// under the outgoing version still verifies against the JWKS — the
// acceptance criterion "gateway JWTs signed under the outgoing key
// continue to validate during that window."
func TestMintGatewayJWT_RotationOverlap(t *testing.T) {
	srv := newMockTransitServer(t, "imas-gateway-jwt", 2)
	srv.minEncryptionVersion = 1 // both versions still valid for verification
	signer := newTestGatewaySigner(t, srv)

	set := jwks(t, signer)
	if set.Len() != 2 {
		t.Fatalf("expected 2 keys in JWKS during rotation overlap, got %d", set.Len())
	}

	// MintGatewayJWT always signs with the latest version (v2); simulate
	// an outgoing v1-signed token directly (using jwx against the raw
	// private key, standing in for what Transit would have produced
	// under that version) and confirm it still verifies against the full
	// JWKS.
	v1 := srv.versions[0]
	claims, err := jwt.NewBuilder().Subject("UOLD").Issuer(GatewayIssuer).
		Expiration(time.Now().Add(time.Hour)).Build()
	if err != nil {
		t.Fatalf("building claims: %v", err)
	}
	hdrs := jws.NewHeaders()
	if err := hdrs.Set(jws.KeyIDKey, strconv.Itoa(v1.version)); err != nil {
		t.Fatalf("setting kid: %v", err)
	}
	signed, err := jwt.Sign(claims, jwt.WithKey(jwa.EdDSA, v1.priv, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatalf("signing with outgoing key version: %v", err)
	}
	if _, err := jwt.Parse(signed, jwt.WithKeySet(set)); err != nil {
		t.Fatalf("expected a token signed under the outgoing key version to still verify, got: %v", err)
	}
}

func jwks(t *testing.T, signer *GatewaySigner) jwk.Set {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/.well-known/jwks.json", nil)
	JWKSHandler(signer)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("JWKSHandler: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	set, err := jwk.Parse(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("parsing served JWKS: %v", err)
	}
	return set
}

func parseCompactHeader(t *testing.T, token string) (map[string]any, error) {
	t.Helper()
	dot := -1
	for i, c := range token {
		if c == '.' {
			dot = i
			break
		}
	}
	if dot < 0 {
		t.Fatalf("malformed compact token %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token[:dot])
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}
