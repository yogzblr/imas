package gatewayjwt

// Validates the served JWKS document's shape directly against RFC
// 7517/8037's field requirements, independent of whether jwx's own
// parser (exercised in mint_test.go) would tolerate something looser.
import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJWKSHandler_ShapeMatchesRFC7517AndRFC8037(t *testing.T) {
	srv := newMockTransitServer(t, "imas-gateway-jwt", 1)
	signer := newTestGatewaySigner(t, srv)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/.well-known/jwks.json", nil)
	JWKSHandler(signer)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}

	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decoding JWKS body: %v", err)
	}
	if len(doc.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(doc.Keys))
	}

	k := doc.Keys[0]
	if k["kty"] != "OKP" {
		t.Errorf(`"kty": got %v, want "OKP" (RFC 8037)`, k["kty"])
	}
	if k["crv"] != "Ed25519" {
		t.Errorf(`"crv": got %v, want "Ed25519" (RFC 8037)`, k["crv"])
	}
	if k["use"] != "sig" {
		t.Errorf(`"use": got %v, want "sig"`, k["use"])
	}
	if k["alg"] != "EdDSA" {
		t.Errorf(`"alg": got %v, want "EdDSA"`, k["alg"])
	}
	if k["kid"] != "1" {
		t.Errorf(`"kid": got %v, want "1"`, k["kid"])
	}

	x, ok := k["x"].(string)
	if !ok || x == "" {
		t.Fatalf(`"x": expected a non-empty string, got %v`, k["x"])
	}
	raw, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		t.Fatalf(`"x" is not valid unpadded base64url (RFC 7517 §3): %v`, err)
	}
	if len(raw) != 32 {
		t.Errorf(`"x": decoded to %d bytes, want 32 (an Ed25519 public key)`, len(raw))
	}

	// The private half must never appear.
	if _, present := k["d"]; present {
		t.Error(`JWKS document must not include the private key field "d"`)
	}
}

func TestJWKSHandler_NoAuthRequired(t *testing.T) {
	// JWKSHandler itself does not gate on any credential — matches how
	// it's registered in internal/api/routers.go (no Auth() wrapper).
	// This test just documents/pins that the handler function has no
	// such check baked in, independent of routing.
	srv := newMockTransitServer(t, "imas-gateway-jwt", 1)
	signer := newTestGatewaySigner(t, srv)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/.well-known/jwks.json", nil) // no Authorization header
	JWKSHandler(signer)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with no credentials, got %d", rec.Code)
	}
}
