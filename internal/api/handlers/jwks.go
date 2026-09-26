package handlers

// GET /v1/.well-known/jwks.json — design doc §2.4 (per the "Gateway JWT
// Companion Token" implementation brief). Serves internal/gatewayjwt's
// JWKS document: the public half of the platform-wide gateway signing
// key, which Envoy's jwt_authn remote_jwks (deploy/envoy/envoy.yaml)
// validates gateway JWTs against.

import (
	"net/http"

	"github.com/yogzblr/imas/internal/gatewayjwt"
)

// gatewaySigner is set once at startup via SetGatewaySigner
// (cmd/farmer/main.go), mirroring SetRecipeStore in recipes.go.
var gatewaySigner *gatewayjwt.GatewaySigner

// SetGatewaySigner installs the signer JWKS serves public keys for.
func SetGatewaySigner(s *gatewayjwt.GatewaySigner) { gatewaySigner = s }

// JWKS handles GET /v1/.well-known/jwks.json. Deliberately not wrapped
// in Auth (see routers.go) — a JWKS document contains only public keys.
func JWKS(w http.ResponseWriter, r *http.Request) {
	if gatewaySigner == nil {
		http.Error(w, "jwks_unavailable", http.StatusServiceUnavailable)
		return
	}
	gatewayjwt.JWKSHandler(gatewaySigner)(w, r)
}
