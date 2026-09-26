package api

import (
	"net/http"

	"github.com/yogzblr/imas/internal/api/handlers"
)

// NewRouter creates an http.ServeMux for the farmer's HTTPS server.
// This server handles:
//   - PKI bootstrap: sprouts without NATS credentials fetch the CA
//     certificate and register their NKey here.
//   - Enrollment (POST /v1/enroll): the join-token-based path that mints a
//     sprout's JWT/NKey identity in one round trip — see
//     docs/design/imas-envoy-enrollment-design.md.
//   - File serving: sprouts download recipe files via the farmer:// scheme,
//     read from object storage (see handlers.SetRecipeStore) rather than
//     local disk — docs/design/imas-master-plan.md Phase 1.
//   - Recipe browsing (GET /v1/recipes, GET /v1/recipes/{name...}): the
//     dot-notation list/get surface used by the imas CLI and web UI,
//     behind workstream H's Envoy JWT gate (deploy/envoy/envoy.yaml's
//     /v1/recipes route) — replaces the old NATS-based
//     internal/natsapi/recipes.go per
//     docs/design/imas-fork-roadmap.md workstream I.
//   - Health checks: unauthenticated /health (liveness) and /ready
//     (readiness) endpoints for Kubernetes probes, monitoring, and
//     automated tooling.
func NewRouter(certificate string) *http.ServeMux {
	_ = certificate // reserved for future TLS configuration
	mux := http.NewServeMux()

	// PKI bootstrap routes (no auth required — pre-enrollment sprouts use these)
	mux.Handle("GET /auth/cert/", Logger(http.HandlerFunc(handlers.GetCertificate), "GetCertificate"))
	mux.Handle("PUT /pki/putnkey", Logger(http.HandlerFunc(handlers.PutNKey), "PutNKey"))

	// Sprout enrollment (docs/design/imas-envoy-enrollment-design.md,
	// cloudxp-machine-manager-api-design.md §3.2) — also no auth required,
	// for the same reason as the PKI bootstrap routes above: a sprout
	// calling this has no JWT yet. Authorization here is the join token
	// itself, validated inside handlers.Enroll/pki.Enroll.
	mux.Handle("POST /v1/enroll", Logger(http.HandlerFunc(handlers.Enroll), "Enroll"))

	// Gateway JWT JWKS (design doc §2.4 per the "Gateway JWT Companion
	// Token" brief) — public keys only, no auth required. What Envoy's
	// jwt_authn remote_jwks (deploy/envoy/envoy.yaml) fetches.
	mux.Handle("GET /v1/.well-known/jwks.json", Logger(http.HandlerFunc(handlers.JWKS), "JWKS"))

	// Fleet release signing key (design doc §2.5) — the public half of
	// imas-fleet-signing, read with farmer's read-only Transit token.
	// Public keys only, no auth required, same as the gateway JWKS above.
	mux.Handle("GET /v1/.well-known/fleet-signing-jwks.json", Logger(http.HandlerFunc(handlers.FleetSigningJWKS), "FleetSigningJWKS"))

	// Health checks (unauthenticated): /health is liveness (process up and
	// holding a Valkey client, no network calls — see handlers.GetHealth);
	// /ready is readiness (PXC, Valkey, and NATS tenant connection state —
	// see handlers.GetReady for what gates it).
	mux.Handle("GET /health", Logger(http.HandlerFunc(handlers.GetHealth), "GetHealth"))
	mux.Handle("GET /ready", Logger(http.HandlerFunc(handlers.GetReady), "GetReady"))

	// File server: serves recipe files over HTTPS (farmer:// scheme).
	mux.Handle("GET /files/", Logger(Auth(http.HandlerFunc(handlers.GetFile), "FileServer"), "FileServer"))

	// Recipe browsing: dot-notation list/get, used by the imas CLI and
	// web UI (docs/design/imas-fork-roadmap.md workstream I).
	mux.Handle("GET /v1/recipes", Logger(Auth(http.HandlerFunc(handlers.ListRecipes), "ListRecipes"), "ListRecipes"))
	mux.Handle("GET /v1/recipes/{name...}", Logger(Auth(http.HandlerFunc(handlers.GetRecipe), "GetRecipe"), "GetRecipe"))

	return mux
}
