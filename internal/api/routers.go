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
//   - Gateway JWT refresh (POST /v1/refresh): an enrolled sprout's
//     proof-of-possession-authenticated renewal of its short-lived
//     gateway JWT, on the same design doc.
//   - File serving: sprouts download recipe files via the farmer:// scheme,
//     read from object storage (see handlers.SetRecipeStore) rather than
//     local disk — docs/design/imas-master-plan.md Phase 1. Behind
//     workstream H's Envoy JWT gate (deploy/envoy/envoy.yaml's /files/
//     route); Auth accepts a sprout's gateway JWT here, scoped to that
//     sprout's own keys (handlers.SproutFilePrefix).
//   - No recipe browsing: the imas CLI and imas serve list and read
//     recipes over sealed imas.api.recipes.list/get
//     (internal/natsapi/recipes.go). The HTTP routes for that were
//     removed once J.3 left them nothing to accept (CL.4).
//   - Sprout update manifest (GET /v1/sprout/update-manifest): the
//     signed fleetsign.Manifest of the caller's tenant's approved sprout
//     version for one OS/arch (cloudxp-machine-manager-api-design.md
//     §2.6). Gateway JWT only; the tenant is the token's, never a
//     parameter. See handlers.GetSproutUpdateManifest.
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

	// Gateway JWT refresh for enrolled sprouts — no auth required here
	// either: the sprout's gateway JWT may already have expired, so the
	// request authenticates as a payloadbox message sealed with the
	// sprout's box key, opened inside handlers.Refresh/pki.RefreshSprout,
	// and the new gateway JWT goes back sealed to it (J.2). No NKey
	// signature (the bus can get one over a CONNECT nonce) and no join
	// token.
	mux.Handle("POST /v1/refresh", Logger(http.HandlerFunc(handlers.Refresh), "Refresh"))

	// Gateway JWT JWKS (design doc §2.4 per the "Gateway JWT Companion
	// Token" brief) — public keys only, no auth required. What Envoy's
	// jwt_authn remote_jwks (deploy/envoy/envoy.yaml) fetches.
	mux.Handle("GET /v1/.well-known/jwks.json", Logger(http.HandlerFunc(handlers.JWKS), "JWKS"))

	// Health checks (unauthenticated): /health is liveness (process up and
	// holding a Valkey client, no network calls — see handlers.GetHealth);
	// /ready is readiness (PXC, Valkey, and NATS tenant connection state —
	// see handlers.GetReady for what gates it).
	mux.Handle("GET /health", Logger(http.HandlerFunc(handlers.GetHealth), "GetHealth"))
	mux.Handle("GET /ready", Logger(http.HandlerFunc(handlers.GetReady), "GetReady"))

	// File server: serves recipe files over HTTPS (farmer:// scheme).
	mux.Handle("GET /files/", Logger(Auth(http.HandlerFunc(handlers.GetFile), "FileServer"), "FileServer"))

	// Sprout update manifest (design doc §2.6): gateway JWT only, which
	// Auth verifies and turns into the (tenant_id, sprout_id) the handler
	// serves — never a CLI token, never a tenant from the query.
	mux.Handle("GET /v1/sprout/update-manifest", Logger(Auth(http.HandlerFunc(handlers.GetSproutUpdateManifest), "SproutUpdateManifest"), "SproutUpdateManifest"))

	return mux
}
