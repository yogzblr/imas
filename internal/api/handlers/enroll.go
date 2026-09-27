package handlers

// POST /v1/enroll: design doc §3.2
// (docs/design/cloudxp-machine-manager-api-design.md,
// docs/design/imas-envoy-enrollment-design.md). FLAG FOR SECURITY REVIEW
// per the task brief — see internal/pki/enroll.go's doc comment for why
// every failure here, at every layer, collapses to the same generic
// response.
//
// Deliberately not wrapped in Auth (see routers.go): an enrolling sprout
// has no JWT yet. It's still served over the same TLS-terminated farmer
// API server as GetCertificate/PutNKey, and is meant to sit behind Envoy's
// own IP-based rate limiting at the DMZ edge (the one route deliberately
// without a JWT gate — see the design doc's "Why this is safe" section).

import (
	"encoding/json"
	"errors"
	"net/http"

	log "github.com/yogzblr/imas/internal/log"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/pki"
)

type enrollRequest struct {
	JoinToken string `json:"join_token"`
	NKeyPub   string `json:"nkey_pub"`
	Hostname  string `json:"hostname"`
	// SproutPub is the sprout's locally-generated X25519 box public key
	// (standard base64, 32 bytes) — see
	// docs/design/imas-payload-encryption-design.md's "Bootstrap". Its
	// private half is generated and held by the sprout alone and is never
	// part of this request.
	SproutPub string `json:"sprout_pub"`
	// Timestamp and NKeySig prove the caller holds the NKey seed behind
	// NKeyPub, not just that it knows NKeyPub (which is public — Envoy
	// forwards it upstream as x-imas-sprout-nkey). NKeySig is the seed's
	// signature over pki.EnrollSigningPayload, unpadded base64url; see
	// pki.EnrollRequest and the enrollment design doc's "Proof of
	// possession" section. Required on every request, first-time and
	// replay alike.
	Timestamp int64  `json:"timestamp"`
	NKeySig   string `json:"nkey_sig"`
}

// enrollSuccessResponse is design doc §3.2's success shape, plus
// nkey_identity and tenant_x25519_pub per
// imas-envoy-enrollment-design.md's "Response, in one round trip" —
// everything the sprout needs for every subsequent interaction, issued
// atomically here rather than across several separate exchanges.
//
// jwt and gateway_jwt are two different tokens for two different
// validators, per the "Gateway JWT Companion Token" brief: jwt is the
// native NATS User JWT nats-server itself validates (alg:ed25519-nkey);
// gateway_jwt is a standard alg:EdDSA JWS (internal/gatewayjwt) for
// Envoy's jwt_authn-gated wss:// and recipe-download routes, since
// Envoy — unlike nats-server — can't be taught NATS's own JWT dialect.
//
// fleet_signing_jwks is the imas-fleet-signing public key set (design doc
// §2.5) as a JWKS document, which the sprout pins next to its root CA
// (pki.PinFleetSigningKeys). It is ADVISORY, a bootstrap fallback only:
// the sprout verifies releases against the key set it fetches live from
// farmer over its SproutRootCA-pinned NATS connection
// (imas.sprouts.<id>.fleetsigningkeys, internal/fleetkeys), so Transit key
// rotations reach it. This enrollment-time copy is used only for a
// sprout's very first update if it has never yet completed a live fetch,
// and is superseded permanently by the first live fetch that succeeds
// (internal/ingredients/selfupdate, keys.go).
//
// tenant_x25519_continuity, present only after the tenant's X25519 key
// has been rotated, is pki.TenantKeyContinuity's proof (sealed to the
// sprout's box key under the tenant keys it may have pinned before) that
// tenant_x25519_pub succeeds them; a sprout re-enrolling with an older
// key pinned verifies it and re-pins. Older sprouts ignore it.
type enrollSuccessResponse struct {
	SproutID         string          `json:"sprout_id"`
	JWT              string          `json:"jwt"`
	GatewayJWT       string          `json:"gateway_jwt"`
	NKeyIdentity     string          `json:"nkey_identity"`
	TenantX25519Pub  string          `json:"tenant_x25519_pub"`
	FleetSigningJWKS json.RawMessage `json:"fleet_signing_jwks"`
	NatsURLs         []string        `json:"nats_urls"`

	TenantX25519Continuity json.RawMessage `json:"tenant_x25519_continuity,omitempty"`
}

// enrollErrorResponse is design doc §3.4's single generic failure shape.
type enrollErrorResponse struct {
	Error string `json:"error"`
}

// Enroll handles POST /v1/enroll. Every failure path — a malformed
// request body, a missing field, or any failure inside pki.Enroll (a bad
// or stale nkey_sig, unknown/malformed token, hash mismatch, revoked,
// expired, exhausted, a lost redemption race) — writes the exact same
// status and body, by design (§3.4): distinguishing them would hand an
// attacker a free oracle for enumerating key_ids or timing a race against
// expiry.
func Enroll(w http.ResponseWriter, r *http.Request) {
	var req enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warnf("enroll: invalid request body: %v", err)
		writeEnrollFailed(w)
		return
	}
	if req.JoinToken == "" || req.NKeyPub == "" || req.Hostname == "" || req.SproutPub == "" || req.Timestamp == 0 || req.NKeySig == "" {
		log.Warnf("enroll: request missing a required field")
		writeEnrollFailed(w)
		return
	}

	// Read the fleet signing key before redeeming anything: if it can't be
	// had, the sprout couldn't pin its bootstrap copy, and failing here
	// leaves the join token unspent for the retry. Enrollment fails closed
	// without it, the same way it does without a gateway JWT signer.
	fleetJWKS, err := enrollFleetSigningJWKS(r)
	if err != nil {
		log.Errorf("enroll: fleet signing key unavailable: %v", err)
		writeEnrollFailed(w)
		return
	}

	result, err := pki.Enroll(r.Context(), pki.EnrollRequest{
		JoinToken: req.JoinToken,
		NKeyPub:   req.NKeyPub,
		Hostname:  req.Hostname,
		SproutPub: req.SproutPub,
		Timestamp: req.Timestamp,
		NKeySig:   req.NKeySig,
	})
	if err != nil {
		// pki.Enroll has already logged the specific reason; nothing more
		// to add here.
		writeEnrollFailed(w)
		return
	}

	resp := enrollSuccessResponse{
		SproutID:         result.SproutID,
		JWT:              result.JWT,
		GatewayJWT:       result.GatewayJWT,
		NKeyIdentity:     req.NKeyPub,
		TenantX25519Pub:  result.TenantX25519Pub,
		FleetSigningJWKS: fleetJWKS,
		NatsURLs:         enrollBusURLs(),

		TenantX25519Continuity: result.TenantX25519Continuity,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Errorf("enroll: writing success response: %v", err)
	}
}

// enrollFleetSigningJWKS returns the fleet signing key set as a JWKS
// document, or an error if no key source is configured
// (IMAS_FLEETSIGN_OPENBAO_*) or Transit can't be read.
func enrollFleetSigningJWKS(r *http.Request) (json.RawMessage, error) {
	if fleetKeySource == nil {
		return nil, errors.New("no fleet signing key source configured")
	}
	ks, err := fleetKeySource.KeySet(r.Context())
	if err != nil {
		return nil, err
	}
	return ks.MarshalJWKS()
}

func writeEnrollFailed(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	if err := json.NewEncoder(w).Encode(enrollErrorResponse{Error: "enrollment_failed"}); err != nil {
		log.Errorf("enroll: writing failure response: %v", err)
	}
}

// enrollBusURLs returns the operator-configured externally-reachable
// wss:// bus addresses (config.SproutBusURLs), falling back to a
// single-node URL derived from this farmer's own interface/websocket port
// when none are configured — good enough for local/dev, not a substitute
// for setting SproutBusURLs to the real Envoy-fronted DMZ addresses in
// production.
func enrollBusURLs() []string {
	if len(config.SproutBusURLs) > 0 {
		return config.SproutBusURLs
	}
	return []string{"wss://" + config.FarmerInterface + ":" + config.FarmerWSPort}
}
