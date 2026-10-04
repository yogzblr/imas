package handlers

// POST /v1/refresh: gateway JWT refresh for an already-enrolled sprout
// (docs/design/imas-envoy-enrollment-design.md, "Gateway JWT refresh").
// FLAG FOR SECURITY REVIEW — see internal/pki/refresh.go.
//
// Not wrapped in Auth, and not jwt_authn-gated at Envoy: the sprout may be
// calling precisely because its gateway JWT has expired (it was powered
// off for longer than the TTL). The authentication is the NKey proof of
// possession pki.RefreshSprout verifies. Envoy gives this route its own
// rate-limit bucket, separate from /v1/enroll's (deploy/envoy).

import (
	"encoding/json"
	"net/http"

	log "github.com/yogzblr/imas/internal/log"

	"github.com/yogzblr/imas/internal/pki"
)

// refreshRequest has no join_token field by design: refresh can only
// re-issue an existing identity, never create one.
type refreshRequest struct {
	NKeyPub   string `json:"nkey_pub"`
	Timestamp int64  `json:"timestamp"`
	NKeySig   string `json:"nkey_sig"`
}

// refreshSuccessResponse carries what a refresh can change. jwt is the
// sprout's existing NATS User JWT (re-sent so a re-minted one reaches
// it); tenant_x25519_pub is re-sent so the sprout can check it against
// the one it pinned. After a tenant key rotation,
// tenant_x25519_continuity carries pki.TenantKeyContinuity's proof that
// the new key succeeds the one the sprout pinned, which is how a sprout
// re-pins (pki.RefreshGatewayJWT); a sprout that predates it ignores the
// field and exits on the mismatch. tenant_id is the sprout's tenant,
// which the sprout checks against the one it pinned at enrollment and
// exits on a mismatch (security review 2026-10, H3). The fleet signing
// keys and bus URLs are enrollment-only.
type refreshSuccessResponse struct {
	SproutID        string `json:"sprout_id"`
	TenantID        string `json:"tenant_id"`
	JWT             string `json:"jwt"`
	GatewayJWT      string `json:"gateway_jwt"`
	NKeyIdentity    string `json:"nkey_identity"`
	TenantX25519Pub string `json:"tenant_x25519_pub"`

	TenantX25519Continuity json.RawMessage `json:"tenant_x25519_continuity,omitempty"`
}

// Refresh handles POST /v1/refresh. Every failure writes the same generic
// response as Enroll (writeEnrollFailed).
func Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	dec := json.NewDecoder(r.Body)
	// A join_token (or any other field) here means a client is using the
	// wrong contract; refuse rather than silently ignore it.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		log.Warnf("refresh: invalid request body: %v", err)
		writeEnrollFailed(w)
		return
	}
	if req.NKeyPub == "" || req.Timestamp == 0 || req.NKeySig == "" {
		log.Warnf("refresh: request missing a required field")
		writeEnrollFailed(w)
		return
	}
	result, err := pki.RefreshSprout(r.Context(), pki.RefreshRequest{
		NKeyPub:   req.NKeyPub,
		Timestamp: req.Timestamp,
		NKeySig:   req.NKeySig,
	})
	if err != nil {
		writeEnrollFailed(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(refreshSuccessResponse{
		SproutID:        result.SproutID,
		TenantID:        result.TenantID,
		JWT:             result.JWT,
		GatewayJWT:      result.GatewayJWT,
		NKeyIdentity:    req.NKeyPub,
		TenantX25519Pub: result.TenantX25519Pub,

		TenantX25519Continuity: result.TenantX25519Continuity,
	}); err != nil {
		log.Errorf("refresh: writing success response: %v", err)
	}
}
