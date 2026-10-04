package handlers

// POST /v1/refresh: gateway JWT refresh for an already-enrolled sprout
// (docs/design/imas-envoy-enrollment-design.md, "Gateway JWT refresh";
// docs/design/imas-payload-encryption-design.md, Decision C). FLAG FOR
// SECURITY REVIEW — see internal/pki/refreshsealed.go.
//
// Not wrapped in Auth, and not jwt_authn-gated at Envoy: the sprout may be
// calling precisely because its gateway JWT has expired (it was powered
// off for longer than the TTL). The authentication is the sealed request
// pki.RefreshSprout opens with the sprout's box key, and the answer is
// sealed back to that key, so nothing in this exchange, at Envoy or
// anywhere else in the DMZ, carries a usable gateway JWT. The NKey-signed
// proof this endpoint used to accept is refused: its fields are unknown
// to this contract. Envoy gives this route its own rate-limit bucket,
// separate from /v1/enroll's (deploy/envoy).

import (
	"encoding/json"
	"net/http"

	log "github.com/yogzblr/imas/internal/log"

	"github.com/yogzblr/imas/internal/pki"
)

// maxRefreshRequestBytes caps a /v1/refresh body. A real one is a sealed
// envelope of one or two copies, well under 4 KiB.
const maxRefreshRequestBytes = 64 << 10

// refreshRequest has no join_token field by design: refresh can only
// re-issue an existing identity, never create one. It has no nkey_sig or
// timestamp either: an NKey signature can be obtained by a compromised bus
// (it signs the CONNECT nonce too), so it proves nothing here. sealed is
// the sprout's s2f.refresh payloadbox envelope (pki.SproutSealedRefresh).
type refreshRequest struct {
	NKeyPub string          `json:"nkey_pub"`
	Sealed  json.RawMessage `json:"sealed"`
}

// refreshSuccessResponse is farmer's sealed reply (purpose f2s.refresh,
// bound to the request's message ID) and nothing else. Its result,
// pki.RefreshResponse, carries what a refresh can change: the gateway JWT;
// the sprout's existing NATS User JWT (re-sent so a re-minted one reaches
// it); tenant_id and tenant_x25519_pub, which the sprout checks against
// its pins; and, after a tenant key rotation, tenant_x25519_continuity,
// pki.TenantKeyContinuity's proof that the new key succeeds the one the
// sprout pinned, which is how a sprout re-pins (pki.RefreshGatewayJWT).
// The fleet signing keys and bus URLs are enrollment-only.
type refreshSuccessResponse struct {
	Sealed json.RawMessage `json:"sealed"`
}

// Refresh handles POST /v1/refresh. Every failure writes the same generic
// response as Enroll (writeEnrollFailed).
func Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRefreshRequestBytes))
	// A join_token, an nkey_sig (the old NKey-signed contract), or any
	// other field here means a client is using the wrong contract; refuse
	// rather than silently ignore it.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		log.Warnf("refresh: invalid request body: %v", err)
		writeEnrollFailed(w)
		return
	}
	if req.NKeyPub == "" || len(req.Sealed) == 0 || string(req.Sealed) == "null" {
		log.Warnf("refresh: request missing a required field")
		writeEnrollFailed(w)
		return
	}
	sealed, err := pki.RefreshSprout(r.Context(), pki.RefreshRequest{NKeyPub: req.NKeyPub, Sealed: req.Sealed})
	if err != nil {
		writeEnrollFailed(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(refreshSuccessResponse{Sealed: sealed}); err != nil {
		log.Errorf("refresh: writing success response: %v", err)
	}
}
