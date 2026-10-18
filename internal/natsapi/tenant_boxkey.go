package natsapi

// Farmer's half of internal.tenant.boxkey: the SaaS API asks for a
// tenant's current box public key when it mints a join token, and puts
// the key's fingerprint in the token (internal/jointoken; security review
// 2026-10, L24). A sprout checks the tenant key its first enrollment
// response names against that fingerprint before pinning it, so a DMZ
// Envoy that substitutes its own key is caught.
//
// FLAG FOR SECURITY REVIEW. The request is a sealed a2f.tenant.boxkey
// Call from the SaaS API (openSaaSAPIRequest: sealed, bound to this
// subject, fresh, accepted once cluster-wide), answered only on a SaaS
// API inbox (controlplane.ValidSaaSAPIReplySubject) with a sealed
// f2a.tenant.boxkey Reply bound to the request's ID. A forged reply can't
// open at the SaaS API, so a compromised bus can't put its own key's
// fingerprint into a token. The answer is a public key; nothing secret
// leaves farmer.

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/controlplane"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/pki"
)

// tenantBoxKeyForToken is pki.TenantX25519PublicKeyForJoinToken, swappable
// in handler tests.
var tenantBoxKeyForToken = pki.TenantX25519PublicKeyForJoinToken

// registerTenantBoxKey queue-subscribes nc to internal.tenant.boxkey in
// natsCoreQueueGroup, so one farmer replica answers each request.
// registerSproutAction, called after it on the same connection, flushes.
func registerTenantBoxKey(nc *nats.Conn, s *sealedAPI) error {
	if _, err := nc.QueueSubscribe(controlplane.SubjectTenantBoxKey, natsCoreQueueGroup, func(msg *nats.Msg) {
		// As internal.sprout.action: no valid SaaS API inbox, no answer
		// and nothing done.
		if !controlplane.ValidSaaSAPIReplySubject(msg.Reply) {
			log.Errorf("natsapi: dropping %s request with a reply subject outside %s: %q", controlplane.SubjectTenantBoxKey, controlplane.SaaSAPIInboxWildcard, msg.Reply)
			return
		}
		sreq := s.openSaaSAPIRequestOrRefuse(msg, true)
		if sreq == nil {
			return
		}
		respondTenantBoxKey(msg, sreq, handleTenantBoxKey(sreq.Params))
	}); err != nil {
		return fmt.Errorf("natsapi: failed to subscribe to %s: %w", controlplane.SubjectTenantBoxKey, err)
	}
	return nil
}

// handleTenantBoxKey answers one opened internal.tenant.boxkey request.
// A failure carries only a fixed ErrorCode; the error is logged here.
func handleTenantBoxKey(data []byte) controlplane.TenantBoxKeyReply {
	var req controlplane.TenantBoxKeyRequest
	if err := json.Unmarshal(data, &req); err != nil {
		log.Errorf("natsapi: malformed %s request: %v", controlplane.SubjectTenantBoxKey, err)
		return controlplane.TenantBoxKeyReply{ErrorCode: controlplane.ErrorInvalidRequest}
	}
	reply := controlplane.TenantBoxKeyReply{TenantID: req.TenantID}
	pub, err := tenantBoxKeyForToken(req.TenantID)
	if err != nil {
		log.Errorf("natsapi: %s for tenant %q: %v", controlplane.SubjectTenantBoxKey, req.TenantID, err)
		switch {
		case errors.Is(err, pki.ErrTenantIDInvalid):
			reply.ErrorCode = controlplane.ErrorInvalidTenantID
		case errors.Is(err, pki.ErrTenantDeprovisioned):
			reply.ErrorCode = controlplane.ErrorTenantNotFound
		default:
			reply.ErrorCode = controlplane.ErrorInternal
		}
		return reply
	}
	reply.TenantX25519Pub = pub
	return reply
}

// respondTenantBoxKey answers msg, the opened request req, with reply
// sealed to the SaaS API. A reply that can't be sealed is answered with
// the internal code and no body, never in plaintext.
func respondTenantBoxKey(msg *nats.Msg, req *sealedRequest, reply controlplane.TenantBoxKeyReply) {
	data, err := sealSaaSAPIReply(req, reply, nil)
	if err != nil {
		log.Errorf("natsapi: sealing the %s reply (message %s): %v", controlplane.SubjectTenantBoxKey, req.ID, err)
		if rerr := respondSealedRefusal(msg, err); rerr != nil {
			log.Errorf("natsapi: responding to %s: %v", controlplane.SubjectTenantBoxKey, rerr)
		}
		return
	}
	if err := respondSealed(msg, data); err != nil {
		log.Errorf("natsapi: responding to %s: %v", controlplane.SubjectTenantBoxKey, err)
	}
}
