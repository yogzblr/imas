package natsapi

// The sealed router: every imas.api.* request goes through serve, the one
// place that opens it, decides who sent it, authorizes, runs, audits and
// seals the reply (docs/design/imas-payload-encryption-design.md,
// Decision A, J.3). FLAG FOR SECURITY REVIEW.
//
// Who sent a request is the user whose registered CLI box key it opened
// under (openCLIRequest: the Imas-Principal header names the user, the
// box must open under that user's key, and the sealed sid must equal the
// header). That user ID, and nothing in the params, is what RBAC, scope
// checks, job attribution and the audit log see. There are no bearer
// tokens and no plaintext fallback: a request that doesn't open is
// answered with a fixed Imas-Payload-Error code and an empty body, and
// never reaches a handler.
//
// The one exception is monitoring: an unsealed health or version request
// is answered in plaintext, as before. It carries no identity and changes
// nothing, and the CLI never sends one (it seals every request, and
// refuses a plaintext reply to any).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/audit"
	intauth "github.com/yogzblr/imas/internal/auth"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// apiCaller is who a sealed request is from.
type apiCaller struct {
	// TenantID is the tenant of the connection the request arrived on,
	// the tenant whose box key it was sealed to.
	TenantID string
	// UserID is the user (NKey public key) whose registered CLI box key
	// the request opened under. Empty only on an unsealed health or
	// version request.
	UserID string
	// req is the opened request (nil in handler unit tests).
	req *sealedRequest
}

// sealedRequestTimeout bounds the work done before a handler runs:
// opening (database and OpenBao reads) and the Valkey claim.
const sealedRequestTimeout = 10 * time.Second

// plaintextMonitoringMethods are answered in plaintext when asked in
// plaintext: monitoring, which has no CLI box key. Nothing else is.
var plaintextMonitoringMethods = map[string]bool{
	MethodHealth:  true,
	MethodVersion: true,
}

// serve handles m, a request for method on tenantID's connection, with
// run.
func (s *sealedAPI) serve(tenantID, method string, run userHandler, m *nats.Msg) {
	if plaintextMonitoringMethods[method] && m.Header.Get(payloadbox.Header) == "" {
		servePlaintextMonitoring(tenantID, run, m)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), sealedRequestTimeout)
	req, err := s.openCLIRequest(ctx, tenantID, m)
	cancel()
	switch {
	case err == nil:
	case errors.Is(err, ErrSealedStoreUnavailable) && req != nil:
		// It opened, so the refusal goes back sealed.
		log.Warnf("natsapi: refusing %s from %s: %v", method, req.Principal, err)
		s.reply(m, req, nil, ErrSealedStoreUnavailable)
		return
	default:
		// The reason stays in farmer's log; the bus sees a fixed code.
		log.Warnf("natsapi: refusing a request on %s (tenant %s, principal header %q): %v",
			m.Subject, tenantID, m.Header.Get(payloadbox.PrincipalHeader), err)
		if rerr := respondSealedRefusal(m, err); rerr != nil {
			log.Errorf("natsapi: failed to answer %s: %v", m.Subject, rerr)
		}
		return
	}

	caller := apiCaller{TenantID: tenantID, UserID: req.Principal, req: req}
	var result any
	err = authorize(method, caller, req.Params)
	if err == nil {
		result, err = run(caller, req.Params)
	}
	auditCall(caller, method, req.Params, result, err)
	s.reply(m, req, result, err)
}

// reply seals result (or err's text) back to req's user and answers m.
// A reply that can't be sealed (the user's key went away in between, the
// tenant keys are unreadable) is answered with the internal code: never
// in plaintext.
func (s *sealedAPI) reply(m *nats.Msg, req *sealedRequest, result any, err error) {
	data, sealErr := sealCLIReply(req, result, err)
	if sealErr != nil {
		log.Errorf("natsapi: sealing the reply to %s for %s: %v", req.Method, req.Principal, sealErr)
		if rerr := respondSealedRefusal(m, sealErr); rerr != nil {
			log.Errorf("natsapi: failed to answer %s: %v", m.Subject, rerr)
		}
		return
	}
	if rerr := respondSealed(m, data); rerr != nil {
		log.Errorf("natsapi: failed to respond to %s: %v", m.Subject, rerr)
	}
}

// servePlaintextMonitoring answers an unsealed health or version request
// in plaintext.
func servePlaintextMonitoring(tenantID string, run userHandler, m *nats.Msg) {
	if m.Reply == "" {
		return
	}
	result, err := run(apiCaller{TenantID: tenantID}, nil)
	var resp response
	if err != nil {
		resp.Error = err.Error()
	} else {
		resp.Result = result
	}
	data, marshalErr := json.Marshal(resp)
	if marshalErr != nil {
		data = []byte(fmt.Sprintf(`{"error":"marshal error: %s"}`, marshalErr.Error()))
	}
	if err := m.Respond(data); err != nil {
		log.Errorf("natsapi: failed to respond to %s: %v", m.Subject, err)
	}
}

// announceCLIPin makes Subscribe log, for the users tenant, the tenant box
// public key and tenant ID every CLI pins (tenantboxpub, tenantid): the
// out-of-band channel an operator copies them from, since the CLI never
// fetches them over the bus. Reading the key also creates the tenant's
// keypair if it doesn't exist yet, so the first admin has something to
// pin. Off in this package's tests.
var announceCLIPin = true

// logCLIPin logs the pin for tenantID (see announceCLIPin).
func logCLIPin(tenantID string) {
	pub, err := pki.GetTenantX25519PublicKey(tenantID)
	if err != nil {
		log.Warnf("natsapi: can't read tenant %s's box key for CLI users to pin: %v", tenantID, err)
		return
	}
	fp := ""
	if k, err := intauth.DecodeCLIBoxPub(pub); err == nil {
		fp = payloadbox.Fingerprint(k)
	}
	log.Noticef("natsapi: imas CLI users pin tenantid=%s tenantboxpub=%s (%s) in their CLI config; copy them out of band", tenantID, pub, fp)
}

// auditCall records method as called by c, the verified user, at the
// configured audit level. For a write, params are recorded too (they hold
// no credential: there is none to redact any more).
func auditCall(c apiCaller, method string, params json.RawMessage, result any, err error) {
	if !audit.ShouldLog(method) {
		return
	}
	logger := audit.Global()
	if logger == nil {
		return
	}
	roleName, username := intauth.UserIdentity(c.UserID)
	entry := audit.Entry{
		Timestamp: time.Now().UTC(),
		Username:  username,
		Pubkey:    c.UserID,
		RoleName:  roleName,
		Action:    method,
		Success:   err == nil,
	}
	if err != nil {
		entry.Error = err.Error()
	}
	if extractor := scopeExtractors[method]; extractor != nil {
		if ids, xerr := extractor(params); xerr == nil {
			entry.Targets = ids
		}
	}
	if !audit.IsReadOnly(method) && len(params) > 0 && json.Valid(params) {
		entry.Parameters = params
	}
	if lerr := logger.Log(entry); lerr != nil {
		log.Errorf("natsapi: audit log failed for %s: %v", method, lerr)
	}
}
