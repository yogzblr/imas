package natsapi

// Sealed control-plane requests, farmer's NATS side
// (docs/design/imas-payload-encryption-design.md, "Sealing the control
// plane", J.1 and J.3). FLAG FOR SECURITY REVIEW.
//
// openCLIRequest and sealCLIReply are wired around every imas.api.*
// handler by the sealed router (sealedrouter.go, J.3). The SaaS API pair
// (openSaaSAPIRequest and its seals) waits for rollout step 5 (J.4) to be
// put around internal.*. Owner decisions, 2026-10-04: sealed only, with
// no bearer token fallback and no plaintext fallback; method names stay
// visible in subjects (open question 9); static keys (open question 8);
// the Valkey claim for mutating methods fails closed (open question 7).
//
// What a request must pass, in order, before a handler may run:
//
//  1. It carries the payloadbox.Header marker. A plaintext request is
//     refused (encryption-required), never run.
//  2. It opens (pki.OpenFromCLI / pki.OpenFromSaaSAPI) under the box key
//     registered for the principal its payloadbox.PrincipalHeader names,
//     in this connection's tenant, and its sealed body names exactly the
//     method and subject it arrived on. Otherwise open-failed.
//  3. This replica's replay guard accepts it: fresh (±5 minutes) and not
//     seen before, keyed on (tenant_id, principal, message id).
//     Otherwise open-failed.
//  4. A mutating method (anything not in readOnlyMethods) is also claimed
//     cluster-wide in Valkey (pki.ClaimSealedMessage). Claimed before:
//     open-failed. Valkey unreachable: refused with ErrSealedStoreUnavailable,
//     which the caller answers with a sealed error, since the request did
//     open. A read-only method never touches Valkey: replayed to another
//     replica it runs again, but its reply is sealed to the requester.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/maphash"
	"strings"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// MethodAuthRotateKey is a CLI user's box key rotation
// (c2f.userkey.pub, handleAuthRotateKey); mutating.
const MethodAuthRotateKey = pki.MethodAuthRotateKey

// readOnlyMethods are the imas.api.* methods that change nothing, so a
// sealed request for one needs no cluster-wide claim: the design's
// explicit list, plus recipes.list and recipes.get (owner decision
// 2026-10-04, PR #95: "yes make it readonly"). Every other method counts
// as mutating, the way
// NATSMethodAction defaults to admin, including cohorts.refresh (it
// rewrites the membership cache and is costly), auth.login (not on the
// design's list; harmless, but a list of exceptions should stay the
// design's) and every method added later.
var readOnlyMethods = map[string]bool{
	MethodHealth:          true,
	MethodVersion:         true,
	MethodSproutsList:     true,
	MethodSproutsGet:      true,
	MethodJobsList:        true,
	MethodJobsGet:         true,
	MethodJobsForSprout:   true,
	MethodPropsGetAll:     true,
	MethodPropsGet:        true,
	MethodCohortsList:     true,
	MethodCohortsGet:      true,
	MethodCohortsResolve:  true,
	MethodCohortsValidate: true,
	MethodPKIList:         true,
	MethodAuthWhoAmI:      true,
	MethodAuthListUsers:   true,
	MethodAuthExplain:     true,
	MethodAuditDates:      true,
	MethodAuditQuery:      true,
	MethodRecipesList:     true,
	MethodRecipesGet:      true,
}

// IsMutatingMethod reports whether a sealed request for method must be
// claimed cluster-wide before it runs.
func IsMutatingMethod(method string) bool { return !readOnlyMethods[method] }

// sealedRefusal is a refusal answered with an empty body and the fixed
// payloadbox.ErrorHeader code, so the bus learns nothing it couldn't
// infer from the refusal itself. The reason stays in farmer's log.
type sealedRefusal struct {
	code   string
	reason error
}

func (r *sealedRefusal) Error() string { return r.code + ": " + r.reason.Error() }
func (r *sealedRefusal) Unwrap() error { return r.reason }

func refuse(code string, reason error) error { return &sealedRefusal{code: code, reason: reason} }

// RefusalCode is the payloadbox.ErrorHeader code for err, a sealed
// request helper's error: its own code for a refusal, internal otherwise.
func RefusalCode(err error) string {
	var r *sealedRefusal
	if errors.As(err, &r) {
		return r.code
	}
	return payloadbox.ErrorCodeInternal
}

// ErrSealedStoreUnavailable: a mutating request opened, but its
// cluster-wide claim couldn't be recorded (Valkey unreachable), so it is
// refused: fail closed. The request did open, so the caller answers with
// a sealed error reply, not a header.
var ErrSealedStoreUnavailable = errors.New("natsapi: the replay store is unavailable; mutating requests are refused until it is back")

// apiGuardShards spreads one replica's replay guard over independent
// payloadbox.ReplayGuards. ReplayGuard sweeps its whole map on every
// accept and holds one lock; sharding bounds both for a replica serving
// many users.
const apiGuardShards = 64

// apiGuardShardEntries is each shard's capacity: 64 x 16384 = 1M
// requests inside one 5-minute window per replica, about 3500 a second.
// A full shard refuses (ReplayGuard never forgets an unexpired ID).
const apiGuardShardEntries = 1 << 14

// apiReplayGuard is one replica's in-memory replay guard for sealed
// control-plane requests, keyed on (tenant_id, principal, message id):
// a message ID is the sender's random choice, unique per sender, and the
// tenant-safety rule keys everything on the tenant.
type apiReplayGuard struct {
	seed   maphash.Seed
	shards [apiGuardShards]*payloadbox.ReplayGuard
}

func newAPIReplayGuard() *apiReplayGuard {
	g := &apiReplayGuard{seed: maphash.MakeSeed()}
	for i := range g.shards {
		g.shards[i] = &payloadbox.ReplayGuard{MaxSkew: payloadbox.DefaultMaxSkew, MaxEntries: apiGuardShardEntries}
	}
	return g
}

// Accept records msg once for (tenantID, principal); payloadbox.ErrStale,
// ErrReplayed or ErrReplayGuardFull otherwise.
func (g *apiReplayGuard) Accept(tenantID, principal string, msg *payloadbox.Message) error {
	// Length-prefixed, so no two (tenant, principal, id) triples share a
	// key.
	var b strings.Builder
	for _, s := range []string{tenantID, principal, msg.ID} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(s)))
		b.Write(n[:])
		b.WriteString(s)
	}
	key := b.String()
	keyed := *msg
	keyed.ID = key
	return g.shards[maphash.String(g.seed, key)%apiGuardShards].Accept(&keyed)
}

// sealedAPI is one replica's state for sealed requests: its replay guard
// and the cluster-wide claim (pki.ClaimSealedMessage; a field so tests
// can stand up two replicas).
type sealedAPI struct {
	guard *apiReplayGuard
	claim func(ctx context.Context, tenantID, principal, msgID string) error
}

func newSealedAPI() *sealedAPI {
	return &sealedAPI{guard: newAPIReplayGuard(), claim: pki.ClaimSealedMessage}
}

// replicaSealedAPI is this process's: one per farmer replica.
var replicaSealedAPI = newSealedAPI()

// sealedRequest is a sealed request that passed every check above, and
// what its reply must be bound to.
type sealedRequest struct {
	TenantID  string // the connection's tenant, or payloadbox.PlatformTenantID
	Principal string // the user's NKey public key, or payloadbox.PrincipalSaaSAPI
	Purpose   string
	Method    string
	Subject   string
	ID        string
	Params    json.RawMessage
	// SealedUnder is the CLI box key the request opened under (a key
	// rotation needs it). Empty for the SaaS API.
	SealedUnder string
}

// accept runs the replay checks (steps 3 and 4) on an opened request.
func (s *sealedAPI) accept(ctx context.Context, req *sealedRequest, msg *payloadbox.Message, mutating bool) error {
	if err := s.guard.Accept(req.TenantID, req.Principal, msg); err != nil {
		return refuse(payloadbox.ErrorCodeOpenFailed, err)
	}
	if !mutating {
		return nil
	}
	err := s.claim(ctx, req.TenantID, req.Principal, msg.ID)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, pki.ErrSealedReplayed):
		return refuse(payloadbox.ErrorCodeOpenFailed, err)
	default:
		return fmt.Errorf("%w: %w", ErrSealedStoreUnavailable, err)
	}
}

// openCLIRequest checks m, a request on imas.api.<method> on tenantID's
// connection, and returns it opened. A *sealedRefusal (RefusalCode) is
// answered with its header code; ErrSealedStoreUnavailable, which comes
// with the opened request, with a sealed error (sealCLIReply); anything
// else with the internal code.
func (s *sealedAPI) openCLIRequest(ctx context.Context, tenantID string, m *nats.Msg) (*sealedRequest, error) {
	if m.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
		return nil, refuse(payloadbox.ErrorCodeEncryptionRequired, errors.New("plaintext request"))
	}
	method, ok := strings.CutPrefix(m.Subject, SubjectPrefix)
	if !ok || method == "" {
		return nil, refuse(payloadbox.ErrorCodeOpenFailed, fmt.Errorf("not an API subject: %s", m.Subject))
	}
	principal := m.Header.Get(payloadbox.PrincipalHeader)
	if !nkeys.IsValidPublicAccountKey(principal) {
		return nil, refuse(payloadbox.ErrorCodeOpenFailed, errors.New("no valid principal header"))
	}
	purpose := payloadbox.PurposeCLIRequest
	if method == MethodAuthRotateKey {
		purpose = payloadbox.PurposeCLIUserKeySubmit
	}
	msg, body, sealedUnder, err := pki.OpenFromCLI(tenantID, principal, purpose, method, m.Subject, m.Data)
	if err != nil {
		if errors.Is(err, payloadbox.ErrOpen) {
			return nil, refuse(payloadbox.ErrorCodeOpenFailed, err)
		}
		return nil, err
	}
	req := &sealedRequest{
		TenantID: tenantID, Principal: principal, Purpose: purpose, Method: method, Subject: m.Subject,
		ID: msg.ID, Params: body.Params, SealedUnder: sealedUnder,
	}
	if err := s.accept(ctx, req, msg, IsMutatingMethod(method)); err != nil {
		if errors.Is(err, ErrSealedStoreUnavailable) {
			// It opened: the caller answers with a sealed error.
			return req, err
		}
		return nil, err
	}
	return req, nil
}

// sealCLIReply seals the reply to req: result, or handlerErr's text,
// inside the box (f2c.api, bound to req's ID, method and subject), to the
// user's active CLI box key, one copy per tenant key.
func sealCLIReply(req *sealedRequest, result any, handlerErr error) ([]byte, error) {
	r := payloadbox.Reply{
		Purpose: payloadbox.PurposeCLIReply, ReplyTo: req.ID, Method: req.Method, Subject: req.Subject, Result: result,
	}
	if handlerErr != nil {
		r.Result, r.Error = nil, handlerErr.Error()
	}
	return pki.SealToCLI(req.TenantID, req.Principal, r)
}

// saasapiPurposes maps an internal.* request subject to its purpose.
var saasapiPurposes = map[string]string{
	controlplane.SubjectTenantProvision:   payloadbox.PurposeSaaSTenantProvision,
	controlplane.SubjectTenantDeprovision: payloadbox.PurposeSaaSTenantDeprovision,
	controlplane.SubjectSproutAction:      payloadbox.PurposeSaaSSproutAction,
}

// saasapiSubjectPrefix is the prefix of every SaaS API subject.
const saasapiSubjectPrefix = "internal."

// openSaaSAPIRequest checks m, a SaaS API request on one of
// saasapiPurposes' subjects, and returns it opened. All three are
// mutating, so each is claimed cluster-wide. Errors as openCLIRequest's.
func (s *sealedAPI) openSaaSAPIRequest(ctx context.Context, m *nats.Msg) (*sealedRequest, error) {
	if m.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
		return nil, refuse(payloadbox.ErrorCodeEncryptionRequired, errors.New("plaintext request"))
	}
	purpose, ok := saasapiPurposes[m.Subject]
	if !ok {
		return nil, refuse(payloadbox.ErrorCodeOpenFailed, fmt.Errorf("not a SaaS API request subject: %s", m.Subject))
	}
	if m.Header.Get(payloadbox.PrincipalHeader) != payloadbox.PrincipalSaaSAPI {
		return nil, refuse(payloadbox.ErrorCodeOpenFailed, errors.New("principal header is not the SaaS API"))
	}
	method := strings.TrimPrefix(m.Subject, saasapiSubjectPrefix)
	msg, body, err := pki.OpenFromSaaSAPI(purpose, method, m.Subject, m.Data)
	if err != nil {
		if errors.Is(err, payloadbox.ErrOpen) {
			return nil, refuse(payloadbox.ErrorCodeOpenFailed, err)
		}
		if errors.Is(err, pki.ErrPlatformBoxNotProvisioned) {
			return nil, refuse(payloadbox.ErrorCodeNoKeys, err)
		}
		return nil, err
	}
	req := &sealedRequest{
		TenantID: payloadbox.PlatformTenantID, Principal: payloadbox.PrincipalSaaSAPI, Purpose: purpose,
		Method: method, Subject: m.Subject, ID: msg.ID, Params: body.Params,
	}
	if err := s.accept(ctx, req, msg, true); err != nil {
		return nil, err
	}
	return req, nil
}

// sealSaaSAPIReply seals farmer's reply to an internal.sprout.action
// request (f2a.sprout.action).
func sealSaaSAPIReply(req *sealedRequest, result any, handlerErr error) ([]byte, error) {
	r := payloadbox.Reply{
		Purpose: payloadbox.PurposeSaaSSproutActionReply, ReplyTo: req.ID, Method: req.Method, Subject: req.Subject, Result: result,
	}
	if handlerErr != nil {
		r.Result, r.Error = nil, handlerErr.Error()
	}
	return pki.SealReplyToSaaSAPI(r)
}

// sealSaaSAPIResult seals an asynchronous provisioning result for jobID:
// f2a.tenant.provisioned on internal.tenant.provisioned.<job_id>, or the
// deprovisioned pair, bound to that subject so it can't be moved to
// another job's. It returns the subject to publish on and the envelope.
func sealSaaSAPIResult(deprovision bool, jobID string, result any) (subject string, data []byte, err error) {
	purpose, prefix := payloadbox.PurposeSaaSTenantProvisioned, controlplane.SubjectTenantProvisionedPrefix
	if deprovision {
		purpose, prefix = payloadbox.PurposeSaaSTenantDeprovisioned, controlplane.SubjectTenantDeprovisionedPrefix
	}
	if jobID == "" || strings.ContainsAny(jobID, ".*> \t") {
		return "", nil, fmt.Errorf("natsapi: invalid job id %q", jobID)
	}
	subject = prefix + jobID
	method := strings.TrimSuffix(strings.TrimPrefix(prefix, saasapiSubjectPrefix), ".")
	data, _, err = pki.SealResultToSaaSAPI(payloadbox.Call{Purpose: purpose, Method: method, Subject: subject, Params: result})
	return subject, data, err
}

// respondSealedRefusal answers m with err's fixed code and no body.
func respondSealedRefusal(m *nats.Msg, err error) error {
	if m.Reply == "" {
		return nil
	}
	resp := nats.NewMsg(m.Reply)
	resp.Header.Set(payloadbox.ErrorHeader, RefusalCode(err))
	return m.RespondMsg(resp)
}

// respondSealed answers m with a sealed reply.
func respondSealed(m *nats.Msg, data []byte) error {
	if m.Reply == "" {
		return nil
	}
	resp := nats.NewMsg(m.Reply)
	resp.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	resp.Data = data
	return m.RespondMsg(resp)
}
