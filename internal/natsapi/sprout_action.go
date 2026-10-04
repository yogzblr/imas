package natsapi

// Farmer's half of internal.sprout.action
// (cloudxp-machine-manager-api-design.md §2.2): the SaaS API asks farmer
// to run one cmd.run or cook on one already-resolved sprout, and farmer
// replies on the request's inbox.
//
// FLAG FOR SECURITY REVIEW. Like internal.tenant.*, this is a
// platform-level control-plane subject in the SYS Account, registered
// once per farmer process on its SYS listener connection — see
// tenant_provision.go and docs/design/imas-internal-api-account.md. Unlike
// internal.tenant.*, a request here reaches into one tenant's fleet on the
// SaaS API's say-so, so two checks run before anything executes:
//
//  1. The reply subject must be one of the SaaS API's own scoped inboxes
//     (controlplane.ValidSaaSAPIReplySubject). Farmer replies from its SYS
//     user, which has no permission restrictions, and NATS doesn't check
//     the reply subject a publisher sets — so an unchecked reply subject
//     would let the SaaS API credential have farmer publish anywhere.
//  2. The point-of-effect tenant check (pki.VerifySproutInTenant): the
//     sprout's own stored tenant_id must equal the request's asserted
//     tenant_id, the sprout must be accepted, and the tenant must be live.
//     The asserted tenant_id is never trusted on its own — this holds even
//     if the SaaS API's asset -> sprout resolution is wrong.
//
// Once both pass, the action goes through the same handleCmdRun/
// handleCook the tenant-facing imas.api.cmd.run/cook subjects use, bound
// to the verified tenant, so it travels over that tenant's own NATS
// connection (its own Account) to the sprout — never any other tenant's.
//
// self_update (design doc §1.8, §2.3, §2.5) adds a third check before
// dispatch (checkSelfUpdateRelease): the request names only a version,
// and farmer re-verifies it against the release catalog it reads
// read-only (internal/fleetcatalog). The version must be the sprout's
// tenant's approved_version, registered and not revoked, and every row of
// it must verify against the imas-fleet-signing public key farmer reads
// from OpenBao Transit with its READ-ONLY token (SetFleetKeySource). The
// SaaS API checked it too, but it can also write saas.fleet_versions, so
// farmer doesn't take its word for it. A version that passes goes to the
// sprout as a one-step cook job (the selfupdate ingredient) carrying only
// the version, over the same tenant connection; the sprout fetches its
// own signed row from farmer and verifies it again, against the keyring
// shipped in its package.
//
// Security review 2026-10 (SEC.5) added, for self_update: farmer's own
// switch, IMAS_SELF_UPDATE_ENABLED (default false; L1), checked before
// anything else, so a forged or replayed internal.sprout.action can't
// install anything while saasapi's dispatch flag is off; and the tenant's
// rollout window, enforced here as well as in saasapi. And, for every
// action (M5): per-tenant concurrency caps well below the pool size, a
// pool reserved for self_update so cmd.run and cook can't starve a
// rollout, and a refusal (farmer_busy) instead of a blocked subscription
// callback when a cap or pool is full (sproutActionLimiter).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"golang.org/x/mod/semver"

	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/fleetcatalog"
	"github.com/yogzblr/imas/internal/fleetsign"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/pki"
)

// verifySproutInTenant, dispatchCmdRun, dispatchCook and triggerCook are
// indirections so handler-level unit tests can stub the pki check and the
// dispatch. Production code always runs the real functions.
var (
	verifySproutInTenant = pki.VerifySproutInTenant
	dispatchCmdRun       = handleCmdRun
	dispatchCook         = handleCook
	triggerCook          = triggerCookOnTenantConn
	dispatchSelfUpdate   = sendSelfUpdate
)

// fleetKeys is the imas-fleet-signing public key source self_update
// verifies releases against, set once at startup by SetFleetKeySource
// (cmd/farmer). While it's nil every self_update is refused.
var fleetKeys fleetsign.KeySetSource

// SetFleetKeySource installs the read-only key source self_update
// verifies release signatures against.
func SetFleetKeySource(src fleetsign.KeySetSource) { fleetKeys = src }

// selfUpdateVerifyTimeout bounds the catalog and Transit key reads behind
// a self_update check (keys normally served from the source's cache).
const selfUpdateVerifyTimeout = 15 * time.Second

const auditActionSproutAction = controlplane.SubjectSproutAction

// Farmer-side self_update switch (security review L1).
const (
	// EnvSelfUpdateEnabled turns self_update on in farmer. Default false:
	// with it off every self_update is refused (self_update_disabled)
	// before the catalog, the tenant or the sprout is even looked at. It
	// is farmer's own switch, independent of saasapi's
	// SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED, so a request forged or
	// replayed on the bus can't start an update saasapi's flag would not.
	// Read once, when RegisterSproutAction is called; a value
	// strconv.ParseBool doesn't accept is logged and leaves it off.
	EnvSelfUpdateEnabled = "IMAS_SELF_UPDATE_ENABLED"
)

// selfUpdateEnabled is EnvSelfUpdateEnabled's value.
var selfUpdateEnabled atomic.Bool

// selfUpdateEnabledFromEnv reads EnvSelfUpdateEnabled, failing closed.
func selfUpdateEnabledFromEnv() bool {
	raw := strings.TrimSpace(os.Getenv(EnvSelfUpdateEnabled))
	if raw == "" {
		return false
	}
	on, err := strconv.ParseBool(raw)
	if err != nil {
		log.Errorf("natsapi: %s=%q is not a boolean; self_update stays disabled", EnvSelfUpdateEnabled, raw)
		return false
	}
	return on
}

// Error codes internal.sprout.action replies with in addition to
// controlplane's. saasapi (internal/saasapi, farmerErrorCode) keeps exactly
// these strings; TestSproutActionErrorCodeValues pins them. They belong in
// internal/controlplane, which was outside SEC.5's scope.
const (
	// ErrorSelfUpdateDisabled: IMAS_SELF_UPDATE_ENABLED is off, so the
	// self_update was refused without being looked at.
	ErrorSelfUpdateDisabled controlplane.ErrorCode = "self_update_disabled"
	// ErrorRolloutWindowClosed: now is outside the tenant's rollout
	// window (saas.tenant_update_policy), so the self_update was refused.
	// The same string saasapi records for an item its own window check
	// stopped.
	ErrorRolloutWindowClosed controlplane.ErrorCode = "rollout_window_closed"
	// ErrorFarmerBusy: the tenant's concurrency cap or the action's pool
	// was full, so the request was refused unrun. Nothing was dispatched;
	// it is safe to send again.
	ErrorFarmerBusy controlplane.ErrorCode = "farmer_busy"
)

// Concurrency of internal.sprout.action (security review M5). Each farmer
// process has two pools: one for cmd.run and cook (and anything
// unrecognized, which is refused at once), and one reserved for
// self_update, so a tenant posting long cmd.runs can't hold the slots a
// rollout wave needs. Within each pool one tenant may hold at most
// EnvSproutActionTenantConcurrency slots. A request that finds its
// tenant's cap or its pool full is refused at once with farmer_busy: the
// subscription callback never blocks, so nothing queues behind a full pool
// until saasapi's reply timeout turns it into dispatch_outcome_unknown.
// All three are read once, when RegisterSproutAction is called. A value
// that isn't a positive integer is logged and the default used; a value
// above maxSproutActionConcurrency is clamped.
const (
	// EnvSproutActionConcurrency is the cmd.run/cook pool's size.
	EnvSproutActionConcurrency = "IMAS_SPROUT_ACTION_CONCURRENCY"
	// EnvSelfUpdateConcurrency is the self_update pool's size.
	EnvSelfUpdateConcurrency = "IMAS_SELF_UPDATE_CONCURRENCY"
	// EnvSproutActionTenantConcurrency is one tenant's cap in each pool.
	EnvSproutActionTenantConcurrency = "IMAS_SPROUT_ACTION_TENANT_CONCURRENCY"
)

// Defaults and bounds. A cmd.run holds its slot until the sprout answers
// (up to its timeout); a self_update only until it is dispatched. The
// defaults match saasapi's (internal/saasapi, dispatchLimits), so one
// saasapi replica alone never sends more than one farmer replica admits.
// The ceiling keeps a typo from turning into an unbounded goroutine count
// on a privileged surface.
const (
	defaultSproutActionConcurrency       = 64
	defaultSelfUpdateConcurrency         = 16
	defaultSproutActionTenantConcurrency = 8
	maxSproutActionConcurrency           = 1024
)

// envConcurrency returns name's value, or def if it's unset or not a
// positive integer, clamped to maxSproutActionConcurrency.
func envConcurrency(name string, def int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		log.Warnf("natsapi: ignoring %s=%q (want a positive integer); using %d", name, raw, def)
		return def
	}
	if n > maxSproutActionConcurrency {
		log.Warnf("natsapi: %s=%d exceeds the maximum; using %d", name, n, maxSproutActionConcurrency)
		return maxSproutActionConcurrency
	}
	return n
}

// sproutActionConcurrency is the cmd.run/cook pool's size.
func sproutActionConcurrency() int {
	return envConcurrency(EnvSproutActionConcurrency, defaultSproutActionConcurrency)
}

// sproutActionLimiter admits internal.sprout.action requests without ever
// blocking: tryAcquire either takes a slot in the request's pool, counted
// against its tenant, or says why it can't. Tenants are counted by the
// request's asserted tenant_id (the point-of-effect check comes later,
// inside the slot); the pool size bounds the total regardless.
type sproutActionLimiter struct {
	mu        sync.Mutex
	tenantCap int
	pools     map[bool]*actionPool // keyed by "is self_update"
}

type actionPool struct {
	size, used int
	byTenant   map[string]int
}

func newSproutActionLimiter(general, selfUpdate, tenantCap int) *sproutActionLimiter {
	return &sproutActionLimiter{tenantCap: tenantCap, pools: map[bool]*actionPool{
		false: {size: general, byTenant: map[string]int{}},
		true:  {size: selfUpdate, byTenant: map[string]int{}},
	}}
}

// tryAcquire takes a slot for a request of actionType from tenantID. It
// returns the release func, or "" and the reason it refused.
func (l *sproutActionLimiter) tryAcquire(tenantID, actionType string) (func(), string) {
	selfUpdate := actionType == controlplane.ActionSelfUpdate
	l.mu.Lock()
	defer l.mu.Unlock()
	p := l.pools[selfUpdate]
	switch {
	case p.byTenant[tenantID] >= l.tenantCap:
		return nil, fmt.Sprintf("tenant %q already has %d %s in flight (cap %d)", tenantID, p.byTenant[tenantID], poolName(selfUpdate), l.tenantCap)
	case p.used >= p.size:
		return nil, fmt.Sprintf("the %s pool is full (%d)", poolName(selfUpdate), p.size)
	}
	p.used++
	p.byTenant[tenantID]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			p.used--
			if p.byTenant[tenantID]--; p.byTenant[tenantID] <= 0 {
				delete(p.byTenant, tenantID)
			}
		})
	}, ""
}

func poolName(selfUpdate bool) string {
	if selfUpdate {
		return "self_update"
	}
	return "cmd.run/cook"
}

// maxSproutActionCmdTimeout caps a cmd.run's own timeout. The handler
// waits for the sprout for 15s plus this long, holding a concurrency slot
// the whole time; the SaaS API's request timeout has to exceed it too.
const maxSproutActionCmdTimeout = 10 * time.Minute

// cookTriggerTimeout matches the window handleCook's goroutine waits for
// its trigger.
const cookTriggerTimeout = 15 * time.Second

// errSproutActionInvalid marks a request farmer rejects as malformed
// before dispatching it.
var errSproutActionInvalid = errors.New("invalid internal.sprout.action request")

// RegisterSproutAction queue-subscribes nc — farmer's SYS listener
// connection — to internal.sprout.action, in the same natsCoreQueueGroup
// as everything else, so exactly one farmer replica handles each request.
// Call once per process, not once per tenant. RegisterTenantProvisioning
// calls it, so it is registered wherever the tenant subjects are. It
// returns only once the server has the subscription.
//
// It reads EnvSelfUpdateEnabled and the concurrency settings
// (sproutActionLimiter) once, here.
func RegisterSproutAction(nc *nats.Conn) error {
	selfUpdateEnabled.Store(selfUpdateEnabledFromEnv())
	general := sproutActionConcurrency()
	reserved := envConcurrency(EnvSelfUpdateConcurrency, defaultSelfUpdateConcurrency)
	tenantCap := envConcurrency(EnvSproutActionTenantConcurrency, defaultSproutActionTenantConcurrency)
	limiter := newSproutActionLimiter(general, reserved, tenantCap)
	if _, err := nc.QueueSubscribe(controlplane.SubjectSproutAction, natsCoreQueueGroup, func(msg *nats.Msg) {
		// Checked before decoding or doing anything else: a request with
		// no valid SaaS API inbox is dropped, not executed and not
		// answered. The contract is request-reply, so there's no one to
		// tell, and running it anyway would be an effect nobody sees.
		if !controlplane.ValidSaaSAPIReplySubject(msg.Reply) {
			log.Errorf("natsapi: dropping %s request with a reply subject outside %s: %q", controlplane.SubjectSproutAction, controlplane.SaaSAPIInboxWildcard, msg.Reply)
			return
		}
		var req controlplane.SproutActionRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			// Refused without dispatching anything: answered here.
			respondSproutAction(msg, handleSproutAction(msg.Data))
			return
		}
		// Never blocks: a full cap or pool is a refusal, answered here.
		release, refused := limiter.tryAcquire(req.TenantID, req.Action.Type)
		if refused != "" {
			respondSproutAction(msg, refuseBusy(req, msg.Data, refused))
			return
		}
		go func() {
			defer release()
			respondSproutAction(msg, handleSproutActionRequest(req, msg.Data))
		}()
	}); err != nil {
		return fmt.Errorf("natsapi: failed to subscribe to %s: %w", controlplane.SubjectSproutAction, err)
	}
	// Subscribe only buffers the SUB; Flush waits for the server to
	// acknowledge it, so the handler is live once this returns. Without
	// it, a request sent right after on another connection (the SaaS
	// API's) can reach the server first and get "no responders". This
	// also covers RegisterTenantProvisioning's subscriptions, made
	// earlier on the same connection.
	if err := nc.Flush(); err != nil {
		return fmt.Errorf("natsapi: failed to confirm subscription to %s: %w", controlplane.SubjectSproutAction, err)
	}
	log.Infof("natsapi: registered sprout action handler (SYS account; cmd.run/cook pool %d, self_update pool %d, per-tenant cap %d; self_update %s)",
		general, reserved, tenantCap, map[bool]string{true: "enabled", false: "disabled (" + EnvSelfUpdateEnabled + ")"}[selfUpdateEnabled.Load()])
	return nil
}

func respondSproutAction(msg *nats.Msg, reply controlplane.SproutActionReply) {
	data, err := json.Marshal(reply)
	if err != nil {
		log.Errorf("natsapi: marshalling %s reply: %v", controlplane.SubjectSproutAction, err)
		return
	}
	if err := msg.Respond(data); err != nil {
		log.Errorf("natsapi: responding to %s: %v", controlplane.SubjectSproutAction, err)
	}
}

// refuseBusy is the reply to a request sproutActionLimiter refused:
// farmer_busy, with nothing run.
func refuseBusy(req controlplane.SproutActionRequest, data []byte, why string) controlplane.SproutActionReply {
	reply := controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID,
		Status: controlplane.StatusFailed, ErrorCode: ErrorFarmerBusy}
	err := fmt.Errorf("refused unrun: %s", why)
	log.Warnf("natsapi: %s %s on sprout %q (tenant %q): %v", controlplane.SubjectSproutAction, req.Action.Type, req.SproutID, req.TenantID, err)
	auditTenantAction(auditActionSproutAction, data, reply, err)
	return reply
}

// handleSproutAction runs one internal.sprout.action request and returns
// the reply. Failures carry only a fixed controlplane.ErrorCode; the full
// error is logged here.
func handleSproutAction(data []byte) controlplane.SproutActionReply {
	var req controlplane.SproutActionRequest
	if err := json.Unmarshal(data, &req); err != nil {
		log.Errorf("natsapi: malformed %s request: %v", controlplane.SubjectSproutAction, err)
		reply := controlplane.SproutActionReply{Status: controlplane.StatusFailed, ErrorCode: controlplane.ErrorInvalidRequest}
		auditTenantAction(auditActionSproutAction, data, reply, err)
		return reply
	}
	return handleSproutActionRequest(req, data)
}

// handleSproutActionRequest is handleSproutAction for a request already
// decoded from data.
func handleSproutActionRequest(req controlplane.SproutActionRequest, data []byte) controlplane.SproutActionReply {
	reply, err := runSproutAction(req)
	if err != nil {
		log.Errorf("natsapi: %s %s on sprout %q (tenant %q) failed: %v", controlplane.SubjectSproutAction, req.Action.Type, req.SproutID, req.TenantID, err)
	}
	auditTenantAction(auditActionSproutAction, data, reply, err)
	return reply
}

func runSproutAction(req controlplane.SproutActionRequest) (controlplane.SproutActionReply, error) {
	reply := controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID, Status: controlplane.StatusFailed}
	fail := func(code controlplane.ErrorCode, err error) (controlplane.SproutActionReply, error) {
		reply.ErrorCode = code
		return reply, err
	}

	switch req.Action.Type {
	case controlplane.ActionCmdRun, controlplane.ActionCook, controlplane.ActionSelfUpdate:
	default:
		return fail(controlplane.ErrorUnsupportedAction, fmt.Errorf("unsupported action type %q", req.Action.Type))
	}
	// Farmer's own switch, before anything is looked up (L1).
	if req.Action.Type == controlplane.ActionSelfUpdate && !selfUpdateEnabled.Load() {
		return fail(ErrorSelfUpdateDisabled, fmt.Errorf("self_update refused: %s is off", EnvSelfUpdateEnabled))
	}

	// The point-of-effect check. Nothing below runs unless the sprout's
	// own stored tenant is the asserted one.
	if err := verifySproutInTenant(req.TenantID, req.SproutID); err != nil {
		switch {
		case errors.Is(err, pki.ErrTenantIDInvalid), errors.Is(err, pki.ErrSproutIDInvalid):
			return fail(controlplane.ErrorInvalidRequest, err)
		case errors.Is(err, pki.ErrSproutIDNotFound), errors.Is(err, pki.ErrTenantNotFound):
			return fail(controlplane.ErrorSproutNotFound, err)
		default:
			return fail(controlplane.ErrorInternal, err)
		}
	}
	// handleCmdRun/handleCook refuse sprout IDs containing '_' (their
	// sprout-subject rule), which VerifySproutInTenant allows; reject it
	// here so the caller gets invalid_request rather than internal_error.
	if strings.Contains(req.SproutID, "_") {
		return fail(controlplane.ErrorInvalidRequest, fmt.Errorf("sprout ID %q can't be targeted by %s", req.SproutID, req.Action.Type))
	}

	switch req.Action.Type {
	case controlplane.ActionCmdRun:
		return runSproutCmd(req, reply)
	case controlplane.ActionSelfUpdate:
		return runSproutSelfUpdate(req, reply)
	}
	return runSproutCook(req, reply)
}

// singleTargetParams builds the imas.api.cmd.run/cook params for exactly one
// target: the verified sprout. Nothing from the request other than the
// sanitized action reaches the handler — in particular no "token", so no
// RBAC identity is borrowed from the payload.
func singleTargetParams(sproutID string, action any) json.RawMessage {
	b, _ := json.Marshal(apitypes.TargetedAction{
		Target: []pki.KeyManager{{SproutID: sproutID}},
		Action: action,
	})
	return b
}

func runSproutCmd(req controlplane.SproutActionRequest, reply controlplane.SproutActionReply) (controlplane.SproutActionReply, error) {
	var in apitypes.CmdRun
	if err := json.Unmarshal(req.Action.Params, &in); err != nil {
		reply.ErrorCode = controlplane.ErrorInvalidRequest
		return reply, fmt.Errorf("%w: cmd.run params: %v", errSproutActionInvalid, err)
	}
	switch {
	case in.Command == "":
		reply.ErrorCode = controlplane.ErrorInvalidRequest
		return reply, fmt.Errorf("%w: cmd.run without a command", errSproutActionInvalid)
	case in.StreamTopic != "":
		// Streaming would have the sprout publish output to a
		// caller-chosen subject in the tenant's Account; the control
		// plane gets its output in the reply instead.
		reply.ErrorCode = controlplane.ErrorInvalidRequest
		return reply, fmt.Errorf("%w: cmd.run stream_topic is not supported", errSproutActionInvalid)
	case in.Timeout < 0 || in.Timeout > maxSproutActionCmdTimeout:
		reply.ErrorCode = controlplane.ErrorInvalidRequest
		return reply, fmt.Errorf("%w: cmd.run timeout %s outside [0, %s]", errSproutActionInvalid, in.Timeout, maxSproutActionCmdTimeout)
	}
	// Input fields only: output fields in the request are dropped.
	action := apitypes.CmdRun{
		Command: in.Command,
		Args:    in.Args,
		Path:    in.Path,
		CWD:     in.CWD,
		RunAs:   in.RunAs,
		Env:     in.Env,
		Timeout: in.Timeout,
	}

	res, err := dispatchCmdRun(req.TenantID, singleTargetParams(req.SproutID, action))
	if err != nil {
		reply.ErrorCode = controlplane.ErrorInternal
		return reply, err
	}
	results, ok := res.(apitypes.TargetedResults)
	if !ok {
		reply.ErrorCode = controlplane.ErrorInternal
		return reply, fmt.Errorf("unexpected cmd.run result type %T", res)
	}
	out, ok := results.Results[req.SproutID].(apitypes.CmdRun)
	if !ok {
		reply.ErrorCode = controlplane.ErrorInternal
		return reply, fmt.Errorf("cmd.run returned no result for sprout %q", req.SproutID)
	}
	if out.Error != nil {
		reply.ErrorCode = controlplane.ErrorInternal
		if errors.Is(out.Error, nats.ErrTimeout) || errors.Is(out.Error, nats.ErrNoResponders) {
			reply.ErrorCode = controlplane.ErrorSproutUnreachable
		}
		return reply, out.Error
	}

	reply.Status = controlplane.StatusCompleted
	reply.Result = &controlplane.CmdRunResult{
		Stdout:   out.Stdout,
		Stderr:   out.Stderr,
		ExitCode: out.ErrCode,
		Duration: out.Duration,
	}
	return reply, nil
}

func runSproutCook(req controlplane.SproutActionRequest, reply controlplane.SproutActionReply) (controlplane.SproutActionReply, error) {
	var in apitypes.CmdCook
	if err := json.Unmarshal(req.Action.Params, &in); err != nil {
		reply.ErrorCode = controlplane.ErrorInvalidRequest
		return reply, fmt.Errorf("%w: cook params: %v", errSproutActionInvalid, err)
	}
	if in.Recipe == "" {
		reply.ErrorCode = controlplane.ErrorInvalidRequest
		return reply, fmt.Errorf("%w: cook without a recipe", errSproutActionInvalid)
	}
	action := apitypes.CmdCook{
		Recipe: in.Recipe,
		State:  in.State,
		Test:   in.Test,
		Env:    in.Env,
	}

	res, err := dispatchCook(req.TenantID, singleTargetParams(req.SproutID, action))
	if err != nil {
		reply.ErrorCode = controlplane.ErrorInternal
		return reply, err
	}
	cmd, ok := res.(apitypes.CmdCook)
	if !ok || cmd.JID == "" {
		reply.ErrorCode = controlplane.ErrorInternal
		return reply, fmt.Errorf("unexpected cook result %T without a JID", res)
	}
	// handleCook only sends the cook once its caller triggers the JID
	// (the CLI subscribes to the job's events first, then triggers). The
	// SaaS API tracks the job through farmer.jobs rather than the event
	// stream, and can't reach the tenant's trigger subject from SYS
	// anyway, so farmer triggers it itself.
	if err := triggerCook(req.TenantID, cmd.JID); err != nil {
		reply.ErrorCode = controlplane.ErrorInternal
		return reply, fmt.Errorf("triggering cook %s: %w", cmd.JID, err)
	}

	reply.Status = controlplane.StatusDispatched
	reply.JID = cmd.JID
	return reply, nil
}

// triggerCookOnTenantConn sends handleCook's trigger for jid over
// tenantID's own connection — the one handleCook subscribed the trigger
// on, so the SUB is already ahead of this request on the wire.
func triggerCookOnTenantConn(tenantID, jid string) error {
	nc := natsConnFor(tenantID)
	if nc == nil {
		return fmt.Errorf("no NATS connection for tenant %q", tenantID)
	}
	b, _ := json.Marshal(config.TriggerMsg{JID: jid})
	_, err := nc.Request(SproutCookTriggerPrefix+jid, b, cookTriggerTimeout)
	return err
}

// runSproutSelfUpdate checks the requested version against the release
// catalog (checkSelfUpdateRelease) and, only if it passes, dispatches the
// selfupdate step. Every refusal is invalid_request, except a closed
// rollout window (rollout_window_closed); the specific reason stays in
// farmer's log. A catalog or key read that fails is internal_error. There is no path that dispatches a version the catalog
// doesn't vouch for.
func runSproutSelfUpdate(req controlplane.SproutActionRequest, reply controlplane.SproutActionReply) (controlplane.SproutActionReply, error) {
	in, err := controlplane.DecodeSelfUpdateParams(req.Action.Params)
	if err != nil {
		reply.ErrorCode = controlplane.ErrorInvalidRequest
		return reply, fmt.Errorf("%w: %w", errSproutActionInvalid, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), selfUpdateVerifyTimeout)
	defer cancel()
	// req.TenantID is the sprout's own stored tenant here: runSproutAction
	// only gets this far once pki.VerifySproutInTenant has confirmed the
	// stored tenant_id equals it.
	if code, err := checkSelfUpdateRelease(ctx, req.TenantID, in.Version); err != nil {
		reply.ErrorCode = code
		return reply, err
	}

	jid, err := dispatchSelfUpdate(req.TenantID, req.SproutID, in.Version)
	if err != nil {
		reply.ErrorCode = controlplane.ErrorInternal
		if errors.Is(err, nats.ErrTimeout) || errors.Is(err, nats.ErrNoResponders) {
			reply.ErrorCode = controlplane.ErrorSproutUnreachable
		}
		return reply, err
	}
	reply.Status = controlplane.StatusDispatched
	reply.JID = jid
	return reply, nil
}

// maxSelfUpdateVersionLen matches saas.fleet_versions.version.
const maxSelfUpdateVersionLen = 64

// checkSelfUpdateRelease re-verifies version against the release catalog
// farmer reads read-only (internal/fleetcatalog: saas.fleet_versions and
// saas.tenant_update_policy) before anything reaches a sprout of
// tenantID. saasapi checked the same, but it can also write those tables,
// so farmer doesn't take its word for it. version must be:
//
//   - canonical semver;
//   - tenantID's approved_version;
//   - registered (at least one row), and not revoked (no row revoked);
//   - signed: EVERY row of it verifies against the imas-fleet-signing key
//     set farmer reads from OpenBao Transit with its READ-ONLY token
//     (SetFleetKeySource). One bad row refuses the whole version, though
//     this sprout would fetch only its own OS/arch row: a version with a
//     forged row is not a release CloudXP signed;
//   - inside the tenant's rollout window now, if its policy sets one
//     (rollout_window_closed otherwise), as saasapi's policyRefusal checks
//     it (checkRolloutWindow).
//
// The sprout then fetches and verifies its own row a third time, against
// the keyring shipped in its package. A refusal is invalid_request; a
// catalog or key read that fails is internal_error.
func checkSelfUpdateRelease(ctx context.Context, tenantID, version string) (controlplane.ErrorCode, error) {
	refuse := func(format string, args ...any) (controlplane.ErrorCode, error) {
		return controlplane.ErrorInvalidRequest, fmt.Errorf("%w: self_update %s for tenant %q refused: %s",
			errSproutActionInvalid, version, tenantID, fmt.Sprintf(format, args...))
	}
	if len(version) > maxSelfUpdateVersionLen || !semver.IsValid(version) || semver.Canonical(version) != version {
		return refuse("not a canonical semver version")
	}
	cat := fleetcatalog.Current()
	if cat == nil {
		return controlplane.ErrorInternal, errors.New("self_update refused: no release catalog configured (farmer has no PXC handle)")
	}
	src := fleetKeys
	if src == nil {
		return controlplane.ErrorInternal, errors.New("self_update refused: no fleet signing key source configured (IMAS_FLEETSIGN_OPENBAO_*)")
	}

	approved, ok, err := cat.ApprovedVersion(ctx, tenantID)
	if err != nil {
		return controlplane.ErrorInternal, fmt.Errorf("self_update refused: reading tenant %q's update policy: %w", tenantID, err)
	}
	if !ok || approved != version {
		return refuse("not the tenant's approved version (approved: %q)", approved)
	}
	if code, err := checkRolloutWindow(ctx, cat, tenantID, selfUpdateNow()); err != nil {
		return code, err
	}
	rows, err := cat.ReleaseRows(ctx, version)
	if err != nil {
		return controlplane.ErrorInternal, fmt.Errorf("self_update refused: reading the catalog rows of %s: %w", version, err)
	}
	if len(rows) == 0 {
		return refuse("not registered in saas.fleet_versions")
	}
	ks, err := src.KeySet(ctx)
	if err != nil {
		return controlplane.ErrorInternal, fmt.Errorf("self_update refused: reading fleet signing keys: %w", err)
	}
	for _, row := range rows {
		m := row.Manifest
		key := m.OS + "/" + m.Arch + "/" + row.PackageType
		switch {
		case row.Revoked:
			return refuse("revoked (row %s)", key)
		case m.Version != version:
			return refuse("catalog returned a row for %s", m.Version)
		}
		if err := ks.Verify(m); err != nil {
			return refuse("row %s does not verify: %v", key, err)
		}
	}
	return "", nil
}

// rolloutWindowCatalog is the read checkRolloutWindow needs from the
// release catalog: tenantID's rollout window from
// saas.tenant_update_policy (rollout_window_start, rollout_window_end;
// both set or both NULL), scoped by tenant_id. ok is false when the tenant
// has no policy row.
//
// internal/fleetcatalog's SQL catalog doesn't implement it yet (adding
// it was outside SEC.5's scope; see docs/BUILD-STATUS.md, Open item 4).
// Until it does, every self_update is refused with internal_error: farmer
// fails closed rather than skip the window.
type rolloutWindowCatalog interface {
	RolloutWindow(ctx context.Context, tenantID string) (start, end *time.Time, ok bool, err error)
}

// selfUpdateNow is farmer's clock for the rollout window, a seam for
// tests.
var selfUpdateNow = time.Now

// checkRolloutWindow refuses a self_update when cat's policy for tenantID
// sets a window and now is outside [start, end), the same rule as
// saasapi's policyRefusal. A catalog that can't read windows, or a read
// that fails, is internal_error.
func checkRolloutWindow(ctx context.Context, cat fleetcatalog.Catalog, tenantID string, now time.Time) (controlplane.ErrorCode, error) {
	wc, ok := cat.(rolloutWindowCatalog)
	if !ok {
		return controlplane.ErrorInternal, errors.New("self_update refused: the release catalog can't read tenant rollout windows (fleetcatalog has no RolloutWindow); failing closed")
	}
	start, end, found, err := wc.RolloutWindow(ctx, tenantID)
	if err != nil {
		return controlplane.ErrorInternal, fmt.Errorf("self_update refused: reading tenant %q's rollout window: %w", tenantID, err)
	}
	if found && start != nil && end != nil && (now.Before(*start) || !now.Before(*end)) {
		return ErrorRolloutWindowClosed, fmt.Errorf("self_update for tenant %q refused: now (%s) is outside its rollout window [%s, %s)",
			tenantID, now.UTC().Format(time.RFC3339), start.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339))
	}
	return "", nil
}

// sendSelfUpdate sends version to sproutID as a one-step cook job — the
// sprout's selfupdate ingredient — over tenantID's own connection, and
// returns its JID. The step carries only the version: the sprout fetches
// and verifies its own signed manifest from farmer (GET
// /v1/sprout/update-manifest) and the package from its configured
// repository. The SaaS API follows the job through farmer.job_status like
// a cook's.
func sendSelfUpdate(tenantID, sproutID, version string) (string, error) {
	jid := cook.GenerateJobID()
	step := cook.Step{
		Ingredient: cook.Ingredient(fleetsign.SelfUpdateIngredient),
		Method:     fleetsign.SelfUpdateMethod,
		ID:         cook.StepID(fleetsign.SelfUpdateStepIDPrefix + version),
		Properties: map[string]interface{}{fleetsign.PropVersion: version},
	}
	if err := cook.SendStepsEvent(tenantID, sproutID, jid, []cook.Step{step}); err != nil {
		return "", fmt.Errorf("sending self_update %s to sprout %q: %w", version, sproutID, err)
	}
	return jid, nil
}
