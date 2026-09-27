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
// self_update (design doc §1.8, §2.5) adds a third check before dispatch:
// the release's signature must verify against the imas-fleet-signing
// public key farmer reads from OpenBao Transit with its READ-ONLY token
// (SetFleetKeySource). The SaaS API checked it too, but it can also write
// saas.fleet_versions, so farmer doesn't take its word for it. A release
// that passes goes to the sprout as a one-step cook job (the selfupdate
// ingredient) over the same tenant connection, and the sprout verifies
// the signature a third time, against the key it pinned at enrollment.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/cook"
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

// selfUpdateVerifyTimeout bounds the Transit key read behind a signature
// check (normally served from the source's cache).
const selfUpdateVerifyTimeout = 15 * time.Second

const auditActionSproutAction = controlplane.SubjectSproutAction

// EnvSproutActionConcurrency sets how many internal.sprout.action
// requests one farmer process runs at once (see sproutActionConcurrency).
// Read once, when RegisterSproutAction is called.
const EnvSproutActionConcurrency = "IMAS_SPROUT_ACTION_CONCURRENCY"

// Bounds for EnvSproutActionConcurrency. A cmd.run holds its slot until
// the sprout answers (up to its timeout), so handling requests serially —
// NATS's default for one subscription — would let one slow sprout stall a
// whole §1.5 batch. When every slot is busy the subscription callback
// blocks, and further requests queue in the subscription's pending buffer.
// The ceiling keeps a typo from turning into an unbounded goroutine count
// on a privileged surface.
const (
	defaultSproutActionConcurrency = 64
	maxSproutActionConcurrency     = 1024
)

// sproutActionConcurrency returns EnvSproutActionConcurrency's value, or
// the default if it's unset or not a positive integer, clamped to
// maxSproutActionConcurrency. A bad value is logged, never fatal: it only
// tunes throughput.
func sproutActionConcurrency() int {
	raw := strings.TrimSpace(os.Getenv(EnvSproutActionConcurrency))
	if raw == "" {
		return defaultSproutActionConcurrency
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		log.Warnf("natsapi: ignoring %s=%q (want a positive integer); using %d", EnvSproutActionConcurrency, raw, defaultSproutActionConcurrency)
		return defaultSproutActionConcurrency
	}
	if n > maxSproutActionConcurrency {
		log.Warnf("natsapi: %s=%d exceeds the maximum; using %d", EnvSproutActionConcurrency, n, maxSproutActionConcurrency)
		return maxSproutActionConcurrency
	}
	return n
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
func RegisterSproutAction(nc *nats.Conn) error {
	concurrency := sproutActionConcurrency()
	slots := make(chan struct{}, concurrency)
	if _, err := nc.QueueSubscribe(controlplane.SubjectSproutAction, natsCoreQueueGroup, func(msg *nats.Msg) {
		// Checked before decoding or doing anything else: a request with
		// no valid SaaS API inbox is dropped, not executed and not
		// answered. The contract is request-reply, so there's no one to
		// tell, and running it anyway would be an effect nobody sees.
		if !controlplane.ValidSaaSAPIReplySubject(msg.Reply) {
			log.Errorf("natsapi: dropping %s request with a reply subject outside %s: %q", controlplane.SubjectSproutAction, controlplane.SaaSAPIInboxWildcard, msg.Reply)
			return
		}
		slots <- struct{}{}
		go func() {
			defer func() { <-slots }()
			reply := handleSproutAction(msg.Data)
			data, err := json.Marshal(reply)
			if err != nil {
				log.Errorf("natsapi: marshalling %s reply: %v", controlplane.SubjectSproutAction, err)
				return
			}
			if err := msg.Respond(data); err != nil {
				log.Errorf("natsapi: responding to %s: %v", controlplane.SubjectSproutAction, err)
			}
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
	log.Infof("natsapi: registered sprout action handler (SYS account, concurrency %d)", concurrency)
	return nil
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

// runSproutSelfUpdate verifies the release's signature and, only if it
// verifies, dispatches the selfupdate step. Signature and field failures
// are invalid_request; the specific reason stays in farmer's log. There is
// no path that dispatches an unsigned or unverifiable release.
func runSproutSelfUpdate(req controlplane.SproutActionRequest, reply controlplane.SproutActionReply) (controlplane.SproutActionReply, error) {
	var in controlplane.SelfUpdateParams
	if err := json.Unmarshal(req.Action.Params, &in); err != nil {
		reply.ErrorCode = controlplane.ErrorInvalidRequest
		return reply, fmt.Errorf("%w: self_update params: %v", errSproutActionInvalid, err)
	}
	rel := fleetsign.Release{Version: in.Version, ArtifactURL: in.ArtifactURL, ChecksumSHA256: in.ChecksumSHA256}
	if _, err := rel.Message(); err != nil {
		reply.ErrorCode = controlplane.ErrorInvalidRequest
		return reply, fmt.Errorf("%w: self_update: %w", errSproutActionInvalid, err)
	}
	src := fleetKeys
	if src == nil {
		reply.ErrorCode = controlplane.ErrorInternal
		return reply, errors.New("self_update refused: no fleet signing key source configured (IMAS_FLEETSIGN_OPENBAO_*)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), selfUpdateVerifyTimeout)
	defer cancel()
	ks, err := src.KeySet(ctx)
	if err != nil {
		reply.ErrorCode = controlplane.ErrorInternal
		return reply, fmt.Errorf("self_update refused: reading fleet signing keys: %w", err)
	}
	if err := ks.Verify(rel, in.Signature); err != nil {
		reply.ErrorCode = controlplane.ErrorInvalidRequest
		return reply, fmt.Errorf("%w: self_update %s refused: %w", errSproutActionInvalid, in.Version, err)
	}

	jid, err := dispatchSelfUpdate(req.TenantID, req.SproutID, in)
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

// sendSelfUpdate sends p to sproutID as a one-step cook job — the
// sprout's selfupdate ingredient — over tenantID's own connection, and
// returns its JID. The SaaS API follows the job through farmer.job_status
// like a cook's.
func sendSelfUpdate(tenantID, sproutID string, p controlplane.SelfUpdateParams) (string, error) {
	jid := cook.GenerateJobID()
	step := cook.Step{
		Ingredient: cook.Ingredient(fleetsign.SelfUpdateIngredient),
		Method:     fleetsign.SelfUpdateMethod,
		ID:         cook.StepID(fleetsign.SelfUpdateStepIDPrefix + p.Version),
		Properties: map[string]interface{}{
			fleetsign.PropVersion:        p.Version,
			fleetsign.PropArtifactURL:    p.ArtifactURL,
			fleetsign.PropChecksumSHA256: p.ChecksumSHA256,
			fleetsign.PropSignature:      p.Signature,
		},
	}
	if err := cook.SendStepsEvent(tenantID, sproutID, jid, []cook.Step{step}); err != nil {
		return "", fmt.Errorf("sending self_update %s to sprout %q: %w", p.Version, sproutID, err)
	}
	return jid, nil
}
