// Security-sensitive: tenant-scoped remote execution.
// FLAG FOR SECURITY REVIEW per the task brief — this is the first SaaS
// API endpoint that makes something run on a tenant's machines. It is the
// SaaS API's half of a two-sided trust boundary; farmer's
// internal.sprout.action handler (internal/natsapi/sprout_action.go) is
// the other half, and independently re-checks that each sprout belongs to
// the asserted tenant before running anything (the point-of-effect check,
// design doc §2.2). This file must be correct on its own regardless:
//
//   - The tenant a batch runs under is always the {tenant_id} path
//     parameter, which Auth has already matched against the caller's
//     token (middleware.go). Nothing in the request body names a tenant
//     or a sprout — the caller supplies asset_ids only.
//   - asset_id -> sprout_id resolution is §1.4's own join
//     (resolveAssetIDs), scoped by tenant_id on both tables, so an item
//     can only ever carry a sprout_id of the caller's own tenant. What
//     doesn't resolve becomes `unresolved` without saying why, exactly
//     like §1.4's `unresolved` list, and is never dispatched.
//   - Batch and item reads and every status update carry tenant_id in the
//     WHERE clause (§4 "Tenant safety"); another tenant's batch_id is 404,
//     the same as one that doesn't exist.
//   - The caller's action is translated into farmer's params shape field
//     by field (translateAction), never passed through: unknown fields are
//     rejected, and nothing like cmd.run's stream_topic or a "token" can be
//     smuggled to farmer.
//   - Failures cross the service boundary only as fixed codes, and are
//     shown only as this file's fixed messages (actionErrorMessage).
package saasapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/controlplane"
	log "github.com/yogzblr/imas/internal/log"
)

const (
	actionBatchIDPrefix = "b_"

	// maxActionBatchIDLen matches AssetActionBatch.ID's column size.
	maxActionBatchIDLen = 32

	// maxActionRequestBytes bounds POST .../sprouts/actions' body: 100
	// maximum-length asset_ids plus a generous action still fit well
	// inside it.
	maxActionRequestBytes = 64 << 10

	// Limits on a cmd.run's params. Generous for any real command line;
	// they exist so one request can't park megabytes in
	// asset_action_batches.action_params.
	maxCmdLen  = 4096
	maxCmdArgs = 256

	// maxRecipeLen bounds a cook's recipe name.
	maxRecipeLen = 255

	// defaultCmdTimeout applies when a cmd.run request doesn't set
	// timeout_seconds. It is never zero: farmer waits for the sprout for
	// only farmerSproutWait plus the command's own timeout, so a zero
	// timeout would have farmer give up on any command running longer
	// than 15s while the command carries on, with no deadline, on the
	// sprout.
	defaultCmdTimeout = 60 * time.Second

	// maxCmdTimeout matches farmer's own cap on a cmd.run timeout
	// (internal/natsapi's maxSproutActionCmdTimeout); farmer rejects
	// anything longer as invalid_request.
	maxCmdTimeout = 10 * time.Minute

	// farmerSproutWait is how long farmer waits on the sprout on top of a
	// cmd.run's own timeout (internal/ingredients/cmd.FRun's request
	// timeout), and how long it waits to trigger a cook
	// (internal/natsapi's cookTriggerTimeout).
	farmerSproutWait = 15 * time.Second

	// dispatchReplyMargin is how much longer than farmer's own worst case
	// this service waits for an internal.sprout.action reply before
	// giving up on it, covering farmer's point-of-effect lookup, time
	// queued behind farmer's concurrency limit, and bus latency.
	dispatchReplyMargin = 30 * time.Second

	// maxConcurrentActionDispatches bounds how many internal.sprout.action
	// requests one SaaS API process has in flight at once, across all
	// batches. It matches farmer's default per-replica concurrency
	// (internal/natsapi's defaultSproutActionConcurrency), so one SaaS API
	// replica alone can't pile up a queue on a single farmer replica.
	maxConcurrentActionDispatches = 64

	// jobRefreshTimeout bounds one GET's JobStatusReader call.
	jobRefreshTimeout = 5 * time.Second
)

// Batch statuses, derived from the batch's items on every GET.
const (
	actionBatchInProgress = "in_progress"
	actionBatchCompleted  = "completed"
)

// Item error codes this service assigns itself, on top of the
// controlplane.ErrorCode values farmer can reply with.
const (
	// errCodeSproutNotAccepted: the asset_id resolved to one of the
	// tenant's sprouts, but its key isn't accepted, so it was never
	// dispatched (farmer would refuse it anyway).
	errCodeSproutNotAccepted = "sprout_not_accepted"
	// errCodeCommandFailed: a cmd.run ran and exited non-zero; exit_code
	// has the value.
	errCodeCommandFailed = "command_failed"
	// errCodeJobFailed: a cook's job finished unsuccessfully.
	errCodeJobFailed = "job_failed"
	// errCodeJobExpired: the sprout started the job too long after it was
	// dispatched (farmer's IMAS_JOB_RECONCILE_WINDOW), so its result was
	// not recorded. It may still have run.
	errCodeJobExpired = "job_expired"
	// errCodeDispatchOutcomeUnknown: the request reached farmer (or may
	// have), but no usable reply came back — it timed out, or the reply
	// was unreadable. The action may or may not have run.
	errCodeDispatchOutcomeUnknown = "dispatch_outcome_unknown"
)

// actionErrorMessages is the only text ever shown for an item's error
// code. Unknown codes get the internal_error message (actionErrorMessage),
// so nothing stored or received is echoed verbatim. controlplane's own
// internal_error message talks about provisioning, so it's replaced here.
var actionErrorMessages = map[string]string{
	string(controlplane.ErrorInvalidRequest):    controlplane.PublicErrorMessage(controlplane.ErrorInvalidRequest),
	string(controlplane.ErrorUnsupportedAction): controlplane.PublicErrorMessage(controlplane.ErrorUnsupportedAction),
	string(controlplane.ErrorSproutNotFound):    controlplane.PublicErrorMessage(controlplane.ErrorSproutNotFound),
	string(controlplane.ErrorSproutUnreachable): controlplane.PublicErrorMessage(controlplane.ErrorSproutUnreachable),
	string(controlplane.ErrorInternal):          "an internal error occurred while running the action; contact support",

	errCodeSproutNotAccepted:      "the sprout's key is not accepted, so the action was not sent",
	errCodeCommandFailed:          "the command exited with a non-zero status",
	errCodeJobFailed:              "the job finished unsuccessfully",
	errCodeJobExpired:             "the sprout started the job too long after it was sent, so its result was not recorded; it may still have run",
	errCodeDispatchOutcomeUnknown: "no reply was received for the action; it may or may not have run",

	// Fleet update rollouts (fleet_update_dispatch.go).
	errCodeRolloutHalted:           "an earlier wave of this rollout did not fully succeed, so the update was not sent to this sprout",
	errCodeRolloutWindowClosed:     "the tenant's rollout window closed before the update was sent to this sprout",
	errCodeApprovalWithdrawn:       "the tenant's approved version changed before the update was sent to this sprout",
	errCodeVersionRevoked:          "the target version was revoked before the update was sent to this sprout",
	errCodeUpdateInProgress:        "the sprout already has an update in progress, so this update was not sent",
	errCodeUnresponsiveAfterUpdate: "the sprout did not reconnect and report the new version in time; it may be unreachable, or may have kept or restored its previous version",
	errCodeNoReleaseForPlatform:    "the target version has no package for this sprout's OS and architecture, so the update was not sent",
	errCodeBelowMinSproutVersion:   "this sprout's version is older than the target version supports updating from, so the update was not sent",
	errCodeSproutNewerThanTarget:   "this sprout already runs a newer version than the target, and sprouts refuse downgrades, so the update was not sent",
	errCodeFactsClockSkew:          "the sprout reported the target version, but the time its report was stored is too far ahead of the SaaS API's clock to show it came after this update; check the clocks (NTP) of the farmer nodes",
}

func actionErrorMessage(code string) string {
	if msg, ok := actionErrorMessages[code]; ok {
		return msg
	}
	return actionErrorMessages[string(controlplane.ErrorInternal)]
}

// farmerErrorCode keeps a farmer reply's error code only if it's one farmer
// is documented to send for internal.sprout.action; anything else — a newer
// farmer, or a malformed reply — is stored as internal_error.
func farmerErrorCode(code controlplane.ErrorCode) string {
	switch code {
	case controlplane.ErrorInvalidRequest, controlplane.ErrorUnsupportedAction,
		controlplane.ErrorSproutNotFound, controlplane.ErrorSproutUnreachable:
		return string(code)
	}
	return string(controlplane.ErrorInternal)
}

// sproutActionRequest is POST .../sprouts/actions' body (design doc §1.5).
type sproutActionRequest struct {
	AssetIDs []string          `json:"asset_ids"`
	Action   sproutActionInput `json:"action"`
}

type sproutActionInput struct {
	Type   string          `json:"type"`
	Params json.RawMessage `json:"params"`
}

// cmdRunInput is a cmd.run's external params. Without args, cmd is split
// on whitespace into the executable and its arguments; with args, cmd is
// the executable, verbatim. Nothing runs through a shell either way (the
// sprout execs the command directly), which is why the split form rejects
// quoting and shell syntax rather than silently passing them through as
// literal arguments.
//
// There is deliberately no env: environment variables are the usual way
// to hand a command a secret, and the batch row persists its params
// (AssetActionBatch.ActionParams). A caller that needs different inputs
// resubmits a new batch. Sent anyway, env is rejected as an unknown field.
type cmdRunInput struct {
	Cmd            string   `json:"cmd"`
	Args           []string `json:"args"`
	CWD            string   `json:"cwd"`
	RunAs          string   `json:"run_as"`
	TimeoutSeconds int      `json:"timeout_seconds"`
}

// cookInput is a cook's external params. Like cmd.run, no env: the cook
// runs in farmer's default environment.
type cookInput struct {
	Recipe string `json:"recipe"`
	Test   bool   `json:"test"`
}

// farmerCmdRun and farmerCook are the params farmer's internal.sprout.action
// handler decodes (internal/api/types' CmdRun and CmdCook — input fields
// only). They're mirrored here, not imported, to keep farmer's dependency
// tree out of this package, as internal/controlplane does;
// TestFarmerActionParamsContract pins the JSON field names against the
// real types.
type farmerCmdRun struct {
	Command string        `json:"command"`
	Args    []string      `json:"args,omitempty"`
	CWD     string        `json:"cwd,omitempty"`
	RunAs   string        `json:"runas,omitempty"`
	Timeout time.Duration `json:"timeout"`
}

type farmerCook struct {
	Recipe string `json:"recipe"`
	Test   bool   `json:"test,omitempty"`
}

type createActionBatchResponse struct {
	BatchID string `json:"batch_id"`
}

// actionBatchResponse is the GET response for both §1.5 batches and §1.8
// update batches. Rollout is set only for an update batch.
type actionBatchResponse struct {
	BatchID    string               `json:"batch_id"`
	Status     string               `json:"status"`
	ActionType string               `json:"action_type"`
	CreatedAt  time.Time            `json:"created_at"`
	Rollout    *rolloutResponse     `json:"rollout,omitempty"`
	Items      []actionItemResponse `json:"items"`
}

type actionItemResponse struct {
	AssetID  string                `json:"asset_id"`
	SproutID string                `json:"sprout_id,omitempty"`
	Status   AssetActionItemStatus `json:"status"`
	JID      string                `json:"jid,omitempty"`
	ExitCode *int                  `json:"exit_code,omitempty"`
	Error    string                `json:"error,omitempty"`
	Message  string                `json:"message,omitempty"`
}

// CreateSproutActionBatch handles POST /tenants/{tenant_id}/sprouts/actions
// (design doc §1.5).
//
// The request is validated in full before anything is written. Then, in
// one transaction, a batch row and one item row per deduplicated asset_id
// are written (the outbox, §4 "Async pattern"): `unresolved` for an
// asset_id §1.4's join doesn't resolve, `failed`/sprout_not_accepted for
// one resolving to a sprout whose key isn't accepted, `queued` for the
// rest. Only after the commit is the 202 sent and the queued items handed
// to dispatchBatch, which runs in the background.
//
// Rate-limited per tenant (see router.go): every call can trigger up to
// maxAssetIDsPerLookup executions and writes as many rows.
func CreateSproutActionBatch(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant_id")
	if !tenantActive(w, tenantID) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxActionRequestBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req sproutActionRequest
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body must be valid JSON with asset_ids and action")
		return
	}
	assetIDs, ok := parseActionAssetIDs(w, req.AssetIDs)
	if !ok {
		return
	}
	action, ok := translateAction(w, req.Action)
	if !ok {
		return
	}

	rows, err := resolveAssetIDs(tenantID, assetIDs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to resolve asset ids")
		return
	}

	batch, queued, err := createActionBatch(tenantID, assetIDs, action, rows)
	if err != nil {
		log.Errorf("saasapi: creating action batch for tenant %s: %v", tenantID, err)
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to create action batch")
		return
	}
	log.Infof("saasapi: action batch %s (tenant %s, %s): %d asset_ids, %d queued for dispatch",
		batch.ID, tenantID, batch.ActionType, len(assetIDs), len(queued))
	writeJSON(w, http.StatusAccepted, createActionBatchResponse{BatchID: batch.ID})
	startBatchDispatch(batch, queued)
}

// GetSproutActionBatch handles GET
// /tenants/{tenant_id}/sprouts/actions/{batch_id} (design doc §1.5).
//
// No NATS call: item status comes from asset_action_items, and running
// items (a cook with a known jid) are refreshed through the installed
// JobStatusReader (see refreshRunningItems). The batch is in_progress
// while any item is queued, dispatching or running, completed otherwise.
//
// A §1.8 update batch is found here too, since it's stored in the same
// tables. GET .../sprouts/updates/{batch_id} finds only update batches.
func GetSproutActionBatch(w http.ResponseWriter, r *http.Request) {
	writeBatchStatus(w, r, "")
}

// writeBatchStatus serves both batch-status GETs. A non-empty actionType
// limits the lookup to batches of that type; any other batch gives the
// same 404 as one that doesn't exist.
func writeBatchStatus(w http.ResponseWriter, r *http.Request, actionType string) {
	tenantID := r.PathValue("tenant_id")
	batchID := r.PathValue("batch_id")
	if !tenantExists(w, tenantID) {
		return
	}
	if batchID == "" || len(batchID) > maxActionBatchIDLen {
		writeError(w, http.StatusNotFound, "batch_not_found", "no such action batch")
		return
	}

	var batch AssetActionBatch
	q := db.Where("id = ? AND tenant_id = ?", batchID, tenantID)
	if actionType != "" {
		q = q.Where("action_type = ?", actionType)
	}
	err := q.First(&batch).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		writeError(w, http.StatusNotFound, "batch_not_found", "no such action batch")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to look up action batch")
		return
	}
	var items []AssetActionItem
	if err := db.Where("batch_id = ? AND tenant_id = ?", batch.ID, tenantID).
		Order("position").Find(&items).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to look up action batch items")
		return
	}
	if batch.ActionType == controlplane.ActionSelfUpdate {
		// A self_update item succeeds when its sprout reports the new
		// version, not when its job does (fleet_update_dispatch.go).
		refreshUpdateItems(r.Context(), db, jobStatusReader, sproutFactsReader, batch, items)
	} else {
		refreshRunningItems(r.Context(), tenantID, items)
	}

	resp := actionBatchResponse{
		BatchID:    batch.ID,
		Status:     actionBatchCompleted,
		ActionType: batch.ActionType,
		CreatedAt:  batch.CreatedAt,
		Rollout:    rolloutOf(batch),
		Items:      make([]actionItemResponse, 0, len(items)),
	}
	for _, it := range items {
		if !it.Status.terminal() {
			resp.Status = actionBatchInProgress
		}
		item := actionItemResponse{
			AssetID:  it.AssetID,
			SproutID: it.SproutID,
			Status:   it.Status,
			JID:      it.JID,
			ExitCode: it.ExitCode,
		}
		if it.ErrorCode != "" {
			item.Error = it.ErrorCode
			item.Message = actionErrorMessage(it.ErrorCode)
		}
		resp.Items = append(resp.Items, item)
	}
	writeJSON(w, http.StatusOK, resp)
}

// tenantActive is tenantExists plus a lifecycle check: actions only run
// for an active tenant. A pending, failed or offboarding tenant has no
// live fleet on farmer (which would refuse the action anyway), so the
// request is refused here, before any batch row is written.
func tenantActive(w http.ResponseWriter, tenantID string) bool {
	var tenant Tenant
	err := db.Select("id", "status").Where("id = ?", tenantID).First(&tenant).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		writeError(w, http.StatusNotFound, "tenant_not_found", "no such tenant")
		return false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to look up tenant")
		return false
	}
	if tenant.Status != TenantStatusActive {
		writeError(w, http.StatusConflict, "tenant_not_active", "the tenant is not active")
		return false
	}
	return true
}

// parseActionAssetIDs validates the request's asset_ids: at most
// maxAssetIDsPerLookup of them (counted before deduplication, as §1.4
// counts), none empty or longer than an asset_id can be. It returns them
// trimmed and deduplicated, in request order.
func parseActionAssetIDs(w http.ResponseWriter, raw []string) ([]string, bool) {
	if len(raw) > maxAssetIDsPerLookup {
		writeErrorDetails(w, http.StatusBadRequest, "too_many_asset_ids",
			"at most 100 asset_ids per request", map[string]any{"max": maxAssetIDsPerLookup})
		return nil, false
	}
	ids := make([]string, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, id := range raw {
		id = strings.TrimSpace(id)
		if id == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "asset_ids must not contain empty values")
			return nil, false
		}
		if len(id) > maxAssetIDLen {
			writeError(w, http.StatusBadRequest, "invalid_request", "asset_id is too long")
			return nil, false
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "asset_ids is required")
		return nil, false
	}
	return ids, true
}

// translateAction validates the caller's action and maps it onto the
// controlplane.SproutAction farmer takes. Only cmd.run and cook are
// accepted. self_update is only sent by §1.8's POST .../sprouts/updates
// (fleet_update_dispatch.go), which builds its params from the version
// catalog and is behind a feature flag. It's never accepted here.
func translateAction(w http.ResponseWriter, in sproutActionInput) (controlplane.SproutAction, bool) {
	invalid := func(msg string) (controlplane.SproutAction, bool) {
		writeError(w, http.StatusBadRequest, "invalid_request", msg)
		return controlplane.SproutAction{}, false
	}
	var params any
	switch in.Type {
	case controlplane.ActionCmdRun:
		var p cmdRunInput
		if err := decodeParams(in.Params, &p); err != nil {
			return invalid("cmd.run params must be an object with cmd and optionally args, cwd, run_as, timeout_seconds")
		}
		out, msg := translateCmdRun(p)
		if msg != "" {
			return invalid(msg)
		}
		params = out
	case controlplane.ActionCook:
		var p cookInput
		if err := decodeParams(in.Params, &p); err != nil {
			return invalid("cook params must be an object with recipe and optionally test")
		}
		out, msg := translateCook(p)
		if msg != "" {
			return invalid(msg)
		}
		params = out
	case "":
		return invalid("action.type is required")
	default:
		writeError(w, http.StatusBadRequest, "unsupported_action", "action.type must be cmd.run or cook")
		return controlplane.SproutAction{}, false
	}
	b, err := json.Marshal(params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to encode action")
		return controlplane.SproutAction{}, false
	}
	return controlplane.SproutAction{Type: in.Type, Params: b}, true
}

// decodeParams strictly decodes an action's params object: missing or
// null params, and unknown fields, are errors.
func decodeParams(raw json.RawMessage, v any) error {
	if len(raw) == 0 || string(raw) == "null" {
		return errors.New("params are required")
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// shellSyntax is what translateCmdRun refuses in a cmd it has to split on
// whitespace: quoting, escapes and shell operators, none of which mean
// anything without a shell. A caller who needs one of these characters in
// an argument passes the arguments in args instead.
const shellSyntax = "\"'\\`$|&;<>(){}*?[]~\n\r"

// translateCmdRun maps cmd.run's external params onto farmer's, returning
// a caller-facing message on a validation failure.
func translateCmdRun(p cmdRunInput) (farmerCmdRun, string) {
	var out farmerCmdRun
	cmd := strings.TrimSpace(p.Cmd)
	switch {
	case cmd == "":
		return out, "cmd.run requires cmd"
	case len(p.Cmd) > maxCmdLen:
		return out, "cmd is too long"
	case strings.ContainsRune(p.Cmd, 0):
		return out, "cmd must not contain NUL bytes"
	case len(p.Args) > maxCmdArgs:
		return out, "too many args"
	case p.TimeoutSeconds < 0 || time.Duration(p.TimeoutSeconds)*time.Second > maxCmdTimeout:
		return out, fmt.Sprintf("timeout_seconds must be between 1 and %d", int(maxCmdTimeout/time.Second))
	}
	if p.Args == nil {
		if strings.ContainsAny(cmd, shellSyntax) {
			return out, "cmd is not run through a shell: quoting, escapes and shell operators aren't supported; pass the executable in cmd and each argument in args"
		}
		fields := strings.Fields(cmd)
		out.Command, out.Args = fields[0], fields[1:]
	} else {
		out.Command = cmd
		for _, a := range p.Args {
			if len(a) > maxCmdLen || strings.ContainsRune(a, 0) {
				return out, "each arg must be at most 4096 bytes and contain no NUL bytes"
			}
		}
		out.Args = p.Args
	}
	out.CWD = p.CWD
	out.RunAs = p.RunAs
	if len(out.CWD) > maxCmdLen || len(out.RunAs) > maxRecipeLen {
		return out, "cwd or run_as is too long"
	}
	out.Timeout = defaultCmdTimeout
	if p.TimeoutSeconds > 0 {
		out.Timeout = time.Duration(p.TimeoutSeconds) * time.Second
	}
	return out, ""
}

// translateCook maps cook's external params onto farmer's. The recipe name
// itself is resolved and validated by farmer.
func translateCook(p cookInput) (farmerCook, string) {
	recipe := strings.TrimSpace(p.Recipe)
	switch {
	case recipe == "":
		return farmerCook{}, "cook requires recipe"
	case len(recipe) > maxRecipeLen:
		return farmerCook{}, "recipe is too long"
	case strings.ContainsAny(recipe, " \t\r\n\x00"):
		return farmerCook{}, "recipe must not contain whitespace or NUL bytes"
	}
	return farmerCook{Recipe: recipe, Test: p.Test}, ""
}

// createActionBatch writes a §1.5 batch and its items in one transaction
// and returns the items that need dispatching.
func createActionBatch(tenantID string, assetIDs []string, action controlplane.SproutAction, resolved []sproutByAssetItem) (AssetActionBatch, []AssetActionItem, error) {
	return createBatch(AssetActionBatch{
		TenantID:     tenantID,
		ActionType:   action.Type,
		ActionParams: string(action.Params),
	}, assetIDs, resolved, nil, nil)
}

// createBatch writes batch (its ID and RequestedAssetIDs are filled in
// here) and one item per asset_id in one transaction, and returns the
// queued items in request order. blocked maps a resolved, accepted
// sprout to the error code its item fails with instead of being queued.
// claim, if set, runs first inside the same transaction; an error from it
// rolls everything back and is returned as is.
func createBatch(batch AssetActionBatch, assetIDs []string, resolved []sproutByAssetItem,
	blocked map[SproutRef]string, claim func(tx *gorm.DB) error) (AssetActionBatch, []AssetActionItem, error) {
	id, err := newID(actionBatchIDPrefix)
	if err != nil {
		return AssetActionBatch{}, nil, err
	}
	requested, err := json.Marshal(assetIDs)
	if err != nil {
		return AssetActionBatch{}, nil, err
	}
	batch.ID = id
	batch.RequestedAssetIDs = string(requested)
	tenantID := batch.TenantID

	byAsset := make(map[string]sproutByAssetItem, len(resolved))
	for _, row := range resolved {
		byAsset[row.AssetID] = row
	}
	items := make([]AssetActionItem, 0, len(assetIDs))
	var queued []AssetActionItem
	for i, assetID := range assetIDs {
		item := AssetActionItem{BatchID: id, AssetID: assetID, TenantID: tenantID, Position: i}
		row, found := byAsset[assetID]
		switch {
		case !found:
			item.Status = ActionItemUnresolved
		case row.KeyState != keyStateAccepted:
			item.SproutID = row.SproutID
			item.Status = ActionItemFailed
			item.ErrorCode = errCodeSproutNotAccepted
		case blocked[SproutRef{TenantID: tenantID, SproutID: row.SproutID}] != "":
			item.SproutID = row.SproutID
			item.Status = ActionItemFailed
			item.ErrorCode = blocked[SproutRef{TenantID: tenantID, SproutID: row.SproutID}]
		default:
			item.SproutID = row.SproutID
			item.Status = ActionItemQueued
		}
		items = append(items, item)
	}

	err = db.Transaction(func(tx *gorm.DB) error {
		if claim != nil {
			if err := claim(tx); err != nil {
				return err
			}
		}
		if err := tx.Create(&batch).Error; err != nil {
			return err
		}
		return tx.Create(&items).Error
	})
	if err != nil {
		return AssetActionBatch{}, nil, err
	}
	for _, it := range items {
		if it.Status == ActionItemQueued {
			queued = append(queued, it)
		}
	}
	return batch, queued, nil
}

var (
	// replyTimeoutFor is dispatchReplyTimeout, indirected so tests can
	// exercise the no-reply path without waiting it out.
	replyTimeoutFor = dispatchReplyTimeout

	// actionDispatchSlots bounds in-flight internal.sprout.action requests
	// process-wide (maxConcurrentActionDispatches).
	actionDispatchSlots = make(chan struct{}, maxConcurrentActionDispatches)
	// actionDispatches tracks background dispatchBatch goroutines, so
	// tests can wait for them before tearing down the database.
	actionDispatches sync.WaitGroup
)

// startBatchDispatch sends a new batch's queued items to farmer in the
// background. The database and bus handles are captured now, so the
// goroutine never sees them change under it.
func startBatchDispatch(batch AssetActionBatch, items []AssetActionItem) {
	if len(items) == 0 {
		return
	}
	d, nc := db, bus
	actionDispatches.Add(1)
	go func() {
		defer actionDispatches.Done()
		dispatchBatch(d, nc, batch, items)
	}()
}

// dispatchBatch sends one internal.sprout.action request per item, at most
// maxConcurrentActionDispatches at a time process-wide, and returns once
// every item has been answered or given up on.
//
// With no bus connection, every item stays queued and nothing is sent —
// the same as publishProvisioningJob leaves a job pending. Re-dispatching
// queued items is the outbox sweeper's job, deferred for this table as for
// provisioning_jobs (see docs/design/imas-internal-api-account.md).
func dispatchBatch(d *gorm.DB, nc *nats.Conn, batch AssetActionBatch, items []AssetActionItem) {
	if nc == nil {
		log.Errorf("saasapi: not connected to the NATS bus; action batch %s (tenant %s) left queued", batch.ID, batch.TenantID)
		return
	}
	var wg sync.WaitGroup
	for _, item := range items {
		actionDispatchSlots <- struct{}{}
		wg.Add(1)
		go func(item AssetActionItem) {
			defer wg.Done()
			defer func() { <-actionDispatchSlots }()
			dispatchItem(d, nc, batch, item)
		}(item)
	}
	wg.Wait()
}

// dispatchReplyTimeout is how long to wait for farmer's reply to an action:
// farmer's own worst case (farmerSproutWait, plus a cmd.run's timeout)
// plus dispatchReplyMargin. It is derived from the params as stored, so a
// re-dispatch of the same item waits the same.
func dispatchReplyTimeout(actionType, params string) time.Duration {
	wait := farmerSproutWait + dispatchReplyMargin
	if actionType == controlplane.ActionCmdRun {
		var p farmerCmdRun
		if err := json.Unmarshal([]byte(params), &p); err == nil && p.Timeout > 0 && p.Timeout <= maxCmdTimeout {
			wait += p.Timeout
		} else {
			wait += maxCmdTimeout
		}
	}
	return wait
}

// itemScope is the WHERE clause every item update uses: the item's full
// key plus its tenant, plus the status the update expects to find, so a
// state transition only ever applies once.
const itemScope = "batch_id = ? AND asset_id = ? AND tenant_id = ? AND status = ?"

// updateItem moves an item from status `from` to whatever update sets,
// reporting whether it did (false if the item was no longer in `from`).
func updateItem(d *gorm.DB, item AssetActionItem, from AssetActionItemStatus, update map[string]any) (bool, error) {
	r := d.Model(&AssetActionItem{}).Where(itemScope, item.BatchID, item.AssetID, item.TenantID, from).Updates(update)
	return r.RowsAffected > 0, r.Error
}

// dispatchItem sends one item to farmer on internal.sprout.action and
// records the outcome.
//
// The item is claimed first by moving it queued -> dispatching (counting
// the attempt); if that doesn't apply, someone else already owns it and
// nothing is sent. From then on:
//
//   - no responders: no farmer was subscribed, so the request provably
//     went nowhere — back to queued, safe to send again.
//   - any other request error (timeout, connection lost mid-request), an
//     unreadable reply, or one naming a different tenant or sprout:
//     failed/dispatch_outcome_unknown. The action may have run, so the
//     item is terminal rather than re-sendable — cmd.run isn't
//     idempotent.
//   - a reply: applied by replyUpdate.
func dispatchItem(d *gorm.DB, nc *nats.Conn, batch AssetActionBatch, item AssetActionItem) {
	data, err := json.Marshal(controlplane.SproutActionRequest{
		TenantID: batch.TenantID,
		SproutID: item.SproutID,
		Action:   controlplane.SproutAction{Type: batch.ActionType, Params: json.RawMessage(batch.ActionParams)},
	})
	if err != nil {
		log.Errorf("saasapi: marshalling %s for batch %s asset %s: %v — item left queued", controlplane.SubjectSproutAction, batch.ID, item.AssetID, err)
		return
	}

	claimed, err := updateItem(d, item, ActionItemQueued, map[string]any{
		"status":   ActionItemDispatching,
		"attempts": gorm.Expr("attempts + 1"),
	})
	if err != nil || !claimed {
		if err != nil {
			log.Errorf("saasapi: claiming batch %s asset %s for dispatch: %v — not sent", batch.ID, item.AssetID, err)
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), replyTimeoutFor(batch.ActionType, batch.ActionParams))
	defer cancel()
	msg, err := nc.RequestWithContext(ctx, controlplane.SubjectSproutAction, data)

	var update map[string]any
	switch {
	case errors.Is(err, nats.ErrNoResponders):
		log.Errorf("saasapi: no farmer subscribed to %s; batch %s asset %s left queued", controlplane.SubjectSproutAction, batch.ID, item.AssetID)
		update = map[string]any{"status": ActionItemQueued}
	case err != nil:
		log.Errorf("saasapi: %s for batch %s asset %s (tenant %s, sprout %s) got no reply: %v — outcome unknown",
			controlplane.SubjectSproutAction, batch.ID, item.AssetID, batch.TenantID, item.SproutID, err)
		update = failedUpdate(errCodeDispatchOutcomeUnknown)
	default:
		update = replyUpdate(batch, item, msg.Data)
	}
	if _, err := updateItem(d, item, ActionItemDispatching, update); err != nil {
		log.Errorf("saasapi: recording outcome for batch %s asset %s: %v", batch.ID, item.AssetID, err)
	}
}

// jobTracked reports whether actionType is answered with a jid and then
// followed through farmer.job_status: cook, and self_update. Farmer
// replies to a self_update, like a cook, dispatched with the jid of the
// sprout's one-step selfupdate job, whose outcome is the update's.
func jobTracked(actionType string) bool {
	return actionType == controlplane.ActionCook || actionType == controlplane.ActionSelfUpdate
}

func failedUpdate(code string) map[string]any {
	return map[string]any{"status": ActionItemFailed, "error_code": code}
}

// replyUpdate maps farmer's internal.sprout.action reply onto the item's
// new state. Only a reply for exactly this tenant and sprout, whose status
// fits the action type, is believed; anything else is logged and recorded
// as dispatch_outcome_unknown or internal_error.
func replyUpdate(batch AssetActionBatch, item AssetActionItem, data []byte) map[string]any {
	var reply controlplane.SproutActionReply
	if err := json.Unmarshal(data, &reply); err != nil {
		log.Errorf("saasapi: unreadable %s reply for batch %s asset %s: %v", controlplane.SubjectSproutAction, batch.ID, item.AssetID, err)
		return failedUpdate(errCodeDispatchOutcomeUnknown)
	}
	if reply.TenantID != batch.TenantID || reply.SproutID != item.SproutID {
		log.Errorf("saasapi: %s reply for batch %s asset %s names tenant %q sprout %q, want %q %q",
			controlplane.SubjectSproutAction, batch.ID, item.AssetID, reply.TenantID, reply.SproutID, batch.TenantID, item.SproutID)
		return failedUpdate(errCodeDispatchOutcomeUnknown)
	}

	switch {
	case reply.Status == controlplane.StatusFailed:
		return failedUpdate(farmerErrorCode(reply.ErrorCode))
	case reply.Status == controlplane.StatusCompleted && batch.ActionType == controlplane.ActionCmdRun && reply.Result != nil:
		exit := reply.Result.ExitCode
		if exit == 0 {
			return map[string]any{"status": ActionItemSucceeded, "exit_code": exit}
		}
		return map[string]any{"status": ActionItemFailed, "error_code": errCodeCommandFailed, "exit_code": exit}
	case reply.Status == controlplane.StatusDispatched && jobTracked(batch.ActionType) && controlplane.ValidJobID(reply.JID):
		return map[string]any{"status": ActionItemRunning, "jid": reply.JID}
	default:
		log.Errorf("saasapi: unexpected %s reply for batch %s asset %s (%s): status %q, jid %q, result set %t",
			controlplane.SubjectSproutAction, batch.ID, item.AssetID, batch.ActionType, reply.Status, reply.JID, reply.Result != nil)
		return failedUpdate(string(controlplane.ErrorInternal))
	}
}

// JobRef names one farmer job. SproutID is only meaningful together with
// the tenant it's looked up under: sprout_id is unique per tenant only.
type JobRef struct {
	SproutID string
	JID      string
}

// JobOutcome is a farmer job's state as a JobStatusReader reports it.
type JobOutcome string

const (
	JobOutcomeRunning   JobOutcome = "running"
	JobOutcomeSucceeded JobOutcome = "succeeded"
	JobOutcomeFailed    JobOutcome = "failed"
	// JobOutcomeExpired: farmer stopped tracking the job because it
	// started too long after dispatch. Terminal, and not a success.
	JobOutcomeExpired JobOutcome = "expired"
)

// JobStatusReader is the local, no-NATS read §1.5 polls running items
// through. Implementations must scope every lookup by tenantID as well as
// sprout and jid, and simply omit jobs they can't find.
//
// The production implementation is farmerJobStatusReader (job_status.go),
// over farmer's tenant-keyed farmer.job_status index. The design doc calls
// this read "farmer.jobs"; farmer.job_status is that table.
type JobStatusReader interface {
	JobOutcomes(ctx context.Context, tenantID string, jobs []JobRef) (map[JobRef]JobOutcome, error)
}

// jobStatusReader defaults to the farmer.job_status reader. SetJobStatusReader
// replaces it; nil means running items aren't refreshed.
var jobStatusReader JobStatusReader = farmerJobStatusReader{}

// SetJobStatusReader replaces the reader GET .../sprouts/actions/{batch_id}
// refreshes running items through (farmerJobStatusReader by default). Call
// once at startup, before NewRouter's handlers serve requests.
func SetJobStatusReader(r JobStatusReader) { jobStatusReader = r }

// refreshRunningItems asks the JobStatusReader about every running item
// with a jid, and records any that has finished: in items, and in its row
// (conditionally on its still being running, so a concurrent GET applying
// the same outcome is a no-op). A reader error leaves every item as
// stored — polling degrades to stale, never to a failed request.
func refreshRunningItems(ctx context.Context, tenantID string, items []AssetActionItem) {
	refreshItems(ctx, db, jobStatusReader, tenantID, items)
}

// refreshItems is refreshRunningItems with the database and reader passed
// in, for callers (the fleet update rollout) that captured them earlier.
func refreshItems(ctx context.Context, d *gorm.DB, reader JobStatusReader, tenantID string, items []AssetActionItem) {
	if reader == nil {
		return
	}
	var refs []JobRef
	for _, it := range items {
		if it.Status == ActionItemRunning && it.JID != "" {
			refs = append(refs, JobRef{SproutID: it.SproutID, JID: it.JID})
		}
	}
	if len(refs) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, jobRefreshTimeout)
	defer cancel()
	outcomes, err := reader.JobOutcomes(ctx, tenantID, refs)
	if err != nil {
		log.Warnf("saasapi: refreshing %d running action items for tenant %s: %v", len(refs), tenantID, err)
		return
	}
	for i := range items {
		it := &items[i]
		if it.Status != ActionItemRunning || it.JID == "" {
			continue
		}
		var update map[string]any
		switch outcomes[JobRef{SproutID: it.SproutID, JID: it.JID}] {
		case JobOutcomeSucceeded:
			update = map[string]any{"status": ActionItemSucceeded}
		case JobOutcomeFailed:
			update = failedUpdate(errCodeJobFailed)
		case JobOutcomeExpired:
			update = failedUpdate(errCodeJobExpired)
		default:
			continue
		}
		if _, err := updateItem(d, *it, ActionItemRunning, update); err != nil {
			log.Errorf("saasapi: recording job %s outcome for batch %s asset %s: %v", it.JID, it.BatchID, it.AssetID, err)
			continue
		}
		it.Status = update["status"].(AssetActionItemStatus)
		if code, ok := update["error_code"].(string); ok {
			it.ErrorCode = code
		}
	}
}
