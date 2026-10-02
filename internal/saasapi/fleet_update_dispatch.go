// Fleet update dispatch, the dispatch half of design doc §1.8: POST
// /tenants/{tenant_id}/sprouts/updates and GET .../sprouts/updates/{batch_id}.
//
// OFF BY DEFAULT. Release signing and registration exist (§2.5):
// cmd/fleetreleaser signs each saas.fleet_versions row, one per OS/arch, and
// saasapi (selfUpdateParams) verifies every row of the target version
// before creating a rollout. But the sprout-side manifest fetch and install
// (§2.6, FU.1/FU.2) don't exist yet, and farmer's self_update handler still
// expects the pre-FU.3 params (an artifact URL and one row's signature),
// which saasapi no longer sends, so farmer refuses every item. §1.8 and §6
// say not to expose this endpoint until that's resolved. So both routes are
// registered only when SetFleetUpdateDispatchEnabled(true) has been called
// before NewRouter
// (Config.FleetUpdateDispatchEnabled, SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED),
// and the handlers check the flag again themselves. With the flag off,
// neither route exists.
//
// An update rollout is an ordinary §1.5 batch whose action.type is
// self_update. It uses the same saas.asset_action_batches/asset_action_items
// rows, asset_id resolution, per-item dispatch and job-status polling as
// sprout_actions.go, and the same tenant-safety rules listed at the top of
// that file. Differences, all for rollout safety (§2.3):
//
//   - The caller names a target_version, not action params. The version
//     must be in CloudXP's own catalog (saas.fleet_versions), not
//     revoked, and every one of its OS/arch rows must carry a signature
//     that verifies. The farmer params carry only the version: each sprout
//     resolves and verifies its own OS/arch manifest (§2.3, §2.6). The
//     caller can't supply a URL, file name or checksum.
//   - The version must be the tenant's approved_version
//     (saas.tenant_update_policy), and now must be inside the tenant's
//     rollout window if one is set. Both, and that the version hasn't been
//     revoked, are checked again before every wave, so withdrawing
//     approval, revoking the version or reaching the end of the window
//     stops the rollout.
//   - Items go out in waves of batch_size, not all at once, and each wave
//     must pass its gate before the next is sent. The defaults are a small
//     wave (defaultUpdateBatchSize) and the strict job_status gate. A §1.5
//     batch sends every item at once and doesn't wait on anything.
//   - Once any wave fails its gate, every item not yet sent is failed with
//     rollout_halted and is never sent.
//   - A sprout that doesn't report its update's outcome before the wave
//     deadline gets its own status, unresponsive_after_update, not a plain
//     failed. The operator's response is different: the sprout's
//     backup/restore path may already have recovered it.
//   - A sprout that already has an unfinished self_update item in another
//     batch of the same tenant isn't sent a second one
//     (update_already_in_progress).
//
// The rollout runs in a background goroutine in the process that accepted
// the POST, like §1.5's dispatch. If that process exits, unsent items stay
// queued until the outbox sweeper exists (deferred, see
// docs/design/imas-internal-api-account.md).
package saasapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/fleetsign"
	log "github.com/yogzblr/imas/internal/log"
)

// fleetUpdateDispatchEnabled is the feature flag. It defaults to false.
var fleetUpdateDispatchEnabled bool

// SetFleetUpdateDispatchEnabled turns POST .../sprouts/updates and GET
// .../sprouts/updates/{batch_id} on or off. Like SetDB and SetAuthConfig,
// call it once at startup, before NewRouter: NewRouter registers the routes
// only if the flag is on at that point.
//
// Don't turn it on in a deployment until sprout has a real signed
// self-update path (yogzblr/imas#286; design doc §1.8, §6).
func SetFleetUpdateDispatchEnabled(enabled bool) { fleetUpdateDispatchEnabled = enabled }

// Rollout gates. A gate decides when a wave counts as passed, so the next
// wave can be sent.
const (
	// gateJobStatus: every item in the wave has succeeded. For a sprout
	// that means its update job has finished successfully in
	// farmer.job_status. This is the default.
	gateJobStatus = "job_status"
	// gateDispatch: farmer accepted every item in the wave, without
	// waiting for the updates to finish. It's the looser gate and must
	// be asked for explicitly.
	gateDispatch = "dispatch"
	// gateProbe is §1.8's example gate. It needs workstream L's probe
	// health signal, which doesn't exist yet, so it's rejected rather
	// than handled like one of the gates above.
	gateProbe = "probe"
)

const (
	// defaultUpdateBatchSize is the wave size when the request doesn't set
	// one. A §1.5 batch sends up to maxAssetIDsPerLookup items at once.
	defaultUpdateBatchSize = 5
	// maxUpdateBatchSize caps a wave, even if the caller asks for more:
	// no single wave of an update touches more machines than this.
	maxUpdateBatchSize = 25

	// maxUpdateRequestBytes bounds POST .../sprouts/updates' body.
	maxUpdateRequestBytes = 64 << 10
)

var (
	// rolloutWaveTimeout is how long a job_status wave may take, after
	// its dispatch replies, before its unfinished items are marked
	// unresponsive_after_update and the rollout halts.
	rolloutWaveTimeout = 30 * time.Minute
	// rolloutPollInterval is how often a job_status wave's job outcomes
	// are re-read while the rollout waits on it.
	rolloutPollInterval = 15 * time.Second
	// rolloutNow is time.Now, replaceable in tests.
	rolloutNow = time.Now
)

// Item error codes for rollouts, in addition to sprout_actions.go's.
const (
	// errCodeRolloutHalted: an earlier wave didn't pass its gate, so this
	// item was never sent.
	errCodeRolloutHalted = "rollout_halted"
	// errCodeRolloutWindowClosed: the tenant's rollout window ended before
	// this item's wave was due, so it was never sent.
	errCodeRolloutWindowClosed = "rollout_window_closed"
	// errCodeApprovalWithdrawn: the tenant's approved_version stopped being
	// this rollout's target before this item's wave was due, so it was
	// never sent.
	errCodeApprovalWithdrawn = "version_approval_withdrawn"
	// errCodeVersionRevoked: the target version was revoked (POST
	// /v1/operator/fleet-releases/{version}/revoke) before this item's wave
	// was due, so it was never sent.
	errCodeVersionRevoked = "version_revoked"
	// errCodeUpdateInProgress: the sprout already had an unfinished update
	// in another batch, so this item was never sent.
	errCodeUpdateInProgress = "update_already_in_progress"
	// errCodeUnresponsiveAfterUpdate goes with the
	// ActionItemUnresponsiveAfterUpdate status.
	errCodeUnresponsiveAfterUpdate = "unresponsive_after_update"
)

// fleetUpdateRequest is POST .../sprouts/updates' body (design doc §1.8).
// BatchSize is a pointer so that an omitted value (use the default) is
// distinct from an explicit 0 (rejected).
type fleetUpdateRequest struct {
	AssetIDs      []string `json:"asset_ids"`
	TargetVersion string   `json:"target_version"`
	BatchSize     *int     `json:"batch_size"`
	Gate          string   `json:"gate"`
}

// farmerSelfUpdate is the params of a self_update internal.sprout.action,
// in the shape design doc §2.2 gives, signature included (§2.5).
type farmerSelfUpdate = controlplane.SelfUpdateParams

// fleetKeys is the READ-ONLY imas-fleet-signing key source catalog rows
// are verified against before a rollout is created (§2.5). Set once at
// startup by SetFleetKeySource; while nil, every rollout is refused.
var fleetKeys fleetsign.KeySetSource

// SetFleetKeySource installs the key source. Like SetDB, call it once at
// startup. The OpenBao token behind it (IMAS_FLEETSIGN_OPENBAO_*) must
// carry only the read-only imas-fleet-verify policy: saasapi can write
// saas.fleet_versions, so it must never also be able to sign rows
// (deploy/fleetreleaser/README.md).
func SetFleetKeySource(src fleetsign.KeySetSource) { fleetKeys = src }

// rolloutResponse describes a rollout batch in the GET response. It's
// omitted for §1.5 batches.
type rolloutResponse struct {
	TargetVersion string `json:"target_version"`
	BatchSize     int    `json:"batch_size"`
	Gate          string `json:"gate"`
}

// CreateFleetUpdateBatch handles POST /tenants/{tenant_id}/sprouts/updates
// (design doc §1.8). It's only registered when the feature flag is on.
//
// The request is checked in this order, and nothing is written until all of
// it passes: the tenant is active; the body is valid; target_version is in
// the catalog (else 400 unknown_version) with every row's signature valid
// (else 500); it's the tenant's approved_version (else 409
// version_not_approved); it isn't revoked (else 409 version_revoked); now is
// inside the tenant's rollout window if one is set (else 409
// outside_rollout_window). Then the batch and its items are written as in
// §1.5, the 202 is sent, and runRollout starts in the background.
//
// Rate-limited per tenant (see router.go).
func CreateFleetUpdateBatch(w http.ResponseWriter, r *http.Request) {
	if !fleetUpdateDispatchEnabled {
		writeError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	tenantID := r.PathValue("tenant_id")
	if !tenantActive(w, tenantID) {
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxUpdateRequestBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req fleetUpdateRequest
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"request body must be valid JSON with asset_ids, target_version and optionally batch_size, gate")
		return
	}
	assetIDs, ok := parseActionAssetIDs(w, req.AssetIDs)
	if !ok {
		return
	}
	batchSize, ok := parseUpdateBatchSize(w, req.BatchSize)
	if !ok {
		return
	}
	gate, ok := parseUpdateGate(w, req.Gate)
	if !ok {
		return
	}
	version := strings.TrimSpace(req.TargetVersion)
	switch {
	case version == "":
		writeError(w, http.StatusBadRequest, "invalid_request", "target_version is required")
		return
	case len(version) > maxFleetVersionLen:
		writeError(w, http.StatusBadRequest, "invalid_request", "target_version is too long")
		return
	}

	var versions []FleetVersion
	if err := db.Where("version = ?", version).Order("os").Order("arch").Find(&versions).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to look up version")
		return
	}
	if len(versions) == 0 {
		writeError(w, http.StatusBadRequest, "unknown_version", "target_version is not in the version catalog")
		return
	}
	params, err := selfUpdateParams(r.Context(), versions)
	if err != nil {
		log.Errorf("saasapi: fleet_versions entry %s is unusable for dispatch: %v", version, err)
		writeError(w, http.StatusInternalServerError, "internal_error", "the catalog entry for this version is invalid; contact support")
		return
	}

	switch code, err := rolloutPolicyCheck(db, tenantID, version, rolloutNow()); {
	case err != nil:
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to look up update policy")
		return
	case code == errCodeApprovalWithdrawn:
		writeError(w, http.StatusConflict, "version_not_approved",
			"target_version is not the tenant's approved version; approve it with PATCH .../update-policy first")
		return
	case code == errCodeVersionRevoked:
		writeError(w, http.StatusConflict, "version_revoked", "target_version has been revoked")
		return
	case code == errCodeRolloutWindowClosed:
		writeError(w, http.StatusConflict, "outside_rollout_window", "now is outside the tenant's rollout window")
		return
	}

	rows, err := resolveAssetIDs(tenantID, assetIDs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to resolve asset ids")
		return
	}
	busy, err := sproutsWithUpdateInProgress(db, tenantID, rows)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to check for updates in progress")
		return
	}
	blocked := make(map[string]string, len(busy))
	for sproutID := range busy {
		blocked[sproutID] = errCodeUpdateInProgress
	}

	batch, queued, err := createBatch(AssetActionBatch{
		TenantID:         tenantID,
		ActionType:       controlplane.ActionSelfUpdate,
		ActionParams:     string(params),
		RolloutBatchSize: batchSize,
		RolloutGate:      gate,
	}, assetIDs, rows, blocked)
	if err != nil {
		log.Errorf("saasapi: creating update batch for tenant %s: %v", tenantID, err)
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to create update batch")
		return
	}
	log.Infof("saasapi: update batch %s (tenant %s): target %s, %d asset_ids, %d queued, batch_size %d, gate %s",
		batch.ID, tenantID, version, len(assetIDs), len(queued), batchSize, gate)
	writeJSON(w, http.StatusAccepted, createActionBatchResponse{BatchID: batch.ID})
	startRollout(batch, queued, version)
}

// GetFleetUpdateBatch handles GET
// /tenants/{tenant_id}/sprouts/updates/{batch_id} (design doc §1.8). The
// response has the same shape as GET .../sprouts/actions/{batch_id}. Only
// self_update batches are found here: a §1.5 batch's id gives 404.
func GetFleetUpdateBatch(w http.ResponseWriter, r *http.Request) {
	if !fleetUpdateDispatchEnabled {
		writeError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	writeBatchStatus(w, r, controlplane.ActionSelfUpdate)
}

// parseUpdateBatchSize applies defaultUpdateBatchSize when batch_size is
// omitted, and rejects anything outside 1..maxUpdateBatchSize.
func parseUpdateBatchSize(w http.ResponseWriter, n *int) (int, bool) {
	if n == nil {
		return defaultUpdateBatchSize, true
	}
	if *n < 1 || *n > maxUpdateBatchSize {
		writeErrorDetails(w, http.StatusBadRequest, "invalid_request", "batch_size must be between 1 and 25",
			map[string]any{"min": 1, "max": maxUpdateBatchSize})
		return 0, false
	}
	return *n, true
}

// parseUpdateGate applies gateJobStatus when gate is omitted.
func parseUpdateGate(w http.ResponseWriter, gate string) (string, bool) {
	switch gate {
	case "":
		return gateJobStatus, true
	case gateJobStatus, gateDispatch:
		return gate, true
	case gateProbe:
		writeError(w, http.StatusBadRequest, "unsupported_gate", "the probe gate is not available yet; use job_status or dispatch")
	default:
		writeError(w, http.StatusBadRequest, "unsupported_gate", "gate must be job_status or dispatch")
	}
	return "", false
}

// selfUpdateParams builds the farmer params for a rollout to one version,
// given all of its saas.fleet_versions rows (one per OS/arch). Every row must
// carry a signature that verifies against the imas-fleet-signing key
// (read-only) over its own manifest fields; one that doesn't, an empty
// signature included, refuses the whole rollout rather than sending it to
// part of a fleet. Revocation is rolloutPolicyCheck's to report. Farmer
// and the sprout each verify again; this is the early, whole-batch
// refusal, not the only one.
//
// The params carry the version only: each sprout fetches and verifies
// the manifest for its own OS and arch (§2.6), so no URL, file name,
// checksum or signature travels in the command.
func selfUpdateParams(ctx context.Context, rows []FleetVersion) (json.RawMessage, error) {
	if len(rows) == 0 {
		return nil, errors.New("no catalog rows")
	}
	if fleetKeys == nil {
		return nil, errors.New("no fleet signing key source configured; refusing to dispatch unverified releases")
	}
	ks, err := fleetKeys.KeySet(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading fleet signing keys: %w", err)
	}
	for _, row := range rows {
		if row.Version != rows[0].Version {
			return nil, fmt.Errorf("rows of different versions (%s, %s)", rows[0].Version, row.Version)
		}
		if err := ks.Verify(row.Manifest()); err != nil {
			return nil, fmt.Errorf("%s/%s signature: %w", row.OS, row.Arch, err)
		}
	}
	return json.Marshal(farmerSelfUpdate{Version: rows[0].Version})
}

// rolloutPolicyCheck compares the tenant's update policy and the catalog
// with a rollout of version at now. It returns "" if the rollout may go
// ahead, errCodeApprovalWithdrawn if version isn't the approved_version
// (including when there's no policy row), errCodeVersionRevoked if version
// has been revoked, and errCodeRolloutWindowClosed if a window is set and
// now is outside [start, end).
func rolloutPolicyCheck(d *gorm.DB, tenantID, version string, now time.Time) (string, error) {
	var revoked int64
	if err := d.Model(&FleetVersion{}).Where("version = ? AND revoked = ?", version, true).Count(&revoked).Error; err != nil {
		return "", err
	}
	if revoked > 0 {
		return errCodeVersionRevoked, nil
	}
	var policies []TenantUpdatePolicy
	if err := d.Where("tenant_id = ?", tenantID).Limit(1).Find(&policies).Error; err != nil {
		return "", err
	}
	if len(policies) == 0 || policies[0].ApprovedVersion == nil || *policies[0].ApprovedVersion != version {
		return errCodeApprovalWithdrawn, nil
	}
	p := policies[0]
	if p.RolloutWindowStart != nil && p.RolloutWindowEnd != nil &&
		(now.Before(*p.RolloutWindowStart) || !now.Before(*p.RolloutWindowEnd)) {
		return errCodeRolloutWindowClosed, nil
	}
	return "", nil
}

// sproutsWithUpdateInProgress returns the sprouts among rows that have an
// unfinished (queued, dispatching or running) item in a self_update batch of
// this tenant. The query is scoped by tenant_id on both tables, since
// sprout_id is only unique within a tenant.
//
// It runs before the new batch is written, not in the same transaction, so
// two POSTs racing for the same sprout can both get past it. The per-tenant
// rate limit makes that unlikely, but it doesn't rule it out.
func sproutsWithUpdateInProgress(d *gorm.DB, tenantID string, rows []sproutByAssetItem) (map[string]bool, error) {
	var ids []string
	for _, row := range rows {
		ids = append(ids, row.SproutID)
	}
	busy := make(map[string]bool)
	if len(ids) == 0 {
		return busy, nil
	}
	var found []string
	err := d.Table(AssetActionItem{}.TableName()+" AS i").
		Joins("JOIN "+AssetActionBatch{}.TableName()+" AS b ON b.id = i.batch_id AND b.tenant_id = i.tenant_id").
		Where("i.tenant_id = ? AND b.action_type = ? AND i.status IN ? AND i.sprout_id IN ?",
			tenantID, controlplane.ActionSelfUpdate,
			[]AssetActionItemStatus{ActionItemQueued, ActionItemDispatching, ActionItemRunning}, ids).
		Distinct().Pluck("i.sprout_id", &found).Error
	if err != nil {
		return nil, err
	}
	for _, id := range found {
		busy[id] = true
	}
	return busy, nil
}

// startRollout runs a new update batch's rollout in the background. It
// captures the database, bus and job-status reader when it starts, like
// startBatchDispatch, and uses the same WaitGroup, so tests can wait for it.
func startRollout(batch AssetActionBatch, queued []AssetActionItem, version string) {
	if len(queued) == 0 {
		return
	}
	d, nc, reader := db, bus, jobStatusReader
	actionDispatches.Add(1)
	go func() {
		defer actionDispatches.Done()
		runRollout(d, nc, reader, batch, queued, version)
	}()
}

// runRollout sends queued (in request order) out in waves of
// batch.RolloutBatchSize. Before each wave it checks the tenant's policy
// again, and after each wave it waits for the gate. If the policy check or
// the gate fails, every item still queued is failed with the matching code
// and the rollout stops.
//
// With no bus connection nothing is sent and every item stays queued, the
// same as dispatchBatch. With the job_status gate and no JobStatusReader,
// the gate could never pass, so the rollout halts without sending
// anything.
func runRollout(d *gorm.DB, nc *nats.Conn, reader JobStatusReader, batch AssetActionBatch, queued []AssetActionItem, version string) {
	if nc == nil {
		log.Errorf("saasapi: not connected to the NATS bus; update batch %s (tenant %s) left queued", batch.ID, batch.TenantID)
		return
	}
	if batch.RolloutGate == gateJobStatus && reader == nil {
		log.Errorf("saasapi: no job status reader for update batch %s (tenant %s); halting before any wave", batch.ID, batch.TenantID)
		haltRollout(d, batch, string(controlplane.ErrorInternal))
		return
	}
	size := batch.RolloutBatchSize
	if size < 1 {
		size = 1
	}
	for start := 0; start < len(queued); start += size {
		wave := queued[start:min(start+size, len(queued))]

		code, err := rolloutPolicyCheck(d, batch.TenantID, version, rolloutNow())
		if err != nil {
			log.Errorf("saasapi: update batch %s (tenant %s): checking update policy: %v; halting", batch.ID, batch.TenantID, err)
			code = string(controlplane.ErrorInternal)
		}
		if code != "" {
			log.Warnf("saasapi: update batch %s (tenant %s) halted before wave %d: %s", batch.ID, batch.TenantID, start/size+1, code)
			haltRollout(d, batch, code)
			return
		}

		dispatchBatch(d, nc, batch, wave)
		if !awaitWave(d, reader, batch, wave) {
			log.Warnf("saasapi: update batch %s (tenant %s): wave %d did not pass the %s gate; halting",
				batch.ID, batch.TenantID, start/size+1, batch.RolloutGate)
			haltRollout(d, batch, errCodeRolloutHalted)
			return
		}
	}
	log.Infof("saasapi: update batch %s (tenant %s): all waves passed", batch.ID, batch.TenantID)
}

// awaitWave waits until wave passes or fails batch's gate, and reports
// whether it passed.
//
// dispatchBatch has already waited for farmer's replies, so with the
// dispatch gate the answer is known immediately: the wave passes if every
// item is running or succeeded. With the job_status gate, awaitWave polls the
// items' job outcomes until none is running (the wave passes if every item
// succeeded). If items are still running at rolloutWaveTimeout, they're marked
// unresponsive_after_update and the wave fails.
//
// An item still queued after dispatchBatch had no farmer to take it. It
// can't pass either gate, so the wave fails and haltRollout fails the item
// along with the rest.
func awaitWave(d *gorm.DB, reader JobStatusReader, batch AssetActionBatch, wave []AssetActionItem) bool {
	deadline := rolloutNow().Add(rolloutWaveTimeout)
	for {
		items, err := loadWaveItems(d, batch, wave)
		if err != nil {
			log.Errorf("saasapi: update batch %s: reading wave items: %v", batch.ID, err)
			return false
		}
		if batch.RolloutGate == gateDispatch {
			for _, it := range items {
				if it.Status != ActionItemRunning && it.Status != ActionItemSucceeded {
					return false
				}
			}
			return true
		}

		refreshItems(context.Background(), d, reader, batch.TenantID, items)
		settled, passed := true, true
		for _, it := range items {
			switch it.Status {
			case ActionItemRunning, ActionItemDispatching:
				settled = false
			case ActionItemSucceeded:
			default:
				passed = false
			}
		}
		if settled {
			return passed
		}
		if !rolloutNow().Before(deadline) {
			markUnresponsive(d, items)
			return false
		}
		time.Sleep(rolloutPollInterval)
	}
}

// loadWaveItems re-reads wave's rows, scoped by tenant.
func loadWaveItems(d *gorm.DB, batch AssetActionBatch, wave []AssetActionItem) ([]AssetActionItem, error) {
	assetIDs := make([]string, len(wave))
	for i, it := range wave {
		assetIDs[i] = it.AssetID
	}
	var items []AssetActionItem
	err := d.Where("batch_id = ? AND tenant_id = ? AND asset_id IN ?", batch.ID, batch.TenantID, assetIDs).
		Order("position").Find(&items).Error
	return items, err
}

// markUnresponsive moves every item still running to
// unresponsive_after_update. The update is conditional on the item still
// being running, so an outcome a concurrent GET has just recorded wins.
func markUnresponsive(d *gorm.DB, items []AssetActionItem) {
	for _, it := range items {
		if it.Status != ActionItemRunning {
			continue
		}
		if _, err := updateItem(d, it, ActionItemRunning, map[string]any{
			"status":     ActionItemUnresponsiveAfterUpdate,
			"error_code": errCodeUnresponsiveAfterUpdate,
		}); err != nil {
			log.Errorf("saasapi: marking batch %s asset %s unresponsive: %v", it.BatchID, it.AssetID, err)
		}
	}
}

// haltRollout fails every item of batch that's still queued with code.
// Items that were already sent are left alone: GET keeps refreshing them.
func haltRollout(d *gorm.DB, batch AssetActionBatch, code string) {
	err := d.Model(&AssetActionItem{}).
		Where("batch_id = ? AND tenant_id = ? AND status = ?", batch.ID, batch.TenantID, ActionItemQueued).
		Updates(failedUpdate(code)).Error
	if err != nil {
		log.Errorf("saasapi: halting update batch %s (tenant %s): %v", batch.ID, batch.TenantID, err)
	}
}

// rolloutOf returns the rollout part of batch's GET response, or nil for a
// batch that isn't a rollout.
func rolloutOf(batch AssetActionBatch) *rolloutResponse {
	if batch.ActionType != controlplane.ActionSelfUpdate {
		return nil
	}
	var p farmerSelfUpdate
	_ = json.Unmarshal([]byte(batch.ActionParams), &p)
	return &rolloutResponse{TargetVersion: p.Version, BatchSize: batch.RolloutBatchSize, Gate: batch.RolloutGate}
}
