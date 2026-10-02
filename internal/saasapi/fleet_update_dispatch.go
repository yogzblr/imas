// Fleet update dispatch, the dispatch half of design doc §1.8: POST
// /tenants/{tenant_id}/sprouts/updates and GET .../sprouts/updates/{batch_id}.
//
// OFF BY DEFAULT. Both routes are registered only when
// SetFleetUpdateDispatchEnabled(true) has been called before NewRouter
// (Config.FleetUpdateDispatchEnabled, SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED),
// and the handlers check the flag again themselves. With the flag off,
// neither route exists. The path behind it is complete: cmd/fleetreleaser
// signs each saas.fleet_versions row (§2.5); saasapi (selfUpdateParams)
// verifies every row of the target version before creating a rollout and
// sends farmer only {version}; farmer re-verifies that version against the
// catalog before dispatching it (internal/natsapi, checkSelfUpdateRelease);
// and the sprout fetches, verifies and installs its own OS/arch row (§2.6,
// internal/ingredients/selfupdate). Turning it on is a deployment decision,
// made by the Terraform UAT gate, not by this code.
//
// An update rollout is an ordinary §1.5 batch whose action.type is
// self_update. It uses the same saas.asset_action_batches/asset_action_items
// rows, asset_id resolution and per-item dispatch as sprout_actions.go, and
// the same tenant-safety rules listed at the top of that file. Differences,
// all for rollout safety (§2.3):
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
//     revoked, are checked again under the claim below and before every
//     wave, so withdrawing approval, revoking the version or reaching the
//     end of the window stops the rollout.
//   - A tenant has at most one update rollout in progress. The batch is
//     written in the same transaction that claims the tenant's
//     tenant_update_policy row (claimRollout), so two POSTs can't both
//     pass the check: one gets 409 update_in_progress.
//   - One batch may span OS and arch. Each sprout is resolved against the
//     target's catalog rows from what it last reported (fleet_sprout_facts.go):
//     a sprout whose OS/arch has no row, that runs a version older than
//     the release's min_sprout_version, or that already runs a newer
//     version is failed up front and never sent anything.
//   - Items go out in waves of batch_size, not all at once. The defaults are
//     a small wave (defaultUpdateBatchSize) and the strict job_status gate.
//     A §1.5 batch sends every item at once and doesn't wait on anything.
//   - Health-based completion. A self_update item succeeds only when its
//     sprout reconnects and reports the target version in its facts, not
//     when farmer accepts the command or the sprout's update job finishes
//     (refreshUpdateItems). A job that fails or expires fails the item.
//   - A sprout that doesn't come back on the target version before its
//     wave's deadline gets its own status, unresponsive_after_update, not a
//     plain failed. The operator's response is different: the sprout may be
//     unable to reconnect, or may have kept or restored its old version.
//   - Once any wave fails its gate, every item not yet sent is failed with
//     rollout_halted and is never sent.
//
// The rollout runs in a background goroutine in the process that accepted
// the POST, like §1.5's dispatch. If that process exits, unsent items stay
// queued until the outbox sweeper exists (deferred, see
// docs/design/imas-internal-api-account.md), and until then they also keep
// the tenant's one rollout slot taken.
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
	"golang.org/x/mod/semver"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

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
// It is off by default; turning it on is a deployment decision (design
// doc §1.8, §2.3).
func SetFleetUpdateDispatchEnabled(enabled bool) { fleetUpdateDispatchEnabled = enabled }

// Rollout gates. A gate decides when the next wave may be sent. Whatever
// the gate, every item of a wave that was sent is followed until its sprout
// reports the target version (succeeded), its job fails, or the wave's
// deadline passes (unresponsive_after_update).
const (
	// gateJobStatus: every item in the wave has succeeded, meaning its
	// sprout reconnected and reported the target version. A failed job
	// fails the wave at once. This is the default.
	gateJobStatus = "job_status"
	// gateDispatch: farmer accepted every item in the wave. The next wave
	// goes out without waiting for the sprouts to come back, but not once
	// any item already sent has failed or gone unresponsive. It's the
	// looser gate and must be asked for explicitly.
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
	// rolloutWaveTimeout is how long a wave's sprouts have, after its
	// dispatch replies, to come back on the target version before their
	// items are marked unresponsive_after_update.
	rolloutWaveTimeout = 30 * time.Minute
	// rolloutPollInterval is how often a wave's job outcomes and sprout
	// facts are re-read while the rollout waits on it.
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
	// in another batch, so this item was never sent. No longer written:
	// a second rollout for a tenant is now refused outright (409
	// update_in_progress). Kept so items stored before that still read
	// back with their message.
	errCodeUpdateInProgress = "update_already_in_progress"
	// errCodeUnresponsiveAfterUpdate goes with the
	// ActionItemUnresponsiveAfterUpdate status.
	errCodeUnresponsiveAfterUpdate = "unresponsive_after_update"
	// errCodeNoReleaseForPlatform: the sprout last reported an OS/arch
	// the target version has no catalog row for, so it was never sent
	// the update (it would only fail to find its manifest).
	errCodeNoReleaseForPlatform = "no_release_for_platform"
	// errCodeBelowMinSproutVersion: the sprout last reported a version
	// older than the target's signed min_sprout_version, which it would
	// refuse, so it was never sent the update.
	errCodeBelowMinSproutVersion = "below_min_sprout_version"
	// errCodeSproutNewerThanTarget: the sprout last reported a version
	// newer than the target. Sprouts refuse downgrades, so it was never
	// sent the update.
	errCodeSproutNewerThanTarget = "sprout_newer_than_target"
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

// farmerSelfUpdate is the params of a self_update internal.sprout.action:
// only the version (design doc §1.8). Farmer refuses any other field.
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
// The request is checked in this order: the tenant is active; the body is
// valid; target_version is in the catalog (else 400 unknown_version) with
// every row's signature valid (else 500); it's the tenant's
// approved_version (else 409 version_not_approved); it isn't revoked (else
// 409 version_revoked); now is inside the tenant's rollout window if one is
// set (else 409 outside_rollout_window). Each resolved sprout is then
// checked against the catalog rows for its own OS and arch
// (planUpdateItems). Finally, in one transaction, claimRollout locks the
// tenant's policy, repeats the policy checks, refuses a second rollout (409
// update_in_progress), and the batch and its items are written as in §1.5.
// Only then is the 202 sent and runRollout started in the background.
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
	if err := db.Where("version = ?", version).Order("os").Order("arch").Order("package_type").Find(&versions).Error; err != nil {
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

	// Checked here for an early answer, and again under claimRollout's
	// lock, which is the check that counts.
	code, err := rolloutPolicyCheck(db, tenantID, version, rolloutNow())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to look up update policy")
		return
	}
	if writeRolloutRefusal(w, rolloutRefused{code: code}) {
		return
	}

	rows, err := resolveAssetIDs(tenantID, assetIDs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to resolve asset ids")
		return
	}
	blocked, err := planUpdateItems(r.Context(), sproutFactsReader, tenantID, rows, versions)
	if err != nil {
		log.Errorf("saasapi: reading sprout facts for an update of tenant %s: %v", tenantID, err)
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to read sprout facts")
		return
	}

	batch, queued, err := createBatch(AssetActionBatch{
		TenantID:         tenantID,
		ActionType:       controlplane.ActionSelfUpdate,
		ActionParams:     string(params),
		RolloutBatchSize: batchSize,
		RolloutGate:      gate,
	}, assetIDs, rows, blocked, claimRollout(tenantID, version, rolloutNow()))
	var refused rolloutRefused
	switch {
	case errors.As(err, &refused):
		writeRolloutRefusal(w, refused)
		return
	case err != nil:
		log.Errorf("saasapi: creating update batch for tenant %s: %v", tenantID, err)
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to create update batch")
		return
	}
	log.Infof("saasapi: update batch %s (tenant %s): target %s, %d asset_ids, %d queued, %d refused per sprout, batch_size %d, gate %s",
		batch.ID, tenantID, version, len(assetIDs), len(queued), len(blocked), batchSize, gate)
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
			return nil, fmt.Errorf("%s signature: %w", row.releaseKey(), err)
		}
	}
	return json.Marshal(farmerSelfUpdate{Version: rows[0].Version})
}

// rolloutPolicyCheck compares the tenant's update policy and the catalog
// with a rollout of version at now. It returns "" if the rollout may go
// ahead, errCodeVersionRevoked if version has been revoked, or
// policyRefusal's code for the tenant's policy row (none counts as nothing
// approved).
func rolloutPolicyCheck(d *gorm.DB, tenantID, version string, now time.Time) (string, error) {
	if revoked, err := versionRevoked(d, version); err != nil || revoked {
		if revoked {
			return errCodeVersionRevoked, nil
		}
		return "", err
	}
	var policies []TenantUpdatePolicy
	if err := d.Where("tenant_id = ?", tenantID).Limit(1).Find(&policies).Error; err != nil {
		return "", err
	}
	var p *TenantUpdatePolicy
	if len(policies) > 0 {
		p = &policies[0]
	}
	return policyRefusal(p, version, now), nil
}

// versionRevoked reports whether any row of version has been revoked
// (revocation covers every row of a version at once).
func versionRevoked(d *gorm.DB, version string) (bool, error) {
	var revoked int64
	err := d.Model(&FleetVersion{}).Where("version = ? AND revoked = ?", version, true).Count(&revoked).Error
	return revoked > 0, err
}

// policyRefusal returns errCodeApprovalWithdrawn if version isn't p's
// approved_version (or there's no policy), errCodeRolloutWindowClosed if
// p sets a window and now is outside [start, end), and "" otherwise.
func policyRefusal(p *TenantUpdatePolicy, version string, now time.Time) string {
	if p == nil || p.ApprovedVersion == nil || *p.ApprovedVersion != version {
		return errCodeApprovalWithdrawn
	}
	if p.RolloutWindowStart != nil && p.RolloutWindowEnd != nil &&
		(now.Before(*p.RolloutWindowStart) || !now.Before(*p.RolloutWindowEnd)) {
		return errCodeRolloutWindowClosed
	}
	return ""
}

// rolloutRefused is a POST refused for a policy reason (code is a
// rolloutPolicyCheck code) or because the tenant already has a rollout in
// progress (code errCodeUpdateInProgress, batchID that rollout).
type rolloutRefused struct {
	code    string
	batchID string
}

func (e rolloutRefused) Error() string { return "rollout refused: " + e.code }

// writeRolloutRefusal writes the 409 for e and reports whether it wrote
// anything: an empty code is no refusal.
func writeRolloutRefusal(w http.ResponseWriter, e rolloutRefused) bool {
	switch e.code {
	case "":
		return false
	case errCodeApprovalWithdrawn:
		writeError(w, http.StatusConflict, "version_not_approved",
			"target_version is not the tenant's approved version; approve it with PATCH .../update-policy first")
	case errCodeVersionRevoked:
		writeError(w, http.StatusConflict, "version_revoked", "target_version has been revoked")
	case errCodeRolloutWindowClosed:
		writeError(w, http.StatusConflict, "outside_rollout_window", "now is outside the tenant's rollout window")
	case errCodeUpdateInProgress:
		writeErrorDetails(w, http.StatusConflict, "update_in_progress",
			"another update rollout for this tenant is still in progress; wait for it to complete",
			map[string]any{"batch_id": e.batchID})
	default:
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to check the update policy")
	}
	return true
}

// claimRollout returns createBatch's claim for a rollout of version: the
// per-tenant "one update in progress" rule, made atomic with the write of
// the batch.
//
// Inside the batch's transaction it locks the tenant's tenant_update_policy
// row (SELECT ... FOR UPDATE), then repeats rolloutPolicyCheck's checks
// against that locked row and refuses if any self_update batch of the
// tenant still has an unfinished (queued, dispatching or running) item. A
// second POST blocks on the lock until the first commits and then sees its
// batch. Finally it writes the row's updated_at. On PXC a row lock only
// orders transactions on the same node; writing the same row is what makes
// Galera certification refuse one of two claims committed on different
// nodes. The new value is always later than the stored one at its
// millisecond precision, so the write is never a no-op MySQL would skip.
// updated_at therefore also moves when a rollout starts.
//
// A tenant without a policy row has nothing approved: policyRefusal
// refuses it.
func claimRollout(tenantID, version string, now time.Time) func(tx *gorm.DB) error {
	return func(tx *gorm.DB) error {
		var policies []TenantUpdatePolicy
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("tenant_id = ?", tenantID).Limit(1).Find(&policies).Error; err != nil {
			return err
		}
		var p *TenantUpdatePolicy
		if len(policies) > 0 {
			p = &policies[0]
		}
		if code := policyRefusal(p, version, now); code != "" {
			return rolloutRefused{code: code}
		}
		revoked, err := versionRevoked(tx, version)
		if err != nil {
			return err
		}
		if revoked {
			return rolloutRefused{code: errCodeVersionRevoked}
		}
		busy, err := updateInProgress(tx, tenantID)
		if err != nil {
			return err
		}
		if busy != "" {
			return rolloutRefused{code: errCodeUpdateInProgress, batchID: busy}
		}
		return tx.Model(&TenantUpdatePolicy{}).Where("tenant_id = ?", tenantID).
			UpdateColumn("updated_at", claimTimestamp(now, p.UpdatedAt)).Error
	}
}

// claimTimestamp is now at millisecond precision (updated_at's), moved to
// just after prev if it isn't later already.
func claimTimestamp(now, prev time.Time) time.Time {
	ts := now.UTC().Truncate(time.Millisecond)
	if !ts.After(prev) {
		ts = prev.UTC().Truncate(time.Millisecond).Add(time.Millisecond)
	}
	return ts
}

// updateInProgress returns the id of a self_update batch of tenantID that
// still has an unfinished (queued, dispatching or running) item, or "" if
// there is none. Both tables are scoped by tenant_id.
func updateInProgress(d *gorm.DB, tenantID string) (string, error) {
	var ids []string
	err := d.Table(AssetActionBatch{}.TableName()+" AS b").
		Joins("JOIN "+AssetActionItem{}.TableName()+" AS i ON i.batch_id = b.id AND i.tenant_id = b.tenant_id").
		Where("b.tenant_id = ? AND b.action_type = ? AND i.status IN ?",
			tenantID, controlplane.ActionSelfUpdate,
			[]AssetActionItemStatus{ActionItemQueued, ActionItemDispatching, ActionItemRunning}).
		Order("b.id").Limit(1).Pluck("b.id", &ids).Error
	if err != nil || len(ids) == 0 {
		return "", err
	}
	return ids[0], nil
}

// planUpdateItems resolves the rollout per sprout (design doc §2.3, mixed
// OS/arch fleets): it returns the accepted sprouts among rows that must not
// be sent the update, each with its error code, judged from what the
// sprout last reported against the target's catalog rows:
//
//   - no row for the sprout's OS and arch: no_release_for_platform;
//   - running a version newer than the target: sprout_newer_than_target
//     (sprouts refuse downgrades);
//   - running a version older than its row's min_sprout_version:
//     below_min_sprout_version (the sprout refuses that too).
//
// A sprout that has reported nothing, or not the fact a check needs, is
// sent the update: it resolves its own row, and refuses what it can't
// take, so its job fails. That is the same check, made later. With no
// reader, nothing is refused here; runRollout then sends nothing.
func planUpdateItems(ctx context.Context, reader SproutFactsReader, tenantID string, rows []sproutByAssetItem, catalog []FleetVersion) (map[SproutRef]string, error) {
	blocked := make(map[SproutRef]string)
	if reader == nil || len(catalog) == 0 {
		return blocked, nil
	}
	var ids []string
	for _, row := range rows {
		if row.KeyState == keyStateAccepted {
			ids = append(ids, row.SproutID)
		}
	}
	if len(ids) == 0 {
		return blocked, nil
	}
	ctx, cancel := context.WithTimeout(ctx, jobRefreshTimeout)
	defer cancel()
	reported, err := reader.SproutFacts(ctx, tenantID, ids)
	if err != nil {
		return nil, err
	}

	target := catalog[0].Version
	// The highest min_sprout_version of each OS/arch's rows. Registration
	// keeps it the same across a version's rows; the highest is the safe
	// reading if it ever isn't.
	minByPlatform := make(map[string]string)
	for _, row := range catalog {
		key := row.OS + "/" + row.Arch
		if cur, ok := minByPlatform[key]; !ok || semver.Compare(row.MinSproutVersion, cur) > 0 {
			minByPlatform[key] = row.MinSproutVersion
		}
	}
	for _, id := range ids {
		ref := SproutRef{TenantID: tenantID, SproutID: id}
		f := reported[ref]
		minVersion, havePlatform := minByPlatform[f.OS+"/"+f.Arch]
		switch {
		case f.OS != "" && f.Arch != "" && !havePlatform:
			blocked[ref] = errCodeNoReleaseForPlatform
		case f.Version == "":
		case semver.Compare(f.Version, target) > 0:
			blocked[ref] = errCodeSproutNewerThanTarget
		case havePlatform && semver.Compare(f.Version, minVersion) < 0:
			blocked[ref] = errCodeBelowMinSproutVersion
		}
	}
	return blocked, nil
}

// rolloutReaders are the two local reads a rollout follows its items
// through: farmer.job_status for job outcomes, and farmer.props for what
// each sprout reports after it reconnects.
type rolloutReaders struct {
	jobs  JobStatusReader
	facts SproutFactsReader
}

// startRollout runs a new update batch's rollout in the background. It
// captures the database, bus and readers when it starts, like
// startBatchDispatch, and uses the same WaitGroup, so tests can wait for it.
func startRollout(batch AssetActionBatch, queued []AssetActionItem, version string) {
	if len(queued) == 0 {
		return
	}
	d, nc, readers := db, bus, rolloutReaders{jobs: jobStatusReader, facts: sproutFactsReader}
	actionDispatches.Add(1)
	go func() {
		defer actionDispatches.Done()
		runRollout(d, nc, readers, batch, queued, version)
	}()
}

// sentWave is one wave that was dispatched, and the deadline by which its
// sprouts must be back on the target version.
type sentWave struct {
	items    []AssetActionItem
	deadline time.Time
}

// runRollout sends queued (in request order) out in waves of
// batch.RolloutBatchSize. Before each wave it checks the tenant's policy
// again, and after each wave it waits for the gate. If the policy check or
// the gate fails, every item still queued is failed with the matching code
// and no further wave is sent. Either way, every wave that was sent is then
// followed until each of its items has an outcome: its sprout reported the
// target version, its job failed, or the wave's deadline passed.
//
// With no bus connection nothing is sent and every item stays queued, the
// same as dispatchBatch. Without a SproutFactsReader no wave could ever
// pass, and with the job_status gate and no JobStatusReader a failed update
// could only ever show as a timeout, so in both cases the rollout halts
// without sending anything.
func runRollout(d *gorm.DB, nc *nats.Conn, readers rolloutReaders, batch AssetActionBatch, queued []AssetActionItem, version string) {
	if nc == nil {
		log.Errorf("saasapi: not connected to the NATS bus; update batch %s (tenant %s) left queued", batch.ID, batch.TenantID)
		return
	}
	if readers.facts == nil || (batch.RolloutGate == gateJobStatus && readers.jobs == nil) {
		log.Errorf("saasapi: no sprout facts or job status reader for update batch %s (tenant %s); halting before any wave", batch.ID, batch.TenantID)
		haltRollout(d, batch, string(controlplane.ErrorInternal))
		return
	}
	size := batch.RolloutBatchSize
	if size < 1 {
		size = 1
	}
	var sent []sentWave
	halted := ""
	for start := 0; start < len(queued) && halted == ""; start += size {
		n := start/size + 1
		code, err := rolloutPolicyCheck(d, batch.TenantID, version, rolloutNow())
		if err != nil {
			log.Errorf("saasapi: update batch %s (tenant %s): checking update policy: %v; halting", batch.ID, batch.TenantID, err)
			code = string(controlplane.ErrorInternal)
		}
		if code != "" {
			log.Warnf("saasapi: update batch %s (tenant %s) halted before wave %d: %s", batch.ID, batch.TenantID, n, code)
			halted = code
			break
		}
		if batch.RolloutGate == gateDispatch && anyWaveFailed(d, readers, batch, sent) {
			log.Warnf("saasapi: update batch %s (tenant %s): an earlier wave has a failed or unresponsive sprout; halting before wave %d",
				batch.ID, batch.TenantID, n)
			halted = errCodeRolloutHalted
			break
		}

		wave := sentWave{items: queued[start:min(start+size, len(queued))]}
		dispatchBatch(d, nc, batch, wave.items)
		wave.deadline = rolloutNow().Add(rolloutWaveTimeout)
		sent = append(sent, wave)

		passed := false
		switch batch.RolloutGate {
		case gateDispatch:
			passed = waveAccepted(d, batch, wave)
		default:
			passed = awaitWave(d, readers, batch, wave, true)
		}
		if !passed {
			log.Warnf("saasapi: update batch %s (tenant %s): wave %d did not pass the %s gate; halting",
				batch.ID, batch.TenantID, n, batch.RolloutGate)
			halted = errCodeRolloutHalted
		}
	}
	if halted != "" {
		haltRollout(d, batch, halted)
	}
	for _, w := range sent {
		awaitWave(d, readers, batch, w, false)
	}
	if halted == "" {
		log.Infof("saasapi: update batch %s (tenant %s): all waves sent and followed to an outcome", batch.ID, batch.TenantID)
	}
}

// awaitWave polls w until every item has an outcome and reports whether
// they all succeeded. With failFast, it returns false as soon as any item
// has failed, without waiting for the rest.
func awaitWave(d *gorm.DB, readers rolloutReaders, batch AssetActionBatch, w sentWave, failFast bool) bool {
	for {
		settled, failed := pollWave(d, readers, batch, w)
		if settled || (failed && failFast) {
			return !failed
		}
		time.Sleep(rolloutPollInterval)
	}
}

// anyWaveFailed polls every wave already sent once and reports whether any
// of their items has failed or gone unresponsive.
func anyWaveFailed(d *gorm.DB, readers rolloutReaders, batch AssetActionBatch, sent []sentWave) bool {
	for _, w := range sent {
		if _, failed := pollWave(d, readers, batch, w); failed {
			return true
		}
	}
	return false
}

// pollWave re-reads w's items, records any outcome refreshUpdateItems
// finds, and reports whether every item has an outcome (settled) and
// whether any of them isn't success (failed). Once w's deadline has
// passed, items still running are marked unresponsive_after_update.
//
// An item still queued after dispatchBatch had no farmer to take it. It
// can't succeed, so it counts as failed, and haltRollout fails it.
func pollWave(d *gorm.DB, readers rolloutReaders, batch AssetActionBatch, w sentWave) (settled, failed bool) {
	items, err := loadWaveItems(d, batch, w.items)
	if err != nil {
		log.Errorf("saasapi: update batch %s: reading wave items: %v", batch.ID, err)
		return true, true
	}
	refreshUpdateItems(context.Background(), d, readers.jobs, readers.facts, batch, items)
	settled = true
	for _, it := range items {
		switch it.Status {
		case ActionItemRunning, ActionItemDispatching:
			settled = false
		case ActionItemSucceeded:
		default:
			failed = true
		}
	}
	if !settled && !rolloutNow().Before(w.deadline) {
		markUnresponsive(d, items)
		return true, true
	}
	return settled, failed
}

// waveAccepted is the dispatch gate: dispatchBatch has already waited for
// farmer's replies, so the wave passes if farmer accepted every item
// (running, or already succeeded).
func waveAccepted(d *gorm.DB, batch AssetActionBatch, w sentWave) bool {
	items, err := loadWaveItems(d, batch, w.items)
	if err != nil {
		log.Errorf("saasapi: update batch %s: reading wave items: %v", batch.ID, err)
		return false
	}
	for _, it := range items {
		if it.Status != ActionItemRunning && it.Status != ActionItemSucceeded {
			return false
		}
	}
	return true
}

// refreshUpdateItems is refreshItems for a self_update batch, used by the
// rollout and by both batch-status GETs. A running item:
//
//   - succeeds once its sprout reports the batch's target version in its
//     facts (it restarted on the new release and reconnected), whatever
//     its job reads;
//   - fails with job_failed or job_expired if its job did;
//   - otherwise stays running, including once its job has succeeded: on
//     Linux that means the installer finished and a restart is pending, on
//     Windows only that the MSI is scheduled. Neither is the sprout back.
//
// Updates are conditional on the item still being running, so concurrent
// callers record each outcome once. A reader error leaves items as stored.
func refreshUpdateItems(ctx context.Context, d *gorm.DB, jobs JobStatusReader, facts SproutFactsReader, batch AssetActionBatch, items []AssetActionItem) {
	var running []int
	for i, it := range items {
		if it.Status == ActionItemRunning {
			running = append(running, i)
		}
	}
	if len(running) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, jobRefreshTimeout)
	defer cancel()
	record := func(it *AssetActionItem, update map[string]any) {
		if ok, err := updateItem(d, *it, ActionItemRunning, update); err != nil || !ok {
			if err != nil {
				log.Errorf("saasapi: recording update outcome for batch %s asset %s: %v", it.BatchID, it.AssetID, err)
			}
			return
		}
		it.Status = update["status"].(AssetActionItemStatus)
		if code, ok := update["error_code"].(string); ok {
			it.ErrorCode = code
		}
	}

	if target := selfUpdateTarget(batch); facts != nil && target != "" {
		ids := make([]string, 0, len(running))
		for _, i := range running {
			ids = append(ids, items[i].SproutID)
		}
		reported, err := facts.SproutFacts(ctx, batch.TenantID, ids)
		if err != nil {
			log.Warnf("saasapi: reading sprout facts for update batch %s (tenant %s): %v", batch.ID, batch.TenantID, err)
		}
		for _, i := range running {
			it := &items[i]
			if reported[SproutRef{TenantID: batch.TenantID, SproutID: it.SproutID}].Version == target {
				record(it, map[string]any{"status": ActionItemSucceeded})
			}
		}
	}

	if jobs == nil {
		return
	}
	var refs []JobRef
	for _, i := range running {
		if it := items[i]; it.Status == ActionItemRunning && it.JID != "" {
			refs = append(refs, JobRef{SproutID: it.SproutID, JID: it.JID})
		}
	}
	if len(refs) == 0 {
		return
	}
	outcomes, err := jobs.JobOutcomes(ctx, batch.TenantID, refs)
	if err != nil {
		log.Warnf("saasapi: refreshing %d update jobs for batch %s (tenant %s): %v", len(refs), batch.ID, batch.TenantID, err)
		return
	}
	for _, i := range running {
		it := &items[i]
		if it.Status != ActionItemRunning || it.JID == "" {
			continue
		}
		switch outcomes[JobRef{SproutID: it.SproutID, JID: it.JID}] {
		case JobOutcomeFailed:
			record(it, failedUpdate(errCodeJobFailed))
		case JobOutcomeExpired:
			record(it, failedUpdate(errCodeJobExpired))
		}
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
// Items that were already sent are left alone: the rollout follows them
// to an outcome, and GET keeps refreshing them.
func haltRollout(d *gorm.DB, batch AssetActionBatch, code string) {
	err := d.Model(&AssetActionItem{}).
		Where("batch_id = ? AND tenant_id = ? AND status = ?", batch.ID, batch.TenantID, ActionItemQueued).
		Updates(failedUpdate(code)).Error
	if err != nil {
		log.Errorf("saasapi: halting update batch %s (tenant %s): %v", batch.ID, batch.TenantID, err)
	}
}

// selfUpdateTarget is the version a self_update batch updates to, or ""
// for any other batch.
func selfUpdateTarget(batch AssetActionBatch) string {
	if batch.ActionType != controlplane.ActionSelfUpdate {
		return ""
	}
	var p farmerSelfUpdate
	if err := json.Unmarshal([]byte(batch.ActionParams), &p); err != nil {
		return ""
	}
	return p.Version
}

// rolloutOf returns the rollout part of batch's GET response, or nil for a
// batch that isn't a rollout.
func rolloutOf(batch AssetActionBatch) *rolloutResponse {
	if batch.ActionType != controlplane.ActionSelfUpdate {
		return nil
	}
	return &rolloutResponse{TargetVersion: selfUpdateTarget(batch), BatchSize: batch.RolloutBatchSize, Gate: batch.RolloutGate}
}
