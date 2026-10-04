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
//     end of the window stops the rollout. That the tenant is still active
//     is checked before every wave and every item (tenant_not_active
//     otherwise): DeleteTenant keeps the policy row.
//   - Waves take dispatch slots from a pool reserved for self_update,
//     within a per-tenant cap (dispatch_limits.go), so cmd.run and cook
//     traffic can't starve a rollout. An item farmer refuses unrun
//     (farmer_busy) is sent again after a short backoff.
//   - A tenant has at most one update rollout in progress. The batch is
//     written in the same transaction that claims the tenant's
//     tenant_update_policy row (claimRollout), so two POSTs can't both
//     pass the check: one gets 409 update_in_progress. The claim writes
//     the row's rollout_claimed_at, never updated_at, so starting a
//     rollout doesn't look like a policy change to GET update-policy.
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
//     (refreshUpdateItems). The report must also have been written after
//     the item was dispatched (reportFresh, within rolloutClockSkew): a
//     leftover row naming the target, from an earlier attempt or a package
//     an administrator reinstalled, is not proof. A sprout that already
//     reported the target when the rollout was planned answers "already
//     running" and never reports again; it passes only once its update
//     job succeeds (the sprout's own check of its running version) while
//     its report still names the target. A report dated beyond saasapi's
//     clock by more than the margin fails the item with facts_clock_skew.
//     A job that fails or expires fails the item.
//   - A sprout that doesn't come back on the target version before its
//     wave's deadline gets its own status, unresponsive_after_update, not a
//     plain failed. The operator's response is different: the sprout may be
//     unable to reconnect, or may have kept or restored its old version.
//   - Once any wave fails its gate, every item not yet sent is failed with
//     rollout_halted and is never sent.
//
// The rollout runs in a background goroutine in the process that accepted
// the POST, like §1.5's dispatch, under the batch's row lease, which it
// renews while it runs. If that process exits, the lease lapses and the
// outbox sweeper of any replica takes the rollout over and resumes it from
// what the database records (sweepRollouts, resumeRollout): the same waves
// of the same size and gate, the policy and the catalog checked again
// before each one. Only items still queued are ever sent; an item a dead
// process left in dispatching is never re-sent: once its dispatcher would
// have given up on the reply it fails with dispatch_outcome_unknown, which
// halts the rollout and frees the tenant's rollout slot.
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
	"golang.org/x/mod/semver"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/fleetcatalog"
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
	// rolloutNow is time.Now, replaceable in tests. It is saasapi's clock:
	// item dispatch times and the freshness check both read it.
	rolloutNow = time.Now
)

// Clock skew between saasapi and the farmer node that wrote a sprout's
// facts, for reportFresh. A sprout_version report counts as proof of an
// update if farmer's write time is later than the item's dispatch time
// (saasapi's clock) minus rolloutClockSkew, and not later than now plus
// it. A stale row written within the margin before dispatch is the
// accepted cost: an update's own report comes after a download, an
// install and a restart, so it is normally well clear of it. Nodes are
// expected to run NTP, which keeps them within milliseconds; a larger skew
// fails closed rather than admitting stale rows. A farmer clock that runs
// behind looks like a stale row (unresponsive_after_update at the
// deadline); one that runs ahead fails the item with facts_clock_skew.
const (
	// defaultRolloutClockSkew is the margin unless
	// SAASAPI_FLEET_UPDATE_CLOCK_SKEW sets another.
	defaultRolloutClockSkew = 30 * time.Second
	// maxRolloutClockSkew caps the margin: every second of it is a second
	// before dispatch in which a stale row still counts.
	maxRolloutClockSkew = 5 * time.Minute
)

// rolloutClockSkew is the margin in use (SetFleetUpdateClockSkew).
var rolloutClockSkew = defaultRolloutClockSkew

// FleetUpdateClockSkew returns the margin in use.
func FleetUpdateClockSkew() time.Duration { return rolloutClockSkew }

// SetFleetUpdateClockSkew sets the margin (Config.FleetUpdateClockSkew,
// SAASAPI_FLEET_UPDATE_CLOCK_SKEW). Like SetFleetUpdateDispatchEnabled,
// call it once at startup, before NewRouter. A value outside
// (0, maxRolloutClockSkew], which LoadConfig refuses, leaves the default.
func SetFleetUpdateClockSkew(d time.Duration) {
	if d <= 0 || d > maxRolloutClockSkew {
		d = defaultRolloutClockSkew
	}
	rolloutClockSkew = d
}

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
	// errCodeFactsClockSkew: the sprout reported the target version in a
	// row the farmer node dated more than rolloutClockSkew ahead of
	// saasapi's clock, so the report can't be shown to postdate the
	// dispatch. The sprout may well have updated; a node clock is wrong.
	errCodeFactsClockSkew = "facts_clock_skew"
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
	blocked, atTarget, err := planUpdateItems(r.Context(), sproutFactsReader, tenantID, rows, versions)
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
	}, assetIDs, rows, blocked, atTarget, claimRollout(tenantID, version, rolloutNow()))
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
	startRollout(batch, queued, version, atTarget)
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
// p sets a window and now is outside [start, end), and "" otherwise. The
// window rule is fleetcatalog.OutsideRolloutWindow, the one farmer
// applies again before each self_update (internal/natsapi,
// checkRolloutWindow).
func policyRefusal(p *TenantUpdatePolicy, version string, now time.Time) string {
	if p == nil || p.ApprovedVersion == nil || *p.ApprovedVersion != version {
		return errCodeApprovalWithdrawn
	}
	if p.RolloutWindowStart != nil && p.RolloutWindowEnd != nil &&
		fleetcatalog.OutsideRolloutWindow(now, *p.RolloutWindowStart, *p.RolloutWindowEnd) {
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
// batch. Finally it writes the row's rollout_claimed_at. On PXC a row lock
// only orders transactions on the same node; writing the same row is what
// makes Galera certification refuse one of two claims committed on
// different nodes. The new value is always later than the stored one at
// its millisecond precision (claimTimestamp), so the write is never a
// no-op MySQL would skip. rollout_claimed_at exists only for this:
// updated_at is not touched, so it keeps meaning "the policy last
// changed", and GET update-policy doesn't return the claim column.
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
		var prev time.Time
		if p.RolloutClaimedAt != nil {
			prev = *p.RolloutClaimedAt
		}
		return tx.Model(&TenantUpdatePolicy{}).Where("tenant_id = ?", tenantID).
			UpdateColumn("rollout_claimed_at", claimTimestamp(now, prev)).Error
	}
}

// claimTimestamp is now at millisecond precision (rollout_claimed_at's),
// moved to just after prev if it isn't later already. prev is zero for a
// row never claimed.
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
//
// It also returns the sprouts that already report the target version.
// They are sent the update like any other and answer "already running",
// so they never write a new report; the wave gate accepts their update
// job's success instead (rolloutProofs, judgeUpdateItem).
func planUpdateItems(ctx context.Context, reader SproutFactsReader, tenantID string, rows []sproutByAssetItem, catalog []FleetVersion) (blocked map[SproutRef]string, atTarget map[SproutRef]bool, err error) {
	blocked = make(map[SproutRef]string)
	atTarget = make(map[SproutRef]bool)
	if reader == nil || len(catalog) == 0 {
		return blocked, atTarget, nil
	}
	var ids []string
	for _, row := range rows {
		if row.KeyState == keyStateAccepted {
			ids = append(ids, row.SproutID)
		}
	}
	if len(ids) == 0 {
		return blocked, atTarget, nil
	}
	ctx, cancel := context.WithTimeout(ctx, jobRefreshTimeout)
	defer cancel()
	reported, err := reader.SproutFacts(ctx, tenantID, ids)
	if err != nil {
		return nil, nil, err
	}

	target := catalog[0].Version
	// The highest min_sprout_version of each OS/arch's rows. Registration
	// keeps it the same across a version's rows; the highest is the safe
	// reading if it ever isn't.
	minByPlatform := make(map[string]string)
	for _, row := range catalog {
		// A prerelease is never installed from an MSI (the sprout refuses
		// it: its ProductVersion can't carry the prerelease), so a
		// prerelease's msi rows give Windows sprouts nothing to install:
		// they fail up front with no_release_for_platform, unsent.
		if row.PackageType == "msi" && semver.Prerelease(target) != "" {
			continue
		}
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
		case f.Version == target:
			atTarget[ref] = true
		}
	}
	return blocked, atTarget, nil
}

// rolloutReaders are the two local reads a rollout follows its items
// through: farmer.job_status for job outcomes, and farmer.props for what
// each sprout reports after it reconnects.
type rolloutReaders struct {
	jobs  JobStatusReader
	facts SproutFactsReader
}

// startRollout runs a new update batch's rollout in the background, renewing
// the lease createBatch wrote while it runs. It captures the database, bus
// and readers when it starts, like startBatchDispatch, and uses the same
// WaitGroup, so tests can wait for it. atTarget is planUpdateItems': the
// sprouts already on the target version.
func startRollout(batch AssetActionBatch, queued []AssetActionItem, version string, atTarget map[SproutRef]bool) {
	if len(queued) == 0 {
		return
	}
	d, nc, readers := db, bus, rolloutReaders{jobs: jobStatusReader, facts: sproutFactsReader}
	actionDispatches.Add(1)
	go func() {
		defer actionDispatches.Done()
		lease := batchLeaseOf(d, batch)
		lease.keepAlive()
		defer lease.stopKeepAlive()
		runRollout(d, nc, readers, batch, queued, version, atTarget, lease)
	}()
}

// updateProof is what counts as proof that one item's update landed: a
// report of the target version written after dispatched (reportFresh), or,
// with jobSuffices, the update job's success while the sprout's report
// still names the target (judgeUpdateItem).
type updateProof struct {
	dispatched  time.Time
	jobSuffices bool
}

// sentWave is one wave that was dispatched, the deadline by which its
// sprouts must be back on the target version, and what proves each of its
// items (by asset_id, the item's key within its batch) succeeded.
//
// A resumed rollout (resumeRollout) gathers every item its dead
// predecessor sent into one sentWave whose deadlines are per item, each
// measured from the item's recorded dispatch time; deadlines is nil for a
// wave this process sent, whose items share deadline.
type sentWave struct {
	items     []AssetActionItem
	proofs    map[string]updateProof
	deadline  time.Time
	deadlines map[string]time.Time
}

// deadlineOf is when the sprout of item it must be back on the target
// version.
func (w sentWave) deadlineOf(it AssetActionItem) time.Time {
	if d, ok := w.deadlines[it.AssetID]; ok {
		return d
	}
	return w.deadline
}

// proof is the rollout's proofFunc for w: an item it has no record of
// dispatching has no proof, so no report can pass it.
func (w sentWave) proof(it AssetActionItem) (updateProof, bool) {
	p, ok := w.proofs[it.AssetID]
	return p, ok
}

// runRollout sends queued (in request order) out in waves of
// batch.RolloutBatchSize. Before each wave it checks the tenant's policy
// again, and after each wave it waits for the gate. If the policy check or
// the gate fails, every item still queued is failed with the matching code
// and no further wave is sent. Either way, every wave that was sent is then
// followed until each of its items has an outcome: its sprout reported the
// target version, its job failed, or the wave's deadline passed.
//
// lease is the batch's (nil for none): before each wave, and before
// halting, the rollout checks it still holds it, and if not stops at once,
// leaving the batch to whoever took it over (outbox_lease.go).
//
// With no bus connection nothing is sent and every item stays queued, the
// same as dispatchBatch. Without a SproutFactsReader no wave could ever
// pass, and with the job_status gate and no JobStatusReader a failed update
// could only ever show as a timeout, so in both cases the rollout halts
// without sending anything.
func runRollout(d *gorm.DB, nc *nats.Conn, readers rolloutReaders, batch AssetActionBatch, queued []AssetActionItem,
	version string, atTarget map[SproutRef]bool, lease *rowLease) {
	if nc == nil {
		log.Errorf("saasapi: not connected to the NATS bus; update batch %s (tenant %s) left queued", batch.ID, batch.TenantID)
		return
	}
	if !readersUsable(readers, batch) {
		log.Errorf("saasapi: no sprout facts or job status reader for update batch %s (tenant %s); halting before any wave", batch.ID, batch.TenantID)
		if lease.held() {
			haltRollout(d, batch, string(controlplane.ErrorInternal))
		}
		return
	}
	r := &rolloutRun{d: d, nc: nc, readers: readers, batch: batch, version: version, lease: lease}
	r.sendWaves(queued, atTarget)
}

// readersUsable reports whether readers can judge batch's waves at all.
func readersUsable(readers rolloutReaders, batch AssetActionBatch) bool {
	return readers.facts != nil && (batch.RolloutGate != gateJobStatus || readers.jobs != nil)
}

// rolloutRun is one process's run of a rollout: a new one (runRollout) or
// one resumed from the database (resumeRollout).
type rolloutRun struct {
	d       *gorm.DB
	nc      *nats.Conn
	readers rolloutReaders
	batch   AssetActionBatch
	version string
	lease   *rowLease
	// resumed: before each wave, also check that the target version is
	// still registered and verifies (rolloutRegistrationCheck), as the
	// POST did before the original process started. (That the tenant is
	// still active is checked for every run.)
	resumed bool
	// sent is every wave sent so far, a resumed run's predecessor's
	// included.
	sent []sentWave
}

// lostLease reports, and logs, that r no longer holds the batch's lease.
func (r *rolloutRun) lostLease() bool {
	if r.lease.held() {
		return false
	}
	log.Warnf("saasapi: update batch %s (tenant %s): no longer holding its lease; leaving the rollout to its new holder",
		r.batch.ID, r.batch.TenantID)
	return true
}

// sendWaves sends queued out in waves, then halts or finishes (finish).
func (r *rolloutRun) sendWaves(queued []AssetActionItem, atTarget map[SproutRef]bool) {
	batch := r.batch
	size := batch.RolloutBatchSize
	if size < 1 {
		size = 1
	}
	halted := ""
	for start := 0; start < len(queued) && halted == ""; start += size {
		n := start/size + 1
		if r.lostLease() {
			return
		}
		code := r.preWaveCheck()
		if code != "" {
			log.Warnf("saasapi: update batch %s (tenant %s) halted before wave %d: %s", batch.ID, batch.TenantID, n, code)
			halted = code
			break
		}
		if batch.RolloutGate == gateDispatch && anyWaveFailed(r.d, r.readers, batch, r.sent) {
			log.Warnf("saasapi: update batch %s (tenant %s): an earlier wave has a failed or unresponsive sprout; halting before wave %d",
				batch.ID, batch.TenantID, n)
			halted = errCodeRolloutHalted
			break
		}

		wave := sentWave{items: queued[start:min(start+size, len(queued))]}
		dispatched, stopped := dispatchWave(r.d, r.nc, batch, wave.items)
		wave.proofs = rolloutProofs(batch, wave.items, dispatched, atTarget)
		wave.deadline = rolloutNow().Add(rolloutWaveTimeout)
		r.sent = append(r.sent, wave)
		if stopped != "" {
			log.Warnf("saasapi: update batch %s (tenant %s) halted during wave %d: %s", batch.ID, batch.TenantID, n, stopped)
			halted = stopped
			break
		}

		passed := false
		switch batch.RolloutGate {
		case gateDispatch:
			passed = waveAccepted(r.d, batch, wave)
		default:
			passed = awaitWave(r.d, r.readers, batch, wave, true, r.lease)
		}
		if r.lostLease() {
			return
		}
		if !passed {
			log.Warnf("saasapi: update batch %s (tenant %s): wave %d did not pass the %s gate; halting",
				batch.ID, batch.TenantID, n, batch.RolloutGate)
			halted = errCodeRolloutHalted
		}
	}
	r.finish(halted)
}

// preWaveCheck is the check before every wave: the tenant's policy and
// the version's revocation (rolloutPolicyCheck); that the tenant is still
// active (rolloutTenantCheck), for a live run as for a resumed one
// (security review L8: DeleteTenant keeps the policy row, so the policy
// check alone would let a live rollout keep going for a deleted tenant);
// and for a resumed run the version's registration too. It returns "" to
// go ahead, or the code the unsent items are failed with. dispatchWave
// repeats the tenant check before every item.
func (r *rolloutRun) preWaveCheck() string {
	code, err := rolloutPolicyCheck(r.d, r.batch.TenantID, r.version, rolloutNow())
	if err != nil {
		log.Errorf("saasapi: update batch %s (tenant %s): checking update policy: %v; halting", r.batch.ID, r.batch.TenantID, err)
		return string(controlplane.ErrorInternal)
	}
	if code != "" {
		return code
	}
	if code := rolloutTenantCheck(r.d, r.batch); code != "" || !r.resumed {
		return code
	}
	return rolloutRegistrationCheck(r.d, r.batch, r.version)
}

// finish fails every unsent item with halted, if set, and then follows
// every sent wave until each of its items has an outcome. It stops,
// without halting, once the lease is lost.
func (r *rolloutRun) finish(halted string) {
	if halted != "" {
		if r.lostLease() {
			return
		}
		haltRollout(r.d, r.batch, halted)
	}
	for _, w := range r.sent {
		awaitWave(r.d, r.readers, r.batch, w, false, r.lease)
		if r.lostLease() {
			return
		}
	}
	if halted == "" {
		log.Infof("saasapi: update batch %s (tenant %s): all waves sent and followed to an outcome", r.batch.ID, r.batch.TenantID)
	}
}

// Retries of a rollout item farmer refused unrun (farmer_busy, or no
// farmer subscribed): up to farmerBusyRetries more sends, after
// farmerBusyBackoff, doubling. Variables so tests can shorten them.
var (
	farmerBusyRetries = 3
	farmerBusyBackoff = 2 * time.Second
)

// dispatchWave is dispatchBatch for one wave of a rollout, recording when
// each item was handed to dispatchItem, on saasapi's clock (rolloutNow).
// The time is taken once the item holds a dispatch slot, just before
// dispatchItem claims and sends it, so it is never later than the send.
//
// Items take slots from the pool reserved for self_update, within the
// tenant's cap (dispatch_limits.go), so no cmd.run or cook traffic delays
// a wave. Before every item, and before every retry, the tenant must
// still be active (security review L8; rolloutTenantCheck): once it
// isn't, nothing more is sent and dispatchWave returns that check's code
// as halted, for sendWaves to stop the rollout with. An item farmer
// refused unrun is sent again up to farmerBusyRetries times, with a fresh
// dispatch time; one still unsent after that stays queued, which fails
// the wave's gate.
func dispatchWave(d *gorm.DB, nc *nats.Conn, batch AssetActionBatch, items []AssetActionItem) (map[string]time.Time, string) {
	limits := dispatchLimits.Load()
	dispatched := make(map[string]time.Time, len(items))
	var mu sync.Mutex
	halted := ""
	stop := func() bool {
		mu.Lock()
		if halted != "" {
			mu.Unlock()
			return true
		}
		mu.Unlock()
		code := rolloutTenantCheck(d, batch)
		if code == "" {
			return false
		}
		mu.Lock()
		if halted == "" {
			halted = code
		}
		mu.Unlock()
		return true
	}
	var wg sync.WaitGroup
	for _, item := range items {
		release := limits.acquire(batch.TenantID, batch.ActionType)
		if stop() {
			release()
			break
		}
		wg.Add(1)
		go func(item AssetActionItem) {
			defer wg.Done()
			defer release()
			backoff := farmerBusyBackoff
			for attempt := 0; ; attempt++ {
				mu.Lock()
				dispatched[item.AssetID] = rolloutNow()
				mu.Unlock()
				if !dispatchItem(d, nc, batch, item) || attempt >= farmerBusyRetries {
					return
				}
				time.Sleep(backoff)
				backoff *= 2
				if stop() {
					return
				}
			}
		}(item)
	}
	wg.Wait()
	return dispatched, halted
}

// rolloutProofs is each wave item's updateProof: a fresh report, or, for
// a sprout that already reported the target version when the rollout was
// planned (atTarget), its update job's success. Such a sprout answers
// "already running" and writes nothing new; that answer is the sprout
// comparing the target with the version it is running (selfupdate,
// prepare), not a database row. An item without a dispatch time gets no
// proof at all.
func rolloutProofs(batch AssetActionBatch, items []AssetActionItem, dispatched map[string]time.Time, atTarget map[SproutRef]bool) map[string]updateProof {
	proofs := make(map[string]updateProof, len(items))
	for _, it := range items {
		at, ok := dispatched[it.AssetID]
		if !ok {
			continue
		}
		proofs[it.AssetID] = updateProof{
			dispatched:  at,
			jobSuffices: atTarget[SproutRef{TenantID: batch.TenantID, SproutID: it.SproutID}],
		}
	}
	return proofs
}

// awaitWave polls w until every item has an outcome and reports whether
// they all succeeded. With failFast, it returns false as soon as any item
// has failed, without waiting for the rest. It also returns false as soon
// as lease (nil for none) is no longer held; the caller checks the lease
// before acting on that.
func awaitWave(d *gorm.DB, readers rolloutReaders, batch AssetActionBatch, w sentWave, failFast bool, lease *rowLease) bool {
	for {
		if !lease.held() {
			return false
		}
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
// whether any of them isn't success (failed). An item still running or
// dispatching once its deadline (deadlineOf) has passed is settled as a
// failure: a running one is marked unresponsive_after_update, a
// dispatching one (its request went out, or may have, and no reply was
// ever recorded) is failed with dispatch_outcome_unknown and never re-sent
// (stuckDispatching). Either way it is terminal, so it no longer holds the
// tenant's rollout slot (updateInProgress).
//
// An item still queued after dispatchBatch had no farmer to take it. It
// can't succeed, so it counts as failed, and haltRollout fails it.
func pollWave(d *gorm.DB, readers rolloutReaders, batch AssetActionBatch, w sentWave) (settled, failed bool) {
	items, err := loadWaveItems(d, batch, w.items)
	if err != nil {
		log.Errorf("saasapi: update batch %s: reading wave items: %v", batch.ID, err)
		return true, true
	}
	refreshUpdateItemsWith(context.Background(), d, readers.jobs, readers.facts, batch, items, w.proof)
	settled = true
	now := rolloutNow()
	var overdue []AssetActionItem
	for _, it := range items {
		switch it.Status {
		case ActionItemRunning, ActionItemDispatching:
			if now.Before(w.deadlineOf(it)) {
				settled = false
			} else {
				overdue = append(overdue, it)
				failed = true
			}
		case ActionItemSucceeded:
		default:
			failed = true
		}
	}
	markOverdue(d, batch, overdue)
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

// proofFunc returns what proves item it's update landed, or false if
// nothing can (refreshUpdateItemsWith then never passes it).
type proofFunc func(it AssetActionItem) (updateProof, bool)

// reportFresh reports whether a sprout_version report farmer wrote at
// written (farmer's clock) is proof of an update dispatched at dispatched
// (saasapi's clock), judged at now (saasapi's clock): written after
// dispatch, less rolloutClockSkew, and not after now, plus
// rolloutClockSkew. A zero written (no write time: a static prop) is
// never fresh. At the boundaries: a row written exactly rolloutClockSkew
// before dispatch doesn't count; one written exactly rolloutClockSkew
// after now still does.
func reportFresh(written, dispatched, now time.Time) bool {
	return !written.IsZero() &&
		written.After(dispatched.Add(-rolloutClockSkew)) &&
		!written.After(now.Add(rolloutClockSkew))
}

// judgeUpdateItem decides a running self_update item's outcome from what
// its sprout last reported (f), its job's outcome (job, "" if unknown),
// and what proves its update landed (p; haveProof false means nothing
// does). It returns the update to record, or nil to leave it running:
//
//  1. the sprout reports target in a fresh row (reportFresh): succeeded;
//  2. the job failed or expired: failed, job_failed or job_expired;
//  3. the sprout reports target in a row dated more than rolloutClockSkew
//     ahead of now: failed, facts_clock_skew;
//  4. p.jobSuffices (the sprout was on the target at planning), the job
//     succeeded, and the report still names target: succeeded. The job
//     table doesn't say whether the sprout found itself already running
//     the target or installed it with a restart pending, so a sprout whose
//     report has since named another version doesn't pass on its job;
//  5. anything else: still running. A succeeded job alone is not the
//     sprout back on the new version.
func judgeUpdateItem(f TimedSproutFacts, target string, p updateProof, haveProof bool, job JobOutcome, now time.Time) map[string]any {
	reportsTarget := target != "" && f.Version == target
	switch {
	case reportsTarget && haveProof && reportFresh(f.Written.Version, p.dispatched, now):
		return map[string]any{"status": ActionItemSucceeded}
	case job == JobOutcomeFailed:
		return failedUpdate(errCodeJobFailed)
	case job == JobOutcomeExpired:
		return failedUpdate(errCodeJobExpired)
	case reportsTarget && f.Written.Version.After(now.Add(rolloutClockSkew)):
		return failedUpdate(errCodeFactsClockSkew)
	case reportsTarget && haveProof && p.jobSuffices && job == JobOutcomeSucceeded:
		return map[string]any{"status": ActionItemSucceeded}
	}
	return nil
}

// refreshUpdateItems is refreshItems for a self_update batch, as both
// batch-status GETs use it: refreshUpdateItemsWith, judging freshness with
// runningSinceProof.
func refreshUpdateItems(ctx context.Context, d *gorm.DB, jobs JobStatusReader, facts SproutFactsReader, batch AssetActionBatch, items []AssetActionItem) {
	refreshUpdateItemsWith(ctx, d, jobs, facts, batch, items, runningSinceProof)
}

// runningSinceProof is the GETs' proofFunc. A GET has no rollout state, so
// it takes a running item's updated_at as its dispatch time, and never
// lets a job's success stand in for a report (jobSuffices is false). That is when
// dispatchItem recorded farmer's reply (nothing else writes a running
// item), on the clock of the saasapi pod that dispatched it, so it is
// never earlier than the dispatch. A GET's check is therefore at least as
// strict as the rollout's, never looser: it may leave running an item the
// rollout passes on its next poll (a sprout that already reported the
// target when the rollout was planned, or a report written between
// dispatch and farmer's reply), but never passes one the rollout wouldn't.
func runningSinceProof(it AssetActionItem) (updateProof, bool) {
	if it.UpdatedAt.IsZero() {
		return updateProof{}, false
	}
	return updateProof{dispatched: it.UpdatedAt}, true
}

// refreshUpdateItemsWith is refreshItems for a self_update batch, used by
// the rollout (with its own record of each item's dispatch, sentWave.proof)
// and by both batch-status GETs (refreshUpdateItems). It reads every
// running item's job outcome and its sprout's last report, with write
// times, and records what judgeUpdateItem decides. In short, a running
// item:
//
//   - succeeds once its sprout reports the batch's target version in a
//     row written after the item's dispatch (reportFresh): it restarted
//     on the new release and reconnected. A report of the target that
//     isn't fresh leaves the item running, and so, once its wave's
//     deadline passes, unresponsive_after_update;
//   - for a sprout already on the target when the rollout was planned,
//     also succeeds once its job succeeds ("already running") while its
//     report still names the target;
//   - fails with job_failed or job_expired if its job did, and with
//     facts_clock_skew if its report of the target is dated too far in
//     saasapi's future (the measured skew is logged);
//   - otherwise stays running, including once its job has succeeded: on
//     Linux that means the installer finished and a restart is pending, on
//     Windows only that the MSI is scheduled. Neither is the sprout back.
//
// Updates are conditional on the item still being running, so concurrent
// callers record each outcome once. A reader error is logged and treated
// as nothing read: no item passes on what wasn't read.
func refreshUpdateItemsWith(ctx context.Context, d *gorm.DB, jobs JobStatusReader, facts SproutFactsReader, batch AssetActionBatch, items []AssetActionItem, proof proofFunc) {
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

	// Job outcomes first, then facts: the report judged is then never
	// older than the job outcome it is judged with, so a sprout whose
	// report changed before its job finished is judged on the change.
	var outcomes map[JobRef]JobOutcome
	if jobs != nil {
		var refs []JobRef
		for _, i := range running {
			if it := items[i]; it.JID != "" {
				refs = append(refs, JobRef{SproutID: it.SproutID, JID: it.JID})
			}
		}
		if len(refs) > 0 {
			var err error
			if outcomes, err = jobs.JobOutcomes(ctx, batch.TenantID, refs); err != nil {
				log.Warnf("saasapi: refreshing %d update jobs for batch %s (tenant %s): %v", len(refs), batch.ID, batch.TenantID, err)
				outcomes = nil
			}
		}
	}

	target := selfUpdateTarget(batch)
	var reported map[SproutRef]TimedSproutFacts
	if facts != nil && target != "" {
		ids := make([]string, 0, len(running))
		for _, i := range running {
			ids = append(ids, items[i].SproutID)
		}
		var err error
		if reported, err = facts.SproutFactsWithWriteTimes(ctx, batch.TenantID, ids); err != nil {
			log.Warnf("saasapi: reading sprout facts for update batch %s (tenant %s): %v", batch.ID, batch.TenantID, err)
			reported = nil
		}
	}

	now := rolloutNow()
	for _, i := range running {
		it := &items[i]
		f := reported[SproutRef{TenantID: batch.TenantID, SproutID: it.SproutID}]
		var job JobOutcome
		if it.JID != "" {
			job = outcomes[JobRef{SproutID: it.SproutID, JID: it.JID}]
		}
		p, ok := proof(*it)
		update := judgeUpdateItem(f, target, p, ok, job, now)
		if update == nil {
			continue
		}
		if code, _ := update["error_code"].(string); code == errCodeFactsClockSkew {
			log.Warnf("saasapi: update batch %s (tenant %s): sprout %s reported %s in a row its farmer node dated %s ahead of saasapi's clock (margin %s); failing it with %s",
				batch.ID, batch.TenantID, it.SproutID, target, f.Written.Version.Sub(now).Round(time.Millisecond), rolloutClockSkew, errCodeFactsClockSkew)
		}
		if ok, err := updateItem(d, *it, ActionItemRunning, update); err != nil || !ok {
			if err != nil {
				log.Errorf("saasapi: recording update outcome for batch %s asset %s: %v", it.BatchID, it.AssetID, err)
			}
			continue
		}
		it.Status = update["status"].(AssetActionItemStatus)
		if code, ok := update["error_code"].(string); ok {
			it.ErrorCode = code
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

// markOverdue settles items past their wave deadline: a running one
// becomes unresponsive_after_update, a dispatching one fails with
// dispatch_outcome_unknown (failStuckDispatching). Each update is
// conditional on the item's status, so an outcome a concurrent GET has
// just recorded wins.
func markOverdue(d *gorm.DB, batch AssetActionBatch, items []AssetActionItem) {
	for _, it := range items {
		if it.Status == ActionItemDispatching {
			failStuckDispatching(d, batch, it)
			continue
		}
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
