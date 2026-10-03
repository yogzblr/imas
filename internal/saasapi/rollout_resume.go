// Security-sensitive: resuming a fleet update rollout a dead process
// started (design doc §1.8, §2.3). FLAG FOR SECURITY REVIEW per the CL.3
// brief. A resumed rollout must never update more sprouts, sooner, or to
// a version less vetted than the original would have:
//
//   - It is taken over only once the batch's lease has lapsed (a live
//     holder renews it), with the same conditional UPDATE every lease
//     claim uses, and the tenant's rollout claim is rewritten with it.
//   - Its state comes from the database alone: the batch's wave size,
//     gate and target version, each item's status, recorded dispatch time
//     (dispatched_at) and planned_at_target.
//   - Items already sent are judged by the gate as one wave, each with the
//     deadline the original wave would have had, measured from its own
//     dispatch time. The gate must pass before anything else is sent.
//   - Only items still queued are sent, in request order, in waves of the
//     original size. Before every wave the tenant's policy, the version's
//     revocation, and its registration (catalog rows whose signatures
//     verify) are checked again, as CreateFleetUpdateBatch and farmer's
//     re-verification do.
//   - Items in dispatching are never re-sent: the sprout deduplicates
//     nothing, so a second send could update (or, for a §1.5 batch, run a
//     command) twice. One a dead process left there fails with
//     dispatch_outcome_unknown once its dispatcher would have given up on
//     it, which halts the rollout and frees the tenant's rollout slot. An
//     operator retries it deliberately, with a new rollout.
package saasapi

import (
	"context"
	"time"

	"github.com/nats-io/nats.go"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/controlplane"
	log "github.com/yogzblr/imas/internal/log"
)

// neverSentCodes are the error codes an update item is failed with without
// ever having been sent: refused at planning, or failed by a halt while
// still queued.
var neverSentCodes = map[string]bool{
	errCodeSproutNotAccepted:     true,
	errCodeNoReleaseForPlatform:  true,
	errCodeBelowMinSproutVersion: true,
	errCodeSproutNewerThanTarget: true,
	errCodeUpdateInProgress:      true,
	errCodeRolloutHalted:         true,
	errCodeRolloutWindowClosed:   true,
	errCodeApprovalWithdrawn:     true,
	errCodeVersionRevoked:        true,
	errCodeNotDelivered:          true,
	errCodeTenantNotActive:       true,
	errCodeExpiredNotSent:        true,
}

// wasSent reports whether it was ever handed to farmer. An item sent by
// this release has dispatched_at set (dispatchItem). One written before
// migration saas/00006 has none, and is judged by its status and error
// code; a failed one whose code doesn't say it was refused or halted
// unsent counts as sent, which can only make a resumed rollout halt, never
// send more.
func wasSent(it AssetActionItem) bool {
	switch it.Status {
	case ActionItemQueued, ActionItemUnresolved:
		return false
	case ActionItemFailed:
		return it.DispatchedAt != nil || !neverSentCodes[it.ErrorCode]
	}
	return true
}

// dispatchTimeOf is when it was sent, on the dispatching saasapi's clock:
// its dispatched_at, or for an item written before that column existed,
// its updated_at, which is never earlier than its dispatch (the same
// fallback as runningSinceProof), so the item's deadline and proof are at
// least as strict as the original's.
func dispatchTimeOf(it AssetActionItem) time.Time {
	if it.DispatchedAt != nil {
		return *it.DispatchedAt
	}
	return it.UpdatedAt
}

// tenantIsActive reports whether tenantID's status is active.
func tenantIsActive(d *gorm.DB, tenantID string) (bool, error) {
	var n int64
	err := d.Model(&Tenant{}).Where("id = ? AND status = ?", tenantID, TenantStatusActive).Count(&n).Error
	return n > 0, err
}

// rolloutRegistrationCheck is a resumed rollout's extra check before each
// wave: the tenant is still active (the POST required it; it may have
// started offboarding since), the target version still has catalog rows,
// every one of them verifies against the fleet signing key
// (selfUpdateParams), and they still build exactly the params the batch
// was created with. Revocation and the tenant's policy are
// rolloutPolicyCheck's. It returns "" to go ahead, tenant_not_active or
// rollout_halted if a check fails, or internal_error if the tenant or the
// catalog can't be read.
func rolloutRegistrationCheck(d *gorm.DB, batch AssetActionBatch, version string) string {
	if active, err := tenantIsActive(d, batch.TenantID); err != nil {
		log.Errorf("saasapi: update batch %s (tenant %s): reading the tenant: %v; halting", batch.ID, batch.TenantID, err)
		return string(controlplane.ErrorInternal)
	} else if !active {
		log.Warnf("saasapi: update batch %s (tenant %s): the tenant is no longer active; halting", batch.ID, batch.TenantID)
		return errCodeTenantNotActive
	}
	var rows []FleetVersion
	if err := d.Where("version = ?", version).Order("os").Order("arch").Order("package_type").Find(&rows).Error; err != nil {
		log.Errorf("saasapi: update batch %s (tenant %s): reading the catalog rows of %s: %v; halting", batch.ID, batch.TenantID, version, err)
		return string(controlplane.ErrorInternal)
	}
	if len(rows) == 0 {
		log.Warnf("saasapi: update batch %s (tenant %s): %s is no longer registered; halting", batch.ID, batch.TenantID, version)
		return errCodeRolloutHalted
	}
	ctx, cancel := context.WithTimeout(context.Background(), jobRefreshTimeout)
	defer cancel()
	params, err := selfUpdateParams(ctx, rows)
	if err != nil {
		log.Warnf("saasapi: update batch %s (tenant %s): the catalog entry for %s is no longer usable: %v; halting", batch.ID, batch.TenantID, version, err)
		return errCodeRolloutHalted
	}
	if string(params) != batch.ActionParams {
		log.Warnf("saasapi: update batch %s (tenant %s): the catalog entry for %s no longer matches the batch; halting", batch.ID, batch.TenantID, version)
		return errCodeRolloutHalted
	}
	return ""
}

// resumeRollout takes over an update rollout whose process died, holding
// lease, and runs it to the end from what the database records:
//
//  1. Every item already sent forms one wave, each item with the deadline
//     its own wave had (dispatched_at plus rolloutWaveTimeout) and the
//     proof it had (a report fresh after dispatched_at, or with
//     planned_at_target its job's success). That wave must pass the
//     batch's gate, as the dead process's last wave had to: job_status
//     waits for every sent item to succeed and fails on the first failure;
//     dispatch needs every sent item accepted (running or succeeded) and
//     none failed. An item left in dispatching is never re-sent: its
//     deadline is when its dispatcher would have given up on the reply
//     (stuckDispatchAfter), after which it fails with
//     dispatch_outcome_unknown and so fails the gate.
//  2. If it passes, the items still queued go out in waves of the batch's
//     size and gate, exactly as runRollout sends them, with the policy,
//     revocation and registration checked before each wave. If it fails,
//     they are failed with rollout_halted, unsent.
//  3. Every sent wave is followed to an outcome.
func resumeRollout(d *gorm.DB, nc *nats.Conn, readers rolloutReaders, batch AssetActionBatch, lease *rowLease) {
	version := selfUpdateTarget(batch)
	if version == "" || nc == nil {
		log.Errorf("saasapi: update batch %s (tenant %s) can't be resumed (no target version or no bus)", batch.ID, batch.TenantID)
		return
	}
	if !readersUsable(readers, batch) {
		log.Errorf("saasapi: no sprout facts or job status reader to resume update batch %s (tenant %s); halting", batch.ID, batch.TenantID)
		if lease.held() {
			haltRollout(d, batch, string(controlplane.ErrorInternal))
		}
		return
	}
	var items []AssetActionItem
	if err := d.Where("batch_id = ? AND tenant_id = ?", batch.ID, batch.TenantID).Order("position").Find(&items).Error; err != nil {
		log.Errorf("saasapi: resuming update batch %s (tenant %s): reading its items: %v", batch.ID, batch.TenantID, err)
		return
	}

	r := &rolloutRun{d: d, nc: nc, readers: readers, batch: batch, version: version, lease: lease, resumed: true}
	var queued []AssetActionItem
	prior := sentWave{proofs: map[string]updateProof{}, deadlines: map[string]time.Time{}}
	atTarget := make(map[SproutRef]bool)
	for _, it := range items {
		ref := SproutRef{TenantID: batch.TenantID, SproutID: it.SproutID}
		if it.PlannedAtTarget {
			atTarget[ref] = true
		}
		switch {
		case it.Status == ActionItemQueued:
			queued = append(queued, it)
		case wasSent(it):
			at := dispatchTimeOf(it)
			prior.items = append(prior.items, it)
			prior.proofs[it.AssetID] = updateProof{dispatched: at, jobSuffices: it.PlannedAtTarget}
			prior.deadlines[it.AssetID] = at.Add(rolloutWaveTimeout)
			if it.Status == ActionItemDispatching {
				// No reply will ever come for it: its dispatcher is gone.
				// It fails once that dispatcher would have given up.
				prior.deadlines[it.AssetID] = at.Add(stuckDispatchAfter(batch))
			}
		}
	}
	log.Warnf("saasapi: resuming update batch %s (tenant %s) to %s: %d items already sent, %d still queued, waves of %d, gate %s",
		batch.ID, batch.TenantID, version, len(prior.items), len(queued), batch.RolloutBatchSize, batch.RolloutGate)

	if len(prior.items) > 0 {
		r.sent = append(r.sent, prior)
		var passed bool
		switch batch.RolloutGate {
		case gateDispatch:
			_, failed := pollWave(d, readers, batch, prior)
			passed = !failed && waveAccepted(d, batch, prior)
		default:
			passed = awaitWave(d, readers, batch, prior, true, lease)
		}
		if r.lostLease() {
			return
		}
		if !passed && len(queued) > 0 {
			log.Warnf("saasapi: update batch %s (tenant %s): the items sent before the takeover did not pass the %s gate; halting",
				batch.ID, batch.TenantID, batch.RolloutGate)
			r.finish(errCodeRolloutHalted)
			return
		}
	}
	r.sendWaves(queued, atTarget)
}

// sweepRollouts is the outbox sweeper's rollout job, run only while fleet
// update dispatch is enabled. It finds self_update batches with items
// still queued, dispatching or running whose lease has lapsed, takes each
// one over
// (claimRolloutTakeover) and resumes it in the background under its lease
// (resumeRollout).
//
// A batch with no lease at all was written by the previous release, which
// didn't take one; its process may still be running it. It is taken over
// only once none of its items has changed for longer than any wave of a
// live rollout goes without a write (rolloutWaveTimeout, plus the reply
// wait and the lease TTL as margin).
//
// A batch whose only unfinished items are in dispatching is resumed too:
// that is how such an item, which a dead process left with no reply, is
// failed (dispatch_outcome_unknown) and stops holding the tenant's rollout
// slot.
func (sw *sweeper) sweepRollouts() {
	if !fleetUpdateDispatchEnabled {
		return
	}
	now := dbTime(outboxNow())
	type ref struct{ BatchID, TenantID string }
	var refs []ref
	if err := sw.d.Table(AssetActionItem{}.TableName()+" AS i").
		Joins("JOIN "+AssetActionBatch{}.TableName()+" AS b ON b.id = i.batch_id AND b.tenant_id = i.tenant_id").
		Where("i.status IN ? AND b.action_type = ?",
			[]AssetActionItemStatus{ActionItemQueued, ActionItemDispatching, ActionItemRunning}, controlplane.ActionSelfUpdate).
		Where("(b.lease_until IS NULL OR b.lease_until < ?)", now).
		Distinct("i.batch_id", "i.tenant_id").Order("i.batch_id").Limit(sweepBatchLimit).
		Scan(&refs).Error; err != nil {
		log.Errorf("saasapi: outbox sweep: finding update rollouts to resume: %v", err)
		return
	}
	for _, r := range refs {
		sw.takeOverRollout(r.BatchID, r.TenantID, now)
	}
}

// legacyRolloutQuiet is how long a never-leased rollout's items must have
// been unchanged before sweepRollouts takes it over.
func (sw *sweeper) legacyRolloutQuiet() time.Duration {
	return rolloutWaveTimeout + farmerSproutWait + dispatchReplyMargin + sw.s.LeaseTTL
}

// takeOverRollout is sweepRollouts for one batch.
func (sw *sweeper) takeOverRollout(batchID, tenantID string, now time.Time) {
	var batch AssetActionBatch
	if err := sw.d.Where("id = ? AND tenant_id = ? AND action_type = ?", batchID, tenantID, controlplane.ActionSelfUpdate).
		First(&batch).Error; err != nil {
		log.Errorf("saasapi: outbox sweep: reading update batch %s (tenant %s): %v", batchID, tenantID, err)
		return
	}
	if batch.LeaseUntil == nil {
		var items []AssetActionItem
		if err := sw.d.Select("batch_id", "asset_id", "updated_at").
			Where("batch_id = ? AND tenant_id = ?", batch.ID, batch.TenantID).Find(&items).Error; err != nil {
			log.Errorf("saasapi: outbox sweep: reading update batch %s (tenant %s): %v", batch.ID, batch.TenantID, err)
			return
		}
		for _, it := range items {
			if now.Sub(it.UpdatedAt) < sw.legacyRolloutQuiet() {
				return
			}
		}
	}
	lease, err := claimRolloutTakeover(sw.d, batch, sw.s.LeaseTTL)
	if err != nil {
		log.Errorf("saasapi: outbox sweep: taking over update batch %s (tenant %s): %v", batch.ID, batch.TenantID, err)
		return
	}
	if lease == nil {
		return // another replica has it, or its process renewed in time
	}
	d, nc, readers := sw.d, sw.nc, sw.readers
	actionDispatches.Add(1)
	go func() {
		defer actionDispatches.Done()
		lease.keepAlive()
		defer lease.stopKeepAlive()
		resumeRollout(d, nc, readers, batch, lease)
	}()
}

// claimRolloutTakeover claims batch's lapsed lease and, in the same
// transaction, takes over the tenant's rollout claim: it rewrites the
// tenant_update_policy row's rollout_claimed_at, as claimRollout does when
// a rollout starts, so that on PXC a takeover and anything else claiming
// the tenant's one rollout slot on another node write the same row and
// certification refuses one of them. It returns nil, nil if the lease
// wasn't free.
func claimRolloutTakeover(d *gorm.DB, batch AssetActionBatch, ttl time.Duration) (*rowLease, error) {
	var lease *rowLease
	err := d.Transaction(func(tx *gorm.DB) error {
		l, err := claimRowLease(tx, batch.TableName(), batchLeaseKey, []any{batch.ID, batch.TenantID},
			"action_type = ?", []any{controlplane.ActionSelfUpdate}, nil, ttl)
		if err != nil || l == nil {
			return err
		}
		var policies []TenantUpdatePolicy
		if err := tx.Where("tenant_id = ?", batch.TenantID).Limit(1).Find(&policies).Error; err != nil {
			return err
		}
		if len(policies) > 0 {
			var prev time.Time
			if policies[0].RolloutClaimedAt != nil {
				prev = *policies[0].RolloutClaimedAt
			}
			if err := tx.Model(&TenantUpdatePolicy{}).Where("tenant_id = ?", batch.TenantID).
				UpdateColumn("rollout_claimed_at", claimTimestamp(outboxNow(), prev)).Error; err != nil {
				return err
			}
		}
		lease = l
		return nil
	})
	if err != nil || lease == nil {
		return nil, err
	}
	lease.d = d // claimed inside tx; renewed outside it
	return lease, nil
}
