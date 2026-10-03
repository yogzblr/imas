// Security-sensitive: the outbox sweeper re-sends work to farmer that no
// live process is sending, including commands to tenants' machines. FLAG
// FOR SECURITY REVIEW per the CL.3 brief. What it may and may not re-send
// is the point of this file:
//
//   - provisioning_jobs still pending: re-published. farmer's
//     internal.tenant.provision and .deprovision handlers are idempotent
//     for a repeated job_id, and saasapi applies one result per job
//     (applyProvisioningResult). See sweepProvisioningJobs.
//   - §1.5 action items still queued: re-dispatched from the batch's
//     stored action_params. A queued item has provably never reached
//     farmer (dispatchItem moves it back to queued only on "no
//     responders"). Items in dispatching are NEVER re-sent: their request
//     went out, cmd.run is not idempotent (AssetActionItemStatus), and
//     nothing downstream deduplicates a second send. One a dead process
//     left there is failed with dispatch_outcome_unknown once its
//     dispatcher would have given up on it. A queued item accepted longer
//     ago than SAASAPI_OUTBOX_ACTION_MAX_AGE is failed, never sent late.
//     See sweepActionBatches.
//   - self_update rollouts whose process died: resumed, wave by wave,
//     after the batch's lease has lapsed, only while fleet update dispatch
//     is enabled. See sweepRollouts and rollout_resume.go.
//
// Every item and job is still claimed by the same conditional UPDATE the
// original dispatch uses, so a sweeper and a live dispatcher, or two
// sweepers, never both send one item; the row lease (outbox_lease.go) on
// top of that keeps two processes from working the same batch or job at
// all. Nothing here logs action params, command lines or credentials:
// only ids, statuses and counts.
package saasapi

import (
	"context"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/controlplane"
	log "github.com/yogzblr/imas/internal/log"
)

// OutboxSweeperSettings configures the outbox sweeper and the leases every
// dispatcher takes (Config.OutboxSweeper; SAASAPI_OUTBOX_*).
type OutboxSweeperSettings struct {
	// Enabled runs the sweeper (SAASAPI_OUTBOX_SWEEPER_ENABLED, default
	// true). Off, dispatchers still take and renew leases, so turning it
	// on later on any replica is safe.
	Enabled bool
	// Interval is the time between sweeps (SAASAPI_OUTBOX_SWEEP_INTERVAL).
	Interval time.Duration
	// ProvisioningStaleAfter is how long a provisioning job may stay
	// pending after it was last published before it is published again;
	// it doubles with each attempt (SAASAPI_OUTBOX_PROVISIONING_STALE_AFTER).
	ProvisioningStaleAfter time.Duration
	// ActionStaleAfter is the same for a queued §1.5 action item, measured
	// from its last change (SAASAPI_OUTBOX_ACTION_STALE_AFTER).
	ActionStaleAfter time.Duration
	// ActionMaxAge is how long after it was accepted a §1.5 action item may
	// still be sent (SAASAPI_OUTBOX_ACTION_MAX_AGE). Past it, a queued item
	// fails with expired_not_sent, by the original dispatcher or the
	// sweeper, whichever reaches it. Nothing downstream bounds this: the
	// sealed envelope's ±5 minute window is measured from when farmer seals
	// it at dispatch, not from when saasapi accepted the request.
	ActionMaxAge time.Duration
	// MaxAttempts bounds the publishes of a provisioning job and the
	// dispatches of an action item, counting the first
	// (SAASAPI_OUTBOX_MAX_ATTEMPTS). Past it the job or item is failed.
	MaxAttempts int
	// LeaseTTL is how long a lease lasts without renewal: how soon a
	// rollout or batch whose process died can be taken over
	// (SAASAPI_OUTBOX_LEASE_TTL). Holders renew every third of it.
	LeaseTTL time.Duration
}

// Defaults and bounds for OutboxSweeperSettings. LoadConfig refuses a
// value outside its bounds.
const (
	defaultOutboxSweepInterval    = 30 * time.Second
	defaultProvisioningStaleAfter = 2 * time.Minute
	defaultActionStaleAfter       = 2 * time.Minute
	defaultActionMaxAge           = 15 * time.Minute
	defaultOutboxMaxAttempts      = 5
	defaultOutboxLeaseTTL         = 2 * time.Minute

	minOutboxSweepInterval = time.Second
	maxOutboxSweepInterval = time.Hour
	minOutboxStaleAfter    = 10 * time.Second
	maxOutboxStaleAfter    = 24 * time.Hour
	minActionMaxAge        = time.Minute
	maxActionMaxAge        = time.Hour
	maxOutboxMaxAttempts   = 50
	minOutboxLeaseTTL      = 15 * time.Second
	maxOutboxLeaseTTL      = time.Hour

	// maxBackoffDoublings caps the exponential backoff: the wait before a
	// re-dispatch is at most the stale threshold times 64.
	maxBackoffDoublings = 6

	// sweepBatchLimit bounds how many rows of each kind one sweep looks
	// at, so one sweep's queries and goroutines stay small; the rest wait
	// for the next sweep.
	sweepBatchLimit = 50
)

// DefaultOutboxSweeperSettings is what LoadConfig starts from.
func DefaultOutboxSweeperSettings() OutboxSweeperSettings {
	return OutboxSweeperSettings{
		Enabled:                true,
		Interval:               defaultOutboxSweepInterval,
		ProvisioningStaleAfter: defaultProvisioningStaleAfter,
		ActionStaleAfter:       defaultActionStaleAfter,
		ActionMaxAge:           defaultActionMaxAge,
		MaxAttempts:            defaultOutboxMaxAttempts,
		LeaseTTL:               defaultOutboxLeaseTTL,
	}
}

// outboxSettings is the configuration in use (SetOutboxSweeperSettings).
var outboxSettings = DefaultOutboxSweeperSettings()

// SetOutboxSweeperSettings installs s. Like SetDB, call it once at startup,
// before NewRouter's handlers serve requests: their dispatches take leases
// with s.LeaseTTL. LoadConfig has already validated s.
func SetOutboxSweeperSettings(s OutboxSweeperSettings) { outboxSettings = s }

// CurrentOutboxSweeperSettings returns the settings in use.
func CurrentOutboxSweeperSettings() OutboxSweeperSettings { return outboxSettings }

// backoff is how long after its last dispatch a job or item that has been
// dispatched attempts times is due again: stale, doubling per attempt
// after the first, at most maxBackoffDoublings times. Zero attempts (never
// dispatched, e.g. no bus at the time) waits stale.
func backoff(stale time.Duration, attempts int) time.Duration {
	n := attempts - 1
	if n < 0 {
		n = 0
	}
	if n > maxBackoffDoublings {
		n = maxBackoffDoublings
	}
	return stale << n
}

// sweeper is one replica's outbox sweeper. The database and bus are
// captured when it starts, like startBatchDispatch's.
type sweeper struct {
	d       *gorm.DB
	nc      *nats.Conn
	readers rolloutReaders
	s       OutboxSweeperSettings
}

// StartOutboxSweeper runs the outbox sweeper every outboxSettings.Interval
// until ctx is done, if outboxSettings.Enabled. Call it after SetDB, SetBus
// and the reader setters. It returns at once; wait blocks until the sweep
// loop has stopped (work it started in the background, under a lease, is
// left to finish or to lapse).
func StartOutboxSweeper(ctx context.Context) (wait func()) {
	var wg sync.WaitGroup
	if !outboxSettings.Enabled {
		log.Infof("saasapi: outbox sweeper disabled (SAASAPI_OUTBOX_SWEEPER_ENABLED=false)")
		return wg.Wait
	}
	sw := &sweeper{d: db, nc: bus, readers: rolloutReaders{jobs: jobStatusReader, facts: sproutFactsReader}, s: outboxSettings}
	log.Infof("saasapi: outbox sweeper running every %s on %s (lease TTL %s, max %d attempts)",
		sw.s.Interval, replicaName, sw.s.LeaseTTL, sw.s.MaxAttempts)
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(sw.s.Interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				sw.sweep()
			}
		}
	}()
	return wg.Wait
}

// sweep runs every job of the sweeper once. With no bus connection it does
// nothing: there would be nothing to send on, and claiming rows it can't
// work would only delay another replica that can.
func (sw *sweeper) sweep() {
	if sw.d == nil || sw.nc == nil || !sw.nc.IsConnected() {
		log.Debugf("saasapi: outbox sweep skipped: not connected to the NATS bus")
		return
	}
	sw.sweepProvisioningJobs()
	sw.sweepActionBatches()
	sw.sweepRollouts()
}

// sweepActionBatches is the outbox sweeper's §1.5 job. It finds batches
// (not update rollouts: sweepRollouts resumes those) whose lease has lapsed
// or was never set and that have work: a queued item due again (backoff
// from the item's last change, counting its attempts), a queued item past
// SAASAPI_OUTBOX_ACTION_MAX_AGE, or an item a dead process left in
// dispatching. For each, it claims the batch's lease and then:
//
//   - fails a stuck dispatching item (stuckDispatching) with
//     dispatch_outcome_unknown. It is never re-sent: its request went out,
//     or may have, and nothing downstream deduplicates a second send, so
//     cmd.run could run twice. An operator can retry it deliberately;
//   - fails a queued item accepted more than SAASAPI_OUTBOX_ACTION_MAX_AGE
//     ago with expired_not_sent, unsent;
//   - fails the batch's other due items with tenant_not_active, unsent, if
//     its tenant is no longer active;
//   - fails a due item already dispatched SAASAPI_OUTBOX_MAX_ATTEMPTS times
//     (each time back to queued: no farmer was listening) with
//     dispatch_not_delivered;
//   - and dispatches the remaining due items in the background under the
//     lease, from the batch's stored action_params, exactly as the original
//     dispatch would have (dispatchBatch).
//
// Only queued items are ever sent: a queued item has provably never
// reached farmer. dispatchItem's queued -> dispatching claim still guards
// every send, so even a live dispatcher that outlived its lease can't send
// an item the sweeper also sends.
func (sw *sweeper) sweepActionBatches() {
	now := dbTime(outboxNow())
	// The shortest stuckDispatchAfter of any batch (a cook, or a cmd.run
	// with the shortest timeout); redispatchBatch checks each item exactly.
	minStuck := farmerSproutWait + 2*dispatchReplyMargin
	type ref struct{ BatchID, TenantID string }
	var refs []ref
	if err := sw.d.Table(AssetActionItem{}.TableName()+" AS i").
		Joins("JOIN "+AssetActionBatch{}.TableName()+" AS b ON b.id = i.batch_id AND b.tenant_id = i.tenant_id").
		Where("b.action_type <> ?", controlplane.ActionSelfUpdate).
		Where("(i.status = ? AND (i.updated_at <= ? OR i.created_at <= ?)) OR (i.status = ? AND i.updated_at <= ?)",
			ActionItemQueued, now.Add(-sw.s.ActionStaleAfter), now.Add(-sw.s.ActionMaxAge),
			ActionItemDispatching, now.Add(-minStuck)).
		Where("(b.lease_until IS NULL OR b.lease_until < ?)", now).
		Distinct("i.batch_id", "i.tenant_id").Order("i.batch_id").Limit(sweepBatchLimit).
		Scan(&refs).Error; err != nil {
		log.Errorf("saasapi: outbox sweep: finding queued action items: %v", err)
		return
	}
	for _, r := range refs {
		sw.redispatchBatch(r.BatchID, r.TenantID, now)
	}
}

// redispatchBatch is sweepActionBatches for one batch.
func (sw *sweeper) redispatchBatch(batchID, tenantID string, now time.Time) {
	var batch AssetActionBatch
	if err := sw.d.Where("id = ? AND tenant_id = ?", batchID, tenantID).First(&batch).Error; err != nil {
		log.Errorf("saasapi: outbox sweep: reading action batch %s (tenant %s): %v", batchID, tenantID, err)
		return
	}
	if batch.ActionType == controlplane.ActionSelfUpdate {
		return
	}
	var open []AssetActionItem
	if err := sw.d.Where("batch_id = ? AND tenant_id = ? AND status IN ?", batch.ID, batch.TenantID,
		[]AssetActionItemStatus{ActionItemQueued, ActionItemDispatching}).
		Order("position").Find(&open).Error; err != nil {
		log.Errorf("saasapi: outbox sweep: reading open items of batch %s (tenant %s): %v", batch.ID, batch.TenantID, err)
		return
	}
	var stuck, expired, due, exhausted []AssetActionItem
	for _, it := range open {
		switch {
		case it.Status == ActionItemDispatching:
			if stuckDispatching(batch, it, now) {
				stuck = append(stuck, it)
			}
		case actionExpired(batch, it, now, sw.s.ActionMaxAge):
			expired = append(expired, it)
		case now.Before(it.UpdatedAt.Add(backoff(sw.s.ActionStaleAfter, it.Attempts))):
		case it.Attempts >= sw.s.MaxAttempts:
			exhausted = append(exhausted, it)
		default:
			due = append(due, it)
		}
	}
	if len(stuck)+len(expired)+len(due)+len(exhausted) == 0 {
		return
	}
	lease, err := claimRowLease(sw.d, batch.TableName(), batchLeaseKey, []any{batch.ID, batch.TenantID},
		"action_type <> ?", []any{controlplane.ActionSelfUpdate}, nil, sw.s.LeaseTTL)
	if err != nil {
		log.Errorf("saasapi: outbox sweep: claiming action batch %s (tenant %s): %v", batch.ID, batch.TenantID, err)
		return
	}
	if lease == nil {
		return // another replica has it, or its dispatcher renewed in time
	}
	for _, it := range stuck {
		failStuckDispatching(sw.d, batch, it)
	}
	for _, it := range expired {
		expireItem(sw.d, batch, it)
	}
	if len(due)+len(exhausted) == 0 {
		return
	}
	// The POST required an active tenant. One that has since started
	// offboarding gets nothing more sent: its due items fail unsent.
	active, err := tenantIsActive(sw.d, batch.TenantID)
	if err != nil {
		log.Errorf("saasapi: outbox sweep: reading tenant %s of batch %s: %v", batch.TenantID, batch.ID, err)
		return
	}
	if !active {
		for _, it := range append(due, exhausted...) {
			if _, err := updateItem(sw.d, it, ActionItemQueued, failedUpdate(errCodeTenantNotActive)); err != nil {
				log.Errorf("saasapi: outbox sweep: failing batch %s asset %s: %v", batch.ID, it.AssetID, err)
			}
		}
		log.Warnf("saasapi: outbox sweep: tenant %s is no longer active; failed %d queued items of batch %s unsent",
			batch.TenantID, len(due)+len(exhausted), batch.ID)
		return
	}
	for _, it := range exhausted {
		if ok, err := updateItem(sw.d, it, ActionItemQueued, failedUpdate(errCodeNotDelivered)); err != nil {
			log.Errorf("saasapi: outbox sweep: failing batch %s asset %s: %v", batch.ID, it.AssetID, err)
		} else if ok {
			log.Warnf("saasapi: outbox sweep: batch %s (tenant %s) asset %s was never delivered in %d attempts; failed with %s",
				batch.ID, batch.TenantID, it.AssetID, it.Attempts, errCodeNotDelivered)
		}
	}
	if len(due) == 0 {
		return
	}
	log.Warnf("saasapi: outbox sweep: re-dispatching %d queued items of action batch %s (tenant %s, %s)",
		len(due), batch.ID, batch.TenantID, batch.ActionType)
	actionDispatches.Add(1)
	go func() {
		defer actionDispatches.Done()
		lease.keepAlive()
		defer lease.stopKeepAlive()
		dispatchBatch(sw.d, sw.nc, batch, due, lease)
	}()
}
