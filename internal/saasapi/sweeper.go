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
//     went out and cmd.run is not idempotent (AssetActionItemStatus). See
//     sweepActionBatches.
//   - self_update rollouts whose process died: resumed, wave by wave,
//     after the batch's lease has lapsed. See sweepRollouts.
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
	defaultOutboxMaxAttempts      = 5
	defaultOutboxLeaseTTL         = 2 * time.Minute

	minOutboxSweepInterval = time.Second
	maxOutboxSweepInterval = time.Hour
	minOutboxStaleAfter    = 10 * time.Second
	maxOutboxStaleAfter    = 24 * time.Hour
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
}
