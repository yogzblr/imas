package jobs

// The job-status index: a small PXC table (farmer.job_status) recording
// each cook job's aggregate status, keyed by (tenant_id, sprout_id, jid).
// It exists so the SaaS API can poll a §1.5 batch's cook items with one
// local, tenant-scoped SQL read
// (docs/design/cloudxp-machine-manager-api-design.md §1.5), rather than
// reading farmer's job object store. The object store has no tenant in its
// keys, and the SaaS API has no access to it.
//
// The index is written alongside the object-store writes in listener.go
// (logJobCreation, logJobs), not instead of them: the object store stays
// the job log and the source of truth for everything else in this package.
// A failed index write is logged and never stops the object-store write,
// and with no database installed (SetDB never called) indexing is off.
//
// # Concurrent, unordered writers
//
// RegisterNatsConn queue-subscribes, so one job's events are spread across
// farmer replicas and applied concurrently, in no guaranteed order — the
// same reason store.go writes one object per event. So no event writes
// the status directly. Each event applies a commutative update to its
// row's counters and flags, which only ever grow (upsertJobEvent):
//
//   - the creation event sets steps_total (the envelope's step count)
//   - "start-<jid>" sets started
//   - each step's completion increments steps_reported, and sets
//     step_failed if the step failed
//   - "completed-<jid>" sets finished; "timeout-<jid>" sets timed_out
//
// Then status is recomputed from the row as it stands (refreshJobStatus,
// jobStatusExpr). A job is terminal only once it's finished AND every step
// has reported. That matters because the sprout's completed-<jid> event
// always says StepCompleted, even when a step failed
// (cook.CookRecipeEnvelope), and a failed step's event can be applied
// after it on another replica. Until the counts agree the job reads as
// running, so a late failure can't be missed by a reader that has already
// seen the job as succeeded.
//
// Whichever replica recomputes last has seen every update applied before
// it, so the stored status always catches up to the full set of events.
//
// # Tenant scoping
//
// tenant_id is the tenant whose NATS connection the event arrived on (the
// tenantID RegisterNatsConn was called with), never anything from the
// message itself. sprout_id is only unique per tenant, so every row, and
// every read (the SaaS API's included), is keyed on the full triple.

import (
	"context"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/yogzblr/imas/internal/cook"
	log "github.com/yogzblr/imas/internal/log"
)

// Index statuses stored in job_status.status. The SaaS API reads these
// strings from farmer.job_status (internal/saasapi/job_status.go mirrors
// them; its tests pin the two together).
const (
	JobIndexStatusPending   = "pending"
	JobIndexStatusRunning   = "running"
	JobIndexStatusSucceeded = "succeeded"
	JobIndexStatusFailed    = "failed"
)

// Column sizes. tenant_id and sprout_id match internal/pki's pki_nkeys;
// jid fits cook.GenerateJobID's UUIDs with room to spare.
const (
	maxIndexTenantIDLen = 191
	maxIndexSproutIDLen = 253
	maxIndexJIDLen      = 64
)

// jobStatusRow is the farmer.job_status table. Status is derived from the
// other columns (jobStatusExpr); they're stored so every writer's update
// can be commutative.
type jobStatusRow struct {
	TenantID      string    `gorm:"column:tenant_id;primaryKey;size:191"`
	SproutID      string    `gorm:"column:sprout_id;primaryKey;size:253"`
	JID           string    `gorm:"column:jid;primaryKey;size:64"`
	Status        string    `gorm:"column:status;size:16;not null"`
	StepsTotal    *int      `gorm:"column:steps_total"`
	StepsReported int       `gorm:"column:steps_reported;not null;default:0"`
	StepFailed    bool      `gorm:"column:step_failed;not null;default:false"`
	Started       bool      `gorm:"column:started;not null;default:false"`
	Finished      bool      `gorm:"column:finished;not null;default:false"`
	TimedOut      bool      `gorm:"column:timed_out;not null;default:false"`
	UpdatedAt     time.Time `gorm:"column:updated_at;not null;index"`
	// DispatchedAt is when farmer dispatched the job (the envelope's
	// DispatchedAt), from its creation event. Nil for jobs created before
	// it was recorded. shouldReconcile dates a job's start by it.
	DispatchedAt *time.Time `gorm:"column:dispatched_at"`
}

func (jobStatusRow) TableName() string { return "job_status" }

// Models returns the GORM models this package owns, for callers assembling
// a single AutoMigrate call across the whole farmer schema (as
// cmd/farmer/main.go does for pki, props and rbac).
func Models() []any { return []any{&jobStatusRow{}} }

// db is the farmer-schema handle the index is written through. Nil
// disables indexing; the object-store job log is unaffected.
var db *gorm.DB

// SetDB installs the farmer-schema handle for the job-status index. Call
// once at startup, after the schema (including Models()) is migrated.
func SetDB(d *gorm.DB) { db = d }

// jobStatusExpr computes a row's status from its counters and flags. It
// reads only columns, so it gives the same answer whichever order the
// events were applied in.
const jobStatusExpr = `CASE
	WHEN timed_out THEN '` + JobIndexStatusFailed + `'
	WHEN finished AND steps_total IS NOT NULL AND steps_reported >= steps_total THEN
		CASE WHEN step_failed THEN '` + JobIndexStatusFailed + `' ELSE '` + JobIndexStatusSucceeded + `' END
	WHEN started OR finished OR steps_reported > 0 THEN '` + JobIndexStatusRunning + `'
	ELSE '` + JobIndexStatusPending + `'
END`

// jobEvent is one event's contribution to its job's row.
type jobEvent struct {
	stepsTotal   *int       // the creation event only
	dispatchedAt *time.Time // the creation event only
	started      bool
	step         bool // a step's own completion (counted)
	stepFailed   bool
	finished     bool
	timedOut     bool
}

// classifyJobEvent maps a imas.cook.<sprout>.<jid> event to its index
// update, by the step IDs cook.CookRecipeEnvelope uses for its bookend
// events; any other ID is a step's own completion.
func classifyJobEvent(jid string, step cook.StepCompletion) jobEvent {
	switch string(step.ID) {
	case "start-" + jid:
		return jobEvent{started: true}
	case "completed-" + jid:
		return jobEvent{finished: true}
	case "timeout-" + jid:
		return jobEvent{timedOut: true}
	}
	return jobEvent{step: true, stepFailed: step.CompletionStatus == cook.StepFailed}
}

// indexJobCreation records a job's step count and dispatch time from its
// creation envelope.
func indexJobCreation(tenantID, sproutID, jid string, steps int, dispatchedAt time.Time) {
	at := dispatchedAt.UTC()
	indexJobEvent(tenantID, sproutID, jid, jobEvent{stepsTotal: &steps, dispatchedAt: &at})
}

// indexJobEvent applies ev to the job's row and recomputes its status.
// Best-effort: a failure is logged and dropped. The job log in the object
// store is written independently.
func indexJobEvent(tenantID, sproutID, jid string, ev jobEvent) {
	d := db
	if d == nil {
		return
	}
	if tenantID == "" || len(tenantID) > maxIndexTenantIDLen || sproutID == "" ||
		len(sproutID) > maxIndexSproutIDLen || jid == "" || len(jid) > maxIndexJIDLen {
		log.Errorf("job status index: not indexing job %q for sprout %q (tenant %q): identifiers out of range", jid, sproutID, tenantID)
		return
	}
	ctx, cancel := opContext()
	defer cancel()
	err := retryOnConflict(ctx, func() error { return upsertJobEvent(ctx, d, tenantID, sproutID, jid, ev) })
	if err != nil {
		log.Errorf("job status index: recording event for job %s (sprout %s, tenant %s): %v", jid, sproutID, tenantID, err)
		return
	}
	err = retryOnConflict(ctx, func() error { return refreshJobStatus(ctx, d, tenantID, sproutID, jid) })
	if err != nil {
		log.Errorf("job status index: updating status of job %s (sprout %s, tenant %s): %v", jid, sproutID, tenantID, err)
	}
}

// conflictRetries bounds retryOnConflict's attempts.
const conflictRetries = 5

// retryOnConflict runs write until it succeeds, fails with anything other
// than a write conflict, or has tried conflictRetries times.
//
// One job's events are written concurrently by several farmer replicas,
// possibly through different PXC nodes, and Galera rejects the loser of
// two concurrent writes to the same row at commit with a deadlock error
// (1213). That write was rolled back, so repeating it is safe, and it has
// to be repeated: a dropped step increment would leave its job running
// forever. Any other error is not retried, since the write may have
// committed and repeating an increment would double-count a step.
func retryOnConflict(ctx context.Context, write func() error) error {
	var err error
	for attempt := range conflictRetries {
		if err = write(); err == nil || !isWriteConflict(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(time.Duration(attempt+1) * 20 * time.Millisecond):
		}
	}
	return err
}

// isWriteConflict reports whether err is MySQL/PXC's deadlock error, 1213
// (ER_LOCK_DEADLOCK), which Galera also returns for a certification
// conflict. Matched on go-sql-driver's fixed "Error 1213" message prefix
// rather than its typed *mysql.MySQLError, to avoid importing the driver
// directly here (it's MPL-2.0; see CLAUDE.md's licensing rule).
func isWriteConflict(err error) bool {
	return strings.Contains(err.Error(), "Error 1213")
}

// upsertJobEvent inserts the job's row if it's the first event seen, or
// applies ev to the existing row. Every assignment either sets a value
// that never changes (steps_total), sets a flag that only goes one way, or
// increments a counter, so concurrent events commute.
func upsertJobEvent(ctx context.Context, d *gorm.DB, tenantID, sproutID, jid string, ev jobEvent) error {
	now := time.Now().UTC()
	row := jobStatusRow{
		TenantID:     tenantID,
		SproutID:     sproutID,
		JID:          jid,
		Status:       JobIndexStatusPending,
		StepsTotal:   ev.stepsTotal,
		DispatchedAt: ev.dispatchedAt,
		StepFailed:   ev.stepFailed,
		Started:      ev.started,
		Finished:     ev.finished,
		TimedOut:     ev.timedOut,
		UpdatedAt:    now,
	}
	updates := map[string]any{"updated_at": now}
	if ev.stepsTotal != nil {
		updates["steps_total"] = *ev.stepsTotal
	}
	if ev.dispatchedAt != nil {
		updates["dispatched_at"] = *ev.dispatchedAt
	}
	if ev.step {
		row.StepsReported = 1
		updates["steps_reported"] = gorm.Expr("steps_reported + 1")
	}
	for col, set := range map[string]bool{"step_failed": ev.stepFailed, "started": ev.started, "finished": ev.finished, "timed_out": ev.timedOut} {
		if set {
			updates[col] = true
		}
	}
	return d.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "sprout_id"}, {Name: "jid"}},
		DoUpdates: clause.Assignments(updates),
	}).Create(&row).Error
}

// refreshJobStatus recomputes the row's status from its current columns.
func refreshJobStatus(ctx context.Context, d *gorm.DB, tenantID, sproutID, jid string) error {
	return d.WithContext(ctx).Model(&jobStatusRow{}).
		Where("tenant_id = ? AND sprout_id = ? AND jid = ?", tenantID, sproutID, jid).
		Updates(map[string]any{"status": gorm.Expr(jobStatusExpr), "updated_at": time.Now().UTC()}).Error
}

// reapJobStatusIndex deletes index rows untouched since cutoff. It's the
// index's own expiry, by its own updated_at, independent of the object
// store's (reap): rows need no object-store lookup to date them, and a
// row outliving its job log by up to a reaper interval is harmless.
func reapJobStatusIndex(cutoff time.Time) {
	d := db
	if d == nil {
		return
	}
	ctx, cancel := opContext()
	defer cancel()
	res := d.WithContext(ctx).Where("updated_at < ?", cutoff.UTC()).Delete(&jobStatusRow{})
	if res.Error != nil {
		log.Errorf("reaper: expiring job status index rows: %v", res.Error)
		return
	}
	if res.RowsAffected > 0 {
		log.Noticef("reaper: removed %d expired job status index row(s)", res.RowsAffected)
	}
}
