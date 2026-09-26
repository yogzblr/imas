package jobs

import (
	"errors"
	"time"

	"gorm.io/gorm"

	log "github.com/yogzblr/imas/internal/log"
)

// reconcileWindow is config.JobReconcileWindow: how long after dispatch a
// job may start on its sprout and still be recorded. 0 disables the
// check. Set once at startup via SetReconcileWindow.
var reconcileWindow time.Duration

// SetReconcileWindow installs the job reconcile window (see
// config.JobReconcileWindow). Call once at startup, before
// RegisterNatsConn.
func SetReconcileWindow(d time.Duration) { reconcileWindow = d }

// reconcileClock is time.Now, swappable in tests.
var reconcileClock = time.Now

// shouldReconcile reports whether an event of job jid on sproutID is
// recorded. With a reconcile window set, a job that has not started yet
// (no start event recorded) and was dispatched longer ago than the
// window is not: that is a sprout cooking a job long after it was
// dispatched, e.g. the staged copy of a push it missed. Its start event
// and every later event are dropped. A job that started within the
// window is recorded to the end, however long it then runs.
//
// It fails open: with no window, no index, no row for the job yet (its
// creation event may still be in flight on another replica), no dispatch
// time recorded, or a lookup error, the event is recorded as before.
func shouldReconcile(tenantID, sproutID, jid string) bool {
	window := reconcileWindow
	d := db
	if window <= 0 || d == nil {
		return true
	}
	ctx, cancel := opContext()
	defer cancel()
	var row jobStatusRow
	err := d.WithContext(ctx).Select("started", "dispatched_at").
		Where("tenant_id = ? AND sprout_id = ? AND jid = ?", tenantID, sproutID, jid).
		Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return true
	}
	if err != nil {
		log.Errorf("job status index: looking up job %s (sprout %s, tenant %s) for the reconcile window: %v", jid, sproutID, tenantID, err)
		return true
	}
	if row.Started || row.DispatchedAt == nil {
		return true
	}
	return reconcileClock().Sub(*row.DispatchedAt) <= window
}
