package jobs

import (
	"encoding/json"
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

// reconcileVerdict is what reconcileCheck decided about one event.
type reconcileVerdict int

const (
	// reconcileRecord: record the event as usual.
	reconcileRecord reconcileVerdict = iota
	// reconcileExpire: the job has just been found late; mark it expired
	// (markJobExpired) and drop the event.
	reconcileExpire
	// reconcileDrop: the job was already marked expired; drop the event.
	reconcileDrop
)

// reconcileCheck decides whether an event of job jid on sproutID is
// recorded. With a reconcile window set, a job that has not started yet
// (no start event recorded) and was dispatched longer ago than the
// window is not: that is a sprout cooking a job long after it was
// dispatched, e.g. the staged copy of a push it missed. It is marked
// expired, and its start event and every later event are dropped. A job
// that started within the window is recorded to the end, however long it
// then runs. A job already marked expired stays expired, whatever the
// window is now.
//
// It fails open: with no window, no index, no row for the job yet (its
// creation event may still be in flight on another replica), no dispatch
// time recorded, or a lookup error, the event is recorded as before.
func reconcileCheck(tenantID, sproutID, jid string) (reconcileVerdict, *time.Time) {
	window := reconcileWindow
	d := db
	if window <= 0 || d == nil {
		return reconcileRecord, nil
	}
	ctx, cancel := opContext()
	defer cancel()
	var row jobStatusRow
	err := d.WithContext(ctx).Select("started", "expired", "dispatched_at").
		Where("tenant_id = ? AND sprout_id = ? AND jid = ?", tenantID, sproutID, jid).
		Take(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return reconcileRecord, nil
	}
	if err != nil {
		log.Errorf("job status index: looking up job %s (sprout %s, tenant %s) for the reconcile window: %v", jid, sproutID, tenantID, err)
		return reconcileRecord, nil
	}
	switch {
	case row.Expired:
		return reconcileDrop, row.DispatchedAt
	case row.Started || row.DispatchedAt == nil:
		return reconcileRecord, nil
	case reconcileClock().Sub(*row.DispatchedAt) <= window:
		return reconcileRecord, nil
	}
	return reconcileExpire, row.DispatchedAt
}

// markJobExpired records that job jid on sproutID expired: the expired
// flag (and so the "expired" status) in the index, and an expired.json
// marker in the job store, which job listings show as JobExpired. Both
// are idempotent, so replicas marking the same job concurrently agree.
func markJobExpired(tenantID, sproutID, jid string, dispatchedAt time.Time) {
	indexJobEvent(tenantID, sproutID, jid, jobEvent{expired: true})
	obj := objStore
	if obj == nil {
		log.Errorf("failed to mark job %s for sprout %s expired: %v", jid, sproutID, ErrJobStoreNotConfigured)
		return
	}
	data, err := json.Marshal(ExpiredMarker{
		JID:          jid,
		DispatchedAt: dispatchedAt.UTC(),
		ExpiredAt:    reconcileClock().UTC(),
		Window:       reconcileWindow,
	})
	if err != nil {
		log.Errorf("failed to encode expiry marker for job %s: %v", jid, err)
		return
	}
	ctx, cancel := opContext()
	defer cancel()
	if err := obj.Put(ctx, expiredKey(sproutID, jid), data); err != nil {
		log.Errorf("failed to mark job %s for sprout %s expired in the job store: %v", jid, sproutID, err)
	}
}
