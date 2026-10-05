package jobs

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/cook"
)

const (
	reconcileTenant = "t_a"
	reconcileSprout = "web-01"
)

// reconcileHarness wires recordJobCreation/logJobs to a test index and job
// store, with a fixed clock and the given reconcile window.
type reconcileHarness struct {
	t   *testing.T
	now time.Time
}

func newReconcileHarness(t *testing.T, window time.Duration) *reconcileHarness {
	t.Helper()
	newIndexTestDB(t)
	useTestObjStore(t)
	h := &reconcileHarness{t: t, now: time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)}
	oldWindow, oldClock := reconcileWindow, reconcileClock
	SetReconcileWindow(window)
	reconcileClock = func() time.Time { return h.now }
	t.Cleanup(func() { reconcileWindow, reconcileClock = oldWindow, oldClock })
	return h
}

// dispatch records jid's creation, dispatched at `at`.
func (h *reconcileHarness) dispatch(jid string, at time.Time) {
	recordJobCreation(reconcileTenant, reconcileSprout, cook.RecipeEnvelope{JobID: jid, Steps: []cook.Step{{ID: "s1"}}, DispatchedAt: at})
}

// event delivers one step event of jid at the harness's current time.
func (h *reconcileHarness) event(jid, stepID string) {
	b, _ := json.Marshal(cook.StepCompletion{ID: cook.StepID(stepID), CompletionStatus: cook.StepCompleted})
	logJobs(reconcileTenant, &nats.Msg{Subject: "imas.cook." + reconcileSprout + "." + jid, Data: b})
}

// runJob delivers a whole one-step job's events.
func (h *reconcileHarness) runJob(jid string) {
	h.event(jid, "start-"+jid)
	h.event(jid, "s1")
	h.event(jid, "completed-"+jid)
}

func (h *reconcileHarness) eventObjects(jid string) int {
	n := 0
	for _, k := range listKeys(h.t, objStore, tenantJobPrefix(reconcileTenant, reconcileSprout, jid)) {
		if strings.Contains(k, "/"+eventsDir) {
			n++
		}
	}
	return n
}

func TestReconcileWindow_DispatchedAtRecorded(t *testing.T) {
	h := newReconcileHarness(t, time.Hour)
	at := h.now.Add(-5 * time.Minute)
	h.dispatch("j1", at)
	row, ok := indexRow(t, db, reconcileTenant, reconcileSprout, "j1")
	if !ok || row.DispatchedAt == nil || !row.DispatchedAt.Equal(at) {
		t.Fatalf("dispatched_at = %v, want %v", row.DispatchedAt, at)
	}

	// An envelope without DispatchedAt is dated by its receipt.
	before := time.Now()
	h.dispatch("j2", time.Time{})
	row, _ = indexRow(t, db, reconcileTenant, reconcileSprout, "j2")
	if row.DispatchedAt == nil || row.DispatchedAt.Before(before.Add(-time.Second)) {
		t.Errorf("undated envelope's dispatched_at = %v, want about now", row.DispatchedAt)
	}
}

func TestReconcileWindow_OnTimeJobRecorded(t *testing.T) {
	h := newReconcileHarness(t, time.Hour)
	h.dispatch("j", h.now.Add(-10*time.Minute))
	h.event("j", "start-j")
	// Still recorded once it runs past the window: it started in time.
	h.now = h.now.Add(2 * time.Hour)
	h.event("j", "s1")
	h.event("j", "completed-j")

	if got := indexStatus(t, db, reconcileTenant, reconcileSprout, "j"); got != JobIndexStatusSucceeded {
		t.Errorf("status = %q, want %q", got, JobIndexStatusSucceeded)
	}
	if n := h.eventObjects("j"); n != 3 {
		t.Errorf("event objects = %d, want 3", n)
	}
}

// A job whose start arrives later than the window after dispatch is not
// reconciled: none of its events are recorded, and it is marked expired in
// the index and the job store.
func TestReconcileWindow_LateJobExpired(t *testing.T) {
	h := newReconcileHarness(t, time.Hour)
	dispatched := h.now.Add(-2 * time.Hour)
	h.dispatch("j", dispatched)
	h.runJob("j")

	row, _ := indexRow(t, db, reconcileTenant, reconcileSprout, "j")
	if !row.Expired || row.Status != JobIndexStatusExpired {
		t.Errorf("row expired = %v, status = %q; want true, %q", row.Expired, row.Status, JobIndexStatusExpired)
	}
	if row.Started || row.Finished || row.StepsReported != 0 {
		t.Errorf("late job's events were recorded: %+v", row)
	}
	if n := h.eventObjects("j"); n != 0 {
		t.Errorf("event objects = %d, want 0", n)
	}

	data, err := objStore.Get(t.Context(), mustKey(reconcileTenant, reconcileSprout, "j", expiredObject))
	if err != nil {
		t.Fatalf("expired marker: %v", err)
	}
	var marker ExpiredMarker
	if err := json.Unmarshal(data, &marker); err != nil {
		t.Fatal(err)
	}
	if marker.JID != "j" || !marker.DispatchedAt.Equal(dispatched) || marker.Window != time.Hour || !marker.ExpiredAt.Equal(h.now) {
		t.Errorf("marker = %+v", marker)
	}

	summary, err := NewStoreWithObjectStore(objStore).GetJob(reconcileTenant, reconcileSprout, "j")
	if err != nil {
		t.Fatal(err)
	}
	if summary.Status != JobExpired {
		t.Errorf("job listing status = %s, want expired", summary.Status)
	}
}

// Once expired, a job stays expired: raising the window later doesn't
// start recording its events.
func TestReconcileWindow_ExpiredIsFinal(t *testing.T) {
	h := newReconcileHarness(t, time.Hour)
	h.dispatch("j", h.now.Add(-2*time.Hour))
	h.event("j", "start-j")
	SetReconcileWindow(24 * time.Hour)
	h.event("j", "s1")
	h.event("j", "completed-j")
	if got := indexStatus(t, db, reconcileTenant, reconcileSprout, "j"); got != JobIndexStatusExpired {
		t.Errorf("status = %q, want expired", got)
	}
	if n := h.eventObjects("j"); n != 0 {
		t.Errorf("event objects = %d, want 0", n)
	}
}

// Deleting (or reaping) an expired job removes its marker too.
func TestReconcileWindow_DeleteRemovesMarker(t *testing.T) {
	h := newReconcileHarness(t, time.Hour)
	h.dispatch("j", h.now.Add(-2*time.Hour))
	h.runJob("j")
	if err := NewStoreWithObjectStore(objStore).DeleteJob(reconcileTenant, reconcileSprout, "j"); err != nil {
		t.Fatal(err)
	}
	if keys := listKeys(t, objStore, tenantJobPrefix(reconcileTenant, reconcileSprout, "j")); len(keys) != 0 {
		t.Errorf("objects left after delete: %v", keys)
	}
}

func TestJobStatus_ExpiredJSON(t *testing.T) {
	b, err := json.Marshal(JobExpired)
	if err != nil || string(b) != `"expired"` {
		t.Fatalf("Marshal(JobExpired) = %s, %v", b, err)
	}
	var s JobStatus
	if err := json.Unmarshal(b, &s); err != nil || s != JobExpired {
		t.Errorf("Unmarshal(%s) = %v, %v", b, s, err)
	}
}

func TestReconcileWindow_Boundary(t *testing.T) {
	h := newReconcileHarness(t, time.Hour)
	h.dispatch("exact", h.now.Add(-time.Hour))
	h.dispatch("over", h.now.Add(-time.Hour-time.Second))
	h.runJob("exact")
	h.runJob("over")
	if got := indexStatus(t, db, reconcileTenant, reconcileSprout, "exact"); got != JobIndexStatusSucceeded {
		t.Errorf("job starting exactly at the window: status %q, want succeeded", got)
	}
	if got := indexStatus(t, db, reconcileTenant, reconcileSprout, "over"); got != JobIndexStatusExpired {
		t.Errorf("job starting past the window: status %q, want expired", got)
	}
}

// With the window unset, or no creation row to date the job by, every
// event is recorded, as before.
func TestReconcileWindow_FailsOpen(t *testing.T) {
	t.Run("window disabled", func(t *testing.T) {
		h := newReconcileHarness(t, 0)
		h.dispatch("j", h.now.Add(-30*24*time.Hour))
		h.runJob("j")
		if got := indexStatus(t, db, reconcileTenant, reconcileSprout, "j"); got != JobIndexStatusSucceeded {
			t.Errorf("status = %q, want succeeded", got)
		}
	})
	t.Run("no creation row", func(t *testing.T) {
		h := newReconcileHarness(t, time.Hour)
		h.runJob("j")
		if n := h.eventObjects("j"); n != 3 {
			t.Errorf("event objects = %d, want 3", n)
		}
	})
	t.Run("no index", func(t *testing.T) {
		h := newReconcileHarness(t, time.Hour)
		SetDB(nil)
		h.runJob("j")
		if n := h.eventObjects("j"); n != 3 {
			t.Errorf("event objects = %d, want 3", n)
		}
	})
}

// Tenant safety: the window check keys on (tenant_id, sprout_id, jid), so
// a late job in one tenant doesn't hide the same IDs in another.
func TestReconcileWindow_PerTenant(t *testing.T) {
	h := newReconcileHarness(t, time.Hour)
	h.dispatch("j", h.now.Add(-2*time.Hour)) // t_a: late
	recordJobCreation("t_b", reconcileSprout, cook.RecipeEnvelope{JobID: "j", Steps: []cook.Step{{ID: "s1"}}, DispatchedAt: h.now})
	start, _ := json.Marshal(cook.StepCompletion{ID: "start-j"})
	logJobs("t_b", &nats.Msg{Subject: "imas.cook." + reconcileSprout + ".j", Data: start})
	h.event("j", "start-j") // t_a's late start

	if row, _ := indexRow(t, db, "t_b", reconcileSprout, "j"); !row.Started {
		t.Error("t_b's on-time job was not recorded")
	}
	if row, _ := indexRow(t, db, reconcileTenant, reconcileSprout, "j"); row.Started || !row.Expired {
		t.Errorf("t_a's late job: started %v, expired %v; want false, true", row.Started, row.Expired)
	}
	if row, _ := indexRow(t, db, "t_b", reconcileSprout, "j"); row.Expired {
		t.Error("t_b's job was marked expired by t_a's")
	}
}
