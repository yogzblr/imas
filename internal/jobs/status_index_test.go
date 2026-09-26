package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/nats-io/nats.go"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/cook"
)

// newIndexTestDB installs a fresh in-memory sqlite farmer schema holding
// job_status. One connection: sqlite serializes writers anyway, and the
// concurrency test below still interleaves its goroutines' statements.
func newIndexTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())), &gorm.Config{})
	if err != nil {
		t.Fatalf("opening test db: %v", err)
	}
	sqlDB, _ := gdb.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := gdb.AutoMigrate(Models()...); err != nil {
		t.Fatalf("migrating: %v", err)
	}
	SetDB(gdb)
	t.Cleanup(func() { SetDB(nil); sqlDB.Close() })
	return gdb
}

func indexRow(t *testing.T, gdb *gorm.DB, tenantID, sproutID, jid string) (jobStatusRow, bool) {
	t.Helper()
	var row jobStatusRow
	err := gdb.Where("tenant_id = ? AND sprout_id = ? AND jid = ?", tenantID, sproutID, jid).First(&row).Error
	if err == gorm.ErrRecordNotFound {
		return row, false
	}
	if err != nil {
		t.Fatalf("reading index row: %v", err)
	}
	return row, true
}

func indexStatus(t *testing.T, gdb *gorm.DB, tenantID, sproutID, jid string) string {
	t.Helper()
	row, ok := indexRow(t, gdb, tenantID, sproutID, jid)
	if !ok {
		return ""
	}
	return row.Status
}

func stepEvent(id string, status cook.CompletionStatus) cook.StepCompletion {
	return cook.StepCompletion{ID: cook.StepID(id), CompletionStatus: status}
}

// indexStep applies one imas.cook event, the way logJobs does.
func indexStep(tenantID, sproutID, jid string, step cook.StepCompletion) {
	indexJobEvent(tenantID, sproutID, jid, classifyJobEvent(jid, step))
}

func TestJobStatusIndex_InOrder(t *testing.T) {
	gdb := newIndexTestDB(t)
	const tenant, sprout, jid = "t_a", "web-01", "11111111-1111-1111-1111-111111111111"

	steps := []struct {
		apply func()
		want  string
	}{
		{func() { indexJobCreation(tenant, sprout, jid, 2, time.Now()) }, JobIndexStatusPending},
		{func() { indexStep(tenant, sprout, jid, stepEvent("start-"+jid, cook.StepCompleted)) }, JobIndexStatusRunning},
		{func() { indexStep(tenant, sprout, jid, stepEvent("s1", cook.StepCompleted)) }, JobIndexStatusRunning},
		{func() { indexStep(tenant, sprout, jid, stepEvent("s2", cook.StepSkipped)) }, JobIndexStatusRunning},
		{func() { indexStep(tenant, sprout, jid, stepEvent("completed-"+jid, cook.StepCompleted)) }, JobIndexStatusSucceeded},
	}
	for i, s := range steps {
		s.apply()
		if got := indexStatus(t, gdb, tenant, sprout, jid); got != s.want {
			t.Fatalf("after event %d: status %q, want %q", i, got, s.want)
		}
	}
	row, _ := indexRow(t, gdb, tenant, sprout, jid)
	if row.StepsTotal == nil || *row.StepsTotal != 2 || row.StepsReported != 2 || row.StepFailed || !row.Finished || row.UpdatedAt.IsZero() {
		t.Fatalf("row = %+v", row)
	}
}

// permutations returns every ordering of 0..n-1.
func permutations(n int) [][]int {
	if n == 0 {
		return [][]int{{}}
	}
	var out [][]int
	for _, p := range permutations(n - 1) {
		for i := 0; i <= len(p); i++ {
			q := append(append(append([]int{}, p[:i]...), n-1), p[i:]...)
			out = append(out, q)
		}
	}
	return out
}

// Farmer replicas apply one job's events in any order. Whatever the order,
// a job with a failed step must end failed, and must never read as
// succeeded along the way (a reader like the SaaS API records the first
// terminal status it sees) — the completed-<jid> event says StepCompleted
// even when a step failed, so it alone can't settle the outcome.
func TestJobStatusIndex_AnyEventOrder(t *testing.T) {
	gdb := newIndexTestDB(t)
	const tenant, sprout = "t_a", "web-01"

	for _, withFailure := range []bool{false, true} {
		for n, order := range permutations(5) {
			jid := fmt.Sprintf("job-%t-%d", withFailure, n)
			s2 := cook.StepCompleted
			if withFailure {
				s2 = cook.StepFailed
			}
			events := []func(){
				func() { indexJobCreation(tenant, sprout, jid, 2, time.Now()) },
				func() { indexStep(tenant, sprout, jid, stepEvent("start-"+jid, cook.StepCompleted)) },
				func() { indexStep(tenant, sprout, jid, stepEvent("s1", cook.StepCompleted)) },
				func() { indexStep(tenant, sprout, jid, stepEvent("s2", s2)) },
				func() { indexStep(tenant, sprout, jid, stepEvent("completed-"+jid, cook.StepCompleted)) },
			}
			want := JobIndexStatusSucceeded
			if withFailure {
				want = JobIndexStatusFailed
			}
			for _, e := range order {
				events[e]()
				// Terminal may come before the last event (start-<jid>
				// adds nothing once every step and completed-<jid> are
				// in), but only ever as the right outcome, never to
				// change again.
				got := indexStatus(t, gdb, tenant, sprout, jid)
				if (got == JobIndexStatusSucceeded || got == JobIndexStatusFailed) && got != want {
					t.Fatalf("order %v: read %q, want only %q once terminal", order, got, want)
				}
			}
			if got := indexStatus(t, gdb, tenant, sprout, jid); got != want {
				t.Fatalf("order %v: final status %q, want %q", order, got, want)
			}
		}
	}
}

func TestJobStatusIndex_ConcurrentWriters(t *testing.T) {
	gdb := newIndexTestDB(t)
	const tenant, sprout, jid = "t_a", "web-01", "concurrent-job"
	const nSteps = 20

	var wg sync.WaitGroup
	run := func(f func()) { wg.Add(1); go func() { defer wg.Done(); f() }() }
	run(func() { indexJobCreation(tenant, sprout, jid, nSteps, time.Now()) })
	run(func() { indexStep(tenant, sprout, jid, stepEvent("start-"+jid, cook.StepCompleted)) })
	run(func() { indexStep(tenant, sprout, jid, stepEvent("completed-"+jid, cook.StepCompleted)) })
	for i := range nSteps {
		status := cook.StepCompleted
		if i == 7 {
			status = cook.StepFailed
		}
		run(func() { indexStep(tenant, sprout, jid, stepEvent(fmt.Sprintf("s%d", i), status)) })
	}
	wg.Wait()

	row, _ := indexRow(t, gdb, tenant, sprout, jid)
	if row.Status != JobIndexStatusFailed || row.StepsReported != nSteps || !row.StepFailed {
		t.Fatalf("row = %+v, want failed with %d steps reported", row, nSteps)
	}
}

func TestJobStatusIndex_TimeoutFailsImmediately(t *testing.T) {
	gdb := newIndexTestDB(t)
	const tenant, sprout, jid = "t_a", "web-01", "timeout-job"
	indexJobCreation(tenant, sprout, jid, 3, time.Now())
	indexStep(tenant, sprout, jid, stepEvent("s1", cook.StepCompleted))
	indexStep(tenant, sprout, jid, stepEvent("timeout-"+jid, cook.StepFailed))
	if got := indexStatus(t, gdb, tenant, sprout, jid); got != JobIndexStatusFailed {
		t.Fatalf("status %q, want failed", got)
	}
}

// sprout_id is unique per tenant only: the same sprout and jid in two
// tenants are two independent rows.
func TestJobStatusIndex_TenantScoped(t *testing.T) {
	gdb := newIndexTestDB(t)
	const sprout, jid = "web-01", "shared-jid"
	indexJobCreation("t_a", sprout, jid, 1, time.Now())
	indexStep("t_a", sprout, jid, stepEvent("s1", cook.StepCompleted))
	indexStep("t_a", sprout, jid, stepEvent("completed-"+jid, cook.StepCompleted))
	indexJobCreation("t_b", sprout, jid, 1, time.Now())
	indexStep("t_b", sprout, jid, stepEvent("s1", cook.StepFailed))

	if got := indexStatus(t, gdb, "t_a", sprout, jid); got != JobIndexStatusSucceeded {
		t.Fatalf("tenant a: %q, want succeeded", got)
	}
	if got := indexStatus(t, gdb, "t_b", sprout, jid); got != JobIndexStatusRunning {
		t.Fatalf("tenant b: %q, want running", got)
	}
}

func TestJobStatusIndex_DisabledOrInvalidIsANoOp(t *testing.T) {
	SetDB(nil)
	indexJobCreation("t_a", "web-01", "j", 1, time.Now()) // must not panic

	gdb := newIndexTestDB(t)
	for _, c := range []struct{ tenant, sprout, jid string }{
		{"", "web-01", "j"},
		{"t_a", "", "j"},
		{"t_a", "web-01", ""},
		{"t_a", "web-01", string(make([]byte, maxIndexJIDLen+1))},
	} {
		indexJobCreation(c.tenant, c.sprout, c.jid, 1, time.Now())
	}
	var n int64
	gdb.Model(&jobStatusRow{}).Count(&n)
	if n != 0 {
		t.Fatalf("%d rows written for invalid identifiers", n)
	}
}

// The listener indexes under the tenant it was registered for, and does
// so even when the object store isn't configured: the two writes are
// independent.
func TestListenerIndexesUnderRegisteredTenant(t *testing.T) {
	gdb := newIndexTestDB(t)
	prev := objStore
	objStore = nil
	t.Cleanup(func() { objStore = prev })

	const jid = "listener-job"
	env, _ := json.Marshal(cook.RecipeEnvelope{JobID: jid, Steps: []cook.Step{{ID: "s1"}}})
	logJobCreation("t_list", &nats.Msg{Subject: "imas.sprouts.web-01.cook", Data: env})
	for _, step := range []cook.StepCompletion{stepEvent("s1", cook.StepCompleted), stepEvent("completed-"+jid, cook.StepCompleted)} {
		b, _ := json.Marshal(step)
		logJobs("t_list", &nats.Msg{Subject: "imas.cook.web-01." + jid, Data: b})
	}
	if got := indexStatus(t, gdb, "t_list", "web-01", jid); got != JobIndexStatusSucceeded {
		t.Fatalf("status %q, want succeeded", got)
	}
}

func TestReapJobStatusIndex(t *testing.T) {
	gdb := newIndexTestDB(t)
	indexJobCreation("t_a", "web-01", "old", 1, time.Now())
	indexJobCreation("t_a", "web-01", "new", 1, time.Now())
	gdb.Model(&jobStatusRow{}).Where("jid = ?", "old").Update("updated_at", time.Now().Add(-48*time.Hour))

	reapJobStatusIndex(time.Now().Add(-24 * time.Hour))
	if _, ok := indexRow(t, gdb, "t_a", "web-01", "old"); ok {
		t.Fatal("expired row survived")
	}
	if _, ok := indexRow(t, gdb, "t_a", "web-01", "new"); !ok {
		t.Fatal("fresh row was reaped")
	}
}

func TestRetryOnConflict(t *testing.T) {
	conflict := errors.New("Error 1213 (40001): Deadlock found when trying to get lock; try restarting transaction")
	calls := 0
	err := retryOnConflict(context.Background(), func() error {
		calls++
		if calls < 3 {
			return conflict
		}
		return nil
	})
	if err != nil || calls != 3 {
		t.Fatalf("conflicts then success: err %v after %d calls, want nil after 3", err, calls)
	}

	// Anything else may have committed: never repeated.
	calls = 0
	other := errors.New("invalid connection")
	if err := retryOnConflict(context.Background(), func() error { calls++; return other }); err != other || calls != 1 {
		t.Fatalf("other error: %v after %d calls, want it after 1", err, calls)
	}

	calls = 0
	if err := retryOnConflict(context.Background(), func() error { calls++; return conflict }); err != conflict || calls != conflictRetries {
		t.Fatalf("persistent conflict: %v after %d calls, want it after %d", err, calls, conflictRetries)
	}
}
