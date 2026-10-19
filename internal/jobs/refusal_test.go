package jobs

import (
	"errors"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/cook"
)

// P29: a cook farmer refused before any copy of it could reach the sprout
// (cook.DispatchRefusalRecorder) ends as refused in the job-status index,
// so the SaaS API sees it end instead of following it as running for ever.

var errTestRefusal = errors.New("cook exceeded its render budget")

// A refused job's row: refused, with no steps and no dispatch time, since
// nothing of it was sent.
func TestRecordJobRefusal(t *testing.T) {
	gdb := newIndexTestDB(t)
	const tenant, sprout, jid = "t_a", "web-01", "refused-job"
	recordJobRefusal(tenant, sprout, jid, errTestRefusal)

	row, ok := indexRow(t, gdb, tenant, sprout, jid)
	if !ok {
		t.Fatal("no index row for the refused job")
	}
	if row.Status != JobIndexStatusRefused || !row.DispatchRefused || row.StepsTotal != nil || row.DispatchedAt != nil {
		t.Fatalf("row = %+v, want refused, with no steps and no dispatch time", row)
	}
}

// Refused is terminal whatever else is recorded for the job, in any
// order: the flag only goes one way and decides the status first. No
// event of a refused job is expected, but nothing recorded can bring it
// back to running or make it a success.
func TestRecordJobRefusal_TerminalInAnyOrder(t *testing.T) {
	const tenant, sprout, jid = "t_a", "web-01", "refused-order"
	others := []func(){
		func() { indexJobCreation(tenant, sprout, jid, 1, time.Now()) },
		func() { indexStep(tenant, sprout, jid, stepEvent("start-"+jid, cook.StepCompleted)) },
		func() { indexStep(tenant, sprout, jid, stepEvent("s1", cook.StepCompleted)) },
		func() { indexStep(tenant, sprout, jid, stepEvent("completed-"+jid, cook.StepCompleted)) },
	}
	for at := 0; at <= len(others); at++ {
		gdb := newIndexTestDB(t)
		for i, apply := range others {
			if i == at {
				recordJobRefusal(tenant, sprout, jid, errTestRefusal)
			}
			apply()
		}
		if at == len(others) {
			recordJobRefusal(tenant, sprout, jid, errTestRefusal)
		}
		if got := indexStatus(t, gdb, tenant, sprout, jid); got != JobIndexStatusRefused {
			t.Errorf("refusal recorded at %d of %d: status %q, want refused", at, len(others), got)
		}
	}
}

// Keyed on (tenant_id, sprout_id, jid): another tenant's job with the same
// sprout ID and jid is untouched.
func TestRecordJobRefusal_TenantScoped(t *testing.T) {
	gdb := newIndexTestDB(t)
	const sprout, jid = "web-01", "shared-jid"
	indexJobCreation("t_b", sprout, jid, 1, time.Now())
	recordJobRefusal("t_a", sprout, jid, errTestRefusal)

	if got := indexStatus(t, gdb, "t_a", sprout, jid); got != JobIndexStatusRefused {
		t.Errorf("tenant a: %q, want refused", got)
	}
	if got := indexStatus(t, gdb, "t_b", sprout, jid); got != JobIndexStatusPending {
		t.Errorf("tenant b: %q, want pending", got)
	}
}

func TestRecordJobRefusal_NoJIDOrNoIndex(t *testing.T) {
	SetDB(nil)
	recordJobRefusal("t_a", "web-01", "j", errTestRefusal) // must not panic

	gdb := newIndexTestDB(t)
	recordJobRefusal("t_a", "web-01", "", errTestRefusal)
	var n int64
	gdb.Model(&jobStatusRow{}).Count(&n)
	if n != 0 {
		t.Fatalf("%d rows written for a refusal without a jid", n)
	}
}

// RegisterNatsConn installs recordJobRefusal as cook's refusal recorder,
// next to its dispatch recorder: a cook refused for a recipe that isn't
// there ends refused in the index.
func TestRegisterNatsConn_InstallsRefusalRecorder(t *testing.T) {
	gdb := newIndexTestDB(t)
	useTestObjStore(t)
	_, conn := startTestNATSServer(t)
	RegisterNatsConn("t_reg", conn)
	t.Cleanup(func() { cook.SetDispatchRefusalRecorder(nil); cook.SetDispatchRecorder(nil) })

	const jid = "refused-on-dispatch"
	if err := cook.SendCookEvent("t_reg", "web-01", "no-such-recipe", jid, false); err == nil {
		t.Fatal("SendCookEvent: got nil for a recipe that isn't there")
	}
	if got := indexStatus(t, gdb, "t_reg", "web-01", jid); got != JobIndexStatusRefused {
		t.Fatalf("status %q, want refused", got)
	}
}
