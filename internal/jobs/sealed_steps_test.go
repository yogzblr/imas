package jobs

// Security review P6 (U3): step events are sealed by the sprout, and
// nothing else changes a job record. FLAG FOR SECURITY REVIEW.

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	mrand "math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/nats-io/nats.go"
	"github.com/valkey-io/valkey-go"
	"golang.org/x/crypto/nacl/box"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/heartbeat"
	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/payloadbox"
)

const p6Sprout = "p6-web"

// p6Job is a dispatched two-step job whose first step succeeds and second
// fails, and its honest, sealed events in the order the sprout sends them.
type p6Job struct {
	t      *testing.T
	s      *stepSealer
	gdb    *gorm.DB
	obj    *objectstore.Store
	jid    string
	events map[string]*nats.Msg
}

func newP6Job(t *testing.T, jid string) *p6Job {
	t.Helper()
	j := &p6Job{t: t, s: sealerFor(t), gdb: newIndexTestDB(t), obj: useTestObjStore(t), jid: jid, events: map[string]*nats.Msg{}}
	recordJobCreation(testTenant, p6Sprout, cook.RecipeEnvelope{JobID: jid, Steps: []cook.Step{{ID: "s1"}, {ID: "s2"}}, DispatchedAt: time.Now()})
	for _, st := range []cook.StepCompletion{
		{ID: cook.StepID("start-" + jid), CompletionStatus: cook.StepCompleted},
		{ID: "s1", CompletionStatus: cook.StepCompleted, Started: time.Now()},
		{ID: "s2", CompletionStatus: cook.StepFailed, Started: time.Now(), Error: errors.New("exit 1")},
		{ID: cook.StepID("completed-" + jid), CompletionStatus: cook.StepCompleted},
	} {
		j.events[string(st.ID)] = j.s.sealedStep(testTenant, p6Sprout, jid, st)
	}
	return j
}

// record is the job's record: its index row and its log as the job store
// reads it.
type p6Record struct {
	status   string
	reported int
	failed   bool
	finished bool
	steps    []string
}

func (j *p6Job) record() p6Record {
	j.t.Helper()
	row, _ := indexRow(j.t, j.gdb, testTenant, p6Sprout, j.jid)
	r := p6Record{status: row.Status, reported: row.StepsReported, failed: row.StepFailed, finished: row.Finished}
	summary, err := NewStoreWithObjectStore(j.obj).GetJob(testTenant, p6Sprout, j.jid)
	if err != nil {
		j.t.Fatal(err)
	}
	for _, st := range summary.Steps {
		b, _ := json.Marshal(st)
		r.steps = append(r.steps, string(b))
	}
	slices.Sort(r.steps)
	return r
}

func (r p6Record) equal(o p6Record) bool {
	return r.status == o.status && r.reported == o.reported && r.failed == o.failed && r.finished == o.finished && slices.Equal(r.steps, o.steps)
}

// A forged "step succeeded" for the failed step changes nothing, however
// it is forged: in plaintext, sealed under a key farmer has no record of,
// sealed by another sprout, for another tenant or job, stale, or a replay
// of a real event, to this replica or another.
func TestStepEvents_ForgedSuccessRefused(t *testing.T) {
	j := newP6Job(t, "p6-forged")
	for _, id := range []string{"start-p6-forged", "s1", "s2", "completed-p6-forged"} {
		logJobs(testTenant, j.events[id])
	}
	want := j.record()
	if want.status != JobIndexStatusFailed {
		t.Fatalf("honest job status %q, want failed", want.status)
	}

	success := cook.StepEvent{JobID: j.jid, Step: cook.StepCompletion{ID: "s2", CompletionStatus: cook.StepCompleted, Started: time.Now()}}
	subject := cook.StepEventSubject(p6Sprout, j.jid)
	plain, _ := json.Marshal(success.Step)
	_, strangerPriv, _ := box.GenerateKey(rand.Reader)
	_, tenantPub := j.s.keys(testTenant, p6Sprout)
	m, _ := payloadbox.NewMessage(payloadbox.PurposeCookStep, testTenant, p6Sprout, "", success)
	stranger, _ := payloadbox.Seal(m, []payloadbox.KeyPair{{PeerPub: tenantPub, Priv: strangerPriv}})
	stale := func(m *payloadbox.Message) {
		m.IssuedAt = time.Now().Add(-payloadbox.DefaultMaxSkew - time.Minute).Unix()
	}
	otherJob := cook.StepEvent{JobID: "another-job", Step: success.Step}

	cases := map[string]*nats.Msg{
		"plaintext":               {Subject: subject, Data: plain},
		"plaintext marked sealed": sealedNATSMsg(subject, plain),
		"sealed by a stranger":    sealedNATSMsg(subject, stranger),
		"sealed by a neighbour":   sealedNATSMsg(subject, j.s.sealBody(testTenant, "p6-neighbour", testTenant, p6Sprout, success, nil)),
		"other tenant's sprout":   sealedNATSMsg(subject, j.s.sealBody("t_other", p6Sprout, "t_other", p6Sprout, success, nil)),
		"names another tenant":    sealedNATSMsg(subject, j.s.sealBody(testTenant, p6Sprout, "t_other", p6Sprout, success, nil)),
		"for another job":         sealedNATSMsg(subject, j.s.sealBody(testTenant, p6Sprout, testTenant, p6Sprout, otherJob, nil)),
		"stale":                   sealedNATSMsg(subject, j.s.sealBody(testTenant, p6Sprout, testTenant, p6Sprout, success, stale)),
		"another purpose": sealedNATSMsg(subject, j.s.sealBody(testTenant, p6Sprout, testTenant, p6Sprout, success,
			func(m *payloadbox.Message) { m.Purpose = payloadbox.PurposeFacts })),
		"replayed s1":             j.events["s1"],
		"moved to another sprout": sealedNATSMsg(cook.StepEventSubject("p6-neighbour", j.jid), j.events["s1"].Data),
	}
	for name, msg := range cases {
		logJobs(testTenant, msg)
		if got := j.record(); !got.equal(want) {
			t.Errorf("%s: job record changed: %+v, want %+v", name, got, want)
		}
	}
	// Replayed to another replica: its own guard hasn't seen the event,
	// but the cluster-wide claim has.
	stepGuard = payloadbox.NewKeyedReplayGuard()
	logJobs(testTenant, j.events["s1"])
	if got := j.record(); !got.equal(want) {
		t.Errorf("replay on another replica changed the job record: %+v", got)
	}
}

// A skipped step: the bus drops the failed step's event and replays the
// successful one to make up the count. The job never reads as succeeded.
func TestStepEvents_SkippedStepNeverSucceeds(t *testing.T) {
	j := newP6Job(t, "p6-skipped")
	for _, id := range []string{"start-p6-skipped", "s1", "completed-p6-skipped"} {
		logJobs(testTenant, j.events[id])
	}
	logJobs(testTenant, j.events["s1"]) // replayed in place of s2
	stepGuard = payloadbox.NewKeyedReplayGuard()
	logJobs(testTenant, j.events["s1"]) // and to another replica
	got := j.record()
	if got.status == JobIndexStatusSucceeded || got.reported != 1 {
		t.Fatalf("job with a skipped step reads %+v", got)
	}
	summary, err := NewStoreWithObjectStore(j.obj).GetJob(testTenant, p6Sprout, j.jid)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Status == JobSucceeded {
		t.Fatalf("job store summary of a job with a skipped step: %s", summary.Status)
	}
	// The real event, when it does arrive, still counts.
	logJobs(testTenant, j.events["s2"])
	if got := j.record(); got.status != JobIndexStatusFailed {
		t.Fatalf("after the failed step's event the job reads %q", got.status)
	}
}

// Reordered events give the same record as in-order ones, and a job whose
// completion arrives before a failed step never reads as succeeded.
func TestStepEvents_ReorderedSameRecord(t *testing.T) {
	inOrder := newP6Job(t, "p6-order")
	ids := []string{"start-p6-order", "s1", "s2", "completed-p6-order"}
	for _, id := range ids {
		logJobs(testTenant, inOrder.events[id])
	}
	want := inOrder.record()

	for round := range 5 {
		jid := "p6-shuffle-" + string(rune('a'+round))
		j := newP6Job(t, jid)
		order := []string{"start-" + jid, "s1", "s2", "completed-" + jid}
		mrand.Shuffle(len(order), func(a, b int) { order[a], order[b] = order[b], order[a] })
		for _, id := range order {
			logJobs(testTenant, j.events[id])
			if r := j.record(); r.status == JobIndexStatusSucceeded {
				t.Fatalf("order %v: job read succeeded after %s", order, id)
			}
		}
		got := j.record()
		if got.status != want.status || got.reported != want.reported || got.failed != want.failed || got.finished != want.finished || len(got.steps) != len(want.steps) {
			t.Fatalf("order %v: record %+v, want %+v", order, got, want)
		}
	}
}

// Valkey unreachable: the claim can't be recorded, so the event is
// refused (fail closed) and the job record is unchanged.
func TestStepEvents_ClaimUnavailableFailsClosed(t *testing.T) {
	j := newP6Job(t, "p6-valkey")
	before := j.record()
	j.s.claimErr = errors.New("valkey: connection refused")
	logJobs(testTenant, j.events["start-p6-valkey"])
	if got := j.record(); !got.equal(before) {
		t.Fatalf("event recorded without a claim: %+v", got)
	}
	j.s.claimErr = nil
	stepGuard = payloadbox.NewKeyedReplayGuard() // as if another replica
	logJobs(testTenant, j.events["start-p6-valkey"])
	if got := j.record(); got.status != JobIndexStatusRunning {
		t.Fatalf("event refused once Valkey is back: %+v", got)
	}
}

// A plaintext step event marks its sprout as needing an upgrade.
func TestStepEvents_PlaintextMarksUpgradeRequired(t *testing.T) {
	j := newP6Job(t, "p6-old")
	mr := miniredis.RunT(t)
	c, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{mr.Addr()}, DisableCache: true})
	if err != nil {
		t.Fatal(err)
	}
	heartbeat.SetClient(c)
	t.Cleanup(func() { heartbeat.SetClient(nil); c.Close() })
	b, _ := json.Marshal(cook.StepCompletion{ID: "start-p6-old", CompletionStatus: cook.StepCompleted})
	before := j.record()
	logJobs(testTenant, &nats.Msg{Subject: cook.StepEventSubject(p6Sprout, j.jid), Data: b})
	if got := heartbeat.UpgradeRequired(context.Background(), testTenant, p6Sprout); got != heartbeat.UpgradeKindCookStep {
		t.Fatalf("UpgradeRequired = %q", got)
	}
	if got := j.record(); !got.equal(before) {
		t.Fatalf("plaintext event recorded: %+v", got)
	}
}
