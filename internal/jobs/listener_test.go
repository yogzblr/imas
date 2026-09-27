package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/nats-io/nats.go"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
	"github.com/yogzblr/imas/internal/pki"
)

// eventually polls cond until it returns true or timeout passes, and
// reports whether it did.
func eventually(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// waitForSteps waits until the job has want steps and returns it.
func waitForSteps(t *testing.T, obj *objectstore.Store, sproutID, jid string, want int) *JobSummary {
	t.Helper()
	store := NewStoreWithObjectStore(obj)
	var summary *JobSummary
	ok := eventually(5*time.Second, func() bool {
		s, err := store.GetJob(sproutID, jid)
		if err != nil {
			return false
		}
		summary = s
		return len(s.Steps) >= want
	})
	if !ok {
		got := -1
		if summary != nil {
			got = len(summary.Steps)
		}
		t.Fatalf("job %s/%s: waited for %d steps, have %d", sproutID, jid, want, got)
	}
	return summary
}

// listKeys lists every key under prefix, failing the test on error.
func listKeys(t *testing.T, obj *objectstore.Store, prefix string) []string {
	t.Helper()
	keys, err := obj.List(context.Background(), prefix)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// useTestObjServer is useTestObjStore for tests that also need the fake
// server's handle, e.g. to inject failures.
func useTestObjServer(t *testing.T) (*objectstoretest.Server, *objectstore.Store) {
	t.Helper()
	srv := objectstoretest.NewServer(t)
	obj, err := objectstore.Open(srv.Config())
	if err != nil {
		t.Fatal(err)
	}
	orig := objStore
	SetStore(obj)
	t.Cleanup(func() { SetStore(orig) })
	return srv, obj
}

func stepMsg(t *testing.T, subject string, step cook.StepCompletion) *nats.Msg {
	t.Helper()
	data, err := json.Marshal(step)
	if err != nil {
		t.Fatal(err)
	}
	return &nats.Msg{Subject: subject, Data: data}
}

func envelopeMsg(t *testing.T, subject string, envelope cook.RecipeEnvelope) *nats.Msg {
	t.Helper()
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return &nats.Msg{Subject: subject, Data: data}
}

// TestRegisterNatsConn_NoLocalDir verifies farmer no longer creates
// config.JobLogDir: job logs live in the object store.
func TestRegisterNatsConn_NoLocalDir(t *testing.T) {
	dir := t.TempDir()
	origJobLogDir := config.JobLogDir
	config.JobLogDir = filepath.Join(dir, "joblogs")
	t.Cleanup(func() { config.JobLogDir = origJobLogDir })
	useTestObjStore(t)

	_, conn := startTestNATSServer(t)
	RegisterNatsConn("t_test", conn)

	if _, err := os.Stat(config.JobLogDir); !os.IsNotExist(err) {
		t.Errorf("expected no local job log dir to be created, got %v", err)
	}
}

func TestLogJobs_StepCompletion(t *testing.T) {
	obj := useTestObjStore(t)

	_, conn := startTestNATSServer(t)
	RegisterNatsConn("t_test", conn)

	step := cook.StepCompletion{
		ID:               "step-1",
		CompletionStatus: cook.StepCompleted,
		Started:          time.Now(),
		Duration:         3 * time.Second,
	}
	data, _ := json.Marshal(step)

	if err := conn.Publish("imas.cook.sprout-log-test.job-log-1", data); err != nil {
		t.Fatal(err)
	}
	conn.Flush()

	summary := waitForSteps(t, obj, "sprout-log-test", "job-log-1", 1)
	if summary.Steps[0].ID != "step-1" || summary.Steps[0].CompletionStatus != cook.StepCompleted {
		t.Errorf("unexpected step: %+v", summary.Steps[0])
	}

	// Stored as one event object.
	keys := listKeys(t, obj, jobPrefix("sprout-log-test", "job-log-1"))
	if len(keys) != 1 || !strings.Contains(keys[0], "/"+eventsDir) {
		t.Errorf("expected one event object, got %v", keys)
	}
}

func TestLogJobs_AppendToExisting(t *testing.T) {
	obj := useTestObjStore(t)

	_, conn := startTestNATSServer(t)
	RegisterNatsConn("t_test", conn)

	// Publish two steps.
	for i := range 2 {
		step := cook.StepCompletion{
			ID:               cook.StepID(fmt.Sprintf("step-%d", i)),
			CompletionStatus: cook.StepCompleted,
			Started:          time.Now(),
			Duration:         time.Second,
		}
		data, _ := json.Marshal(step)
		if err := conn.Publish("imas.cook.sprout-append.job-append-1", data); err != nil {
			t.Fatal(err)
		}
	}
	conn.Flush()

	// Both steps are in the job, in order.
	summary := waitForSteps(t, obj, "sprout-append", "job-append-1", 2)
	if len(summary.Steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(summary.Steps))
	}
	if summary.Steps[0].ID != "step-0" || summary.Steps[1].ID != "step-1" {
		t.Errorf("steps out of order: %s, %s", summary.Steps[0].ID, summary.Steps[1].ID)
	}
}

func TestLogJobs_ExistingJobAppend(t *testing.T) {
	obj := useTestObjStore(t)

	// A job already created with a placeholder.
	placeholder := cook.StepCompletion{ID: "existing-step", CompletionStatus: cook.StepNotStarted, Started: time.Now()}
	b, _ := json.Marshal(placeholder)
	putObject(t, obj, createdKey("sprout-existing", "existing-job"), append(b, '\n'))

	newStep := cook.StepCompletion{
		ID:               "new-step",
		CompletionStatus: cook.StepFailed,
		Started:          time.Now(),
		Duration:         2 * time.Second,
	}
	logJobs("", stepMsg(t, "imas.cook.sprout-existing.existing-job", newStep))

	summary := waitForSteps(t, obj, "sprout-existing", "existing-job", 2)
	if summary.Steps[0].ID != "existing-step" || summary.Steps[1].ID != "new-step" {
		t.Errorf("expected created.jsonl before events, got %s, %s", summary.Steps[0].ID, summary.Steps[1].ID)
	}
	// The created object itself is untouched: events never rewrite it.
	data, err := obj.Get(context.Background(), createdKey("sprout-existing", "existing-job"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(append(b, '\n')) {
		t.Errorf("created.jsonl was modified: %q", data)
	}
}

func TestLogJobs_InvalidJSON(t *testing.T) {
	obj := useTestObjStore(t)

	// Invalid JSON — should not panic, and nothing is written.
	logJobs("", &nats.Msg{Subject: "imas.cook.sprout-bad.job-bad", Data: []byte("invalid json")})

	if keys := listKeys(t, obj, jobKeyPrefix); len(keys) != 0 {
		t.Errorf("expected nothing written for invalid JSON, got %v", keys)
	}
}

func TestLogJobs_ShortSubject(t *testing.T) {
	obj := useTestObjStore(t)
	step := makeStep("s1", cook.StepCompleted, time.Now(), time.Second)

	// The wildcard subscription guarantees 4 tokens, but logJobs guards
	// anyway.
	logJobs("", stepMsg(t, "imas.cook.only-three", step))

	if keys := listKeys(t, obj, jobKeyPrefix); len(keys) != 0 {
		t.Errorf("expected nothing written for a short subject, got %v", keys)
	}
}

// TestLogJobs_UnsafeKeySegment verifies a subject token that would break
// out of its own job's key prefix is refused.
func TestLogJobs_UnsafeKeySegment(t *testing.T) {
	obj := useTestObjStore(t)
	step := makeStep("s1", cook.StepCompleted, time.Now(), time.Second)

	logJobs("", stepMsg(t, "imas.cook.sprout/other.job", step))
	logJobs("", stepMsg(t, "imas.cook.sprout.job/events", step))
	logJobs("", stepMsg(t, "imas.cook.sprout...", step))

	if keys := listKeys(t, obj, ""); len(keys) != 0 {
		t.Errorf("expected nothing written for unsafe key segments, got %v", keys)
	}
}

func TestLogJobs_NotConfigured(t *testing.T) {
	orig := objStore
	SetStore(nil)
	t.Cleanup(func() { SetStore(orig) })

	// Should log and drop the event, not panic.
	logJobs("", stepMsg(t, "imas.cook.sprout.job", makeStep("s1", cook.StepCompleted, time.Now(), time.Second)))
}

func TestLogJobs_PutError(t *testing.T) {
	srv, obj := useTestObjServer(t)

	srv.FailNext(1, 403, "AccessDenied")
	// Should log the failed Put, not panic.
	logJobs("", stepMsg(t, "imas.cook.sprout-err.job-err", makeStep("s1", cook.StepCompleted, time.Now(), time.Second)))

	if keys := listKeys(t, obj, jobKeyPrefix); len(keys) != 0 {
		t.Errorf("expected nothing written after a failed Put, got %v", keys)
	}
}

func TestLogJobs_ConcurrentSteps(t *testing.T) {
	obj := useTestObjStore(t)

	_, conn := startTestNATSServer(t)
	RegisterNatsConn("t_test", conn)

	// Publish many steps in a burst.
	const stepCount = 20
	for i := range stepCount {
		step := cook.StepCompletion{
			ID:               cook.StepID(fmt.Sprintf("step-%d", i)),
			CompletionStatus: cook.StepCompleted,
			Started:          time.Now(),
			Duration:         time.Millisecond,
		}
		data, _ := json.Marshal(step)
		if err := conn.Publish("imas.cook.sprout-concurrent.job-concurrent", data); err != nil {
			t.Fatal(err)
		}
	}
	conn.Flush()

	summary := waitForSteps(t, obj, "sprout-concurrent", "job-concurrent", stepCount)
	if len(summary.Steps) != stepCount {
		t.Errorf("expected %d steps, got %d", stepCount, len(summary.Steps))
	}
}

func TestRecordJobCreation(t *testing.T) {
	obj := useTestObjStore(t)

	envelope := cook.RecipeEnvelope{
		JobID:     "creation-job-1",
		InvokedBy: "UPUBKEY_CREATOR",
		Steps: []cook.Step{
			{ID: "step-a"},
			{ID: "step-b"},
		},
	}
	recordJobCreation("t_test", "sprout-create", envelope)

	// Verify the job was created with placeholder steps.
	summary := waitForSteps(t, obj, "sprout-create", "creation-job-1", 2)
	if len(summary.Steps) != 2 {
		t.Errorf("expected 2 placeholder steps, got %d", len(summary.Steps))
	}
	for _, step := range summary.Steps {
		if step.CompletionStatus != cook.StepNotStarted {
			t.Errorf("expected StepNotStarted, got %d", step.CompletionStatus)
		}
	}

	// Verify the meta object was written.
	if !objectExists(t, obj, metaKey("sprout-create", "creation-job-1")) {
		t.Fatal("expected meta object to exist")
	}
	if summary.InvokedBy != "UPUBKEY_CREATOR" {
		t.Errorf("expected UPUBKEY_CREATOR, got %s", summary.InvokedBy)
	}
}

func TestRecordJobCreation_ThenSteps(t *testing.T) {
	obj := useTestObjStore(t)

	recordJobCreation("", "sprout-flow", cook.RecipeEnvelope{
		JobID: "flow-job",
		Steps: []cook.Step{{ID: "a"}, {ID: "b"}},
	})
	logJobs("", stepMsg(t, "imas.cook.sprout-flow.flow-job", makeStep("a", cook.StepCompleted, time.Now(), time.Second)))
	logJobs("", stepMsg(t, "imas.cook.sprout-flow.flow-job", makeStep("b", cook.StepCompleted, time.Now(), time.Second)))

	// Same lines, in the same order, the old local .jsonl file held:
	// placeholders first, then events as they arrived.
	summary := waitForSteps(t, obj, "sprout-flow", "flow-job", 4)
	var got []string
	for _, s := range summary.Steps {
		got = append(got, fmt.Sprintf("%s:%d", s.ID, s.CompletionStatus))
	}
	want := []string{
		fmt.Sprintf("a:%d", cook.StepNotStarted), fmt.Sprintf("b:%d", cook.StepNotStarted),
		fmt.Sprintf("a:%d", cook.StepCompleted), fmt.Sprintf("b:%d", cook.StepCompleted),
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("steps = %v, want %v", got, want)
	}
}

func TestRecordJobCreation_EmptyJobID(t *testing.T) {
	obj := useTestObjStore(t)

	// Envelope with empty JobID should be ignored.
	recordJobCreation("", "sprout-empty", cook.RecipeEnvelope{
		JobID: "",
		Steps: []cook.Step{{ID: "step-a"}},
	})

	if keys := listKeys(t, obj, jobKeyPrefix); len(keys) != 0 {
		t.Errorf("expected no objects for empty job ID envelope, got %v", keys)
	}
}

func TestRecordJobCreation_NoInvokedBy(t *testing.T) {
	obj := useTestObjStore(t)

	before := time.Now().UTC().Add(-time.Second)
	recordJobCreation("", "sprout-noinv", cook.RecipeEnvelope{
		JobID: "no-invoker-job",
		Steps: []cook.Step{{ID: "step-a"}},
	})

	summary := waitForSteps(t, obj, "sprout-noinv", "no-invoker-job", 1)
	if summary.InvokedBy != "" {
		t.Errorf("expected empty InvokedBy, got %q", summary.InvokedBy)
	}

	// meta.json is still written, since the reaper dates a job by its
	// CreatedAt until the first event arrives.
	meta, err := readJobMeta(context.Background(), obj, jobRef{sproutID: "sprout-noinv", jid: "no-invoker-job"})
	if err != nil {
		t.Fatalf("expected meta object: %v", err)
	}
	if meta.CreatedAt.Before(before) {
		t.Errorf("expected CreatedAt to be set, got %v", meta.CreatedAt)
	}
}

func TestRecordJobCreation_DuplicateJobID(t *testing.T) {
	obj := useTestObjStore(t)
	env := cook.RecipeEnvelope{
		JobID: "dup-job",
		Steps: []cook.Step{{ID: "step-a"}},
	}

	// First creation.
	recordJobCreation("", "sprout-dup", env)
	key := createdKey("sprout-dup", "dup-job")
	originalContent, err := obj.Get(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}

	// Second creation with same JID — should be a no-op since the job
	// already exists (the placeholders carry a fresh Started time, so a
	// rewrite would change the content).
	time.Sleep(time.Millisecond)
	recordJobCreation("", "sprout-dup", env)

	afterContent, err := obj.Get(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if string(originalContent) != string(afterContent) {
		t.Error("expected duplicate job creation to be a no-op")
	}
}

func TestRecordJobCreation_EmptySproutID(t *testing.T) {
	obj := useTestObjStore(t)

	recordJobCreation("", "", cook.RecipeEnvelope{JobID: "j", Steps: []cook.Step{{ID: "s"}}})

	if keys := listKeys(t, obj, jobKeyPrefix); len(keys) != 0 {
		t.Errorf("expected nothing written for an empty sprout ID, got %v", keys)
	}
}

func TestRecordJobCreation_UnsafeKeySegment(t *testing.T) {
	obj := useTestObjStore(t)

	recordJobCreation("", "sprout", cook.RecipeEnvelope{JobID: "../other", Steps: []cook.Step{{ID: "s"}}})
	recordJobCreation("", "a/b", cook.RecipeEnvelope{JobID: "j", Steps: []cook.Step{{ID: "s"}}})

	if keys := listKeys(t, obj, ""); len(keys) != 0 {
		t.Errorf("expected nothing written for unsafe key segments, got %v", keys)
	}
}

func TestRecordJobCreation_NotConfigured(t *testing.T) {
	orig := objStore
	SetStore(nil)
	t.Cleanup(func() { SetStore(orig) })

	// Should log and drop the event, not panic.
	recordJobCreation("", "sprout", cook.RecipeEnvelope{JobID: "j", Steps: []cook.Step{{ID: "s"}}})
}

func TestRecordJobCreation_ExistsError(t *testing.T) {
	srv, obj := useTestObjServer(t)

	srv.FailNext(1, 403, "AccessDenied")
	recordJobCreation("", "sprout-err", cook.RecipeEnvelope{JobID: "j", Steps: []cook.Step{{ID: "s"}}})

	// A failed existence check doesn't risk overwriting a job: nothing is
	// written.
	if keys := listKeys(t, obj, jobKeyPrefix); len(keys) != 0 {
		t.Errorf("expected nothing written after a failed existence check, got %v", keys)
	}
}

// TestRegisterNatsConn_UsesQueueGroup verifies that RegisterNatsConn
// subscribes to imas.cook.*.* as a queue-group member of "imas-core",
// not a plain fan-out subscriber. This used to be the other way around
// (see the function's own doc comment for why that changed): job logs
// used to live in each replica's own local directory, so every replica
// needed its own copy of every event. They now live in the shared job
// object store, where fan-out would have every replica write its own copy
// of each event into the same job.
//
// It simulates a second farmer replica by adding another queue subscriber
// on the same subject and queue group directly (mirroring
// internal/facts's TestRegisterFarmerListener_UsesQueueGroup), then
// verifies that published events are load-balanced across the two instead
// of delivered to both, and that the primary listener recorded exactly
// the share it received — once each.
func TestRegisterNatsConn_UsesQueueGroup(t *testing.T) {
	t.Run("step events", func(t *testing.T) {
		obj := useTestObjStore(t)
		_, conn := startTestNATSServer(t)
		RegisterNatsConn("t_test", conn)
		conn.Flush()

		// Simulate a second farmer replica subscribing to the same
		// subject in the same queue group.
		var secondReplicaHits int64
		sub, err := conn.QueueSubscribe("imas.cook.*.*", natsCoreQueueGroup, func(msg *nats.Msg) {
			atomic.AddInt64(&secondReplicaHits, 1)
		})
		if err != nil {
			t.Fatalf("simulate second replica subscribe: %v", err)
		}
		defer sub.Unsubscribe()
		conn.Flush()

		const numEvents = 20
		for i := range numEvents {
			step := cook.StepCompletion{
				ID:               cook.StepID(fmt.Sprintf("step-%d", i)),
				CompletionStatus: cook.StepCompleted,
				Started:          time.Now(),
			}
			data, _ := json.Marshal(step)
			if err := conn.Publish("imas.cook.queue-sprout.queue-job", data); err != nil {
				t.Fatal(err)
			}
		}
		conn.Flush()

		// Every event went to exactly one queue member: the primary
		// listener recorded the ones the simulated replica didn't get.
		prefix := jobPrefix("queue-sprout", "queue-job") + eventsDir
		ok := eventually(5*time.Second, func() bool {
			return int64(len(listKeys(t, obj, prefix)))+atomic.LoadInt64(&secondReplicaHits) == numEvents
		})
		hits := atomic.LoadInt64(&secondReplicaHits)
		recorded := len(listKeys(t, obj, prefix))
		if !ok {
			t.Fatalf("expected recorded (%d) + second replica (%d) = %d events", recorded, hits, numEvents)
		}
		// If RegisterNatsConn used plain Subscribe, the second replica
		// would get every event (hits == numEvents) and the primary would
		// record all of them too; under a different group name, hits
		// would be 0.
		if hits == 0 {
			t.Error("expected second replica to receive at least some events via queue-group load balancing")
		}
		if hits >= numEvents {
			t.Errorf("expected events to be load-balanced across queue members, but second replica received all %d (fan-out, not queue-grouped)", hits)
		}
	})
}

// A job is recorded by the replica that dispatches it: RegisterNatsConn
// installs recordJobCreation as cook's DispatchRecorder, since the
// dispatch itself is sealed to the sprout and can't be read off the bus.
func TestRegisterNatsConn_RecordsDispatchedJobs(t *testing.T) {
	obj := useTestObjStore(t)
	gdb, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := gdb.AutoMigrate(pki.Models()...); err != nil {
		t.Fatal(err)
	}
	pki.SetDB(gdb)
	t.Cleanup(func() { pki.SetDB(nil) })

	_, conn := startTestNATSServer(t)
	RegisterNatsConn("t_test", conn)
	t.Cleanup(func() { cook.SetDispatchRecorder(nil) })
	cook.RegisterFarmerNatsConn("t_test", conn)
	t.Cleanup(func() { cook.UnregisterFarmerNatsConn("t_test") })
	// A sprout with no box key on record, so the dispatch is plaintext
	// and a stub can acknowledge it.
	if _, err := conn.Subscribe(cook.CookSubject("sprout-dispatch"), func(m *nats.Msg) {
		var env cook.RecipeEnvelope
		json.Unmarshal(m.Data, &env)
		b, _ := json.Marshal(cook.Ack{Acknowledged: true, JobID: env.JobID})
		m.Respond(b)
	}); err != nil {
		t.Fatal(err)
	}
	conn.Flush()

	if err := cook.SendStepsEvent("t_test", "sprout-dispatch", "dispatch-job", []cook.Step{{ID: "s1"}, {ID: "s2"}}); err != nil {
		t.Fatalf("SendStepsEvent: %v", err)
	}
	summary := waitForSteps(t, obj, "sprout-dispatch", "dispatch-job", 2)
	if len(summary.Steps) != 2 {
		t.Errorf("expected 2 placeholder steps, got %d", len(summary.Steps))
	}
}

// TestRegisterNatsConn_TwoReplicasRecordEachEventOnce runs two farmer
// "replicas" (separate NATS connections, both RegisterNatsConn'd) against
// one shared bucket and reads the result through a third, independently
// opened client: every event is recorded exactly once, and whichever
// replica handled it, the job is complete from anywhere.
func TestRegisterNatsConn_TwoReplicasRecordEachEventOnce(t *testing.T) {
	stores := objectstoretest.NewSharedStores(t, 2)
	orig := objStore
	SetStore(stores[0])
	t.Cleanup(func() { SetStore(orig) })

	ns, connA := startTestNATSServer(t)
	connB, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connB.Close)
	RegisterNatsConn("t_test", connA)
	RegisterNatsConn("t_test", connB)
	connA.Flush()
	connB.Flush()

	pub, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pub.Close)

	const numSteps = 30
	envelope := cook.RecipeEnvelope{JobID: "shared-job", InvokedBy: "UADMIN", Steps: []cook.Step{{ID: "s"}}}
	// Recorded by whichever replica dispatched it (cook's
	// DispatchRecorder), once.
	recordJobCreation("t_test", "sprout-shared", envelope)
	// Let the creation land first so its existence check can't race the
	// events below (it would still be correct either way; this just keeps
	// the expected count exact).
	waitForSteps(t, stores[1], "sprout-shared", "shared-job", 1)
	for i := range numSteps {
		step := makeStep(fmt.Sprintf("step-%d", i), cook.StepCompleted, time.Now(), time.Millisecond)
		b, _ := json.Marshal(step)
		if err := pub.Publish("imas.cook.sprout-shared.shared-job", b); err != nil {
			t.Fatal(err)
		}
	}
	pub.Flush()

	// Read through the other client: 1 placeholder + numSteps events,
	// no duplicates.
	waitForSteps(t, stores[1], "sprout-shared", "shared-job", 1+numSteps)
	time.Sleep(100 * time.Millisecond) // any duplicate would have landed by now
	summary, err := NewStoreWithObjectStore(stores[1]).GetJob("sprout-shared", "shared-job")
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Steps) != 1+numSteps {
		t.Errorf("expected %d steps (each event recorded once), got %d", 1+numSteps, len(summary.Steps))
	}
	seen := map[cook.StepID]int{}
	for _, s := range summary.Steps {
		if s.CompletionStatus == cook.StepCompleted {
			seen[s.ID]++
		}
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("step %s recorded %d times", id, n)
		}
	}
	if summary.InvokedBy != "UADMIN" {
		t.Errorf("InvokedBy = %q, want UADMIN", summary.InvokedBy)
	}
}

func TestLogJobs_FailedStepWithError(t *testing.T) {
	obj := useTestObjStore(t)

	_, conn := startTestNATSServer(t)
	RegisterNatsConn("t_test", conn)

	step := cook.StepCompletion{
		ID:               "step-fail",
		CompletionStatus: cook.StepFailed,
		Started:          time.Now(),
		Duration:         time.Second,
		Error:            errors.New("boom"),
	}
	data, err := json.Marshal(step)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Publish("imas.cook.sprout-fail.job-fail-1", data); err != nil {
		t.Fatal(err)
	}
	conn.Flush()

	summary := waitForSteps(t, obj, "sprout-fail", "job-fail-1", 1)
	if len(summary.Steps) != 1 {
		t.Fatalf("expected 1 step, got %d", len(summary.Steps))
	}
	got := summary.Steps[0]
	if got.ID != "step-fail" || got.CompletionStatus != cook.StepFailed {
		t.Errorf("got step %+v", got)
	}
	if got.Error == nil || got.Error.Error() != "boom" {
		t.Errorf("Error = %v, want boom", got.Error)
	}
	if summary.Status != JobFailed || summary.Failed != 1 {
		t.Errorf("summary = %+v, want one failed step", summary)
	}
}

func TestLogJobs_LegacyEmptyObjectError(t *testing.T) {
	// Sprouts on an older version still send "Error":{}; the event must
	// be recorded, not dropped.
	obj := useTestObjStore(t)

	_, conn := startTestNATSServer(t)
	RegisterNatsConn("t_test", conn)

	payload := []byte(`{"ID":"timeout-job-old","CompletionStatus":3,"ChangesMade":false,"Changes":null,"started":"0001-01-01T00:00:00Z","Error":{}}`)
	if err := conn.Publish("imas.cook.sprout-old.job-old", payload); err != nil {
		t.Fatal(err)
	}
	conn.Flush()

	summary := waitForSteps(t, obj, "sprout-old", "job-old", 1)
	if len(summary.Steps) != 1 || summary.Steps[0].CompletionStatus != cook.StepFailed || summary.Steps[0].Error == nil {
		t.Errorf("got %+v, want one failed step with a non-nil Error", summary.Steps)
	}
}
