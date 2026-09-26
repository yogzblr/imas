package jobs

// This code subscribes to the job topics and records each job's events in
// the shared job object store (see store.go for the key layout and why
// each event is its own object).

// Jobs will eventuall be stored in triplicate: farmer-side (the shared job
// object store), in the jobs directory on the sprout, and in the jobs
// directory on the cli user's machine. For now, they are only stored
// farmer-side. Jobs can be retrieved from the farmer with the imas job
// command.

// Job data expiration is configurable via the joblogttl setting on both the
// farmer (Store.StartReaperCtx) and the sprout (StartSproutReaper).

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/yogzblr/imas/internal/log"

	"github.com/yogzblr/imas/internal/cook"
)

// natsCoreQueueGroup is the queue group every farmer replica shares for
// imas.cook.*.* and imas.sprouts.*.cook. It has the same well-known value
// internal/natsapi/router.go's Subscribe and internal/facts's listener use;
// the constant is unexported in both, so this package defines its own copy
// of the same value, as internal/facts does.
const natsCoreQueueGroup = "imas-core"

// RegisterNatsConn subscribes to job-related subjects on conn, one of
// farmer's per-tenant NATS connections (see
// docs/design/imas-tenant-context-threading.md's Option A). Called once
// per tenant connection by cmd/farmer/main.go, so every tenant's job/cook
// events reach farmer, not just the legacy tenant's. Job storage itself
// (the job object store, see SetStore) stays a single, un-partitioned
// keyspace across every tenant. The design doc makes the same carve-out
// explicit for internal/cook and internal/facts: this is about which
// connection a handler runs on, not about rescoping what the handler does
// once it's there.
//
// This used to use plain Subscribe (fan-out), not QueueSubscribe, on
// purpose. Job data was written to a local, per-process directory
// (config.JobLogDir), and with several farmer replicas a client's
// job-status query could land on any of them, so every replica needed its
// own on-disk copy of every job event to answer it. Job logs now live in
// object storage shared by every replica (store.go), and any replica reads
// the same objects whichever one received an event. That makes fan-out
// wasted work: every replica would write its own copy of each event into
// the same shared job, so every step would show up N times, once per
// replica. QueueSubscribe under the shared "imas-core" group (the same
// group internal/natsapi/router.go and internal/facts use) has exactly one
// replica record each event. internal/facts made the same change once
// props moved to PXC.
//
// Queue-grouping also means one job's events are spread across replicas
// and handled concurrently. That is why store.go writes each event as its
// own object instead of rewriting one shared object per job.
func RegisterNatsConn(tenantID string, conn *nats.Conn) {
	// conn is used directly below rather than stored in a package-level
	// var, since RegisterNatsConn can now run concurrently for different
	// tenants (docs/design/imas-tenant-context-threading.md) — a shared var
	// would race between one call's assignment and another's Subscribe, and
	// nothing else in this package needs to read it back afterward.
	//
	// tenantID is passed to each handler for the job-status index
	// (status_index.go), which keys every row by the tenant whose
	// connection the event arrived on.
	_, err := conn.QueueSubscribe("imas.cook.*.*", natsCoreQueueGroup, func(msg *nats.Msg) {
		logJobs(tenantID, msg)
	})
	if err != nil {
		log.Error(err)
	}
	_, err = conn.QueueSubscribe("imas.sprouts.*.cook", natsCoreQueueGroup, func(msg *nats.Msg) {
		logJobCreation(tenantID, msg)
	})
	if err != nil {
		log.Error(err)
	}
}

// logJobCreation records a new job from its recipe envelope: in the job
// object store, and (its step count) in the job-status index for tenantID.
func logJobCreation(tenantID string, msg *nats.Msg) {
	// Subject: imas.sprouts.<sproutID>.cook
	tComponents := strings.Split(msg.Subject, ".")
	if len(tComponents) < 4 {
		log.Errorf("unexpected subject format for job creation: %s", msg.Subject)
		return
	}
	sprout := tComponents[2]

	var envelope cook.RecipeEnvelope
	if err := json.Unmarshal(msg.Data, &envelope); err != nil {
		log.Errorf("failed to unmarshal recipe envelope: %v", err)
		return
	}
	if envelope.JobID == "" {
		return
	}
	if !validKeySegment(sprout) || !validKeySegment(envelope.JobID) {
		log.Errorf("refusing to record job %q for sprout %q: not usable as an object key segment", envelope.JobID, sprout)
		return
	}
	// Independent of the object-store writes below, which it neither
	// waits on nor replaces. Idempotent, so it runs even when created.jsonl
	// already exists.
	dispatchedAt := envelope.DispatchedAt
	if dispatchedAt.IsZero() {
		// An envelope from a farmer that predates DispatchedAt: this
		// replica's receipt of the push is within milliseconds of it.
		dispatchedAt = time.Now()
	}
	indexJobCreation(tenantID, sprout, envelope.JobID, len(envelope.Steps), dispatchedAt)
	obj := objStore
	if obj == nil {
		log.Errorf("failed to record job %s for sprout %s: %v", envelope.JobID, sprout, ErrJobStoreNotConfigured)
		return
	}
	ctx, cancel := opContext()
	defer cancel()

	// Write a creation marker so the job appears in listings immediately,
	// even before any step completions arrive.
	exists, err := obj.Exists(ctx, createdKey(sprout, envelope.JobID))
	if err != nil {
		log.Errorf("failed to check for existing job %s: %v", envelope.JobID, err)
		return
	}
	if exists {
		// Already created (shouldn't happen, but be safe).
		return
	}

	// Write job metadata: invoker info for audit attribution, and the
	// creation time the reaper dates a job by until its first event
	// arrives. Written even without an invoker for that reason.
	meta := JobMeta{
		JID:       envelope.JobID,
		InvokedBy: envelope.InvokedBy,
		CreatedAt: time.Now().UTC(),
	}
	if metaData, mErr := json.Marshal(meta); mErr == nil {
		if putErr := obj.Put(ctx, metaKey(sprout, envelope.JobID), metaData); putErr != nil {
			log.Errorf("failed to write job metadata for %s: %v", envelope.JobID, putErr)
		}
	}

	// Write a "not started" step for each step in the envelope so the job
	// shows up with the correct total count right away.
	var buf bytes.Buffer
	for _, step := range envelope.Steps {
		placeholder := cook.StepCompletion{
			ID:               step.ID,
			CompletionStatus: cook.StepNotStarted,
			Started:          time.Now(),
		}
		b, marshalErr := json.Marshal(placeholder)
		if marshalErr != nil {
			log.Errorf("failed to marshal placeholder step: %v", marshalErr)
			continue
		}
		buf.Write(b)
		buf.WriteString("\n")
	}
	if err := obj.Put(ctx, createdKey(sprout, envelope.JobID), buf.Bytes()); err != nil {
		log.Errorf("failed to create job %s: %v", envelope.JobID, err)
		return
	}
	log.Noticef("job %s created for sprout %s (%d steps)", envelope.JobID, sprout, len(envelope.Steps))
}

// logJobs records one job event: in the job object store, and in the
// job-status index for tenantID.
func logJobs(tenantID string, msg *nats.Msg) {
	// Subject: imas.cook.<sproutID>.<jid>
	tComponents := strings.Split(msg.Subject, ".")
	if len(tComponents) < 4 {
		log.Errorf("unexpected subject format for job step: %s", msg.Subject)
		return
	}
	sprout := tComponents[2]
	JID := tComponents[3]

	// Get the completedStep data
	var completedStep cook.StepCompletion
	err := json.Unmarshal(msg.Data, &completedStep)
	if err != nil {
		log.Error(err)
		return
	}
	if !validKeySegment(sprout) || !validKeySegment(JID) {
		log.Errorf("refusing to record step for job %q on sprout %q: not usable as an object key segment", JID, sprout)
		return
	}
	switch verdict, dispatchedAt := reconcileCheck(tenantID, sprout, JID); verdict {
	case reconcileExpire:
		log.Warnf("job %s on sprout %s (tenant %s) started more than %s after dispatch: marking it expired and not recording its steps", JID, sprout, tenantID, reconcileWindow)
		markJobExpired(tenantID, sprout, JID, *dispatchedAt)
		return
	case reconcileDrop:
		log.Debugf("not recording step %s of expired job %s on sprout %s (tenant %s)", completedStep.ID, JID, sprout, tenantID)
		return
	}
	// Independent of the object-store write below; see logJobCreation.
	indexJobEvent(tenantID, sprout, JID, classifyJobEvent(JID, completedStep))
	b, err := json.Marshal(completedStep)
	if err != nil {
		log.Error(err)
		return
	}
	obj := objStore
	if obj == nil {
		log.Errorf("failed to record step %s of job %s: %v", completedStep.ID, JID, ErrJobStoreNotConfigured)
		return
	}
	ctx, cancel := opContext()
	defer cancel()

	// Each event is its own object; see store.go for why.
	key := eventKey(sprout, JID, time.Now())
	log.Tracef("Job event object: %s\n", key)
	if err := obj.Put(ctx, key, append(b, '\n')); err != nil {
		log.Errorf("failed to record step %s of job %s: %v", completedStep.ID, JID, err)
		return
	}

	// Log the job
	log.Tracef("Job %s received\n", completedStep.ID)
}
