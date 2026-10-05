package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
)

func TestReapRemovesExpiredJobs(t *testing.T) {
	store, obj := newTestStore(t)
	step := makeStep("s1", cook.StepCompleted, time.Now(), time.Second)

	// old-job's newest event arrived 48h ago; new-job's just now.
	writeJobEvent(t, obj, "sprout-a", "old-job", time.Now().Add(-49*time.Hour), step)
	writeJobEvent(t, obj, "sprout-a", "old-job", time.Now().Add(-48*time.Hour), step)
	writeJobEvent(t, obj, "sprout-a", "new-job", time.Now(), step)

	// Reap with a 24h TTL — old-job should be removed.
	store.reap(24 * time.Hour)

	if _, err := store.GetJob(testTenant, "sprout-a", "old-job"); err != ErrJobNotFound {
		t.Errorf("expected old-job to be removed, got %v", err)
	}
	if _, err := store.GetJob(testTenant, "sprout-a", "new-job"); err != nil {
		t.Errorf("expected new-job to still exist, got error: %v", err)
	}
}

// TestReapUsesNewestEvent verifies a long-running job isn't expired just
// because its first event is old.
func TestReapUsesNewestEvent(t *testing.T) {
	store, obj := newTestStore(t)
	step := makeStep("s1", cook.StepCompleted, time.Now(), time.Second)

	writeJobEvent(t, obj, "sprout-a", "long-job", time.Now().Add(-72*time.Hour), step)
	writeJobEvent(t, obj, "sprout-a", "long-job", time.Now().Add(-time.Hour), step)

	store.reap(24 * time.Hour)

	if _, err := store.GetJob(testTenant, "sprout-a", "long-job"); err != nil {
		t.Errorf("expected long-job to survive (newest event is 1h old), got %v", err)
	}
}

func TestReap_RemovesMetaAndCreated(t *testing.T) {
	store, obj := newTestStore(t)

	// A job that was created 48h ago and never got a step event: dated by
	// its meta.json CreatedAt.
	putObject(t, obj, createdKey("sprout-meta-reap", "old-with-meta"), []byte("{}\n"))
	putObject(t, obj, metaKey("sprout-meta-reap", "old-with-meta"),
		[]byte(`{"jid":"old-with-meta","created_at":"`+time.Now().Add(-48*time.Hour).UTC().Format(time.RFC3339)+`"}`))

	store.reap(24 * time.Hour)

	if objectExists(t, obj, createdKey("sprout-meta-reap", "old-with-meta")) {
		t.Error("expected old job's created.jsonl to be removed")
	}
	if objectExists(t, obj, metaKey("sprout-meta-reap", "old-with-meta")) {
		t.Error("expected old meta to be removed along with job")
	}
}

// TestReap_RemovesOrphanMeta covers a meta.json whose created.jsonl Put
// failed: not a job as far as reads go, but still expired.
func TestReap_RemovesOrphanMeta(t *testing.T) {
	store, obj := newTestStore(t)

	putObject(t, obj, metaKey("sprout-orphan", "orphan"),
		[]byte(`{"jid":"orphan","created_at":"`+time.Now().Add(-48*time.Hour).UTC().Format(time.RFC3339)+`"}`))

	store.reap(24 * time.Hour)

	if objectExists(t, obj, metaKey("sprout-orphan", "orphan")) {
		t.Error("expected orphaned meta.json to be removed")
	}
}

// TestReap_KeepsUndatableJobs verifies a job with no event and no meta —
// nothing to tell its age by — is left alone rather than deleted.
func TestReap_KeepsUndatableJobs(t *testing.T) {
	store, obj := newTestStore(t)
	putObject(t, obj, createdKey("sprout-x", "undated"), []byte("{}\n"))

	store.reap(time.Nanosecond)

	if !objectExists(t, obj, createdKey("sprout-x", "undated")) {
		t.Error("expected a job with no datable object to be kept")
	}
}

func TestReap_SkipsStrayObjects(t *testing.T) {
	store, obj := newTestStore(t)

	// Objects outside the job layout are never touched.
	putObject(t, obj, "jobs/t_test/sprout-skip/notes.txt", []byte("keep me"))
	putObject(t, obj, "elsewhere/old.jsonl", []byte("keep me"))

	store.reap(time.Nanosecond)

	for _, key := range []string{"jobs/t_test/sprout-skip/notes.txt", "elsewhere/old.jsonl"} {
		if !objectExists(t, obj, key) {
			t.Errorf("expected %s to be preserved", key)
		}
	}
}

func TestReap_NotConfigured(t *testing.T) {
	orig := objStore
	SetStore(nil)
	t.Cleanup(func() { SetStore(orig) })

	// Should log and return, not panic.
	NewStore().reap(time.Hour)
}

func TestReap_ListError(t *testing.T) {
	srv := objectstoretest.NewServer(t)
	obj, err := objectstore.Open(srv.Config())
	if err != nil {
		t.Fatal(err)
	}
	store := NewStoreWithObjectStore(obj)
	step := makeStep("s1", cook.StepCompleted, time.Now(), time.Second)
	writeJobEvent(t, obj, "sprout-a", "old-job", time.Now().Add(-48*time.Hour), step)

	srv.FailNext(1, 403, "AccessDenied")
	store.reap(24 * time.Hour)

	// The failed listing means nothing was deleted.
	keys, err := obj.List(context.Background(), jobPrefix("sprout-a", "old-job"))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Errorf("expected old job to survive a failed listing, got keys %v", keys)
	}
}

func TestReapZeroTTLNoOp(t *testing.T) {
	store, obj := newTestStore(t)
	step := makeStep("s1", cook.StepCompleted, time.Now(), time.Second)
	writeJobEvent(t, obj, "sprout-c", "job", time.Now().Add(-9999*time.Hour), step)

	// StartReaper bails on ttl<=0 without starting a goroutine, so nothing
	// is ever deleted.
	store.StartReaper(0)

	if _, err := store.GetJob(testTenant, "sprout-c", "job"); err != nil {
		t.Errorf("expected job to still exist when TTL=0: %v", err)
	}
}

func TestEventTime(t *testing.T) {
	at := time.Unix(0, 1_700_000_000_123_456_789)
	got, ok := eventTime(eventKey("s", "j", at))
	if !ok || !got.Equal(at) {
		t.Errorf("eventTime(eventKey(%v)) = %v, %v", at, got, ok)
	}
	for _, key := range []string{"jobs/s/j/events/nodash.jsonl", "jobs/s/j/events/abc-def.jsonl"} {
		if _, ok := eventTime(key); ok {
			t.Errorf("eventTime(%q) should fail", key)
		}
	}
}
