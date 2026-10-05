package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
)

// newTestStore returns a Store backed by its own fake S3 bucket, and that
// bucket's objectstore.Store for seeding or inspecting objects directly.
func newTestStore(t *testing.T) (*Store, *objectstore.Store) {
	t.Helper()
	obj := objectstoretest.NewStore(t)
	return NewStoreWithObjectStore(obj), obj
}

// useTestObjStore installs a fresh fake bucket as the package-level job
// store (what RegisterNatsConn's listeners and NewStore use) for the rest
// of the test.
func useTestObjStore(t *testing.T) *objectstore.Store {
	t.Helper()
	obj := objectstoretest.NewStore(t)
	orig := objStore
	SetStore(obj)
	t.Cleanup(func() { SetStore(orig) })
	return obj
}

// writeJobFile seeds a job's step log the way RegisterNatsConn's listener
// writes it: one event object per step, in order.
func writeJobFile(t *testing.T, obj *objectstore.Store, sproutID, jid string, steps []cook.StepCompletion) {
	t.Helper()
	base := time.Now()
	for i, step := range steps {
		writeJobEvent(t, obj, sproutID, jid, base.Add(time.Duration(i)), step)
	}
}

// writeJobEvent seeds one event object as if it had been received at at.
func writeJobEvent(t *testing.T, obj *objectstore.Store, sproutID, jid string, at time.Time, step cook.StepCompletion) {
	t.Helper()
	b, err := json.Marshal(step)
	if err != nil {
		t.Fatal(err)
	}
	if err := obj.Put(context.Background(), eventKey(sproutID, jid, at), append(b, '\n')); err != nil {
		t.Fatal(err)
	}
}

// putObject writes raw content to key, failing the test on error.
func putObject(t *testing.T, obj *objectstore.Store, key string, data []byte) {
	t.Helper()
	if err := obj.Put(context.Background(), key, data); err != nil {
		t.Fatal(err)
	}
}

// objectExists reports whether key is in obj, failing the test on error.
func objectExists(t *testing.T, obj *objectstore.Store, key string) bool {
	t.Helper()
	ok, err := obj.Exists(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func makeStep(id string, status cook.CompletionStatus, started time.Time, duration time.Duration) cook.StepCompletion {
	return cook.StepCompletion{
		ID:               cook.StepID(id),
		CompletionStatus: status,
		Started:          started,
		Duration:         duration,
	}
}

func TestNewStore(t *testing.T) {
	obj := objectstoretest.NewStore(t)
	store := NewStoreWithObjectStore(obj)
	got, err := store.backend()
	if err != nil {
		t.Fatalf("backend: %v", err)
	}
	if got != obj {
		t.Error("expected the Store to use the object store it was given")
	}
}

func TestGetJob_Found(t *testing.T) {
	store, obj := newTestStore(t)
	now := time.Now().Truncate(time.Second)

	steps := []cook.StepCompletion{
		makeStep("step-1", cook.StepCompleted, now, 5*time.Second),
		makeStep("step-2", cook.StepCompleted, now.Add(5*time.Second), 3*time.Second),
	}
	writeJobFile(t, obj, "sprout-a", "job-123", steps)

	summary, err := store.GetJob(testTenant, "sprout-a", "job-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summary.JID != "job-123" {
		t.Errorf("expected JID job-123, got %s", summary.JID)
	}
	if summary.SproutID != "sprout-a" {
		t.Errorf("expected SproutID sprout-a, got %s", summary.SproutID)
	}
	if summary.Total != 2 {
		t.Errorf("expected 2 total steps, got %d", summary.Total)
	}
	if summary.Succeeded != 2 {
		t.Errorf("expected 2 succeeded, got %d", summary.Succeeded)
	}
	if summary.Status != JobSucceeded {
		t.Errorf("expected status succeeded, got %s", summary.Status)
	}
}

func TestGetJob_NotFound(t *testing.T) {
	store, _ := newTestStore(t)

	_, err := store.GetJob(testTenant, "nonexistent", "no-such-job")
	if err != ErrJobNotFound {
		t.Errorf("expected ErrJobNotFound, got %v", err)
	}
}

func TestFindJob(t *testing.T) {
	store, obj := newTestStore(t)
	now := time.Now().Truncate(time.Second)

	steps := []cook.StepCompletion{
		makeStep("step-1", cook.StepFailed, now, 2*time.Second),
	}
	writeJobFile(t, obj, "sprout-b", "unique-jid", steps)

	summary, err := store.FindJob(testTenant, "unique-jid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summary.SproutID != "sprout-b" {
		t.Errorf("expected sprout-b, got %s", summary.SproutID)
	}
	if summary.Status != JobFailed {
		t.Errorf("expected status failed, got %s", summary.Status)
	}
}

func TestFindJob_NotFound(t *testing.T) {
	store, _ := newTestStore(t)

	_, err := store.FindJob(testTenant, "missing")
	if err != ErrJobNotFound {
		t.Errorf("expected ErrJobNotFound, got %v", err)
	}
}

func TestListJobsForSprout(t *testing.T) {
	store, obj := newTestStore(t)
	now := time.Now().Truncate(time.Second)

	writeJobFile(t, obj, "sprout-c", "job-1", []cook.StepCompletion{
		makeStep("s1", cook.StepCompleted, now, time.Second),
	})
	writeJobFile(t, obj, "sprout-c", "job-2", []cook.StepCompletion{
		makeStep("s1", cook.StepCompleted, now.Add(10*time.Second), time.Second),
	})
	writeJobFile(t, obj, "sprout-c", "job-3", []cook.StepCompletion{
		makeStep("s1", cook.StepFailed, now.Add(20*time.Second), time.Second),
	})

	summaries, err := store.ListJobsForSprout(testTenant, "sprout-c")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(summaries) != 3 {
		t.Fatalf("expected 3 jobs, got %d", len(summaries))
	}
	// Should be sorted by start time, most recent first
	if summaries[0].JID != "job-3" {
		t.Errorf("expected job-3 first (most recent), got %s", summaries[0].JID)
	}
	if summaries[2].JID != "job-1" {
		t.Errorf("expected job-1 last (oldest), got %s", summaries[2].JID)
	}
}

func TestListJobsForSprout_NoJobs(t *testing.T) {
	store, _ := newTestStore(t)

	_, err := store.ListJobsForSprout(testTenant, "nonexistent")
	if err != ErrSproutNoJobs {
		t.Errorf("expected ErrSproutNoJobs, got %v", err)
	}
}

func TestListAllJobs(t *testing.T) {
	store, obj := newTestStore(t)
	now := time.Now().Truncate(time.Second)

	writeJobFile(t, obj, "sprout-x", "job-a", []cook.StepCompletion{
		makeStep("s1", cook.StepCompleted, now, time.Second),
	})
	writeJobFile(t, obj, "sprout-y", "job-b", []cook.StepCompletion{
		makeStep("s1", cook.StepCompleted, now.Add(5*time.Second), time.Second),
	})

	summaries, err := store.ListAllJobs(testTenant, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(summaries) != 2 {
		t.Fatalf("expected 2 jobs, got %d", len(summaries))
	}
	// Most recent first
	if summaries[0].JID != "job-b" {
		t.Errorf("expected job-b first, got %s", summaries[0].JID)
	}
}

func TestListAllJobs_WithLimit(t *testing.T) {
	store, obj := newTestStore(t)
	now := time.Now().Truncate(time.Second)

	for i := range 5 {
		writeJobFile(t, obj, "sprout-z", fmt.Sprintf("job-%d", i), []cook.StepCompletion{
			makeStep("s1", cook.StepCompleted, now.Add(time.Duration(i)*time.Minute), time.Second),
		})
	}

	summaries, err := store.ListAllJobs(testTenant, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(summaries) != 3 {
		t.Errorf("expected 3 jobs (limited), got %d", len(summaries))
	}
}

func TestListSprouts(t *testing.T) {
	store, obj := newTestStore(t)
	now := time.Now()

	for _, sprout := range []string{"gamma", "alpha", "beta"} {
		writeJobFile(t, obj, sprout, "job-1", []cook.StepCompletion{
			makeStep("s1", cook.StepCompleted, now, time.Second),
		})
	}
	// A second job for one sprout doesn't list it twice.
	writeJobFile(t, obj, "alpha", "job-2", []cook.StepCompletion{
		makeStep("s1", cook.StepCompleted, now, time.Second),
	})

	sprouts, err := store.ListSprouts(testTenant)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"alpha", "beta", "gamma"}
	if fmt.Sprint(sprouts) != fmt.Sprint(want) {
		t.Errorf("ListSprouts = %v, want %v", sprouts, want)
	}
}

func TestCountJobsForSprout(t *testing.T) {
	store, obj := newTestStore(t)
	now := time.Now().Truncate(time.Second)

	writeJobFile(t, obj, "sprout-count", "j1", []cook.StepCompletion{
		makeStep("s1", cook.StepCompleted, now, time.Second),
	})
	writeJobFile(t, obj, "sprout-count", "j2", []cook.StepCompletion{
		makeStep("s1", cook.StepCompleted, now, time.Second),
	})

	count, err := store.CountJobsForSprout(testTenant, "sprout-count")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2, got %d", count)
	}
}

func TestCountJobsForSprout_Nonexistent(t *testing.T) {
	store, _ := newTestStore(t)

	count, err := store.CountJobsForSprout(testTenant, "ghost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

func TestDetermineJobStatus(t *testing.T) {
	tests := []struct {
		name     string
		steps    []cook.StepCompletion
		expected JobStatus
	}{
		{
			name:     "empty steps returns pending",
			steps:    nil,
			expected: JobPending,
		},
		{
			name: "all completed returns succeeded",
			steps: []cook.StepCompletion{
				makeStep("s1", cook.StepCompleted, time.Now(), time.Second),
				makeStep("s2", cook.StepCompleted, time.Now(), time.Second),
			},
			expected: JobSucceeded,
		},
		{
			name: "all skipped returns succeeded",
			steps: []cook.StepCompletion{
				makeStep("s1", cook.StepSkipped, time.Now(), 0),
			},
			expected: JobSucceeded,
		},
		{
			name: "any in progress returns running",
			steps: []cook.StepCompletion{
				makeStep("s1", cook.StepCompleted, time.Now(), time.Second),
				makeStep("s2", cook.StepInProgress, time.Now(), 0),
			},
			expected: JobRunning,
		},
		{
			name: "any failed returns failed",
			steps: []cook.StepCompletion{
				makeStep("s1", cook.StepCompleted, time.Now(), time.Second),
				makeStep("s2", cook.StepFailed, time.Now(), time.Second),
			},
			expected: JobFailed,
		},
		{
			name: "mix of completed and not started returns partial",
			steps: []cook.StepCompletion{
				makeStep("s1", cook.StepCompleted, time.Now(), time.Second),
				makeStep("s2", cook.StepNotStarted, time.Time{}, 0),
			},
			expected: JobPartial,
		},
		{
			name: "all not started returns pending",
			steps: []cook.StepCompletion{
				makeStep("s1", cook.StepNotStarted, time.Time{}, 0),
				makeStep("s2", cook.StepNotStarted, time.Time{}, 0),
			},
			expected: JobPending,
		},
		{
			name: "in progress takes priority over failed",
			steps: []cook.StepCompletion{
				makeStep("s1", cook.StepFailed, time.Now(), time.Second),
				makeStep("s2", cook.StepInProgress, time.Now(), 0),
			},
			expected: JobRunning,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := determineJobStatus(tt.steps)
			if got != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, got)
			}
		})
	}
}

func TestJobStatusJSON(t *testing.T) {
	tests := []struct {
		status   JobStatus
		expected string
	}{
		{JobPending, `"pending"`},
		{JobRunning, `"running"`},
		{JobSucceeded, `"succeeded"`},
		{JobFailed, `"failed"`},
		{JobPartial, `"partial"`},
	}

	for _, tt := range tests {
		t.Run(tt.status.String(), func(t *testing.T) {
			b, err := json.Marshal(tt.status)
			if err != nil {
				t.Fatalf("marshal error: %v", err)
			}
			if string(b) != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, string(b))
			}

			var unmarshaled JobStatus
			if err := json.Unmarshal(b, &unmarshaled); err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}
			if unmarshaled != tt.status {
				t.Errorf("expected %v after roundtrip, got %v", tt.status, unmarshaled)
			}
		})
	}
}

func TestBuildSummary_Duration(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	steps := []cook.StepCompletion{
		makeStep("s1", cook.StepCompleted, now, 5*time.Second),
		makeStep("s2", cook.StepCompleted, now.Add(5*time.Second), 10*time.Second),
		makeStep("s3", cook.StepFailed, now.Add(2*time.Second), 3*time.Second),
	}

	summary := buildSummary("test-jid", "test-sprout", steps)

	if !summary.StartedAt.Equal(now) {
		t.Errorf("expected StartedAt %v, got %v", now, summary.StartedAt)
	}
	// Latest end: s2 started at +5s with 10s duration = +15s from now
	expectedDuration := 15 * time.Second
	if summary.Duration != expectedDuration {
		t.Errorf("expected duration %v, got %v", expectedDuration, summary.Duration)
	}
	if summary.Succeeded != 2 {
		t.Errorf("expected 2 succeeded, got %d", summary.Succeeded)
	}
	if summary.Failed != 1 {
		t.Errorf("expected 1 failed, got %d", summary.Failed)
	}
}

func TestReadJobFile_EmptyLines(t *testing.T) {
	dir := t.TempDir()
	jobFile := filepath.Join(dir, "test.jsonl")

	step := makeStep("s1", cook.StepCompleted, time.Now().Truncate(time.Second), time.Second)
	b, _ := json.Marshal(step)
	// File with blank lines
	content := fmt.Sprintf("\n%s\n\n%s\n\n", string(b), string(b))
	if err := os.WriteFile(jobFile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	steps, err := readJobFile(jobFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(steps) != 2 {
		t.Errorf("expected 2 steps (skipping blank lines), got %d", len(steps))
	}
}

func TestListAllJobs_EmptyBucket(t *testing.T) {
	store, _ := newTestStore(t)

	summaries, err := store.ListAllJobs(testTenant, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(summaries) != 0 {
		t.Errorf("expected 0 jobs, got %d", len(summaries))
	}
}

func TestListSprouts_EmptyBucket(t *testing.T) {
	store, _ := newTestStore(t)

	sprouts, err := store.ListSprouts(testTenant)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sprouts) != 0 {
		t.Errorf("expected 0 sprouts, got %d", len(sprouts))
	}
}

func TestStore_NotConfigured(t *testing.T) {
	orig := objStore
	SetStore(nil)
	t.Cleanup(func() { SetStore(orig) })
	store := NewStore()

	if _, err := store.GetJob(testTenant, "s", "j"); !errors.Is(err, ErrJobStoreNotConfigured) {
		t.Errorf("GetJob: expected ErrJobStoreNotConfigured, got %v", err)
	}
	if _, err := store.FindJob(testTenant, "j"); !errors.Is(err, ErrJobStoreNotConfigured) {
		t.Errorf("FindJob: expected ErrJobStoreNotConfigured, got %v", err)
	}
	if _, err := store.ListJobsForSprout(testTenant, "s"); !errors.Is(err, ErrJobStoreNotConfigured) {
		t.Errorf("ListJobsForSprout: expected ErrJobStoreNotConfigured, got %v", err)
	}
	if _, err := store.ListAllJobs(testTenant, 0); !errors.Is(err, ErrJobStoreNotConfigured) {
		t.Errorf("ListAllJobs: expected ErrJobStoreNotConfigured, got %v", err)
	}
	if err := store.DeleteJob(testTenant, "s", "j"); !errors.Is(err, ErrJobStoreNotConfigured) {
		t.Errorf("DeleteJob: expected ErrJobStoreNotConfigured, got %v", err)
	}
	if _, err := store.ListSprouts(testTenant); !errors.Is(err, ErrJobStoreNotConfigured) {
		t.Errorf("ListSprouts: expected ErrJobStoreNotConfigured, got %v", err)
	}
	if _, err := store.CountJobsForSprout(testTenant, "s"); !errors.Is(err, ErrJobStoreNotConfigured) {
		t.Errorf("CountJobsForSprout: expected ErrJobStoreNotConfigured, got %v", err)
	}
}

// TestNewStore_ResolvesStoreLazily covers internal/natsapi's usage: it
// calls NewStore in an init(), before main has called SetStore.
func TestNewStore_ResolvesStoreLazily(t *testing.T) {
	orig := objStore
	SetStore(nil)
	t.Cleanup(func() { SetStore(orig) })
	store := NewStore()

	obj := useTestObjStore(t)
	writeJobFile(t, obj, "sprout-late", "job-late", []cook.StepCompletion{
		makeStep("s1", cook.StepCompleted, time.Now(), time.Second),
	})
	if _, err := store.GetJob(testTenant, "sprout-late", "job-late"); err != nil {
		t.Errorf("GetJob after SetStore: %v", err)
	}
}

func writeJobMeta(t *testing.T, obj *objectstore.Store, sproutID, jid, invokedBy string) {
	t.Helper()
	meta := JobMeta{
		JID:       jid,
		InvokedBy: invokedBy,
		CreatedAt: time.Now().UTC(),
	}
	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	putObject(t, obj, metaKey(sproutID, jid), data)
}

func TestGetJob_WithInvokedBy(t *testing.T) {
	store, obj := newTestStore(t)
	now := time.Now()

	steps := []cook.StepCompletion{
		makeStep("step-1", cook.StepCompleted, now, time.Second),
	}
	writeJobFile(t, obj, "web-1", "job-meta-1", steps)
	writeJobMeta(t, obj, "web-1", "job-meta-1", "UPUBKEY_ALICE")

	summary, err := store.GetJob(testTenant, "web-1", "job-meta-1")
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if summary.InvokedBy != "UPUBKEY_ALICE" {
		t.Errorf("InvokedBy = %q, want UPUBKEY_ALICE", summary.InvokedBy)
	}
}

func TestGetJob_WithoutMeta(t *testing.T) {
	store, obj := newTestStore(t)
	now := time.Now()

	steps := []cook.StepCompletion{
		makeStep("step-1", cook.StepCompleted, now, time.Second),
	}
	writeJobFile(t, obj, "web-1", "job-no-meta", steps)

	summary, err := store.GetJob(testTenant, "web-1", "job-no-meta")
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if summary.InvokedBy != "" {
		t.Errorf("InvokedBy = %q, want empty", summary.InvokedBy)
	}
}

func TestFindJob_WithInvokedBy(t *testing.T) {
	store, obj := newTestStore(t)
	now := time.Now()

	steps := []cook.StepCompletion{
		makeStep("step-1", cook.StepCompleted, now, time.Second),
	}
	writeJobFile(t, obj, "db-1", "job-find-meta", steps)
	writeJobMeta(t, obj, "db-1", "job-find-meta", "UPUBKEY_BOB")

	summary, err := store.FindJob(testTenant, "job-find-meta")
	if err != nil {
		t.Fatalf("FindJob: %v", err)
	}
	if summary.InvokedBy != "UPUBKEY_BOB" {
		t.Errorf("InvokedBy = %q, want UPUBKEY_BOB", summary.InvokedBy)
	}
}

func TestListJobsForSprout_WithInvokedBy(t *testing.T) {
	store, obj := newTestStore(t)
	now := time.Now()

	steps := []cook.StepCompletion{
		makeStep("step-1", cook.StepCompleted, now, time.Second),
	}
	writeJobFile(t, obj, "app-1", "job-list-1", steps)
	writeJobMeta(t, obj, "app-1", "job-list-1", "UPUBKEY_CAROL")
	writeJobFile(t, obj, "app-1", "job-list-2", steps)
	// No meta for job-list-2

	summaries, err := store.ListJobsForSprout(testTenant, "app-1")
	if err != nil {
		t.Fatalf("ListJobsForSprout: %v", err)
	}
	if len(summaries) != 2 {
		t.Fatalf("expected 2 summaries, got %d", len(summaries))
	}

	foundMeta := false
	foundNoMeta := false
	for _, s := range summaries {
		if s.JID == "job-list-1" && s.InvokedBy == "UPUBKEY_CAROL" {
			foundMeta = true
		}
		if s.JID == "job-list-2" && s.InvokedBy == "" {
			foundNoMeta = true
		}
	}
	if !foundMeta {
		t.Error("job-list-1 should have InvokedBy=UPUBKEY_CAROL")
	}
	if !foundNoMeta {
		t.Error("job-list-2 should have empty InvokedBy")
	}
}

func TestDeleteJob_Found(t *testing.T) {
	store, obj := newTestStore(t)
	now := time.Now().Truncate(time.Second)

	steps := []cook.StepCompletion{
		makeStep("step-1", cook.StepCompleted, now, 2*time.Second),
		makeStep("step-2", cook.StepCompleted, now, 2*time.Second),
	}
	putObject(t, obj, createdKey("sprout-del", "del-job-1"), []byte("\n"))
	writeJobFile(t, obj, "sprout-del", "del-job-1", steps)
	writeJobMeta(t, obj, "sprout-del", "del-job-1", "testuser")
	// A different job on the same sprout must survive.
	writeJobFile(t, obj, "sprout-del", "keep-job", steps)

	// Confirm it exists.
	_, err := store.FindJob(testTenant, "del-job-1")
	if err != nil {
		t.Fatalf("setup: job should exist: %v", err)
	}

	// Delete it.
	if err := store.DeleteJob(testTenant, "sprout-del", "del-job-1"); err != nil {
		t.Fatalf("DeleteJob: %v", err)
	}

	// Confirm it's gone.
	_, err = store.FindJob(testTenant, "del-job-1")
	if err != ErrJobNotFound {
		t.Errorf("expected ErrJobNotFound after delete, got %v", err)
	}

	// Confirm every one of its objects, meta included, is gone.
	keys, err := obj.List(context.Background(), jobPrefix("sprout-del", "del-job-1"))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Errorf("expected no objects left for the deleted job, got %v", keys)
	}
	if _, err := store.GetJob(testTenant, "sprout-del", "keep-job"); err != nil {
		t.Errorf("other job on the same sprout should survive: %v", err)
	}
}

func TestDeleteJob_NotFound(t *testing.T) {
	store, _ := newTestStore(t)

	err := store.DeleteJob(testTenant, "sprout-del", "nonexistent-jid")
	if err != ErrJobNotFound {
		t.Errorf("expected ErrJobNotFound, got %v", err)
	}
}

func TestDeleteJob_EmptyBucket(t *testing.T) {
	store, _ := newTestStore(t)

	err := store.DeleteJob(testTenant, "any-sprout", "any-jid")
	if err != ErrJobNotFound {
		t.Errorf("expected ErrJobNotFound for an empty bucket, got %v", err)
	}
}

func TestReadJobMeta_MalformedJSON(t *testing.T) {
	store, obj := newTestStore(t)

	writeJobFile(t, obj, "sprout-bad", "bad-job", []cook.StepCompletion{
		makeStep("s1", cook.StepCompleted, time.Now(), time.Second),
	})
	putObject(t, obj, metaKey("sprout-bad", "bad-job"), []byte("not json"))

	summary, err := store.GetJob(testTenant, "sprout-bad", "bad-job")
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if summary.InvokedBy != "" {
		t.Errorf("InvokedBy = %q, want empty for malformed meta", summary.InvokedBy)
	}
}

// TestStore_SharedBucketAcrossReplicas is the property this package's move
// to object storage exists for: two farmer replicas, each with its own
// independently opened client on the same bucket, see the same job data.
// Before, each replica had its own local directory, so a job-status query
// could only be answered by the replica that happened to record the job.
func TestStore_SharedBucketAcrossReplicas(t *testing.T) {
	clients := objectstoretest.NewSharedStores(t, 2)
	replicaA := NewStoreWithObjectStore(clients[0])
	replicaB := NewStoreWithObjectStore(clients[1])
	now := time.Now().Truncate(time.Second)

	// Queue-grouped listeners spread one job's events across replicas:
	// the creation and first step land on A, the second step on B.
	putObject(t, clients[0], createdKey("web-1", "job-shared"),
		[]byte(`{"ID":"step-1","CompletionStatus":0}`+"\n"+`{"ID":"step-2","CompletionStatus":0}`+"\n"))
	writeJobMeta(t, clients[0], "web-1", "job-shared", "UPUBKEY_ALICE")
	writeJobEvent(t, clients[0], "web-1", "job-shared", now, makeStep("step-1", cook.StepCompleted, now, time.Second))
	writeJobEvent(t, clients[1], "web-1", "job-shared", now.Add(time.Millisecond), makeStep("step-2", cook.StepFailed, now, 2*time.Second))
	writeJobFile(t, clients[1], "db-1", "job-other", []cook.StepCompletion{
		makeStep("s1", cook.StepCompleted, now.Add(time.Minute), time.Second),
	})

	for name, replica := range map[string]*Store{"A": replicaA, "B": replicaB} {
		got, err := replica.GetJob(testTenant, "web-1", "job-shared")
		if err != nil {
			t.Fatalf("replica %s GetJob: %v", name, err)
		}
		if got.Total != 4 || got.Succeeded != 1 || got.Failed != 1 || got.InvokedBy != "UPUBKEY_ALICE" {
			t.Errorf("replica %s sees %+v, want the whole job from both replicas' writes", name, got)
		}
		if got.Status != JobFailed {
			t.Errorf("replica %s status = %s, want failed", name, got.Status)
		}

		found, err := replica.FindJob(testTenant, "job-other")
		if err != nil || found.SproutID != "db-1" {
			t.Errorf("replica %s FindJob(job-other) = %+v, %v", name, found, err)
		}
		all, err := replica.ListAllJobs(testTenant, 0)
		if err != nil || len(all) != 2 {
			t.Errorf("replica %s ListAllJobs = %d jobs, %v; want 2", name, len(all), err)
		}
		sprouts, err := replica.ListSprouts(testTenant)
		if err != nil || fmt.Sprint(sprouts) != "[db-1 web-1]" {
			t.Errorf("replica %s ListSprouts = %v, %v", name, sprouts, err)
		}
	}

	// A delete through one replica is seen by the other.
	if err := replicaB.DeleteJob(testTenant, "web-1", "job-shared"); err != nil {
		t.Fatalf("replica B DeleteJob: %v", err)
	}
	if _, err := replicaA.GetJob(testTenant, "web-1", "job-shared"); err != ErrJobNotFound {
		t.Errorf("replica A after B's delete: expected ErrJobNotFound, got %v", err)
	}
}
