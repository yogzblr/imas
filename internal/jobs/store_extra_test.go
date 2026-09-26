package jobs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
)

func TestNewStore_Default(t *testing.T) {
	// NewStore uses the package-level store; verify it returns a non-nil store.
	store := NewStore()
	if store == nil {
		t.Fatal("expected non-nil store")
	}
}

func TestJobStatus_String_Unknown(t *testing.T) {
	var s JobStatus = 99
	if s.String() != "unknown" {
		t.Errorf("expected 'unknown', got %q", s.String())
	}
}

func TestJobStatus_UnmarshalJSON_Invalid(t *testing.T) {
	var s JobStatus
	err := s.UnmarshalJSON([]byte(`"bogus"`))
	if err == nil {
		t.Error("expected error for unknown status string")
	}
}

func TestJobStatus_UnmarshalJSON_NotString(t *testing.T) {
	var s JobStatus
	err := s.UnmarshalJSON([]byte(`123`))
	if err == nil {
		t.Error("expected error for non-string JSON")
	}
}

func TestReadJobFile_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	jobFile := filepath.Join(dir, "bad.jsonl")
	os.WriteFile(jobFile, []byte("not json at all\n"), 0o644)

	_, err := readJobFile(jobFile)
	if err == nil {
		t.Error("expected error for invalid JSON in job file")
	}
}

func TestGetJob_InvalidRef(t *testing.T) {
	store, obj := newTestStore(t)
	writeJobFile(t, obj, "sprout", "job", []cook.StepCompletion{
		makeStep("s1", cook.StepCompleted, time.Now(), time.Second),
	})

	for _, ref := range [][2]string{{"", "job"}, {"sprout", ""}, {"..", "job"}, {"sprout/job", "x"}, {"sprout", "job/events"}} {
		if _, err := store.GetJob(ref[0], ref[1]); err != ErrJobNotFound {
			t.Errorf("GetJob(%q, %q): expected ErrJobNotFound, got %v", ref[0], ref[1], err)
		}
	}
	if _, err := store.ListJobsForSprout("a/b"); err != ErrSproutNoJobs {
		t.Errorf("ListJobsForSprout: expected ErrSproutNoJobs, got %v", err)
	}
}

func TestGetJob_ReadError(t *testing.T) {
	store, obj := newTestStore(t)

	// An event object that isn't valid JSONL.
	putObject(t, obj, eventKey("sprout-err", "job-bad", time.Now()), []byte("not json\n"))

	_, err := store.GetJob("sprout-err", "job-bad")
	if err == nil || err == ErrJobNotFound {
		t.Errorf("expected a read error for a corrupt event object, got %v", err)
	}
}

func TestGetJob_ObjectStoreError(t *testing.T) {
	srv := objectstoretest.NewServer(t)
	obj, err := objectstore.Open(srv.Config())
	if err != nil {
		t.Fatal(err)
	}
	store := NewStoreWithObjectStore(obj)
	writeJobFile(t, obj, "sprout-err", "job", []cook.StepCompletion{
		makeStep("s1", cook.StepCompleted, time.Now(), time.Second),
	})

	srv.FailNext(1, 403, "AccessDenied")
	if _, err := store.GetJob("sprout-err", "job"); err == nil || err == ErrJobNotFound {
		t.Errorf("expected the object store's error to surface, got %v", err)
	}
}

func TestCountJobsForSprout_IgnoresStrayObjects(t *testing.T) {
	store, obj := newTestStore(t)

	writeJobFile(t, obj, "sprout-mixed", "job", []cook.StepCompletion{
		makeStep("s1", cook.StepCompleted, time.Now(), time.Second),
	})
	// Metadata alone doesn't make a job, and keys outside the layout are
	// ignored.
	writeJobMeta(t, obj, "sprout-mixed", "meta-only", "UPUBKEY")
	putObject(t, obj, "jobs/sprout-mixed/readme.txt", []byte("hi"))
	putObject(t, obj, "jobs/sprout-mixed/job/notes.txt", []byte("hi"))
	putObject(t, obj, "jobs/sprout-mixed/job/events/nested/x.jsonl", []byte("{}\n"))

	count, err := store.CountJobsForSprout("sprout-mixed")
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected 1 job, got %d", count)
	}
}

func TestListJobsForSprout_SkipsStrayObjects(t *testing.T) {
	store, obj := newTestStore(t)
	now := time.Now().Truncate(time.Second)

	// Create a real job.
	writeJobFile(t, obj, "sprout-dirs", "real-job", []cook.StepCompletion{
		makeStep("s1", cook.StepCompleted, now, time.Second),
	})
	// Objects that aren't part of any job's log.
	putObject(t, obj, "jobs/sprout-dirs/readme.txt", []byte("hi"))
	putObject(t, obj, "jobs/sprout-dirs/not-a-job/other.bin", []byte("hi"))

	summaries, err := store.ListJobsForSprout("sprout-dirs")
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 1 {
		t.Errorf("expected 1 job, got %d", len(summaries))
	}
}

func TestBuildSummary_ZeroStartTimes(t *testing.T) {
	steps := []cook.StepCompletion{
		makeStep("s1", cook.StepNotStarted, time.Time{}, 0),
		makeStep("s2", cook.StepNotStarted, time.Time{}, 0),
	}

	summary := buildSummary("jid", "sprout", steps)
	if !summary.StartedAt.IsZero() {
		t.Error("expected zero StartedAt for not-started steps")
	}
	if summary.Duration != 0 {
		t.Errorf("expected zero duration, got %v", summary.Duration)
	}
}

func TestBuildSummary_Skipped(t *testing.T) {
	now := time.Now()
	steps := []cook.StepCompletion{
		makeStep("s1", cook.StepCompleted, now, time.Second),
		makeStep("s2", cook.StepSkipped, now, 0),
	}

	summary := buildSummary("jid", "sprout", steps)
	if summary.Skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", summary.Skipped)
	}
	if summary.Succeeded != 1 {
		t.Errorf("expected 1 succeeded, got %d", summary.Succeeded)
	}
}

func TestListAllJobs_WithInvokedBy(t *testing.T) {
	store, obj := newTestStore(t)
	now := time.Now().Truncate(time.Second)

	writeJobFile(t, obj, "sprout-allinv", "job-inv-1", []cook.StepCompletion{
		makeStep("s1", cook.StepCompleted, now, time.Second),
	})
	writeJobMeta(t, obj, "sprout-allinv", "job-inv-1", "UPUBKEY_TESTER")

	summaries, err := store.ListAllJobs(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 1 {
		t.Fatalf("expected 1 job, got %d", len(summaries))
	}
	if summaries[0].InvokedBy != "UPUBKEY_TESTER" {
		t.Errorf("expected UPUBKEY_TESTER, got %s", summaries[0].InvokedBy)
	}
}

func TestDefaultCLIStorePath(t *testing.T) {
	path, err := DefaultCLIStorePath()
	if err != nil {
		t.Fatalf("DefaultCLIStorePath: %v", err)
	}
	if path == "" {
		t.Error("expected non-empty path")
	}
	// Should end with "imas/jobs".
	if filepath.Base(path) != "jobs" {
		t.Errorf("expected path ending with 'jobs', got %q", path)
	}
}

func TestCLIStore_RecordJobStart_ExistingJsonl(t *testing.T) {
	dir := t.TempDir()
	store, err := NewCLIStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Pre-create the JSONL file.
	sproutDir := filepath.Join(dir, "sprout-pre")
	os.MkdirAll(sproutDir, 0o700)
	jobFile := filepath.Join(sproutDir, "pre-job.jsonl")
	os.WriteFile(jobFile, []byte("existing content\n"), 0o600)

	meta := CLIJobMeta{
		JID:      "pre-job",
		SproutID: "sprout-pre",
		UserKey:  "UTEST",
	}

	// Should not overwrite existing JSONL.
	if err := store.RecordJobStart(meta); err != nil {
		t.Fatal(err)
	}

	content, _ := os.ReadFile(jobFile)
	if string(content) != "existing content\n" {
		t.Error("expected existing JSONL content to be preserved")
	}
}

func TestCLIStore_GetJob_WithBadMeta(t *testing.T) {
	dir := t.TempDir()
	store, err := NewCLIStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Create a job with valid JSONL but malformed meta.
	sproutDir := filepath.Join(dir, "sprout-badmeta")
	os.MkdirAll(sproutDir, 0o700)

	step := cook.StepCompletion{
		ID:               "s1",
		CompletionStatus: cook.StepCompleted,
		Started:          time.Now(),
		Duration:         time.Second,
	}
	b, _ := json.Marshal(step)
	os.WriteFile(filepath.Join(sproutDir, "bad-meta-job.jsonl"), append(b, '\n'), 0o600)
	os.WriteFile(filepath.Join(sproutDir, "bad-meta-job.meta.json"), []byte("not json"), 0o600)

	summary, meta, err := store.GetJob("bad-meta-job")
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if summary == nil {
		t.Fatal("expected non-nil summary")
	}
	if meta != nil {
		t.Error("expected nil meta for malformed meta file")
	}
}

func TestCLIStore_ListJobs_SortOrder(t *testing.T) {
	dir := t.TempDir()
	store, err := NewCLIStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Truncate(time.Second)

	// Create jobs with different start times.
	for i, offset := range []time.Duration{0, 10 * time.Second, 5 * time.Second} {
		jid := "sort-job-" + string(rune('a'+i))
		meta := CLIJobMeta{JID: jid, SproutID: "sprout-sort", UserKey: "U1", CreatedAt: time.Now()}
		store.RecordJobStart(meta)
		step := cook.StepCompletion{
			ID:               cook.StepID("s1"),
			CompletionStatus: cook.StepCompleted,
			Started:          now.Add(offset),
			Duration:         time.Second,
		}
		store.AppendStep("sprout-sort", jid, step)
	}

	jobs, err := store.ListJobs(0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 3 {
		t.Fatalf("expected 3, got %d", len(jobs))
	}
	// Most recent first: sort-job-b (10s), sort-job-c (5s), sort-job-a (0s).
	if jobs[0].JID != "sort-job-b" {
		t.Errorf("expected sort-job-b first, got %s", jobs[0].JID)
	}
}
