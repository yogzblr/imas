package cook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/pki"
)

// syncHarness stubs SyncStagedRecipe's download and cook, and points the
// handled-jobs file and clock at test values.
type syncHarness struct {
	mu     sync.Mutex
	staged *RecipeEnvelope // nil: nothing staged
	cooked []string
	now    time.Time
	// duringFetch, if set, runs inside the download, before it returns.
	duringFetch func()
}

func newSyncHarness(t *testing.T) *syncHarness {
	t.Helper()
	h := &syncHarness{now: time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)}
	oldFile, oldAge := config.SproutHandledJobsFile, config.StagedRecipeMaxAge
	config.SproutHandledJobsFile = filepath.Join(t.TempDir(), "handled-jobs")
	config.StagedRecipeMaxAge = 0
	oldFetch, oldCook, oldClock := fetchStaged, cookPulled, syncClock
	fetchStaged = func(context.Context) (RecipeEnvelope, error) {
		if h.duringFetch != nil {
			h.duringFetch()
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.staged == nil {
			return RecipeEnvelope{}, fmt.Errorf("%w: test", pki.ErrFarmerFileNotFound)
		}
		return *h.staged, nil
	}
	cookPulled = func(env RecipeEnvelope) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.cooked = append(h.cooked, env.JobID)
		return nil
	}
	syncClock = func() time.Time { return h.now }
	t.Cleanup(func() {
		config.SproutHandledJobsFile, config.StagedRecipeMaxAge = oldFile, oldAge
		fetchStaged, cookPulled, syncClock = oldFetch, oldCook, oldClock
	})
	return h
}

// stage makes jobID, dispatched age ago, the staged recipe.
func (h *syncHarness) stage(jobID string, age time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.staged = &RecipeEnvelope{JobID: jobID, DispatchedAt: h.now.Add(-age)}
}

func (h *syncHarness) cookedJobs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.cooked...)
}

func mustSync(t *testing.T, want SyncOutcome) {
	t.Helper()
	got, err := SyncStagedRecipe(t.Context(), SyncOnStartup)
	if err != nil {
		t.Fatalf("SyncStagedRecipe: %v", err)
	}
	if got != want {
		t.Fatalf("SyncStagedRecipe = %q, want %q", got, want)
	}
}

func TestSyncStagedRecipe_NothingStaged(t *testing.T) {
	h := newSyncHarness(t)
	mustSync(t, SyncNothingStaged)
	if len(h.cookedJobs()) != 0 {
		t.Error("cooked something with nothing staged")
	}
}

// A recent job the sprout never saw is cooked, once.
func TestSyncStagedRecipe_CooksMissedJobOnce(t *testing.T) {
	h := newSyncHarness(t)
	h.stage("job-a", 10*time.Minute)
	mustSync(t, SyncCooked)
	mustSync(t, SyncAlreadyHandled)
	if got := h.cookedJobs(); len(got) != 1 || got[0] != "job-a" {
		t.Errorf("cooked = %v, want [job-a]", got)
	}
}

// A job the sprout received by push is not cooked again from its staged
// copy, even after later pushes that were never staged (self updates).
func TestSyncStagedRecipe_SkipsPushedJob(t *testing.T) {
	h := newSyncHarness(t)
	h.stage("job-a", time.Minute)
	NotePushedEnvelope("job-a")
	NotePushedEnvelope("self-update-1")
	NotePushedEnvelope("self-update-2")
	mustSync(t, SyncAlreadyHandled)
	if len(h.cookedJobs()) != 0 {
		t.Error("re-cooked a pushed job")
	}
}

// Handled jobs survive a restart: they're read back from disk.
func TestSyncStagedRecipe_HandledJobsPersist(t *testing.T) {
	h := newSyncHarness(t)
	h.stage("job-a", time.Minute)
	NotePushedEnvelope("job-a")
	b, err := os.ReadFile(config.SproutHandledJobsFile)
	if err != nil || strings.TrimSpace(string(b)) != "job-a" {
		t.Fatalf("handled jobs file = %q, %v; want job-a", b, err)
	}
	mustSync(t, SyncAlreadyHandled)
}

func TestSyncStagedRecipe_MaxAge(t *testing.T) {
	for name, tc := range map[string]struct {
		setting, age time.Duration
		want         SyncOutcome
	}{
		"default, recent":       {0, 59 * time.Minute, SyncCooked},
		"default, too old":      {0, 61 * time.Minute, SyncTooOld},
		"configured, recent":    {10 * time.Minute, 9 * time.Minute, SyncCooked},
		"configured, too old":   {10 * time.Minute, 11 * time.Minute, SyncTooOld},
		"dispatched in future":  {0, -5 * time.Minute, SyncCooked},
		"negative setting = 1h": {-time.Minute, 30 * time.Minute, SyncCooked},
	} {
		t.Run(name, func(t *testing.T) {
			h := newSyncHarness(t)
			config.StagedRecipeMaxAge = tc.setting
			h.stage("job-a", tc.age)
			mustSync(t, tc.want)
			if cooked := len(h.cookedJobs()) == 1; cooked != (tc.want == SyncCooked) {
				t.Errorf("cooked = %v, want %v", cooked, tc.want == SyncCooked)
			}
			// Skipped or not, it's never considered again.
			mustSync(t, SyncAlreadyHandled)
		})
	}
}

// A staged recipe from a farmer that doesn't stamp DispatchedAt has no
// known age, so it is not cooked.
func TestSyncStagedRecipe_Undated(t *testing.T) {
	h := newSyncHarness(t)
	h.staged = &RecipeEnvelope{JobID: "job-a"}
	mustSync(t, SyncUndated)
	if len(h.cookedJobs()) != 0 {
		t.Error("cooked an undated recipe")
	}
}

// A push landing while the staged copy is being fetched wins: the pulled
// copy is the same job or an older one, and is dropped.
func TestSyncStagedRecipe_PushDuringFetchWins(t *testing.T) {
	h := newSyncHarness(t)
	h.stage("job-old", time.Minute)
	h.duringFetch = func() { NotePushedEnvelope("job-new") }
	mustSync(t, SyncPushRaced)
	if len(h.cookedJobs()) != 0 {
		t.Error("cooked a pull that raced a push")
	}
}

// Concurrent triggers (startup, reconnect, nudge at once) cook a job once.
func TestSyncStagedRecipe_ConcurrentTriggersCookOnce(t *testing.T) {
	h := newSyncHarness(t)
	h.stage("job-a", time.Minute)
	var wg sync.WaitGroup
	for _, trig := range []SyncTrigger{SyncOnStartup, SyncOnReconnect, SyncOnNudge, SyncOnNudge} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := SyncStagedRecipe(context.Background(), trig); err != nil {
				t.Errorf("SyncStagedRecipe(%s): %v", trig, err)
			}
		}()
	}
	wg.Wait()
	if got := h.cookedJobs(); len(got) != 1 {
		t.Errorf("cooked = %v, want job-a once", got)
	}
}

func TestSyncStagedRecipe_FetchErrorReturned(t *testing.T) {
	h := newSyncHarness(t)
	boom := errors.New("boom")
	fetchStaged = func(context.Context) (RecipeEnvelope, error) { return RecipeEnvelope{}, boom }
	if _, err := SyncStagedRecipe(t.Context(), SyncOnReconnect); !errors.Is(err, boom) {
		t.Fatalf("SyncStagedRecipe = %v, want the fetch error", err)
	}
	if len(h.cookedJobs()) != 0 {
		t.Error("cooked after a failed fetch")
	}
}

// If the job can't be recorded as handled it isn't cooked, since nothing
// would stop a later pull from cooking it again.
func TestSyncStagedRecipe_UnrecordableJobNotCooked(t *testing.T) {
	h := newSyncHarness(t)
	h.stage("job-a", time.Minute)
	notADir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notADir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	config.SproutHandledJobsFile = filepath.Join(notADir, "handled-jobs")
	if _, err := SyncStagedRecipe(t.Context(), SyncOnStartup); err == nil {
		t.Fatal("SyncStagedRecipe succeeded without being able to record the job")
	}
	if len(h.cookedJobs()) != 0 {
		t.Error("cooked a job it couldn't record")
	}
}

func TestRecordHandledJob_KeepsNewest(t *testing.T) {
	newSyncHarness(t)
	for i := range maxHandledJobs + 10 {
		NotePushedEnvelope(fmt.Sprintf("job-%d", i))
	}
	ids, err := loadHandledJobs()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != maxHandledJobs || ids[0] != "job-10" || ids[len(ids)-1] != fmt.Sprintf("job-%d", maxHandledJobs+9) {
		t.Errorf("kept %d jobs, %s..%s; want the newest %d", len(ids), ids[0], ids[len(ids)-1], maxHandledJobs)
	}
	handledMu.Lock()
	err = recordHandledJob("bad\nid")
	handledMu.Unlock()
	if err == nil {
		t.Error("recorded a job ID containing a newline")
	}
}

func TestNudgeSprout(t *testing.T) {
	nc, cleanup := startCookTestNATS(t)
	defer cleanup()

	if err := NudgeSprout(testTenantID, "web-01"); err == nil {
		t.Error("NudgeSprout succeeded with no sprout listening")
	}

	sub, err := nc.Subscribe(NudgeSubject("web-01"), func(m *nats.Msg) {
		b, _ := json.Marshal(Ack{Acknowledged: true})
		m.Respond(b)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Unsubscribe()
	if err := NudgeSprout(testTenantID, "web-01"); err != nil {
		t.Errorf("NudgeSprout: %v", err)
	}
	if err := NudgeSprout("t_unknown", "web-01"); err == nil {
		t.Error("NudgeSprout succeeded for a tenant with no connection")
	}
}

// Farmer stamps every dispatch with its time, which the staged copy
// carries to the sprout.
func TestDispatchStampsDispatchedAt(t *testing.T) {
	env := RecipeEnvelope{JobID: "j", DispatchedAt: time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"dispatched_at":"2026-09-26T12:00:00Z"`) {
		t.Errorf("envelope JSON %s has no dispatched_at", b)
	}
	b, _ = json.Marshal(RecipeEnvelope{JobID: "j"})
	if strings.Contains(string(b), "dispatched_at") {
		t.Errorf("zero DispatchedAt should be omitted: %s", b)
	}
}
