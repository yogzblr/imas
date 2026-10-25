package cook

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yogzblr/imas/internal/config"
)

// panickingCooker panics in Apply when panics is set, like an ingredient
// writing to a nil map; otherwise it succeeds.
type panickingCooker struct {
	mockRecipeCooker
	panics  bool
	applied *atomic.Int32
	counts  map[string]int // never made: Apply writes to a nil map
}

func (p *panickingCooker) Apply(ctx context.Context) (Result, error) {
	if p.panics {
		p.counts["boom"]++
	}
	p.applied.Add(1)
	return Result{Succeeded: true}, nil
}

func TestRunStepRecoversAPanic(t *testing.T) {
	var applied atomic.Int32
	step := Step{ID: "boom", Ingredient: "cmd", Method: "run"}
	res, err := runStep(context.Background(), &panickingCooker{panics: true, applied: &applied}, step, false)
	var sp *StepPanicError
	if !res.Failed || res.Succeeded || !errors.As(err, &sp) {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	for _, want := range []string{"step boom: cmd.run (apply) panicked: assignment to entry in nil map", "(*panickingCooker).Apply"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	if strings.Contains(sp.Stack, "runtime/debug.Stack") || strings.Contains(sp.Stack, "RecoverStepPanic") {
		t.Errorf("stack not trimmed:\n%s", sp.Stack)
	}

	// Test mode calls Test, which does not panic here.
	if res, err := runStep(context.Background(), &panickingCooker{panics: true, applied: &applied}, step, true); err != nil || res.Failed {
		t.Errorf("test mode: res=%+v err=%v", res, err)
	}
}

func TestTrimPanicStack(t *testing.T) {
	stack := "goroutine 1 [running]:\nruntime/debug.Stack()\n\t/go/stack.go:26\npanic({0x1, 0x2})\n\t/go/panic.go:785\nmain.f()\n\t/x/f.go:3\n"
	if got := trimPanicStack([]byte(stack)); got != "main.f()\n\t/x/f.go:3" {
		t.Errorf("got %q", got)
	}
	var long strings.Builder
	long.WriteString("goroutine 1 [running]:\npanic(0x1)\n\t/go/panic.go:1\n")
	for i := 0; i < 20; i++ {
		long.WriteString("f()\n\t/x.go:1\n")
	}
	if got := trimPanicStack([]byte(long.String())); strings.Count(got, "f()") != stepPanicFrames || !strings.HasSuffix(got, "\t...") {
		t.Errorf("got %q", got)
	}
}

// A step whose ingredient panics fails its job with the panic in its error,
// the sprout carries on, and a later step of the same ingredient runs, as
// does a panicking on_exit step's sibling.
func TestCookRecipeEnvelopeRecoversAPanickingStep(t *testing.T) {
	_, cleanup := startCookTestNATS(t)
	defer cleanup()

	tmpDir := t.TempDir()
	oldDir := config.JobLogDir
	config.JobLogDir = tmpDir
	defer func() { config.JobLogDir = oldDir }()

	origCooker := NewRecipeCooker
	defer func() { NewRecipeCooker = origCooker }()
	oldSproutID := config.SproutID
	config.SproutID = "panic-sprout"
	defer func() { config.SproutID = oldSproutID }()

	var applied atomic.Int32
	NewRecipeCooker = func(id StepID, ingredient Ingredient, method string, params map[string]interface{}) (RecipeCooker, error) {
		return &panickingCooker{panics: strings.HasPrefix(string(id), "boom"), applied: &applied}, nil
	}

	envelope := RecipeEnvelope{
		JobID: "panic-job",
		Steps: []Step{
			{
				ID: "boom", Ingredient: "cmd", Method: "run",
				OnExit: []Step{
					{ID: "boom-cleanup", Ingredient: "cmd", Method: "run"},
					{ID: "cleanup", Ingredient: "cmd", Method: "run"},
				},
			},
			{
				ID: "after", Ingredient: "cmd", Method: "run",
				Requisites: RequisiteSet{{Condition: OnFail, StepIDs: []StepID{"boom"}}},
			},
		},
	}
	if err := CookRecipeEnvelope(envelope); err != nil {
		t.Fatalf("CookRecipeEnvelope: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(tmpDir, "panic-job.jsonl"))
	if err != nil {
		t.Fatalf("read job log: %v", err)
	}
	got := map[StepID]StepCompletion{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var c StepCompletion
		if json.Unmarshal([]byte(line), &c) == nil {
			got[c.ID] = c
		}
	}
	boom, ok := got["boom"]
	if !ok || boom.CompletionStatus != StepFailed || boom.Error == nil ||
		!strings.Contains(boom.Error.Error(), "step boom: cmd.run (apply) panicked: assignment to entry in nil map") {
		t.Fatalf("boom = %+v (found %v)", boom, ok)
	}
	if after, ok := got["after"]; !ok || after.CompletionStatus != StepCompleted {
		t.Fatalf("after = %+v (found %v)", after, ok)
	}
	// "cleanup" (on_exit) and "after" applied.
	if n := applied.Load(); n != 2 {
		t.Errorf("applied %d steps, want 2", n)
	}
}
