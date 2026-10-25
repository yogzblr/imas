package ingredients

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/cook"
)

// slowCooker blocks in Test/Apply until its context ends or block closes,
// like a COM call or a hung child process.
type slowCooker struct {
	mockCooker
	block     chan struct{}
	ignoreCtx bool
	res       cook.Result
}

func (s *slowCooker) wait(ctx context.Context) (cook.Result, error) {
	if s.ignoreCtx {
		<-s.block
		return s.res, nil
	}
	select {
	case <-ctx.Done():
		return cook.Result{Failed: true}, ctx.Err()
	case <-s.block:
		return s.res, nil
	}
}

func (s *slowCooker) Test(ctx context.Context) (cook.Result, error)  { return s.wait(ctx) }
func (s *slowCooker) Apply(ctx context.Context) (cook.Result, error) { return s.wait(ctx) }
func (s *slowCooker) Parse(string, string, map[string]interface{}) (cook.RecipeCooker, error) {
	return s, nil
}

func TestWindowsStepBound(t *testing.T) {
	t.Setenv(WindowsStepTimeoutEnv, "")
	origOS := goos
	t.Cleanup(func() { goos = origOS })

	goos = "linux"
	tests := []struct {
		ing    cook.Ingredient
		params map[string]interface{}
		want   time.Duration
		ok     bool
	}{
		{"win_shortcut", nil, DefaultWindowsStepTimeout, true},
		{"win_task", map[string]interface{}{}, DefaultWindowsStepTimeout, true},
		{"win_certutil", map[string]interface{}{"timeout": "5s"}, DefaultWindowsStepTimeout, true},
		{"win_certutil", map[string]interface{}{"timeout": "2m"}, 6*time.Minute + 30*time.Second, true},
		{"win_psget", nil, 15 * time.Minute, true},
		{"win_update", nil, 0, false},
		{"service", nil, 0, false}, // not on Linux
		{"cmd", nil, 0, false},
	}
	for _, tt := range tests {
		got, ok := windowsStepBound(tt.ing, tt.params)
		if got != tt.want || ok != tt.ok {
			t.Errorf("windowsStepBound(%s, %v) = %v, %v; want %v, %v", tt.ing, tt.params, got, ok, tt.want, tt.ok)
		}
	}

	goos = "windows"
	if got, ok := windowsStepBound("service", nil); !ok || got != 3*time.Minute {
		t.Errorf("service on Windows: %v, %v", got, ok)
	}
	if got, ok := windowsStepBound("user", nil); !ok || got != DefaultWindowsStepTimeout {
		t.Errorf("user on Windows: %v, %v", got, ok)
	}
	if _, ok := windowsStepBound("cmd", nil); ok {
		t.Error("cmd is never bounded here: it has its own timeout")
	}

	t.Setenv(WindowsStepTimeoutEnv, "2m")
	if got, _ := windowsStepBound("win_shortcut", nil); got != 2*time.Minute {
		t.Errorf("knob: %v", got)
	}
	if got, _ := windowsStepBound("win_psget", nil); got != 15*time.Minute {
		t.Errorf("the knob must not shorten a long ingredient: %v", got)
	}
	t.Setenv(WindowsStepTimeoutEnv, "0")
	if _, ok := windowsStepBound("win_shortcut", nil); ok {
		t.Error(`"0" turns the bound off`)
	}
	t.Setenv(WindowsStepTimeoutEnv, "bogus")
	if got, _ := windowsStepBound("win_shortcut", nil); got != DefaultWindowsStepTimeout {
		t.Errorf("a bad knob keeps the default: %v", got)
	}
}

func TestBoundedCookerFailsAtTheBound(t *testing.T) {
	for _, ignore := range []bool{false, true} {
		s := &slowCooker{block: make(chan struct{}), ignoreCtx: ignore}
		b := boundedCooker{RecipeCooker: s, ingredient: "win_shortcut", method: "present", bound: 50 * time.Millisecond}
		start := time.Now()
		res, err := b.Apply(context.Background())
		close(s.block)
		if err == nil || !res.Failed || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("ignoreCtx=%v: res=%+v err=%v", ignore, res, err)
		}
		for _, want := range []string{"win_shortcut.present (apply) did not finish within 50ms", WindowsStepTimeoutEnv} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q lacks %q", err, want)
			}
		}
		if time.Since(start) > 2*time.Second {
			t.Errorf("took %v", time.Since(start))
		}
	}
}

func TestBoundedCookerPassesThroughInTime(t *testing.T) {
	s := &slowCooker{block: make(chan struct{}), res: cook.Result{Succeeded: true, Changed: true}}
	close(s.block)
	b := boundedCooker{RecipeCooker: s, ingredient: "win_task", method: "absent", bound: time.Second}
	res, err := b.Test(context.Background())
	if err != nil || !res.Succeeded || !res.Changed {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestNewRecipeCookerBoundsWindowsSteps(t *testing.T) {
	s := &slowCooker{mockCooker: mockCooker{name: "win_p35test", methods: []string{"present"}}, block: make(chan struct{})}
	close(s.block)
	RegisterAllMethods(s)
	c, err := NewRecipeCooker("id", "win_p35test", "present", map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.(boundedCooker); !ok {
		t.Errorf("got %T, want boundedCooker", c)
	}
}

// A step that honours its context returns ctx.Err() as the bound strikes,
// often before the bound's own select case is chosen: the error still names
// the bound, every time.
func TestBoundedCookerNamesTheBoundWhenTheStepGivesUp(t *testing.T) {
	for i := 0; i < 200; i++ {
		s := &slowCooker{block: make(chan struct{})}
		b := boundedCooker{RecipeCooker: s, ingredient: "win_task", method: "present", bound: time.Millisecond}
		_, err := b.Test(context.Background())
		close(s.block)
		if err == nil || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "did not finish within 1ms") {
			t.Fatalf("run %d: err=%v", i, err)
		}
	}
	// A parent cancellation is not the bound's.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &slowCooker{block: make(chan struct{})}
	_, err := boundedCooker{RecipeCooker: s, ingredient: "win_task", method: "present", bound: time.Minute}.Test(ctx)
	if err == nil || strings.Contains(err.Error(), "did not finish within") {
		t.Errorf("parent cancel: %v", err)
	}
}

// A call abandoned at the bound may still finish its change, so a later
// step of the same ingredient waits for it within its own bound, and fails
// rather than run on top of it (review on #319). Other ingredients do not
// wait.
func TestBoundedCookerFencesAnAbandonedStep(t *testing.T) {
	hung := &slowCooker{block: make(chan struct{}), ignoreCtx: true}
	if _, err := (boundedCooker{RecipeCooker: hung, ingredient: "win_fence", method: "present", bound: 20 * time.Millisecond}).Apply(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "may still complete its change (later win_fence steps wait for it)") {
		t.Fatalf("abandoned step: %v", err)
	}

	quick := &slowCooker{block: make(chan struct{}), res: cook.Result{Succeeded: true}}
	close(quick.block)
	res, err := boundedCooker{RecipeCooker: quick, ingredient: "win_fence", method: "absent", bound: 50 * time.Millisecond}.Apply(context.Background())
	if err == nil || !res.Failed || !errors.Is(err, context.DeadlineExceeded) ||
		!strings.Contains(err.Error(), "did not start: an earlier win_fence step abandoned at the Windows step bound is still running") {
		t.Fatalf("step over a running abandoned one: res=%+v err=%v", res, err)
	}
	if res, err := (boundedCooker{RecipeCooker: quick, ingredient: "win_other", method: "absent", bound: time.Second}).Apply(context.Background()); err != nil || !res.Succeeded {
		t.Fatalf("another ingredient waited: res=%+v err=%v", res, err)
	}

	// The abandoned call returns while the next step waits: that step runs.
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(hung.block)
	}()
	res, err = boundedCooker{RecipeCooker: quick, ingredient: "win_fence", method: "absent", bound: 5 * time.Second}.Apply(context.Background())
	if err != nil || !res.Succeeded {
		t.Fatalf("after the abandoned call returned: res=%+v err=%v", res, err)
	}
	abandonedSteps.Lock()
	left := len(abandonedSteps.by)
	abandonedSteps.Unlock()
	if left != 0 {
		t.Errorf("%d fences left", left)
	}
}
