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
