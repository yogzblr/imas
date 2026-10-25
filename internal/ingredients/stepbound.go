package ingredients

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/yogzblr/imas/internal/cook"
)

// The bound on a Windows ingredient step (P35, B9). A Windows ingredient
// calls COM objects, the SCM and native tools that can hang; UAT Run 2 on
// rc.21 waited six minutes on a step whose sprout had died, until the
// caller's own token expired. Every step of a win_* ingredient, and on a
// Windows sprout every step of service, user, group, registry and lgpo,
// now fails with a clear error when it has not finished within its bound:
//
//   - DefaultWindowsStepTimeout (60 s), or IMAS_WINDOWS_STEP_TIMEOUT on the
//     sprout (a Go duration; "0" turns the bound off);
//   - longer for the ingredients that install or download by design
//     (windowsStepDefaults; win_update, which searches and installs
//     updates for as long as they take, has none);
//   - and never shorter than three times the step's own "timeout"
//     property plus 30 s (an ingredient runs at most a few calls, each
//     bounded by that property).
//
// The step's context is cancelled at the bound, so a step that runs
// child processes (winexec) kills them; a call that cannot be cancelled
// (an in-process COM call) is abandoned and the step fails anyway.
const (
	WindowsStepTimeoutEnv     = "IMAS_WINDOWS_STEP_TIMEOUT"
	DefaultWindowsStepTimeout = 60 * time.Second
)

// windowsStepDefaults are the bounds of the ingredients whose steps take
// minutes by design; 0 means unbounded. The environment knob does not
// shorten them.
var windowsStepDefaults = map[cook.Ingredient]time.Duration{
	"win_update":        0,
	"service":           3 * time.Minute, // a start or stop waits for the SCM
	"win_psget":         15 * time.Minute,
	"win_servermanager": 30 * time.Minute,
	"win_appx":          15 * time.Minute,
	"win_dsc":           15 * time.Minute,
	"win_iis":           15 * time.Minute,
	"win_smtp_server":   15 * time.Minute,
	"win_snmp":          15 * time.Minute,
}

// windowsOnlyBounded are the cross-platform ingredients bounded on a
// Windows sprout, where they call the SCM, the account and registry APIs.
var windowsOnlyBounded = map[cook.Ingredient]bool{
	"service": true, "user": true, "group": true, "registry": true, "lgpo": true,
}

// goos is runtime.GOOS; tests replace it.
var goos = runtime.GOOS

// windowsStepBound returns the bound for a step of ingredient with params,
// and false when the step is not bounded.
func windowsStepBound(ingredient cook.Ingredient, params map[string]interface{}) (time.Duration, bool) {
	if !strings.HasPrefix(string(ingredient), "win_") && !(goos == "windows" && windowsOnlyBounded[ingredient]) {
		return 0, false
	}
	bound := DefaultWindowsStepTimeout
	if raw := strings.TrimSpace(os.Getenv(WindowsStepTimeoutEnv)); raw != "" {
		d, err := time.ParseDuration(raw)
		if err == nil && d >= 0 {
			bound = d
		}
	}
	if long, ok := windowsStepDefaults[ingredient]; ok {
		if long == 0 {
			return 0, false
		}
		if long > bound || bound == 0 {
			bound = long
		}
	}
	if bound == 0 {
		return 0, false
	}
	if raw, ok := params["timeout"].(string); ok {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 {
			if own := 3*d + 30*time.Second; own > bound {
				bound = own
			}
		}
	}
	return bound, true
}

// boundedCooker runs a step's Test and Apply under its bound.
type boundedCooker struct {
	cook.RecipeCooker
	ingredient cook.Ingredient
	method     string
	bound      time.Duration
}

func (b boundedCooker) Test(ctx context.Context) (cook.Result, error) {
	return b.run(ctx, "test", b.RecipeCooker.Test)
}

func (b boundedCooker) Apply(ctx context.Context) (cook.Result, error) {
	return b.run(ctx, "apply", b.RecipeCooker.Apply)
}

type stepOutcome struct {
	res cook.Result
	err error
}

func (b boundedCooker) run(ctx context.Context, mode string, fn func(context.Context) (cook.Result, error)) (cook.Result, error) {
	bctx, cancel := context.WithTimeout(ctx, b.bound)
	defer cancel()
	done := make(chan stepOutcome, 1)
	go func() {
		res, err := fn(bctx)
		done <- stepOutcome{res, err}
	}()
	boundErr := func() error {
		return fmt.Errorf("%s.%s (%s) did not finish within %s, the Windows step bound (%s; default %s); it was cancelled and abandoned: %w",
			b.ingredient, b.method, mode, b.bound, WindowsStepTimeoutEnv, DefaultWindowsStepTimeout, context.DeadlineExceeded)
	}
	// finished keeps a step's own result, except that a step that gave up
	// because the bound struck (returning its context's error) says so.
	finished := func(o stepOutcome) (cook.Result, error) {
		if errors.Is(o.err, context.DeadlineExceeded) && bctx.Err() != nil && ctx.Err() == nil {
			return o.res, boundErr()
		}
		return o.res, o.err
	}
	select {
	case o := <-done:
		return finished(o)
	case <-bctx.Done():
		// A step that finished as the bound struck keeps its own result.
		select {
		case o := <-done:
			return finished(o)
		default:
		}
		if ctx.Err() != nil {
			return cook.Result{Failed: true}, fmt.Errorf("%s.%s (%s): %w", b.ingredient, b.method, mode, ctx.Err())
		}
		return cook.Result{Failed: true}, boundErr()
	}
}
