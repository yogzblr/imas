package cook

import (
	"context"
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/yogzblr/imas/internal/log"
)

// A panic in an ingredient's Test or Apply (a nil map, a bad type
// assertion, a COM wrapper bug) used to crash the sprout: the job was never
// completed and its caller waited for its own timeout (#319, review on
// #320). runStep recovers it on the cook path and the step fails with a
// StepPanicError instead; a cooker that runs the step in a goroutine of its
// own (the Windows step bound) recovers there with RecoverStepPanic, since
// no caller can recover a panic in another goroutine.

// stepPanicFrames is how many frames of the panicking goroutine's stack a
// StepPanicError keeps.
const stepPanicFrames = 8

// StepPanicError is the failure of a step whose ingredient panicked.
type StepPanicError struct {
	Step       StepID
	Ingredient Ingredient
	Method     string
	Mode       string // "test" or "apply"
	Value      interface{}
	Stack      string
}

func (e *StepPanicError) Error() string {
	return fmt.Sprintf("step %s: %s.%s (%s) panicked: %v\n%s", e.Step, e.Ingredient, e.Method, e.Mode, e.Value, e.Stack)
}

// RecoverStepPanic turns p, a value recovered by a deferred function in the
// goroutine that panicked, into a step failure, and logs it. Call it from
// that deferred function: the stack it keeps is the caller's goroutine's.
func RecoverStepPanic(id StepID, ingredient Ingredient, method, mode string, p interface{}) (Result, error) {
	err := &StepPanicError{Step: id, Ingredient: ingredient, Method: method, Mode: mode, Value: p, Stack: trimPanicStack(debug.Stack())}
	log.Errorf("%v", err)
	return Result{Failed: true}, err
}

// trimPanicStack keeps the frames below the runtime's panic frame, that is
// the code that panicked and its callers, at most stepPanicFrames of them.
func trimPanicStack(stack []byte) string {
	lines := strings.Split(strings.TrimRight(string(stack), "\n"), "\n")
	start := 1 // the "goroutine N [running]:" line
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.HasPrefix(lines[i], "panic(") {
			start = i + 2 // the frame's function line and its file line
			break
		}
	}
	if start > len(lines) {
		start = len(lines)
	}
	lines = lines[start:]
	if len(lines) > 2*stepPanicFrames {
		lines = append(lines[:2*stepPanicFrames], "\t...")
	}
	return strings.Join(lines, "\n")
}

// runStep runs a step's Test (testMode) or Apply, failing the step instead
// of the sprout when the ingredient panics.
func runStep(ctx context.Context, ingredient RecipeCooker, step Step, testMode bool) (res Result, err error) {
	mode, fn := "apply", ingredient.Apply
	if testMode {
		mode, fn = "test", ingredient.Test
	}
	defer func() {
		if p := recover(); p != nil {
			res, err = RecoverStepPanic(step.ID, step.Ingredient, step.Method, mode, p)
		}
	}()
	return fn(ctx)
}
