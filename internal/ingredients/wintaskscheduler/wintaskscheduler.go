//go:build windows

// Package wintaskscheduler implements imas's win_task ingredient:
// declarative management of Windows Task Scheduler tasks (create,
// update, delete), matching the relevant surface of Salt's win_task
// state module. It drives the Task Scheduler 2.0 COM API
// (Schedule.Service -> ITaskService/ITaskFolder/ITaskDefinition) the
// same way Salt's Python implementation drives it through
// win32com.client.Dispatch("Schedule.Service"). See G.6 in
// docs/design/imas-windows-parity-addendum.md; the COM lifecycle
// pattern (single-threaded apartment bound to a locked OS thread,
// paired CoInitializeEx/CoUninitialize, explicit Release of every
// acquired IDispatch) follows the one the winshortcut ingredient
// established.
//
// FLAG FOR SECURITY REVIEW: this package cross-compiles (GOOS=windows)
// cleanly but has not been exercised against a real Windows Task
// Scheduler; treat it as ready for review, not verified. Two things
// beyond the general "written, not verified" caveat are worth a
// deliberate look: (1) the COM reference-counting discipline in
// com.go -- a VARIANT holding VT_DISPATCH and the *ole.IDispatch its
// ToIDispatch() extracts are the SAME underlying COM reference, so
// releasing both (once via VARIANT.Clear(), once via
// IDispatch.Release()) over-releases the object; see the
// oleTaskBackend doc comment in com.go for the chokepoint this
// package uses to keep that from happening at every call site. (2)
// present() cannot read a task's stored password back from the API to
// compare it against the recipe's, so it always rewrites the task
// whenever a password parameter is supplied rather than silently
// treating an unverifiable field as unchanged -- see present.go.
package wintaskscheduler

import (
	"context"
	"errors"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
	"github.com/yogzblr/imas/internal/ingredients/winexec"
)

const ingredientName = "win_task"

const (
	methodPresent = "present"
	methodAbsent  = "absent"
)

var (
	ErrTaskMethodUndefined = errors.New("wintaskscheduler method undefined")
	ErrMissingCommand      = errors.New("wintaskscheduler present requires a command")
	ErrInvalidTriggerType  = errors.New("invalid trigger_type")
	ErrInvalidRunLevel     = errors.New("invalid run_level")
	ErrMissingStartTime    = errors.New("start_date and start_time are required for this trigger_type")
	ErrInvalidStartTime    = errors.New("invalid start_date/start_time")
	ErrMissingDaysOfWeek   = errors.New("days_of_week is required for a weekly trigger_type")
	ErrInvalidDayOfWeek    = errors.New("invalid day in days_of_week")
)

// Compile-time interface check.
var _ cook.RecipeCooker = Task{}

// Task is a imas ingredient for managing Windows Task Scheduler tasks.
// "name" is always the full Task Scheduler path, e.g. `\imas\backup`.
type Task struct {
	id     string
	method string
	params map[string]interface{}
}

func (t Task) Parse(id, method string, params map[string]interface{}) (cook.RecipeCooker, error) {
	if params == nil {
		params = map[string]interface{}{}
	}
	parsed := Task{id: id, method: method, params: params}
	if err := parsed.validate(); err != nil {
		return nil, err
	}
	return parsed, nil
}

func (t Task) validate() error {
	set, err := t.PropertiesForMethod(t.method)
	if err != nil {
		return err
	}
	propSet, err := ingredients.PropMapToPropSet(set)
	if err != nil {
		return err
	}
	for _, v := range propSet {
		if !v.IsReq {
			continue
		}
		val, ok := winexec.StringParam(t.params, v.Key)
		if !ok || val == "" {
			if v.Key == "name" {
				return ingredients.ErrMissingName
			}
			return fmt.Errorf("missing required property %s", v.Key)
		}
	}
	if t.method == methodPresent {
		if _, _, err := buildDesiredState(t.params); err != nil {
			return err
		}
	}
	return nil
}

func (t Task) dispatch(ctx context.Context, test bool) (cook.Result, error) {
	switch t.method {
	case methodPresent:
		return t.present(ctx, test)
	case methodAbsent:
		return t.absent(ctx, test)
	default:
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil},
			errors.Join(ErrTaskMethodUndefined, fmt.Errorf("method %s undefined", t.method))
	}
}

func (t Task) Test(ctx context.Context) (cook.Result, error) {
	return t.dispatch(ctx, true)
}

func (t Task) Apply(ctx context.Context) (cook.Result, error) {
	return t.dispatch(ctx, false)
}

func (t Task) PropertiesForMethod(method string) (map[string]string, error) {
	switch method {
	case methodPresent:
		return ingredients.MethodPropsSet{
			ingredients.MethodProps{Key: "name", Type: "string", IsReq: true, Description: `full Task Scheduler path, e.g. \imas\backup`},
			ingredients.MethodProps{Key: "command", Type: "string", IsReq: true, Description: "executable the task runs"},
			ingredients.MethodProps{Key: "trigger_type", Type: "string", IsReq: true, Description: "one of once, daily, weekly, on_logon, on_startup, on_idle"},
			ingredients.MethodProps{Key: "arguments", Type: "string", IsReq: false, Description: "command-line arguments passed to command"},
			ingredients.MethodProps{Key: "start_in", Type: "string", IsReq: false, Description: "working directory the command is launched from"},
			ingredients.MethodProps{Key: "description", Type: "string", IsReq: false, Description: "task description"},
			ingredients.MethodProps{Key: "enabled", Type: "bool", IsReq: false, Description: "whether the task is enabled (default true)"},
			ingredients.MethodProps{Key: "hidden", Type: "bool", IsReq: false, Description: "whether the task is hidden (default false)"},
			ingredients.MethodProps{Key: "run_level", Type: "string", IsReq: false, Description: "limited or highest (default limited)"},
			ingredients.MethodProps{Key: "user_name", Type: "string", IsReq: false, Description: "account the task runs as (default: SYSTEM)"},
			ingredients.MethodProps{Key: "password", Type: "string", IsReq: false, Description: "password for user_name; supplying it always forces a rewrite, since it can't be read back to compare"},
			ingredients.MethodProps{Key: "start_date", Type: "string", IsReq: false, Description: "YYYY-MM-DD, required for trigger_type once/daily/weekly"},
			ingredients.MethodProps{Key: "start_time", Type: "string", IsReq: false, Description: "HH:MM (24h), required for trigger_type once/daily/weekly"},
			ingredients.MethodProps{Key: "days_interval", Type: "string", IsReq: false, Description: "daily trigger repeat interval in days (default 1)"},
			ingredients.MethodProps{Key: "weeks_interval", Type: "string", IsReq: false, Description: "weekly trigger repeat interval in weeks (default 1)"},
			ingredients.MethodProps{Key: "days_of_week", Type: "[]string", IsReq: false, Description: "required for trigger_type weekly, e.g. [monday, wednesday]"},
		}.ToMap(), nil
	case methodAbsent:
		return ingredients.MethodPropsSet{
			ingredients.MethodProps{Key: "name", Type: "string", IsReq: true, Description: `full Task Scheduler path, e.g. \imas\backup`},
		}.ToMap(), nil
	default:
		return nil, errors.Join(ErrTaskMethodUndefined, fmt.Errorf("method %s undefined", method))
	}
}

func (t Task) Methods() (string, []string) {
	return ingredientName, []string{methodAbsent, methodPresent}
}

func (t Task) Properties() (map[string]interface{}, error) {
	return t.params, nil
}

func init() {
	ingredients.RegisterAllMethods(Task{})
}
