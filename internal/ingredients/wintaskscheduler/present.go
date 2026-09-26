//go:build windows

package wintaskscheduler

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients/winexec"
)

// ErrTaskNotFound is returned by taskBackend.Load when no task (or no
// containing folder) exists at the given path.
var ErrTaskNotFound = errors.New("wintaskscheduler: task not found")

// Task Scheduler trigger type constants (TASK_TRIGGER_TYPE2 in
// taskschd.idl), used both to validate/normalize the trigger_type
// param and, in com.go, as the argument to ITriggerCollection.Create.
const (
	triggerOnce   = 1 // TASK_TRIGGER_TIME
	triggerDaily  = 2 // TASK_TRIGGER_DAILY
	triggerWeekly = 3 // TASK_TRIGGER_WEEKLY
	triggerIdle   = 6 // TASK_TRIGGER_IDLE
	triggerBoot   = 8 // TASK_TRIGGER_BOOT
	triggerLogon  = 9 // TASK_TRIGGER_LOGON
)

var triggerTypes = map[string]int{
	"once":       triggerOnce,
	"daily":      triggerDaily,
	"weekly":     triggerWeekly,
	"on_idle":    triggerIdle,
	"on_startup": triggerBoot,
	"on_logon":   triggerLogon,
}

func triggerTypeName(n int) string {
	for name, v := range triggerTypes {
		if v == n {
			return name
		}
	}
	return ""
}

var runLevels = map[string]bool{"limited": true, "highest": true}

// dayBits maps a weekly trigger's days_of_week names to the bitmask
// IWeeklyTrigger.DaysOfWeek expects (TASK_WEEKDAY: Sunday=0x1 through
// Saturday=0x40).
var dayBits = map[string]int{
	"sunday":    1,
	"monday":    2,
	"tuesday":   4,
	"wednesday": 8,
	"thursday":  16,
	"friday":    32,
	"saturday":  64,
}

func daysOfWeekMask(days []string) int {
	mask := 0
	for _, d := range days {
		mask |= dayBits[d]
	}
	return mask
}

func maskToDaysOfWeek(mask int) []string {
	days := []string{}
	for name, bit := range dayBits {
		if mask&bit != 0 {
			days = append(days, name)
		}
	}
	sort.Strings(days)
	return days
}

// taskState is the desired or observed state of a scheduled task's
// definition. It intentionally excludes the run-as password: the Task
// Scheduler API has no way to read a stored password back out, so it
// can never be part of an observed/desired comparison -- see present().
type taskState struct {
	Command       string
	Arguments     string
	WorkingDir    string
	Description   string
	Enabled       bool
	Hidden        bool
	RunLevel      string
	UserName      string
	TriggerType   string
	StartBoundary string
	DaysInterval  int
	WeeksInterval int
	DaysOfWeek    []string
}

// Equal reports whether a and b describe the same task. Path-shaped and
// account fields are compared case-insensitively and trimmed, matching
// the normalization Task Scheduler is known to apply on save.
func (a taskState) Equal(b taskState) bool {
	if len(a.DaysOfWeek) != len(b.DaysOfWeek) {
		return false
	}
	for i := range a.DaysOfWeek {
		if a.DaysOfWeek[i] != b.DaysOfWeek[i] {
			return false
		}
	}
	return strings.EqualFold(strings.TrimSpace(a.Command), strings.TrimSpace(b.Command)) &&
		a.Arguments == b.Arguments &&
		strings.EqualFold(strings.TrimSpace(a.WorkingDir), strings.TrimSpace(b.WorkingDir)) &&
		a.Description == b.Description &&
		a.Enabled == b.Enabled &&
		a.Hidden == b.Hidden &&
		a.RunLevel == b.RunLevel &&
		strings.EqualFold(a.UserName, b.UserName) &&
		a.TriggerType == b.TriggerType &&
		a.StartBoundary == b.StartBoundary &&
		a.DaysInterval == b.DaysInterval &&
		a.WeeksInterval == b.WeeksInterval
}

// taskBackend abstracts the COM-backed Task Scheduler calls this
// ingredient needs, so tests can substitute an in-memory fake instead
// of touching a real Windows Task Scheduler service and COM apartment.
type taskBackend interface {
	// Load reads the current definition of the task at path. It returns
	// ErrTaskNotFound if no task (or containing folder) exists there.
	Load(path string) (taskState, error)
	// Save creates or updates the task at path to match state.
	// userPassword is supplied separately from taskState since it can
	// never be read back for comparison (see the taskState doc comment).
	Save(path string, state taskState, userPassword string) error
	// Delete removes the task at path. It is a no-op if the task (or its
	// containing folder) is already absent.
	Delete(path string) error
}

// backend is replaceable in tests.
var backend taskBackend = oleTaskBackend{}

func intParamOr(params map[string]interface{}, key string, def int) int {
	v, ok := params[key]
	if !ok {
		return def
	}
	switch vt := v.(type) {
	case float64:
		return int(vt)
	case int:
		return vt
	case string:
		if n, err := strconv.Atoi(vt); err == nil {
			return n
		}
	}
	return def
}

func parseTriggerType(params map[string]interface{}) (string, error) {
	raw, ok := winexec.StringParam(params, "trigger_type")
	if !ok || raw == "" {
		return "", fmt.Errorf("%w: trigger_type is required", ErrInvalidTriggerType)
	}
	lower := strings.ToLower(raw)
	if _, ok := triggerTypes[lower]; !ok {
		return "", fmt.Errorf("%w: %q", ErrInvalidTriggerType, raw)
	}
	return lower, nil
}

func parseRunLevel(params map[string]interface{}) (string, error) {
	raw, ok := winexec.StringParam(params, "run_level")
	if !ok || raw == "" {
		return "limited", nil
	}
	lower := strings.ToLower(raw)
	if !runLevels[lower] {
		return "", fmt.Errorf("%w: %q", ErrInvalidRunLevel, raw)
	}
	return lower, nil
}

func parseStartBoundary(params map[string]interface{}) (string, error) {
	date, _ := winexec.StringParam(params, "start_date")
	tm, _ := winexec.StringParam(params, "start_time")
	if date == "" || tm == "" {
		return "", ErrMissingStartTime
	}
	t, err := time.Parse("2006-01-02 15:04", date+" "+tm)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidStartTime, err)
	}
	return t.Format("2006-01-02T15:04:05"), nil
}

func parseDaysOfWeek(params map[string]interface{}) ([]string, error) {
	raw, ok := winexec.StringSliceParam(params, "days_of_week")
	if !ok || len(raw) == 0 {
		return nil, ErrMissingDaysOfWeek
	}
	days := make([]string, 0, len(raw))
	for _, d := range raw {
		lower := strings.ToLower(strings.TrimSpace(d))
		if _, ok := dayBits[lower]; !ok {
			return nil, fmt.Errorf("%w: %q", ErrInvalidDayOfWeek, d)
		}
		days = append(days, lower)
	}
	sort.Strings(days)
	return days, nil
}

// buildDesiredState turns the recipe's params into the taskState
// present() should converge the task toward, plus the run-as password
// (kept out of taskState -- see its doc comment).
func buildDesiredState(params map[string]interface{}) (taskState, string, error) {
	command, _ := winexec.StringParam(params, "command")
	if command == "" {
		return taskState{}, "", ErrMissingCommand
	}
	arguments, _ := winexec.StringParam(params, "arguments")
	workingDir, _ := winexec.StringParam(params, "start_in")
	description, _ := winexec.StringParam(params, "description")
	enabled := winexec.BoolParam(params, "enabled", true)
	hidden := winexec.BoolParam(params, "hidden", false)

	runLevel, err := parseRunLevel(params)
	if err != nil {
		return taskState{}, "", err
	}

	userName, _ := winexec.StringParam(params, "user_name")
	password, _ := winexec.StringParam(params, "password")

	triggerType, err := parseTriggerType(params)
	if err != nil {
		return taskState{}, "", err
	}

	state := taskState{
		Command:     command,
		Arguments:   arguments,
		WorkingDir:  workingDir,
		Description: description,
		Enabled:     enabled,
		Hidden:      hidden,
		RunLevel:    runLevel,
		UserName:    userName,
		TriggerType: triggerType,
	}

	switch triggerType {
	case "once":
		if state.StartBoundary, err = parseStartBoundary(params); err != nil {
			return taskState{}, "", err
		}
	case "daily":
		if state.StartBoundary, err = parseStartBoundary(params); err != nil {
			return taskState{}, "", err
		}
		state.DaysInterval = intParamOr(params, "days_interval", 1)
	case "weekly":
		if state.StartBoundary, err = parseStartBoundary(params); err != nil {
			return taskState{}, "", err
		}
		state.WeeksInterval = intParamOr(params, "weeks_interval", 1)
		if state.DaysOfWeek, err = parseDaysOfWeek(params); err != nil {
			return taskState{}, "", err
		}
	}

	return state, password, nil
}

func (t Task) present(_ context.Context, test bool) (cook.Result, error) {
	name, _ := winexec.StringParam(t.params, "name")
	desired, password, err := buildDesiredState(t.params)
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}

	current, loadErr := backend.Load(name)
	exists := true
	if loadErr != nil {
		if errors.Is(loadErr, ErrTaskNotFound) {
			exists = false
		} else {
			return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, loadErr
		}
	}

	// A supplied password can never be verified against what's stored
	// (the Task Scheduler API doesn't expose it back), so treat "password
	// given" as always requiring a rewrite rather than silently reporting
	// no-change on a field that can't actually be compared.
	if exists && password == "" && current.Equal(desired) {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{
			cook.Snprintf("task %q already matches the desired state", name),
		}}, nil
	}

	if test {
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
			cook.Snprintf("task %q would be created or updated", name),
		}}, nil
	}

	if err := backend.Save(name, desired, password); err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
		cook.Snprintf("task %q has been created or updated", name),
	}}, nil
}
