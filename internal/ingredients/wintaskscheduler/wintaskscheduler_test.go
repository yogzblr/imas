//go:build windows

package wintaskscheduler

import (
	"context"
	"errors"
	"testing"
)

// fakeBackend is an in-memory stand-in for oleTaskBackend, keyed by
// path, so present()/absent() can be exercised without a real COM
// apartment or Task Scheduler service.
type fakeBackend struct {
	states    map[string]taskState
	loadErr   error
	saveErr   error
	deleteErr error
	saved     []string
	deleted   []string
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{states: map[string]taskState{}}
}

func (f *fakeBackend) Load(path string) (taskState, error) {
	if f.loadErr != nil {
		return taskState{}, f.loadErr
	}
	state, ok := f.states[path]
	if !ok {
		return taskState{}, ErrTaskNotFound
	}
	return state, nil
}

func (f *fakeBackend) Save(path string, state taskState, _ string) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.states[path] = state
	f.saved = append(f.saved, path)
	return nil
}

func (f *fakeBackend) Delete(path string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.states, path)
	f.deleted = append(f.deleted, path)
	return nil
}

func installFakeBackend(t *testing.T) *fakeBackend {
	t.Helper()
	fb := newFakeBackend()
	orig := backend
	backend = fb
	t.Cleanup(func() { backend = orig })
	return fb
}

func newTask(method string, params map[string]interface{}) Task {
	return Task{id: "test-id", method: method, params: params}
}

func baseParams(overrides map[string]interface{}) map[string]interface{} {
	p := map[string]interface{}{
		"name":         `\imas\backup`,
		"command":      `C:\Windows\system32\backup.exe`,
		"trigger_type": "once",
		"start_date":   "2026-01-01",
		"start_time":   "03:00",
	}
	for k, v := range overrides {
		p[k] = v
	}
	return p
}

// --- Methods / PropertiesForMethod ---

func TestTaskMethods(t *testing.T) {
	name, methods := Task{}.Methods()
	if name != ingredientName {
		t.Errorf("name = %q, want %q", name, ingredientName)
	}
	want := map[string]bool{"present": true, "absent": true}
	if len(methods) != len(want) {
		t.Fatalf("methods = %v, want keys of %v", methods, want)
	}
	for _, m := range methods {
		if !want[m] {
			t.Errorf("unexpected method %q", m)
		}
	}
}

// --- Parse / validate ---

func TestParsePresentMissingName(t *testing.T) {
	p := baseParams(nil)
	delete(p, "name")
	_, err := Task{}.Parse("id", methodPresent, p)
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestParsePresentMissingCommand(t *testing.T) {
	p := baseParams(nil)
	delete(p, "command")
	_, err := Task{}.Parse("id", methodPresent, p)
	if err == nil {
		t.Fatal("expected error for missing command")
	}
}

func TestParsePresentInvalidTriggerType(t *testing.T) {
	_, err := Task{}.Parse("id", methodPresent, baseParams(map[string]interface{}{"trigger_type": "sideways"}))
	if !errors.Is(err, ErrInvalidTriggerType) {
		t.Fatalf("err = %v, want ErrInvalidTriggerType", err)
	}
}

func TestParsePresentInvalidRunLevel(t *testing.T) {
	_, err := Task{}.Parse("id", methodPresent, baseParams(map[string]interface{}{"run_level": "godmode"}))
	if !errors.Is(err, ErrInvalidRunLevel) {
		t.Fatalf("err = %v, want ErrInvalidRunLevel", err)
	}
}

func TestParsePresentMissingStartTime(t *testing.T) {
	p := baseParams(nil)
	delete(p, "start_time")
	_, err := Task{}.Parse("id", methodPresent, p)
	if !errors.Is(err, ErrMissingStartTime) {
		t.Fatalf("err = %v, want ErrMissingStartTime", err)
	}
}

func TestParsePresentWeeklyMissingDaysOfWeek(t *testing.T) {
	_, err := Task{}.Parse("id", methodPresent, baseParams(map[string]interface{}{"trigger_type": "weekly"}))
	if !errors.Is(err, ErrMissingDaysOfWeek) {
		t.Fatalf("err = %v, want ErrMissingDaysOfWeek", err)
	}
}

func TestParsePresentWeeklyInvalidDay(t *testing.T) {
	_, err := Task{}.Parse("id", methodPresent, baseParams(map[string]interface{}{
		"trigger_type": "weekly",
		"days_of_week": []string{"funday"},
	}))
	if !errors.Is(err, ErrInvalidDayOfWeek) {
		t.Fatalf("err = %v, want ErrInvalidDayOfWeek", err)
	}
}

func TestParsePresentOnStartupNoStartTimeNeeded(t *testing.T) {
	p := baseParams(map[string]interface{}{"trigger_type": "on_startup"})
	delete(p, "start_date")
	delete(p, "start_time")
	_, err := Task{}.Parse("id", methodPresent, p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParsePresentOK(t *testing.T) {
	_, err := Task{}.Parse("id", methodPresent, baseParams(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseAbsentMissingName(t *testing.T) {
	_, err := Task{}.Parse("id", methodAbsent, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

// --- buildDesiredState ---

func TestBuildDesiredStateWeekly(t *testing.T) {
	state, password, err := buildDesiredState(baseParams(map[string]interface{}{
		"trigger_type":   "weekly",
		"days_of_week":   []string{"Friday", "monday"},
		"weeks_interval": "2",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if password != "" {
		t.Errorf("password = %q, want empty", password)
	}
	if len(state.DaysOfWeek) != 2 || state.DaysOfWeek[0] != "friday" || state.DaysOfWeek[1] != "monday" {
		t.Errorf("DaysOfWeek = %v, want sorted [friday monday]", state.DaysOfWeek)
	}
	if state.WeeksInterval != 2 {
		t.Errorf("WeeksInterval = %d, want 2", state.WeeksInterval)
	}
}

func TestBuildDesiredStateDailyDefaultInterval(t *testing.T) {
	state, _, err := buildDesiredState(baseParams(map[string]interface{}{"trigger_type": "daily"}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.DaysInterval != 1 {
		t.Errorf("DaysInterval = %d, want 1", state.DaysInterval)
	}
}

func TestBuildDesiredStateMissingCommand(t *testing.T) {
	p := baseParams(nil)
	delete(p, "command")
	if _, _, err := buildDesiredState(p); !errors.Is(err, ErrMissingCommand) {
		t.Fatalf("err = %v, want ErrMissingCommand", err)
	}
}

// --- present ---

func TestTaskPresentCreatesWhenAbsent(t *testing.T) {
	fb := installFakeBackend(t)
	s := newTask(methodPresent, baseParams(nil))

	result, err := s.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || !result.Changed {
		t.Fatalf("result = %+v, want succeeded+changed", result)
	}
	if len(fb.saved) != 1 || fb.saved[0] != `\imas\backup` {
		t.Fatalf("saved = %v, want [\\imas\\backup]", fb.saved)
	}
}

func TestTaskPresentTestModeDoesNotSave(t *testing.T) {
	fb := installFakeBackend(t)
	s := newTask(methodPresent, baseParams(nil))

	result, err := s.Test(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || !result.Changed {
		t.Fatalf("result = %+v, want succeeded+changed", result)
	}
	if len(fb.saved) != 0 {
		t.Fatalf("saved = %v, want none in test mode", fb.saved)
	}
}

func TestTaskPresentNoopWhenMatching(t *testing.T) {
	fb := installFakeBackend(t)
	desired, _, err := buildDesiredState(baseParams(nil))
	if err != nil {
		t.Fatalf("buildDesiredState: %v", err)
	}
	fb.states[`\imas\backup`] = desired

	s := newTask(methodPresent, baseParams(nil))
	result, err := s.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Changed {
		t.Fatalf("result = %+v, want succeeded and unchanged", result)
	}
	if len(fb.saved) != 0 {
		t.Fatalf("saved = %v, want none when already matching", fb.saved)
	}
}

func TestTaskPresentUpdatesWhenDiffers(t *testing.T) {
	fb := installFakeBackend(t)
	fb.states[`\imas\backup`] = taskState{Command: `C:\old.exe`, TriggerType: "once", StartBoundary: "2026-01-01T03:00:00", RunLevel: "limited"}

	s := newTask(methodPresent, baseParams(nil))
	result, err := s.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || !result.Changed {
		t.Fatalf("result = %+v, want succeeded+changed", result)
	}
	if fb.states[`\imas\backup`].Command != `C:\Windows\system32\backup.exe` {
		t.Errorf("Command = %q, want updated value", fb.states[`\imas\backup`].Command)
	}
}

func TestTaskPresentPasswordAlwaysForcesRewrite(t *testing.T) {
	fb := installFakeBackend(t)
	desired, _, err := buildDesiredState(baseParams(nil))
	if err != nil {
		t.Fatalf("buildDesiredState: %v", err)
	}
	fb.states[`\imas\backup`] = desired

	s := newTask(methodPresent, baseParams(map[string]interface{}{
		"user_name": "svc_backup",
		"password":  "hunter2",
	}))
	result, err := s.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || !result.Changed {
		t.Fatalf("result = %+v, want succeeded+changed because a password was supplied", result)
	}
	if len(fb.saved) != 1 {
		t.Fatalf("saved = %v, want exactly one save", fb.saved)
	}
}

// --- absent ---

func TestTaskAbsentAlreadyGone(t *testing.T) {
	installFakeBackend(t)
	s := newTask(methodAbsent, map[string]interface{}{"name": `\imas\backup`})
	result, err := s.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Changed {
		t.Fatalf("result = %+v, want succeeded and unchanged", result)
	}
}

func TestTaskAbsentRemovesExisting(t *testing.T) {
	fb := installFakeBackend(t)
	fb.states[`\imas\backup`] = taskState{Command: `C:\Windows\system32\backup.exe`}

	s := newTask(methodAbsent, map[string]interface{}{"name": `\imas\backup`})
	result, err := s.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || !result.Changed {
		t.Fatalf("result = %+v, want succeeded+changed", result)
	}
	if _, ok := fb.states[`\imas\backup`]; ok {
		t.Fatal("task still present after absent")
	}
}

func TestTaskAbsentTestModeDoesNotRemove(t *testing.T) {
	fb := installFakeBackend(t)
	fb.states[`\imas\backup`] = taskState{Command: `C:\Windows\system32\backup.exe`}

	s := newTask(methodAbsent, map[string]interface{}{"name": `\imas\backup`})
	result, err := s.Test(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || !result.Changed {
		t.Fatalf("result = %+v, want succeeded+changed", result)
	}
	if len(fb.deleted) != 0 {
		t.Fatalf("deleted = %v, want none in test mode", fb.deleted)
	}
}

// --- maskToDaysOfWeek / daysOfWeekMask round trip ---

func TestDaysOfWeekMaskRoundTrip(t *testing.T) {
	days := []string{"monday", "friday", "sunday"}
	mask := daysOfWeekMask(days)
	got := maskToDaysOfWeek(mask)
	if len(got) != 3 || got[0] != "friday" || got[1] != "monday" || got[2] != "sunday" {
		t.Errorf("maskToDaysOfWeek(%d) = %v, want sorted [friday monday sunday]", mask, got)
	}
}
