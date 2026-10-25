package winshortcut

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// fakeBackend is an in-memory stand-in for oleShortcutBackend, keyed by
// path, so present()/absent() can be exercised without a real COM
// apartment.
type fakeBackend struct {
	states  map[string]shortcutState
	loadErr error
	saveErr error
	saved   []string
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{states: map[string]shortcutState{}}
}

func (f *fakeBackend) Load(_ context.Context, path string) (shortcutState, error) {
	if f.loadErr != nil {
		return shortcutState{}, f.loadErr
	}
	return f.states[path], nil
}

func (f *fakeBackend) Save(_ context.Context, path string, state shortcutState) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.states[path] = state
	f.saved = append(f.saved, path)
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

func newShortcut(method string, params map[string]interface{}) Shortcut {
	return Shortcut{id: "test-id", method: method, params: params}
}

// --- Methods / PropertiesForMethod ---

func TestMethods(t *testing.T) {
	name, methods := Shortcut{}.Methods()
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
	_, err := Shortcut{}.Parse("id", methodPresent, map[string]interface{}{"target": `C:\Windows\notepad.exe`})
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestParsePresentMissingTarget(t *testing.T) {
	_, err := Shortcut{}.Parse("id", methodPresent, map[string]interface{}{"name": `C:\Users\Public\Desktop\Notepad.lnk`})
	if err == nil {
		t.Fatal("expected error for missing target")
	}
}

func TestParsePresentInvalidWindowStyle(t *testing.T) {
	_, err := Shortcut{}.Parse("id", methodPresent, map[string]interface{}{
		"name":         `C:\Users\Public\Desktop\Notepad.lnk`,
		"target":       `C:\Windows\notepad.exe`,
		"window_style": "sideways",
	})
	if !errors.Is(err, ErrInvalidWindowStyle) {
		t.Fatalf("err = %v, want ErrInvalidWindowStyle", err)
	}
}

func TestParsePresentOK(t *testing.T) {
	_, err := Shortcut{}.Parse("id", methodPresent, map[string]interface{}{
		"name":   `C:\Users\Public\Desktop\Notepad.lnk`,
		"target": `C:\Windows\notepad.exe`,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseAbsentMissingName(t *testing.T) {
	_, err := Shortcut{}.Parse("id", methodAbsent, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error for missing name")
	}
}

// --- parseWindowStyle ---

func TestParseWindowStyleDefault(t *testing.T) {
	n, err := parseWindowStyle(map[string]interface{}{})
	if err != nil || n != 1 {
		t.Fatalf("n, err = %d, %v; want 1, nil", n, err)
	}
}

func TestParseWindowStyleNamed(t *testing.T) {
	for name, want := range windowStyles {
		n, err := parseWindowStyle(map[string]interface{}{"window_style": name})
		if err != nil || n != want {
			t.Errorf("parseWindowStyle(%q) = %d, %v; want %d, nil", name, n, err, want)
		}
	}
}

func TestParseWindowStyleNumeric(t *testing.T) {
	n, err := parseWindowStyle(map[string]interface{}{"window_style": "7"})
	if err != nil || n != 7 {
		t.Fatalf("n, err = %d, %v; want 7, nil", n, err)
	}
}

func TestParseWindowStyleInvalid(t *testing.T) {
	if _, err := parseWindowStyle(map[string]interface{}{"window_style": "9"}); !errors.Is(err, ErrInvalidWindowStyle) {
		t.Fatalf("err = %v, want ErrInvalidWindowStyle", err)
	}
}

// --- buildDesiredState ---

func TestBuildDesiredStateIconLocation(t *testing.T) {
	state, err := buildDesiredState(map[string]interface{}{
		"target":        `C:\Windows\notepad.exe`,
		"icon_location": `C:\Windows\notepad.exe`,
		"icon_index":    "2",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := `C:\Windows\notepad.exe,2`
	if state.IconLocation != want {
		t.Errorf("IconLocation = %q, want %q", state.IconLocation, want)
	}
}

func TestBuildDesiredStateMissingTarget(t *testing.T) {
	if _, err := buildDesiredState(map[string]interface{}{}); !errors.Is(err, ErrMissingTarget) {
		t.Fatalf("err = %v, want ErrMissingTarget", err)
	}
}

// --- present ---

func TestPresentCreatesWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Notepad.lnk")
	fb := installFakeBackend(t)

	s := newShortcut(methodPresent, map[string]interface{}{
		"name":   path,
		"target": `C:\Windows\notepad.exe`,
	})

	result, err := s.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || !result.Changed {
		t.Fatalf("result = %+v, want succeeded+changed", result)
	}
	if len(fb.saved) != 1 || fb.saved[0] != path {
		t.Fatalf("saved = %v, want [%s]", fb.saved, path)
	}
}

func TestPresentTestModeDoesNotSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Notepad.lnk")
	fb := installFakeBackend(t)

	s := newShortcut(methodPresent, map[string]interface{}{
		"name":   path,
		"target": `C:\Windows\notepad.exe`,
	})

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

func TestPresentNoopWhenMatching(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Notepad.lnk")
	if err := os.WriteFile(path, []byte("stub"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	fb := installFakeBackend(t)
	fb.states[path] = shortcutState{TargetPath: `C:\Windows\notepad.exe`, WindowStyle: 1}

	s := newShortcut(methodPresent, map[string]interface{}{
		"name":   path,
		"target": `C:\Windows\notepad.exe`,
	})

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

func TestPresentUpdatesWhenDiffers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Notepad.lnk")
	if err := os.WriteFile(path, []byte("stub"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	fb := installFakeBackend(t)
	fb.states[path] = shortcutState{TargetPath: `C:\Windows\old.exe`, WindowStyle: 1}

	s := newShortcut(methodPresent, map[string]interface{}{
		"name":   path,
		"target": `C:\Windows\notepad.exe`,
	})

	result, err := s.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || !result.Changed {
		t.Fatalf("result = %+v, want succeeded+changed", result)
	}
	if fb.states[path].TargetPath != `C:\Windows\notepad.exe` {
		t.Errorf("TargetPath = %q, want updated value", fb.states[path].TargetPath)
	}
}

// --- absent ---

func TestAbsentAlreadyGone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Notepad.lnk")

	s := newShortcut(methodAbsent, map[string]interface{}{"name": path})
	result, err := s.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Changed {
		t.Fatalf("result = %+v, want succeeded and unchanged", result)
	}
}

func TestAbsentRemovesExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Notepad.lnk")
	if err := os.WriteFile(path, []byte("stub"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	s := newShortcut(methodAbsent, map[string]interface{}{"name": path})
	result, err := s.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || !result.Changed {
		t.Fatalf("result = %+v, want succeeded+changed", result)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file still exists after absent: %v", err)
	}
}

func TestAbsentTestModeDoesNotRemove(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Notepad.lnk")
	if err := os.WriteFile(path, []byte("stub"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	s := newShortcut(methodAbsent, map[string]interface{}{"name": path})
	result, err := s.Test(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || !result.Changed {
		t.Fatalf("result = %+v, want succeeded+changed", result)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file should still exist in test mode: %v", err)
	}
}
