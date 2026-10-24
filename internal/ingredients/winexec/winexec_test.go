package winexec

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/ingredients"
)

func TestParseTimeoutDefault(t *testing.T) {
	d, err := ParseTimeout("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != DefaultTimeout {
		t.Errorf("expected DefaultTimeout, got %v", d)
	}
}

func TestParseTimeoutValid(t *testing.T) {
	d, err := ParseTimeout("5s")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != 5*time.Second {
		t.Errorf("expected 5s, got %v", d)
	}
}

func TestParseTimeoutInvalid(t *testing.T) {
	if _, err := ParseTimeout("not-a-duration"); err == nil {
		t.Error("expected error for invalid duration")
	}
}

func TestStringParam(t *testing.T) {
	params := map[string]interface{}{"name": "value", "wrong_type": 42}
	if v, ok := StringParam(params, "name"); !ok || v != "value" {
		t.Errorf("expected (value, true), got (%q, %v)", v, ok)
	}
	if _, ok := StringParam(params, "missing"); ok {
		t.Error("expected ok=false for missing key")
	}
	if _, ok := StringParam(params, "wrong_type"); ok {
		t.Error("expected ok=false for wrong type")
	}
}

func TestBoolParam(t *testing.T) {
	params := map[string]interface{}{"flag": true, "wrong_type": "yes"}
	if !BoolParam(params, "flag", false) {
		t.Error("expected true")
	}
	if !BoolParam(params, "missing", true) {
		t.Error("expected default true for missing key")
	}
	if BoolParam(params, "wrong_type", false) {
		t.Error("expected default false for wrong type")
	}
}

func TestStringSliceParam(t *testing.T) {
	params := map[string]interface{}{"servers": []string{"a", "b"}, "wrong_type": "a"}
	v, ok := StringSliceParam(params, "servers")
	if !ok || len(v) != 2 {
		t.Errorf("expected 2-element slice, got %v, ok=%v", v, ok)
	}
	if _, ok := StringSliceParam(params, "missing"); ok {
		t.Error("expected ok=false for missing key")
	}
	if _, ok := StringSliceParam(params, "wrong_type"); ok {
		t.Error("expected ok=false for wrong type")
	}
}

func TestStringParamOr(t *testing.T) {
	params := map[string]interface{}{"name": "value"}
	if got := StringParamOr(params, "name", "default"); got != "value" {
		t.Errorf("expected value, got %q", got)
	}
	if got := StringParamOr(params, "missing", "default"); got != "default" {
		t.Errorf("expected default, got %q", got)
	}
}

func TestPSQuote(t *testing.T) {
	if got := PSQuote("simple"); got != "'simple'" {
		t.Errorf("expected 'simple', got %q", got)
	}
	if got := PSQuote("it's"); got != "'it''s'" {
		t.Errorf("expected escaped quote, got %q", got)
	}
}

func TestPSBool(t *testing.T) {
	if PSBool(true) != "$true" {
		t.Error("expected $true")
	}
	if PSBool(false) != "$false" {
		t.Error("expected $false")
	}
}

func TestRunCLINonexistentBinary(t *testing.T) {
	_, err := RunCLI(context.Background(), "imas-definitely-not-a-real-binary", nil, 2*time.Second)
	if err == nil {
		t.Error("expected error for nonexistent binary")
	}
	if code, ok := ExitCode(err); ok {
		t.Errorf("expected no exit code for a binary that never started, got %d", code)
	}
}

// The tests below run real processes, so they need a POSIX sh and sleep;
// on Windows CI the fake-exec tests in the ingredient packages cover the
// same paths.

func TestExitCodeFromRunCLI(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs sh")
	}
	_, err := RunCLI(context.Background(), "sh", []string{"-c", "echo nope; exit 3"}, 5*time.Second)
	if err == nil {
		t.Fatal("expected error for exit 3")
	}
	code, ok := ExitCode(err)
	if !ok || code != 3 {
		t.Errorf("expected (3, true), got (%d, %v) from %v", code, ok, err)
	}
	if !strings.Contains(err.Error(), "stdout: nope") {
		t.Errorf("expected the CommandError shape, got %v", err)
	}
}

func TestExitCodeHiddenOnTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs sleep")
	}
	_, err := RunCLI(context.Background(), "sleep", []string{"5"}, 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected error for a timed-out command")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got %v", err)
	}
	if code, ok := ExitCode(err); ok {
		t.Errorf("expected no exit code for a killed process, got %d", code)
	}
}

type fakeExit int

func (e fakeExit) ExitCode() int { return int(e) }
func (e fakeExit) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func TestExitCodeThroughCommandError(t *testing.T) {
	err := ingredients.CommandError("netsh.exe", fakeExit(1), []byte("No rules match the specified criteria."), nil)
	if code, ok := ExitCode(err); !ok || code != 1 {
		t.Errorf("expected (1, true), got (%d, %v)", code, ok)
	}
	if code, ok := ExitCode(errors.New("plain")); ok {
		t.Errorf("expected no exit code for a plain error, got %d", code)
	}
	if _, ok := ExitCode(nil); ok {
		t.Error("expected no exit code for nil")
	}
}
