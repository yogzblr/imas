package winfirewall

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
)

// exitError stands in for *exec.ExitError: winexec.ExitCode only needs
// its ExitCode method.
type exitError int

func (e exitError) ExitCode() int { return int(e) }
func (e exitError) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

// noMatchErr is the error winexec.RunCLI returned in UAT Run 2 for
// `show rule` on a missing rule.
func noMatchErr(code int) error {
	return ingredients.CommandError("netsh.exe", exitError(code), []byte("No rules match the specified criteria."), nil)
}

const showRuleOut = `Rule Name:                            Allow RDP
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Action:                               Allow
Ok.`

// fakeNetsh replaces runCLI for a test. show answers `show rule`; the
// verbs called ("show", "add", "delete") are recorded.
type fakeNetsh struct {
	showOut string
	showErr error
	calls   []string
}

func (f *fakeNetsh) install(t *testing.T) {
	t.Helper()
	orig := runCLI
	runCLI = func(_ context.Context, exe string, args []string, _ time.Duration) (string, error) {
		if exe != "netsh.exe" || len(args) < 4 {
			t.Fatalf("unexpected command %s %v", exe, args)
		}
		f.calls = append(f.calls, args[2])
		if args[2] == "show" {
			return f.showOut, f.showErr
		}
		return "Ok.", nil
	}
	t.Cleanup(func() { runCLI = orig })
}

func (f *fakeNetsh) called(verb string) bool {
	for _, c := range f.calls {
		if c == verb {
			return true
		}
	}
	return false
}

func parseRule(t *testing.T, method string) Rule {
	t.Helper()
	cooker, err := (Rule{}).Parse("id1", method, map[string]interface{}{"name": "Allow RDP"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return cooker.(Rule)
}

func TestNoMatchErrShape(t *testing.T) {
	want := "netsh.exe: exit status 1; stderr: (empty); stdout: No rules match the specified criteria."
	if got := noMatchErr(1).Error(); got != want {
		t.Errorf("fake error is not Run 2's:\n got %q\nwant %q", got, want)
	}
}

func TestRuleCases(t *testing.T) {
	missing := fakeNetsh{showOut: "No rules match the specified criteria.", showErr: noMatchErr(1)}
	exists := fakeNetsh{showOut: showRuleOut}
	tests := []struct {
		name    string
		method  string
		netsh   fakeNetsh
		apply   bool
		changed bool
		verb    string // the change command expected; "" for none
	}{
		{"present missing test", methodRulePresent, missing, false, true, ""},
		{"present missing apply", methodRulePresent, missing, true, true, "add"},
		{"present exists test", methodRulePresent, exists, false, false, ""},
		{"present exists apply", methodRulePresent, exists, true, false, ""},
		{"absent missing test", methodRuleAbsent, missing, false, false, ""},
		{"absent missing apply", methodRuleAbsent, missing, true, false, ""},
		{"absent exists test", methodRuleAbsent, exists, false, true, ""},
		{"absent exists apply", methodRuleAbsent, exists, true, true, "delete"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := tt.netsh
			f.install(t)
			r := parseRule(t, tt.method)
			var res cook.Result
			var err error
			if tt.apply {
				res, err = r.Apply(context.Background())
			} else {
				res, err = r.Test(context.Background())
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !res.Succeeded || res.Failed || res.Changed != tt.changed {
				t.Errorf("got Succeeded=%v Failed=%v Changed=%v, want true false %v", res.Succeeded, res.Failed, res.Changed, tt.changed)
			}
			for _, verb := range []string{"add", "delete"} {
				if f.called(verb) != (verb == tt.verb) {
					t.Errorf("%s called: %v, want %v (calls %v)", verb, f.called(verb), verb == tt.verb, f.calls)
				}
			}
		})
	}
}

// A rule that exists is found in any locale: exit 0 is the signal, not
// the English "Rule Name:" header.
func TestRuleExistsInAnyLocale(t *testing.T) {
	f := fakeNetsh{showOut: "Regelname:                            Allow RDP\nOK."}
	f.install(t)
	res, err := parseRule(t, methodRulePresent).Apply(context.Background())
	if err != nil || !res.Succeeded || res.Changed || f.called("add") {
		t.Errorf("got %+v, %v, calls %v; want present, unchanged, no add", res, err, f.calls)
	}
}

func TestShowRuleFailureIsError(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"exit 2", noMatchErr(2)},
		{"no exit code", ingredients.CommandError("netsh.exe", errors.New("exec: file does not exist"), nil, nil)},
		{"timeout", ingredients.CommandError("netsh.exe", fmt.Errorf("%w (%v)", context.DeadlineExceeded, exitError(1)), nil, nil)},
	}
	for _, tt := range tests {
		for _, method := range []string{methodRulePresent, methodRuleAbsent} {
			for _, apply := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s %s apply=%v", tt.name, method, apply), func(t *testing.T) {
					f := fakeNetsh{showErr: tt.err}
					f.install(t)
					r := parseRule(t, method)
					var res cook.Result
					var err error
					if apply {
						res, err = r.Apply(context.Background())
					} else {
						res, err = r.Test(context.Background())
					}
					if err == nil {
						t.Fatal("expected an error")
					}
					if !res.Failed || res.Changed {
						t.Errorf("got Failed=%v Changed=%v, want true false", res.Failed, res.Changed)
					}
					if f.called("add") || f.called("delete") {
						t.Errorf("expected no change command, got %v", f.calls)
					}
				})
			}
		}
	}
}

func TestParseRequiresName(t *testing.T) {
	if _, err := (Rule{}).Parse("id1", methodRulePresent, map[string]interface{}{}); err != ingredients.ErrMissingName {
		t.Errorf("expected ErrMissingName, got %v", err)
	}
}

func TestParseInvalidMethod(t *testing.T) {
	_, err := (Rule{}).Parse("id1", "bogus", map[string]interface{}{"name": "Allow RDP"})
	if err != ingredients.ErrInvalidMethod {
		t.Errorf("expected ErrInvalidMethod, got %v", err)
	}
}

func TestParseOK(t *testing.T) {
	cooker, err := (Rule{}).Parse("id1", methodRulePresent, map[string]interface{}{
		"name": "Allow RDP", "protocol": "TCP", "localport": "3389",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	r, ok := cooker.(Rule)
	if !ok {
		t.Fatalf("expected Rule, got %T", cooker)
	}
	if r.name != "Allow RDP" {
		t.Errorf("expected name %q, got %q", "Allow RDP", r.name)
	}
}

func TestMethods(t *testing.T) {
	name, methods := Rule{}.Methods()
	if name != ingredientName {
		t.Errorf("expected %q, got %q", ingredientName, name)
	}
	if len(methods) != 2 {
		t.Errorf("expected 2 methods, got %d", len(methods))
	}
}
