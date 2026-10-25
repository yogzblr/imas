//go:build linux

package systemd

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/taigrr/systemctl"

	"github.com/yogzblr/imas/internal/ingredients/service"
)

// isEnabledAnswer is what `systemctl is-enabled UNIT` prints and its exit
// code, per systemctl(1) (systemd 252, AlmaLinux 9; 255, Ubuntu 24.04).
type isEnabledAnswer struct {
	stdout, stderr string
	code           int
}

var isEnabledAnswers = map[string]isEnabledAnswer{
	"enabled":         {"enabled\n", "", 0},
	"enabled-runtime": {"enabled-runtime\n", "", 0},
	"disabled":        {"disabled\n", "", 1},
	"masked":          {"masked\n", "", 1},
	"masked-runtime":  {"masked-runtime\n", "", 1},
	"static":          {"static\n", "", 0},
	"indirect":        {"indirect\n", "", 0},
	"generated":       {"generated\n", "", 0},
	"linked":          {"linked\n", "", 1},
	"alias":           {"alias\n", "", 0},
	"not-found":       {"not-found\n", "", 4},
	// systemd before 246 printed no state for a missing unit.
	"not-found (old)": {"", "Failed to get unit file state for nope.service: No such file or directory\n", 1},
}

// fakeSystemctl answers is-enabled with the given answer and records the
// calls.
func fakeSystemctl(t *testing.T, a isEnabledAnswer) *[][]string {
	t.Helper()
	var calls [][]string
	orig := runSystemctl
	runSystemctl = func(_ context.Context, args ...string) (string, string, int, error) {
		calls = append(calls, args)
		if len(args) == 0 || args[0] != "is-enabled" {
			t.Fatalf("unexpected systemctl %v", args)
		}
		return a.stdout, a.stderr, a.code, nil
	}
	t.Cleanup(func() { runSystemctl = orig })
	return &calls
}

func TestUnitStatesWithRealExitCodes(t *testing.T) {
	wantMasked := map[string]bool{"masked": true, "masked-runtime": true}
	wantEnabled := map[string]bool{"enabled": true, "enabled-runtime": true, "static": true, "indirect": true, "generated": true, "alias": true}
	for name, a := range isEnabledAnswers {
		t.Run(name, func(t *testing.T) {
			calls := fakeSystemctl(t, a)
			masked, err := isMaskedState(context.Background(), "u.service", systemctl.Options{})
			if err != nil || masked != wantMasked[name] {
				t.Errorf("isMasked = %v, %v; want %v, nil", masked, err, wantMasked[name])
			}
			enabled, err := isEnabledState(context.Background(), "u.service", systemctl.Options{})
			if strings.HasPrefix(name, "not-found") {
				if err == nil || !errors.Is(err, systemctl.ErrDoesNotExist) {
					t.Errorf("isEnabled on a missing unit: %v, %v; want ErrDoesNotExist", enabled, err)
				}
			} else if err != nil || enabled != wantEnabled[name] {
				t.Errorf("isEnabled = %v, %v; want %v, nil", enabled, err, wantEnabled[name])
			}
			if got := (*calls)[0]; strings.Join(got, " ") != "is-enabled --system u.service" {
				t.Errorf("systemctl %v", got)
			}
		})
	}
}

// UAT I.service.masked / unmasked on AlmaLinux 9, Run 2 on rc.21: test
// mode before any change failed with "exit status 1". The masked and
// unmasked methods now succeed from every state, test mode and real, and
// only touch the unit when needed.
func TestMaskedUnmaskedFromEveryState(t *testing.T) {
	for name, a := range isEnabledAnswers {
		for _, method := range []string{"masked", "unmasked"} {
			t.Run(method+"/"+name, func(t *testing.T) {
				fakeSystemctl(t, a)
				ss := &stubState{}
				origMask, origUnmask := sysMask, sysUnmask
				sysMask = func(context.Context, string, systemctl.Options, ...string) error { ss.record("mask"); return nil }
				sysUnmask = func(context.Context, string, systemctl.Options, ...string) error { ss.record("unmask"); return nil }
				t.Cleanup(func() { sysMask, sysUnmask = origMask, origUnmask })

				origInit := service.Init
				service.Init = "systemd"
				t.Cleanup(func() { service.Init = origInit })

				cooker, err := service.Service{}.Parse("id", method, map[string]interface{}{"name": "u.service"})
				if err != nil {
					t.Fatal(err)
				}
				masked := name == "masked" || name == "masked-runtime"
				wantChange := masked == (method == "unmasked")
				res, err := cooker.Test(context.Background())
				if err != nil || !res.Succeeded || res.Changed != wantChange {
					t.Fatalf("test mode: res=%+v err=%v, want changed=%v", res, err, wantChange)
				}
				res, err = cooker.Apply(context.Background())
				if err != nil || !res.Succeeded || res.Changed != wantChange {
					t.Fatalf("real: res=%+v err=%v, want changed=%v", res, err, wantChange)
				}
				verb := strings.TrimSuffix(method, "ed")
				if called := len(ss.calls) == 1 && ss.calls[0] == verb; called != wantChange || len(ss.calls) > 1 {
					t.Errorf("calls %v, want %s only when a change is due (%v)", ss.calls, verb, wantChange)
				}
			})
		}
	}
}

func TestUnreadableStateIsAnErrorWithTheOutput(t *testing.T) {
	fakeSystemctl(t, isEnabledAnswer{"", "Failed to connect to bus: No medium found\n", 1})
	_, err := isMaskedState(context.Background(), "u.service", systemctl.Options{UserMode: true})
	if err == nil || !strings.Contains(err.Error(), "Failed to connect to bus") || !strings.Contains(err.Error(), "exit status 1") {
		t.Fatalf("err = %v", err)
	}
}

func TestUserModeQueriesTheUserManager(t *testing.T) {
	calls := fakeSystemctl(t, isEnabledAnswers["enabled"])
	if _, err := isEnabledState(context.Background(), "u.service", systemctl.Options{UserMode: true}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join((*calls)[0], " "); got != "is-enabled --user u.service" {
		t.Errorf("systemctl %s", got)
	}
}

// A query is bounded: a systemctl that hangs fails the step in
// queryTimeout, not after the caller's own timeout.
func TestQueryTimeout(t *testing.T) {
	orig := queryTimeout
	queryTimeout = 50 * time.Millisecond
	t.Cleanup(func() { queryTimeout = orig })
	start := time.Now()
	// The real runner, on a command that never ends: systemctl is
	// replaced by sleep through PATH.
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/systemctl", []byte("#!/bin/sh\nexec /bin/sleep 5\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	_, _, _, err := runSystemctl(context.Background(), "is-enabled", "--system", "u.service")
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("took %v", time.Since(start))
	}
}
