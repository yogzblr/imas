package cmd

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// UAT.9: findings from reading cmd.run for the UAT gate (uat/cases/cmd/run.yaml).

// Test mode must report the step as Succeeded: the cook engine marks a step
// whose result is not Succeeded as failed, in test mode too, so a test mode
// cook of any cmd.run step used to fail.
func TestTestModeReportsSuccess(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "marker")
	c := Cmd{id: "t", method: cmdRunMethod, params: map[string]interface{}{"name": "touch " + marker}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := c.Test(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Succeeded || res.Failed {
		t.Errorf("test mode: Succeeded=%v Failed=%v, want Succeeded and not Failed", res.Succeeded, res.Failed)
	}
	if !res.Changed {
		t.Error("test mode: Changed=false, but the command would run (cmd.run acts on every cook)")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("test mode ran the command")
	}
}

// A command that ran and exited 0 is a change, as Salt reports it; one that
// failed is not Succeeded and not a change.
func TestRealRunReportsChange(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ok := Cmd{id: "t", method: cmdRunMethod, params: map[string]interface{}{"name": "echo hi"}}
	res, err := ok.Apply(ctx)
	if err != nil || !res.Succeeded || res.Failed {
		t.Fatalf("echo: result %+v, error %v", res, err)
	}
	if !res.Changed {
		t.Error("a command that ran and succeeded must report Changed")
	}
	bad := Cmd{id: "t", method: cmdRunMethod, params: map[string]interface{}{"name": "false"}}
	res, _ = bad.Apply(ctx)
	if res.Succeeded || !res.Failed || res.Changed {
		t.Errorf("a failing command: Succeeded=%v Failed=%v Changed=%v, want failed and no change", res.Succeeded, res.Failed, res.Changed)
	}
}

// On Windows there is no /bin/sh: a command with shell characters goes
// through powershell.exe, and a backslash (a path separator there) is not a
// shell character.
func TestShellByOS(t *testing.T) {
	for _, tc := range []struct {
		goos, cmd string
		shell     bool
	}{
		{"linux", "echo hi", false},
		{"linux", "echo hi | tr a-z A-Z", true},
		{"linux", `echo a\ b`, true},
		{"linux", "a\nb", true},
		{"windows", "hostname", false},
		{"windows", `C:\Windows\System32\hostname.exe`, false},
		{"windows", "hostname | more", true},
		{"windows", `echo "a b"`, true},
		{"windows", "a && b", true},
		{"windows", "a\nb", true},
	} {
		if got := needsShellFor(tc.goos, tc.cmd); got != tc.shell {
			t.Errorf("needsShellFor(%s, %q) = %v, want %v", tc.goos, tc.cmd, got, tc.shell)
		}
	}
	exe, args := shellCommand("linux", "echo a | b")
	if exe != "/bin/sh" || !reflect.DeepEqual(args, []string{"-c", "echo a | b"}) {
		t.Errorf("linux shell: %s %v", exe, args)
	}
	exe, args = shellCommand("windows", "echo a | b")
	if exe != "powershell.exe" || !reflect.DeepEqual(args, []string{"-NoProfile", "-NonInteractive", "-Command", "echo a | b"}) {
		t.Errorf("windows shell: %s %v", exe, args)
	}
}
