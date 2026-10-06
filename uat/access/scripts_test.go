// Package access runs the tests of the UAT.1 access scripts (tunnels.sh and
// vmctl.sh) against a stubbed az, and shellcheck on them. Each check skips
// when its tool is not on PATH, so `go test ./...` stays green on a machine
// without them. Nothing reaches Azure.
package access

import (
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func dir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate uat/access")
	}
	return filepath.Dir(file)
}

func need(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH", tool)
		}
	}
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	t.Logf("%s", out)
}

func TestAccessScripts(t *testing.T) {
	need(t, "bash", "jq", "python3", "base64", "timeout", "setsid", "pgrep")
	run(t, "bash", "tests/access_test.sh")
}

func TestShellcheck(t *testing.T) {
	need(t, "shellcheck")
	run(t, "shellcheck", "tunnels.sh", "vmctl.sh", "tests/access_test.sh", "tests/stubs/az", "tests/stubs/systemctl")
}
