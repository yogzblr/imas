// Package tofu runs the checks of the UAT.1 OpenTofu stacks that need no
// Azure account: the destroy.sh test against stubbed tofu and az, shellcheck
// on the scripts, and tofu fmt -check. Each check skips when its tool is not
// on PATH, so `go test ./...` stays green on a machine without them. tofu
// validate and tofu test need the providers and are run by hand (README.md).
package tofu

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
		t.Fatal("cannot locate uat/tofu")
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

func TestDestroyScript(t *testing.T) {
	need(t, "bash", "jq")
	run(t, "bash", "tests/destroy_test.sh")
}

func TestShellcheck(t *testing.T) {
	need(t, "shellcheck")
	run(t, "shellcheck", "destroy.sh", "tests/destroy_test.sh", "tests/stubs/az", "tests/stubs/tofu")
}

func TestTofuFmt(t *testing.T) {
	need(t, "tofu")
	run(t, "tofu", "fmt", "-check", "-recursive", "-diff")
}
