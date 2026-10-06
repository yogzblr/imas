// Package scripts runs the checks of the UAT workflow's helper scripts
// (UAT.6) that need no Azure account: the shell tests against stubbed az, gh
// and curl, shellcheck, and actionlint and yamllint on the two workflows.
// Each check skips when its tool is not on PATH, so `go test ./...` stays
// green on a machine without them.
package scripts

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
		t.Fatal("cannot locate uat/scripts")
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

func run(t *testing.T, cwd, name string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = cwd
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	t.Logf("%s", out)
}

var scriptFiles = []string{
	"check-inputs.sh", "collect-artifacts.sh", "janitor.sh", "material.sh",
	"run-id.sh", "runner-cidr.sh", "verify-teardown.sh",
	"tests/scripts_test.sh", "tests/stubs/az", "tests/stubs/gh", "tests/stubs/curl",
}

var workflows = []string{
	"../../.github/workflows/uat.yml",
	"../../.github/workflows/uat-janitor.yml",
}

func TestScripts(t *testing.T) {
	need(t, "bash", "jq", "od")
	run(t, dir(t), "bash", "tests/scripts_test.sh")
}

func TestShellcheck(t *testing.T) {
	need(t, "shellcheck")
	run(t, dir(t), "shellcheck", append([]string{"-x"}, scriptFiles...)...)
}

func TestActionlint(t *testing.T) {
	need(t, "actionlint")
	run(t, dir(t), "actionlint", workflows...)
}

func TestYamllint(t *testing.T) {
	need(t, "yamllint")
	run(t, dir(t), "yamllint", append([]string{"-s", "-c", "yamllint.yaml", "yamllint.yaml"}, workflows...)...)
}
