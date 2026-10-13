// Package k0s runs the tests of the UAT hub cluster scripts (bootstrap.sh and
// check.sh, single-node and HA hubs) against stubbed k0sctl, kubectl, curl
// and sleep, and shellcheck and yamllint on them. Each check skips when its
// tool is not on PATH, so `go test ./...` stays green on a machine without
// them. Nothing reaches a cluster or the network.
package k0s

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
		t.Fatal("cannot locate uat/k0s")
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

func TestK0sScripts(t *testing.T) {
	need(t, "bash", "jq", "openssl", "base64", "sha256sum")
	run(t, "bash", "tests/test-k0s.sh")
}

func TestShellcheck(t *testing.T) {
	need(t, "shellcheck")
	run(t, "shellcheck", "-x", "-P", "SCRIPTDIR",
		"bootstrap.sh", "check.sh", "lib.sh", "install-tools.sh",
		"tests/run.sh", "tests/test-k0s.sh",
		"tests/stubs/curl", "tests/stubs/k0sctl", "tests/stubs/kubectl", "tests/stubs/sleep")
}

func TestYamllint(t *testing.T) {
	need(t, "yamllint")
	files, err := filepath.Glob(filepath.Join(dir(t), "testdata", "expected", "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no golden k0sctl files: %v", err)
	}
	run(t, "yamllint", append([]string{"-s", "-c", ".yamllint.yaml", ".yamllint.yaml"}, files...)...)
}
