// Package lite runs the tests of the UAT local rig (uat/lite, UAT.8): the
// bash tests against stubbed docker, kind, kubectl and helm, shellcheck and
// yamllint, and a check that the uat.json and harness.json the rig writes
// are read by uat/tests/harness's own parser (harness.json strictly, as the
// harness reads it). Each check skips when a tool it needs is not on PATH,
// so `go test ./...` stays green on a machine without them. Nothing starts
// a container or a cluster.
package lite

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/yogzblr/imas/uat/tests/harness"
)

func dir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate uat/lite")
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

func run(t *testing.T, env []string, name string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir(t)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	t.Logf("%s", out)
}

// TestLiteScripts runs tests/test_lite.sh, then reads the material one
// stubbed up.sh wrote with the harness's parsers and lints the kind configs
// it rendered.
func TestLiteScripts(t *testing.T) {
	need(t, "bash", "jq", "openssl", "awk", "sha256sum", "base64", "cmp", "stat", "find")
	keep := t.TempDir()
	run(t, []string{"LITE_TEST_KEEP=" + keep}, "bash", "tests/test_lite.sh")

	raw, err := os.ReadFile(filepath.Join(keep, "uat.json"))
	if err != nil {
		t.Fatalf("the shell test kept no uat.json: %v", err)
	}
	u, err := harness.ParseUAT(raw)
	if err != nil {
		t.Fatalf("harness.ParseUAT refuses the rig's uat.json: %v", err)
	}
	if len(u.Sprouts) != 4 {
		t.Errorf("uat.json has %d sprouts, want 4", len(u.Sprouts))
	}
	perTenant := map[int]map[string]bool{}
	for name, s := range u.Sprouts {
		if s.Connection != "ssh" {
			t.Errorf("%s: connection %q, want ssh (no docker connection)", name, s.Connection)
		}
		if s.OS == harness.OSWindows {
			t.Errorf("%s: the rig has no Windows sprouts", name)
		}
		if perTenant[int(s.Tenant)] == nil {
			perTenant[int(s.Tenant)] = map[string]bool{}
		}
		perTenant[int(s.Tenant)][s.OS] = true
	}
	for _, n := range []int{1, 2} {
		if !perTenant[n][harness.OSUbuntu] || !perTenant[n][harness.OSAlma] {
			t.Errorf("tenant %d does not have one Ubuntu and one AlmaLinux sprout: %v", n, perTenant[n])
		}
	}
	if u.Core.PublicIP != "" || u.DMZ.PublicIP != "" {
		t.Errorf("hubs have a public_ip (%q, %q): X3 would probe an address that is not core", u.Core.PublicIP, u.DMZ.PublicIP)
	}

	raw, err = os.ReadFile(filepath.Join(keep, "harness.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s harness.Settings
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields() // as the harness reads harness.json
	if err := dec.Decode(&s); err != nil {
		t.Fatalf("harness.json does not decode strictly into harness.Settings: %v", err)
	}
	if !strings.HasSuffix(s.EnvoyURL, ":8443") || !strings.HasSuffix(s.SproutEnvoyAddress, ":8443") {
		t.Errorf("Envoy is on 8443: envoy_url %q, sprout_envoy_address %q", s.EnvoyURL, s.SproutEnvoyAddress)
	}
	if !strings.HasSuffix(s.VMCtl, "/uat/lite/vmctl.sh") {
		t.Errorf("vmctl is %q, want the rig's", s.VMCtl)
	}
	if !s.BindTenant.Enabled() {
		t.Errorf("bind_tenant is incomplete: %v", s.BindTenant.Missing())
	}

	t.Run("yamllint", func(t *testing.T) {
		need(t, "yamllint")
		run(t, nil, "yamllint", "-s", "-c", ".yamllint.yaml", ".yamllint.yaml",
			filepath.Join(keep, "dmz.yaml"), filepath.Join(keep, "core.yaml"), filepath.Join(keep, "cluster-issuer.yaml"))
	})
}

func TestShellcheck(t *testing.T) {
	need(t, "shellcheck")
	files := []string{"up.sh", "down.sh", "run.sh", "vmctl.sh", "write-material.sh", "lib.sh",
		"config.env", "versions.env", "tests/test_lite.sh"}
	for _, pattern := range []string{"tests/stubs/*", "tests/fake/*"} {
		m, err := filepath.Glob(filepath.Join(dir(t), pattern))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range m {
			rel, _ := filepath.Rel(dir(t), f)
			files = append(files, rel)
		}
	}
	run(t, nil, "shellcheck", append([]string{"-x", "-P", "SCRIPTDIR"}, files...)...)
}
