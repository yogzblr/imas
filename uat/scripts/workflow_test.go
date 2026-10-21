package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The UAT workflow as far as these checks read it.
type workflow struct {
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]struct {
		Env   map[string]string `yaml:"env"`
		Steps []step            `yaml:"steps"`
	} `yaml:"jobs"`
}

type step struct {
	Name string            `yaml:"name"`
	ID   string            `yaml:"id"`
	If   string            `yaml:"if"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	Env  map[string]string `yaml:"env"`
}

func loadUATWorkflow(t *testing.T) (workflow, []step) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir(t), "..", "..", ".github", "workflows", "uat.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var wf workflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	job, ok := wf.Jobs["uat"]
	if !ok {
		t.Fatal("uat.yml has no job uat")
	}
	return wf, job.Steps
}

func index(t *testing.T, steps []step, name string) int {
	t.Helper()
	for i, s := range steps {
		if s.Name == name {
			return i
		}
	}
	t.Fatalf("uat.yml has no step %q", name)
	return -1
}

// firstLine is a run script's first command.
func firstLine(run string) string {
	return strings.TrimSpace(strings.SplitN(strings.TrimSpace(run), "\n", 2)[0])
}

// TestWorkflowSessionPhases checks W6's wiring in the UAT workflow: the
// login time is recorded, every step that uses the tunnels starts with
// session.sh phase, enrolment and the tests start on a fresh login and
// fresh, probed tunnels and refresh between their own steps, the ages are
// printed on a failure, and nothing stops the destroy.
func TestWorkflowSessionPhases(t *testing.T) {
	wf, steps := loadUATWorkflow(t)
	if wf.Permissions["id-token"] != "write" {
		t.Errorf("permissions id-token = %q: every login (azure/login and az-relogin.sh) needs write", wf.Permissions["id-token"])
	}
	env := wf.Jobs["uat"].Env
	for _, k := range []string{"AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID"} {
		if env[k] == "" {
			t.Errorf("job env has no %s: az-relogin.sh needs it in every step", k)
		}
	}
	prep := steps[index(t, steps, "Prepare directories")].Run
	for _, k := range []string{"AZ_RELOGIN_DIR=", "UAT_SESSION_UAT=", "UAT_SESSION_ACCESS=$RUNNER_TEMP/uat-state/access", "UAT_SESSION_KUBECONFIGS="} {
		if !strings.Contains(prep, k) {
			t.Errorf("Prepare directories does not set %s", k)
		}
	}

	login := index(t, steps, "Azure login (OIDC)")
	if s := steps[login+1]; s.Run != "uat/access/session.sh mark-login" {
		t.Errorf("the step after the first login must record it, got %q (%s)", s.Name, s.Run)
	}
	if got := firstLine(steps[index(t, steps, "Open the Bastion tunnels (uat/access)")].Run); got != `uat/access/session.sh phase "Bastion tunnels" --no-tunnels --force` {
		t.Errorf("the tunnels must be opened on a fresh login, first line %q", got)
	}

	// Every step that uses a tunnel starts as a phase.
	for _, name := range []string{
		"k0s on both hubs (uat/k0s)", "Core hub (uat/hub/core)", "DMZ hub (uat/hub/dmz)",
		"Core hub, second half (uat/hub/core/finish.sh)", "DMZ check",
	} {
		if got := firstLine(steps[index(t, steps, name)].Run); !strings.HasPrefix(got, "uat/access/session.sh phase ") {
			t.Errorf("%s does not start with session.sh phase: %q", name, got)
		}
	}

	for _, c := range []struct{ login, phase, next string }{
		{"Azure login again (before enrolment)", `uat/access/session.sh phase "enrolment" --force --probe`, "Tenants and enrolment (uat/enroll)"},
		{"Azure login again (before the tests)", `uat/access/session.sh phase "tests" --force --probe`, "Tests (uat/tests/run.sh)"},
	} {
		i := index(t, steps, c.login)
		if steps[i].Uses != "" || strings.TrimSpace(steps[i].Run) != c.phase {
			t.Errorf("%s: want run %q, got uses %q run %q", c.login, c.phase, steps[i].Uses, steps[i].Run)
		}
		if steps[i+1].Name != c.next {
			t.Errorf("%s must come right before %s, not %s", c.login, c.next, steps[i+1].Name)
		}
		if got := steps[i+1].Env["UAT_SESSION_HOOK"]; got != "${{ github.workspace }}/uat/access/session.sh" {
			t.Errorf("%s: UAT_SESSION_HOOK = %q", c.next, got)
		}
	}

	diag := index(t, steps, "Azure login and tunnel ages (on failure)")
	if s := steps[diag]; !strings.HasPrefix(s.If, "failure()") || !strings.HasPrefix(s.Run, "uat/access/session.sh ages ") {
		t.Errorf("the failure diagnostic: if %q run %q", s.If, s.Run)
	}
	if diag > index(t, steps, "Close the Bastion tunnels") {
		t.Error("the failure diagnostic must run before the tunnels are closed")
	}

	destroy := steps[index(t, steps, "Destroy (uat/tofu/destroy.sh)")]
	if strings.Contains(destroy.Run, "session.sh phase") {
		t.Error("the destroy must not run the age guard (session.sh phase)")
	}
	for _, line := range strings.Split(destroy.Run, "\n") {
		if strings.Contains(line, "session.sh") && !strings.HasSuffix(strings.TrimSpace(line), "|| true; fi") &&
			!strings.HasSuffix(strings.TrimSpace(line), "|| true") {
			t.Errorf("a session.sh call that can stop the destroy: %q", line)
		}
	}
	if !strings.HasPrefix(steps[index(t, steps, "Azure login again (before the destroy)")].Uses, "azure/login@") {
		t.Error("the login before the destroy stays the azure/login action")
	}
}

// TestJanitorWorkflowSession checks that the janitor, whose deletions can
// outlive its OIDC login, records the login and gives janitor.sh the
// session hook and what az-relogin.sh needs (W6).
func TestJanitorWorkflowSession(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(dir(t), "..", "..", ".github", "workflows", "uat-janitor.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var wf workflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	if wf.Permissions["id-token"] != "write" {
		t.Errorf("permissions id-token = %q", wf.Permissions["id-token"])
	}
	steps := wf.Jobs["janitor"].Steps
	login := index(t, steps, "Azure login (OIDC)")
	if s := steps[login+1]; s.Run != "uat/access/session.sh mark-login" {
		t.Errorf("the step after the login must record it, got %q (%s)", s.Name, s.Run)
	}
	del := steps[index(t, steps, "Delete expired UAT resource groups")]
	if del.Env["UAT_SESSION_HOOK"] != "${{ github.workspace }}/uat/access/session.sh" {
		t.Errorf("janitor.sh needs UAT_SESSION_HOOK, got %q", del.Env["UAT_SESSION_HOOK"])
	}
	for _, k := range []string{"AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_ID"} {
		if del.Env[k] == "" {
			t.Errorf("the delete step has no %s for az-relogin.sh", k)
		}
	}
}
