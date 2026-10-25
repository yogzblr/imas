//go:build windows_integration || systemd_integration

package ingredients

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
	"github.com/yogzblr/imas/uat/tests/harness"
)

// The local integration run (W11, Part D): the UAT case catalogue's cycle
// (Cycle.Run: setup, test mode, real cook, idempotency, out of band
// check, revert) on the machine the test runs on, with no hub, bus or
// Azure. Cook runs the recipe's steps through the registered ingredients
// as the sprout does (ingredients.NewRecipeCooker, with its Windows step
// bound) and writes the sprout's job log where HostCall reads it; Run runs
// a host script locally. The Windows job (build tag windows_integration)
// runs on a GitHub Windows Server 2022 runner, the systemd one
// (systemd_integration) on an Ubuntu runner and in an AlmaLinux 9
// container with systemd as PID 1 (.github/workflows/ingredients-os.yml).
// Both must run as an administrator or root: the cases change the host
// and revert what they change, with throwaway names (@NONCE@).
//
// IMAS_IT_CASES (comma-separated ids) narrows the cases; IMAS_IT_SKIP
// (id=reason, comma-separated) skips some with a reason.

// localDriver is the Driver of the local run.
type localDriver struct {
	mu      sync.Mutex
	recipes map[string]string
	jobDir  string
	n       int
}

func newLocalDriver(t *testing.T) *localDriver {
	dir := "/var/cache/imas/sprout/jobs"
	if runtime.GOOS == "windows" {
		dir = filepath.Join(os.Getenv("ProgramData"), "imas", "cache", "sprout", "jobs")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("the job log directory (HostCall reads it): %v", err)
	}
	return &localDriver{recipes: map[string]string{}, jobDir: dir}
}

func (d *localDriver) Upload(_ context.Context, tenant int, name, content string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.recipes[fmt.Sprintf("%d/%s", tenant, name)] = content
	return nil
}

func (d *localDriver) Delete(_ context.Context, tenant int, name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.recipes, fmt.Sprintf("%d/%s", tenant, name))
}

// localStep is one step of a recipe: its ingredient, method and properties.
type localStep struct {
	id, ingredient, method string
	params                 map[string]interface{}
}

// recipeStepsWithParams reads a recipe's steps in id order, each with its
// list of one-key property maps merged into one map, as the sprout gets
// them.
func recipeStepsWithParams(recipe string) ([]localStep, error) {
	var doc struct {
		Steps map[string]map[string][]map[string]interface{} `yaml:"steps"`
	}
	if err := yaml.Unmarshal([]byte(recipe), &doc); err != nil {
		return nil, err
	}
	var out []localStep
	for id, st := range doc.Steps {
		for key, props := range st {
			ing, method, _ := strings.Cut(key, ".")
			params := map[string]interface{}{}
			for _, p := range props {
				for k, v := range p {
					params[k] = v
				}
			}
			out = append(out, localStep{id: id, ingredient: ing, method: method, params: params})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out, nil
}

func (d *localDriver) Cook(ctx context.Context, sp harness.Sprout, recipe string, test bool, timeout time.Duration) (harness.Item, error) {
	d.mu.Lock()
	content, ok := d.recipes[fmt.Sprintf("%d/%s", sp.Tenant, recipe)]
	d.n++
	jid := fmt.Sprintf("local-%d-%d", time.Now().UnixNano(), d.n)
	d.mu.Unlock()
	if !ok {
		return harness.Item{AssetID: sp.AssetID, Status: harness.ItemFailed, Error: "job_refused"}, nil
	}
	steps, err := recipeStepsWithParams(content)
	if err != nil {
		return harness.Item{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	lines := []StepCompletion{{ID: "start-" + jid, CompletionStatus: StatusCompleted}}
	item := harness.Item{AssetID: sp.AssetID, SproutID: sp.SproutID, JID: jid, Status: harness.ItemSucceeded}
	for _, s := range steps {
		sc := StepCompletion{ID: s.id, CompletionStatus: StatusCompleted}
		cooker, err := ingredients.NewRecipeCooker(cook.StepID(s.id), cook.Ingredient(s.ingredient), s.method, s.params)
		var res cook.Result
		if err == nil {
			if test {
				res, err = cooker.Test(ctx)
			} else {
				res, err = cooker.Apply(ctx)
			}
		}
		if err == nil && res.Failed {
			err = fmt.Errorf("the step reported a failure: %s", notes(res))
		}
		if err != nil {
			e := err.Error()
			sc.CompletionStatus, sc.Error = StatusFailed, &e
			item.Status, item.Error = harness.ItemFailed, "job_failed"
		} else if !test && res.Changed {
			// The sprout drops a test mode step's Changed and notes
			// (internal/cook/sproutcook.go); the cycle relies on that.
			sc.ChangesMade, sc.Changes = true, []string{notes(res)}
		}
		lines = append(lines, sc)
	}
	lines = append(lines, StepCompletion{ID: "completed-" + jid, CompletionStatus: StatusCompleted})
	var b strings.Builder
	for _, l := range lines {
		j, _ := json.Marshal(l)
		b.Write(j)
		b.WriteString("\n")
	}
	if err := os.WriteFile(filepath.Join(d.jobDir, jid+".jsonl"), []byte(b.String()), 0o644); err != nil {
		return item, fmt.Errorf("writing the job log: %w", err)
	}
	return item, nil
}

func notes(r cook.Result) string {
	var parts []string
	for _, n := range r.Notes {
		parts = append(parts, n.String())
	}
	return strings.Join(parts, "; ")
}

// Run runs a host script here: a script file in powershell.exe on
// Windows, sh on Linux (the test runs as root).
func (d *localDriver) Run(ctx context.Context, sp harness.Sprout, script string) (*harness.RunResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	var cmd *exec.Cmd
	if sp.IsWindows() {
		f, err := os.CreateTemp("", "imas-it-*.ps1")
		if err != nil {
			return nil, err
		}
		defer os.Remove(f.Name())
		// A BOM, so Windows PowerShell reads the file as UTF-8.
		if _, err := f.WriteString("\uFEFF" + script); err != nil {
			f.Close()
			return nil, err
		}
		f.Close()
		cmd = exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", f.Name())
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", script)
	}
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("the host script timed out: %w: %s", ctx.Err(), clip(string(out), 400))
	}
	_ = err // a script's own exit code is in its values (ScriptCall)
	return harness.ParseRunOutput(out), nil
}

// localOS is this host's OS as the cases name it.
func localOS(t *testing.T) string {
	if runtime.GOOS == "windows" {
		return harness.OSWindows
	}
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		t.Fatalf("reading /etc/os-release: %v", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "ID="); ok {
			switch strings.Trim(v, `"`) {
			case "ubuntu":
				return "ubuntu"
			case "almalinux", "rhel", "rocky", "centos":
				return "alma"
			}
		}
	}
	t.Fatalf("this OS is neither Ubuntu nor an EL9 (AlmaLinux) one: %s", b)
	return ""
}

// runLocalCases runs the cases with these ids on this host, each a
// subtest, in order (they change the host one at a time).
func runLocalCases(t *testing.T, ids []string) {
	if v := os.Getenv("IMAS_IT_CASES"); v != "" {
		ids = strings.Split(v, ",")
	}
	skip := map[string]string{}
	for _, kv := range strings.Split(os.Getenv("IMAS_IT_SKIP"), ",") {
		if id, reason, ok := strings.Cut(kv, "="); ok {
			skip[strings.TrimSpace(id)] = reason
		}
	}
	root, err := FindRoot()
	if err != nil {
		t.Fatal(err)
	}
	all, err := LoadCases(CasesDir(root))
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]*Case{}
	for _, c := range all {
		byID[c.ID] = c
	}
	osName := localOS(t)
	sp := harness.Sprout{VM: "local", OS: osName, Tenant: 1, SproutID: "local-01", AssetID: "local"}
	d := newLocalDriver(t)
	for _, id := range ids {
		id = strings.TrimSpace(id)
		t.Run(id, func(t *testing.T) {
			c, ok := byID[id]
			if !ok {
				t.Fatalf("no case %s under %s", id, CasesDir(root))
			}
			if r, ok := skip[id]; ok {
				t.Skipf("IMAS_IT_SKIP: %s", r)
			}
			ctx, cancel := context.WithTimeout(context.Background(), CaseLimit(c))
			defer cancel()
			cy := &Cycle{Case: c, Sprout: sp, Driver: d, Vars: NewVars(c, sp, strings.ToLower(harness.Nonce(8))), Limit: CaseLimit(c)}
			Replay(t, cy.Run(ctx))
		})
	}
}
