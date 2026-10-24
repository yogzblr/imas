//go:build uat

package ingredients

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/yogzblr/imas/uat/tests/harness"
)

// flagValue is a test flag's value ("" if it isn't defined).
func flagValue(name string) string {
	if f := flag.Lookup(name); f != nil {
		return f.Value.String()
	}
	return ""
}

// runDeadline is the test binary's deadline less a margin for the
// reverts and the report, or 8 hours.
func runDeadline(t *testing.T) time.Time {
	if d, ok := t.Deadline(); ok {
		return d.Add(-5 * time.Minute)
	}
	return time.Now().Add(8 * time.Hour)
}

// loadAll reads the registry from the source and the case files.
func loadAll(t *testing.T, sc *harness.Scenario) (string, *Registry, []*Case) {
	t.Helper()
	root, err := FindRoot()
	sc.NoErr(err, "finding the repository root (the registry is read from the source)")
	reg, err := LoadRegistry(root)
	sc.NoErr(err, "reading the ingredient registry from the source")
	cases, err := LoadCases(CasesDir(root))
	sc.NoErr(err, "loading the cases from %s", CasesDir(root))
	return root, reg, cases
}

// TestIngredients is the ingredient conformance tier: every case on every
// tenant 1 sprout of a matching OS (and the tenant2 subset on tenant 2's),
// one subtest per case and sprout: TestIngredients/<id>/<t1-ubuntu>.
// Sprouts run in parallel; one sprout runs its cases in (order, id) order.
// A failure is a finding for the ingredient's owner: it names the case,
// the sprout and what differed. Nothing here fixes an ingredient.
func TestIngredients(t *testing.T) {
	sc := harness.Begin(t, "Ingredients")
	_, reg, cases := loadAll(t, sc)
	f := ready(t, sc)
	runM, err := NewMatcher(flagValue("test.run"))
	sc.NoErr(err, "parsing -test.run")
	skipM, err := NewMatcher(flagValue("test.skip"))
	sc.NoErr(err, "parsing -test.skip")

	plan := BuildPlan(reg, cases, f.Sprouts())
	if f.Env.Settings.ContainerSprouts {
		plan.SkipNeed(NeedSELinux, ContainerSkip)
	}
	ctx, cancel := context.WithDeadline(context.Background(), runDeadline(t))
	defer cancel()
	runner := &Runner{
		Driver: harnessDriver{f: f, diag: harness.VMDiagFromEnv()},
		Ready:  f.Ready,
		Nonce:  func() string { return harness.Nonce(8) },
		Selected: func(id, name string) bool {
			return runM.Match("TestIngredients", id, name) && !skipM.MatchSkip("TestIngredients", id, name)
		},
	}
	logEstimate(t, ctx, f, plan, runner.Selected)
	runner.Start(ctx, plan)
	for _, c := range plan.Cases {
		jobs := plan.Jobs[c.ID]
		t.Run(c.ID, func(t *testing.T) {
			if len(jobs) == 0 {
				harness.Begin(t, c.ID).Skipf("no OS to run on: the case and the registry name none")
			}
			for _, j := range jobs {
				t.Run(j.Name, func(t *testing.T) {
					t.Parallel()
					Replay(t, runner.Result(ctx, j))
				})
			}
		})
	}
}

// envCookEstimate overrides the time one cook is estimated to take.
const envCookEstimate = "IMAS_UAT_COOK_ESTIMATE"

// logEstimate times one trivial host call on every VM the selection uses
// (in parallel; the call goes through the same vmctl.sh channel as the
// cases'), estimates each VM's share of the plan from it (Plan.Estimate)
// and logs that against the time left, so a run that cannot fit says so
// at the start rather than with "the run ended before the case ran" at
// the end. It never fails the test.
func logEstimate(t *testing.T, ctx context.Context, f *harness.Fleet, plan *Plan, selected func(id, name string) bool) {
	perCook := 15 * time.Second
	if d, err := time.ParseDuration(os.Getenv(envCookEstimate)); err == nil && d > 0 {
		perCook = d
	}
	vms := map[string]harness.Sprout{}
	for _, c := range plan.Cases {
		for _, j := range plan.Jobs[c.ID] {
			if j.Skip == "" && j.Sprout.VM != "" && selected(c.ID, j.Name) {
				vms[j.Sprout.VM] = j.Sprout
			}
		}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	perCall := map[string]time.Duration{}
	for vm, sp := range vms {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			defer cancel()
			probe := "true"
			if sp.IsWindows() {
				probe = "$null = 0"
			}
			start := time.Now()
			res, err := f.VM.Run(cctx, vm, sp.Family(), probe)
			took := time.Since(start)
			if err != nil || res.ExitCode != 0 {
				t.Logf("ingredients estimate: a trivial host call on %s failed after %s: %v; its cases may fail on the channel (vmctl.sh)", vm, took.Round(time.Second), err)
				return
			}
			mu.Lock()
			perCall[vm] = took
			mu.Unlock()
		}()
	}
	wg.Wait()
	// A VM whose probe failed is estimated at run-command's pace.
	ests := plan.Estimate(selected, perCall, 45*time.Second, perCook)
	var worst VMEstimate
	for _, e := range ests {
		t.Logf("ingredients estimate: %s", e)
		if e.Total > worst.Total {
			worst = e
		}
	}
	deadline, _ := ctx.Deadline()
	left := time.Until(deadline).Round(time.Minute)
	t.Logf("ingredients estimate: VMs run in parallel; the longest, %s, needs about %s (%s a cook, %s); %s left before the run's deadline",
		worst.VM, worst.Total.Round(time.Minute), perCook, envCookEstimate, left)
	if worst.Total > left {
		t.Logf("ingredients estimate: WARNING: %s's cases need about %s more than is left; the cases at the end of its list will fail with \"the run ended before the case ran\"",
			worst.VM, (worst.Total - left).Round(time.Minute))
	}
}

// TestIngredientsCoverage fails when a registered method has neither a
// case nor a written skip on an OS it applies to, and lists every skip
// with its reason in the log and in <report>/ingredients-coverage.txt.
func TestIngredientsCoverage(t *testing.T) {
	sc := harness.Begin(t, "IngredientsCoverage")
	_, reg, cases := loadAll(t, sc)
	rep := Coverage(reg, cases)
	text := rep.String()
	t.Log("\n" + text)
	if dir := reportDir(); dir != "" {
		if err := os.WriteFile(filepath.Join(dir, "ingredients-coverage.txt"), []byte(text), 0o644); err != nil {
			t.Logf("writing the coverage file: %v", err)
		}
	}
	if err := rep.Err(); err != nil {
		sc.Fatalf("the cases don't cover the registry: %v", err)
	}
}

// reportDir is where run.sh writes the report, if it exists.
func reportDir() string {
	dir := os.Getenv("IMAS_UAT_REPORT_DIR")
	if dir == "" && os.Getenv(harness.EnvDir) != "" {
		dir = filepath.Join(os.Getenv(harness.EnvDir), "report")
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return ""
	}
	return dir
}
