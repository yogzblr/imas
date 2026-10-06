//go:build uat

package ingredients

import (
	"context"
	"flag"
	"os"
	"path/filepath"
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
	ctx, cancel := context.WithDeadline(context.Background(), runDeadline(t))
	defer cancel()
	runner := &Runner{
		Driver: harnessDriver{f},
		Ready:  f.Ready,
		Nonce:  func() string { return harness.Nonce(8) },
		Selected: func(id, name string) bool {
			return runM.Match("TestIngredients", id, name) && !skipM.MatchSkip("TestIngredients", id, name)
		},
	}
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
