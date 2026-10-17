package cook

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// The per-cook render budget (security review B4, S4): every render of a
// cook, in both phases (finding includes, building steps), charges one
// budget, made by resolveRecipeSteps.

// setCookLimits lowers (or raises) the render limits for the rest of t,
// directly, as the other render tests do.
func setCookLimits(t *testing.T, l RenderLimits) {
	t.Helper()
	orig := CurrentRenderLimits()
	t.Cleanup(func() {
		MaxRenderedRecipeBytes, RecipeRenderTimeout, maxRangeIterations = orig.MaxRenderedBytes, orig.RenderTimeout, orig.MaxRangeIterations
		cookRenderTimeout, cookMaxRenderedBytes, cookMaxRangeIterations, maxRecipeIncludes = orig.CookRenderTimeout, orig.CookMaxRenderedBytes, orig.CookMaxRangeIterations, orig.MaxIncludes
	})
	if l.MaxRenderedBytes != 0 {
		MaxRenderedRecipeBytes = l.MaxRenderedBytes
	}
	if l.RenderTimeout != 0 {
		RecipeRenderTimeout = l.RenderTimeout
	}
	if l.MaxRangeIterations != 0 {
		maxRangeIterations = l.MaxRangeIterations
	}
	if l.CookRenderTimeout != 0 {
		cookRenderTimeout = l.CookRenderTimeout
	}
	if l.CookMaxRenderedBytes != 0 {
		cookMaxRenderedBytes = l.CookMaxRenderedBytes
	}
	if l.CookMaxRangeIterations != 0 {
		cookMaxRangeIterations = l.CookMaxRangeIterations
	}
	if l.MaxIncludes != 0 {
		maxRecipeIncludes = l.MaxIncludes
	}
}

// writeIncluding writes recipe "main", which includes every recipe of
// bodies (name to source) and has a step of its own, and the recipes
// themselves. It returns the bytes one render of all of them writes
// (their sources, as none prints anything but its own text).
func writeIncluding(t *testing.T, bodies map[string]string) int {
	t.Helper()
	prefix := newRecipeTestStore(t)
	var b strings.Builder
	b.WriteString("include:\n")
	for name := range bodies {
		fmt.Fprintf(&b, "  - %s\n", name)
	}
	b.WriteString("steps:\n  main step:\n    cmd.run:\n      - name: echo main\n")
	writeRecipe(t, filepath.Join(prefix, "main.imas"), b.String())
	total := b.Len()
	for name, body := range bodies {
		writeRecipe(t, filepath.Join(prefix, name+".imas"), body)
		total += len(body)
	}
	return total
}

// plainRecipe is a recipe with one step, named after name, and no
// template actions.
func plainRecipe(name string) string {
	return fmt.Sprintf("steps:\n  %s step:\n    cmd.run:\n      - name: echo %s\n", name, name)
}

// rangeRecipe is a recipe whose one range runs n times.
func rangeRecipe(name string, n int) string {
	return fmt.Sprintf("steps:\n  %s step:\n    cmd.run:\n      - name: echo{{ range split %q \",\" }} x{{ end }}\n", name, strings.TrimSuffix(strings.Repeat("a,", n), ","))
}

func cookBudgetError(t *testing.T, err error, counter string) {
	t.Helper()
	if !errors.Is(err, ErrCookRenderBudget) {
		t.Fatalf("got %v, want ErrCookRenderBudget", err)
	}
	be, ok := errors.AsType[*CookBudgetError](err)
	if !ok || be.Counter != counter {
		t.Fatalf("got %v, want the %s counter", err, counter)
	}
}

func resolveMain(t *testing.T) ([]Step, error) {
	t.Helper()
	return resolveRecipeSteps(context.Background(), testPropsTenantID, "budget-sprout", "main")
}

// Each counter: a cook whose recipes together exceed it fails with
// ErrCookRenderBudget naming it, and the same recipes fit when the limit
// is their cost. Each recipe is rendered once per phase, so the cost of
// a cook is twice one render of every recipe.
func TestCookBudget_EachCounter(t *testing.T) {
	t.Run("iterations", func(t *testing.T) {
		writeIncluding(t, map[string]string{"a": rangeRecipe("a", 6), "b": rangeRecipe("b", 6)})
		const cost = 2 * (6 + 6)
		setCookLimits(t, RenderLimits{MaxRangeIterations: 6, CookMaxRangeIterations: cost - 1})
		_, err := resolveMain(t)
		cookBudgetError(t, err, CookBudgetIterations)
		if !strings.Contains(err.Error(), fmt.Sprintf("total range iterations over %d", cost-1)) {
			t.Errorf("message %q does not name the counter and the limit", err)
		}
		cookMaxRangeIterations = cost
		if steps, err := resolveMain(t); err != nil || len(steps) != 3 {
			t.Fatalf("at the limit: %d steps, %v", len(steps), err)
		}
	})
	t.Run("bytes", func(t *testing.T) {
		one := writeIncluding(t, map[string]string{"a": plainRecipe("a"), "b": plainRecipe("b")})
		cost := 2 * one
		setCookLimits(t, RenderLimits{MaxRenderedBytes: 200, CookMaxRenderedBytes: cost - 1})
		_, err := resolveMain(t)
		cookBudgetError(t, err, CookBudgetBytes)
		if !strings.Contains(err.Error(), fmt.Sprintf("total rendered bytes over %d", cost-1)) {
			t.Errorf("message %q does not name the counter and the limit", err)
		}
		cookMaxRenderedBytes = cost
		if steps, err := resolveMain(t); err != nil || len(steps) != 3 {
			t.Fatalf("at the limit: %d steps, %v", len(steps), err)
		}
	})
	t.Run("time", func(t *testing.T) {
		// Ten recipes, each doing the same work. The budget (and each
		// render's own limit) is about five renders' time, so one render
		// is well inside both, and the cook's twenty renders are not.
		const spin = `{{ range split (printf "%0199d" 0) "" }}{{ range split (printf "%0199d" 0) "" }}{{ $x := upper "a" }}{{ end }}{{ end }}`
		bodies := map[string]string{}
		for i := range 10 {
			name := fmt.Sprintf("r%d", i)
			bodies[name] = spin + plainRecipe(name)
		}
		writeIncluding(t, bodies)
		setCookLimits(t, RenderLimits{MaxRangeIterations: 1 << 40, CookMaxRangeIterations: 1 << 40, RenderTimeout: time.Minute, CookRenderTimeout: 5 * time.Minute})
		start := time.Now()
		if _, err := renderRecipeTemplate(newCookBudget(), testPropsTenantID, "budget-sprout", "r0", []byte(bodies["r0"])); err != nil {
			t.Fatal(err)
		}
		one := max(time.Since(start), 5*time.Millisecond)
		if _, err := resolveMain(t); err != nil {
			t.Fatalf("under a generous budget: %v", err)
		}
		RecipeRenderTimeout, cookRenderTimeout = 5*one, 5*one
		_, err := resolveMain(t)
		cookBudgetError(t, err, CookBudgetTime)
		if !strings.Contains(err.Error(), "total render time over "+(5*one).String()) {
			t.Errorf("message %q does not name the counter and the limit", err)
		}
	})
}

// The budget is the cook's, not a render's: recipes each at 60 percent of
// a counter fail on the second render, though no render is over its own
// limit (which equals the cook's here).
func TestCookBudget_Shared(t *testing.T) {
	writeIncluding(t, map[string]string{"a": rangeRecipe("a", 6), "b": rangeRecipe("b", 6)})
	setCookLimits(t, RenderLimits{MaxRangeIterations: 10, CookMaxRangeIterations: 10})
	for _, name := range []RecipeName{"a", "b"} {
		if _, err := renderRecipeTemplate(newCookBudget(), testPropsTenantID, "budget-sprout", string(name), []byte(rangeRecipe(string(name), 6))); err != nil {
			t.Fatalf("%s alone: %v", name, err)
		}
	}
	budget := newCookBudget()
	if _, err := renderRecipeTemplate(budget, testPropsTenantID, "budget-sprout", "a", []byte(rangeRecipe("a", 6))); err != nil {
		t.Fatalf("first render: %v", err)
	}
	_, err := renderRecipeTemplate(budget, testPropsTenantID, "budget-sprout", "b", []byte(rangeRecipe("b", 6)))
	cookBudgetError(t, err, CookBudgetIterations)
	_, err = resolveMain(t)
	cookBudgetError(t, err, CookBudgetIterations)
}

// Both phases charge the budget: a set of recipes whose one render each
// fits fails at twice that, during step building.
func TestCookBudget_BothPhases(t *testing.T) {
	one := writeIncluding(t, map[string]string{"a": plainRecipe("a"), "b": plainRecipe("b")})
	setCookLimits(t, RenderLimits{MaxRenderedBytes: 200, CookMaxRenderedBytes: one})
	budget := newCookBudget()
	includes, err := collectAllIncludes(context.Background(), budget, testPropsTenantID, "budget-sprout", getBasePath(), "main")
	if err != nil || len(includes) != 3 {
		t.Fatalf("discovery alone: %v, %v", includes, err)
	}
	if budget.bytesUsed != one {
		t.Errorf("discovery charged %d bytes, want %d (each recipe once)", budget.bytesUsed, one)
	}
	_, err = resolveMain(t)
	cookBudgetError(t, err, CookBudgetBytes)
	cookMaxRenderedBytes = 2*one - 1
	_, err = resolveMain(t)
	cookBudgetError(t, err, CookBudgetBytes)
	cookMaxRenderedBytes = 2 * one
	if _, err := resolveMain(t); err != nil {
		t.Fatalf("both phases at the limit: %v", err)
	}
}

// Two cooks at once each have their own budget: each fits its budget
// alone, and they all succeed together.
func TestCookBudget_ConcurrentCooksDoNotShare(t *testing.T) {
	writeIncluding(t, map[string]string{"a": rangeRecipe("a", 6), "b": rangeRecipe("b", 6)})
	setCookLimits(t, RenderLimits{MaxRangeIterations: 6, CookMaxRangeIterations: 24})
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := range 16 {
		wg.Go(func() {
			_, err := resolveRecipeSteps(context.Background(), testPropsTenantID, fmt.Sprintf("budget-sprout-%d", i), "main")
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent cook: %v", err)
		}
	}
}

// The time counter runs across renders: a render that starts with the
// cook's time spent fails at once, and one that starts with little left
// stops when it runs out, though its own limit is far off.
func TestCookBudget_TimeAcrossRenders(t *testing.T) {
	setCookLimits(t, RenderLimits{MaxRangeIterations: 1 << 40, CookMaxRangeIterations: 1 << 40, RenderTimeout: time.Minute, CookRenderTimeout: time.Minute})
	spent := newCookBudget()
	spent.timeUsed = spent.timeLimit
	_, err := renderRecipeTemplate(spent, testPropsTenantID, "budget-sprout", "a", []byte(plainRecipe("a")))
	cookBudgetError(t, err, CookBudgetTime)

	nearly := newCookBudget()
	nearly.timeUsed = nearly.timeLimit - 100*time.Millisecond
	list := `(split (printf "%0999d" 0) "")`
	start := time.Now()
	_, err = renderRecipeTemplate(nearly, testPropsTenantID, "budget-sprout", "a", []byte(`{{ range `+list+` }}{{ range `+list+` }}{{ range `+list+` }}{{ end }}{{ end }}{{ end }}`))
	cookBudgetError(t, err, CookBudgetTime)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("render stopped after %v, want about 100ms", elapsed)
	}
	if nearly.timeUsed < nearly.timeLimit {
		t.Errorf("time used %v not charged up to the limit %v", nearly.timeUsed, nearly.timeLimit)
	}
}

// A budget failure stops the cook before anything is staged.
func TestCookBudget_NothingStaged(t *testing.T) {
	writeIncluding(t, map[string]string{"a": rangeRecipe("a", 6), "b": rangeRecipe("b", 6)})
	setCookLimits(t, RenderLimits{MaxRangeIterations: 6, CookMaxRangeIterations: 10})
	err := SendCookEventContext(context.Background(), testTenantID, "budget-stage-sprout", "main", GenerateJobID(), false)
	cookBudgetError(t, err, CookBudgetIterations)
	key := mustStagedKey(t, testTenantID, "budget-stage-sprout")
	if _, err := store.Get(context.Background(), key); err == nil {
		t.Errorf("%s was staged for a cook over its budget", key)
	}
}

// writeIncludes writes "main" including n plain recipes.
func writeIncludes(t *testing.T, n int) {
	t.Helper()
	bodies := map[string]string{}
	for i := range n {
		name := fmt.Sprintf("inc%03d", i)
		bodies[name] = plainRecipe(name)
	}
	writeIncluding(t, bodies)
}

// The include cap counts the distinct recipes a cook includes (not the
// one it names): 64 by default, settable, with the configured number in
// the error.
func TestCookIncludeCap(t *testing.T) {
	for _, tc := range []struct {
		limit, includes int
		ok              bool
	}{
		{0, 64, true},
		{0, 65, false},
		{3, 3, true},
		{3, 4, false},
		{256, 256, true},
		{256, 257, false},
	} {
		t.Run(fmt.Sprintf("cap %d, %d includes", tc.limit, tc.includes), func(t *testing.T) {
			setCookLimits(t, RenderLimits{MaxIncludes: tc.limit, CookMaxRenderedBytes: 64 << 20})
			writeIncludes(t, tc.includes)
			want := tc.limit
			if want == 0 {
				want = DefaultMaxRecipeIncludes
			}
			steps, err := resolveMain(t)
			if tc.ok {
				if err != nil || len(steps) != tc.includes+1 {
					t.Fatalf("got %d steps, %v; want %d", len(steps), err, tc.includes+1)
				}
				return
			}
			if !errors.Is(err, ErrInvalidFormat) || !errors.Is(err, ErrTooManyIncludes) {
				t.Fatalf("got %v, want ErrInvalidFormat and ErrTooManyIncludes", err)
			}
			if !strings.Contains(err.Error(), fmt.Sprintf("more than %d recipes included", want)) {
				t.Errorf("message %q does not carry the cap %d", err, want)
			}
		})
	}
}

// ValidateRecipeSource (the upload check) refuses a recipe whose own
// include list is over the cap, without resolving any include.
func TestValidateRecipeSource_IncludeCap(t *testing.T) {
	src := func(n int) []byte {
		var b strings.Builder
		b.WriteString("include:\n")
		for i := range n {
			fmt.Fprintf(&b, "  - not.uploaded.yet%d\n", i)
		}
		return []byte(b.String())
	}
	if err := ValidateRecipeSource("r", src(64)); err != nil {
		t.Errorf("64 includes: %v", err)
	}
	err := ValidateRecipeSource("r", src(65))
	if !errors.Is(err, ErrTooManyIncludes) || !errors.Is(err, ErrInvalidFormat) || !strings.Contains(err.Error(), "more than 64") {
		t.Errorf("65 includes: %v", err)
	}
}

// No render runs outside a cook's budget: newRenderState, the only way to
// start a render, takes the budget, and is called only by
// renderRecipeTemplate (which takes one from its caller) and
// ValidateRecipeSource (which makes one); renderRecipeTemplate's callers
// in the cook path pass the cook's.
func TestNoRenderOutsideACookBudget(t *testing.T) {
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	callers := map[string][]string{}
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		{
			for _, d := range f.Decls {
				fn, ok := d.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if call, ok := n.(*ast.CallExpr); ok {
						if id, ok := call.Fun.(*ast.Ident); ok {
							callers[id.Name] = append(callers[id.Name], fn.Name.Name)
						}
					}
					return true
				})
			}
		}
	}
	for callee, want := range map[string][]string{
		"newRenderState":        {"ValidateRecipeSource", "renderRecipeTemplate"},
		"executeRecipeTemplate": {"ValidateRecipeSource", "renderRecipeTemplate"},
		"renderRecipeTemplate":  {"extractIncludes", "resolveRecipeSteps"},
		"newCookBudget":         {"ValidateRecipeSource", "resolveRecipeSteps"},
	} {
		got := slices.Clone(callers[callee])
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("%s is called by %v, want %v", callee, got, want)
		}
	}
}
