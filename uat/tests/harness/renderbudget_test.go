package harness

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/props"
	"github.com/yogzblr/imas/uat/tests/harness/fakestack"
)

// RB1's recipes, rendered by internal/cook with its default limits (the
// chart's farmer.recipes.templateLimits), without a cluster: every part
// and both main recipes pass the upload check (cook.ValidateRecipeSource,
// what saasapi runs), the cook including RB1OverParts parts runs out of
// the per-cook range iterations, and the one including RB1InParts
// resolves. Rig rc.15 found the parts' former printf "%09000d" refused at
// upload (recipe_template_failed: the width cap is 1000).
func TestRB1RecipesAgainstCook(t *testing.T) {
	if l := cook.CurrentRenderLimits(); l.MaxRangeIterations != cook.DefaultMaxRangeIterations || l.CookMaxRangeIterations != cook.DefaultCookMaxRangeIterations {
		t.Fatalf("the cook package's limits are not its defaults: %+v", l)
	}
	// The arithmetic: one render of a part inside the per-render limit,
	// the over cook's two renders of each part over the per-cook one, the
	// inside cook's under it.
	if RB1PartIterations > cook.DefaultMaxRangeIterations {
		t.Fatalf("a part renders %d iterations, over the per-render %d", RB1PartIterations, cook.DefaultMaxRangeIterations)
	}
	if over := 2 * RB1OverParts * RB1PartIterations; over <= cook.DefaultCookMaxRangeIterations {
		t.Fatalf("the over cook costs %d, inside the per-cook %d", over, cook.DefaultCookMaxRangeIterations)
	}
	if in := 2 * RB1InParts * RB1PartIterations; in > cook.DefaultCookMaxRangeIterations {
		t.Fatalf("the inside cook costs %d, over the per-cook %d", in, cook.DefaultCookMaxRangeIterations)
	}
	if RB1OverParts > cook.DefaultMaxRecipeIncludes {
		t.Fatalf("%d includes, over the include cap %d", RB1OverParts, cook.DefaultMaxRecipeIncludes)
	}
	// A cap of one fewer iteration per render refuses a part: it renders
	// exactly RB1PartIterations.
	setRenderLimits(t, cook.RenderLimits{MaxRangeIterations: RB1PartIterations - 1})
	if err := cook.ValidateRecipeSource("part", []byte(RB1PartRecipe)); !errors.Is(err, cook.ErrTemplateRangeTooLong) {
		t.Fatalf("a part under a per-render cap of %d: %v, want the range limit", RB1PartIterations-1, err)
	}
	setRenderLimits(t, cook.RenderLimits{MaxRangeIterations: cook.DefaultMaxRangeIterations})

	const tid = "t_rb1aaaaaaaaaaaaa"
	var parts []string
	for i := range RB1OverParts {
		parts = append(parts, fmt.Sprintf("uat.rb1.unit.p%d", i))
	}
	over := RB1MainRecipe(parts, "imas-uat-rb1-unit-over.txt", "rb1 over unit")
	in := RB1MainRecipe(parts[:RB1InParts], "imas-uat-rb1-unit-in.txt", "rb1 in unit")

	// The upload check, for every recipe RB1 uploads.
	for name, src := range map[string]string{"part": RB1PartRecipe, "over": over, "in": in} {
		if err := cook.ValidateRecipeSource(name, []byte(src)); err != nil {
			t.Errorf("uploading %s: %v", name, err)
		}
	}
	// The fake's upload check agrees, and refuses the former width.
	if code, msg := fakestack.CheckRecipe(RB1PartRecipe); code != "" {
		t.Errorf("the fake refuses a part: %s %s", code, msg)
	}
	former := strings.ReplaceAll(RB1PartRecipe, "%01000d", "%09000d")
	if err := cook.ValidateRecipeSource("former", []byte(former)); !errors.Is(err, cook.ErrTemplateArgument) {
		t.Errorf("the former part: %v, want the argument error (printf width)", err)
	}
	if code, _ := fakestack.CheckRecipe(former); code != "recipe_template_failed" {
		t.Errorf("the fake takes the former part: %q", code)
	}

	// The cooks, through the cook package's own resolution: a recipe
	// store holding the tenant's recipes, and props and pki on an
	// in-memory database (the sprout has no box key, so nothing is
	// sealed). A stage guard stops each cook once it has resolved, before
	// any dispatch.
	gdb, err := gorm.Open(sqlite.Open("file:rb1?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := gdb.AutoMigrate(append(props.Models(), pki.Models()...)...); err != nil {
		t.Fatal(err)
	}
	props.SetDB(gdb)
	pki.SetDB(gdb)
	store := objectstoretest.NewStore(t)
	cook.SetStore(store)
	origDir := config.RecipeDir
	config.RecipeDir = "platform-recipes"
	t.Setenv(cook.RecipeDirEnvVar, "")
	t.Cleanup(func() {
		cook.SetStore(nil)
		props.SetDB(nil)
		pki.SetDB(nil)
		config.RecipeDir = origDir
	})
	prefix, err := cook.TenantRecipePrefix(tid)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		prefix + "uat/rb1/unit/over.imas": over,
		prefix + "uat/rb1/unit/in.imas":   in,
	}
	for _, p := range parts {
		files[prefix+strings.ReplaceAll(p, ".", "/")+".imas"] = RB1PartRecipe
	}
	objectstoretest.Seed(t, store, files)

	var mu sync.Mutex
	refused := map[string]error{}
	cook.SetDispatchRefusalRecorder(func(_, _, jid string, err error) {
		mu.Lock()
		defer mu.Unlock()
		refused[jid] = err
	})
	t.Cleanup(func() { cook.SetDispatchRefusalRecorder(nil) })
	errResolved := errors.New("resolved: stopped before dispatch")
	guard := cook.WithStageGuard(func() error { return errResolved })

	err = cook.SendCookEventContext(context.Background(), tid, "rb1-sprout", "uat.rb1.unit.over", "jid-over", false, guard)
	var be *cook.CookBudgetError
	if !errors.As(err, &be) || be.Counter != cook.CookBudgetIterations {
		t.Errorf("the over cook (%d parts): %v, want the per-cook range iterations", RB1OverParts, err)
	}
	if !strings.Contains(fmt.Sprint(err), "cook exceeded its render budget") {
		t.Errorf("the over cook's error %q lacks the text RB1 looks for in farmer's log", err)
	}
	err = cook.SendCookEventContext(context.Background(), tid, "rb1-sprout", "uat.rb1.unit.in", "jid-in", false, guard)
	if !errors.Is(err, errResolved) {
		t.Errorf("the inside cook (%d parts): %v, want it resolved to the stage guard", RB1InParts, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !errors.Is(refused["jid-over"], cook.ErrCookRenderBudget) {
		t.Errorf("the over cook was not refused for its budget (P29's job_refused): %v", refused["jid-over"])
	}
}

// setRenderLimits sets cook's render limits for the rest of t.
func setRenderLimits(t *testing.T, l cook.RenderLimits) {
	t.Helper()
	orig := cook.CurrentRenderLimits()
	if err := cook.SetRenderLimits(l); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cook.SetRenderLimits(orig); err != nil {
			t.Error(err)
		}
	})
}
