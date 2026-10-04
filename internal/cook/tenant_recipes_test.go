package cook

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
)

// SEC.4: a recipe name resolves under the cooking sprout's tenant's
// prefix, then the platform prefix, and never under another tenant's.

func seedTenantRecipes(t *testing.T) {
	t.Helper()
	newRecipeTestStore(t) // platform prefix "recipes"
	objectstoretest.Seed(t, store, map[string]string{
		"recipes/shared.imas":             "steps:\n  platform:\n    cmd.run:\n      - name: echo platform\n",
		"recipes/web/init.imas":           "steps:\n  platform web:\n    cmd.run:\n      - name: echo platform web\n",
		"tenants/t_a/recipes/web.imas":    "steps:\n  a web:\n    cmd.run:\n      - name: echo a\n",
		"tenants/t_a/recipes/a/only.imas": "include:\n  - shared\nsteps:\n  a only:\n    cmd.run:\n      - name: echo a only\n",
		"tenants/t_b/recipes/secret.imas": "steps:\n  b secret:\n    cmd.run:\n      - name: echo b secret\n",
		"tenants/t_b/recipes/web.imas":    "steps:\n  b web:\n    cmd.run:\n      - name: echo b\n",
		"sprouts/t_b/web-01/recipe.json":  `{"job_id":"b"}`,
	})
}

func TestRecipeResolution_TenantThenPlatform(t *testing.T) {
	seedTenantRecipes(t)
	ctx := context.Background()
	for _, tc := range []struct {
		tenant, name, want string
	}{
		{"t_a", "web", "tenants/t_a/recipes/web.imas"},
		{"t_b", "web", "tenants/t_b/recipes/web.imas"},
		{"t_c", "web", "recipes/web/init.imas"},
		{"t_a", "shared", "recipes/shared.imas"},
		{"t_a", "a.only", "tenants/t_a/recipes/a/only.imas"},
		{"t_a", "a/only", "tenants/t_a/recipes/a/only.imas"},
	} {
		got, err := ResolveRecipeFilePath(ctx, tc.tenant, getBasePath(), RecipeName(tc.name))
		if err != nil || got != tc.want {
			t.Errorf("%s %q: got %q, %v; want %q", tc.tenant, tc.name, got, err, tc.want)
		}
	}
}

// TestRecipeResolution_CrossTenantRefused: no name, plain or crafted,
// gets tenant A another tenant's recipe or staged file.
func TestRecipeResolution_CrossTenantRefused(t *testing.T) {
	seedTenantRecipes(t)
	ctx := context.Background()
	for _, name := range []string{
		"secret",
		"tenants.t_b.recipes.secret",
		"../tenants/t_b/recipes/secret",
		"../../t_b/recipes/secret",
		"..t_b.recipes.secret",
		"/tenants/t_b/recipes/secret",
		"a/../../../t_b/recipes/secret",
		"sprouts.t_b.web-01.recipe",
		"secret%2e",
		"sec ret",
		"",
		".",
		"a..b",
	} {
		key, err := ResolveRecipeFilePath(ctx, "t_a", getBasePath(), RecipeName(name))
		if err == nil || !errors.Is(err, ErrNoRecipe) {
			t.Errorf("t_a resolving %q: got %q, %v; want ErrNoRecipe", name, key, err)
		}
	}
	// And through the full render path: nothing is read or rendered.
	if _, err := resolveRecipeSteps(ctx, "t_a", "web-01", "secret"); !errors.Is(err, ErrNoRecipe) {
		t.Errorf("t_a cooking t_b's recipe: got %v, want ErrNoRecipe", err)
	}
}

// TestRecipeResolution_RelativeIncludeCannotClimb: a relative include is
// resolved like any name and cannot climb into another prefix.
func TestRecipeResolution_RelativeIncludeCannotClimb(t *testing.T) {
	seedTenantRecipes(t)
	objectstoretest.Seed(t, store, map[string]string{
		"tenants/t_a/recipes/climb.imas": "include:\n  - ./../../t_b/recipes/secret\nsteps: {}\n",
		"tenants/t_a/recipes/abs.imas":   "include:\n  - tenants.t_b.recipes.secret\nsteps: {}\n",
	})
	for _, name := range []RecipeName{"climb", "abs"} {
		if _, err := resolveRecipeSteps(context.Background(), "t_a", "web-01", name); !errors.Is(err, ErrNoRecipe) {
			t.Errorf("%s: got %v, want ErrNoRecipe", name, err)
		}
	}
}

// TestRecipeResolution_TenantIncludesPlatform: a tenant recipe can include
// a platform recipe.
func TestRecipeResolution_TenantIncludesPlatform(t *testing.T) {
	seedTenantRecipes(t)
	steps, err := resolveRecipeSteps(context.Background(), "t_a", "web-01", "a.only")
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 2 {
		t.Fatalf("got %d steps, want a only + platform", len(steps))
	}
}

// TestPlatformRecipePrefix_ReservedRefused: an empty platform prefix, or
// one under tenants/, sprouts/ or jobs/, is refused rather than letting a
// name reach those trees.
func TestPlatformRecipePrefix_ReservedRefused(t *testing.T) {
	seedTenantRecipes(t)
	for _, base := range []string{"", ".", "/", "tenants", "tenants/t_a", "/tenants/t_b/recipes", "sprouts/", "jobs", "./tenants"} {
		if _, err := PlatformRecipePrefix(base); !errors.Is(err, ErrRecipePrefixInvalid) {
			t.Errorf("PlatformRecipePrefix(%q): got %v, want ErrRecipePrefixInvalid", base, err)
		}
		if key, err := ResolveRecipeFilePath(context.Background(), "t_a", base, "tenants.t_b.recipes.secret"); err == nil {
			t.Errorf("basepath %q: resolved %q", base, key)
		}
	}
	for _, base := range []string{"recipes", "/srv/imas/recipes/prod", "recipes/v1.2"} {
		if _, err := PlatformRecipePrefix(base); err != nil {
			t.Errorf("PlatformRecipePrefix(%q): %v", base, err)
		}
	}
	orig := config.RecipeDir
	config.RecipeDir = ""
	t.Cleanup(func() { config.RecipeDir = orig })
	if _, err := resolveRecipeSteps(context.Background(), "t_a", "web-01", "tenants.t_b.recipes.secret"); err == nil {
		t.Error("empty recipe dir: cross-tenant name resolved")
	}
}

func TestTenantRecipePrefix_InvalidTenant(t *testing.T) {
	for _, tenant := range []string{"", ".", "..", "t/b", `t\b`, "t\x00"} {
		if _, err := TenantRecipePrefix(tenant); !errors.Is(err, ErrRecipePrefixInvalid) {
			t.Errorf("TenantRecipePrefix(%q): got %v", tenant, err)
		}
	}
}

func TestParseRecipeName(t *testing.T) {
	for name, want := range map[string]string{
		"web":              "web",
		"web.nginx":        "web/nginx",
		"web/nginx":        "web/nginx",
		"apache.init.imas": "apache/init",
		"a_b-c.D9":         "a_b-c/D9",
	} {
		segs, _, err := ParseRecipeName(name)
		if err != nil {
			t.Errorf("%q: %v", name, err)
			continue
		}
		if got := strings.Join(segs, "/"); got != want {
			t.Errorf("%q: got %q, want %q", name, got, want)
		}
	}
}
