package natsapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
)

// useRecipeBrowseStore installs a fresh store for recipes.list/get with
// the platform tree under "recipes/", and objects outside it that must
// never be listed or read.
func useRecipeBrowseStore(t *testing.T) {
	t.Helper()
	srv := objectstoretest.NewServer(t)
	s, err := objectstore.Open(srv.Config())
	if err != nil {
		t.Fatal(err)
	}
	SetRecipeStore(s)
	t.Cleanup(func() { SetRecipeStore(nil) })
	origDir := config.RecipeDir
	config.RecipeDir = "recipes"
	t.Cleanup(func() { config.RecipeDir = origDir })
	objectstoretest.Seed(t, s, map[string]string{
		"recipes/webserver/nginx." + config.ImasExt:    "steps: {}\n",
		"recipes/base." + config.ImasExt:               "steps: {}\n",
		"recipes/README.md":                            "not a recipe",
		"tenants/t_a/recipes/secret." + config.ImasExt: "tenant's own",
		"sprouts/t_a/web-01/recipe.json":               `{"rendered":"secret"}`,
		"recipes/big." + config.ImasExt:                strings.Repeat("x", maxRecipeGetBytes+1),
	})
}

func TestHandleRecipesList(t *testing.T) {
	useRecipeBrowseStore(t)
	result, err := handleRecipesList("t_a", nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range result.(map[string][]RecipeInfo)["recipes"] {
		got[r.Name] = true
	}
	if !got["webserver.nginx"] || !got["base"] || !got["big"] || len(got) != 3 {
		t.Fatalf("recipes.list = %v; want the platform tree's recipes only", got)
	}
}

func TestHandleRecipesGet(t *testing.T) {
	useRecipeBrowseStore(t)
	result, err := handleRecipesGet("t_a", json.RawMessage(`{"name":"webserver.nginx"}`))
	if err != nil {
		t.Fatal(err)
	}
	if rc := result.(RecipeContent); rc.Content != "steps: {}\n" || rc.Path != "webserver/nginx."+config.ImasExt {
		t.Fatalf("recipes.get = %+v", rc)
	}
	for name, params := range map[string]string{
		"missing":          `{"name":"nope"}`,
		"empty":            `{"name":""}`,
		"climbing out":     `{"name":"../tenants/t_a/recipes/secret"}`,
		"too large":        `{"name":"big"}`,
		"not JSON":         `{`,
		"absolute":         `{"name":"/sprouts/t_a/web-01/recipe"}`,
		"empty segment":    `{"name":"webserver..nginx"}`,
		"another tenant's": `{"name":"tenants.t_a.recipes.secret"}`,
	} {
		if _, err := handleRecipesGet("t_a", json.RawMessage(params)); err == nil {
			t.Errorf("%s: recipes.get succeeded", name)
		}
	}
}

func TestHandleRecipesNotConfigured(t *testing.T) {
	SetRecipeStore(nil)
	if _, err := handleRecipesList("t_a", nil); err == nil {
		t.Error("recipes.list with no store")
	}
	if _, err := handleRecipesGet("t_a", json.RawMessage(`{"name":"base"}`)); err == nil {
		t.Error("recipes.get with no store")
	}
}
