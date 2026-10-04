package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/api/handlers"
	"github.com/yogzblr/imas/internal/cook"
)

// SEC.4: a sprout of one tenant can never fetch another tenant's staged or
// source recipe, at any layer: recipe resolution in cook, staging, the
// /files/ route through the real router, Auth and GetFile without the
// router's path cleaning, and the CLI recipe routes.

const (
	acmeSecret  = "acme-only-secret-step"
	otherSecret = "other-only-secret-step"
)

func tenantRecipeFixture() map[string]string {
	return map[string]string{
		"tenants/t_acme/recipes/private.imas":  "steps:\n  " + acmeSecret + ":\n    cmd.run:\n      - name: echo acme\n",
		"tenants/t_other/recipes/private.imas": "steps:\n  " + otherSecret + ":\n    cmd.run:\n      - name: echo other\n",
		"tenants/t_acme/recipes/acmeonly.imas": "steps:\n  " + acmeSecret + "-2:\n    cmd.run:\n      - name: echo acme\n",
	}
}

func TestTenantRecipes_CrossTenantRefusedAtEveryLayer(t *testing.T) {
	key := installGatewayKey(t)
	srv := newStagingTestServerWithRecipes(t, tenantRecipeFixture(), "t_acme", "t_other")
	exp := time.Now().Add(time.Hour)
	ctx := context.Background()

	// Box keys on record, as enrollment leaves them, so what farmer stages
	// is sealed to each sprout (security review 2026-10-b, B1).
	for _, id := range [][2]string{{"t_acme", "web-01"}, {"t_other", "web-01"}, {"t_other", "web-02"}} {
		recordStagingSprout(t, id[0], id[1])
	}

	// Layer 1, recipe resolution: each tenant's "private" is its own, and
	// t_other cannot cook acme's recipe by name or by a crafted name.
	jidAcme := cook.GenerateJobID()
	if err := cook.SendCookEventContext(ctx, "t_acme", "web-01", "private", jidAcme, false); err != nil {
		t.Fatalf("t_acme cooking its own recipe: %v", err)
	}
	jidOther := cook.GenerateJobID()
	if err := cook.SendCookEventContext(ctx, "t_other", "web-01", "private", jidOther, false); err != nil {
		t.Fatalf("t_other cooking its own recipe: %v", err)
	}
	for _, name := range []cook.RecipeName{"acmeonly", "tenants.t_acme.recipes.acmeonly", "../t_acme/recipes/acmeonly", "../../tenants/t_acme/recipes/acmeonly"} {
		err := cook.SendCookEventContext(ctx, "t_other", "web-02", name, cook.GenerateJobID(), false)
		if !errors.Is(err, cook.ErrNoRecipe) {
			t.Errorf("t_other cooking %q: got %v, want ErrNoRecipe", name, err)
		}
	}

	// Layer 2, staging: each sprout's staged copy holds its own tenant's
	// steps only, opens for that sprout only, and the refused cook staged
	// nothing. Nothing is readable in the served body itself.
	readStaged := func(tenant, sprout string) (int, string) {
		stagedKey, err := cook.StagedRecipeKey(tenant, sprout)
		if err != nil {
			t.Fatal(err)
		}
		return get(t, srv.URL+"/files/"+stagedKey, "Bearer "+mint(t, key.priv, tenant, sprout, exp))
	}
	stepsOf := func(env cook.RecipeEnvelope) string {
		b, _ := json.Marshal(env.Steps)
		return string(b)
	}
	code, body := readStaged("t_acme", "web-01")
	if code != http.StatusOK || strings.Contains(body, acmeSecret) || strings.Contains(body, otherSecret) {
		t.Fatalf("t_acme/web-01 staged: %d %s", code, body)
	}
	env := openStaged(t, "t_acme", "web-01", body)
	if steps := stepsOf(env); env.JobID != jidAcme || !strings.Contains(steps, acmeSecret) || strings.Contains(steps, otherSecret) {
		t.Fatalf("t_acme/web-01 staged envelope: %+v", env)
	}
	code, body = readStaged("t_other", "web-01")
	if code != http.StatusOK || strings.Contains(body, acmeSecret) || strings.Contains(body, otherSecret) {
		t.Fatalf("t_other/web-01 staged: %d %s", code, body)
	}
	env = openStaged(t, "t_other", "web-01", body)
	if steps := stepsOf(env); env.JobID != jidOther || !strings.Contains(steps, otherSecret) || strings.Contains(steps, acmeSecret) {
		t.Fatalf("t_other/web-01 staged envelope: %+v", env)
	}
	if code, _ := readStaged("t_other", "web-02"); code != http.StatusNotFound {
		t.Errorf("t_other/web-02 after refused cooks: got %d, want 404 (nothing staged)", code)
	}

	// Layer 3, /files/ through the real router: t_other's web-01 (the
	// same sprout_id as acme's) asks for acme's staged and source recipes.
	otherToken := "Bearer " + mint(t, key.priv, "t_other", "web-01", exp)
	for _, path := range []string{
		"sprouts/t_acme/web-01/recipe.json",
		"tenants/t_acme/recipes/private.imas",
		"tenants/t_other/recipes/private.imas", // its own tenant's source: not served to sprouts either
		"recipes/webserver.imas",
		"sprouts/t_other/web-01/../../t_acme/web-01/recipe.json",
		"sprouts/t_other/web-01/%2e%2e/%2e%2e/t_acme/web-01/recipe.json",
		"sprouts/t_other/web-01/..%2f..%2ft_acme%2fweb-01%2frecipe.json",
		"sprouts/t_other//web-01/../../t_acme/web-01/recipe.json",
		"sprouts/t_other/web-01/./../../t_acme/web-01/recipe.json",
	} {
		code, body := get(t, srv.URL+"/files/"+path, otherToken)
		if code == http.StatusOK || strings.Contains(body, acmeSecret) {
			t.Errorf("t_other/web-01 GET /files/%s: got %d %q, want refused", path, code, body)
		}
	}

	// Layer 4, Auth and GetFile without the router: a request path the
	// mux would have cleaned or redirected reaches the handler as-is.
	files := Auth(http.HandlerFunc(handlers.GetFile), "FileServer")
	for _, path := range []string{
		"/files/sprouts/t_other/web-01/../../t_acme/web-01/recipe.json",
		"/files/sprouts/t_other/web-01/../../../tenants/t_acme/recipes/private.imas",
		"/files/sprouts/t_other/web-01//../../t_acme/web-01/recipe.json",
		"/files/sprouts/t_acme/web-01/recipe.json",
	} {
		req := httptest.NewRequest(http.MethodGet, "http://farmer/files/x", nil)
		req.URL.Path = path
		req.Header.Set("Authorization", otherToken)
		rec := httptest.NewRecorder()
		files.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), acmeSecret) {
			t.Errorf("Auth+GetFile %s: got %d, want 403", path, rec.Code)
		}
	}
}

// TestTenantRecipes_GetRecipeRefusesCraftedNames: the CLI's GET
// /v1/recipes/{name...} reads the platform tree only, and a crafted name
// cannot reach a tenant's recipes or a sprout's staged file.
func TestTenantRecipes_GetRecipeRefusesCraftedNames(t *testing.T) {
	newStagingTestServerWithRecipes(t, tenantRecipeFixture())
	for _, name := range []string{
		"../tenants/t_acme/recipes/private",
		"..tenants.t_acme.recipes.private",
		"/tenants/t_acme/recipes/private",
		"a/../../tenants/t_acme/recipes/private",
		"..",
	} {
		req := httptest.NewRequest(http.MethodGet, "/v1/recipes/x", nil)
		req.SetPathValue("name", name)
		rec := httptest.NewRecorder()
		handlers.GetRecipe(rec, req)
		if rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), acmeSecret) {
			t.Errorf("GetRecipe(%q): got %d %q, want 400", name, rec.Code, rec.Body.String())
		}
	}
	// A name that is valid but only exists under a tenant prefix is not
	// found in the platform tree.
	req := httptest.NewRequest(http.MethodGet, "/v1/recipes/x", nil)
	req.SetPathValue("name", "tenants.t_acme.recipes.private")
	rec := httptest.NewRecorder()
	handlers.GetRecipe(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GetRecipe(tenants.t_acme.recipes.private): got %d, want 404", rec.Code)
	}
}
