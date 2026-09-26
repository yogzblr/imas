package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
)

func setupRecipeHandlerTest(t *testing.T) {
	t.Helper()
	store := objectstoretest.NewStore(t)
	origStore := recipeStore
	SetRecipeStore(store)
	t.Cleanup(func() { SetRecipeStore(origStore) })

	origDir := config.RecipeDir
	config.RecipeDir = "recipes"
	t.Cleanup(func() { config.RecipeDir = origDir })

	objectstoretest.Seed(t, store, map[string]string{
		"recipes/webserver/nginx.imas":   "pkg.installed:\n  - name: nginx\n",
		"recipes/database/postgres.imas": "pkg.installed:\n  - name: postgresql\n",
		"recipes/README.md":              "not a recipe",
	})
}

func TestListRecipes_Success(t *testing.T) {
	setupRecipeHandlerTest(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/recipes", nil)
	rec := httptest.NewRecorder()
	ListRecipes(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Recipes []RecipeInfo `json:"recipes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Recipes) != 2 {
		t.Fatalf("expected 2 recipes, got %d: %+v", len(resp.Recipes), resp.Recipes)
	}
	names := map[string]bool{}
	for _, r := range resp.Recipes {
		names[r.Name] = true
	}
	if !names["webserver.nginx"] || !names["database.postgres"] {
		t.Errorf("unexpected recipe names: %+v", resp.Recipes)
	}
}

func TestListRecipes_NoStore(t *testing.T) {
	origStore := recipeStore
	SetRecipeStore(nil)
	t.Cleanup(func() { SetRecipeStore(origStore) })

	req := httptest.NewRequest(http.MethodGet, "/v1/recipes", nil)
	rec := httptest.NewRecorder()
	ListRecipes(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}

func TestListRecipes_NoRecipeDir(t *testing.T) {
	setupRecipeHandlerTest(t)
	config.RecipeDir = ""

	req := httptest.NewRequest(http.MethodGet, "/v1/recipes", nil)
	rec := httptest.NewRecorder()
	ListRecipes(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}

func TestGetRecipe_Success(t *testing.T) {
	setupRecipeHandlerTest(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/recipes/webserver.nginx", nil)
	req.SetPathValue("name", "webserver.nginx")
	rec := httptest.NewRecorder()
	GetRecipe(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var rc RecipeContent
	if err := json.Unmarshal(rec.Body.Bytes(), &rc); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if rc.Name != "webserver.nginx" {
		t.Errorf("expected name webserver.nginx, got %q", rc.Name)
	}
	if rc.Content != "pkg.installed:\n  - name: nginx\n" {
		t.Errorf("unexpected content: %q", rc.Content)
	}
}

func TestGetRecipe_NotFound(t *testing.T) {
	setupRecipeHandlerTest(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/recipes/does.not.exist", nil)
	req.SetPathValue("name", "does.not.exist")
	rec := httptest.NewRecorder()
	GetRecipe(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestGetRecipe_MissingName(t *testing.T) {
	setupRecipeHandlerTest(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/recipes/", nil)
	rec := httptest.NewRecorder()
	GetRecipe(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestGetRecipe_NoStore(t *testing.T) {
	origStore := recipeStore
	SetRecipeStore(nil)
	t.Cleanup(func() { SetRecipeStore(origStore) })

	req := httptest.NewRequest(http.MethodGet, "/v1/recipes/webserver.nginx", nil)
	req.SetPathValue("name", "webserver.nginx")
	rec := httptest.NewRecorder()
	GetRecipe(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}
