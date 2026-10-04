package client

import (
	"encoding/json"
	"testing"
)

// Recipe browsing is a sealed request like every other CLI call: the
// stand-in farmer only answers what opens under the CLI's key.
func TestListRecipes_Success(t *testing.T) {
	defer startTestNATS(t)()
	testFarmer.Handle(t, NatsConn, "recipes.list", func(json.RawMessage) (any, error) {
		return map[string][]RecipeInfo{"recipes": {{Name: "webserver.nginx", Path: "webserver/nginx.imas", Size: 42}}}, nil
	})

	recipes, err := ListRecipes()
	if err != nil {
		t.Fatalf("ListRecipes: %v", err)
	}
	if len(recipes) != 1 || recipes[0].Name != "webserver.nginx" {
		t.Fatalf("unexpected recipes: %+v", recipes)
	}
}

func TestListRecipes_Empty(t *testing.T) {
	defer startTestNATS(t)()
	mockHandler(t, NatsConn, "imas.api.recipes.list", map[string]any{})

	recipes, err := ListRecipes()
	if err != nil || recipes == nil || len(recipes) != 0 {
		t.Fatalf("ListRecipes = %v, %v; want an empty list", recipes, err)
	}
}

func TestGetRecipe_Success(t *testing.T) {
	defer startTestNATS(t)()
	testFarmer.Handle(t, NatsConn, "recipes.get", func(p json.RawMessage) (any, error) {
		var req struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(p, &req); err != nil || req.Name != "webserver.nginx" {
			t.Errorf("recipes.get params %s", p)
		}
		return RecipeContent{Name: "webserver.nginx", Path: "webserver/nginx.imas", Content: "pkg.installed: nginx", Size: 21}, nil
	})

	recipe, err := GetRecipe("webserver.nginx")
	if err != nil {
		t.Fatalf("GetRecipe: %v", err)
	}
	if recipe.Content != "pkg.installed: nginx" {
		t.Fatalf("unexpected content: %q", recipe.Content)
	}
}

func TestGetRecipe_NotFound(t *testing.T) {
	defer startTestNATS(t)()
	mockErrorHandler(t, NatsConn, "imas.api.recipes.get", "recipe missing.recipe not found")

	if _, err := GetRecipe("missing.recipe"); err == nil {
		t.Fatal("expected error for missing recipe")
	}
}

func TestListRecipes_BadJSON(t *testing.T) {
	defer startTestNATS(t)()
	mockBadJSONHandler(t, NatsConn, "imas.api.recipes.list")

	if _, err := ListRecipes(); err == nil {
		t.Fatal("expected an unmarshal error")
	}
}
