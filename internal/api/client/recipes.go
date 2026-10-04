// Recipe browsing: the platform recipe tree's dot-notation list and get,
// over sealed imas.api.recipes.list and imas.api.recipes.get (J.3).
//
// These used to go over farmer's HTTPS API (GET /v1/recipes, removed in
// CL.4) with the CLI's bearer token in the Authorization header. Bearer tokens are gone: any
// credential built from the CLI's NKey signature is one a compromised bus
// can mint from a CONNECT nonce (docs/design/
// imas-payload-encryption-design.md, Decision A). So recipe browsing is a
// sealed request like every other CLI call: one mechanism, authenticated
// by the CLI box key, with a sealed reply.
package client

import (
	"encoding/json"
	"fmt"
)

// RecipeInfo mirrors natsapi.RecipeInfo for CLI/web UI unmarshaling.
type RecipeInfo struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Size int64  `json:"size"`
}

// RecipeContent mirrors natsapi.RecipeContent for CLI/web UI unmarshaling.
type RecipeContent struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Content string `json:"content"`
	Size    int64  `json:"size"`
}

// ListRecipes fetches the list of recipes available on the farmer.
func ListRecipes() ([]RecipeInfo, error) {
	resp, err := NatsRequest("recipes.list", nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Recipes []RecipeInfo `json:"recipes"`
	}
	if err := json.Unmarshal(resp, &out); err != nil {
		return nil, fmt.Errorf("list recipes: %w", err)
	}
	if out.Recipes == nil {
		out.Recipes = []RecipeInfo{}
	}
	return out.Recipes, nil
}

// GetRecipe fetches a single recipe's content by dot-notation name.
func GetRecipe(name string) (RecipeContent, error) {
	var result RecipeContent
	resp, err := NatsRequest("recipes.get", map[string]string{"name": name})
	if err != nil {
		return result, err
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return result, fmt.Errorf("get recipe: %w", err)
	}
	return result, nil
}
