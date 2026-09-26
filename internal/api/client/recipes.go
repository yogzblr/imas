// Recipe browsing over farmer's dedicated HTTP endpoint
// (internal/api/handlers/recipes.go's ListRecipes/GetRecipe), replacing
// the old imas.api.recipes.list/recipes.get NATS methods — see
// docs/design/imas-fork-roadmap.md workstream I. Authenticates with the
// same signed NKey token NatsRequest injects into NATS payloads (see
// auth.NewToken), carried here as the Authorization header
// internal/api/middleware.go's Auth expects.
package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/yogzblr/imas/internal/auth"
	"github.com/yogzblr/imas/internal/config"
)

// RecipeInfo mirrors handlers.RecipeInfo for CLI/web UI unmarshaling.
type RecipeInfo struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Size int64  `json:"size"`
}

// RecipeContent mirrors handlers.RecipeContent for CLI/web UI unmarshaling.
type RecipeContent struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Content string `json:"content"`
	Size    int64  `json:"size"`
}

// recipeHTTPTimeout bounds a single recipe list/get request.
const recipeHTTPTimeout = 30 * time.Second

// farmerRecipeClient builds an HTTPS client trusted against the same root
// CA NewNatsClient uses, so it works wherever pki.LoadRootCA("imas") has
// already run (root.go's PersistentPreRun, ahead of every CLI command).
func farmerRecipeClient() (*http.Client, error) {
	certPool := x509.NewCertPool()
	rootPEM, err := os.ReadFile(config.ImasRootCA)
	if err != nil || rootPEM == nil {
		return nil, fmt.Errorf("failed to read root CA from %q: %w", config.ImasRootCA, err)
	}
	if !certPool.AppendCertsFromPEM(rootPEM) {
		return nil, fmt.Errorf("failed to parse root CA from %q", config.ImasRootCA)
	}
	tlsCfg := &tls.Config{
		ServerName: config.FarmerInterface,
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS12,
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   recipeHTTPTimeout,
	}, nil
}

// farmerRecipeGet issues an authenticated GET against the farmer's HTTPS
// API and returns the raw response body.
func farmerRecipeGet(path string) ([]byte, error) {
	httpClient, err := farmerRecipeClient()
	if err != nil {
		return nil, err
	}
	reqURL := fmt.Sprintf("https://%s:%s%s", config.FarmerInterface, config.FarmerAPIPort, path)
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	token, err := auth.NewToken()
	if err != nil {
		return nil, fmt.Errorf("failed to create auth token: %w", err)
	}
	req.Header.Set("Authorization", token)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request to %s failed: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response from %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		msg := string(body)
		if msg == "" {
			msg = resp.Status
		}
		return nil, fmt.Errorf("%s: %s", path, msg)
	}
	return body, nil
}

// ListRecipes fetches the list of recipes available on the farmer.
func ListRecipes() ([]RecipeInfo, error) {
	body, err := farmerRecipeGet("/v1/recipes")
	if err != nil {
		return nil, err
	}
	var resp struct {
		Recipes []RecipeInfo `json:"recipes"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("list recipes: %w", err)
	}
	return resp.Recipes, nil
}

// GetRecipe fetches a single recipe's content by dot-notation name.
func GetRecipe(name string) (RecipeContent, error) {
	var result RecipeContent
	body, err := farmerRecipeGet("/v1/recipes/" + url.PathEscape(name))
	if err != nil {
		return result, err
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return result, fmt.Errorf("get recipe: %w", err)
	}
	return result, nil
}
