package client

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/taigrr/jety"

	"github.com/yogzblr/imas/internal/config"
)

// setupRecipeTestServer starts a TLS test server, trusts its certificate
// as config.ImasRootCA, and points config.FarmerInterface/FarmerAPIPort at
// it — mirroring how the real farmerRecipeClient() verifies a connection
// against a pinned root CA (no InsecureSkipVerify), rather than the
// TLS-bootstrap shortcut internal/pki/pki_test.go's FetchRootCA tests use.
func setupRecipeTestServer(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	ts := httptest.NewTLSServer(handler)
	t.Cleanup(ts.Close)

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	caFile := filepath.Join(t.TempDir(), "rootca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	host, port, ok := strings.Cut(strings.TrimPrefix(ts.URL, "https://"), ":")
	if !ok {
		t.Fatalf("unexpected test server URL: %s", ts.URL)
	}

	origRootCA, origIface, origPort := config.ImasRootCA, config.FarmerInterface, config.FarmerAPIPort
	config.ImasRootCA = caFile
	config.FarmerInterface = host
	config.FarmerAPIPort = port
	t.Cleanup(func() {
		config.ImasRootCA = origRootCA
		config.FarmerInterface = origIface
		config.FarmerAPIPort = origPort
	})

	setupTokenInjectionTest(t)
}

func TestListRecipes_Success(t *testing.T) {
	setupRecipeTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/recipes" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") == "" {
			t.Error("expected Authorization header to be set")
		}
		json.NewEncoder(w).Encode(map[string][]RecipeInfo{
			"recipes": {{Name: "webserver.nginx", Path: "webserver/nginx.imas", Size: 42}},
		})
	})

	recipes, err := ListRecipes()
	if err != nil {
		t.Fatalf("ListRecipes: %v", err)
	}
	if len(recipes) != 1 || recipes[0].Name != "webserver.nginx" {
		t.Fatalf("unexpected recipes: %+v", recipes)
	}
}

func TestGetRecipe_Success(t *testing.T) {
	setupRecipeTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/recipes/webserver.nginx" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(RecipeContent{
			Name: "webserver.nginx", Path: "webserver/nginx.imas",
			Content: "pkg.installed: nginx", Size: 21,
		})
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
	setupRecipeTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	if _, err := GetRecipe("missing.recipe"); err == nil {
		t.Fatal("expected error for missing recipe")
	}
}

func TestListRecipes_NoRootCA(t *testing.T) {
	origRootCA := config.ImasRootCA
	config.ImasRootCA = filepath.Join(t.TempDir(), "does-not-exist.pem")
	t.Cleanup(func() { config.ImasRootCA = origRootCA })

	if _, err := ListRecipes(); err == nil {
		t.Fatal("expected error when root CA file is missing")
	}
}

func TestListRecipes_NoPrivkey(t *testing.T) {
	setupRecipeTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string][]RecipeInfo{"recipes": {}})
	})
	jety.Set("privkey", "")

	if _, err := ListRecipes(); err == nil {
		t.Fatal("expected error when no signing key is configured")
	}
}
