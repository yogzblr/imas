// Recipe file serving. This used to be http.FileServer over farmer's
// local-disk basepath (config.RecipeDir) — see
// docs/design/imas-master-plan.md Phase 1: that doesn't survive
// horizontal scaling, since any core replica needs to be able to serve
// any recipe, so reads now go through object storage instead. Git
// remains the source of truth; syncing a merged commit into the bucket
// this reads from is a deploy-time concern (see
// internal/objectstore's package doc), not something this handler does.
//
// ListRecipes/GetRecipe below are this endpoint's dot-notation
// browse/introspect surface (imas CLI's `recipes list`/`recipes show`,
// and the web UI's /api/v1/recipes routes) — the HTTP replacement for
// what used to be internal/natsapi/recipes.go's NATS request/reply
// handlers, per docs/design/imas-fork-roadmap.md workstream I. GetFile
// stays the raw-bytes-by-exact-key download path sprouts use for the
// farmer:// scheme.
package handlers

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/objectstore"
)

// recipeStore is the object-storage backend GetFile reads from. Set once
// at startup via SetRecipeStore.
var recipeStore *objectstore.Store

// SetRecipeStore installs the object-storage backend GetFile reads from.
func SetRecipeStore(s *objectstore.Store) { recipeStore = s }

// GetFile serves a single recipe file's content, reusing the
// authenticated-download shape of internal/ingredients/file/http's
// client-side provider — a bearer token in the Authorization header (see
// Auth in middleware.go), a GET request, and the raw bytes back — for the
// route sprouts already know as the farmer:// scheme's read path.
func GetFile(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/files/")
	if key == "" || strings.HasSuffix(r.URL.Path, "/") {
		http.NotFound(w, r)
		return
	}
	if recipeStore == nil {
		http.Error(w, "recipe store not configured", http.StatusServiceUnavailable)
		return
	}

	data, err := recipeStore.Get(r.Context(), key)
	if err != nil {
		if objectstore.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "failed to read recipe", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// RecipeInfo represents a recipe file in the listing.
type RecipeInfo struct {
	// Name is the dot-notation recipe name (e.g., "webserver.nginx").
	Name string `json:"name"`
	// Path is the object key relative to the recipe root.
	Path string `json:"path"`
	// Size is the file size in bytes.
	Size int64 `json:"size"`
}

// RecipeContent represents the full content of a recipe file.
type RecipeContent struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Content string `json:"content"`
	Size    int64  `json:"size"`
}

func writeRecipeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// ListRecipes handles GET /v1/recipes: a JSON listing of every recipe
// under config.RecipeDir, resolved the same way GetRecipe resolves a
// single one.
func ListRecipes(w http.ResponseWriter, r *http.Request) {
	if recipeStore == nil {
		http.Error(w, "recipe store not configured", http.StatusServiceUnavailable)
		return
	}
	recipeDir := config.RecipeDir
	if recipeDir == "" {
		http.Error(w, "recipe directory not configured", http.StatusServiceUnavailable)
		return
	}

	ctx := r.Context()
	ext := "." + config.ImasExt
	prefix := strings.TrimSuffix(recipeDir, "/") + "/"

	keys, err := recipeStore.List(ctx, prefix)
	if err != nil {
		http.Error(w, "error listing recipes", http.StatusInternalServerError)
		return
	}

	recipes := []RecipeInfo{}
	for _, key := range keys {
		if !strings.HasSuffix(key, ext) {
			continue
		}
		relPath := strings.TrimPrefix(key, prefix)

		// Convert file path to dot-notation recipe name:
		// "webserver/nginx.imas" -> "webserver.nginx"
		name := strings.TrimSuffix(relPath, ext)
		name = strings.ReplaceAll(name, "/", ".")

		size := int64(-1)
		if s, statErr := recipeStore.Size(ctx, key); statErr == nil {
			size = s
		}

		recipes = append(recipes, RecipeInfo{Name: name, Path: relPath, Size: size})
	}

	writeRecipeJSON(w, http.StatusOK, map[string][]RecipeInfo{"recipes": recipes})
}

// GetRecipe handles GET /v1/recipes/{name...}: resolves a dot-notation
// recipe name to an object key and returns its content as JSON.
func GetRecipe(w http.ResponseWriter, r *http.Request) {
	recipeName := r.PathValue("name")
	if recipeName == "" {
		http.Error(w, "recipe name is required", http.StatusBadRequest)
		return
	}
	if recipeStore == nil {
		http.Error(w, "recipe store not configured", http.StatusServiceUnavailable)
		return
	}
	recipeDir := config.RecipeDir
	if recipeDir == "" {
		http.Error(w, "recipe directory not configured", http.StatusServiceUnavailable)
		return
	}

	// Convert dot-notation to an object key. Object storage has no
	// directory-traversal concept the way a local filesystem does — a
	// crafted name containing ".." just names a distinct, harmless key,
	// never a path outside the bucket — so no separate path-traversal
	// check is needed here, same as the NATS handler this replaces.
	relPath := strings.ReplaceAll(recipeName, ".", "/") + "." + config.ImasExt
	key := filepath.Join(recipeDir, relPath)

	content, err := recipeStore.Get(r.Context(), key)
	if err != nil {
		if objectstore.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "cannot read recipe", http.StatusInternalServerError)
		return
	}

	writeRecipeJSON(w, http.StatusOK, RecipeContent{
		Name:    recipeName,
		Path:    relPath,
		Content: string(content),
		Size:    int64(len(content)),
	})
}
