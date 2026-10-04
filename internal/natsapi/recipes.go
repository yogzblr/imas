package natsapi

// recipes.list and recipes.get: the platform recipe tree's dot-notation
// browse surface for the imas CLI and imas serve, on the sealed API (J.3).
//
// They were HTTP routes (GET /v1/recipes, internal/api/handlers/
// recipes.go) behind the CLI's bearer token. Bearer tokens are gone: a
// credential built from the CLI's NKey signature is one a compromised bus
// can mint from a CONNECT nonce (docs/design/
// imas-payload-encryption-design.md, Decision A). So these are sealed
// requests like every other CLI call. They read the same keys, the
// platform tree only (cook.PlatformRecipePrefix), never tenants/,
// sprouts/ or jobs/.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/objectstore"
)

// recipeStore is the object store recipes are browsed in: the one farmer
// reads recipes from (cmd/farmer installs it with SetRecipeStore).
var recipeStore *objectstore.Store

// SetRecipeStore installs the object store recipes.list and recipes.get
// read.
func SetRecipeStore(s *objectstore.Store) { recipeStore = s }

// maxRecipeGetBytes bounds a recipe recipes.get returns, so its sealed
// reply (JSON-escaped, sealed once per tenant key, base64) stays well
// inside the bus's default 1 MiB payload limit.
const maxRecipeGetBytes = 256 << 10

// recipeOpTimeout bounds one recipes.* call's object store work.
const recipeOpTimeout = 30 * time.Second

// RecipeInfo is one recipe in recipes.list.
type RecipeInfo struct {
	// Name is the dot-notation recipe name (e.g., "webserver.nginx").
	Name string `json:"name"`
	// Path is the object key relative to the recipe root.
	Path string `json:"path"`
	// Size is the file size in bytes, or -1 if unknown.
	Size int64 `json:"size"`
}

// RecipeContent is recipes.get's answer.
type RecipeContent struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Content string `json:"content"`
	Size    int64  `json:"size"`
}

var (
	errRecipeStoreNotConfigured = errors.New("recipe store not configured")
	errRecipeDirNotConfigured   = errors.New("recipe directory not configured")
)

func platformRecipePrefix() (string, error) {
	if recipeStore == nil {
		return "", errRecipeStoreNotConfigured
	}
	if config.RecipeDir == "" {
		return "", errRecipeDirNotConfigured
	}
	prefix, err := cook.PlatformRecipePrefix(config.RecipeDir)
	if err != nil {
		return "", errors.New("recipe directory not usable")
	}
	return prefix, nil
}

func handleRecipesList(_ string, _ json.RawMessage) (any, error) {
	prefix, err := platformRecipePrefix()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), recipeOpTimeout)
	defer cancel()
	keys, err := recipeStore.List(ctx, prefix)
	if err != nil {
		return nil, errors.New("error listing recipes")
	}
	ext := "." + config.ImasExt
	recipes := []RecipeInfo{}
	for _, key := range keys {
		if !strings.HasSuffix(key, ext) {
			continue
		}
		relPath := strings.TrimPrefix(key, prefix)
		// "webserver/nginx.imas" -> "webserver.nginx"
		name := strings.ReplaceAll(strings.TrimSuffix(relPath, ext), "/", ".")
		size := int64(-1)
		if s, statErr := recipeStore.Size(ctx, key); statErr == nil {
			size = s
		}
		recipes = append(recipes, RecipeInfo{Name: name, Path: relPath, Size: size})
	}
	return map[string][]RecipeInfo{"recipes": recipes}, nil
}

func handleRecipesGet(_ string, params json.RawMessage) (any, error) {
	var p RecipesGetRequest
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	if p.Name == "" {
		return nil, errors.New("recipe name is required")
	}
	// A name cook would accept: no "..", empty segment or leading slash.
	segments, _, err := cook.ParseRecipeName(p.Name)
	if err != nil {
		return nil, errors.New("invalid recipe name")
	}
	prefix, err := platformRecipePrefix()
	if err != nil {
		return nil, err
	}
	relPath := strings.Join(segments, "/") + "." + config.ImasExt
	ctx, cancel := context.WithTimeout(context.Background(), recipeOpTimeout)
	defer cancel()
	content, err := recipeStore.GetLimited(ctx, prefix+relPath, maxRecipeGetBytes)
	switch {
	case objectstore.IsNotExist(err):
		return nil, fmt.Errorf("recipe %s not found", p.Name)
	case errors.Is(err, objectstore.ErrObjectTooLarge):
		return nil, fmt.Errorf("recipe %s is larger than %d bytes, too large to show here", p.Name, maxRecipeGetBytes)
	case err != nil:
		return nil, errors.New("cannot read recipe")
	}
	return RecipeContent{Name: p.Name, Path: relPath, Content: string(content), Size: int64(len(content))}, nil
}
