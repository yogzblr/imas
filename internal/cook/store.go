package cook

import (
	"context"
	"errors"

	"github.com/yogzblr/imas/internal/objectstore"
)

// store is the object-storage backend recipes are read from — see
// docs/design/imas-master-plan.md Phase 1: farmer's local-disk recipe
// tree (config.RecipeDir/IMAS_RECIPE_DIR) doesn't survive horizontal
// scaling, since any replica needs to be able to serve any recipe. Git
// remains the source of truth; this package only reads what's already
// been synced into the bucket.
var store *objectstore.Store

// SetStore installs the object-storage backend this package reads
// recipes from. Call once at startup, mirroring RegisterNatsConn's
// injection pattern.
func SetStore(s *objectstore.Store) { store = s }

// readRecipe returns the content of the recipe object at key. It mirrors
// internal/api/handlers/recipes.go's GetFile: no store is a distinct,
// explicit error (never a silent local-disk fallback — that would hide
// exactly the cross-replica inconsistency object storage exists to
// close), and a missing key maps to ErrNoRecipe via objectstore.IsNotExist.
func readRecipe(ctx context.Context, key string) ([]byte, error) {
	if store == nil {
		return nil, ErrRecipeStoreNotConfigured
	}
	data, err := store.Get(ctx, key)
	if err != nil {
		if objectstore.IsNotExist(err) {
			return nil, errors.Join(ErrNoRecipe, err)
		}
		return nil, err
	}
	return data, nil
}

// recipeExists reports whether key is present in the recipe store, with
// the same not-configured handling as readRecipe.
func recipeExists(ctx context.Context, key string) (bool, error) {
	if store == nil {
		return false, ErrRecipeStoreNotConfigured
	}
	return store.Exists(ctx, key)
}
