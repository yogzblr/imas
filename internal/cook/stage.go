package cook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/yogzblr/imas/internal/log"
)

// Staged recipes: a copy of the rendered, sprout-specific RecipeEnvelope
// SendCookEventContext pushes to a sprout over NATS, written to the
// recipe bucket under that sprout's own key prefix so the sprout can
// fetch it over HTTP (GET /files/<key>, internal/api/handlers/recipes.go's
// GetFile) with its gateway JWT.
//
// NATS push stays the dispatch path: a cook is still triggered by
// farmer's request on imas.sprouts.<id>.cook, and the pushed envelope is
// what the sprout executes. The staged copy is a second, pull-readable
// copy of that same envelope, for a sprout that needs its current
// recipe again without farmer re-pushing it.
//
// # Key layout
//
//	sprouts/<tenant_id>/<sprout_id>/recipe.json
//
// The prefix is the one internal/api's Auth grants a gateway JWT
// (handlers.SproutFilePrefix, which this package can't import because
// handlers imports cook). internal/api's staged-recipe tests check the
// two agree. The key sits at the bucket root, outside config.RecipeDir,
// because GetFile reads keys verbatim.
//
// # Staleness
//
// One fixed object name per (tenant_id, sprout_id), overwritten on every
// dispatch, rather than one object per job. GetFile serves whatever key
// it's asked for, so versioned objects would all stay readable. With a
// fixed name the sprout can only ever read the latest recipe farmer
// dispatched to it. The envelope carries its JobID, so a reader can tell
// which dispatch it came from.
//
// If the overwrite fails, stageRecipe deletes the old object, so a failed
// write never leaves an older recipe readable in place of the one being
// pushed. If the delete fails too, the dispatch is refused.
//
// The copy is written before the push, so it is in place by the time the
// sprout receives the job, and it is kept whether or not the push
// succeeds: it records the recipe farmer last assigned to the sprout.

// stagedRecipeRoot is the top-level key prefix under which each sprout's
// staged files live. It must match handlers.sproutFileRoot.
const stagedRecipeRoot = "sprouts/"

// StagedRecipeName is the fixed object name, under a sprout's prefix,
// of its latest dispatched recipe.
const StagedRecipeName = "recipe.json"

// StagedRecipeKey returns the object key a sprout's latest dispatched
// recipe is staged at: sprouts/<tenant_id>/<sprout_id>/recipe.json. It
// is keyed on the (tenant_id, sprout_id) pair, never sprout_id alone,
// since a sprout_id is only unique within its tenant. It returns an error
// if either ID can't stand as a single key segment, since that could put
// the key under another sprout's prefix (e.g. tenant "t/web-01").
func StagedRecipeKey(tenantID, sproutID string) (string, error) {
	if !isStageKeySegment(tenantID) || !isStageKeySegment(sproutID) {
		return "", fmt.Errorf("cook: tenant %q / sprout %q not usable as a staged recipe key", tenantID, sproutID)
	}
	return stagedRecipeRoot + tenantID + "/" + sproutID + "/" + StagedRecipeName, nil
}

// isStageKeySegment mirrors internal/api's isKeySegment, which Auth
// applies to a gateway JWT's tenant_id and sprout_id: a key written under
// IDs Auth would reject could never be read by the sprout anyway.
func isStageKeySegment(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\\\x00")
}

// stageRecipe writes env to sproutID's staged recipe key, replacing the
// previous one. See the staleness notes above for what happens on
// failure.
func stageRecipe(ctx context.Context, tenantID, sproutID string, env RecipeEnvelope) error {
	if store == nil {
		return ErrRecipeStoreNotConfigured
	}
	key, err := StagedRecipeKey(tenantID, sproutID)
	if err != nil {
		return err
	}
	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("cook: encoding staged recipe for %s/%s: %w", tenantID, sproutID, err)
	}
	putErr := store.Put(ctx, key, data)
	if putErr == nil {
		return nil
	}
	log.Errorf("cook: staging recipe for job %s at %s failed, removing the previous copy: %v", env.JobID, key, putErr)
	if delErr := store.Delete(ctx, key); delErr != nil {
		return errors.Join(
			fmt.Errorf("cook: staging recipe at %s: %w", key, putErr),
			fmt.Errorf("cook: removing stale staged recipe at %s: %w", key, delErr),
		)
	}
	return nil
}

// UnstageRecipe removes sproutID's staged recipe, if any. Deleting a key
// that doesn't exist is not an error. Call it when a sprout is deleted:
// sprout IDs come from hostnames and are reused, so a new host enrolling
// under the same (tenant_id, sprout_id) would otherwise be able to read
// the recipe staged for the old one.
func UnstageRecipe(ctx context.Context, tenantID, sproutID string) error {
	if store == nil {
		return ErrRecipeStoreNotConfigured
	}
	key, err := StagedRecipeKey(tenantID, sproutID)
	if err != nil {
		return err
	}
	return store.Delete(ctx, key)
}
