package cook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// ErrStagedRecipeUnverified means the staged recipe this sprout pulled
// did not open as a payloadbox envelope farmer sealed for it under
// payloadbox.PurposeStagedRecipe (stage.go): forged, for another sprout
// or tenant, sealed under a key this sprout doesn't hold, the old plain
// JSON form, or this sprout has no payload-encryption keys. It is never
// cooked, and never recorded as handled, so it can't shadow a real job.
var ErrStagedRecipeUnverified = errors.New("cook: staged recipe did not verify as sealed by farmer for this sprout")

// The download, swappable in tests, which stand in for whatever answers
// GET /files/ (here, possibly a compromised DMZ).
var (
	stagedIdentity  = pki.GatewayJWTIdentity
	fetchFarmerFile = pki.FetchFarmerFile
)

// FetchStagedRecipe is the sprout side of stageRecipe: it downloads this
// sprout's latest dispatched recipe from its staged key
// (StagedRecipeKey, sprouts/<tenant_id>/<sprout_id>/recipe.json) over
// farmer's GET /files/, authenticated with the sprout's gateway JWT
// (pki.FetchFarmerFile, which refreshes an expired or expiring token
// first), and opens it.
//
// The tenant and sprout IDs that pick the key come from the gateway JWT's
// own claims, the pair Auth scopes that token to, so the key is always
// one this sprout may read. A sprout with nothing staged yet gets
// pki.ErrFarmerFileNotFound.
//
// FLAG FOR SECURITY REVIEW (security review 2026-10-b, B1). What comes
// back is trusted for nothing until it opens: the body must be a
// payloadbox envelope under PurposeStagedRecipe that opens with this
// sprout's box key and its pinned tenant key, naming its pinned tenant
// and pinned sprout ID (pki.SproutOpenStagedFromFarmer); anything else,
// plain JSON included, is ErrStagedRecipeUnverified, with no fallback.
// The RecipeEnvelope returned is decoded from inside the opened message
// only, so its JobID and DispatchedAt, which pullStagedRecipe's replay
// and freshness checks use, are farmer's, never the object key's or the
// response's.
func FetchStagedRecipe(ctx context.Context) (RecipeEnvelope, error) {
	tenantID, sproutID, err := stagedIdentity(ctx)
	if err != nil {
		return RecipeEnvelope{}, err
	}
	key, err := StagedRecipeKey(tenantID, sproutID)
	if err != nil {
		return RecipeEnvelope{}, err
	}
	data, err := fetchFarmerFile(ctx, key)
	if err != nil {
		return RecipeEnvelope{}, err
	}
	return openStagedRecipe(data)
}

// openStagedRecipe opens data, a staged recipe as pulled, for this
// sprout: its pinned sprout ID and tenant, its own keys.
func openStagedRecipe(data []byte) (RecipeEnvelope, error) {
	sproutID, err := pki.PinnedSproutID()
	if err != nil {
		return RecipeEnvelope{}, fmt.Errorf("%w: %w", ErrStagedRecipeUnverified, err)
	}
	msg, err := pki.SproutOpenStagedFromFarmer(sproutID, payloadbox.PurposeStagedRecipe, data)
	if err != nil {
		return RecipeEnvelope{}, fmt.Errorf("%w: %w", ErrStagedRecipeUnverified, err)
	}
	var env RecipeEnvelope
	if err := json.Unmarshal(msg.Body, &env); err != nil {
		return RecipeEnvelope{}, fmt.Errorf("%w: its body does not decode as a recipe envelope", ErrStagedRecipeUnverified)
	}
	return env, nil
}
