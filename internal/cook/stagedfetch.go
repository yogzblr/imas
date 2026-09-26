package cook

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/yogzblr/imas/internal/pki"
)

// FetchStagedRecipe is the sprout side of stageRecipe: it downloads this
// sprout's latest dispatched recipe from its staged key
// (StagedRecipeKey, sprouts/<tenant_id>/<sprout_id>/recipe.json) over
// farmer's GET /files/, authenticated with the sprout's gateway JWT
// (pki.FetchFarmerFile, which refreshes an expired or expiring token
// first).
//
// The tenant and sprout IDs come from the gateway JWT's own claims, the
// pair Auth scopes that token to, so the key is always one this sprout
// may read. A sprout with nothing staged yet gets pki.ErrFarmerFileNotFound.
func FetchStagedRecipe(ctx context.Context) (RecipeEnvelope, error) {
	tenantID, sproutID, err := pki.GatewayJWTIdentity(ctx)
	if err != nil {
		return RecipeEnvelope{}, err
	}
	key, err := StagedRecipeKey(tenantID, sproutID)
	if err != nil {
		return RecipeEnvelope{}, err
	}
	data, err := pki.FetchFarmerFile(ctx, key)
	if err != nil {
		return RecipeEnvelope{}, err
	}
	var env RecipeEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return RecipeEnvelope{}, fmt.Errorf("cook: decoding staged recipe %s: %w", key, err)
	}
	return env, nil
}
