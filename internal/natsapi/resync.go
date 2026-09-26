package natsapi

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/pki"
)

// nudgeSprout is cook.NudgeSprout, swappable in tests.
var nudgeSprout = cook.NudgeSprout

// handleCookResync nudges each targeted sprout to pull its staged recipe
// (cook.NudgeSprout), for an operator to resync sprouts without
// re-dispatching. A sprout cooks what it pulls only if it missed that job
// and the job is recent (cook.SyncStagedRecipe), so this needs the same
// scoped "cook" permission as a dispatch. Each target's result is
// apitypes.ResyncResult.
func handleCookResync(tenantID string, params json.RawMessage) (any, error) {
	var ta apitypes.TargetedAction
	if err := json.Unmarshal(params, &ta); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}
	if len(ta.Target) == 0 {
		return nil, fmt.Errorf("no targets specified")
	}
	for _, target := range ta.Target {
		if !pki.IsValidSproutID(target.SproutID) || strings.Contains(target.SproutID, "_") {
			return nil, fmt.Errorf("invalid sprout ID: %s", target.SproutID)
		}
		if registered, _ := pki.NKeyExists(tenantID, target.SproutID, ""); !registered {
			return nil, fmt.Errorf("unknown sprout: %s", target.SproutID)
		}
	}

	results := apitypes.TargetedResults{Results: make(map[string]interface{}, len(ta.Target))}
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, target := range ta.Target {
		wg.Add(1)
		go func(sproutID string) {
			defer wg.Done()
			res := apitypes.ResyncResult{Nudged: true}
			if err := nudgeSprout(tenantID, sproutID); err != nil {
				res = apitypes.ResyncResult{Error: err.Error()}
			}
			mu.Lock()
			results.Results[sproutID] = res
			mu.Unlock()
		}(target.SproutID)
	}
	wg.Wait()
	return results, nil
}
