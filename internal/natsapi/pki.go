package natsapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/yogzblr/imas/internal/cook"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/pki"
)

func handlePKIList(tenantID string, _ json.RawMessage) (any, error) {
	return pki.ListNKeysByType(tenantID), nil
}

func handlePKIAccept(tenantID string, params json.RawMessage) (any, error) {
	var km pki.KeyManager
	if err := json.Unmarshal(params, &km); err != nil {
		return nil, err
	}
	// Accepting "web-01_1" deletes the existing "web-01" and renames the
	// new host to "web-01" (pki.AcceptNKey), handing it web-01's sprout ID
	// and so its staged recipe prefix.
	base, _, replacesBase := strings.Cut(km.SproutID, "_")
	if replacesBase {
		if err := unstageBeforeIdentityChange(tenantID, base); err != nil {
			return nil, err
		}
	}
	err := pki.AcceptNKey(tenantID, km.SproutID)
	if err != nil {
		return nil, err
	}
	if replacesBase {
		unstageAfterIdentityChange(tenantID, base)
	}
	return map[string]bool{"success": true}, nil
}

func handlePKIReject(tenantID string, params json.RawMessage) (any, error) {
	var km pki.KeyManager
	if err := json.Unmarshal(params, &km); err != nil {
		return nil, err
	}
	err := pki.RejectNKey(tenantID, km.SproutID, "")
	if err != nil {
		return nil, err
	}
	return map[string]bool{"success": true}, nil
}

func handlePKIDeny(tenantID string, params json.RawMessage) (any, error) {
	var km pki.KeyManager
	if err := json.Unmarshal(params, &km); err != nil {
		return nil, err
	}
	err := pki.DenyNKey(tenantID, km.SproutID)
	if err != nil {
		return nil, err
	}
	return map[string]bool{"success": true}, nil
}

func handlePKIUnaccept(tenantID string, params json.RawMessage) (any, error) {
	var km pki.KeyManager
	if err := json.Unmarshal(params, &km); err != nil {
		return nil, err
	}
	err := pki.UnacceptNKey(tenantID, km.SproutID, "")
	if err != nil {
		return nil, err
	}
	return map[string]bool{"success": true}, nil
}

func handlePKIDelete(tenantID string, params json.RawMessage) (any, error) {
	var km pki.KeyManager
	if err := json.Unmarshal(params, &km); err != nil {
		return nil, err
	}
	if err := unstageBeforeIdentityChange(tenantID, km.SproutID); err != nil {
		return nil, err
	}
	err := pki.DeleteNKey(tenantID, km.SproutID)
	if err != nil {
		return nil, err
	}
	unstageAfterIdentityChange(tenantID, km.SproutID)
	return map[string]bool{"success": true}, nil
}

// Sprout IDs come from hostnames and are reused: after a sprout is
// deleted, or replaced through handlePKIAccept, the next host to take its
// sprout ID gets a gateway JWT for the same sprouts/<tenant_id>/<sprout_id>/
// prefix, and would be able to read the recipe staged for the old host
// (see internal/cook/stage.go). So the staged recipe is removed around
// every such change:
//
//   - before it, and the change is refused if that fails, so a store
//     outage can't leave the copy behind with no way to retry;
//   - after it, for a dispatch that staged a recipe in between. A dispatch
//     that stages after this second removal fails its stage guard
//     (sproutIdentityGuard) and removes its own copy.

func unstageBeforeIdentityChange(tenantID, sproutID string) error {
	if err := unstageRecipe(tenantID, sproutID); err != nil {
		return fmt.Errorf("removing staged recipe for sprout %s, sprout left unchanged: %w", sproutID, err)
	}
	return nil
}

func unstageAfterIdentityChange(tenantID, sproutID string) {
	if err := unstageRecipe(tenantID, sproutID); err != nil {
		log.Errorf("removing staged recipe for sprout %s in tenant %s after its identity changed: %v", sproutID, tenantID, err)
	}
}

func unstageRecipe(tenantID, sproutID string) error {
	// An ID that can't form a staged key never had a recipe staged, and
	// with no recipe store nothing can have been staged either: a
	// dispatch reads its recipe from the same store.
	if _, err := cook.StagedRecipeKey(tenantID, sproutID); err != nil {
		return nil
	}
	err := cook.UnstageRecipe(context.Background(), tenantID, sproutID)
	if errors.Is(err, cook.ErrRecipeStoreNotConfigured) {
		return nil
	}
	return err
}
