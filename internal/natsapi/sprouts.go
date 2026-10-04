package natsapi

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/yogzblr/imas/internal/heartbeat"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/rbac"
)

// SproutInfo represents a sprout with its key state and connectivity status.
type SproutInfo struct {
	ID        string `json:"id"`
	KeyState  string `json:"key_state"`
	Connected bool   `json:"connected"`
	NKey      string `json:"nkey,omitempty"`
}

func handleSproutsList(c apiCaller, params json.RawMessage) (any, error) {
	tenantID := c.TenantID
	allKeys := pki.ListNKeysByType(tenantID)
	var sprouts []SproutInfo

	type entry struct {
		id    string
		state string
	}
	var entries []entry
	for _, km := range allKeys.Accepted.Sprouts {
		entries = append(entries, entry{id: km.SproutID, state: "accepted"})
	}
	for _, km := range allKeys.Unaccepted.Sprouts {
		entries = append(entries, entry{id: km.SproutID, state: "unaccepted"})
	}
	for _, km := range allKeys.Denied.Sprouts {
		entries = append(entries, entry{id: km.SproutID, state: "denied"})
	}
	for _, km := range allKeys.Rejected.Sprouts {
		entries = append(entries, entry{id: km.SproutID, state: "rejected"})
	}

	for _, e := range entries {
		info := SproutInfo{
			ID:       e.id,
			KeyState: e.state,
		}
		nkey, err := pki.GetNKey(tenantID, e.id)
		if err == nil {
			info.NKey = nkey
		}
		if e.state == "accepted" && natsConnFor(tenantID) != nil {
			info.Connected = probeSprout(tenantID, e.id)
		}
		sprouts = append(sprouts, info)
	}

	if sprouts == nil {
		sprouts = []SproutInfo{}
	}

	// Scope filtering: only the sprouts the verified user may view. A
	// user with no role sees none (UserScopeFilter returns nil).
	allIDs := make([]string, len(sprouts))
	for i, s := range sprouts {
		allIDs[i] = s.ID
	}
	allowedSet := make(map[string]bool, len(allIDs))
	for _, id := range filterSproutsByScope(tenantID, c.UserID, rbac.ActionView, allIDs) {
		allowedSet[id] = true
	}
	filtered := make([]SproutInfo, 0, len(allowedSet))
	for _, s := range sprouts {
		if allowedSet[s.ID] {
			filtered = append(filtered, s)
		}
	}
	sprouts = filtered

	return map[string][]SproutInfo{"sprouts": sprouts}, nil
}

func handleSproutsGet(tenantID string, params json.RawMessage) (any, error) {
	var km pki.KeyManager
	if err := json.Unmarshal(params, &km); err != nil {
		return nil, err
	}
	if !pki.IsValidSproutID(km.SproutID) {
		return nil, fmt.Errorf("invalid sprout ID")
	}

	nkey, err := pki.GetNKey(tenantID, km.SproutID)
	if err != nil {
		return nil, fmt.Errorf("sprout not found")
	}

	keyState := resolveKeyState(tenantID, km.SproutID)
	info := SproutInfo{
		ID:       km.SproutID,
		KeyState: keyState,
		NKey:     nkey,
	}

	if keyState == "accepted" && natsConnFor(tenantID) != nil {
		info.Connected = probeSprout(tenantID, km.SproutID)
	}

	return info, nil
}

// probeSprout reports whether sproutID, within tenantID, currently has a
// live NATS connection to farmer. This used to be a synchronous
// request/reply ping to the sprout itself (up to sproutPingTimeout=3s per
// call, ~10x over the <300ms budget for a fleet-listing request) — it now
// reads a Valkey heartbeat key maintained by internal/heartbeat's
// $SYS.ACCOUNT.*.CONNECT/DISCONNECT listener, a single fast local read
// instead of a round trip to the sprout. See
// docs/design/imas-master-plan.md Phase 1.
func probeSprout(tenantID, sproutID string) bool {
	if natsConnFor(tenantID) == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return heartbeat.IsOnline(ctx, tenantID, sproutID)
}

func resolveKeyState(tenantID, sproutID string) string {
	allKeys := pki.ListNKeysByType(tenantID)
	for _, km := range allKeys.Accepted.Sprouts {
		if km.SproutID == sproutID {
			return "accepted"
		}
	}
	for _, km := range allKeys.Unaccepted.Sprouts {
		if km.SproutID == sproutID {
			return "unaccepted"
		}
	}
	for _, km := range allKeys.Denied.Sprouts {
		if km.SproutID == sproutID {
			return "denied"
		}
	}
	for _, km := range allKeys.Rejected.Sprouts {
		if km.SproutID == sproutID {
			return "rejected"
		}
	}
	return "unknown"
}
