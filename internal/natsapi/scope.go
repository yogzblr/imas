package natsapi

import (
	"encoding/json"
	"fmt"

	intauth "github.com/yogzblr/imas/internal/auth"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/rbac"
)

// scopeExtractor extracts target sprout IDs from NATS API params.
// It returns the sprout IDs that the request targets, or nil if the
// method is not scoped (global actions like PKI, auth).
type scopeExtractor func(params json.RawMessage) ([]string, error)

// scopeExtractors maps NATS API methods to their scope extraction
// functions. Methods not in this map skip scope-level checks (they
// rely on action-level checks from authMiddleware only).
var scopeExtractors = map[string]scopeExtractor{
	// TargetedAction methods — extract from target[].sprout_id
	"cook":        extractTargetedSproutIDs,
	"cmd.run":     extractTargetedSproutIDs,
	"test.ping":   extractTargetedSproutIDs,
	"shell.start": extractShellSproutID,

	// Props methods — extract from sprout_id field
	"props.getall": extractPropsSproutID,
	"props.get":    extractPropsSproutID,
	"props.set":    extractPropsSproutID,
	"props.delete": extractPropsSproutID,

	// Jobs scoped to a sprout
	"jobs.forsprout": extractJobsForSproutID,

	// Sprout detail
	"sprouts.get": extractSproutsGetID,
}

// targetedParams extracts sprout IDs from TargetedAction-style params.
type targetedParams struct {
	Target []struct {
		SproutID string `json:"sprout_id"`
	} `json:"target"`
}

func extractTargetedSproutIDs(params json.RawMessage) ([]string, error) {
	var tp targetedParams
	if err := json.Unmarshal(params, &tp); err != nil {
		return nil, fmt.Errorf("invalid targeted params: %w", err)
	}
	if len(tp.Target) == 0 {
		return nil, fmt.Errorf("no targets specified")
	}
	ids := make([]string, len(tp.Target))
	for i, t := range tp.Target {
		if t.SproutID == "" {
			return nil, fmt.Errorf("target %d: sprout_id is required", i)
		}
		ids[i] = t.SproutID
	}
	return ids, nil
}

type sproutIDParam struct {
	SproutID string `json:"sprout_id"`
}

func extractShellSproutID(params json.RawMessage) ([]string, error) {
	var p sproutIDParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid shell params: %w", err)
	}
	if p.SproutID == "" {
		return nil, fmt.Errorf("sprout_id is required")
	}
	return []string{p.SproutID}, nil
}

func extractPropsSproutID(params json.RawMessage) ([]string, error) {
	var p sproutIDParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid props params: %w", err)
	}
	if p.SproutID == "" {
		return nil, fmt.Errorf("sprout_id is required")
	}
	return []string{p.SproutID}, nil
}

func extractJobsForSproutID(params json.RawMessage) ([]string, error) {
	var p sproutIDParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid jobs params: %w", err)
	}
	if p.SproutID == "" {
		return nil, fmt.Errorf("sprout_id is required")
	}
	return []string{p.SproutID}, nil
}

func extractSproutsGetID(params json.RawMessage) ([]string, error) {
	var p sproutIDParam
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid sprouts.get params: %w", err)
	}
	if p.SproutID == "" {
		return nil, fmt.Errorf("sprout_id is required")
	}
	return []string{p.SproutID}, nil
}

// allAcceptedSproutIDs returns all accepted sprout IDs from the PKI store,
// within tenantID — the connection's own tenant (see docs/design/
// imas-tenant-context-threading.md). This is used by the cohort resolver
// to evaluate dynamic cohorts.
func allAcceptedSproutIDs(tenantID string) []string {
	allKeys := pki.ListNKeysByType(tenantID)
	ids := make([]string, 0, len(allKeys.Accepted.Sprouts))
	for _, km := range allKeys.Accepted.Sprouts {
		ids = append(ids, km.SproutID)
	}
	return ids
}

// checkScopedAccess verifies that the token's role permits the given
// action on the specified sprout IDs, within tenantID. Returns nil if
// access is granted, ErrAccessDenied otherwise.
func checkScopedAccess(tenantID, token string, action rbac.Action, sproutIDs []string) error {
	allIDs := allAcceptedSproutIDs(tenantID)
	if !intauth.TokenHasScopedAccess(token, action, sproutIDs, allIDs) {
		return rbac.ErrAccessDenied
	}
	return nil
}

// filterSproutsByScope returns the subset of sproutIDs the token's role
// permits for the given action, within tenantID.
func filterSproutsByScope(tenantID, token string, action rbac.Action, sproutIDs []string) []string {
	allIDs := allAcceptedSproutIDs(tenantID)
	return intauth.TokenScopeFilter(token, action, sproutIDs, allIDs)
}
