package natsapi

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/rbac"
)

// cohortRegistry is a single, process-wide *rbac.Registry, deliberately not
// re-keyed per tenant here even though internal/pki.ListNKeysByType calls
// below are now correctly threaded to each connection's own tenantID.
// rbac.Registry already carries an explicit tenantID fixed at construction
// (workstream E), but the cohort *definitions* it holds are loaded once, at
// boot/SIGHUP, from a single config file (cmd/farmer/main.go's
// loadCohortRegistry, driven by rbac.LoadCohortsFromConfig) — the same
// "genuinely process-level, not a per-request tenant being papered over"
// shape docs/design/imas-tenant-context-threading.md's point 4 describes
// for internal/rbac/internal/auth's policy layer, which this task's brief
// explicitly keeps out of scope ("has no tenant concept at all and stays
// that way"). Giving cohort definitions themselves real per-tenant config
// is that same follow-up workstream's territory, not this one's.
var cohortRegistry *rbac.Registry

// SetCohortRegistry assigns the cohort registry for NATS API handlers.
func SetCohortRegistry(r *rbac.Registry) {
	cohortRegistry = r
}

// CohortSummary provides basic info about a named cohort.
type CohortSummary struct {
	Name string          `json:"name"`
	Type rbac.CohortType `json:"type"`
}

// CohortResolveParams is the request for resolving a cohort.
type CohortResolveParams struct {
	Name string `json:"name"`
}

func handleCohortsList(_ string, _ json.RawMessage) (any, error) {
	if cohortRegistry == nil {
		return map[string][]CohortSummary{"cohorts": {}}, nil
	}

	names := cohortRegistry.List()
	summaries := make([]CohortSummary, 0, len(names))
	for _, name := range names {
		c, err := cohortRegistry.Get(name)
		if err != nil {
			continue
		}
		summaries = append(summaries, CohortSummary{
			Name: name,
			Type: c.Type,
		})
	}

	return map[string][]CohortSummary{"cohorts": summaries}, nil
}

// CohortGetParams is the request for fetching a single cohort definition.
type CohortGetParams struct {
	Name string `json:"name"`
}

// CohortDetail provides the full definition of a cohort, including
// membership rules and resolved member count.
type CohortDetail struct {
	Name     string             `json:"name"`
	Type     rbac.CohortType    `json:"type"`
	Members  []string           `json:"members,omitempty"`
	Match    *rbac.DynamicMatch `json:"match,omitempty"`
	Compound *rbac.CompoundExpr `json:"compound,omitempty"`
	Resolved []string           `json:"resolved"`
	Count    int                `json:"count"`
}

func handleCohortsGet(tenantID string, params json.RawMessage) (any, error) {
	if cohortRegistry == nil {
		return nil, fmt.Errorf("no cohort registry configured")
	}

	var p CohortGetParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	if p.Name == "" {
		return nil, fmt.Errorf("cohort name is required")
	}

	cohort, err := cohortRegistry.Get(p.Name)
	if err != nil {
		return nil, err
	}

	// Resolve current membership for the detail view.
	allKeys := pki.ListNKeysByType(tenantID)
	allSproutIDs := make([]string, 0, len(allKeys.Accepted.Sprouts))
	for _, km := range allKeys.Accepted.Sprouts {
		allSproutIDs = append(allSproutIDs, km.SproutID)
	}

	resolved := make([]string, 0)
	members, resolveErr := cohortRegistry.Resolve(p.Name, allSproutIDs)
	if resolveErr == nil {
		for id := range members {
			resolved = append(resolved, id)
		}
	}

	detail := CohortDetail{
		Name:     cohort.Name,
		Type:     cohort.Type,
		Members:  cohort.Members,
		Match:    cohort.Match,
		Compound: cohort.Compound,
		Resolved: resolved,
		Count:    len(resolved),
	}

	return detail, nil
}

func handleCohortsResolve(tenantID string, params json.RawMessage) (any, error) {
	if cohortRegistry == nil {
		return nil, fmt.Errorf("no cohort registry configured")
	}

	var p CohortResolveParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	if p.Name == "" {
		return nil, fmt.Errorf("cohort name is required")
	}

	allKeys := pki.ListNKeysByType(tenantID)
	allSproutIDs := make([]string, 0, len(allKeys.Accepted.Sprouts))
	for _, km := range allKeys.Accepted.Sprouts {
		allSproutIDs = append(allSproutIDs, km.SproutID)
	}

	members, err := cohortRegistry.Resolve(p.Name, allSproutIDs)
	if err != nil {
		return nil, err
	}

	sprouts := make([]string, 0, len(members))
	for id := range members {
		sprouts = append(sprouts, id)
	}

	return map[string]any{
		"name":    p.Name,
		"sprouts": sprouts,
	}, nil
}

// CohortRefreshParams is the request for refreshing cohort membership.
// If Name is empty, all cohorts are refreshed.
type CohortRefreshParams struct {
	Name string `json:"name,omitempty"`
}

// CohortRefreshResponse is the response for a cohort refresh operation.
type CohortRefreshResponse struct {
	Refreshed []rbac.RefreshResult `json:"refreshed"`
}

func handleCohortsRefresh(tenantID string, params json.RawMessage) (any, error) {
	if cohortRegistry == nil {
		return nil, fmt.Errorf("no cohort registry configured")
	}

	var p CohortRefreshParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, err
		}
	}

	allKeys := pki.ListNKeysByType(tenantID)
	allSproutIDs := make([]string, 0, len(allKeys.Accepted.Sprouts))
	for _, km := range allKeys.Accepted.Sprouts {
		allSproutIDs = append(allSproutIDs, km.SproutID)
	}
	sort.Strings(allSproutIDs)

	if p.Name != "" {
		// Refresh a single cohort.
		result, err := cohortRegistry.Refresh(p.Name, allSproutIDs)
		if err != nil {
			return nil, err
		}
		return CohortRefreshResponse{
			Refreshed: []rbac.RefreshResult{*result},
		}, nil
	}

	// Refresh all cohorts.
	results, err := cohortRegistry.RefreshAll(allSproutIDs)
	if err != nil {
		return nil, err
	}
	return CohortRefreshResponse{Refreshed: results}, nil
}

// CohortValidateResponse describes the outcome of validating all cohort references.
type CohortValidateResponse struct {
	Valid   bool     `json:"valid"`
	Errors  []string `json:"errors,omitempty"`
	Cohorts int      `json:"cohorts"`
}

func handleCohortsValidate(_ string, _ json.RawMessage) (any, error) {
	if cohortRegistry == nil {
		return CohortValidateResponse{Valid: true, Cohorts: 0}, nil
	}

	names := cohortRegistry.List()
	resp := CohortValidateResponse{
		Cohorts: len(names),
	}

	errs := cohortRegistry.ValidateReferencesAll()
	if len(errs) > 0 {
		resp.Valid = false
		resp.Errors = make([]string, len(errs))
		for i, e := range errs {
			resp.Errors[i] = e.Error()
		}
	} else {
		resp.Valid = true
	}

	return resp, nil
}
