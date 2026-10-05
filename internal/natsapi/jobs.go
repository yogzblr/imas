package natsapi

// The jobs.* handlers read and change farmer's job store
// (internal/jobs/store.go). Every one of them takes the verified caller,
// and every job store call is made in the caller's tenant, c.TenantID:
// the tenant whose connection the sealed request arrived on and whose key
// it opened under, never a field of the params. The job store lists only
// that tenant's jobs/<tenant>/ prefix, so a sprout_id or jid another tenant
// also uses can't reach a caller of this one. ownJob and ownJobs check the
// tenant of what comes back once more before it is returned.

import (
	"encoding/json"
	"fmt"

	"github.com/yogzblr/imas/internal/jobs"
	"github.com/yogzblr/imas/internal/rbac"
)

var jobStore *jobs.Store

func init() {
	jobStore = jobs.NewStore()
}

// JobsListParams holds optional parameters for listing jobs.
type JobsListParams struct {
	Limit int    `json:"limit,omitempty"`
	User  string `json:"user,omitempty"` // filter by invoking user pubkey
}

// JobsGetParams identifies a job by JID.
type JobsGetParams struct {
	JID string `json:"jid"`
}

// JobsForSproutParams identifies a sprout for job listing.
type JobsForSproutParams struct {
	SproutID string `json:"sprout_id"`
}

// ownJob refuses a job that wasn't read from tenantID's job store, as if
// it didn't exist. The store only reads tenantID's prefix, so this never
// fires; it keeps a job of another tenant from ever reaching the caller
// should that change.
func ownJob(tenantID string, s *jobs.JobSummary) (*jobs.JobSummary, error) {
	if s == nil || s.TenantID != tenantID {
		return nil, jobs.ErrJobNotFound
	}
	return s, nil
}

// ownJobs is ownJob for a listing: it drops any job not read from
// tenantID's job store.
func ownJobs(tenantID string, in []jobs.JobSummary) []jobs.JobSummary {
	out := make([]jobs.JobSummary, 0, len(in))
	for _, s := range in {
		if s.TenantID == tenantID {
			out = append(out, s)
		}
	}
	return out
}

func handleJobsList(c apiCaller, params json.RawMessage) (any, error) {
	var p JobsListParams
	if len(params) > 0 {
		json.Unmarshal(params, &p)
	}
	limit := p.Limit
	if limit <= 0 {
		limit = 50
	}
	summaries, err := jobStore.ListAllJobs(c.TenantID, limit)
	if err != nil {
		return nil, err
	}
	summaries = ownJobs(c.TenantID, summaries)

	// Scope filtering: only jobs for sprouts the verified user may view.
	sproutIDs := make([]string, 0, len(summaries))
	seen := make(map[string]bool)
	for _, s := range summaries {
		if s.SproutID != "" && !seen[s.SproutID] {
			sproutIDs = append(sproutIDs, s.SproutID)
			seen[s.SproutID] = true
		}
	}
	allowedSet := make(map[string]bool, len(sproutIDs))
	for _, id := range filterSproutsByScope(c.TenantID, c.UserID, rbac.ActionView, sproutIDs) {
		allowedSet[id] = true
	}
	filtered := make([]jobs.JobSummary, 0, len(summaries))
	for _, s := range summaries {
		if s.SproutID == "" || allowedSet[s.SproutID] {
			filtered = append(filtered, s)
		}
	}
	summaries = filtered

	// Filter by invoking user if requested.
	if p.User != "" {
		filtered := make([]jobs.JobSummary, 0, len(summaries))
		for _, s := range summaries {
			if s.InvokedBy == p.User {
				filtered = append(filtered, s)
			}
		}
		summaries = filtered
	}

	return summaries, nil
}

// findCallerJob looks jid up in c's tenant and checks c may take action on
// the sprout that ran it.
func findCallerJob(c apiCaller, jid string, action rbac.Action) (*jobs.JobSummary, error) {
	summary, err := jobStore.FindJob(c.TenantID, jid)
	if err != nil {
		return nil, err
	}
	if summary, err = ownJob(c.TenantID, summary); err != nil {
		return nil, err
	}
	// Scope check against the job's sprout, which is only known after
	// looking the job up (the middleware checks the action alone).
	if summary.SproutID != "" {
		if err := checkScopedAccess(c.TenantID, c.UserID, action, []string{summary.SproutID}); err != nil {
			return nil, rbac.ErrAccessDenied
		}
	}
	return summary, nil
}

func handleJobsGet(c apiCaller, params json.RawMessage) (any, error) {
	var p JobsGetParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	if p.JID == "" {
		return nil, fmt.Errorf("jid is required")
	}
	summary, err := findCallerJob(c, p.JID, rbac.ActionView)
	if err != nil {
		return nil, err
	}
	return summary, nil
}

// JobsDeleteParams identifies a job to delete by JID.
type JobsDeleteParams struct {
	JID string `json:"jid"`
}

func handleJobsDelete(c apiCaller, params json.RawMessage) (any, error) {
	var p JobsDeleteParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	if p.JID == "" {
		return nil, fmt.Errorf("jid is required")
	}

	// Look up the job first to check scope access, then delete exactly
	// that job: the caller's tenant's run of jid on that sprout.
	summary, err := findCallerJob(c, p.JID, rbac.ActionJobAdmin)
	if err != nil {
		return nil, err
	}
	if err := jobStore.DeleteJob(c.TenantID, summary.SproutID, p.JID); err != nil {
		return nil, err
	}

	return JobsDeleteResponse{
		JID:     p.JID,
		Message: "job deleted",
	}, nil
}

func handleJobsCancel(c apiCaller, params json.RawMessage) (any, error) {
	tenantID := c.TenantID
	var p JobsGetParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	if p.JID == "" {
		return nil, fmt.Errorf("jid is required")
	}

	summary, err := findCallerJob(c, p.JID, rbac.ActionJobAdmin)
	if err != nil {
		return nil, err
	}

	if summary.Status != jobs.JobRunning && summary.Status != jobs.JobPending {
		return nil, fmt.Errorf("job cannot be cancelled: status is %s", summary.Status)
	}

	subject := SproutSubject(summary.SproutID, SproutCancel)
	cancelMsg, _ := json.Marshal(map[string]string{"jid": p.JID})

	// The cancel goes out on the caller's own tenant connection, to the
	// sprout of that tenant that ran the job.
	nc := natsConnFor(tenantID)
	if nc == nil {
		return nil, fmt.Errorf("NATS connection not available")
	}

	if err := nc.Publish(subject, cancelMsg); err != nil {
		return nil, fmt.Errorf("failed to publish cancel: %w", err)
	}

	return map[string]string{
		"jid":     p.JID,
		"sprout":  summary.SproutID,
		"message": "cancel request published",
	}, nil
}

// handleJobsListForSprout lists c's tenant's jobs on sprout_id. The
// middleware has already checked c may view that sprout (scopeExtractors).
func handleJobsListForSprout(c apiCaller, params json.RawMessage) (any, error) {
	var p JobsForSproutParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	if p.SproutID == "" {
		return nil, fmt.Errorf("sprout_id is required")
	}

	summaries, err := jobStore.ListJobsForSprout(c.TenantID, p.SproutID)
	if err != nil {
		return nil, err
	}
	return ownJobs(c.TenantID, summaries), nil
}
