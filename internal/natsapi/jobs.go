package natsapi

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

func handleJobsList(c apiCaller, params json.RawMessage) (any, error) {
	var p JobsListParams
	if len(params) > 0 {
		json.Unmarshal(params, &p)
	}
	limit := p.Limit
	if limit <= 0 {
		limit = 50
	}
	summaries, err := jobStore.ListAllJobs(limit)
	if err != nil {
		return nil, err
	}
	if summaries == nil {
		summaries = []jobs.JobSummary{}
	}

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

func handleJobsGet(_ string, params json.RawMessage) (any, error) {
	var p JobsGetParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	if p.JID == "" {
		return nil, fmt.Errorf("jid is required")
	}
	summary, err := jobStore.FindJob(p.JID)
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

	// Look up the job first to check scope access.
	summary, err := jobStore.FindJob(p.JID)
	if err != nil {
		return nil, err
	}

	// Scope check: verify the user can delete jobs on this sprout.
	if summary.SproutID != "" {
		if err := checkScopedAccess(c.TenantID, c.UserID, rbac.ActionJobAdmin, []string{summary.SproutID}); err != nil {
			return nil, rbac.ErrAccessDenied
		}
	}

	if err := jobStore.DeleteJob(p.JID); err != nil {
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

	summary, err := jobStore.FindJob(p.JID)
	if err != nil {
		return nil, err
	}

	// Scope check: verify the user can cancel jobs on this sprout.
	// The middleware checks action-level (job_admin), but we need to
	// verify scope against the job's sprout_id which is only known
	// after looking up the job.
	if summary.SproutID != "" {
		if err := checkScopedAccess(tenantID, c.UserID, rbac.ActionJobAdmin, []string{summary.SproutID}); err != nil {
			return nil, rbac.ErrAccessDenied
		}
	}

	if summary.Status != jobs.JobRunning && summary.Status != jobs.JobPending {
		return nil, fmt.Errorf("job cannot be cancelled: status is %s", summary.Status)
	}

	subject := SproutSubject(summary.SproutID, SproutCancel)
	cancelMsg, _ := json.Marshal(map[string]string{"jid": p.JID})

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

func handleJobsListForSprout(_ string, params json.RawMessage) (any, error) {
	var p JobsForSproutParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, err
	}
	if p.SproutID == "" {
		return nil, fmt.Errorf("sprout_id is required")
	}

	summaries, err := jobStore.ListJobsForSprout(p.SproutID)
	if err != nil {
		return nil, err
	}
	if summaries == nil {
		summaries = []jobs.JobSummary{}
	}
	return summaries, nil
}
