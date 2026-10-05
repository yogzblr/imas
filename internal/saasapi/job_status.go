package saasapi

// The production JobStatusReader: §1.5's local, no-NATS poll of cook job
// status, over farmer's job-status index (internal/jobs/status_index.go).
// It reads farmer.job_status through the saas service account's SELECT
// grant on farmer.* (§4.1), as asset_links.go reads farmer.pki_nkeys. The
// SaaS API gets no access to farmer's job object store: the index is the
// only thing it reads.

import (
	"context"
	"errors"
)

// farmerJobStatusTable is internal/jobs' jobStatusRow table. Only its
// tenant_id, sprout_id, jid and status columns are read
// (TestFarmerJobStatusColumnContract pins them against jobs.Models()).
const farmerJobStatusTable = "farmer.job_status"

// Status strings farmer writes to farmer.job_status (internal/jobs'
// JobIndexStatus* constants, pinned by TestFarmerJobStatusColumnContract).
// Only the terminal ones matter here; anything else reads as running.
const (
	farmerJobSucceeded = "succeeded"
	farmerJobFailed    = "failed"
	// farmerJobExpired: the job started on its sprout later than farmer's
	// reconcile window allows, so farmer recorded none of its steps. It
	// may or may not have run; farmer won't record anything more for it.
	farmerJobExpired = "expired"
)

// farmerJobStatusReader implements JobStatusReader over farmer.job_status.
type farmerJobStatusReader struct{}

var (
	errNoDB = errors.New("saasapi: database not configured")
	// errNoJobTenant: a job status lookup without a tenant is refused
	// rather than run unscoped.
	errNoJobTenant = errors.New("saasapi: job status lookup needs a tenant")
)

// JobOutcomes looks up every requested job in one query, keyed on the full
// (tenant_id, sprout_id, jid) — farmer.job_status' primary key — since a
// sprout_id is only unique within its tenant. A job with no row yet (its
// first event hasn't been indexed) is simply absent from the result.
//
// tenantID is the tenant of the batch being polled (its route's
// {tenant_id}, which the batch was looked up under), never anything from
// a request body. An empty tenant is refused, and every row's tenant_id is
// checked against it once more before its status is used, so another
// tenant's row for the same sprout_id and jid can never decide an item
// (security review 2026-10-b, I4).
func (farmerJobStatusReader) JobOutcomes(ctx context.Context, tenantID string, jobs []JobRef) (map[JobRef]JobOutcome, error) {
	d := db
	if d == nil {
		return nil, errNoDB
	}
	if tenantID == "" {
		return nil, errNoJobTenant
	}
	if len(jobs) == 0 {
		return map[JobRef]JobOutcome{}, nil
	}
	pairs := make([][]any, len(jobs))
	for i, j := range jobs {
		pairs[i] = []any{j.SproutID, j.JID}
	}
	var rows []struct {
		TenantID string
		SproutID string
		JID      string `gorm:"column:jid"`
		Status   string
	}
	err := d.WithContext(ctx).Table(farmerJobStatusTable).
		Select("tenant_id", "sprout_id", "jid", "status").
		Where("tenant_id = ? AND (sprout_id, jid) IN ?", tenantID, pairs).
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	out := make(map[JobRef]JobOutcome, len(rows))
	for _, r := range rows {
		if r.TenantID != tenantID {
			continue
		}
		outcome := JobOutcomeRunning
		switch r.Status {
		case farmerJobSucceeded:
			outcome = JobOutcomeSucceeded
		case farmerJobFailed:
			outcome = JobOutcomeFailed
		case farmerJobExpired:
			outcome = JobOutcomeExpired
		}
		out[JobRef{SproutID: r.SproutID, JID: r.JID}] = outcome
	}
	return out, nil
}
