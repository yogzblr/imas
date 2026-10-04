package saasapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/controlplane"
	log "github.com/yogzblr/imas/internal/log"
)

// enqueueProvisioningJob writes an outbox row for an async tenant
// operation (design doc §4 "Async pattern"), which dispatchProvisioning/
// dispatchDeprovisioning then publish to farmer over NATS. It must be
// called within the same transaction as the Tenant row write so the outbox
// row and the tenant's pending/offboarding status can never diverge.
func enqueueProvisioningJob(tx *gorm.DB, tenantID string, jobType ProvisioningJobType) (*ProvisioningJob, error) {
	id, err := newID("pj_")
	if err != nil {
		return nil, err
	}
	job := &ProvisioningJob{
		ID:       id,
		TenantID: tenantID,
		Type:     jobType,
		Status:   ProvisioningJobPending,
	}
	if err := tx.Create(job).Error; err != nil {
		return nil, err
	}
	return job, nil
}

// dispatchProvisioning is called after the enclosing transaction commits.
// It publishes internal.tenant.provision (design doc §2.2) carrying the
// job's ID, which farmer echoes back on internal.tenant.provisioned.{job_id}
// for StartProvisioningResultListener to apply.
//
// Fire-and-forget over NATS core: a publish that fails (or a request
// farmer never receives) leaves the job pending with its attempt counted.
// The outbox sweeper re-publishes a job still pending after a backoff
// (sweepProvisioningJobs), until the attempt limit fails it.
func dispatchProvisioning(_ context.Context, job *ProvisioningJob, tenantName string) {
	subject, payload := provisioningRequest(job, tenantName)
	publishProvisioningJob(job, subject, payload)
}

// dispatchDeprovisioning is the DELETE-path counterpart of
// dispatchProvisioning, publishing internal.tenant.deprovision.
func dispatchDeprovisioning(_ context.Context, job *ProvisioningJob) {
	subject, payload := provisioningRequest(job, "")
	publishProvisioningJob(job, subject, payload)
}

func publishProvisioningJob(job *ProvisioningJob, subject string, payload any) {
	nc := bus
	if nc == nil {
		log.Errorf("saasapi: not connected to the NATS bus; job %s (tenant %s, %s) left pending", job.ID, job.TenantID, job.Type)
		return
	}
	data, err := json.Marshal(payload)
	if err != nil {
		log.Errorf("saasapi: marshalling %s for job %s: %v", subject, job.ID, err)
		return
	}
	// The attempt and its time are recorded before the publish, so the
	// sweeper's backoff counts from no later than the request.
	if err := db.Model(&ProvisioningJob{}).Where("id = ? AND tenant_id = ?", job.ID, job.TenantID).
		UpdateColumns(map[string]any{
			"attempts":           gorm.Expr("attempts + 1"),
			"last_dispatched_at": dbTime(outboxNow()),
		}).Error; err != nil {
		log.Errorf("saasapi: recording dispatch attempt for job %s: %v", job.ID, err)
	}
	sendProvisioningJob(nc, job, subject, data)
}

// sendProvisioningJob publishes data, a job's request, on subject. The
// caller has already counted the attempt.
func sendProvisioningJob(nc *nats.Conn, job *ProvisioningJob, subject string, data []byte) {
	if err := nc.Publish(subject, data); err != nil {
		log.Errorf("saasapi: publishing %s for job %s (tenant %s): %v — job left pending", subject, job.ID, job.TenantID, err)
		return
	}
	log.Infof("saasapi: dispatched %s for job %s (tenant %s)", subject, job.ID, job.TenantID)
}

// provisioningRequest is job's farmer request: its subject and payload.
// tenantName is only used for a provision job.
func provisioningRequest(job *ProvisioningJob, tenantName string) (string, any) {
	if job.Type == ProvisioningJobDeprovision {
		return controlplane.SubjectTenantDeprovision, controlplane.TenantDeprovisionRequest{JobID: job.ID, TenantID: job.TenantID}
	}
	return controlplane.SubjectTenantProvision, controlplane.TenantProvisionRequest{JobID: job.ID, TenantID: job.TenantID, Name: tenantName}
}

// provisioningNoResultMessage is the last_error of a job the outbox sweeper
// gave up on: a fixed, caller-safe message like publicJobError's.
const provisioningNoResultMessage = "no result was received for this request after repeated attempts; contact support"

// sweepProvisioningJobs is the outbox sweeper's provisioning job: every
// pending job whose backoff has passed since it was last published (or,
// never published, since it was written) is published again, under a
// row lease claimed in the same UPDATE that counts the attempt; one that
// has used every attempt is failed instead (failStaleProvisioningJob).
//
// Re-publishing is safe because a repeated job_id is harmless on both
// sides (checked for CL.3, see docs/design/imas-internal-api-account.md):
// farmer's ProvisionTenant re-confirms an existing Account and re-pushes
// it, DeprovisionTenant finds the tenant already deleted and reports
// offboarded, and applyProvisioningResult applies the first result of a
// job and ignores the rest. A late copy of a provision request still
// running on farmer when the tenant is offboarded is handled by farmer
// (internal/pki re-checks the tenant after its push and locks it out again;
// a tenant deprovisioned before any row existed gets a deleted tombstone),
// so DELETE doesn't wait for re-published copies (DeleteTenant).
func (sw *sweeper) sweepProvisioningJobs() {
	now := dbTime(outboxNow())
	var jobs []ProvisioningJob
	if err := sw.d.Where("status = ?", ProvisioningJobPending).
		Where("COALESCE(last_dispatched_at, created_at) <= ?", now.Add(-sw.s.ProvisioningStaleAfter)).
		Where(leaseFree, now).
		Order("created_at").Limit(sweepBatchLimit).Find(&jobs).Error; err != nil {
		log.Errorf("saasapi: outbox sweep: reading pending provisioning jobs: %v", err)
		return
	}
	for i := range jobs {
		job := &jobs[i]
		last := job.CreatedAt
		if job.LastDispatchedAt != nil {
			last = *job.LastDispatchedAt
		}
		if now.Before(last.Add(backoff(sw.s.ProvisioningStaleAfter, job.Attempts))) {
			continue
		}
		if job.Attempts >= sw.s.MaxAttempts {
			sw.failStaleProvisioningJob(job, now)
			continue
		}
		sw.republishProvisioningJob(job, now)
	}
}

// republishProvisioningJob claims job (still pending, with the attempt
// count read, and its lease free), counting the attempt, and publishes it.
// Another replica that read the same row matches nothing and sends
// nothing.
func (sw *sweeper) republishProvisioningJob(job *ProvisioningJob, now time.Time) {
	var name string
	if job.Type == ProvisioningJobProvision {
		var tenant Tenant
		if err := sw.d.Select("id", "name").Where("id = ?", job.TenantID).First(&tenant).Error; err != nil {
			log.Errorf("saasapi: outbox sweep: looking up tenant %s for job %s: %v", job.TenantID, job.ID, err)
			return
		}
		name = tenant.Name
	}
	subject, payload := provisioningRequest(job, name)
	data, err := json.Marshal(payload)
	if err != nil {
		log.Errorf("saasapi: outbox sweep: marshalling %s for job %s: %v", subject, job.ID, err)
		return
	}
	lease, err := claimRowLease(sw.d, ProvisioningJob{}.TableName(), "id = ? AND tenant_id = ?", []any{job.ID, job.TenantID},
		"status = ? AND attempts = ?", []any{ProvisioningJobPending, job.Attempts},
		map[string]any{"attempts": gorm.Expr("attempts + 1"), "last_dispatched_at": now}, sw.s.LeaseTTL)
	if err != nil {
		log.Errorf("saasapi: outbox sweep: claiming job %s (tenant %s): %v", job.ID, job.TenantID, err)
		return
	}
	if lease == nil {
		return // another replica has it, or it moved on
	}
	log.Warnf("saasapi: outbox sweep: job %s (tenant %s, %s) still pending; publishing it again (attempt %d of %d)",
		job.ID, job.TenantID, job.Type, job.Attempts+1, sw.s.MaxAttempts)
	sendProvisioningJob(sw.nc, job, subject, data)
}

// failStaleProvisioningJob fails a pending job that has used every attempt
// and waited out its last backoff with no result, as a farmer failure
// would (applyProvisioningResult): a provision job's tenant moves from
// pending to failed, so it can be deleted; a deprovision job's tenant
// stays offboarding, and GET .../status shows the job's error. The update
// is conditional on the job being unchanged and unleased since it was
// read. A result that arrives afterwards is ignored like any duplicate.
func (sw *sweeper) failStaleProvisioningJob(job *ProvisioningJob, now time.Time) {
	err := sw.d.Transaction(func(tx *gorm.DB) error {
		r := tx.Model(&ProvisioningJob{}).
			Where("id = ? AND tenant_id = ? AND status = ? AND attempts = ?", job.ID, job.TenantID, ProvisioningJobPending, job.Attempts).
			Where(leaseFree, now).
			Updates(map[string]any{
				"status":     ProvisioningJobFailed,
				"last_error": fmt.Sprintf("%s (reference %s)", provisioningNoResultMessage, job.ID),
				"warning":    "",
			})
		if r.Error != nil || r.RowsAffected == 0 {
			return r.Error
		}
		log.Errorf("saasapi: outbox sweep: job %s (tenant %s, %s) got no result after %d attempts; marked failed",
			job.ID, job.TenantID, job.Type, job.Attempts)
		if job.Type != ProvisioningJobProvision {
			return nil
		}
		return tx.Model(&Tenant{}).Where("id = ? AND status = ?", job.TenantID, TenantStatusPending).
			Update("status", TenantStatusFailed).Error
	})
	if err != nil {
		log.Errorf("saasapi: outbox sweep: failing job %s (tenant %s): %v", job.ID, job.TenantID, err)
	}
}

// StartProvisioningResultListener queue-subscribes nc to farmer's
// internal.tenant.provisioned.* and internal.tenant.deprovisioned.* result
// subjects and applies each result to the saas schema — the other half of
// design doc §4's async pattern. Call once at startup, after ConnectBus.
func StartProvisioningResultListener(nc *nats.Conn) error {
	subs := []struct {
		wildcard, prefix string
		jobType          ProvisioningJobType
	}{
		{controlplane.SubjectTenantProvisionedWildcard, controlplane.SubjectTenantProvisionedPrefix, ProvisioningJobProvision},
		{controlplane.SubjectTenantDeprovisionedWildcard, controlplane.SubjectTenantDeprovisionedPrefix, ProvisioningJobDeprovision},
	}
	for _, s := range subs {
		prefix, jobType := s.prefix, s.jobType
		if _, err := nc.QueueSubscribe(s.wildcard, busQueueGroup, func(msg *nats.Msg) {
			handleProvisioningResult(jobType, prefix, msg.Subject, msg.Data)
		}); err != nil {
			return fmt.Errorf("saasapi: subscribing to %s: %w", s.wildcard, err)
		}
	}
	return nc.Flush()
}

func handleProvisioningResult(jobType ProvisioningJobType, prefix, subject string, data []byte) {
	jobID, ok := controlplane.JobIDFromSubject(subject, prefix)
	if !ok {
		log.Errorf("saasapi: ignoring provisioning result on unexpected subject %q", subject)
		return
	}
	var res controlplane.TenantResult
	if err := json.Unmarshal(data, &res); err != nil {
		log.Errorf("saasapi: ignoring malformed provisioning result for job %s: %v", jobID, err)
		return
	}
	if res.JobID != jobID {
		log.Errorf("saasapi: ignoring provisioning result whose job_id %q doesn't match its subject's %q", res.JobID, jobID)
		return
	}
	if err := applyProvisioningResult(jobType, res); err != nil {
		log.Errorf("saasapi: applying %s result for job %s (tenant %s): %v", jobType, jobID, res.TenantID, err)
	}
}

var errUnexpectedResult = errors.New("unexpected provisioning result")

// publicJobError is what a failed job records as last_error, which
// GET /tenants/{id}/status returns to external callers: a fixed,
// caller-safe message for the result's error code, plus the job ID as a
// reference an operator can match against farmer's logs (where the full
// error is recorded). Nothing from the result is stored verbatim, so even
// a farmer that wrongly put detail on the bus couldn't leak it here.
func publicJobError(jobID string, code controlplane.ErrorCode) string {
	return fmt.Sprintf("%s (reference %s)", controlplane.PublicErrorMessage(code), jobID)
}

// applyProvisioningResult moves a pending ProvisioningJob to
// succeeded/failed and transitions its Tenant accordingly, in one
// transaction:
//
//   - provision succeeded:   tenant pending -> active
//   - provision failed:      tenant pending -> failed (job.last_error set
//     to a fixed public message, see publicJobError)
//   - deprovision succeeded: tenant offboarding -> offboarded (with
//     job.warning set if farmer had nothing to tear down)
//   - deprovision failed:    tenant stays offboarding; GetTenantStatus
//     surfaces the failed job's last_error
//
// Both updates are conditional on the row's current status, so a duplicate
// or late result (NATS core can redeliver nothing, but the outbox sweeper
// re-publishes a pending job, and farmer's ProvisionTenant is idempotent)
// is a no-op, and a provision result arriving after the tenant was already
// moved to offboarding never resurrects it as active.
func applyProvisioningResult(jobType ProvisioningJobType, res controlplane.TenantResult) error {
	var succeeded bool
	switch {
	case res.Status == controlplane.StatusFailed:
		succeeded = false
	case jobType == ProvisioningJobProvision && res.Status == controlplane.StatusActive,
		jobType == ProvisioningJobDeprovision && res.Status == controlplane.StatusOffboarded:
		succeeded = true
	default:
		return fmt.Errorf("%w: status %q for a %s job", errUnexpectedResult, res.Status, jobType)
	}

	return db.Transaction(func(tx *gorm.DB) error {
		var job ProvisioningJob
		if err := tx.First(&job, "id = ?", res.JobID).Error; err != nil {
			return fmt.Errorf("looking up job: %w", err)
		}
		if job.Type != jobType {
			return fmt.Errorf("%w: job is a %s job, result is for %s", errUnexpectedResult, job.Type, jobType)
		}
		if job.TenantID != res.TenantID {
			return fmt.Errorf("%w: job belongs to tenant %s, result names %s", errUnexpectedResult, job.TenantID, res.TenantID)
		}

		jobUpdate := map[string]any{
			"status":     ProvisioningJobSucceeded,
			"last_error": "",
			"warning":    controlplane.PublicWarningMessage(res.WarningCode),
		}
		if !succeeded {
			jobUpdate = map[string]any{"status": ProvisioningJobFailed, "last_error": publicJobError(job.ID, res.ErrorCode), "warning": ""}
		}
		r := tx.Model(&ProvisioningJob{}).Where("id = ? AND status = ?", job.ID, ProvisioningJobPending).Updates(jobUpdate)
		if r.Error != nil {
			return r.Error
		}
		if r.RowsAffected == 0 {
			log.Infof("saasapi: job %s already %s; ignoring duplicate result", job.ID, job.Status)
			return nil
		}

		var from, to TenantStatus
		switch {
		case jobType == ProvisioningJobProvision && succeeded:
			from, to = TenantStatusPending, TenantStatusActive
		case jobType == ProvisioningJobProvision:
			from, to = TenantStatusPending, TenantStatusFailed
		case succeeded:
			from, to = TenantStatusOffboarding, TenantStatusOffboarded
		default:
			log.Warnf("saasapi: deprovisioning tenant %s failed (job %s): %s", job.TenantID, job.ID, res.ErrorCode)
			return nil
		}
		if err := tx.Model(&Tenant{}).Where("id = ? AND status = ?", job.TenantID, from).Update("status", to).Error; err != nil {
			return err
		}
		log.Infof("saasapi: job %s (%s) -> %s; tenant %s -> %s", job.ID, jobType, jobUpdate["status"], job.TenantID, to)
		return nil
	})
}
