package saasapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

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
// Re-dispatching stale pending jobs is the outbox sweeper's job — deferred,
// see docs/design/imas-internal-api-account.md.
func dispatchProvisioning(_ context.Context, job *ProvisioningJob, tenantName string) {
	publishProvisioningJob(job, controlplane.SubjectTenantProvision, controlplane.TenantProvisionRequest{
		JobID:    job.ID,
		TenantID: job.TenantID,
		Name:     tenantName,
	})
}

// dispatchDeprovisioning is the DELETE-path counterpart of
// dispatchProvisioning, publishing internal.tenant.deprovision.
func dispatchDeprovisioning(_ context.Context, job *ProvisioningJob) {
	publishProvisioningJob(job, controlplane.SubjectTenantDeprovision, controlplane.TenantDeprovisionRequest{
		JobID:    job.ID,
		TenantID: job.TenantID,
	})
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
	if err := db.Model(&ProvisioningJob{}).Where("id = ?", job.ID).
		UpdateColumn("attempts", gorm.Expr("attempts + 1")).Error; err != nil {
		log.Errorf("saasapi: recording dispatch attempt for job %s: %v", job.ID, err)
	}
	if err := nc.Publish(subject, data); err != nil {
		log.Errorf("saasapi: publishing %s for job %s (tenant %s): %v — job left pending", subject, job.ID, job.TenantID, err)
		return
	}
	log.Infof("saasapi: dispatched %s for job %s (tenant %s)", subject, job.ID, job.TenantID)
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
// or late result (NATS core can redeliver nothing, but a future outbox
// sweeper can re-dispatch, and farmer's ProvisionTenant is idempotent) is a
// no-op, and a provision result arriving after the tenant was already
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
