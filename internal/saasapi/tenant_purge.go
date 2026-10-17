package saasapi

// Erasing an offboarded tenant's data (S6, docs/briefs/S6-tenant-erasure.md):
// the SaaS API's half. FLAG FOR SECURITY REVIEW: this starts the deletion
// of a tenant's data for good.
//
// Offboarding (DELETE /tenants/{id}) locks the tenant out at once, as
// before. Its data is erased later, by a purge job: the outbox sweeper
// starts one for a tenant offboarded for SAASAPI_TENANT_PURGE_AFTER
// (default 720h), and an operator can start one at once (POST
// /v1/operator/tenants/{tenant_id}/purge). A purge job is a
// provisioning_jobs row of type purge, published to farmer on the sealed
// internal.tenant.purge subject with the same sealing, lease, retry and
// result path as a deprovision. Farmer erases its own data (Valkey, the
// farmer schema, the object store, the tenant's Transit keys); when its
// successful result arrives, this service deletes the tenant's saas-schema
// rows (tenantpurge.SaasTables), clears the tenant's name and plan, and
// sets it purged. A failed purge leaves the tenant offboarded, with the
// job's fixed error in GET .../status; the sweeper starts a new one no
// more than once a day.
//
// At most one purge job per tenant is pending: starting one writes the
// tenant row's purge_claimed_at, conditional on the value read, in the
// transaction that inserts the job (startPurge), so two replicas, or the
// sweeper and the operator route, never both start one.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/controlplane"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/tenantpurge"
)

// TenantPurgeSettings configures the automatic purge of offboarded
// tenants (Config.TenantPurge; SAASAPI_TENANT_PURGE_*).
type TenantPurgeSettings struct {
	// Enabled lets the outbox sweeper start purges
	// (SAASAPI_TENANT_PURGE_ENABLED, default true). Off, nothing is
	// purged automatically; an operator can still start a purge.
	Enabled bool
	// After is how long a tenant stays offboarded before the sweeper
	// purges it (SAASAPI_TENANT_PURGE_AFTER, default 720h, 1h to 8760h).
	After time.Duration
}

// Defaults and bounds for TenantPurgeSettings. LoadConfig refuses a value
// outside them.
const (
	defaultTenantPurgeAfter = 720 * time.Hour
	minTenantPurgeAfter     = time.Hour
	maxTenantPurgeAfter     = 8760 * time.Hour

	// purgeRetryInterval is how long after one purge job was started the
	// sweeper may start another for the same tenant (decision 4: a failed
	// purge is retried no more than once a day).
	purgeRetryInterval = 24 * time.Hour
)

// DefaultTenantPurgeSettings is what LoadConfig starts from.
func DefaultTenantPurgeSettings() TenantPurgeSettings {
	return TenantPurgeSettings{Enabled: true, After: defaultTenantPurgeAfter}
}

// tenantPurgeSettings is the configuration in use.
var tenantPurgeSettings = DefaultTenantPurgeSettings()

// SetTenantPurgeSettings installs s. Call it once at startup, before
// StartOutboxSweeper and NewRouter. LoadConfig has already validated s.
func SetTenantPurgeSettings(s TenantPurgeSettings) { tenantPurgeSettings = s }

// CurrentTenantPurgeSettings returns the settings in use.
func CurrentTenantPurgeSettings() TenantPurgeSettings { return tenantPurgeSettings }

// loadTenantPurgeSettings overrides s's defaults with whichever
// SAASAPI_TENANT_PURGE_* variables are set, refusing a value that doesn't
// parse or is out of range.
func loadTenantPurgeSettings(s *TenantPurgeSettings) error {
	if v := os.Getenv("SAASAPI_TENANT_PURGE_ENABLED"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("saasapi: SAASAPI_TENANT_PURGE_ENABLED=%q: not a boolean", v)
		}
		s.Enabled = b
	}
	if v := os.Getenv("SAASAPI_TENANT_PURGE_AFTER"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < minTenantPurgeAfter || d > maxTenantPurgeAfter {
			return fmt.Errorf("saasapi: SAASAPI_TENANT_PURGE_AFTER=%q: want a duration from %s to %s", v, minTenantPurgeAfter, maxTenantPurgeAfter)
		}
		s.After = d
	}
	return nil
}

// offboardedSince is when t's retention delay started.
func offboardedSince(t Tenant) time.Time {
	if t.OffboardedAt != nil {
		return *t.OffboardedAt
	}
	return t.UpdatedAt
}

// purgeAfter is when the sweeper purges t, an offboarded tenant, or nil
// with automatic purge off.
func purgeAfter(t Tenant, s TenantPurgeSettings) *time.Time {
	if !s.Enabled || t.Status != TenantStatusOffboarded {
		return nil
	}
	at := offboardedSince(t).Add(s.After).UTC()
	return &at
}

// startPurge's outcomes.
var (
	errPurgeTenantNotFound = errors.New("no such tenant")
	errNotOffboarded       = errors.New("tenant is not offboarded")
	errPurgeInProgress     = errors.New("a purge of the tenant is already pending")
	errPurgeRecent         = errors.New("a purge of the tenant was started less than a day ago")
)

// startPurge starts a purge job for tenantID, which must be offboarded
// with no purge job pending: in one transaction it claims the tenant row
// (purge_claimed_at, conditional on the value read) and inserts the job.
// Unless operator is set, it also refuses a tenant whose last purge job
// started within purgeRetryInterval (errPurgeRecent). The caller
// publishes the job (dispatchPurge) after this returns.
func startPurge(d *gorm.DB, tenantID, trigger string, now time.Time, operator bool) (*ProvisioningJob, error) {
	var job *ProvisioningJob
	err := d.Transaction(func(tx *gorm.DB) error {
		var t Tenant
		if err := tx.Where("id = ?", tenantID).First(&t).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			return errPurgeTenantNotFound
		} else if err != nil {
			return err
		}
		if t.Status != TenantStatusOffboarded {
			return errNotOffboarded
		}
		var pending int64
		if err := tx.Model(&ProvisioningJob{}).
			Where("tenant_id = ? AND type = ? AND status = ?", tenantID, ProvisioningJobPurge, ProvisioningJobPending).
			Count(&pending).Error; err != nil {
			return err
		}
		if pending > 0 {
			return errPurgeInProgress
		}
		if !operator && t.PurgeClaimedAt != nil && now.Before(t.PurgeClaimedAt.Add(purgeRetryInterval)) {
			return errPurgeRecent
		}
		claim := tx.Model(&Tenant{}).Where("id = ? AND status = ?", tenantID, TenantStatusOffboarded)
		if t.PurgeClaimedAt == nil {
			claim = claim.Where("purge_claimed_at IS NULL")
		} else {
			claim = claim.Where("purge_claimed_at = ?", *t.PurgeClaimedAt)
		}
		r := claim.UpdateColumn("purge_claimed_at", now)
		if r.Error != nil {
			return r.Error
		}
		if r.RowsAffected == 0 {
			return errTenantStateChanged
		}
		var err error
		job, err = enqueuePurgeJob(tx, tenantID, trigger)
		return err
	})
	return job, err
}

// enqueuePurgeJob writes a purge job's outbox row; see
// enqueueProvisioningJob.
func enqueuePurgeJob(tx *gorm.DB, tenantID, trigger string) (*ProvisioningJob, error) {
	id, err := newID("pj_")
	if err != nil {
		return nil, err
	}
	// Dated on the outbox clock, which the sweeper's backoff reads.
	job := &ProvisioningJob{ID: id, TenantID: tenantID, Type: ProvisioningJobPurge, Status: ProvisioningJobPending, PurgeTrigger: trigger,
		CreatedAt: dbTime(outboxNow())}
	if err := tx.Create(job).Error; err != nil {
		return nil, err
	}
	return job, nil
}

// dispatchPurge publishes job, a purge job just started, as
// dispatchDeprovisioning does a deprovision job.
func dispatchPurge(_ context.Context, job *ProvisioningJob) {
	subject, payload := provisioningRequest(job, "")
	publishProvisioningJob(job, subject, payload)
}

// sweepTenantPurges is the outbox sweeper's purge job: for every tenant
// offboarded for at least SAASAPI_TENANT_PURGE_AFTER with no purge job
// pending and none started in the last day, it starts one (trigger
// retention) and publishes it. Off with SAASAPI_TENANT_PURGE_ENABLED=false.
func (sw *sweeper) sweepTenantPurges() {
	s := tenantPurgeSettings
	if !s.Enabled {
		return
	}
	now := dbTime(outboxNow())
	var due []Tenant
	if err := sw.d.Where("status = ?", TenantStatusOffboarded).
		Where("COALESCE(offboarded_at, updated_at) <= ?", now.Add(-s.After)).
		Where("purge_claimed_at IS NULL OR purge_claimed_at <= ?", now.Add(-purgeRetryInterval)).
		Order("id").Limit(sweepBatchLimit).Find(&due).Error; err != nil {
		log.Errorf("saasapi: outbox sweep: reading tenants due a purge: %v", err)
		return
	}
	for _, t := range due {
		job, err := startPurge(sw.d, t.ID, controlplane.PurgeTriggerRetention, now, false)
		switch {
		case errors.Is(err, errPurgeInProgress), errors.Is(err, errPurgeRecent), errors.Is(err, errNotOffboarded), errors.Is(err, errTenantStateChanged):
			continue // pending, another replica started one, or it moved on
		case err != nil:
			log.Errorf("saasapi: outbox sweep: starting the purge of tenant %s: %v", t.ID, err)
			continue
		}
		log.Warnf("saasapi: outbox sweep: tenant %s offboarded since %s; starting purge job %s (retention %s)",
			t.ID, offboardedSince(t).UTC().Format(time.RFC3339), job.ID, s.After)
		subject, payload := provisioningRequest(job, "")
		publishProvisioningJobOn(sw.nc, sw.d, job, subject, payload)
	}
}

// purgeSaasRows deletes tenantID's rows from every saas-schema table of
// tenantpurge.SaasTables, in bounded batches, and returns the counts. Run
// before the purge result is recorded, so a failure leaves the job pending
// and the next result (the sweeper publishes the job again) finishes it.
func purgeSaasRows(ctx context.Context, d *gorm.DB, tenantID string) (map[string]int64, error) {
	counts := map[string]int64{}
	for _, table := range tenantpurge.SaasTables {
		n, err := tenantpurge.DeleteRows(ctx, d, table, tenantID, tenantpurge.DefaultBatch)
		counts["saas."+table] = n
		if err != nil {
			return counts, err
		}
	}
	return counts, nil
}

// purgeSaasRowsForResult checks res against its job (a pending purge job
// of the tenant res names, whose tenant is offboarded) and deletes the
// tenant's saas-schema rows. A result for anything else deletes nothing:
// applyProvisioningResult refuses or ignores it afterwards.
func purgeSaasRowsForResult(res controlplane.TenantResult) error {
	var job ProvisioningJob
	if err := db.First(&job, "id = ?", res.JobID).Error; err != nil {
		return fmt.Errorf("looking up job: %w", err)
	}
	if job.Type != ProvisioningJobPurge || job.TenantID != res.TenantID || job.Status != ProvisioningJobPending {
		return nil
	}
	var t Tenant
	if err := db.Where("id = ? AND status = ?", job.TenantID, TenantStatusOffboarded).First(&t).Error; errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	counts, err := purgeSaasRows(context.Background(), db, job.TenantID)
	if err != nil {
		return fmt.Errorf("deleting tenant %s's saas rows (%v so far): %w", job.TenantID, counts, err)
	}
	log.Infof("saasapi: tenant %s's saas rows deleted (job %s): %v", job.TenantID, job.ID, counts)
	return nil
}

// purgeCounts keeps only well-formed categories of a farmer result, for
// the log: fixed names and numbers, at most MaxPurgeCategories of them.
func purgeCounts(in map[string]int64) map[string]int64 {
	out := map[string]int64{}
	for k, v := range in {
		if len(out) == controlplane.MaxPurgeCategories {
			break
		}
		if controlplane.ValidPurgeCategory(k) {
			out[k] = v
		}
	}
	return out
}

// safeStep is a farmer result's failed step, if it is one of the steps.
func safeStep(s string) string {
	if controlplane.ValidPurgeStep(s) {
		return s
	}
	return ""
}

// purgeTenantResponse is POST /v1/operator/tenants/{tenant_id}/purge's
// 202 body.
type purgeTenantResponse struct {
	TenantID string       `json:"tenant_id"`
	JobID    string       `json:"job_id"`
	Status   TenantStatus `json:"status"`
}

// purgeTenant handles POST /v1/operator/tenants/{tenant_id}/purge on the
// operator plane: it starts a purge of an offboarded tenant now, whatever
// its retention delay, and answers 202 with the job's ID. 404
// tenant_not_found for an unknown tenant, 409 not_offboarded for a tenant
// in any other status (a purged one included), 409 purge_in_progress if a
// purge job is pending. Poll GET /tenants/{tenant_id}/status for the
// outcome.
func (p *operatorPlane) purgeTenant(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant_id")
	job, err := startPurge(db, tenantID, controlplane.PurgeTriggerOperator, dbTime(outboxNow()), true)
	switch {
	case errors.Is(err, errPurgeTenantNotFound):
		writeError(w, http.StatusNotFound, "tenant_not_found", "no such tenant")
		return
	case errors.Is(err, errNotOffboarded):
		writeError(w, http.StatusConflict, "not_offboarded", "only an offboarded tenant can be purged")
		return
	case errors.Is(err, errPurgeInProgress), errors.Is(err, errTenantStateChanged):
		writeError(w, http.StatusConflict, "purge_in_progress", "a purge of this tenant is already pending")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to start the purge")
		return
	}
	log.Warnf("saasapi: operator started purge job %s for tenant %s", job.ID, tenantID)
	dispatchPurge(r.Context(), job)
	writeJSON(w, http.StatusAccepted, purgeTenantResponse{TenantID: tenantID, JobID: job.ID, Status: TenantStatusOffboarded})
}
