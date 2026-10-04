package saasapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"gorm.io/gorm"
)

type createTenantRequest struct {
	Name   string `json:"name"`
	PlanID string `json:"plan_id"`
}

type tenantStatusResponse struct {
	TenantID  string       `json:"tenant_id"`
	Status    TenantStatus `json:"status"`
	LastError string       `json:"last_error,omitempty"`
	// Warning is set when the most recent job succeeded with a warning —
	// e.g. offboarding a tenant that was never provisioned on farmer.
	Warning string `json:"warning,omitempty"`
}

// CreateTenant handles POST /tenants (design doc §1.1). It's async: the
// tenant row is created with status "pending" and a provisioning_jobs
// outbox row is written in the same transaction, then the provisioning
// request is published to farmer over NATS (see provisioning.go). The
// tenant moves to active/failed when farmer's result comes back. The
// response is 202 Accepted, never 201, since provisioning isn't complete
// yet.
func CreateTenant(w http.ResponseWriter, r *http.Request) {
	var req createTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body must be valid JSON")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "name is required")
		return
	}

	tenantID, err := newID("t_")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to generate tenant id")
		return
	}
	tenant := Tenant{
		ID:     tenantID,
		Name:   req.Name,
		Status: TenantStatusPending,
		PlanID: req.PlanID,
	}

	var job *ProvisioningJob
	err = db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&tenant).Error; err != nil {
			return err
		}
		var jobErr error
		job, jobErr = enqueueProvisioningJob(tx, tenant.ID, ProvisioningJobProvision)
		return jobErr
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to create tenant")
		return
	}

	dispatchProvisioning(r.Context(), job, tenant.Name)

	writeJSON(w, http.StatusAccepted, tenantStatusResponse{TenantID: tenant.ID, Status: tenant.Status})
}

// GetTenant handles GET /tenants/{tenant_id} (design doc §1.1).
func GetTenant(w http.ResponseWriter, r *http.Request) {
	tenant, ok := lookupTenant(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, tenant)
}

type patchTenantRequest struct {
	Name   *string `json:"name"`
	PlanID *string `json:"plan_id"`
}

// PatchTenant handles PATCH /tenants/{tenant_id} (design doc §1.1),
// updating name/plan. The design doc also mentions "metadata" in prose,
// but §4.2's schema sketch has no metadata column on `saas.tenants` —
// deliberately left out here rather than inventing schema beyond what's
// specified; see the PR description.
func PatchTenant(w http.ResponseWriter, r *http.Request) {
	tenant, ok := lookupTenant(w, r)
	if !ok {
		return
	}

	var req patchTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body must be valid JSON")
		return
	}

	updates := map[string]any{}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "name cannot be empty")
			return
		}
		updates["name"] = name
	}
	if req.PlanID != nil {
		updates["plan_id"] = *req.PlanID
	}
	if len(updates) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "no updatable fields provided")
		return
	}

	if err := db.Model(&tenant).Updates(updates).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to update tenant")
		return
	}
	if err := db.First(&tenant, "id = ?", tenant.ID).Error; err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to reload tenant")
		return
	}
	writeJSON(w, http.StatusOK, tenant)
}

// errProvisioningInProgress / errTenantStateChanged are DeleteTenant's
// in-transaction conflict outcomes.
var (
	errProvisioningInProgress = errors.New("tenant provisioning is still in progress")
	errTenantStateChanged     = errors.New("tenant status changed concurrently")
)

// DeleteTenant handles DELETE /tenants/{tenant_id} (design doc §1.1) —
// offboarding follows the same async create-row-then-poll pattern as
// CreateTenant.
//
// A tenant whose provisioning is still in flight (status pending, or any
// provision job still pending) can't be deleted yet: 409
// provisioning_in_progress, retry once GET .../status leaves pending.
// Only active or failed tenants can be offboarded, and that's enforced by
// a conditional update inside the transaction, not just the pre-check, so
// a concurrent status change can't slip past it.
//
// A provision job the outbox sweeper published more than once doesn't
// hold DELETE up: an earlier copy can still be running on one farmer
// replica while the deprovision runs on another, and farmer itself closes
// that race (internal/pki's ProvisionTenant re-checks the tenant's deleted
// state after its push and pushes the lockout again if the deprovision
// won; see "Outbox re-dispatch sweeper" in
// docs/design/imas-internal-api-account.md).
func DeleteTenant(w http.ResponseWriter, r *http.Request) {
	tenant, ok := lookupTenant(w, r)
	if !ok {
		return
	}
	switch tenant.Status {
	case TenantStatusOffboarding, TenantStatusOffboarded:
		writeError(w, http.StatusConflict, "offboarding_in_progress", "tenant is already offboarding or offboarded")
		return
	case TenantStatusPending:
		writeError(w, http.StatusConflict, "provisioning_in_progress", "tenant provisioning is still in progress; retry once it has completed")
		return
	}

	var job *ProvisioningJob
	err := db.Transaction(func(tx *gorm.DB) error {
		var inFlight int64
		if err := tx.Model(&ProvisioningJob{}).
			Where("tenant_id = ? AND type = ? AND status = ?", tenant.ID, ProvisioningJobProvision, ProvisioningJobPending).
			Count(&inFlight).Error; err != nil {
			return err
		}
		if inFlight > 0 {
			return errProvisioningInProgress
		}
		res := tx.Model(&Tenant{}).
			Where("id = ? AND status IN ?", tenant.ID, []TenantStatus{TenantStatusActive, TenantStatusFailed}).
			Update("status", TenantStatusOffboarding)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return errTenantStateChanged
		}
		var jobErr error
		job, jobErr = enqueueProvisioningJob(tx, tenant.ID, ProvisioningJobDeprovision)
		return jobErr
	})
	switch {
	case errors.Is(err, errProvisioningInProgress):
		writeError(w, http.StatusConflict, "provisioning_in_progress", "tenant provisioning is still in progress; retry once it has completed")
		return
	case errors.Is(err, errTenantStateChanged):
		writeError(w, http.StatusConflict, "tenant_state_changed", "tenant status changed while offboarding was requested; retry")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to start tenant offboarding")
		return
	}

	dispatchDeprovisioning(r.Context(), job)

	writeJSON(w, http.StatusAccepted, tenantStatusResponse{TenantID: tenant.ID, Status: TenantStatusOffboarding})
}

// GetTenantStatus handles GET /tenants/{tenant_id}/status (design doc
// §1.1) — a lightweight status-only poll, including the last provisioning
// error if the most recent outbox job for this tenant failed, or its
// warning if it succeeded with one (both fixed, caller-safe messages —
// see provisioning.go's publicJobError and controlplane.PublicWarningMessage).
func GetTenantStatus(w http.ResponseWriter, r *http.Request) {
	tenant, ok := lookupTenant(w, r)
	if !ok {
		return
	}

	resp := tenantStatusResponse{TenantID: tenant.ID, Status: tenant.Status}
	var job ProvisioningJob
	if err := db.Where("tenant_id = ?", tenant.ID).Order("created_at DESC").First(&job).Error; err == nil {
		switch {
		case job.Status == ProvisioningJobFailed &&
			(tenant.Status == TenantStatusFailed || tenant.Status == TenantStatusOffboarding):
			resp.LastError = job.LastError
		case job.Status == ProvisioningJobSucceeded:
			resp.Warning = job.Warning
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func lookupTenant(w http.ResponseWriter, r *http.Request) (Tenant, bool) {
	tenantID := r.PathValue("tenant_id")
	var tenant Tenant
	err := db.First(&tenant, "id = ?", tenantID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		writeError(w, http.StatusNotFound, "tenant_not_found", "no such tenant")
		return Tenant{}, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to look up tenant")
		return Tenant{}, false
	}
	return tenant, true
}
