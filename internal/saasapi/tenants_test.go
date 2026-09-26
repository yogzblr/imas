package saasapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/controlplane"
)

func doRequest(t *testing.T, h http.HandlerFunc, method, path string, pathValues map[string]string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encoding request body: %v", err)
		}
	}
	r := httptest.NewRequest(method, path, &buf)
	for k, v := range pathValues {
		r.SetPathValue(k, v)
	}
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func TestCreateTenant(t *testing.T) {
	gdb := newTestDB(t)

	w := doRequest(t, CreateTenant, "POST", "/v1/tenants", nil, createTenantRequest{Name: "Acme Bank", PlanID: "plan_std"})
	if w.Code != 202 {
		t.Fatalf("status = %d, want 202, body=%s", w.Code, w.Body.String())
	}

	var resp tenantStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.Status != TenantStatusPending {
		t.Fatalf("status = %q, want pending", resp.Status)
	}
	if resp.TenantID == "" {
		t.Fatalf("expected a non-empty tenant_id")
	}

	var job ProvisioningJob
	if err := gdb.Where("tenant_id = ?", resp.TenantID).First(&job).Error; err != nil {
		t.Fatalf("expected a provisioning_jobs row: %v", err)
	}
	if job.Type != ProvisioningJobProvision || job.Status != ProvisioningJobPending {
		t.Fatalf("unexpected job %+v", job)
	}
}

func TestCreateTenantMissingName(t *testing.T) {
	newTestDB(t)
	w := doRequest(t, CreateTenant, "POST", "/v1/tenants", nil, createTenantRequest{PlanID: "plan_std"})
	if w.Code != 400 {
		t.Fatalf("status = %d, want 400, body=%s", w.Code, w.Body.String())
	}
	var errResp errorResponse
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "invalid_request" {
		t.Fatalf("error code = %q, want invalid_request", errResp.Error)
	}
}

func mustCreateTenant(t *testing.T, name string) string {
	t.Helper()
	w := doRequest(t, CreateTenant, "POST", "/v1/tenants", nil, createTenantRequest{Name: name})
	if w.Code != 202 {
		t.Fatalf("creating tenant: status = %d, body=%s", w.Code, w.Body.String())
	}
	var resp tenantStatusResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	return resp.TenantID
}

func TestGetTenant(t *testing.T) {
	newTestDB(t)
	id := mustCreateTenant(t, "Acme Bank")

	w := doRequest(t, GetTenant, "GET", "/v1/tenants/"+id, map[string]string{"tenant_id": id}, nil)
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	var tenant Tenant
	json.Unmarshal(w.Body.Bytes(), &tenant)
	if tenant.Name != "Acme Bank" {
		t.Fatalf("name = %q, want Acme Bank", tenant.Name)
	}
}

func TestGetTenantNotFound(t *testing.T) {
	newTestDB(t)
	w := doRequest(t, GetTenant, "GET", "/v1/tenants/nope", map[string]string{"tenant_id": "nope"}, nil)
	if w.Code != 404 {
		t.Fatalf("status = %d, want 404, body=%s", w.Code, w.Body.String())
	}
	var errResp errorResponse
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "tenant_not_found" {
		t.Fatalf("error code = %q, want tenant_not_found", errResp.Error)
	}
}

func TestPatchTenant(t *testing.T) {
	newTestDB(t)
	id := mustCreateTenant(t, "Acme Bank")

	newName := "Acme Bank International"
	w := doRequest(t, PatchTenant, "PATCH", "/v1/tenants/"+id, map[string]string{"tenant_id": id}, patchTenantRequest{Name: &newName})
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	var tenant Tenant
	json.Unmarshal(w.Body.Bytes(), &tenant)
	if tenant.Name != newName {
		t.Fatalf("name = %q, want %q", tenant.Name, newName)
	}
}

func TestPatchTenantNoFields(t *testing.T) {
	newTestDB(t)
	id := mustCreateTenant(t, "Acme Bank")

	w := doRequest(t, PatchTenant, "PATCH", "/v1/tenants/"+id, map[string]string{"tenant_id": id}, patchTenantRequest{})
	if w.Code != 400 {
		t.Fatalf("status = %d, want 400, body=%s", w.Code, w.Body.String())
	}
}

// completeProvisioning applies a result for tenantID's pending provision
// job the way the NATS result listener does, as if farmer had answered.
func completeProvisioning(t *testing.T, gdb *gorm.DB, tenantID string, res controlplane.TenantResult) {
	t.Helper()
	var job ProvisioningJob
	if err := gdb.Where("tenant_id = ? AND type = ?", tenantID, ProvisioningJobProvision).First(&job).Error; err != nil {
		t.Fatalf("loading provision job: %v", err)
	}
	res.JobID, res.TenantID = job.ID, tenantID
	if err := applyProvisioningResult(ProvisioningJobProvision, res); err != nil {
		t.Fatalf("applyProvisioningResult: %v", err)
	}
}

func TestDeleteTenant(t *testing.T) {
	gdb := newTestDB(t)
	id := mustCreateTenant(t, "Acme Bank")
	completeProvisioning(t, gdb, id, controlplane.TenantResult{Status: controlplane.StatusActive})

	w := doRequest(t, DeleteTenant, "DELETE", "/v1/tenants/"+id, map[string]string{"tenant_id": id}, nil)
	if w.Code != 202 {
		t.Fatalf("status = %d, want 202, body=%s", w.Code, w.Body.String())
	}
	var resp tenantStatusResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Status != TenantStatusOffboarding {
		t.Fatalf("status = %q, want offboarding", resp.Status)
	}

	var job ProvisioningJob
	if err := gdb.Where("tenant_id = ? AND type = ?", id, ProvisioningJobDeprovision).First(&job).Error; err != nil {
		t.Fatalf("expected a deprovision job: %v", err)
	}

	// A second delete while already offboarding must conflict, not
	// silently enqueue a second deprovision job.
	w2 := doRequest(t, DeleteTenant, "DELETE", "/v1/tenants/"+id, map[string]string{"tenant_id": id}, nil)
	if w2.Code != 409 {
		t.Fatalf("second delete status = %d, want 409, body=%s", w2.Code, w2.Body.String())
	}
}

// TestDeleteTenantRejectedWhileProvisioning: DELETE on a tenant whose
// provisioning is still in flight is a 409, and changes nothing — no
// deprovision job, status left pending — so a provision and a deprovision
// request can never race each other on farmer.
func TestDeleteTenantRejectedWhileProvisioning(t *testing.T) {
	gdb := newTestDB(t)
	id := mustCreateTenant(t, "Still Provisioning Co")

	w := doRequest(t, DeleteTenant, "DELETE", "/v1/tenants/"+id, map[string]string{"tenant_id": id}, nil)
	if w.Code != 409 {
		t.Fatalf("status = %d, want 409, body=%s", w.Code, w.Body.String())
	}
	var errResp errorResponse
	json.Unmarshal(w.Body.Bytes(), &errResp)
	if errResp.Error != "provisioning_in_progress" {
		t.Fatalf("error code = %q, want provisioning_in_progress", errResp.Error)
	}
	var n int64
	gdb.Model(&ProvisioningJob{}).Where("tenant_id = ? AND type = ?", id, ProvisioningJobDeprovision).Count(&n)
	if n != 0 {
		t.Fatalf("expected no deprovision job, found %d", n)
	}
	var tenant Tenant
	gdb.First(&tenant, "id = ?", id)
	if tenant.Status != TenantStatusPending {
		t.Fatalf("tenant status = %q, want it left pending", tenant.Status)
	}

	// Once provisioning completes, the same DELETE goes through.
	completeProvisioning(t, gdb, id, controlplane.TenantResult{Status: controlplane.StatusActive})
	if w := doRequest(t, DeleteTenant, "DELETE", "/v1/tenants/"+id, map[string]string{"tenant_id": id}, nil); w.Code != 202 {
		t.Fatalf("status after provisioning = %d, want 202, body=%s", w.Code, w.Body.String())
	}
}

// TestDeleteTenantRejectedWithPendingProvisionJob covers the in-transaction
// check: even if the tenant row's status isn't pending, a still-pending
// provision job (e.g. one a future outbox sweeper is re-dispatching) means
// provisioning is in flight, so DELETE is refused.
func TestDeleteTenantRejectedWithPendingProvisionJob(t *testing.T) {
	gdb := newTestDB(t)
	tenant, _ := seedTenantAndJob(t, gdb, TenantStatusFailed, ProvisioningJobProvision)

	w := doRequest(t, DeleteTenant, "DELETE", "/v1/tenants/"+tenant.ID, map[string]string{"tenant_id": tenant.ID}, nil)
	if w.Code != 409 {
		t.Fatalf("status = %d, want 409, body=%s", w.Code, w.Body.String())
	}
	var got Tenant
	gdb.First(&got, "id = ?", tenant.ID)
	if got.Status != TenantStatusFailed {
		t.Fatalf("tenant status = %q, want it left failed", got.Status)
	}
}

// A tenant whose provisioning failed (nothing in flight) can be deleted.
func TestDeleteFailedTenant(t *testing.T) {
	gdb := newTestDB(t)
	id := mustCreateTenant(t, "Failed Co")
	completeProvisioning(t, gdb, id, controlplane.TenantResult{Status: controlplane.StatusFailed, ErrorCode: controlplane.ErrorInternal})
	if w := doRequest(t, DeleteTenant, "DELETE", "/v1/tenants/"+id, map[string]string{"tenant_id": id}, nil); w.Code != 202 {
		t.Fatalf("status = %d, want 202, body=%s", w.Code, w.Body.String())
	}
}

func TestGetTenantStatus(t *testing.T) {
	newTestDB(t)
	id := mustCreateTenant(t, "Acme Bank")

	w := doRequest(t, GetTenantStatus, "GET", "/v1/tenants/"+id+"/status", map[string]string{"tenant_id": id}, nil)
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	var resp tenantStatusResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Status != TenantStatusPending {
		t.Fatalf("status = %q, want pending", resp.Status)
	}
	if resp.LastError != "" {
		t.Fatalf("expected no last_error for a freshly created tenant, got %q", resp.LastError)
	}
}
