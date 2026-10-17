package saasapi

// S6: tenant_purge.go and the purge's paths through provisioning.go,
// tenants.go and the operator plane.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/tenantpurge"
)

// newPurgeTestDB is newTestDB emptied of tenants and outbox rows: the
// sweeper looks at every tenant.
func newPurgeTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	gdb := newTestDB(t)
	// One connection: SQLite's shared-cache mode locks whole tables, so
	// concurrent sweepers would deadlock each other here. On MySQL they
	// run concurrently: TestMySQLStartPurgeOnePending.
	if sqlDB, err := gdb.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
		t.Cleanup(func() { sqlDB.SetMaxOpenConns(0) })
	}
	empty := func() {
		clearOutbox(t, gdb)
		for _, m := range []any{&Tenant{}, &EnrollmentKey{}, &AssetLink{}, &TenantUpdatePolicy{}} {
			if err := gdb.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(m).Error; err != nil {
				t.Fatal(err)
			}
		}
	}
	empty()
	t.Cleanup(empty)
	prev := tenantPurgeSettings
	t.Cleanup(func() { SetTenantPurgeSettings(prev) })
	SetTenantPurgeSettings(DefaultTenantPurgeSettings())
	return gdb
}

// offboardedTenant creates an offboarded tenant, offboarded at since.
func offboardedTenant(t *testing.T, gdb *gorm.DB, id string, since time.Time) Tenant {
	t.Helper()
	at := since.UTC()
	tenant := Tenant{ID: id, Name: "Customer " + id, PlanID: "gold", Status: TenantStatusOffboarded, OffboardedAt: &at}
	if err := gdb.Create(&tenant).Error; err != nil {
		t.Fatal(err)
	}
	return tenant
}

func purgeJobs(t *testing.T, gdb *gorm.DB, tenantID string) []ProvisioningJob {
	t.Helper()
	var jobs []ProvisioningJob
	if err := gdb.Where("tenant_id = ? AND type = ?", tenantID, ProvisioningJobPurge).Order("created_at").Find(&jobs).Error; err != nil {
		t.Fatal(err)
	}
	return jobs
}

func TestLoadConfigTenantPurge(t *testing.T) {
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TenantPurge != (TenantPurgeSettings{Enabled: true, After: 720 * time.Hour}) {
		t.Fatalf("defaults = %+v", cfg.TenantPurge)
	}
	for _, edge := range []string{"1h", "8760h", "48h"} {
		t.Setenv("SAASAPI_TENANT_PURGE_AFTER", edge)
		cfg, err := LoadConfig()
		if want, _ := time.ParseDuration(edge); err != nil || cfg.TenantPurge.After != want {
			t.Fatalf("SAASAPI_TENANT_PURGE_AFTER=%s: %+v, %v", edge, cfg.TenantPurge, err)
		}
	}
	for _, bad := range []string{"59m", "8761h", "0", "-1h", "30d", "soon"} {
		t.Setenv("SAASAPI_TENANT_PURGE_AFTER", bad)
		if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "SAASAPI_TENANT_PURGE_AFTER") {
			t.Errorf("SAASAPI_TENANT_PURGE_AFTER=%s: %v, want a startup error", bad, err)
		}
	}
	t.Setenv("SAASAPI_TENANT_PURGE_AFTER", "")
	t.Setenv("SAASAPI_TENANT_PURGE_ENABLED", "false")
	if cfg, err := LoadConfig(); err != nil || cfg.TenantPurge.Enabled {
		t.Fatalf("SAASAPI_TENANT_PURGE_ENABLED=false: %+v, %v", cfg.TenantPurge, err)
	}
	t.Setenv("SAASAPI_TENANT_PURGE_ENABLED", "maybe")
	if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "SAASAPI_TENANT_PURGE_ENABLED") {
		t.Errorf("SAASAPI_TENANT_PURGE_ENABLED=maybe: %v, want a startup error", err)
	}
}

// subscribePurges collects the sealed purge requests farmer would get.
func subscribePurges(t *testing.T, nc *nats.Conn) func(want int) []controlplane.TenantPurgeRequest {
	t.Helper()
	sub, err := nc.SubscribeSync(controlplane.SubjectTenantPurge)
	if err != nil {
		t.Fatal(err)
	}
	_ = nc.Flush()
	return func(want int) []controlplane.TenantPurgeRequest {
		t.Helper()
		var out []controlplane.TenantPurgeRequest
		for len(out) < want {
			msg, err := sub.NextMsg(2 * time.Second)
			if err != nil {
				t.Fatalf("waiting for purge request %d of %d: %v", len(out)+1, want, err)
			}
			var req controlplane.TenantPurgeRequest
			if _, err := farmerOpenRequest(msg, &req); err != nil {
				t.Fatalf("opening a purge request as farmer: %v", err)
			}
			out = append(out, req)
		}
		if msg, err := sub.NextMsg(200 * time.Millisecond); err == nil {
			t.Fatalf("an extra purge request: %s", msg.Subject)
		}
		return out
	}
}

// Retention: nothing before SAASAPI_TENANT_PURGE_AFTER, a purge job
// (sealed, trigger retention) once it has passed, one per tenant however
// many sweepers run, none while one is pending, a new one at most daily
// after a failure, and nothing with the switch off.
func TestSweepTenantPurges_Retention(t *testing.T) {
	gdb := newPurgeTestDB(t)
	clock := useOutboxClock(t)
	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	received := subscribePurges(t, nc)
	SetTenantPurgeSettings(TenantPurgeSettings{Enabled: true, After: 48 * time.Hour})

	offboardedTenant(t, gdb, "t_due", clock.Now().Add(-47*time.Hour))
	// A tenant offboarded by an older saasapi has no offboarded_at: its
	// updated_at counts.
	old := Tenant{ID: "t_old", Name: "Old", Status: TenantStatusOffboarded}
	if err := gdb.Create(&old).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Model(&Tenant{}).Where("id = ?", "t_old").UpdateColumn("updated_at", clock.Now().Add(-47*time.Hour)).Error; err != nil {
		t.Fatal(err)
	}
	active := Tenant{ID: "t_active", Name: "Active", Status: TenantStatusActive}
	if err := gdb.Create(&active).Error; err != nil {
		t.Fatal(err)
	}
	gdb.Model(&Tenant{}).Where("id = ?", "t_active").UpdateColumn("updated_at", clock.Now().Add(-1000*time.Hour))

	sw := testSweeper(gdb, nc)
	sw.sweepTenantPurges()
	received(0)
	if n := len(purgeJobs(t, gdb, "t_due")) + len(purgeJobs(t, gdb, "t_old")); n != 0 {
		t.Fatalf("%d purge jobs before the retention delay", n)
	}

	clock.Advance(2 * time.Hour)
	sweepConcurrently(testSweeper(gdb, nc), testSweeper(gdb, nc), testSweeper(gdb, nc))
	reqs := received(2)
	got := map[string]string{}
	for _, r := range reqs {
		got[r.TenantID] = r.Trigger
	}
	if got["t_due"] != controlplane.PurgeTriggerRetention || got["t_old"] != controlplane.PurgeTriggerRetention {
		t.Fatalf("purge requests %+v", reqs)
	}
	for _, id := range []string{"t_due", "t_old"} {
		jobs := purgeJobs(t, gdb, id)
		if len(jobs) != 1 || jobs[0].Status != ProvisioningJobPending || jobs[0].PurgeTrigger != controlplane.PurgeTriggerRetention || jobs[0].Attempts != 1 {
			t.Fatalf("%s's purge jobs %+v", id, jobs)
		}
	}
	if len(purgeJobs(t, gdb, "t_active")) != 0 {
		t.Fatal("an active tenant got a purge job")
	}

	// Pending: no second job.
	clock.Advance(25 * time.Hour)
	sw.sweepTenantPurges()
	received(0)

	// Failed: a new job only a day after the last one started.
	job := purgeJobs(t, gdb, "t_due")[0]
	if err := applyProvisioningResult(ProvisioningJobPurge, controlplane.TenantResult{
		JobID: job.ID, TenantID: "t_due", Status: controlplane.StatusFailed, ErrorCode: controlplane.ErrorPurgeIncomplete, FailedStep: "objects",
	}); err != nil {
		t.Fatal(err)
	}
	var tenant Tenant
	gdb.First(&tenant, "id = ?", "t_due")
	gdb.Model(&Tenant{}).Where("id = ?", "t_due").UpdateColumn("purge_claimed_at", clock.Now().Add(-23*time.Hour))
	sw.sweepTenantPurges()
	received(0)
	clock.Advance(2 * time.Hour)
	sw.sweepTenantPurges()
	if reqs := received(1); reqs[0].TenantID != "t_due" {
		t.Fatalf("retry %+v", reqs)
	}
	if jobs := purgeJobs(t, gdb, "t_due"); len(jobs) != 2 || jobs[1].Status != ProvisioningJobPending {
		t.Fatalf("t_due's jobs after the retry %+v", jobs)
	}

	// Off: nothing, whatever is due.
	offboardedTenant(t, gdb, "t_off", clock.Now().Add(-1000*time.Hour))
	SetTenantPurgeSettings(TenantPurgeSettings{Enabled: false, After: 48 * time.Hour})
	sw.sweepTenantPurges()
	received(0)
	if len(purgeJobs(t, gdb, "t_off")) != 0 {
		t.Fatal("a purge was started with SAASAPI_TENANT_PURGE_ENABLED=false")
	}
}

// seedSaasRows gives tenantID one row in each saas table it owns, with a
// sprout of the same ID as every other tenant's.
func seedSaasRows(t *testing.T, gdb *gorm.DB, tenantID string) {
	t.Helper()
	now := time.Now().UTC()
	v := "1.0.0"
	for _, row := range []any{
		&EnrollmentKey{KeyID: "ek_" + tenantID, TenantID: tenantID, KeyHash: strings.Repeat("a", 64), Expiry: now.Add(time.Hour), MaxUses: 1},
		&AssetLink{ID: "al_" + tenantID, TenantID: tenantID, SproutID: "web-01", AssetID: "asset-" + tenantID, LinkedAt: now},
		&AssetActionBatch{ID: "b_" + tenantID, TenantID: tenantID, ActionType: controlplane.ActionCmdRun, ActionParams: "{}", RequestedAssetIDs: "[]"},
		&AssetActionItem{BatchID: "b_" + tenantID, AssetID: "asset-" + tenantID, TenantID: tenantID, SproutID: "web-01", Status: ActionItemFailed},
		&TenantUpdatePolicy{TenantID: tenantID, ApprovedVersion: &v},
	} {
		if err := gdb.Create(row).Error; err != nil {
			t.Fatalf("seeding %T for %s: %v", row, tenantID, err)
		}
	}
}

func saasRowCounts(t *testing.T, gdb *gorm.DB, tenantID string) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	for _, table := range tenantpurge.SaasTables {
		var n int64
		if err := gdb.Table(table).Where("tenant_id = ?", tenantID).Count(&n).Error; err != nil {
			t.Fatal(err)
		}
		out[table] = n
	}
	return out
}

// A deprovision result starts the retention delay; a successful purge
// result deletes the tenant's saas rows (no other tenant's, even with a
// sprout of the same ID), clears its name and plan and sets it purged,
// once; a failed one leaves it offboarded with the error in GET
// .../status.
func TestApplyPurgeResults(t *testing.T) {
	gdb := newPurgeTestDB(t)
	clock := useOutboxClock(t)

	tenant, job := seedTenantAndJob(t, gdb, TenantStatusOffboarding, ProvisioningJobDeprovision)
	if err := applyProvisioningResult(ProvisioningJobDeprovision, controlplane.TenantResult{JobID: job.ID, TenantID: tenant.ID, Status: controlplane.StatusOffboarded}); err != nil {
		t.Fatal(err)
	}
	got, _ := reload(t, gdb, tenant.ID, job.ID)
	if got.Status != TenantStatusOffboarded || got.OffboardedAt == nil || !got.OffboardedAt.Equal(clock.Now()) {
		t.Fatalf("after the deprovision result: %+v", got)
	}

	for _, id := range []string{"t_a", "t_b"} {
		offboardedTenant(t, gdb, id, clock.Now().Add(-time.Hour))
		seedSaasRows(t, gdb, id)
	}
	pjob, err := startPurge(gdb, "t_a", controlplane.PurgeTriggerOperator, clock.Now(), true)
	if err != nil {
		t.Fatal(err)
	}
	// A failure first: offboarded, the error shown, nothing deleted.
	if err := applyProvisioningResult(ProvisioningJobPurge, controlplane.TenantResult{JobID: pjob.ID, TenantID: "t_a", Status: controlplane.StatusFailed, ErrorCode: controlplane.ErrorPurgeRefused}); err != nil {
		t.Fatal(err)
	}
	status := tenantStatus(t, "t_a")
	if status.Status != TenantStatusOffboarded || !strings.Contains(status.LastError, "refused to erase") || !strings.Contains(status.LastError, pjob.ID) {
		t.Fatalf("status after a failed purge %+v", status)
	}
	if c := saasRowCounts(t, gdb, "t_a"); c["asset_links"] != 1 {
		t.Fatalf("a failed purge deleted rows: %v", c)
	}

	pjob, err = startPurge(gdb, "t_a", controlplane.PurgeTriggerOperator, clock.Now(), true)
	if err != nil {
		t.Fatal(err)
	}
	ok := controlplane.TenantResult{JobID: pjob.ID, TenantID: "t_a", Status: controlplane.StatusPurged, Counts: map[string]int64{"db.props": 4}}
	// A result naming another tenant is refused and deletes nothing.
	wrong := ok
	wrong.TenantID = "t_b"
	if err := applyProvisioningResult(ProvisioningJobPurge, wrong); !errors.Is(err, errUnexpectedResult) {
		t.Fatalf("a purge result for another tenant: %v", err)
	}
	if c := saasRowCounts(t, gdb, "t_b"); c["asset_links"] != 1 {
		t.Fatalf("a mismatched result deleted t_b's rows: %v", c)
	}
	if err := applyProvisioningResult(ProvisioningJobPurge, ok); err != nil {
		t.Fatal(err)
	}
	var purged Tenant
	gdb.First(&purged, "id = ?", "t_a")
	if purged.Status != TenantStatusPurged || purged.Name != "" || purged.PlanID != "" {
		t.Fatalf("purged tenant %+v", purged)
	}
	for table, n := range saasRowCounts(t, gdb, "t_a") {
		if n != 0 {
			t.Errorf("t_a still has %d rows in %s", n, table)
		}
	}
	for table, n := range saasRowCounts(t, gdb, "t_b") {
		if n != 1 {
			t.Errorf("t_b has %d rows in %s, want 1", n, table)
		}
	}
	var jobs int64
	gdb.Model(&ProvisioningJob{}).Where("tenant_id = ?", "t_a").Count(&jobs)
	if jobs != 2 {
		t.Errorf("t_a's provisioning jobs: %d, want both purge jobs kept", jobs)
	}
	// Applied once.
	seedSaasRows(t, gdb, "t_c")
	if err := applyProvisioningResult(ProvisioningJobPurge, ok); err != nil {
		t.Fatal(err)
	}
	if st := tenantStatus(t, "t_a"); st.Status != TenantStatusPurged || st.LastError != "" || st.PurgeAfter != nil {
		t.Fatalf("status of a purged tenant %+v", st)
	}
	// An unexpected status for a purge job is refused.
	if err := applyProvisioningResult(ProvisioningJobPurge, controlplane.TenantResult{JobID: pjob.ID, TenantID: "t_a", Status: controlplane.StatusOffboarded}); !errors.Is(err, errUnexpectedResult) {
		t.Errorf("an offboarded status for a purge job: %v", err)
	}
}

func tenantStatus(t *testing.T, id string) tenantStatusResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/tenants/"+id+"/status", nil)
	req.SetPathValue("tenant_id", id)
	w := httptest.NewRecorder()
	GetTenantStatus(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET status of %s: %d %s", id, w.Code, w.Body)
	}
	var out tenantStatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(w.Body.String(), "purge_after") != (out.PurgeAfter != nil) {
		t.Fatalf("purge_after shown wrongly: %s", w.Body)
	}
	return out
}

// GET .../status shows purge_after (RFC 3339) for an offboarded tenant
// with automatic purge on, and not otherwise.
func TestTenantStatusPurgeAfter(t *testing.T) {
	gdb := newPurgeTestDB(t)
	since := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	offboardedTenant(t, gdb, "t_off", since)
	st := tenantStatus(t, "t_off")
	if st.PurgeAfter == nil || !st.PurgeAfter.Equal(since.Add(720*time.Hour)) {
		t.Fatalf("purge_after %v", st.PurgeAfter)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/tenants/t_off/status", nil)
	req.SetPathValue("tenant_id", "t_off")
	w := httptest.NewRecorder()
	GetTenantStatus(w, req)
	if !strings.Contains(w.Body.String(), `"purge_after":"2026-10-01T12:00:00Z"`) {
		t.Errorf("purge_after not RFC 3339: %s", w.Body)
	}
	SetTenantPurgeSettings(TenantPurgeSettings{Enabled: false, After: time.Hour})
	if st := tenantStatus(t, "t_off"); st.PurgeAfter != nil {
		t.Errorf("purge_after with automatic purge off: %v", st.PurgeAfter)
	}
	SetTenantPurgeSettings(DefaultTenantPurgeSettings())
	gdb.Create(&Tenant{ID: "t_live", Name: "Live", Status: TenantStatusActive})
	if st := tenantStatus(t, "t_live"); st.PurgeAfter != nil {
		t.Errorf("purge_after for an active tenant: %v", st.PurgeAfter)
	}
}

// A purged tenant keeps its record, but nothing can be stored for it
// again, and it can't be renamed or offboarded again.
func TestPurgedTenantAcceptsNoData(t *testing.T) {
	gdb := newPurgeTestDB(t)
	gdb.Create(&Tenant{ID: "t_gone", Status: TenantStatusPurged})
	do := func(h http.HandlerFunc, method, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/v1/tenants/t_gone", strings.NewReader(body))
		req.SetPathValue("tenant_id", "t_gone")
		w := httptest.NewRecorder()
		h(w, req)
		return w
	}
	if w := do(PatchTenant, http.MethodPatch, `{"name":"Back"}`); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "tenant_purged") {
		t.Errorf("PATCH a purged tenant: %d %s", w.Code, w.Body)
	}
	if w := do(DeleteTenant, http.MethodDelete, ""); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "offboarding_in_progress") {
		t.Errorf("DELETE a purged tenant: %d %s", w.Code, w.Body)
	}
	if w := do(CreateEnrollmentKey, http.MethodPost, `{"expires_in_hours":1,"max_uses":1}`); w.Code != http.StatusNotFound {
		t.Errorf("an enrollment key for a purged tenant: %d %s", w.Code, w.Body)
	}
	if w := do(GetTenant, http.MethodGet, ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"status":"purged"`) {
		t.Errorf("GET a purged tenant: %d %s", w.Code, w.Body)
	}
	var n int64
	gdb.Model(&EnrollmentKey{}).Where("tenant_id = ?", "t_gone").Count(&n)
	if n != 0 {
		t.Error("an enrollment key was stored for a purged tenant")
	}
}

func purgeRoute(t *testing.T, h http.Handler, token, tenantID string) (int, map[string]any) {
	t.Helper()
	return operatorDo(t, h, token, http.MethodPost, "/v1/operator/tenants/"+tenantID+"/purge", nil)
}

// POST /v1/operator/tenants/{tenant_id}/purge: the operator token only;
// 404, 409 not_offboarded, 202 with the job's ID (sealed request,
// trigger operator, before the retention delay), then 409
// purge_in_progress while it is pending; rate limited.
func TestOperatorPurgeTenant(t *testing.T) {
	gdb := newPurgeTestDB(t)
	clock := useOutboxClock(t)
	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	prevBus := bus
	SetBus(nc)
	t.Cleanup(func() { SetBus(prevBus) })
	received := subscribePurges(t, nc)
	p := &operatorPlane{tokens: [][]byte{[]byte(testOperatorToken)}, limiter: unlimited{}}
	h := p.handler()

	offboardedTenant(t, gdb, "t_now", clock.Now())
	gdb.Create(&Tenant{ID: "t_live", Name: "Live", Status: TenantStatusActive})
	gdb.Create(&Tenant{ID: "t_gone", Status: TenantStatusPurged})

	for _, tok := range []string{"", "wrong-token-wrong-token-wrong-token", testInternalSecretForPurge} {
		if code, _ := purgeRoute(t, h, tok, "t_now"); code != http.StatusUnauthorized {
			t.Errorf("token %q: %d, want 401", tok, code)
		}
	}
	if code, body := purgeRoute(t, h, testOperatorToken, "t_unknown"); code != http.StatusNotFound || body["error"] != "tenant_not_found" {
		t.Errorf("unknown tenant: %d %v", code, body)
	}
	for _, id := range []string{"t_live", "t_gone"} {
		if code, body := purgeRoute(t, h, testOperatorToken, id); code != http.StatusConflict || body["error"] != "not_offboarded" {
			t.Errorf("%s: %d %v", id, code, body)
		}
	}
	received(0)
	code, body := purgeRoute(t, h, testOperatorToken, "t_now")
	if code != http.StatusAccepted || body["tenant_id"] != "t_now" || body["status"] != "offboarded" {
		t.Fatalf("purge: %d %v", code, body)
	}
	jobs := purgeJobs(t, gdb, "t_now")
	if len(jobs) != 1 || body["job_id"] != jobs[0].ID || jobs[0].PurgeTrigger != controlplane.PurgeTriggerOperator {
		t.Fatalf("jobs %+v, body %v", jobs, body)
	}
	if reqs := received(1); reqs[0].JobID != jobs[0].ID || reqs[0].Trigger != controlplane.PurgeTriggerOperator || reqs[0].TenantID != "t_now" {
		t.Fatalf("request %+v", reqs)
	}
	if code, body := purgeRoute(t, h, testOperatorToken, "t_now"); code != http.StatusConflict || body["error"] != "purge_in_progress" {
		t.Errorf("second purge while pending: %d %v", code, body)
	}
	if n := len(purgeJobs(t, gdb, "t_now")); n != 1 {
		t.Errorf("%d purge jobs, want 1", n)
	}
	// An operator may start a new one at once after a failure (the daily
	// spacing is the sweeper's).
	applyProvisioningResult(ProvisioningJobPurge, controlplane.TenantResult{JobID: jobs[0].ID, TenantID: "t_now", Status: controlplane.StatusFailed, ErrorCode: controlplane.ErrorPurgeIncomplete})
	if code, _ := purgeRoute(t, h, testOperatorToken, "t_now"); code != http.StatusAccepted {
		t.Errorf("an operator retry after a failure: %d", code)
	}
	received(1)

	// Rate limited, like every operator route, after the token check.
	limited := (&operatorPlane{tokens: [][]byte{[]byte(testOperatorToken)}}).handler()
	for i := range operatorRouteBurst {
		if code, _ := purgeRoute(t, limited, testOperatorToken, "t_unknown"); code != http.StatusNotFound {
			t.Fatalf("request %d within the burst: %d", i, code)
		}
	}
	if code, body := purgeRoute(t, limited, testOperatorToken, "t_unknown"); code != http.StatusTooManyRequests || body["error"] != "rate_limited" {
		t.Errorf("past the burst: %d %v", code, body)
	}
	if code, _ := purgeRoute(t, limited, "", "t_unknown"); code != http.StatusUnauthorized {
		t.Errorf("no token past the burst: %d, want 401 before the limit", code)
	}
	// The release routes share the plane's limiter, each with its own
	// bucket.
	if code, _ := operatorDo(t, limited, testOperatorToken, http.MethodPost, "/v1/operator/fleet-releases/v9.9.9/revoke", nil); code == http.StatusTooManyRequests {
		t.Error("another route's bucket was spent by the purge route")
	}
}

const testInternalSecretForPurge = "not-the-operator-token-but-long-enough-to-try"

// Sealed results on internal.tenant.purged.*: plaintext, forged, moved
// and deprovision results refused; the genuine one applied once.
func TestPurgeResultsAreSealed(t *testing.T) {
	gdb := newPurgeTestDB(t)
	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	if err := StartProvisioningResultListener(nc); err != nil {
		t.Fatal(err)
	}
	offboardedTenant(t, gdb, "t_s", time.Now())
	seedSaasRows(t, gdb, "t_s")
	job, err := startPurge(gdb, "t_s", controlplane.PurgeTriggerOperator, dbTime(time.Now()), true)
	if err != nil {
		t.Fatal(err)
	}
	purged := controlplane.TenantResult{JobID: job.ID, TenantID: "t_s", Status: controlplane.StatusPurged}
	subject := controlplane.PurgedSubject(job.ID)
	publish := func(m *nats.Msg) {
		t.Helper()
		if err := nc.PublishMsg(m); err != nil {
			t.Fatal(err)
		}
		_ = nc.Flush()
	}
	unchanged := func(what string) {
		t.Helper()
		time.Sleep(100 * time.Millisecond)
		var tenant Tenant
		gdb.First(&tenant, "id = ?", "t_s")
		if tenant.Status != TenantStatusOffboarded || saasRowCounts(t, gdb, "t_s")["asset_links"] != 1 {
			t.Fatalf("%s was applied: tenant %s", what, tenant.Status)
		}
	}
	plain := nats.NewMsg(subject)
	plain.Data, _ = json.Marshal(purged)
	publish(plain)
	unchanged("a plaintext result")
	publish(impostorKeys(t).sealedResultMsg(ProvisioningJobPurge, purged))
	unchanged("a result sealed under an impostor platform key")
	asDeprov := testKeys.sealedResultMsg(ProvisioningJobDeprovision, controlplane.TenantResult{JobID: job.ID, TenantID: "t_s", Status: controlplane.StatusPurged})
	asDeprov.Subject = subject
	publish(asDeprov)
	unchanged("a deprovision-sealed result moved onto the purge subject")
	claimed := nats.NewMsg(subject)
	claimed.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	claimed.Data, _ = json.Marshal(purged)
	publish(claimed)
	unchanged("a plaintext result claiming to be sealed")

	genuine := testKeys.sealedResultMsg(ProvisioningJobPurge, purged)
	publish(genuine)
	deadline := time.Now().Add(2 * time.Second)
	for {
		var tenant Tenant
		gdb.First(&tenant, "id = ?", "t_s")
		if tenant.Status == TenantStatusPurged {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the genuine purge result was not applied")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := openTenantResult(ProvisioningJobPurge, job.ID, genuine); !errors.Is(err, payloadbox.ErrReplayed) {
		t.Fatalf("a replayed result: %v, want ErrReplayed", err)
	}
}
