package saasapi

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/jobs"
)

// mustInsertFarmerJobStatus upserts a farmer.job_status row, standing in
// for internal/jobs' listener.
func mustInsertFarmerJobStatus(t *testing.T, gdb *gorm.DB, tenantID, sproutID, jid, status string) {
	t.Helper()
	if err := gdb.Exec(`INSERT INTO farmer.job_status (tenant_id, sprout_id, jid, status, updated_at)
VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
ON CONFLICT (tenant_id, sprout_id, jid) DO UPDATE SET status = excluded.status`,
		tenantID, sproutID, jid, status).Error; err != nil {
		t.Fatalf("inserting farmer job status: %v", err)
	}
}

// TestFarmerJobStatusColumnContract pins what farmerJobStatusReader reads
// from farmer.job_status to internal/jobs' own model and status strings,
// so a rename on the farmer side breaks this test rather than §1.5's
// polling in production.
func TestFarmerJobStatusColumnContract(t *testing.T) {
	var found *schema.Schema
	for _, m := range jobs.Models() {
		sch, err := schema.Parse(m, &sync.Map{}, schema.NamingStrategy{})
		if err != nil {
			t.Fatalf("parsing jobs model %T: %v", m, err)
		}
		if "farmer."+sch.Table == farmerJobStatusTable {
			found = sch
		}
	}
	if found == nil {
		t.Fatalf("no jobs model has table %q", strings.TrimPrefix(farmerJobStatusTable, "farmer."))
	}
	for _, col := range []string{"tenant_id", "sprout_id", "jid", "status"} {
		if found.LookUpField(col) == nil {
			t.Fatalf("job_status has no %q column", col)
		}
	}
	var pk []string
	for _, f := range found.PrimaryFields {
		pk = append(pk, f.DBName)
	}
	if fmt.Sprint(pk) != "[tenant_id sprout_id jid]" {
		t.Fatalf("job_status primary key = %v, want [tenant_id sprout_id jid] (the lookup key)", pk)
	}
	if farmerJobSucceeded != jobs.JobIndexStatusSucceeded || farmerJobFailed != jobs.JobIndexStatusFailed ||
		farmerJobExpired != jobs.JobIndexStatusExpired {
		t.Fatalf("status strings drifted: saasapi %q/%q/%q, jobs %q/%q/%q",
			farmerJobSucceeded, farmerJobFailed, farmerJobExpired,
			jobs.JobIndexStatusSucceeded, jobs.JobIndexStatusFailed, jobs.JobIndexStatusExpired)
	}
}

func TestFarmerJobStatusReader(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	mustInsertFarmerJobStatus(t, gdb, "t_a", "web-01", "j1", jobs.JobIndexStatusSucceeded)
	mustInsertFarmerJobStatus(t, gdb, "t_a", "web-02", "j2", jobs.JobIndexStatusFailed)
	mustInsertFarmerJobStatus(t, gdb, "t_a", "web-03", "j3", jobs.JobIndexStatusRunning)
	mustInsertFarmerJobStatus(t, gdb, "t_a", "web-04", "j4", jobs.JobIndexStatusPending)
	mustInsertFarmerJobStatus(t, gdb, "t_a", "web-08", "j8", jobs.JobIndexStatusExpired)
	// Same sprout_id and jid, other tenant.
	mustInsertFarmerJobStatus(t, gdb, "t_b", "web-05", "j5", jobs.JobIndexStatusSucceeded)
	// Matching jid, different sprout: not the requested job.
	mustInsertFarmerJobStatus(t, gdb, "t_a", "web-99", "j6", jobs.JobIndexStatusSucceeded)

	refs := []JobRef{
		{"web-01", "j1"}, {"web-02", "j2"}, {"web-03", "j3"}, {"web-04", "j4"},
		{"web-05", "j5"}, {"web-06", "j6"}, {"web-07", "missing"}, {"web-08", "j8"},
	}
	got, err := farmerJobStatusReader{}.JobOutcomes(t.Context(), "t_a", refs)
	if err != nil {
		t.Fatalf("JobOutcomes: %v", err)
	}
	want := map[JobRef]JobOutcome{
		{"web-01", "j1"}: JobOutcomeSucceeded,
		{"web-02", "j2"}: JobOutcomeFailed,
		{"web-03", "j3"}: JobOutcomeRunning,
		{"web-04", "j4"}: JobOutcomeRunning,
		{"web-08", "j8"}: JobOutcomeExpired,
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("JobOutcomes = %v, want %v", got, want)
	}

	if got, err := (farmerJobStatusReader{}).JobOutcomes(t.Context(), "t_a", nil); err != nil || len(got) != 0 {
		t.Fatalf("no refs: %v, %v", got, err)
	}
	SetDB(nil)
	if _, err := (farmerJobStatusReader{}).JobOutcomes(t.Context(), "t_a", refs); err == nil {
		t.Fatal("no database: want an error")
	}
}

// A job status lookup without a tenant is refused, never run unscoped.
func TestFarmerJobStatusReader_RefusesEmptyTenant(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	mustInsertFarmerJobStatus(t, gdb, "t_a", "web-01", "j1", jobs.JobIndexStatusSucceeded)
	if got, err := (farmerJobStatusReader{}).JobOutcomes(t.Context(), "", []JobRef{{"web-01", "j1"}}); !errors.Is(err, errNoJobTenant) || got != nil {
		t.Fatalf("JobOutcomes with no tenant = %v, %v; want errNoJobTenant", got, err)
	}
}

// FIX.2 (security review 2026-10-b I4) through the route: two tenants
// each have a cook batch whose running item is on the same sprout_id with
// the same jid, and farmer.job_status holds a different outcome for each.
// GET .../sprouts/actions/{batch_id} applies each tenant's own row only,
// and one tenant's batch can't be read under the other tenant's path.
func TestGetSproutActionBatch_TwoTenantsSameSproutAndJID(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	installReader(t, farmerJobStatusReader{})
	const sprout, jid = "web-01", "11111111-2222-3333-4444-555555555555"
	tenants := []string{mustCreateActiveTenant(t, gdb), mustCreateActiveTenant(t, gdb)}
	outcome := map[string]string{tenants[0]: jobs.JobIndexStatusFailed, tenants[1]: jobs.JobIndexStatusSucceeded}
	batches := map[string]string{}
	for _, tid := range tenants {
		batchID, err := newID(actionBatchIDPrefix)
		if err != nil {
			t.Fatal(err)
		}
		batches[tid] = batchID
		if err := gdb.Create(&AssetActionBatch{ID: batchID, TenantID: tid, ActionType: controlplane.ActionCook,
			ActionParams: "{}", RequestedAssetIDs: `["a1"]`}).Error; err != nil {
			t.Fatal(err)
		}
		if err := gdb.Create(&AssetActionItem{BatchID: batchID, AssetID: "a1", TenantID: tid, SproutID: sprout,
			Status: ActionItemRunning, JID: jid}).Error; err != nil {
			t.Fatal(err)
		}
		mustInsertFarmerJobStatus(t, gdb, tid, sprout, jid, outcome[tid])
	}

	want := map[string]struct {
		status AssetActionItemStatus
		code   string
	}{
		tenants[0]: {ActionItemFailed, errCodeJobFailed},
		tenants[1]: {ActionItemSucceeded, ""},
	}
	for _, tid := range tenants {
		code, got := getBatch(t, tid, batches[tid])
		if code != 200 || len(got.Items) != 1 {
			t.Fatalf("%s: GET = %d %+v", tid, code, got)
		}
		if it := got.Items[0]; it.Status != want[tid].status || it.Error != want[tid].code {
			t.Errorf("%s: item = %+v, want %s %q (its own job status row)", tid, it, want[tid].status, want[tid].code)
		}
	}
	// Each batch under the other tenant's path is not found.
	if code, _ := getBatch(t, tenants[1], batches[tenants[0]]); code != 404 {
		t.Errorf("tenant 0's batch under tenant 1's path: %d, want 404", code)
	}
	if code, _ := getBatch(t, tenants[0], batches[tenants[1]]); code != 404 {
		t.Errorf("tenant 1's batch under tenant 0's path: %d, want 404", code)
	}
}
