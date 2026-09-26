package saasapi

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"

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
	if farmerJobSucceeded != jobs.JobIndexStatusSucceeded || farmerJobFailed != jobs.JobIndexStatusFailed {
		t.Fatalf("status strings drifted: saasapi %q/%q, jobs %q/%q",
			farmerJobSucceeded, farmerJobFailed, jobs.JobIndexStatusSucceeded, jobs.JobIndexStatusFailed)
	}
}

func TestFarmerJobStatusReader(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	mustInsertFarmerJobStatus(t, gdb, "t_a", "web-01", "j1", jobs.JobIndexStatusSucceeded)
	mustInsertFarmerJobStatus(t, gdb, "t_a", "web-02", "j2", jobs.JobIndexStatusFailed)
	mustInsertFarmerJobStatus(t, gdb, "t_a", "web-03", "j3", jobs.JobIndexStatusRunning)
	mustInsertFarmerJobStatus(t, gdb, "t_a", "web-04", "j4", jobs.JobIndexStatusPending)
	// Same sprout_id and jid, other tenant.
	mustInsertFarmerJobStatus(t, gdb, "t_b", "web-05", "j5", jobs.JobIndexStatusSucceeded)
	// Matching jid, different sprout: not the requested job.
	mustInsertFarmerJobStatus(t, gdb, "t_a", "web-99", "j6", jobs.JobIndexStatusSucceeded)

	refs := []JobRef{
		{"web-01", "j1"}, {"web-02", "j2"}, {"web-03", "j3"}, {"web-04", "j4"},
		{"web-05", "j5"}, {"web-06", "j6"}, {"web-07", "missing"},
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
