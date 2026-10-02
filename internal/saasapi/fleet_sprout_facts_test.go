package saasapi

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm/schema"

	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/facts"
	"github.com/yogzblr/imas/internal/props"
)

// farmerPropsTable's columns and key, as read here, are internal/props'
// own.
func TestFarmerSproutFactsColumnContract(t *testing.T) {
	var found *schema.Schema
	for _, m := range props.Models() {
		sch, err := schema.Parse(m, &sync.Map{}, schema.NamingStrategy{})
		if err != nil {
			t.Fatalf("parsing props model %T: %v", m, err)
		}
		if "farmer."+sch.Table == farmerPropsTable {
			found = sch
		}
	}
	if found == nil {
		t.Fatalf("no props model has table %q", strings.TrimPrefix(farmerPropsTable, "farmer."))
	}
	for _, col := range []string{"tenant_id", "sprout_id", "name", "value"} {
		if found.LookUpField(col) == nil {
			t.Fatalf("props has no %q column", col)
		}
	}
	var pk []string
	for _, f := range found.PrimaryFields {
		pk = append(pk, f.DBName)
	}
	if fmt.Sprint(pk) != "[tenant_id sprout_id name]" {
		t.Fatalf("props primary key = %v, want [tenant_id sprout_id name] (the lookup key)", pk)
	}
}

// The version prop read here is the one farmer's facts listener writes.
func TestFarmerSproutVersionPropContract(t *testing.T) {
	if farmerPropSproutVersion != facts.PropSproutVersion {
		t.Fatalf("saasapi reads %q, internal/facts writes %q", farmerPropSproutVersion, facts.PropSproutVersion)
	}
}

func TestFarmerSproutFactsReader(t *testing.T) {
	gdb := newUpdateTestDB(t)
	mustReportFacts(t, gdb, "t_a", "web-01", "linux", "amd64", "v2.4.1")
	mustReportFacts(t, gdb, "t_a", "web-02", "windows", "arm64", "v2.4.1+dirty")
	mustReportFacts(t, gdb, "t_a", "web-03", "linux", "amd64", "dev")
	mustReportFacts(t, gdb, "t_a", "web-04", "linux", "amd64", "")
	// Same sprout_id, another tenant: never read for t_a.
	mustReportFacts(t, gdb, "t_b", "web-05", "linux", "amd64", "v9.9.9")
	mustReportFacts(t, gdb, "t_b", "web-01", "darwin", "arm64", "v9.9.9")
	if err := reportFact(gdb, "t_a", "web-01", "hostname", "web-01.example"); err != nil {
		t.Fatal(err)
	}

	got, err := farmerSproutFactsReader{}.SproutFacts(context.Background(), "t_a",
		[]string{"web-01", "web-02", "web-03", "web-04", "web-05", "web-06"})
	if err != nil {
		t.Fatalf("SproutFacts: %v", err)
	}
	ref := func(id string) SproutRef { return SproutRef{TenantID: "t_a", SproutID: id} }
	want := map[SproutRef]SproutFacts{
		ref("web-01"): {OS: "linux", Arch: "amd64", Version: "v2.4.1"},
		// Build metadata dropped; reports that aren't semver read as none.
		ref("web-02"): {OS: "windows", Arch: "arm64", Version: "v2.4.1"},
		ref("web-03"): {OS: "linux", Arch: "amd64"},
		ref("web-04"): {OS: "linux", Arch: "amd64"},
	}
	if len(got) != len(want) {
		t.Fatalf("SproutFacts = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%v = %+v, want %+v", k, got[k], v)
		}
	}

	if got, err := (farmerSproutFactsReader{}).SproutFacts(context.Background(), "t_a", nil); err != nil || len(got) != 0 {
		t.Fatalf("no sprouts: %v %v", got, err)
	}
}

// Both batch-status GETs judge a self_update item by the version its
// sprout reports, not by its job: a finished job leaves the item running
// (and the batch in progress) until the sprout reports the target version,
// and only its own tenant's report counts.
func TestGetUpdateBatch_ItemSucceedsOnReportedVersion(t *testing.T) {
	gdb := newUpdateTestDB(t)
	installReader(t, farmerJobStatusReader{})
	tid := mustCreateActiveTenant(t, gdb)
	other := mustCreateActiveTenant(t, gdb)
	params, _ := selfUpdateParams(context.Background(), []FleetVersion{mustPublishVersion(t, gdb, "v2.4.1", time.Now())})
	batchID, err := newID(actionBatchIDPrefix)
	if err != nil {
		t.Fatal(err)
	}
	batch := AssetActionBatch{ID: batchID, TenantID: tid, ActionType: controlplane.ActionSelfUpdate,
		ActionParams: string(params), RequestedAssetIDs: `["a1","a2"]`, RolloutBatchSize: 5, RolloutGate: gateJobStatus}
	items := []AssetActionItem{
		{BatchID: batch.ID, AssetID: "a1", TenantID: tid, Position: 0, SproutID: "web-01", Status: ActionItemRunning, JID: jidFor("upd-01")},
		{BatchID: batch.ID, AssetID: "a2", TenantID: tid, Position: 1, SproutID: "web-02", Status: ActionItemRunning, JID: jidFor("upd-02")},
	}
	if err := gdb.Create(&batch).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Create(&items).Error; err != nil {
		t.Fatal(err)
	}
	mustInsertFarmerJobStatus(t, gdb, tid, "web-01", jidFor("upd-01"), "succeeded")
	mustInsertFarmerJobStatus(t, gdb, tid, "web-02", jidFor("upd-02"), "failed")
	mustReportFacts(t, gdb, tid, "web-01", "linux", "amd64", "v2.4.0")
	// Another tenant's web-01 is on the target already.
	mustReportFacts(t, gdb, other, "web-01", "linux", "amd64", "v2.4.1")

	_, got := getUpdateBatch(t, tid, batch.ID)
	if got.Status != actionBatchInProgress || got.Items[0].Status != ActionItemRunning {
		t.Fatalf("job succeeded, old version reported: %+v", got)
	}
	if it := got.Items[1]; it.Status != ActionItemFailed || it.Error != errCodeJobFailed {
		t.Fatalf("failed job: %+v", it)
	}

	mustReportFacts(t, gdb, tid, "web-01", "linux", "amd64", "v2.4.1")
	// §1.5's GET finds the update batch too, and judges it the same way.
	_, got = getBatch(t, tid, batch.ID)
	if got.Status != actionBatchCompleted || got.Items[0].Status != ActionItemSucceeded {
		t.Fatalf("after the sprout reported v2.4.1: %+v", got)
	}
}
