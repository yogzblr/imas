package saasapi

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestLoadConfigRetention(t *testing.T) {
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Retention.TerminalRows != 90*24*time.Hour {
		t.Fatalf("default = %s, want 2160h", cfg.Retention.TerminalRows)
	}
	for _, v := range []string{"", "0", "0s"} {
		t.Setenv("SAASAPI_TERMINAL_ROW_RETENTION", v)
		if cfg, err := LoadConfig(); err != nil || cfg.Retention.TerminalRows != 2160*time.Hour {
			t.Fatalf("%q: %v, %s; want the default", v, err, cfg.Retention.TerminalRows)
		}
	}
	for v, want := range map[string]time.Duration{"24h": 24 * time.Hour, "87600h": 87600 * time.Hour, "720h": 720 * time.Hour} {
		t.Setenv("SAASAPI_TERMINAL_ROW_RETENTION", v)
		if cfg, err := LoadConfig(); err != nil || cfg.Retention.TerminalRows != want {
			t.Fatalf("%q: %v, %s", v, err, cfg.Retention.TerminalRows)
		}
	}
	for _, bad := range []string{"23h", "87601h", "-1h", "90d", "soon"} {
		t.Setenv("SAASAPI_TERMINAL_ROW_RETENTION", bad)
		if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "SAASAPI_TERMINAL_ROW_RETENTION") {
			t.Fatalf("%q: %v, want an error naming the variable", bad, err)
		}
	}
}

// fastPrune shortens the prune's pacing for a test and counts the rows
// each DELETE removes, returning the largest.
func fastPrune(t *testing.T, gdb *gorm.DB, rows, batches int) *int64 {
	t.Helper()
	oldRows, oldPause, oldMax := pruneBatchRows, pruneBatchPause, pruneMaxBatches
	pruneBatchRows, pruneBatchPause, pruneMaxBatches = rows, 0, batches
	t.Cleanup(func() { pruneBatchRows, pruneBatchPause, pruneMaxBatches = oldRows, oldPause, oldMax })
	var largest int64
	name := fmt.Sprintf("test:count_deletes_%p", t)
	if err := gdb.Callback().Delete().After("gorm:delete").Register(name, func(tx *gorm.DB) {
		if tx.Statement.RowsAffected > largest {
			largest = tx.Statement.RowsAffected
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = gdb.Callback().Delete().Remove(name) })
	return &largest
}

// A large table: finished batches older than the retention go, items
// then batch, at most pruneBatchRows rows per DELETE and pruneMaxBatches
// DELETEs per run; a younger batch, an old batch with an open or a
// recently changed item, and an old batch under a live lease all stay.
func TestPruneTerminalRowsLargeTable(t *testing.T) {
	gdb := newTestDB(t)
	clearOutbox(t, gdb)
	// Smaller on sqlite, which is slow under -race; the MySQL test
	// (sweeper_mysql_test.go) prunes the full size.
	testPruneLargeTable(t, gdb, gdb, 40, 60)
}

// testPruneLargeTable seeds an action table of oldBatches finished batches
// older than the retention plus four that must stay, itemsPerBatch items
// each, through g1, and prunes it with g1 and g2 (two replicas) by turns
// until nothing is left to prune.
func testPruneLargeTable(t *testing.T, g1, g2 *gorm.DB, oldBatches, itemsPerBatch int) {
	gdb := g1
	largest := fastPrune(t, g1, 500, 20)
	if g2 != g1 {
		largest2 := fastPrune(t, g2, 500, 20)
		t.Cleanup(func() {
			if *largest2 > 500 {
				t.Errorf("a DELETE on the second replica removed %d rows, want at most 500", *largest2)
			}
		})
	}
	now := dbTime(time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC))
	old := now.Add(-91 * 24 * time.Hour)
	young := now.Add(-89 * 24 * time.Hour)
	lease := now.Add(time.Minute)

	type spec struct {
		id, tenant string
		created    time.Time
		item       func(i int) (AssetActionItemStatus, time.Time)
		lease      *time.Time
		gone       bool
	}
	var specs []spec
	for n := range oldBatches {
		specs = append(specs, spec{id: fmt.Sprintf("b_old_%03d", n), tenant: []string{"t_a", "t_b"}[n%2], created: old,
			item: func(i int) (AssetActionItemStatus, time.Time) {
				return []AssetActionItemStatus{ActionItemSucceeded, ActionItemFailed, ActionItemUnresolved}[i%3], old
			}, gone: true})
	}
	specs = append(specs,
		spec{id: "b_young", tenant: "t_a", created: young,
			item: func(int) (AssetActionItemStatus, time.Time) { return ActionItemSucceeded, young }},
		spec{id: "b_open", tenant: "t_a", created: old,
			item: func(i int) (AssetActionItemStatus, time.Time) {
				if i == 7 {
					return ActionItemRunning, old
				}
				return ActionItemSucceeded, old
			}},
		spec{id: "b_recent_item", tenant: "t_b", created: old,
			item: func(i int) (AssetActionItemStatus, time.Time) {
				if i == 0 {
					return ActionItemFailed, young
				}
				return ActionItemFailed, old
			}},
		spec{id: "b_leased", tenant: "t_b", created: old, lease: &lease,
			item: func(int) (AssetActionItemStatus, time.Time) { return ActionItemUnresponsiveAfterUpdate, old }},
	)
	var batches []AssetActionBatch
	var items []AssetActionItem
	for _, s := range specs {
		batches = append(batches, AssetActionBatch{ID: s.id, TenantID: s.tenant, ActionType: "cmd.run", ActionParams: "{}",
			RequestedAssetIDs: "[]", CreatedAt: s.created, LeaseUntil: s.lease})
		for i := range itemsPerBatch {
			st, at := s.item(i)
			items = append(items, AssetActionItem{BatchID: s.id, AssetID: fmt.Sprintf("a%03d", i), TenantID: s.tenant,
				Position: i, Status: st, CreatedAt: s.created, UpdatedAt: at})
		}
	}
	if err := gdb.CreateInBatches(batches, 200).Error; err != nil {
		t.Fatal(err)
	}
	// UpdatedAt is GORM-managed: insert without its autoUpdateTime.
	if err := gdb.Session(&gorm.Session{SkipHooks: true}).CreateInBatches(items, 400).Error; err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if it.UpdatedAt.Equal(young) {
			if err := gdb.Model(&AssetActionItem{}).Where("batch_id = ? AND asset_id = ?", it.BatchID, it.AssetID).
				UpdateColumn("updated_at", young).Error; err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := gdb.Model(&AssetActionItem{}).Where("updated_at <> ?", young).UpdateColumn("updated_at", old).Error; err != nil {
		t.Fatal(err)
	}
	var total int64
	gdb.Model(&AssetActionItem{}).Count(&total)
	if total != int64(len(items)) {
		t.Fatalf("seeded %d items, want %d", total, len(items))
	}

	r, err := pruneTerminalRows(context.Background(), gdb, 90*24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if r.Items+r.Batches == 0 || r.Items > 20*500 || r.Batches > 20 {
		t.Fatalf("first run removed %+v: want some, and at most 20 DELETEs of 500 rows", r)
	}
	runs := 1
	for ; runs < 100; runs++ {
		r, err = pruneTerminalRows(context.Background(), []*gorm.DB{g1, g2}[runs%2], 90*24*time.Hour, now)
		if err != nil {
			t.Fatal(err)
		}
		if r == (pruneResult{}) {
			break
		}
	}
	if runs < 3 {
		t.Fatalf("pruned in %d runs: the per-run cap did not hold", runs)
	}
	if *largest > 500 {
		t.Fatalf("a DELETE removed %d rows, want at most 500", *largest)
	}
	for _, s := range specs {
		var nb, ni int64
		gdb.Model(&AssetActionBatch{}).Where("id = ? AND tenant_id = ?", s.id, s.tenant).Count(&nb)
		gdb.Model(&AssetActionItem{}).Where("batch_id = ? AND tenant_id = ?", s.id, s.tenant).Count(&ni)
		if s.gone && (nb != 0 || ni != 0) {
			t.Fatalf("batch %s: %d batch rows and %d items left, want none", s.id, nb, ni)
		}
		if !s.gone && (nb != 1 || ni != int64(itemsPerBatch)) {
			t.Fatalf("batch %s: %d batch rows and %d items left, want it whole", s.id, nb, ni)
		}
	}
}

func TestPruneTerminalRowsProvisioningJobsAndEnrollmentKeys(t *testing.T) {
	gdb := newTestDB(t)
	clearOutbox(t, gdb)
	testPruneJobsAndKeys(t, gdb)
}

// testPruneJobsAndKeys checks which provisioning jobs and enrollment keys
// a prune removes, on gdb.
func testPruneJobsAndKeys(t *testing.T, gdb *gorm.DB) {
	fastPrune(t, gdb, 2, 50)
	// The shared in-memory database keeps other tests' rows.
	for _, m := range []any{&EnrollmentKey{}, &Tenant{}} {
		if err := gdb.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(m).Error; err != nil {
			t.Fatal(err)
		}
	}
	now := dbTime(time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC))
	old := now.Add(-91 * 24 * time.Hour)
	young := now.Add(-89 * 24 * time.Hour)
	for id, st := range map[string]TenantStatus{"t_act": TenantStatusActive, "t_fail": TenantStatusFailed,
		"t_off": TenantStatusOffboarded, "t_offing": TenantStatusOffboarding, "t_gone": TenantStatusPurged} {
		if err := gdb.Create(&Tenant{ID: id, Name: id, Status: st}).Error; err != nil {
			t.Fatal(err)
		}
	}
	jobs := []struct {
		id, tenant string
		typ        ProvisioningJobType
		status     ProvisioningJobStatus
		at         time.Time
		gone       bool
	}{
		{"pj_1", "t_act", ProvisioningJobProvision, ProvisioningJobSucceeded, old, true},
		{"pj_2", "t_act", ProvisioningJobProvision, ProvisioningJobFailed, old, true},
		{"pj_3", "t_fail", ProvisioningJobProvision, ProvisioningJobFailed, old, true},
		{"pj_4", "t_act", ProvisioningJobProvision, ProvisioningJobSucceeded, young, false},
		{"pj_5", "t_act", ProvisioningJobProvision, ProvisioningJobPending, old, false},
		{"pj_6", "t_off", ProvisioningJobDeprovision, ProvisioningJobSucceeded, old, false},
		{"pj_7", "t_offing", ProvisioningJobDeprovision, ProvisioningJobFailed, old, false},
		{"pj_8", "t_gone", ProvisioningJobPurge, ProvisioningJobSucceeded, old, false},
		{"pj_9", "t_gone", ProvisioningJobProvision, ProvisioningJobSucceeded, old, false},
	}
	for _, j := range jobs {
		if err := gdb.Create(&ProvisioningJob{ID: j.id, TenantID: j.tenant, Type: j.typ, Status: j.status, CreatedAt: j.at}).Error; err != nil {
			t.Fatal(err)
		}
		if err := gdb.Model(&ProvisioningJob{}).Where("id = ?", j.id).UpdateColumn("updated_at", j.at).Error; err != nil {
			t.Fatal(err)
		}
	}
	keys := []struct {
		id, tenant string
		expiry     time.Time
		gone       bool
	}{
		{"k1", "t_act", old, true},
		{"k2", "t_fail", old.Add(-time.Hour), true},
		{"k3", "t_act", old, true},
		{"k4", "t_act", young, false},
		{"k5", "t_act", now.Add(time.Hour), false},
	}
	for _, k := range keys {
		if err := gdb.Create(&EnrollmentKey{KeyID: k.id, TenantID: k.tenant, KeyHash: "h", Expiry: k.expiry, MaxUses: 1}).Error; err != nil {
			t.Fatal(err)
		}
	}
	r, err := pruneTerminalRows(context.Background(), gdb, 90*24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if r.ProvisioningJobs != 3 || r.EnrollmentKeys != 3 {
		t.Fatalf("removed %+v, want 3 provisioning jobs and 3 enrollment keys", r)
	}
	for _, j := range jobs {
		var n int64
		gdb.Model(&ProvisioningJob{}).Where("id = ?", j.id).Count(&n)
		if (n == 0) != j.gone {
			t.Errorf("job %s (%s, %s, tenant %s): left %d, gone want %v", j.id, j.typ, j.status, j.tenant, n, j.gone)
		}
	}
	for _, k := range keys {
		var n int64
		gdb.Model(&EnrollmentKey{}).Where("key_id = ?", k.id).Count(&n)
		if (n == 0) != k.gone {
			t.Errorf("key %s: left %d, gone want %v", k.id, n, k.gone)
		}
	}
}

// The sweeper prunes with no bus: deleting needs none.
func TestStartOutboxSweeperPrunesWithoutBus(t *testing.T) {
	gdb := newTestDB(t)
	clearOutbox(t, gdb)
	fastPrune(t, gdb, 500, 50)
	if err := gdb.Create(&EnrollmentKey{KeyID: "k_old", TenantID: "t_a", KeyHash: "h",
		Expiry: time.Now().UTC().Add(-100 * 24 * time.Hour), MaxUses: 1}).Error; err != nil {
		t.Fatal(err)
	}
	old := outboxSettings
	outboxSettings.Enabled, outboxSettings.Interval = true, time.Hour
	t.Cleanup(func() { outboxSettings = old })
	ctx, cancel := context.WithCancel(context.Background())
	wait := StartOutboxSweeper(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for {
		var n int64
		gdb.Model(&EnrollmentKey{}).Where("key_id = ?", "k_old").Count(&n)
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the expired key was not pruned")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	wait()
}
