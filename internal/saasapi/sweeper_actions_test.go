package saasapi

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/controlplane"
)

// completingFarmer answers every cmd.run with exit 0.
func completingFarmer(req controlplane.SproutActionRequest) any {
	return controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID,
		Status: controlplane.StatusCompleted, Result: &controlplane.CmdRunResult{}}
}

// sendsPerSprout counts the requests farmer saw for each tenant/sprout.
func sendsPerSprout(f *fakeFarmer) map[SproutRef]int {
	reqs, _ := f.seen()
	out := map[SproutRef]int{}
	for _, r := range reqs {
		out[SproutRef{TenantID: r.TenantID, SproutID: r.SproutID}]++
	}
	return out
}

// mustActionFleet sets up n accepted, linked sprouts for tid (act-01 →
// asset a1-<tid>, ...) and returns the asset ids.
func mustActionFleet(t *testing.T, gdb *gorm.DB, tid string, n int) []string {
	t.Helper()
	assets := make([]string, n)
	for i := range n {
		sprout := fmt.Sprintf("act-%02d", i+1)
		assets[i] = fmt.Sprintf("a%d-%s", i+1, tid)
		mustInsertFarmerSprout(t, gdb, tid, sprout, "accepted")
		mustLinkAsset(t, tid, sprout, assets[i])
	}
	return assets
}

func batchItems(t *testing.T, gdb *gorm.DB, batchID string) []AssetActionItem {
	t.Helper()
	var items []AssetActionItem
	if err := gdb.Where("batch_id = ?", batchID).Order("position").Find(&items).Error; err != nil {
		t.Fatal(err)
	}
	return items
}

// The crash case: a batch accepted by a process with no bus (as if it died
// before dispatching) keeps its items queued. Once its lease has lapsed,
// two sweepers on the same database send each item exactly once, from the
// stored params, and the batch completes.
func TestSweepActionBatches_CrashThenTwoSweepers(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	clearOutbox(t, gdb)
	clock := useTestClock(t)
	tid := mustCreateActiveTenant(t, gdb)
	assets := mustActionFleet(t, gdb, tid, 6)

	SetBus(nil)
	code, resp := postActions(t, tid, map[string]any{"asset_ids": assets, "action": cmdAction("uptime")})
	actionDispatches.Wait()
	if code != 202 {
		t.Fatalf("POST: %d %v", code, resp)
	}
	batchID := resp["batch_id"].(string)
	for _, it := range batchItems(t, gdb, batchID) {
		if it.Status != ActionItemQueued || it.Attempts != 0 || it.DispatchedAt != nil {
			t.Fatalf("item without a bus = %+v", it)
		}
	}

	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	farmer := startFakeFarmer(t, ns, completingFarmer)
	a, b := testSweeper(gdb, nc), testSweeper(gdb, nc)

	// The creating process's lease is still live: nothing is sent.
	clock.Advance(defaultOutboxLeaseTTL - time.Second)
	sweepConcurrently(a, b)
	if reqs, _ := farmer.seen(); len(reqs) != 0 {
		t.Fatalf("sent %d requests under a live lease", len(reqs))
	}

	clock.Advance(2 * time.Second)
	sweepConcurrently(a, b, a, b)
	sends := sendsPerSprout(farmer)
	if len(sends) != len(assets) {
		t.Fatalf("farmer saw %d sprouts, want %d: %v", len(sends), len(assets), sends)
	}
	for ref, n := range sends {
		if n != 1 || ref.TenantID != tid {
			t.Fatalf("%v sent %d times", ref, n)
		}
	}
	reqs, _ := farmer.seen()
	var p farmerCmdRun
	if err := json.Unmarshal(reqs[0].Action.Params, &p); err != nil || p.Command != "uptime" || reqs[0].Action.Type != controlplane.ActionCmdRun {
		t.Fatalf("re-dispatched action = %+v (%v)", reqs[0].Action, err)
	}
	for _, it := range batchItems(t, gdb, batchID) {
		if it.Status != ActionItemSucceeded || it.Attempts != 1 || it.DispatchedAt == nil {
			t.Fatalf("item after the sweep = %+v", it)
		}
	}
	if _, got := getBatch(t, tid, batchID); got.Status != actionBatchCompleted {
		t.Fatalf("batch = %s", got.Status)
	}

	// Nothing left to do: later sweeps send nothing more.
	clock.Advance(time.Hour)
	sweepConcurrently(a, b)
	if reqs, _ := farmer.seen(); len(reqs) != len(assets) {
		t.Fatalf("farmer got %d requests after a later sweep", len(reqs))
	}
}

// An item in dispatching was sent, or may have been, and no reply was
// recorded. The sweeper never sends it again. While its dispatcher could
// still be waiting on the reply it is left alone; once that dispatcher
// would have given up (stuckDispatchAfter), it fails with
// dispatch_outcome_unknown and the batch completes. The queued item next
// to it is sent.
func TestSweepActionBatches_StuckDispatchingFailsNeverResent(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	clearOutbox(t, gdb)
	clock := useTestClock(t)
	tid := mustCreateActiveTenant(t, gdb)
	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	farmer := startFakeFarmer(t, ns, completingFarmer)

	params, _ := json.Marshal(farmerCmdRun{Command: "rm", Args: []string{"-f", "/tmp/x"}, Timeout: time.Minute})
	expired := dbTime(clock.Now().Add(-time.Minute))
	batch := AssetActionBatch{ID: "b_disp_" + tid, TenantID: tid, ActionType: controlplane.ActionCmdRun,
		ActionParams: string(params), RequestedAssetIDs: `["d1","q1"]`, LeaseOwner: "dead-pod/x", LeaseUntil: &expired}
	stuckAfter := stuckDispatchAfter(batch) // 1m cmd.run + 45s reply wait + 30s margin
	sent := dbTime(clock.Now())
	items := []AssetActionItem{
		{BatchID: batch.ID, AssetID: "d1", TenantID: tid, Position: 0, SproutID: "web-d", Status: ActionItemDispatching, Attempts: 1, DispatchedAt: &sent},
		{BatchID: batch.ID, AssetID: "q1", TenantID: tid, Position: 1, SproutID: "web-q", Status: ActionItemQueued},
	}
	if err := gdb.Create(&batch).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Create(&items).Error; err != nil {
		t.Fatal(err)
	}

	// Its dispatcher could still be waiting: left alone; the queued item is
	// sent.
	clock.Advance(stuckAfter - time.Second)
	sweepConcurrently(testSweeper(gdb, nc), testSweeper(gdb, nc))
	sends := sendsPerSprout(farmer)
	if sends[SproutRef{TenantID: tid, SproutID: "web-d"}] != 0 || sends[SproutRef{TenantID: tid, SproutID: "web-q"}] != 1 || len(sends) != 1 {
		t.Fatalf("sends = %v, want only web-q once", sends)
	}
	got := batchItems(t, gdb, batch.ID)
	if got[0].Status != ActionItemDispatching || got[0].ErrorCode != "" || !got[0].DispatchedAt.Equal(sent) {
		t.Fatalf("dispatching item changed before its dispatcher would have given up: %+v", got[0])
	}
	if got[1].Status != ActionItemSucceeded {
		t.Fatalf("queued item = %+v", got[1])
	}

	// Past it (and past the lease this sweep took): failed, outcome
	// unknown, never re-sent.
	clock.Advance(defaultOutboxLeaseTTL + 2*time.Second)
	sweepConcurrently(testSweeper(gdb, nc), testSweeper(gdb, nc))
	if sends := sendsPerSprout(farmer); sends[SproutRef{TenantID: tid, SproutID: "web-d"}] != 0 {
		t.Fatalf("dispatching item re-sent: %v", sends)
	}
	got = batchItems(t, gdb, batch.ID)
	if got[0].Status != ActionItemFailed || got[0].ErrorCode != errCodeDispatchOutcomeUnknown || got[0].Attempts != 1 {
		t.Fatalf("stuck item = %+v, want failed %s", got[0], errCodeDispatchOutcomeUnknown)
	}
	if _, resp := getBatch(t, tid, batch.ID); resp.Status != actionBatchCompleted {
		t.Fatalf("batch = %s, want completed", resp.Status)
	}
}

// A queued item accepted longer ago than SAASAPI_OUTBOX_ACTION_MAX_AGE is
// never sent: after an outage the sweeper fails it with expired_not_sent
// instead of delivering a stale command.
func TestSweepActionBatches_ExpiredNeverSent(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	clearOutbox(t, gdb)
	clock := useTestClock(t)
	tid := mustCreateActiveTenant(t, gdb)
	assets := mustActionFleet(t, gdb, tid, 2)
	SetBus(nil)
	_, resp := postActions(t, tid, map[string]any{"asset_ids": assets, "action": cmdAction("uptime")})
	actionDispatches.Wait()
	batchID := resp["batch_id"].(string)

	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	farmer := startFakeFarmer(t, ns, completingFarmer)
	clock.Advance(defaultActionMaxAge + time.Second)
	sweepConcurrently(testSweeper(gdb, nc), testSweeper(gdb, nc))
	if reqs, _ := farmer.seen(); len(reqs) != 0 {
		t.Fatalf("sent %d expired items", len(reqs))
	}
	for _, it := range batchItems(t, gdb, batchID) {
		if it.Status != ActionItemFailed || it.ErrorCode != errCodeExpiredNotSent || it.Attempts != 0 {
			t.Fatalf("item = %+v", it)
		}
	}
	if _, got := getBatch(t, tid, batchID); got.Status != actionBatchCompleted ||
		got.Items[0].Error != errCodeExpiredNotSent || got.Items[0].Message != actionErrorMessage(errCodeExpiredNotSent) {
		t.Fatalf("GET = %+v", got)
	}
}

// The original dispatcher applies the same limit: an item still waiting
// for a dispatch slot when it expires is failed, not sent.
func TestDispatchBatch_ExpiresOldItems(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	clearOutbox(t, gdb)
	clock := useTestClock(t)
	tid := mustCreateActiveTenant(t, gdb)
	assets := mustActionFleet(t, gdb, tid, 1)
	SetBus(nil)
	_, resp := postActions(t, tid, map[string]any{"asset_ids": assets, "action": cmdAction("uptime")})
	actionDispatches.Wait()
	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	farmer := startFakeFarmer(t, ns, completingFarmer)

	var batch AssetActionBatch
	gdb.First(&batch, "id = ?", resp["batch_id"])
	items := batchItems(t, gdb, batch.ID)
	accepted := items[0].CreatedAt
	if actionExpired(batch, items[0], accepted.Add(defaultActionMaxAge-time.Millisecond), defaultActionMaxAge) ||
		!actionExpired(batch, items[0], accepted.Add(defaultActionMaxAge), defaultActionMaxAge) {
		t.Fatal("the max age boundary is wrong")
	}
	clock.Advance(defaultActionMaxAge + time.Second)
	dispatchBatch(gdb, nc, batch, items, nil)
	if reqs, _ := farmer.seen(); len(reqs) != 0 {
		t.Fatalf("sent %d expired items", len(reqs))
	}
	if it := batchItems(t, gdb, batch.ID)[0]; it.Status != ActionItemFailed || it.ErrorCode != errCodeExpiredNotSent {
		t.Fatalf("item = %+v", it)
	}
	// Update rollouts are never expired: their items wait for their wave.
	if actionExpired(AssetActionBatch{ActionType: controlplane.ActionSelfUpdate}, items[0], clock.Now().Add(24*time.Hour), defaultActionMaxAge) {
		t.Fatal("a self_update item expired")
	}
}

// With no farmer listening, a re-dispatch goes back to queued (provably
// undelivered, dispatched_at cleared) with its attempt counted, waits out
// a growing backoff, and once it has used every attempt is failed with
// dispatch_not_delivered rather than sent again.
func TestSweepActionBatches_BackoffAndAttemptLimit(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	clearOutbox(t, gdb)
	clock := useTestClock(t)
	tid := mustCreateActiveTenant(t, gdb)
	assets := mustActionFleet(t, gdb, tid, 1)
	SetBus(nil)
	_, resp := postActions(t, tid, map[string]any{"asset_ids": assets, "action": cmdAction("uptime")})
	actionDispatches.Wait()
	batchID := resp["batch_id"].(string)

	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	sw := testSweeper(gdb, nc)
	sw.s.ActionStaleAfter = 10 * time.Second
	sw.s.LeaseTTL = 15 * time.Second
	sw.s.MaxAttempts = 3

	// The item's backoff counts from its last change, on the real clock
	// GORM stamps updated_at with; the test clock only moves forward from
	// there.
	item := func() AssetActionItem { return batchItems(t, gdb, batchID)[0] }
	for attempt := 1; attempt <= 3; attempt++ {
		clock.Advance(defaultOutboxLeaseTTL + backoff(sw.s.ActionStaleAfter, attempt-1))
		sweepConcurrently(sw)
		it := item()
		if it.Status != ActionItemQueued || it.Attempts != attempt || it.DispatchedAt != nil {
			t.Fatalf("after attempt %d: %+v", attempt, it)
		}
	}
	clock.Advance(defaultOutboxLeaseTTL + backoff(sw.s.ActionStaleAfter, 3))
	sweepConcurrently(sw)
	if it := item(); it.Status != ActionItemFailed || it.ErrorCode != errCodeNotDelivered || it.Attempts != 3 {
		t.Fatalf("after the attempt limit: %+v", it)
	}
	if _, got := getBatch(t, tid, batchID); got.Status != actionBatchCompleted || got.Items[0].Message != actionErrorMessage(errCodeNotDelivered) {
		t.Fatalf("GET = %+v", got)
	}
}

// Update rollouts are sweepRollouts' to resume, never re-dispatched as a
// plain batch.
func TestSweepActionBatches_SkipsUpdateBatches(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	clearOutbox(t, gdb)
	clock := useTestClock(t)
	tid := mustCreateActiveTenant(t, gdb)
	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	farmer := startFakeFarmer(t, ns, completingFarmer)
	batch := AssetActionBatch{ID: "b_upd_" + tid, TenantID: tid, ActionType: controlplane.ActionSelfUpdate,
		ActionParams: `{"version":"v2.4.1"}`, RequestedAssetIDs: `["u1"]`, RolloutBatchSize: 1, RolloutGate: gateJobStatus}
	if err := gdb.Create(&batch).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.Create(&AssetActionItem{BatchID: batch.ID, AssetID: "u1", TenantID: tid, SproutID: "upd-01", Status: ActionItemQueued}).Error; err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Hour)
	sweepConcurrently(testSweeper(gdb, nc)) // fleet update dispatch is off
	if reqs, _ := farmer.seen(); len(reqs) != 0 {
		t.Fatalf("an update batch was dispatched as a plain batch: %d requests", len(reqs))
	}
}

// A dispatcher whose lease has been lost (another holder took the row)
// sends nothing more.
func TestDispatchBatch_StopsWhenLeaseLost(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	clearOutbox(t, gdb)
	clock := useTestClock(t)
	tid := mustCreateActiveTenant(t, gdb)
	assets := mustActionFleet(t, gdb, tid, 2)
	SetBus(nil)
	_, resp := postActions(t, tid, map[string]any{"asset_ids": assets, "action": cmdAction("uptime")})
	actionDispatches.Wait()
	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	farmer := startFakeFarmer(t, ns, completingFarmer)

	var batch AssetActionBatch
	gdb.First(&batch, "id = ?", resp["batch_id"])
	original := batchLeaseOf(gdb, batch)
	clock.Advance(defaultOutboxLeaseTTL + time.Second)
	if l, err := claimRowLease(gdb, batch.TableName(), batchLeaseKey, []any{batch.ID, tid}, "", nil, nil, time.Minute); l == nil || err != nil {
		t.Fatalf("taking over: %v", err)
	}
	original.renew()
	dispatchBatch(gdb, nc, batch, batchItems(t, gdb, batch.ID), original)
	if reqs, _ := farmer.seen(); len(reqs) != 0 {
		t.Fatalf("a dispatcher without its lease sent %d requests", len(reqs))
	}
}

// A batch whose tenant has started offboarding since it was accepted gets
// nothing more sent: its queued items fail with tenant_not_active.
func TestSweepActionBatches_TenantNoLongerActive(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	clearOutbox(t, gdb)
	clock := useTestClock(t)
	tid := mustCreateActiveTenant(t, gdb)
	assets := mustActionFleet(t, gdb, tid, 2)
	SetBus(nil)
	_, resp := postActions(t, tid, map[string]any{"asset_ids": assets, "action": cmdAction("uptime")})
	actionDispatches.Wait()
	gdb.Model(&Tenant{}).Where("id = ?", tid).Update("status", TenantStatusOffboarding)

	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	farmer := startFakeFarmer(t, ns, completingFarmer)
	clock.Advance(defaultOutboxLeaseTTL + time.Second)
	sweepConcurrently(testSweeper(gdb, nc))
	if reqs, _ := farmer.seen(); len(reqs) != 0 {
		t.Fatalf("sent %d requests for an offboarding tenant", len(reqs))
	}
	for _, it := range batchItems(t, gdb, resp["batch_id"].(string)) {
		if it.Status != ActionItemFailed || it.ErrorCode != errCodeTenantNotActive || it.Attempts != 0 {
			t.Fatalf("item = %+v", it)
		}
	}
}

// Every item error code saasapi can store is in the OpenAPI enum and in
// docs/api/saasapi.md's "Item error codes", so clients know to handle it.
func TestItemErrorCodesDocumented(t *testing.T) {
	spec, err := os.ReadFile("../../docs/api/saasapi-openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	ref, err := os.ReadFile("../../docs/api/saasapi.md")
	if err != nil {
		t.Fatal(err)
	}
	section := string(ref)
	if i := strings.Index(section, "#### Item error codes"); i >= 0 {
		section = section[i:]
	} else {
		t.Fatal(`docs/api/saasapi.md has no "Item error codes" section`)
	}
	for code := range actionErrorMessages {
		if !strings.Contains(string(spec), "                  - "+code+"\n") {
			t.Errorf("%s is not in the OpenAPI item error enum", code)
		}
		if !strings.Contains(section, "`"+code+"`") {
			t.Errorf("%s is not in docs/api/saasapi.md's item error codes", code)
		}
	}
}
