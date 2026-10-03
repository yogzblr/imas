package saasapi

import (
	"fmt"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/controlplane"
)

// dispatchedFarmer answers every self_update as dispatched, with the
// sprout's jid.
func dispatchedFarmer(req controlplane.SproutActionRequest) any {
	return controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID,
		Status: controlplane.StatusDispatched, JID: jidFor(req.SproutID)}
}

// succeedingReader is a waveReader whose every job has succeeded, after
// which its sprout reports v2.4.1.
func succeedingReader(f *fakeFarmer, gdb *gorm.DB) *waveReader {
	return &waveReader{farmer: f, gdb: gdb, reconnect: "v2.4.1", outcome: func(JobRef, int) (JobOutcome, bool) {
		return JobOutcomeSucceeded, true
	}}
}

// rolloutFixture is a tenant with an approved, registered v2.4.1 and n
// sprouts on the old version.
type rolloutFixture struct {
	gdb    *gorm.DB
	tid    string
	assets []string
}

func newRolloutFixture(t *testing.T, n int) rolloutFixture {
	t.Helper()
	gdb := newUpdateTestDB(t)
	clearOutbox(t, gdb)
	fastRollouts(t, 5*time.Second)
	tid := mustCreateActiveTenant(t, gdb)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	mustApprove(t, gdb, tid, "v2.4.1")
	return rolloutFixture{gdb: gdb, tid: tid, assets: mustUpdateFleet(t, gdb, tid, n)}
}

// sprout is the sprout behind f.assets[i].
func (f rolloutFixture) sprout(i int) string { return fmt.Sprintf("upd-%02d", i+1) }

// seed writes a rollout batch as a process that died part-way through it
// would have left it: items[i] is f.assets[i]'s item, with whatever status
// and dispatch time the caller gave it.
func (f rolloutFixture) seed(t *testing.T, size int, gate string, leaseUntil *time.Time, items []AssetActionItem) AssetActionBatch {
	t.Helper()
	batch := AssetActionBatch{ID: "b_res_" + f.tid, TenantID: f.tid, ActionType: controlplane.ActionSelfUpdate,
		ActionParams: `{"version":"v2.4.1"}`, RequestedAssetIDs: "[]", RolloutBatchSize: size, RolloutGate: gate}
	if leaseUntil != nil {
		batch.LeaseOwner, batch.LeaseUntil = "dead-pod/x", leaseUntil
	}
	if err := f.gdb.Create(&batch).Error; err != nil {
		t.Fatal(err)
	}
	for i := range items {
		items[i].BatchID, items[i].AssetID, items[i].TenantID, items[i].Position, items[i].SproutID =
			batch.ID, f.assets[i], f.tid, i, f.sprout(i)
	}
	if err := f.gdb.Create(&items).Error; err != nil {
		t.Fatal(err)
	}
	return batch
}

func sentAt(d time.Time) *time.Time { d = dbTime(d); return &d }

// sentSprouts lists the sprouts farmer was sent an update for, in order.
func sentSprouts(f *fakeFarmer) []string {
	reqs, _ := f.seen()
	out := make([]string, len(reqs))
	for i, r := range reqs {
		out[i] = r.SproutID
	}
	return out
}

func itemStates(t *testing.T, gdb *gorm.DB, batchID string) []string {
	t.Helper()
	var out []string
	for _, it := range batchItems(t, gdb, batchID) {
		out = append(out, string(it.Status)+"/"+it.ErrorCode)
	}
	return out
}

func wantStates(t *testing.T, got []string, want ...string) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("items = %v, want %v", got, want)
	}
}

// The crash case: a rollout accepted by a process with no bus (as if it
// died before its first wave) is resumed by the sweeper once the batch's
// lease has lapsed. Two sweepers on one database send each item exactly
// once, in waves of the original size that never overlap, and the
// tenant's rollout slot is free afterwards.
func TestSweepRollouts_CrashThenTwoSweepers(t *testing.T) {
	f := newRolloutFixture(t, 5)
	clock := useOutboxClock(t)
	SetBus(nil)
	code, resp := postUpdates(t, f.tid, map[string]any{"asset_ids": f.assets, "target_version": "v2.4.1", "batch_size": 2})
	actionDispatches.Wait()
	if code != 202 {
		t.Fatalf("POST: %d %v", code, resp)
	}
	batchID := resp["batch_id"].(string)
	wantStates(t, itemStates(t, f.gdb, batchID), "queued/", "queued/", "queued/", "queued/", "queued/")
	if busy, _ := updateInProgress(f.gdb, f.tid); busy != batchID {
		t.Fatalf("the dead rollout doesn't hold the tenant's slot: %q", busy)
	}

	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	farmer := startFakeFarmer(t, ns, dispatchedFarmer)
	reader := succeedingReader(farmer, f.gdb)
	installReader(t, reader)
	a, b := testSweeper(f.gdb, nc), testSweeper(f.gdb, nc)

	// Its lease is still live: not taken over.
	sweepConcurrently(a, b)
	if n := len(sentSprouts(farmer)); n != 0 {
		t.Fatalf("a live rollout was taken over: %d sent", n)
	}

	clock.Advance(defaultOutboxLeaseTTL + time.Second)
	sweepConcurrently(a, b, a, b)
	sent := sentSprouts(farmer)
	if len(sent) != 5 {
		t.Fatalf("sent %v, want 5 requests", sent)
	}
	count := map[string]int{}
	for _, s := range sent {
		count[s]++
	}
	for i := range f.assets {
		if count[f.sprout(i)] != 1 {
			t.Fatalf("%s sent %d times (all: %v)", f.sprout(i), count[f.sprout(i)], sent)
		}
	}
	for _, n := range reader.seenAtOK {
		if n != 2 && n != 4 && n != 5 {
			t.Fatalf("waves overlapped: the reader saw %d sent (all: %v)", n, reader.seenAtOK)
		}
	}
	wantStates(t, itemStates(t, f.gdb, batchID), "succeeded/", "succeeded/", "succeeded/", "succeeded/", "succeeded/")
	if busy, _ := updateInProgress(f.gdb, f.tid); busy != "" {
		t.Fatalf("the tenant's rollout slot is still held by %s", busy)
	}
	var policy TenantUpdatePolicy
	if f.gdb.First(&policy, "tenant_id = ?", f.tid); policy.RolloutClaimedAt == nil {
		t.Fatal("the takeover didn't rewrite the tenant's rollout claim")
	}
}

// A process died after sending the first wave: those items are never sent
// again, and are judged from their recorded dispatch time; the queued
// rest go out in waves of the original size once that wave passes.
func TestSweepRollouts_ResumesAfterFirstWave(t *testing.T) {
	f := newRolloutFixture(t, 5)
	clock := useOutboxClock(t)
	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	farmer := startFakeFarmer(t, ns, dispatchedFarmer)
	reader := succeedingReader(farmer, f.gdb)
	installReader(t, reader)

	expired := dbTime(clock.Now().Add(-time.Second))
	sent := sentAt(time.Now().Add(-time.Minute))
	batch := f.seed(t, 2, gateJobStatus, &expired, []AssetActionItem{
		{Status: ActionItemRunning, JID: jidFor(f.sprout(0)), Attempts: 1, DispatchedAt: sent},
		{Status: ActionItemRunning, JID: jidFor(f.sprout(1)), Attempts: 1, DispatchedAt: sent},
		{Status: ActionItemQueued}, {Status: ActionItemQueued}, {Status: ActionItemQueued},
	})

	sweepConcurrently(testSweeper(f.gdb, nc), testSweeper(f.gdb, nc))
	if got := sentSprouts(farmer); len(got) != 3 || got[0] == f.sprout(0) || got[0] == f.sprout(1) {
		t.Fatalf("sent %v, want only the 3 queued sprouts", got)
	}
	for _, n := range reader.seenAtOK {
		if n != 0 && n != 2 && n != 3 {
			t.Fatalf("waves of the wrong size: the reader saw %d sent (all: %v)", n, reader.seenAtOK)
		}
	}
	wantStates(t, itemStates(t, f.gdb, batch.ID), "succeeded/", "succeeded/", "succeeded/", "succeeded/", "succeeded/")
}

// A sent item that failed before the takeover fails the gate: the queued
// rest are halted, never sent.
func TestSweepRollouts_FailedSentItemHalts(t *testing.T) {
	f := newRolloutFixture(t, 3)
	useOutboxClock(t)
	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	farmer := startFakeFarmer(t, ns, dispatchedFarmer)
	installReader(t, succeedingReader(farmer, f.gdb))

	expired := dbTime(time.Now().Add(-time.Second))
	sent := sentAt(time.Now().Add(-time.Minute))
	batch := f.seed(t, 1, gateDispatch, &expired, []AssetActionItem{
		{Status: ActionItemSucceeded, JID: jidFor(f.sprout(0)), Attempts: 1, DispatchedAt: sent},
		{Status: ActionItemFailed, ErrorCode: errCodeJobFailed, JID: jidFor(f.sprout(1)), Attempts: 1, DispatchedAt: sent},
		{Status: ActionItemQueued},
	})
	sweepConcurrently(testSweeper(f.gdb, nc))
	if got := sentSprouts(farmer); len(got) != 0 {
		t.Fatalf("sent %v after a failed wave", got)
	}
	wantStates(t, itemStates(t, f.gdb, batch.ID), "succeeded/", "failed/job_failed", "failed/rollout_halted")
}

// Before every resumed wave the version is checked again: revoked, no
// longer approved, or no longer registered, the queued items are failed
// unsent.
func TestSweepRollouts_RecheckedBeforeResumedWave(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(f rolloutFixture)
		code   string
	}{
		{"revoked", func(f rolloutFixture) {
			f.gdb.Model(&FleetVersion{}).Where("version = ?", "v2.4.1").Update("revoked", true)
		}, errCodeVersionRevoked},
		{"approval withdrawn", func(f rolloutFixture) {
			mustPublishVersion(t, f.gdb, "v2.5.0", time.Now())
			mustApprove(t, f.gdb, f.tid, "v2.5.0")
		}, errCodeApprovalWithdrawn},
		{"tenant offboarding", func(f rolloutFixture) {
			f.gdb.Model(&Tenant{}).Where("id = ?", f.tid).Update("status", TenantStatusOffboarding)
		}, errCodeTenantNotActive},
		{"no longer registered", func(f rolloutFixture) {
			f.gdb.Where("version = ?", "v2.4.1").Delete(&FleetVersion{})
		}, errCodeRolloutHalted},
		{"signature no longer verifies", func(f rolloutFixture) {
			f.gdb.Model(&FleetVersion{}).Where("version = ?", "v2.4.1").Update("checksum_sha256", "ab"+fmt.Sprintf("%062d", 0))
		}, errCodeRolloutHalted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRolloutFixture(t, 2)
			useOutboxClock(t)
			ns := startTestBus(t)
			nc := connectSaaSBus(t, ns)
			farmer := startFakeFarmer(t, ns, dispatchedFarmer)
			installReader(t, succeedingReader(farmer, f.gdb))
			expired := dbTime(time.Now().Add(-time.Second))
			batch := f.seed(t, 1, gateJobStatus, &expired, []AssetActionItem{
				{Status: ActionItemSucceeded, JID: jidFor(f.sprout(0)), Attempts: 1, DispatchedAt: sentAt(time.Now().Add(-time.Minute))},
				{Status: ActionItemQueued},
			})
			tc.change(f)
			sweepConcurrently(testSweeper(f.gdb, nc))
			if got := sentSprouts(farmer); len(got) != 0 {
				t.Fatalf("sent %v", got)
			}
			wantStates(t, itemStates(t, f.gdb, batch.ID), "succeeded/", "failed/"+tc.code)
		})
	}
}

// A live lease is not taken over; once it has lapsed it is.
func TestSweepRollouts_LiveLeaseNotTakenOver(t *testing.T) {
	f := newRolloutFixture(t, 1)
	clock := useOutboxClock(t)
	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	farmer := startFakeFarmer(t, ns, dispatchedFarmer)
	installReader(t, succeedingReader(farmer, f.gdb))
	live := dbTime(clock.Now().Add(time.Minute))
	batch := f.seed(t, 1, gateJobStatus, &live, []AssetActionItem{{Status: ActionItemQueued}})

	sweepConcurrently(testSweeper(f.gdb, nc))
	if got := sentSprouts(farmer); len(got) != 0 {
		t.Fatalf("sent %v under a live lease", got)
	}
	clock.Advance(time.Minute + time.Millisecond)
	sweepConcurrently(testSweeper(f.gdb, nc))
	if got := sentSprouts(farmer); len(got) != 1 {
		t.Fatalf("sent %v after the lease lapsed", got)
	}
	wantStates(t, itemStates(t, f.gdb, batch.ID), "succeeded/")
}

// An item a dead process left in dispatching is never re-sent. It holds
// the gate until its deadline, measured from its dispatch time, and then
// fails it: the queued rest are halted unsent, and the item itself is left
// in dispatching.
func TestSweepRollouts_NeverResendsDispatching(t *testing.T) {
	f := newRolloutFixture(t, 2)
	useOutboxClock(t)
	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	farmer := startFakeFarmer(t, ns, dispatchedFarmer)
	installReader(t, succeedingReader(farmer, f.gdb))
	expired := dbTime(time.Now().Add(-time.Second))
	batch := f.seed(t, 1, gateJobStatus, &expired, []AssetActionItem{
		{Status: ActionItemDispatching, Attempts: 1, DispatchedAt: sentAt(time.Now().Add(-4 * time.Second))},
		{Status: ActionItemQueued},
	})
	start := time.Now()
	sweepConcurrently(testSweeper(f.gdb, nc))
	if got := sentSprouts(farmer); len(got) != 0 {
		t.Fatalf("sent %v", got)
	}
	if waited := time.Since(start); waited < 500*time.Millisecond {
		t.Fatalf("halted after %s, before the dispatching item's deadline", waited)
	}
	wantStates(t, itemStates(t, f.gdb, batch.ID), "dispatching/", "failed/rollout_halted")
}

// With fleet update dispatch off, nothing is resumed.
func TestSweepRollouts_OnlyWhenDispatchEnabled(t *testing.T) {
	f := newRolloutFixture(t, 1)
	useOutboxClock(t)
	SetFleetUpdateDispatchEnabled(false)
	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	farmer := startFakeFarmer(t, ns, dispatchedFarmer)
	expired := dbTime(time.Now().Add(-time.Hour))
	f.seed(t, 1, gateJobStatus, &expired, []AssetActionItem{{Status: ActionItemQueued}})
	sweepConcurrently(testSweeper(f.gdb, nc))
	if got := sentSprouts(farmer); len(got) != 0 {
		t.Fatalf("resumed with dispatch disabled: sent %v", got)
	}
}

// A batch the previous release wrote has no lease; it is taken over only
// once its items have been quiet for longer than a live rollout ever is.
func TestSweepRollouts_LegacyBatchWaitsForQuiet(t *testing.T) {
	f := newRolloutFixture(t, 1)
	clock := useOutboxClock(t)
	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	farmer := startFakeFarmer(t, ns, dispatchedFarmer)
	installReader(t, succeedingReader(farmer, f.gdb))
	f.seed(t, 1, gateJobStatus, nil, []AssetActionItem{{Status: ActionItemQueued}})
	sw := testSweeper(f.gdb, nc)

	clock.Advance(sw.legacyRolloutQuiet() - time.Second)
	sweepConcurrently(sw)
	if got := sentSprouts(farmer); len(got) != 0 {
		t.Fatalf("a recently active legacy rollout was taken over: %v", got)
	}
	clock.Advance(2 * time.Second)
	sweepConcurrently(sw)
	if got := sentSprouts(farmer); len(got) != 1 {
		t.Fatalf("a quiet legacy rollout was not resumed: %v", got)
	}
}

func TestWasSent(t *testing.T) {
	at := time.Now()
	for _, tc := range []struct {
		it   AssetActionItem
		want bool
	}{
		{AssetActionItem{Status: ActionItemQueued}, false},
		{AssetActionItem{Status: ActionItemUnresolved}, false},
		{AssetActionItem{Status: ActionItemDispatching}, true},
		{AssetActionItem{Status: ActionItemRunning}, true},
		{AssetActionItem{Status: ActionItemSucceeded}, true},
		{AssetActionItem{Status: ActionItemUnresponsiveAfterUpdate}, true},
		{AssetActionItem{Status: ActionItemFailed, ErrorCode: errCodeRolloutHalted}, false},
		{AssetActionItem{Status: ActionItemFailed, ErrorCode: errCodeNoReleaseForPlatform}, false},
		{AssetActionItem{Status: ActionItemFailed, ErrorCode: errCodeJobFailed}, true},
		{AssetActionItem{Status: ActionItemFailed, ErrorCode: errCodeJobFailed, DispatchedAt: &at}, true},
		{AssetActionItem{Status: ActionItemFailed, ErrorCode: string(controlplane.ErrorInternal)}, true},
	} {
		if got := wasSent(tc.it); got != tc.want {
			t.Errorf("wasSent(%s/%s, dispatched %t) = %t", tc.it.Status, tc.it.ErrorCode, tc.it.DispatchedAt != nil, got)
		}
	}
}

// A live rollout renews its lease while it waits on a wave, so sweepers
// running all the while, over several lease TTLs, never take it over.
func TestSweepRollouts_LiveRolloutKeepsItsLease(t *testing.T) {
	f := newRolloutFixture(t, 3)
	prev := outboxSettings
	outboxSettings.LeaseTTL = 300 * time.Millisecond
	t.Cleanup(func() { outboxSettings = prev })
	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	farmer := startFakeFarmer(t, ns, dispatchedFarmer)
	start := time.Now()
	installReader(t, &waveReader{farmer: farmer, gdb: f.gdb, reconnect: "v2.4.1", outcome: func(JobRef, int) (JobOutcome, bool) {
		if time.Since(start) < 1500*time.Millisecond {
			return JobOutcomeRunning, true
		}
		return JobOutcomeSucceeded, true
	}})

	code, resp := postUpdates(t, f.tid, map[string]any{"asset_ids": f.assets, "target_version": "v2.4.1", "batch_size": 2})
	if code != 202 {
		t.Fatalf("POST: %d %v", code, resp)
	}
	var created AssetActionBatch
	f.gdb.First(&created, "id = ?", resp["batch_id"])
	sw := testSweeper(f.gdb, nc)
	sw.s.LeaseTTL = outboxSettings.LeaseTTL
	for time.Since(start) < 2*time.Second {
		sw.sweep()
		time.Sleep(50 * time.Millisecond)
	}
	actionDispatches.Wait()
	sent := sentSprouts(farmer)
	if len(sent) != 3 {
		t.Fatalf("sent %v, want each of 3 sprouts once", sent)
	}
	wantStates(t, itemStates(t, f.gdb, resp["batch_id"].(string)), "succeeded/", "succeeded/", "succeeded/")
	var after AssetActionBatch
	f.gdb.First(&after, "id = ?", resp["batch_id"])
	if created.LeaseOwner == "" || after.LeaseOwner != created.LeaseOwner {
		t.Fatalf("the live rollout's lease changed hands (%q -> %q)", created.LeaseOwner, after.LeaseOwner)
	}
}
