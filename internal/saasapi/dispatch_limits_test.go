package saasapi

// Security review 2026-10 fixes in saasapi's dispatch (SEC.5; FLAG FOR
// SECURITY REVIEW): per-tenant caps and a reserved self_update pool (M5),
// farmer's busy refusal, and a live rollout re-checking that the tenant is
// active before every wave and every item (L8).

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/controlplane"
)

// useDispatchLimits installs a limiter of these sizes for the test.
func useDispatchLimits(t *testing.T, general, selfUpdate, tenantCap int) {
	t.Helper()
	prev := dispatchLimits.Load()
	setDispatchLimits(general, selfUpdate, tenantCap)
	t.Cleanup(func() { dispatchLimits.Store(prev) })
}

func TestLoadConfigDispatchConcurrency(t *testing.T) {
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if s := cfg.OutboxSweeper; s.DispatchConcurrency != 64 || s.SelfUpdateDispatchConcurrency != 16 || s.DispatchTenantConcurrency != 8 {
		t.Fatalf("defaults = %+v", s)
	}
	t.Setenv("SAASAPI_ACTION_DISPATCH_CONCURRENCY", "100")
	t.Setenv("SAASAPI_SELF_UPDATE_DISPATCH_CONCURRENCY", "20")
	t.Setenv("SAASAPI_ACTION_DISPATCH_TENANT_CONCURRENCY", "50")
	cfg, err = LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if s := cfg.OutboxSweeper; s.DispatchConcurrency != 100 || s.SelfUpdateDispatchConcurrency != 20 || s.DispatchTenantConcurrency != 50 {
		t.Fatalf("overrides = %+v", s)
	}
	for _, bad := range []map[string]string{
		{"SAASAPI_ACTION_DISPATCH_CONCURRENCY": "0"},
		{"SAASAPI_ACTION_DISPATCH_CONCURRENCY": "lots"},
		{"SAASAPI_ACTION_DISPATCH_CONCURRENCY": "1025"},
		{"SAASAPI_SELF_UPDATE_DISPATCH_CONCURRENCY": "-1"},
		{"SAASAPI_ACTION_DISPATCH_TENANT_CONCURRENCY": "8.5"},
		// One tenant may hold at most half the pool.
		{"SAASAPI_ACTION_DISPATCH_TENANT_CONCURRENCY": "51"},
		{"SAASAPI_ACTION_DISPATCH_CONCURRENCY": "8", "SAASAPI_ACTION_DISPATCH_TENANT_CONCURRENCY": "8"},
	} {
		t.Run(fmt.Sprint(bad), func(t *testing.T) {
			for k, v := range bad {
				t.Setenv(k, v)
			}
			if _, err := LoadConfig(); err == nil {
				t.Errorf("%v accepted", bad)
			}
		})
	}
}

func TestSetOutboxSweeperSettingsInstallsDispatchLimits(t *testing.T) {
	prevSettings, prevLimits := outboxSettings, dispatchLimits.Load()
	t.Cleanup(func() { outboxSettings = prevSettings; dispatchLimits.Store(prevLimits) })

	s := DefaultOutboxSweeperSettings()
	s.DispatchConcurrency, s.SelfUpdateDispatchConcurrency, s.DispatchTenantConcurrency = 10, 3, 2
	SetOutboxSweeperSettings(s)
	l := dispatchLimits.Load()
	if l.pools[false].size != 10 || l.pools[true].size != 3 || l.tenantCap != 2 {
		t.Fatalf("limiter = general %d, self_update %d, tenant %d", l.pools[false].size, l.pools[true].size, l.tenantCap)
	}
	// Settings written before these fields existed (zero) take the defaults.
	SetOutboxSweeperSettings(OutboxSweeperSettings{LeaseTTL: time.Minute})
	l = dispatchLimits.Load()
	if l.pools[false].size != 64 || l.pools[true].size != 16 || l.tenantCap != 8 {
		t.Fatalf("zero settings: general %d, self_update %d, tenant %d", l.pools[false].size, l.pools[true].size, l.tenantCap)
	}
}

// TestDispatchLimiter: a tenant at its cap waits without holding a pool
// slot, so another tenant still gets one; self_update has its own pool.
func TestDispatchLimiter(t *testing.T) {
	l := newDispatchLimiter(3, 1, 2)
	cmd := controlplane.ActionCmdRun
	a1, a2 := l.acquire("t_a", cmd), l.acquire("t_a", cmd)

	third := make(chan func())
	go func() { third <- l.acquire("t_a", cmd) }()
	select {
	case <-third:
		t.Fatal("t_a got a third slot past its cap")
	case <-time.After(50 * time.Millisecond):
	}
	// t_b proceeds although t_a is waiting.
	b1 := l.acquire("t_b", cmd)
	if n, total := l.inUse("t_a", cmd); n != 2 || total != 3 {
		t.Fatalf("t_a %d, total %d", n, total)
	}
	// The pool is full now; self_update is not affected, by either tenant.
	su := l.acquire("t_a", controlplane.ActionSelfUpdate)
	// Releasing one of t_a's slots admits t_a's waiter.
	a1()
	a1() // idempotent
	var a3 func()
	select {
	case a3 = <-third:
	case <-time.After(time.Second):
		t.Fatal("t_a's waiter never got the freed slot")
	}
	for _, rel := range []func(){a2, a3, b1, su} {
		rel()
	}
	for _, p := range l.pools {
		if p.used != 0 || len(p.byTenant) != 0 {
			t.Fatalf("pool left with %d used, tenants %v", p.used, p.byTenant)
		}
	}
}

// heldFarmer is a fake farmer that holds (doesn't answer) every cmd.run
// of one tenant until released, and answers everything else at once:
// cmd.run completed, self_update dispatched.
type heldFarmer struct {
	mu       sync.Mutex
	hold     string
	released bool
	held     []*nats.Msg
	inFlight int
	peak     int
	seen     map[string]int // requests by tenant/type
}

func startHeldFarmer(t *testing.T, ns *server.Server, hold string) *heldFarmer {
	t.Helper()
	f := &heldFarmer{hold: hold, seen: map[string]int{}}
	fnc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fnc.Close)
	answer := func(msg *nats.Msg, req controlplane.SproutActionRequest) {
		reply := controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID}
		if req.Action.Type == controlplane.ActionSelfUpdate {
			reply.Status, reply.JID = controlplane.StatusDispatched, jidFor(req.SproutID)
		} else {
			reply.Status, reply.Result = controlplane.StatusCompleted, &controlplane.CmdRunResult{}
		}
		b, _ := json.Marshal(reply)
		_ = msg.Respond(b)
	}
	if _, err := fnc.Subscribe(controlplane.SubjectSproutAction, func(msg *nats.Msg) {
		var req controlplane.SproutActionRequest
		_ = json.Unmarshal(msg.Data, &req)
		f.mu.Lock()
		f.seen[req.TenantID+"/"+req.Action.Type]++
		if req.TenantID == f.hold && req.Action.Type == controlplane.ActionCmdRun && !f.released {
			f.held = append(f.held, msg)
			f.inFlight++
			f.peak = max(f.peak, f.inFlight)
			f.mu.Unlock()
			return
		}
		f.mu.Unlock()
		answer(msg, req)
	}); err != nil {
		t.Fatal(err)
	}
	_ = fnc.Flush()
	t.Cleanup(f.release)
	return f
}

func (f *heldFarmer) heldCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.held)
}

func (f *heldFarmer) release() {
	f.mu.Lock()
	f.released = true
	held := f.held
	f.held, f.inFlight = nil, 0
	f.mu.Unlock()
	for _, msg := range held {
		var req controlplane.SproutActionRequest
		_ = json.Unmarshal(msg.Data, &req)
		b, _ := json.Marshal(controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID,
			Status: controlplane.StatusCompleted, Result: &controlplane.CmdRunResult{}})
		_ = msg.Respond(b)
	}
}

// waitBatchDone polls GET until the batch is completed.
func waitBatchDone(t *testing.T, get func() (int, actionBatchResponse), what string) actionBatchResponse {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		code, got := get()
		if code == 200 && got.Status == actionBatchCompleted {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s not completed: %d %+v", what, code, got)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestDispatch_HostileTenantFillsItsCap is security review M5's scenario:
// a tenant posts long cmd.runs that farmer doesn't answer. It holds only
// its cap of dispatch slots; another tenant's batch completes meanwhile,
// and so does a rollout, the hostile tenant's own included, from the
// reserved self_update pool.
func TestDispatch_HostileTenantFillsItsCap(t *testing.T) {
	gdb := newUpdateTestDB(t)
	fastRollouts(t, 5*time.Second)
	useDispatchLimits(t, 4, 2, 2)
	ns := startTestBus(t)
	connectSaaSBus(t, ns)

	hostile := mustCreateActiveTenant(t, gdb)
	other := mustCreateActiveTenant(t, gdb)
	var hostileAssets []string
	for i := 1; i <= 6; i++ {
		sprout := fmt.Sprintf("h-%02d", i)
		mustInsertFarmerSprout(t, gdb, hostile, sprout, "accepted")
		mustLinkAsset(t, hostile, sprout, "h"+sprout+hostile)
		hostileAssets = append(hostileAssets, "h"+sprout+hostile)
	}
	mustInsertFarmerSprout(t, gdb, other, "web-01", "accepted")
	mustLinkAsset(t, other, "web-01", "o-web-01")
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	mustApprove(t, gdb, hostile, "v2.4.1")
	updateAssets := mustUpdateFleet(t, gdb, hostile, 3)
	installReader(t, &waveReader{gdb: gdb, reconnect: "v2.4.1", outcome: func(JobRef, int) (JobOutcome, bool) {
		return JobOutcomeSucceeded, true
	}})
	farmer := startHeldFarmer(t, ns, hostile)

	code, resp := postActions(t, hostile, map[string]any{"asset_ids": hostileAssets,
		"action": map[string]any{"type": "cmd.run", "params": map[string]any{"cmd": "sleep 600", "timeout_seconds": 600}}})
	if code != 202 {
		t.Fatalf("hostile POST: %d %v", code, resp)
	}
	hostileBatch := resp["batch_id"].(string)
	for deadline := time.Now().Add(5 * time.Second); farmer.heldCount() < 2; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("hostile tenant got %d requests to farmer, want its cap of 2", farmer.heldCount())
		}
	}

	// Another tenant's action goes through while the hostile one waits.
	code, resp = postActions(t, other, map[string]any{"asset_ids": []string{"o-web-01"}, "action": cmdAction("uptime")})
	if code != 202 {
		t.Fatalf("other POST: %d %v", code, resp)
	}
	otherBatch := resp["batch_id"].(string)
	got := waitBatchDone(t, func() (int, actionBatchResponse) { return getBatch(t, other, otherBatch) }, "other tenant's batch")
	if got.Items[0].Status != ActionItemSucceeded {
		t.Fatalf("other tenant's item = %+v", got.Items[0])
	}

	// A rollout wave, for the hostile tenant itself, from the reserved pool.
	code, resp = postUpdates(t, hostile, map[string]any{"asset_ids": updateAssets, "target_version": "v2.4.1", "batch_size": 3})
	if code != 202 {
		t.Fatalf("rollout POST: %d %v", code, resp)
	}
	rollout := resp["batch_id"].(string)
	got = waitBatchDone(t, func() (int, actionBatchResponse) { return getUpdateBatch(t, hostile, rollout) }, "rollout")
	for _, it := range got.Items {
		if it.Status != ActionItemSucceeded {
			t.Fatalf("rollout item = %+v", it)
		}
	}

	// Still only the cap: the other four hostile items never reached farmer.
	if n := farmer.heldCount(); n != 2 {
		t.Fatalf("hostile tenant has %d requests at farmer, want 2", n)
	}
	farmer.release()
	got = waitBatchDone(t, func() (int, actionBatchResponse) { return getBatch(t, hostile, hostileBatch) }, "hostile batch")
	for _, it := range got.Items {
		if it.Status != ActionItemSucceeded {
			t.Fatalf("hostile item = %+v", it)
		}
	}
	actionDispatches.Wait()
	farmer.mu.Lock()
	defer farmer.mu.Unlock()
	if farmer.peak > 2 || farmer.seen[hostile+"/cmd.run"] != 6 || farmer.seen[hostile+"/self_update"] != 3 {
		t.Fatalf("peak %d held, seen %v", farmer.peak, farmer.seen)
	}
}

// setTenantStatus moves tenant tid to status.
func setTenantStatus(t *testing.T, gdb *gorm.DB, tid string, status TenantStatus) {
	t.Helper()
	if err := gdb.Model(&Tenant{}).Where("id = ?", tid).Update("status", status).Error; err != nil {
		t.Fatal(err)
	}
}

// TestFleetUpdate_TenantRecheckedBeforeEachWave (L8): a live rollout, not
// only a resumed one, stops once the tenant isn't active, with the code
// the resumed path uses.
func TestFleetUpdate_TenantRecheckedBeforeEachWave(t *testing.T) {
	for _, status := range []TenantStatus{TenantStatusOffboarding, TenantStatusOffboarded, TenantStatusFailed} {
		t.Run(string(status), func(t *testing.T) {
			gdb := newUpdateTestDB(t)
			fastRollouts(t, 5*time.Second)
			ns := startTestBus(t)
			connectSaaSBus(t, ns)
			tid := mustCreateActiveTenant(t, gdb)
			mustPublishVersion(t, gdb, "v2.4.1", time.Now())
			mustApprove(t, gdb, tid, "v2.4.1")
			assets := mustUpdateFleet(t, gdb, tid, 4)
			farmer := startFakeFarmer(t, ns, func(req controlplane.SproutActionRequest) any {
				return controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID,
					Status: controlplane.StatusDispatched, JID: jidFor(req.SproutID)}
			})
			// The tenant leaves "active" while the first wave is waited on;
			// its policy row stays, as DeleteTenant leaves it.
			installReader(t, &waveReader{farmer: farmer, gdb: gdb, reconnect: "v2.4.1", outcome: func(_ JobRef, call int) (JobOutcome, bool) {
				if call == 1 {
					setTenantStatus(t, gdb, tid, status)
				}
				return JobOutcomeSucceeded, true
			}})
			_, resp := postUpdates(t, tid, map[string]any{"asset_ids": assets, "target_version": "v2.4.1", "batch_size": 2})
			actionDispatches.Wait()
			if reqs, _ := farmer.seen(); len(reqs) != 2 {
				t.Fatalf("farmer got %d requests, want only wave 1's 2", len(reqs))
			}
			var items []AssetActionItem
			gdb.Where("batch_id = ? AND tenant_id = ?", resp["batch_id"], tid).Order("position").Find(&items)
			for i, it := range items {
				if i < 2 && it.Status != ActionItemSucceeded {
					t.Errorf("wave 1 item %+v", it)
				}
				if i >= 2 && (it.Status != ActionItemFailed || it.ErrorCode != errCodeTenantNotActive || it.DispatchedAt != nil) {
					t.Errorf("wave 2 item %+v, want failed %s, unsent", it, errCodeTenantNotActive)
				}
			}
		})
	}
}

// TestFleetUpdate_TenantRecheckedBeforeEachItem (L8): within a wave, too,
// nothing more is sent once the tenant isn't active. A tenant cap of 1
// makes the wave's items go out one at a time.
func TestFleetUpdate_TenantRecheckedBeforeEachItem(t *testing.T) {
	gdb := newUpdateTestDB(t)
	fastRollouts(t, 5*time.Second)
	useDispatchLimits(t, 64, 16, 1)
	ns := startTestBus(t)
	connectSaaSBus(t, ns)
	tid := mustCreateActiveTenant(t, gdb)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	mustApprove(t, gdb, tid, "v2.4.1")
	assets := mustUpdateFleet(t, gdb, tid, 3)
	var first sync.Once
	farmer := startFakeFarmer(t, ns, func(req controlplane.SproutActionRequest) any {
		first.Do(func() { setTenantStatus(t, gdb, tid, TenantStatusOffboarding) })
		return controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID,
			Status: controlplane.StatusDispatched, JID: jidFor(req.SproutID)}
	})
	installReader(t, &waveReader{farmer: farmer, gdb: gdb, reconnect: "v2.4.1", outcome: func(JobRef, int) (JobOutcome, bool) {
		return JobOutcomeSucceeded, true
	}})
	_, resp := postUpdates(t, tid, map[string]any{"asset_ids": assets, "target_version": "v2.4.1", "batch_size": 3})
	actionDispatches.Wait()
	if reqs, _ := farmer.seen(); len(reqs) != 1 {
		t.Fatalf("farmer got %d requests, want 1", len(reqs))
	}
	var items []AssetActionItem
	gdb.Where("batch_id = ? AND tenant_id = ?", resp["batch_id"], tid).Order("position").Find(&items)
	if items[0].Status != ActionItemSucceeded {
		t.Errorf("the item sent before the change: %+v", items[0])
	}
	for _, it := range items[1:] {
		if it.Status != ActionItemFailed || it.ErrorCode != errCodeTenantNotActive || it.DispatchedAt != nil {
			t.Errorf("item %+v, want failed %s, unsent", it, errCodeTenantNotActive)
		}
	}
}

// TestFleetUpdate_FarmerBusyIsRetried: an item farmer refused unrun
// (farmer_busy) is sent again within the wave; one refused every time
// stays unsent and halts the rollout.
func TestFleetUpdate_FarmerBusyIsRetried(t *testing.T) {
	prevRetries, prevBackoff := farmerBusyRetries, farmerBusyBackoff
	farmerBusyRetries, farmerBusyBackoff = 2, 5*time.Millisecond
	t.Cleanup(func() { farmerBusyRetries, farmerBusyBackoff = prevRetries, prevBackoff })

	for _, tc := range []struct {
		name     string
		busyFor  int // refusals per sprout before farmer accepts
		wantReqs int
		want     AssetActionItemStatus
		wantCode string
	}{
		{"accepted on retry", 1, 2 * 2, ActionItemSucceeded, ""},
		{"busy throughout", 100, 2 * 3, ActionItemFailed, errCodeRolloutHalted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gdb := newUpdateTestDB(t)
			fastRollouts(t, 5*time.Second)
			ns := startTestBus(t)
			connectSaaSBus(t, ns)
			tid := mustCreateActiveTenant(t, gdb)
			mustPublishVersion(t, gdb, "v2.4.1", time.Now())
			mustApprove(t, gdb, tid, "v2.4.1")
			assets := mustUpdateFleet(t, gdb, tid, 2)
			var mu sync.Mutex
			asked := map[string]int{}
			farmer := startFakeFarmer(t, ns, func(req controlplane.SproutActionRequest) any {
				mu.Lock()
				asked[req.SproutID]++
				n := asked[req.SproutID]
				mu.Unlock()
				reply := controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID}
				if n <= tc.busyFor {
					reply.Status, reply.ErrorCode = controlplane.StatusFailed, farmerCodeBusy
				} else {
					reply.Status, reply.JID = controlplane.StatusDispatched, jidFor(req.SproutID)
				}
				return reply
			})
			installReader(t, &waveReader{farmer: farmer, gdb: gdb, reconnect: "v2.4.1", outcome: func(JobRef, int) (JobOutcome, bool) {
				return JobOutcomeSucceeded, true
			}})
			_, resp := postUpdates(t, tid, map[string]any{"asset_ids": assets, "target_version": "v2.4.1", "batch_size": 2})
			actionDispatches.Wait()
			if reqs, _ := farmer.seen(); len(reqs) != tc.wantReqs {
				t.Fatalf("farmer got %d requests, want %d", len(reqs), tc.wantReqs)
			}
			var items []AssetActionItem
			gdb.Where("batch_id = ? AND tenant_id = ?", resp["batch_id"], tid).Order("position").Find(&items)
			for _, it := range items {
				if it.Status != tc.want || it.ErrorCode != tc.wantCode {
					t.Errorf("item %+v, want %s %s", it, tc.want, tc.wantCode)
				}
			}
		})
	}
}

// A §1.5 item farmer refused as busy ran nothing: it goes back to queued,
// undelivered, for the outbox sweeper to send again.
func TestSproutActionBatch_FarmerBusyLeavesItemQueued(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	ns := startTestBus(t)
	connectSaaSBus(t, ns)
	tid := mustCreateActiveTenant(t, gdb)
	mustInsertFarmerSprout(t, gdb, tid, "web-01", "accepted")
	mustLinkAsset(t, tid, "web-01", "a1")
	startFakeFarmer(t, ns, func(req controlplane.SproutActionRequest) any {
		return controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID,
			Status: controlplane.StatusFailed, ErrorCode: farmerCodeBusy}
	})
	_, resp := postActions(t, tid, map[string]any{"asset_ids": []string{"a1"}, "action": cmdAction("uptime")})
	actionDispatches.Wait()
	var it AssetActionItem
	if err := gdb.Where("batch_id = ? AND tenant_id = ?", resp["batch_id"], tid).First(&it).Error; err != nil {
		t.Fatal(err)
	}
	if it.Status != ActionItemQueued || it.DispatchedAt != nil || it.Attempts != 1 || it.ErrorCode != "" {
		t.Fatalf("item = %+v, want queued, undelivered, 1 attempt", it)
	}
}

func TestReplyUpdate_FarmerCodes(t *testing.T) {
	batch := AssetActionBatch{ID: "b_1", TenantID: "t_1", ActionType: controlplane.ActionSelfUpdate}
	item := AssetActionItem{AssetID: "a1", SproutID: "web-01"}
	for code, want := range map[controlplane.ErrorCode]map[string]any{
		"rollout_window_closed": failedUpdate(errCodeRolloutWindowClosed),
		"self_update_disabled":  failedUpdate(string(controlplane.ErrorInternal)),
		"farmer_busy":           requeueUpdate(),
		"something_new":         failedUpdate(string(controlplane.ErrorInternal)),
	} {
		b, _ := json.Marshal(controlplane.SproutActionReply{TenantID: "t_1", SproutID: "web-01", Status: controlplane.StatusFailed, ErrorCode: code})
		if got := replyUpdate(batch, item, b); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s: %v, want %v", code, got, want)
		}
	}
	// A busy reply naming another sprout is not believed.
	b, _ := json.Marshal(controlplane.SproutActionReply{TenantID: "t_1", SproutID: "web-02", Status: controlplane.StatusFailed, ErrorCode: farmerCodeBusy})
	if got := replyUpdate(batch, item, b); got["error_code"] != errCodeDispatchOutcomeUnknown {
		t.Errorf("mismatched busy reply: %v", got)
	}
	// The strings farmer sends (internal/natsapi pins the same values).
	if farmerCodeBusy != "farmer_busy" || farmerCodeSelfUpdateDisabled != "self_update_disabled" || farmerCodeRolloutWindowClosed != "rollout_window_closed" {
		t.Error("farmer code values changed")
	}
}
