package saasapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

// withMaxPending installs outbox settings with MaxPendingPerTenant = limit
// for the test.
func withMaxPending(t *testing.T, limit int) {
	t.Helper()
	prev := CurrentOutboxSweeperSettings()
	s := DefaultOutboxSweeperSettings()
	s.MaxPendingPerTenant = limit
	SetOutboxSweeperSettings(s)
	t.Cleanup(func() { SetOutboxSweeperSettings(prev) })
}

// seedItems writes one batch of tenantID with n items in status st.
func seedItems(t *testing.T, gdb *gorm.DB, tenantID string, st AssetActionItemStatus, n int) {
	t.Helper()
	id, _ := newID(actionBatchIDPrefix)
	if err := gdb.Create(&AssetActionBatch{ID: id, TenantID: tenantID, ActionType: "cmd.run",
		ActionParams: "{}", RequestedAssetIDs: "[]"}).Error; err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if err := gdb.Create(&AssetActionItem{BatchID: id, AssetID: fmt.Sprintf("seed-%d", i), TenantID: tenantID,
			Position: i, Status: st}).Error; err != nil {
			t.Fatal(err)
		}
	}
}

// linkedAssets gives tenantID n accepted, linked sprouts and returns
// their asset ids, so a §1.5 request for them queues n items.
func linkedAssets(t *testing.T, gdb *gorm.DB, tenantID, prefix string, n int) []string {
	t.Helper()
	ids := make([]string, n)
	for i := range n {
		sprout := fmt.Sprintf("%s-%02d", prefix, i)
		ids[i] = fmt.Sprintf("%s-%s-%d", prefix, tenantID, i)
		mustInsertFarmerSprout(t, gdb, tenantID, sprout, "accepted")
		mustLinkAsset(t, tenantID, sprout, ids[i])
	}
	return ids
}

func rowCounts(t *testing.T, gdb *gorm.DB) (batches, items int64) {
	t.Helper()
	gdb.Model(&AssetActionBatch{}).Count(&batches)
	gdb.Model(&AssetActionItem{}).Count(&items)
	return batches, items
}

func postActionsRaw(t *testing.T, tenantID string, assetIDs []string) *http.Response {
	t.Helper()
	w := doRequest(t, CreateSproutActionBatch, "POST", "/v1/tenants/"+tenantID+"/sprouts/actions",
		map[string]string{"tenant_id": tenantID}, map[string]any{"asset_ids": assetIDs, "action": cmdAction("ls")})
	actionDispatches.Wait()
	return w.Result()
}

type backlogRefusal struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Details struct {
		Pending   *int `json:"pending"`
		Limit     *int `json:"limit"`
		Requested *int `json:"requested"`
		Available *int `json:"available"`
	} `json:"details"`
}

// assertRefused checks resp is the backlog_full refusal with these
// numbers.
func assertRefused(t *testing.T, resp *http.Response, pending, limit, requested, available int) {
	t.Helper()
	var body backlogRefusal
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding refusal: %v", err)
	}
	if resp.StatusCode != http.StatusTooManyRequests || body.Error != "backlog_full" {
		t.Fatalf("got %d %q, want 429 backlog_full", resp.StatusCode, body.Error)
	}
	if body.Message != "this tenant has too many actions waiting to be sent; wait for some to finish and send again" {
		t.Errorf("message = %q", body.Message)
	}
	if got := resp.Header.Get("Retry-After"); got != "60" {
		t.Errorf("Retry-After = %q, want 60", got)
	}
	d := body.Details
	if d.Pending == nil || d.Limit == nil || d.Requested == nil || d.Available == nil {
		t.Fatalf("details missing a number: %+v", d)
	}
	if *d.Pending != pending || *d.Limit != limit || *d.Requested != requested || *d.Available != available {
		t.Errorf("details = pending %d limit %d requested %d available %d, want %d %d %d %d",
			*d.Pending, *d.Limit, *d.Requested, *d.Available, pending, limit, requested, available)
	}
}

// Pending plus requested equal to the limit is accepted, one more is
// refused as a whole with nothing written; the limit counts deduplicated
// asset_ids.
func TestBacklogBoundary(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	SetBus(nil) // nothing is sent: items stay queued
	withMaxPending(t, 5)
	tid := mustCreateActiveTenant(t, gdb)
	seedItems(t, gdb, tid, ActionItemQueued, 3)
	assets := linkedAssets(t, gdb, tid, "bnd", 3)

	// 3 pending + 2 (one duplicate in the request) = 5: accepted.
	if resp := postActionsRaw(t, tid, []string{assets[0], assets[1], assets[0]}); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("at the limit: %d, want 202", resp.StatusCode)
	}
	if n, _ := countPendingItems(gdb, tid); n != 5 {
		t.Fatalf("pending after accept = %d, want 5", n)
	}

	batches, items := rowCounts(t, gdb)
	assertRefused(t, postActionsRaw(t, tid, []string{assets[2]}), 5, 5, 1, 0)
	if b, i := rowCounts(t, gdb); b != batches || i != items {
		t.Fatalf("a refusal wrote rows: batches %d->%d, items %d->%d", batches, b, items, i)
	}
}

// The details report what is left, and available is never negative when
// the backlog is already over the limit (a lowered setting, or the soft
// limit's race).
func TestBacklogRefusalDetails(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	SetBus(nil)
	withMaxPending(t, 10)
	tid := mustCreateActiveTenant(t, gdb)
	seedItems(t, gdb, tid, ActionItemQueued, 7)
	assertRefused(t, postActionsRaw(t, tid, []string{"a", "b", "c", "d"}), 7, 10, 4, 3)

	other := mustCreateActiveTenant(t, gdb)
	seedItems(t, gdb, other, ActionItemDispatching, 12)
	assertRefused(t, postActionsRaw(t, other, []string{"a"}), 12, 10, 1, 0)
}

// One tenant's backlog does not refuse another tenant's request.
func TestBacklogIsPerTenant(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	SetBus(nil)
	withMaxPending(t, 4)
	full := mustCreateActiveTenant(t, gdb)
	other := mustCreateActiveTenant(t, gdb)
	seedItems(t, gdb, full, ActionItemQueued, 3)
	seedItems(t, gdb, other, ActionItemQueued, 3)
	assertRefused(t, postActionsRaw(t, full, []string{"x", "y"}), 3, 4, 2, 1)
	if resp := postActionsRaw(t, other, []string{"x"}); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("the other tenant: %d, want 202", resp.StatusCode)
	}
}

// Only queued and dispatching items count; running, finished and
// unresolved ones do not.
func TestBacklogCountsQueuedAndDispatchingOnly(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	SetBus(nil)
	withMaxPending(t, 5)
	tid := mustCreateActiveTenant(t, gdb)
	for _, st := range []AssetActionItemStatus{ActionItemRunning, ActionItemSucceeded, ActionItemFailed,
		ActionItemUnresolved, ActionItemUnresponsiveAfterUpdate} {
		seedItems(t, gdb, tid, st, 10)
	}
	if n, err := countPendingItems(gdb, tid); err != nil || n != 0 {
		t.Fatalf("pending with no queued or dispatching item = %d, %v; want 0", n, err)
	}
	seedItems(t, gdb, tid, ActionItemQueued, 2)
	seedItems(t, gdb, tid, ActionItemDispatching, 2)
	if n, err := countPendingItems(gdb, tid); err != nil || n != 4 {
		t.Fatalf("pending = %d, %v; want 4", n, err)
	}
	if resp := postActionsRaw(t, tid, []string{"u1"}); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("4 pending + 1 with limit 5: %d, want 202", resp.StatusCode)
	}
	assertRefused(t, postActionsRaw(t, tid, []string{"u1", "u2"}), 4, 5, 2, 1)
}

// An update rollout is never refused by the backlog cap, even when the
// tenant is over it.
func TestBacklogDoesNotBlockUpdateRollouts(t *testing.T) {
	gdb := newUpdateTestDB(t)
	SetBus(nil) // nothing is sent: this test only looks at the answer
	withMaxPending(t, 2)
	tid := mustCreateActiveTenant(t, gdb)
	seedItems(t, gdb, tid, ActionItemQueued, 5)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	mustApprove(t, gdb, tid, "v2.4.1")
	assets := mustUpdateFleet(t, gdb, tid, 3)
	code, resp := postUpdates(t, tid, map[string]any{"asset_ids": assets, "target_version": "v2.4.1"})
	actionDispatches.Wait()
	if code != http.StatusAccepted {
		t.Fatalf("rollout over the cap: %d %v, want 202", code, resp)
	}
	// And the §1.5 endpoint still refuses this tenant, counting the
	// rollout's queued items too.
	pending, err := countPendingItems(gdb, tid)
	if err != nil || pending < 5 {
		t.Fatalf("pending = %d, %v", pending, err)
	}
	assertRefused(t, postActionsRaw(t, tid, []string{"z"}), pending, 2, 1, 0)
}

// A zero MaxPendingPerTenant (a settings literal that doesn't set it)
// takes the default instead of refusing everything.
func TestBacklogZeroSettingTakesDefault(t *testing.T) {
	prev := CurrentOutboxSweeperSettings()
	t.Cleanup(func() { SetOutboxSweeperSettings(prev) })
	SetOutboxSweeperSettings(OutboxSweeperSettings{LeaseTTL: time.Minute})
	if got := CurrentOutboxSweeperSettings().MaxPendingPerTenant; got != defaultMaxPendingPerTenant {
		t.Fatalf("MaxPendingPerTenant = %d, want %d", got, defaultMaxPendingPerTenant)
	}
}

// backlog_full, its details and Retry-After are documented in the API
// reference and the OpenAPI spec of POST .../sprouts/actions.
func TestBacklogFullDocumented(t *testing.T) {
	spec, err := os.ReadFile("../../docs/api/saasapi-openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	ref, err := os.ReadFile("../../docs/api/saasapi.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"backlog_full", "Retry-After", "BacklogFullError", "RateLimitedError", "RateLimitedOrBacklogFull", "enum: [rate_limited]", "enum: [backlog_full]",
		"SAASAPI_ACTION_MAX_PENDING_PER_TENANT", "required: [pending, limit, requested, available]"} {
		if !strings.Contains(string(spec), want) {
			t.Errorf("the OpenAPI spec lacks %q", want)
		}
	}
	for _, want := range []string{"`backlog_full`", "Retry-After: 60", "`SAASAPI_ACTION_MAX_PENDING_PER_TENANT` | `2000`",
		"\"pending\"", "\"limit\"", "\"requested\"", "\"available\"", "soft limit", "expired_not_sent"} {
		if !strings.Contains(string(ref), want) {
			t.Errorf("docs/api/saasapi.md lacks %q", want)
		}
	}
}
