package saasapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/props"
)

// newUpdateTestDB is newTestDBWithFarmer with an empty version catalog
// (see newFleetTestDB for why it's cleared) and the dispatch feature flag
// on for the duration of the test.
func newUpdateTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	gdb := newTestDBWithFarmer(t)
	empty := func() { gdb.Where("1 = 1").Delete(&FleetVersion{}) }
	empty()
	t.Cleanup(empty)
	// internal/props' table, where farmer's facts listener stores what each
	// sprout reports (fleet_sprout_facts.go reads it);
	// TestFarmerSproutFactsColumnContract pins the columns read.
	if err := gdb.Exec(`CREATE TABLE IF NOT EXISTS farmer.props (
		tenant_id TEXT NOT NULL,
		sprout_id TEXT NOT NULL,
		name      TEXT NOT NULL,
		value     TEXT,
		static    BOOLEAN NOT NULL DEFAULT 0,
		expiry    DATETIME NOT NULL,
		PRIMARY KEY (tenant_id, sprout_id, name)
	)`).Error; err != nil {
		t.Fatalf("creating farmer.props: %v", err)
	}
	enableFleetUpdateDispatch(t)
	withTestFleetKeys(t)
	return gdb
}

// reportFact stores one fact for tenantID's sproutID the way farmer's facts
// listener does (props.SetPropForTenant), written now: expiry is the write
// time plus props.DefaultPropTTL (TestPropWriteTimeMatchesProps).
func reportFact(gdb *gorm.DB, tenantID, sproutID, name, value string) error {
	return reportFactWrittenAt(gdb, tenantID, sproutID, name, value, time.Now())
}

// reportFactWrittenAt is reportFact as if farmer had written the row at
// written.
func reportFactWrittenAt(gdb *gorm.DB, tenantID, sproutID, name, value string, written time.Time) error {
	return gdb.Exec(`INSERT INTO farmer.props (tenant_id, sprout_id, name, value, static, expiry)
VALUES (?, ?, ?, ?, 0, ?)
ON CONFLICT (tenant_id, sprout_id, name) DO UPDATE SET value = excluded.value, static = excluded.static, expiry = excluded.expiry`,
		tenantID, sproutID, name, value, written.Add(props.DefaultPropTTL).UTC()).Error
}

// mustReportFacts stores a sprout's os, arch and (if set) sprout_version,
// written an hour ago: long expired, which planning ignores, and long
// before any dispatch in the test, so never proof of an update.
func mustReportFacts(t *testing.T, gdb *gorm.DB, tenantID, sproutID, osName, arch, version string) {
	t.Helper()
	facts := map[string]string{farmerPropOS: osName, farmerPropArch: arch}
	if version != "" {
		facts[farmerPropSproutVersion] = version
	}
	for name, value := range facts {
		if err := reportFactWrittenAt(gdb, tenantID, sproutID, name, value, time.Now().Add(-time.Hour)); err != nil {
			t.Fatalf("reporting %s for %s/%s: %v", name, tenantID, sproutID, err)
		}
	}
}

// oldSproutVersion is what mustUpdateFleet's sprouts report before they
// are updated.
const oldSproutVersion = "v2.4.0"

func enableFleetUpdateDispatch(t *testing.T) {
	t.Helper()
	SetFleetUpdateDispatchEnabled(true)
	t.Cleanup(func() { SetFleetUpdateDispatchEnabled(false) })
}

// fastRollouts makes wave deadlines and polling short, and waits for any
// rollout goroutines before the test's database is torn down.
func fastRollouts(t *testing.T, waveTimeout time.Duration) {
	t.Helper()
	prevTimeout, prevPoll := rolloutWaveTimeout, rolloutPollInterval
	rolloutWaveTimeout, rolloutPollInterval = waveTimeout, 5*time.Millisecond
	t.Cleanup(func() {
		actionDispatches.Wait()
		rolloutWaveTimeout, rolloutPollInterval = prevTimeout, prevPoll
	})
}

func mustApprove(t *testing.T, gdb *gorm.DB, tenantID, version string, window ...time.Time) {
	t.Helper()
	p := TenantUpdatePolicy{TenantID: tenantID, ApprovedVersion: &version}
	if len(window) == 2 {
		p.RolloutWindowStart, p.RolloutWindowEnd = &window[0], &window[1]
	}
	if err := gdb.Save(&p).Error; err != nil {
		t.Fatalf("saving policy: %v", err)
	}
}

// mustUpdateFleet sets up tenant tid with n accepted, linked sprouts
// (upd-01 → asset u1, ...), each reporting linux/amd64 and
// oldSproutVersion, and returns the asset ids in order.
func mustUpdateFleet(t *testing.T, gdb *gorm.DB, tid string, n int) []string {
	t.Helper()
	assets := make([]string, n)
	for i := range n {
		sprout := fmt.Sprintf("upd-%02d", i+1)
		assets[i] = fmt.Sprintf("u%d-%s", i+1, tid)
		mustInsertFarmerSprout(t, gdb, tid, sprout, "accepted")
		mustLinkAsset(t, tid, sprout, assets[i])
		mustReportFacts(t, gdb, tid, sprout, "linux", "amd64", oldSproutVersion)
	}
	return assets
}

func postUpdates(t *testing.T, tenantID string, body any) (int, map[string]any) {
	t.Helper()
	w := doRequest(t, CreateFleetUpdateBatch, "POST", "/v1/tenants/"+tenantID+"/sprouts/updates",
		map[string]string{"tenant_id": tenantID}, body)
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp
}

func getUpdateBatch(t *testing.T, tenantID, batchID string) (int, actionBatchResponse) {
	t.Helper()
	w := doRequest(t, GetFleetUpdateBatch, "GET", "/v1/tenants/"+tenantID+"/sprouts/updates/"+batchID,
		map[string]string{"tenant_id": tenantID, "batch_id": batchID}, nil)
	var resp actionBatchResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp
}

// jidFor is the jid the fake farmer answers a self_update for sprout with.
func jidFor(sprout string) string {
	return "00000000-0000-0000-0000-0000000000" + strings.TrimPrefix(sprout, "upd-")
}

// waveReader is a JobStatusReader whose answer for each job is decided by
// outcome, and which records how many farmer requests had been seen each
// time it was asked, so tests can check waves never overlap.
//
// With reconnect set, a sprout whose job it reports succeeded then
// "restarts on the new release": it reports reconnect as its
// sprout_version in gdb's farmer.props, which the rollout sees on its next
// poll. Without it, a succeeded job is all the rollout ever sees.
type waveReader struct {
	mu        sync.Mutex
	farmer    *fakeFarmer
	outcome   func(ref JobRef, call int) (JobOutcome, bool)
	gdb       *gorm.DB
	reconnect string
	calls     int
	seenAtOK  []int
	tenants   map[string]bool
}

func (r *waveReader) JobOutcomes(_ context.Context, tenantID string, jobs []JobRef) (map[JobRef]JobOutcome, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.tenants == nil {
		r.tenants = map[string]bool{}
	}
	r.tenants[tenantID] = true
	if r.farmer != nil {
		reqs, _ := r.farmer.seen()
		r.seenAtOK = append(r.seenAtOK, len(reqs))
	}
	out := map[JobRef]JobOutcome{}
	for _, j := range jobs {
		if o, ok := r.outcome(j, r.calls); ok {
			out[j] = o
			if o == JobOutcomeSucceeded && r.reconnect != "" {
				if err := reportFact(r.gdb, tenantID, j.SproutID, farmerPropSproutVersion, r.reconnect); err != nil {
					return nil, err
				}
			}
		}
	}
	return out, nil
}

func installReader(t *testing.T, r JobStatusReader) {
	t.Helper()
	SetJobStatusReader(r)
	t.Cleanup(func() { SetJobStatusReader(farmerJobStatusReader{}) })
}

func TestFleetUpdateDispatchDisabledByDefault(t *testing.T) {
	if fleetUpdateDispatchEnabled {
		t.Fatal("fleet update dispatch is enabled by default")
	}
	gdb := newTestDBWithFarmer(t)
	tid := mustCreateActiveTenant(t, gdb)
	if code, resp := postUpdates(t, tid, map[string]any{"asset_ids": []string{"a1"}, "target_version": "v1"}); code != 404 || resp["error"] != "not_found" {
		t.Fatalf("POST with the flag off: %d %v", code, resp)
	}
	if code, _ := getUpdateBatch(t, tid, "b_x"); code != 404 {
		t.Fatalf("GET with the flag off: %d", code)
	}
	var n int64
	gdb.Model(&AssetActionBatch{}).Where("tenant_id = ?", tid).Count(&n)
	if n != 0 {
		t.Fatalf("%d batches written with the flag off", n)
	}
}

func TestRouterFleetUpdateDispatchRoutesWhenEnabled(t *testing.T) {
	gdb := newUpdateTestDB(t)
	auth := newTestAuthEnv(t)
	a := mustCreateActiveTenant(t, gdb)
	b := mustCreateActiveTenant(t, gdb)
	mux := NewRouter()

	serve := func(method, path, body, tokenTenant string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		auth.setAuthHeaders(r, tokenTenant)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	// Registered: an unknown version is the handler's 400, not the mux's 404.
	if w := serve("POST", "/v1/tenants/"+a+"/sprouts/updates", `{"asset_ids":["x"],"target_version":"v9"}`, a); w.Code != 400 ||
		!strings.Contains(w.Body.String(), "unknown_version") {
		t.Fatalf("POST own tenant: %d %s", w.Code, w.Body.String())
	}
	if w := serve("GET", "/v1/tenants/"+a+"/sprouts/updates/b_nope", "", a); w.Code != 404 ||
		!strings.Contains(w.Body.String(), "batch_not_found") {
		t.Fatalf("GET own tenant: %d %s", w.Code, w.Body.String())
	}
	// Still behind Auth's organization check.
	if w := serve("POST", "/v1/tenants/"+a+"/sprouts/updates", `{}`, b); w.Code != 403 {
		t.Fatalf("POST another tenant: %d", w.Code)
	}
	if w := serve("GET", "/v1/tenants/"+a+"/sprouts/updates/b_nope", "", b); w.Code != 403 {
		t.Fatalf("GET another tenant: %d", w.Code)
	}
	unauth := httptest.NewRecorder()
	mux.ServeHTTP(unauth, httptest.NewRequest("POST", "/v1/tenants/"+a+"/sprouts/updates", strings.NewReader(`{}`)))
	if unauth.Code != 401 {
		t.Fatalf("unauthenticated POST: %d", unauth.Code)
	}
}

func TestCreateFleetUpdateBatch_Validation(t *testing.T) {
	gdb := newUpdateTestDB(t)
	tid := mustCreateActiveTenant(t, gdb)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	mustPublishVersion(t, gdb, "v2.5.0", time.Now())
	mustApprove(t, gdb, tid, "v2.4.1")

	ok := func(extra map[string]any) map[string]any {
		body := map[string]any{"asset_ids": []string{"a1"}, "target_version": "v2.4.1"}
		for k, v := range extra {
			body[k] = v
		}
		return body
	}
	cases := []struct {
		name     string
		body     any
		status   int
		wantCode string
	}{
		{"no asset ids", ok(map[string]any{"asset_ids": []string{}}), 400, "invalid_request"},
		{"too many asset ids", ok(map[string]any{"asset_ids": make([]string, maxAssetIDsPerLookup+1)}), 400, "too_many_asset_ids"},
		{"missing target_version", ok(map[string]any{"target_version": " "}), 400, "invalid_request"},
		{"long target_version", ok(map[string]any{"target_version": strings.Repeat("v", maxFleetVersionLen+1)}), 400, "invalid_request"},
		{"batch_size 0", ok(map[string]any{"batch_size": 0}), 400, "invalid_request"},
		{"batch_size over the cap", ok(map[string]any{"batch_size": maxUpdateBatchSize + 1}), 400, "invalid_request"},
		{"probe gate not available", ok(map[string]any{"gate": "probe"}), 400, "unsupported_gate"},
		{"unknown gate", ok(map[string]any{"gate": "yolo"}), 400, "unsupported_gate"},
		{"artifact_url smuggled", ok(map[string]any{"artifact_url": "https://evil.test/sprout"}), 400, "invalid_request"},
		{"action smuggled", ok(map[string]any{"action": cmdAction("ls")}), 400, "invalid_request"},
		{"tenant smuggled", ok(map[string]any{"tenant_id": "t_other"}), 400, "invalid_request"},
		{"not in the catalog", ok(map[string]any{"target_version": "v9.9.9"}), 400, "unknown_version"},
		{"in the catalog but not approved", ok(map[string]any{"target_version": "v2.5.0"}), 409, "version_not_approved"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, resp := postUpdates(t, tid, tc.body)
			if code != tc.status || resp["error"] != tc.wantCode {
				t.Fatalf("got %d %v, want %d %s", code, resp, tc.status, tc.wantCode)
			}
		})
	}

	// No policy row at all: nothing is approved.
	other := mustCreateActiveTenant(t, gdb)
	if code, resp := postUpdates(t, other, ok(nil)); code != 409 || resp["error"] != "version_not_approved" {
		t.Fatalf("tenant without a policy: %d %v", code, resp)
	}

	// Outside the rollout window, on either side.
	now := time.Now().UTC()
	windowed := mustCreateActiveTenant(t, gdb)
	for _, w := range [][2]time.Time{{now.Add(time.Hour), now.Add(2 * time.Hour)}, {now.Add(-2 * time.Hour), now.Add(-time.Hour)}} {
		mustApprove(t, gdb, windowed, "v2.4.1", w[0], w[1])
		if code, resp := postUpdates(t, windowed, ok(nil)); code != 409 || resp["error"] != "outside_rollout_window" {
			t.Fatalf("window %v: %d %v", w, code, resp)
		}
	}

	// Not active.
	pending, _ := newID("t_")
	gdb.Create(&Tenant{ID: pending, Name: "p", Status: TenantStatusPending})
	if code, resp := postUpdates(t, pending, ok(nil)); code != 409 || resp["error"] != "tenant_not_active" {
		t.Fatalf("pending tenant: %d %v", code, resp)
	}

	// Scoped to this test's tenants: the sqlite test database is shared
	// across the package's tests.
	var n int64
	gdb.Model(&AssetActionBatch{}).Where("tenant_id IN ?", []string{tid, other, windowed, pending}).Count(&n)
	if n != 0 {
		t.Fatalf("%d batches written for rejected requests", n)
	}
}

func TestCreateFleetUpdateBatch_UnusableCatalogEntry(t *testing.T) {
	gdb := newUpdateTestDB(t)
	tid := mustCreateActiveTenant(t, gdb)
	// Rows that could only be in the table by a write that skipped
	// registration: a malformed checksum, and a file name with a path.
	for _, v := range []FleetVersion{
		{ID: "fv_sum", Version: "v8.0.1", OS: "linux", Arch: "amd64", PackageType: "deb", FileName: "imas-sprout_8.0.1_amd64.deb",
			ChecksumSHA256: "abc", MinSproutVersion: "v0.0.0", Signature: "v1:" + strings.Repeat("A", 86) + "=="},
		{ID: "fv_path", Version: "v8.0.2", OS: "linux", Arch: "amd64", PackageType: "deb", FileName: "../imas-sprout.deb",
			ChecksumSHA256: strings.Repeat("ab", 32), MinSproutVersion: "v0.0.0", Signature: "v1:" + strings.Repeat("A", 86) + "=="},
	} {
		v.ReleasedAt = time.Now()
		if err := gdb.Create(&v).Error; err != nil {
			t.Fatal(err)
		}
		mustApprove(t, gdb, tid, v.Version)
		code, resp := postUpdates(t, tid, map[string]any{"asset_ids": []string{"a1"}, "target_version": v.Version})
		if code != 500 || resp["error"] != "internal_error" || strings.Contains(fmt.Sprint(resp), "imas-sprout") {
			t.Fatalf("%s: %d %v", v.Version, code, resp)
		}
	}
}

// The main path, with the default job_status gate: waves of batch_size go
// out in request order, each only after the previous one's jobs have all
// succeeded, carrying only the target version (each sprout resolves its
// own OS/arch manifest).
func TestFleetUpdate_JobStatusGateRollsOutInWaves(t *testing.T) {
	gdb := newUpdateTestDB(t)
	fastRollouts(t, 5*time.Second)
	ns := startTestBus(t)
	connectSaaSBus(t, ns)
	tid := mustCreateActiveTenant(t, gdb)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	mustPublishVersionFor(t, gdb, "v2.4.1", "windows", "amd64", time.Now())
	mustApprove(t, gdb, tid, "v2.4.1")
	assets := mustUpdateFleet(t, gdb, tid, 7)

	farmer := startFakeFarmer(t, ns, func(req controlplane.SproutActionRequest) any {
		return controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID,
			Status: controlplane.StatusDispatched, JID: jidFor(req.SproutID)}
	})
	// Each job reads as running the first time it's asked about, then
	// succeeded: every wave has to be polled at least twice.
	asked := map[JobRef]bool{}
	reader := &waveReader{farmer: farmer, gdb: gdb, reconnect: "v2.4.1", outcome: func(ref JobRef, _ int) (JobOutcome, bool) {
		if !asked[ref] {
			asked[ref] = true
			return JobOutcomeRunning, true
		}
		return JobOutcomeSucceeded, true
	}}
	installReader(t, reader)

	code, resp := postUpdates(t, tid, map[string]any{"asset_ids": assets, "target_version": "v2.4.1", "batch_size": 3})
	if code != 202 {
		t.Fatalf("POST: %d %v", code, resp)
	}
	batchID := resp["batch_id"].(string)
	actionDispatches.Wait()

	reqs, _ := farmer.seen()
	if len(reqs) != 7 {
		t.Fatalf("farmer got %d requests, want 7", len(reqs))
	}
	for i, req := range reqs {
		var p farmerSelfUpdate
		dec := json.NewDecoder(strings.NewReader(string(req.Action.Params)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&p); err != nil || req.Action.Type != controlplane.ActionSelfUpdate || req.TenantID != tid ||
			p != (farmerSelfUpdate{Version: "v2.4.1"}) {
			t.Fatalf("request %d = %+v %s (%v)", i, req, req.Action.Params, err)
		}
	}
	// Waves never overlap: the reader only ever saw 3, 6 or 7 requests
	// sent — never a count in between, which would mean the next wave went
	// out before this one passed.
	for _, n := range reader.seenAtOK {
		if n != 3 && n != 6 && n != 7 {
			t.Fatalf("reader was asked with %d requests sent (all: %v)", n, reader.seenAtOK)
		}
	}
	if len(reader.tenants) != 1 || !reader.tenants[tid] {
		t.Fatalf("reader asked about tenants %v", reader.tenants)
	}

	code, got := getUpdateBatch(t, tid, batchID)
	if code != 200 || got.Status != actionBatchCompleted || got.ActionType != controlplane.ActionSelfUpdate || len(got.Items) != 7 {
		t.Fatalf("GET: %d %+v", code, got)
	}
	if got.Rollout == nil || *got.Rollout != (rolloutResponse{TargetVersion: "v2.4.1", BatchSize: 3, Gate: gateJobStatus}) {
		t.Fatalf("rollout = %+v", got.Rollout)
	}
	for _, it := range got.Items {
		if it.Status != ActionItemSucceeded || it.JID == "" {
			t.Fatalf("item = %+v", it)
		}
	}
	if body, _ := json.Marshal(got); strings.Contains(string(body), "imas-sprout_") || strings.Contains(string(body), "signature") {
		t.Fatalf("GET leaks catalog details: %s", body)
	}
}

func TestFleetUpdate_Defaults(t *testing.T) {
	gdb := newUpdateTestDB(t)
	tid := mustCreateActiveTenant(t, gdb)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	mustApprove(t, gdb, tid, "v2.4.1")
	SetBus(nil) // nothing is sent: this test only looks at the stored batch
	code, resp := postUpdates(t, tid, map[string]any{"asset_ids": []string{"a1"}, "target_version": "v2.4.1"})
	actionDispatches.Wait()
	if code != 202 {
		t.Fatalf("POST: %d %v", code, resp)
	}
	var batch AssetActionBatch
	gdb.First(&batch, "id = ?", resp["batch_id"])
	if batch.RolloutBatchSize != defaultUpdateBatchSize || batch.RolloutGate != gateJobStatus {
		t.Fatalf("defaults = %d/%s", batch.RolloutBatchSize, batch.RolloutGate)
	}
	// Smaller and stricter than a §1.5 batch, which sends everything at
	// once without a gate.
	if defaultUpdateBatchSize >= maxAssetIDsPerLookup || maxUpdateBatchSize >= maxAssetIDsPerLookup {
		t.Fatalf("update batch sizes %d/%d are not below §1.5's %d", defaultUpdateBatchSize, maxUpdateBatchSize, maxAssetIDsPerLookup)
	}
}

// One failed job in a wave halts the rollout: no later wave is sent, and
// every unsent item is failed with rollout_halted.
func TestFleetUpdate_FailedWaveHaltsRollout(t *testing.T) {
	gdb := newUpdateTestDB(t)
	fastRollouts(t, 5*time.Second)
	ns := startTestBus(t)
	connectSaaSBus(t, ns)
	tid := mustCreateActiveTenant(t, gdb)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	mustApprove(t, gdb, tid, "v2.4.1")
	assets := mustUpdateFleet(t, gdb, tid, 5)
	farmer := startFakeFarmer(t, ns, func(req controlplane.SproutActionRequest) any {
		return controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID,
			Status: controlplane.StatusDispatched, JID: jidFor(req.SproutID)}
	})
	installReader(t, &waveReader{farmer: farmer, gdb: gdb, reconnect: "v2.4.1", outcome: func(ref JobRef, _ int) (JobOutcome, bool) {
		if ref.SproutID == "upd-02" {
			return JobOutcomeFailed, true
		}
		return JobOutcomeSucceeded, true
	}})

	_, resp := postUpdates(t, tid, map[string]any{"asset_ids": assets, "target_version": "v2.4.1", "batch_size": 2})
	actionDispatches.Wait()
	if reqs, _ := farmer.seen(); len(reqs) != 2 {
		t.Fatalf("farmer got %d requests, want only the first wave's 2", len(reqs))
	}
	_, got := getUpdateBatch(t, tid, resp["batch_id"].(string))
	want := []struct {
		status AssetActionItemStatus
		code   string
	}{
		{ActionItemSucceeded, ""}, {ActionItemFailed, errCodeJobFailed},
		{ActionItemFailed, errCodeRolloutHalted}, {ActionItemFailed, errCodeRolloutHalted}, {ActionItemFailed, errCodeRolloutHalted},
	}
	for i, it := range got.Items {
		if it.Status != want[i].status || it.Error != want[i].code || (it.Error != "" && it.Message != actionErrorMessage(it.Error)) {
			t.Errorf("item %d = %+v, want %s %s", i, it, want[i].status, want[i].code)
		}
	}
	if got.Status != actionBatchCompleted {
		t.Fatalf("batch = %s, want completed", got.Status)
	}
}

// An expired job (farmer's reconcile window) is terminal: its item fails
// with job_expired and the rollout halts, rather than waiting on a job
// farmer will never record.
func TestFleetUpdate_ExpiredJobHaltsRollout(t *testing.T) {
	gdb := newUpdateTestDB(t)
	fastRollouts(t, 5*time.Second)
	ns := startTestBus(t)
	connectSaaSBus(t, ns)
	tid := mustCreateActiveTenant(t, gdb)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	mustApprove(t, gdb, tid, "v2.4.1")
	assets := mustUpdateFleet(t, gdb, tid, 5)
	farmer := startFakeFarmer(t, ns, func(req controlplane.SproutActionRequest) any {
		return controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID,
			Status: controlplane.StatusDispatched, JID: jidFor(req.SproutID)}
	})
	installReader(t, &waveReader{farmer: farmer, gdb: gdb, reconnect: "v2.4.1", outcome: func(ref JobRef, _ int) (JobOutcome, bool) {
		if ref.SproutID == "upd-02" {
			return JobOutcomeExpired, true
		}
		return JobOutcomeSucceeded, true
	}})

	_, resp := postUpdates(t, tid, map[string]any{"asset_ids": assets, "target_version": "v2.4.1", "batch_size": 2})
	actionDispatches.Wait()
	if reqs, _ := farmer.seen(); len(reqs) != 2 {
		t.Fatalf("farmer got %d requests, want only the first wave's 2", len(reqs))
	}
	_, got := getUpdateBatch(t, tid, resp["batch_id"].(string))
	want := []struct {
		status AssetActionItemStatus
		code   string
	}{
		{ActionItemSucceeded, ""}, {ActionItemFailed, errCodeJobExpired},
		{ActionItemFailed, errCodeRolloutHalted}, {ActionItemFailed, errCodeRolloutHalted}, {ActionItemFailed, errCodeRolloutHalted},
	}
	for i, it := range got.Items {
		if it.Status != want[i].status || it.Error != want[i].code || (it.Error != "" && it.Message != actionErrorMessage(it.Error)) {
			t.Errorf("item %d = %+v, want %s %s", i, it, want[i].status, want[i].code)
		}
	}
	if got.Status != actionBatchCompleted {
		t.Fatalf("batch = %s, want completed", got.Status)
	}
}

// A sprout that never reports its update's outcome is
// unresponsive_after_update, not failed, and halts the rollout.
func TestFleetUpdate_UnresponsiveAfterUpdate(t *testing.T) {
	gdb := newUpdateTestDB(t)
	fastRollouts(t, 50*time.Millisecond)
	ns := startTestBus(t)
	connectSaaSBus(t, ns)
	tid := mustCreateActiveTenant(t, gdb)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	mustApprove(t, gdb, tid, "v2.4.1")
	assets := mustUpdateFleet(t, gdb, tid, 3)
	farmer := startFakeFarmer(t, ns, func(req controlplane.SproutActionRequest) any {
		return controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID,
			Status: controlplane.StatusDispatched, JID: jidFor(req.SproutID)}
	})
	installReader(t, &waveReader{farmer: farmer, gdb: gdb, reconnect: "v2.4.1", outcome: func(ref JobRef, _ int) (JobOutcome, bool) {
		if ref.SproutID == "upd-01" {
			return JobOutcomeSucceeded, true
		}
		return "", false // upd-02 never shows up in farmer.job_status
	}})

	_, resp := postUpdates(t, tid, map[string]any{"asset_ids": assets, "target_version": "v2.4.1", "batch_size": 2})
	actionDispatches.Wait()
	_, got := getUpdateBatch(t, tid, resp["batch_id"].(string))
	items := itemsByAsset(got)
	if it := items[assets[0]]; it.Status != ActionItemSucceeded {
		t.Errorf("upd-01 = %+v", it)
	}
	if it := items[assets[1]]; it.Status != ActionItemUnresponsiveAfterUpdate || it.Error != errCodeUnresponsiveAfterUpdate ||
		it.Message != actionErrorMessage(errCodeUnresponsiveAfterUpdate) || it.JID != jidFor("upd-02") {
		t.Errorf("upd-02 = %+v", it)
	}
	if it := items[assets[2]]; it.Status != ActionItemFailed || it.Error != errCodeRolloutHalted {
		t.Errorf("upd-03 = %+v", it)
	}
	if got.Status != actionBatchCompleted {
		t.Fatalf("batch = %s, want completed (unresponsive is terminal)", got.Status)
	}
}

// Approval withdrawn, or the window closing, between waves stops the
// rollout before the next wave.
func TestFleetUpdate_PolicyRecheckedBeforeEachWave(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(gdb *gorm.DB, tid string)
		code   string
	}{
		{"approval withdrawn", func(gdb *gorm.DB, tid string) {
			gdb.Model(&TenantUpdatePolicy{}).Where("tenant_id = ?", tid).Update("approved_version", nil)
		}, errCodeApprovalWithdrawn},
		{"different version approved", func(gdb *gorm.DB, tid string) {
			gdb.Model(&TenantUpdatePolicy{}).Where("tenant_id = ?", tid).Update("approved_version", "v2.5.0")
		}, errCodeApprovalWithdrawn},
		{"window closed", func(gdb *gorm.DB, tid string) {
			now := time.Now().UTC()
			gdb.Model(&TenantUpdatePolicy{}).Where("tenant_id = ?", tid).
				Updates(map[string]any{"rollout_window_start": now.Add(-2 * time.Hour), "rollout_window_end": now.Add(-time.Hour)})
		}, errCodeRolloutWindowClosed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gdb := newUpdateTestDB(t)
			fastRollouts(t, 5*time.Second)
			ns := startTestBus(t)
			connectSaaSBus(t, ns)
			tid := mustCreateActiveTenant(t, gdb)
			mustPublishVersion(t, gdb, "v2.4.1", time.Now())
			mustPublishVersion(t, gdb, "v2.5.0", time.Now())
			mustApprove(t, gdb, tid, "v2.4.1")
			assets := mustUpdateFleet(t, gdb, tid, 4)
			farmer := startFakeFarmer(t, ns, func(req controlplane.SproutActionRequest) any {
				return controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID,
					Status: controlplane.StatusDispatched, JID: jidFor(req.SproutID)}
			})
			// The policy changes while the first wave is being waited on.
			installReader(t, &waveReader{farmer: farmer, gdb: gdb, reconnect: "v2.4.1", outcome: func(ref JobRef, call int) (JobOutcome, bool) {
				if call == 1 {
					tc.change(gdb, tid)
				}
				return JobOutcomeSucceeded, true
			}})

			_, resp := postUpdates(t, tid, map[string]any{"asset_ids": assets, "target_version": "v2.4.1", "batch_size": 2})
			actionDispatches.Wait()
			if reqs, _ := farmer.seen(); len(reqs) != 2 {
				t.Fatalf("farmer got %d requests, want 2", len(reqs))
			}
			_, got := getUpdateBatch(t, tid, resp["batch_id"].(string))
			for i, it := range got.Items {
				if i < 2 && it.Status != ActionItemSucceeded {
					t.Errorf("wave 1 item %+v", it)
				}
				if i >= 2 && (it.Status != ActionItemFailed || it.Error != tc.code) {
					t.Errorf("wave 2 item %+v, want failed %s", it, tc.code)
				}
			}
		})
	}
}

// The looser dispatch gate sends the next wave once farmer has accepted
// this one, without waiting for its sprouts to come back, and halts if
// farmer refuses one. Every item sent is still followed to an outcome:
// sprouts that reconnect on the target version succeed.
func TestFleetUpdate_DispatchGate(t *testing.T) {
	gdb := newUpdateTestDB(t)
	fastRollouts(t, 5*time.Second)
	ns := startTestBus(t)
	connectSaaSBus(t, ns)
	tid := mustCreateActiveTenant(t, gdb)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	mustApprove(t, gdb, tid, "v2.4.1")
	assets := mustUpdateFleet(t, gdb, tid, 5)
	farmer := startFakeFarmer(t, ns, func(req controlplane.SproutActionRequest) any {
		if req.SproutID == "upd-04" {
			return controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID,
				Status: controlplane.StatusFailed, ErrorCode: controlplane.ErrorSproutUnreachable}
		}
		return controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID,
			Status: controlplane.StatusDispatched, JID: jidFor(req.SproutID)}
	})
	// No job outcome is ever recorded; each sprout that took the update
	// reconnects on it.
	installReader(t, &waveReader{farmer: farmer, outcome: func(ref JobRef, _ int) (JobOutcome, bool) {
		_ = reportFact(gdb, tid, ref.SproutID, farmerPropSproutVersion, "v2.4.1")
		return "", false
	}})

	_, resp := postUpdates(t, tid, map[string]any{"asset_ids": assets, "target_version": "v2.4.1", "batch_size": 2, "gate": "dispatch"})
	actionDispatches.Wait()
	if reqs, _ := farmer.seen(); len(reqs) != 4 {
		t.Fatalf("farmer got %d requests, want 4 (waves 1 and 2)", len(reqs))
	}
	_, got := getUpdateBatch(t, tid, resp["batch_id"].(string))
	want := []struct {
		status AssetActionItemStatus
		code   string
	}{
		{ActionItemSucceeded, ""}, {ActionItemSucceeded, ""},
		{ActionItemSucceeded, ""}, {ActionItemFailed, string(controlplane.ErrorSproutUnreachable)},
		{ActionItemFailed, errCodeRolloutHalted},
	}
	for i, it := range got.Items {
		if it.Status != want[i].status || it.Error != want[i].code {
			t.Errorf("item %d = %+v, want %s %s", i, it, want[i].status, want[i].code)
		}
	}
}

// With the dispatch gate the waves don't wait for sprouts to come back,
// but a sprout that never does still ends unresponsive_after_update, not
// succeeded: farmer accepting the command is not the update landing.
func TestFleetUpdate_DispatchGateStillFollowsSprouts(t *testing.T) {
	gdb := newUpdateTestDB(t)
	fastRollouts(t, 100*time.Millisecond)
	ns := startTestBus(t)
	connectSaaSBus(t, ns)
	tid := mustCreateActiveTenant(t, gdb)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	mustApprove(t, gdb, tid, "v2.4.1")
	assets := mustUpdateFleet(t, gdb, tid, 3)
	farmer := startFakeFarmer(t, ns, func(req controlplane.SproutActionRequest) any {
		return controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID,
			Status: controlplane.StatusDispatched, JID: jidFor(req.SproutID)}
	})
	// Every job succeeds, and no sprout ever reports the new version.
	installReader(t, &waveReader{farmer: farmer, outcome: func(JobRef, int) (JobOutcome, bool) { return JobOutcomeSucceeded, true }})

	_, resp := postUpdates(t, tid, map[string]any{"asset_ids": assets, "target_version": "v2.4.1", "batch_size": 1, "gate": "dispatch"})
	actionDispatches.Wait()
	if reqs, _ := farmer.seen(); len(reqs) != 3 {
		t.Fatalf("farmer got %d requests, want 3: the dispatch gate doesn't wait for sprouts", len(reqs))
	}
	_, got := getUpdateBatch(t, tid, resp["batch_id"].(string))
	for _, it := range got.Items {
		if it.Status != ActionItemUnresponsiveAfterUpdate || it.Error != errCodeUnresponsiveAfterUpdate {
			t.Errorf("item = %+v, want unresponsive_after_update", it)
		}
	}
	if got.Status != actionBatchCompleted {
		t.Fatalf("batch = %s, want completed", got.Status)
	}
}

// With the dispatch gate, no wave goes out once an item already sent has
// failed.
func TestFleetUpdate_DispatchGateHaltsOnEarlierFailure(t *testing.T) {
	gdb := newUpdateTestDB(t)
	fastRollouts(t, 5*time.Second)
	ns := startTestBus(t)
	connectSaaSBus(t, ns)
	tid := mustCreateActiveTenant(t, gdb)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	mustApprove(t, gdb, tid, "v2.4.1")
	assets := mustUpdateFleet(t, gdb, tid, 3)
	farmer := startFakeFarmer(t, ns, func(req controlplane.SproutActionRequest) any {
		return controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID,
			Status: controlplane.StatusDispatched, JID: jidFor(req.SproutID)}
	})
	installReader(t, &waveReader{farmer: farmer, outcome: func(JobRef, int) (JobOutcome, bool) { return JobOutcomeFailed, true }})

	_, resp := postUpdates(t, tid, map[string]any{"asset_ids": assets, "target_version": "v2.4.1", "batch_size": 1, "gate": "dispatch"})
	actionDispatches.Wait()
	if reqs, _ := farmer.seen(); len(reqs) != 1 {
		t.Fatalf("farmer got %d requests, want only wave 1's", len(reqs))
	}
	_, got := getUpdateBatch(t, tid, resp["batch_id"].(string))
	if it := got.Items[0]; it.Status != ActionItemFailed || it.Error != errCodeJobFailed {
		t.Errorf("wave 1 item = %+v, want failed job_failed", it)
	}
	for _, it := range got.Items[1:] {
		if it.Status != ActionItemFailed || it.Error != errCodeRolloutHalted {
			t.Errorf("unsent item = %+v, want failed rollout_halted", it)
		}
	}
}

// The core of the health gate (design doc §2.3): a wave whose jobs all
// succeed, but whose sprouts never reconnect and report the new version,
// doesn't pass. Its items end unresponsive_after_update and the next wave
// is never sent.
func TestFleetUpdate_JobSuccessAloneDoesNotPassWave(t *testing.T) {
	gdb := newUpdateTestDB(t)
	fastRollouts(t, 100*time.Millisecond)
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
	// upd-01 comes back on the new version; upd-02's job succeeds, but it
	// keeps reporting the old one (say, the restart never happened).
	installReader(t, &waveReader{farmer: farmer, outcome: func(ref JobRef, _ int) (JobOutcome, bool) {
		if ref.SproutID == "upd-01" {
			_ = reportFact(gdb, tid, ref.SproutID, farmerPropSproutVersion, "v2.4.1")
		}
		return JobOutcomeSucceeded, true
	}})

	_, resp := postUpdates(t, tid, map[string]any{"asset_ids": assets, "target_version": "v2.4.1", "batch_size": 2})
	actionDispatches.Wait()
	if reqs, _ := farmer.seen(); len(reqs) != 2 {
		t.Fatalf("farmer got %d requests, want only wave 1's 2", len(reqs))
	}
	_, got := getUpdateBatch(t, tid, resp["batch_id"].(string))
	want := []struct {
		status AssetActionItemStatus
		code   string
	}{
		{ActionItemSucceeded, ""}, {ActionItemUnresponsiveAfterUpdate, errCodeUnresponsiveAfterUpdate},
		{ActionItemFailed, errCodeRolloutHalted}, {ActionItemFailed, errCodeRolloutHalted},
	}
	for i, it := range got.Items {
		if it.Status != want[i].status || it.Error != want[i].code {
			t.Errorf("item %d = %+v, want %s %s", i, it, want[i].status, want[i].code)
		}
	}
}

// A tenant has one update rollout in progress at a time: a second POST is
// 409 update_in_progress, naming the first, until every item of the first
// has an outcome. Another tenant (with the same sprout_ids) is unaffected.
func TestFleetUpdate_OneRolloutPerTenant(t *testing.T) {
	gdb := newUpdateTestDB(t)
	fastRollouts(t, 200*time.Millisecond)
	ns := startTestBus(t)
	connectSaaSBus(t, ns)
	tid := mustCreateActiveTenant(t, gdb)
	other := mustCreateActiveTenant(t, gdb)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	mustApprove(t, gdb, tid, "v2.4.1")
	mustApprove(t, gdb, other, "v2.4.1")
	assets := mustUpdateFleet(t, gdb, tid, 2)
	otherAssets := mustUpdateFleet(t, gdb, other, 1) // also upd-01
	startFakeFarmer(t, ns, func(req controlplane.SproutActionRequest) any {
		return controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID,
			Status: controlplane.StatusDispatched, JID: jidFor(req.SproutID)}
	})
	installReader(t, &waveReader{farmer: nil, outcome: func(JobRef, int) (JobOutcome, bool) { return "", false }})

	var before TenantUpdatePolicy
	gdb.First(&before, "tenant_id = ?", tid)

	code, first := postUpdates(t, tid, map[string]any{"asset_ids": assets[:1], "target_version": "v2.4.1"})
	if code != 202 {
		t.Fatalf("first POST: %d %v", code, first)
	}
	// The first rollout's sprout never comes back, so it's in progress
	// until its wave's deadline.
	code, second := postUpdates(t, tid, map[string]any{"asset_ids": assets[1:], "target_version": "v2.4.1"})
	details, _ := second["details"].(map[string]any)
	if code != 409 || second["error"] != "update_in_progress" || details["batch_id"] != first["batch_id"] {
		t.Fatalf("second POST: %d %v", code, second)
	}
	if code, resp := postUpdates(t, other, map[string]any{"asset_ids": otherAssets, "target_version": "v2.4.1"}); code != 202 {
		t.Fatalf("other tenant's POST: %d %v", code, resp)
	}

	// The claim wrote the policy row (so Galera would certify two claims
	// against each other), in rollout_claimed_at. updated_at, which says
	// when the policy last changed, didn't move.
	var after TenantUpdatePolicy
	gdb.First(&after, "tenant_id = ?", tid)
	if before.RolloutClaimedAt != nil || after.RolloutClaimedAt == nil || !after.UpdatedAt.Equal(before.UpdatedAt) ||
		*after.ApprovedVersion != "v2.4.1" {
		t.Fatalf("policy after claim = %+v (before %+v)", after, before)
	}

	actionDispatches.Wait()
	if _, got := getUpdateBatch(t, tid, first["batch_id"].(string)); got.Items[0].Status != ActionItemUnresponsiveAfterUpdate {
		t.Fatalf("first rollout's item = %+v", got.Items[0])
	}
	// Once the first rollout is over, the tenant can start another.
	if code, resp := postUpdates(t, tid, map[string]any{"asset_ids": assets[1:], "target_version": "v2.4.1"}); code != 202 {
		t.Fatalf("POST after the first rollout ended: %d %v", code, resp)
	}
	var again TenantUpdatePolicy
	gdb.First(&again, "tenant_id = ?", tid)
	if again.RolloutClaimedAt == nil || !again.RolloutClaimedAt.After(*after.RolloutClaimedAt) || !again.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("policy after the second claim = %+v (after the first %+v)", again, after)
	}
}

// Concurrent POSTs for one tenant: exactly one creates a rollout. The
// in-progress check runs inside the transaction that writes the batch,
// so there is no window between checking and acting.
func TestFleetUpdate_ConcurrentPostsClaimOnce(t *testing.T) {
	gdb := newUpdateTestDB(t)
	tid := mustCreateActiveTenant(t, gdb)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	mustApprove(t, gdb, tid, "v2.4.1")
	assets := mustUpdateFleet(t, gdb, tid, 1)
	SetBus(nil) // items stay queued: the first rollout stays in progress
	var before TenantUpdatePolicy
	gdb.First(&before, "tenant_id = ?", tid)

	const n = 8
	codes := make(chan int, n)
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, _ := postUpdates(t, tid, map[string]any{"asset_ids": assets, "target_version": "v2.4.1"})
			codes <- code
		}()
	}
	wg.Wait()
	actionDispatches.Wait()
	close(codes)
	count := map[int]int{}
	for c := range codes {
		count[c]++
	}
	if count[202] != 1 || count[409] != n-1 {
		t.Fatalf("status counts = %v, want one 202 and %d 409s", count, n-1)
	}
	var batches int64
	gdb.Model(&AssetActionBatch{}).Where("tenant_id = ? AND action_type = ?", tid, controlplane.ActionSelfUpdate).Count(&batches)
	if batches != 1 {
		t.Fatalf("%d update batches written, want 1", batches)
	}
	// The one claim that won is in rollout_claimed_at, not updated_at.
	var after TenantUpdatePolicy
	gdb.First(&after, "tenant_id = ?", tid)
	if after.RolloutClaimedAt == nil || !after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("policy after the claims = %+v (before %+v)", after, before)
	}
}

// claimRollout repeats the policy checks against the row it has locked,
// so a policy that changed after the handler's early check still refuses
// the rollout, and nothing is written.
func TestClaimRolloutRechecksPolicy(t *testing.T) {
	gdb := newUpdateTestDB(t)
	now := time.Now()
	for _, tc := range []struct {
		name  string
		setup func(tid string)
		code  string
	}{
		{"no policy", func(string) {}, errCodeApprovalWithdrawn},
		{"other version approved", func(tid string) { mustApprove(t, gdb, tid, "v2.5.0") }, errCodeApprovalWithdrawn},
		{"window closed", func(tid string) { mustApprove(t, gdb, tid, "v2.4.1", now.Add(-2*time.Hour), now.Add(-time.Hour)) }, errCodeRolloutWindowClosed},
		{"revoked", func(tid string) {
			mustApprove(t, gdb, tid, "v2.4.1")
			gdb.Model(&FleetVersion{}).Where("version = ?", "v2.4.1").Update("revoked", true)
		}, errCodeVersionRevoked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gdb.Where("1 = 1").Delete(&FleetVersion{})
			mustPublishVersion(t, gdb, "v2.4.1", now)
			mustPublishVersion(t, gdb, "v2.5.0", now)
			tid := mustCreateActiveTenant(t, gdb)
			tc.setup(tid)
			err := gdb.Transaction(claimRollout(tid, "v2.4.1", now))
			var refused rolloutRefused
			if !errors.As(err, &refused) || refused.code != tc.code {
				t.Fatalf("claim: %v, want refusal %s", err, tc.code)
			}
		})
	}
}

func TestClaimTimestamp(t *testing.T) {
	base := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		now, prev, want time.Time
	}{
		{base.Add(time.Second), base, base.Add(time.Second)},
		{base.Add(1500 * time.Microsecond), base, base.Add(time.Millisecond)},
		// Same millisecond as the stored value, or behind it (clock skew
		// between pods): one millisecond past the stored value.
		{base.Add(300 * time.Microsecond), base, base.Add(time.Millisecond)},
		{base.Add(-time.Minute), base, base.Add(time.Millisecond)},
	} {
		if got := claimTimestamp(tc.now, tc.prev); !got.Equal(tc.want) {
			t.Errorf("claimTimestamp(%s, %s) = %s, want %s", tc.now, tc.prev, got, tc.want)
		}
	}
}

// One batch across OS and arch: each sprout is resolved against the
// target's rows for its own OS and arch, from what it last reported.
// Sprouts that would refuse the update, or have no package, are failed up
// front with their own code and never sent anything.
func TestFleetUpdate_MixedPlatformsResolvePerSprout(t *testing.T) {
	gdb := newUpdateTestDB(t)
	fastRollouts(t, 5*time.Second)
	ns := startTestBus(t)
	connectSaaSBus(t, ns)
	tid := mustCreateActiveTenant(t, gdb)
	for _, p := range [][3]string{{"linux", "amd64", "deb"}, {"linux", "arm64", "deb"}, {"windows", "amd64", "msi"}} {
		mustPublishRelease(t, gdb, FleetVersion{Version: "v2.4.1", OS: p[0], Arch: p[1], PackageType: p[2], MinSproutVersion: "v2.0.0"})
	}
	mustApprove(t, gdb, tid, "v2.4.1")

	sprouts := []struct {
		id, os, arch, version string
		sent                  bool
		code                  string
	}{
		{"mix-linux", "linux", "amd64", "v2.3.0", true, ""},
		{"mix-arm", "linux", "arm64", "v2.3.0", true, ""},
		{"mix-win", "windows", "amd64", "v2.3.0", true, ""},
		{"mix-already", "linux", "amd64", "v2.4.1", true, ""},
		{"mix-unknown", "", "", "", true, ""},
		{"mix-darwin", "darwin", "arm64", "v2.3.0", false, errCodeNoReleaseForPlatform},
		{"mix-old", "linux", "amd64", "v1.9.0", false, errCodeBelowMinSproutVersion},
		{"mix-newer", "windows", "amd64", "v2.5.0", false, errCodeSproutNewerThanTarget},
	}
	var assets []string
	for _, s := range sprouts {
		mustInsertFarmerSprout(t, gdb, tid, s.id, "accepted")
		mustLinkAsset(t, tid, s.id, "a-"+s.id)
		assets = append(assets, "a-"+s.id)
		if s.os != "" {
			mustReportFacts(t, gdb, tid, s.id, s.os, s.arch, s.version)
		}
	}
	farmer := startFakeFarmer(t, ns, func(req controlplane.SproutActionRequest) any {
		return controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID,
			Status: controlplane.StatusDispatched, JID: "00000000-0000-0000-0000-0000000000aa"}
	})
	installReader(t, &waveReader{farmer: farmer, gdb: gdb, reconnect: "v2.4.1",
		outcome: func(JobRef, int) (JobOutcome, bool) { return JobOutcomeSucceeded, true }})

	code, resp := postUpdates(t, tid, map[string]any{"asset_ids": assets, "target_version": "v2.4.1", "batch_size": 25})
	if code != 202 {
		t.Fatalf("POST: %d %v", code, resp)
	}
	actionDispatches.Wait()
	reqs, _ := farmer.seen()
	sent := map[string]bool{}
	for _, r := range reqs {
		var p farmerSelfUpdate
		if err := json.Unmarshal(r.Action.Params, &p); err != nil || p.Version != "v2.4.1" {
			t.Fatalf("request params %s (%v): one target_version covers every platform", r.Action.Params, err)
		}
		sent[r.SproutID] = true
	}
	_, got := getUpdateBatch(t, tid, resp["batch_id"].(string))
	items := itemsByAsset(got)
	for _, s := range sprouts {
		it := items["a-"+s.id]
		if sent[s.id] != s.sent {
			t.Errorf("%s sent = %t, want %t", s.id, sent[s.id], s.sent)
		}
		if s.sent && it.Status != ActionItemSucceeded {
			t.Errorf("%s = %+v, want succeeded", s.id, it)
		}
		if !s.sent && (it.Status != ActionItemFailed || it.Error != s.code || it.Message != actionErrorMessage(s.code)) {
			t.Errorf("%s = %+v, want failed %s", s.id, it, s.code)
		}
	}
}

// mustPublishRelease registers v (Version, OS, Arch, PackageType and
// MinSproutVersion set by the caller) signed with the test fleet key.
func mustPublishRelease(t *testing.T, gdb *gorm.DB, v FleetVersion) {
	t.Helper()
	id, err := newID("fv_")
	if err != nil {
		t.Fatal(err)
	}
	v.ID = id
	v.FileName = "imas-sprout_" + strings.TrimPrefix(v.Version, "v") + "_" + v.OS + "_" + v.Arch + "." + v.PackageType
	v.ChecksumSHA256 = strings.Repeat("cd", 32)
	v.ReleasedAt = time.Now().UTC()
	v.Signature = signTestRelease(t, v)
	if err := gdb.Create(&v).Error; err != nil {
		t.Fatalf("registering %s %s: %v", v.Version, v.releaseKey(), err)
	}
}

// GET .../sprouts/updates only finds update batches of the caller's
// tenant; §1.5's GET finds update batches too, with the rollout field.
func TestGetFleetUpdateBatch_Scoping(t *testing.T) {
	gdb := newUpdateTestDB(t)
	tid := mustCreateActiveTenant(t, gdb)
	other := mustCreateActiveTenant(t, gdb)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	mustApprove(t, gdb, tid, "v2.4.1")
	SetBus(nil)

	_, upd := postUpdates(t, tid, map[string]any{"asset_ids": []string{"a1"}, "target_version": "v2.4.1"})
	_, act := postActions(t, tid, map[string]any{"asset_ids": []string{"a1"}, "action": cmdAction("ls")})
	actionDispatches.Wait()
	updID, actID := upd["batch_id"].(string), act["batch_id"].(string)

	if code, got := getUpdateBatch(t, tid, updID); code != 200 || got.Rollout == nil {
		t.Fatalf("own update batch: %d %+v", code, got)
	}
	if code, _ := getUpdateBatch(t, tid, actID); code != 404 {
		t.Fatalf("a cmd.run batch through the updates GET: %d, want 404", code)
	}
	wOther := doRequest(t, GetFleetUpdateBatch, "GET", "/", map[string]string{"tenant_id": other, "batch_id": updID}, nil)
	wMissing := doRequest(t, GetFleetUpdateBatch, "GET", "/", map[string]string{"tenant_id": other, "batch_id": "b_nope"}, nil)
	if wOther.Code != 404 || wOther.Body.String() != wMissing.Body.String() {
		t.Fatalf("cross-tenant GET: %d %s vs %s", wOther.Code, wOther.Body.String(), wMissing.Body.String())
	}
	if code, got := getBatch(t, tid, updID); code != 200 || got.ActionType != controlplane.ActionSelfUpdate || got.Rollout == nil {
		t.Fatalf("update batch through §1.5's GET: %d %+v", code, got)
	}
	if _, got := getBatch(t, tid, actID); got.Rollout != nil {
		t.Fatalf("cmd.run batch has a rollout: %+v", got.Rollout)
	}
}

func TestRolloutPolicyCheck(t *testing.T) {
	gdb := newUpdateTestDB(t)
	tid := mustCreateActiveTenant(t, gdb)
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	check := func() string {
		t.Helper()
		code, err := rolloutPolicyCheck(gdb, tid, "v2.4.1", now)
		if err != nil {
			t.Fatalf("rolloutPolicyCheck: %v", err)
		}
		return code
	}
	if c := check(); c != errCodeApprovalWithdrawn {
		t.Fatalf("no policy: %q", c)
	}
	mustApprove(t, gdb, tid, "v2.4.1")
	if c := check(); c != "" {
		t.Fatalf("approved, no window: %q", c)
	}
	for _, tc := range []struct {
		start, end time.Time
		want       string
	}{
		{now, now.Add(time.Hour), ""},                          // start is inclusive
		{now.Add(-time.Hour), now, errCodeRolloutWindowClosed}, // end is exclusive
		{now.Add(time.Minute), now.Add(time.Hour), errCodeRolloutWindowClosed},
	} {
		mustApprove(t, gdb, tid, "v2.4.1", tc.start, tc.end)
		if c := check(); c != tc.want {
			t.Errorf("window %s–%s: %q, want %q", tc.start, tc.end, c, tc.want)
		}
	}
}

func TestReplyUpdate_SelfUpdate(t *testing.T) {
	batch := AssetActionBatch{ID: "b_1", TenantID: "t_1", ActionType: controlplane.ActionSelfUpdate}
	item := AssetActionItem{BatchID: "b_1", AssetID: "a1", TenantID: "t_1", SproutID: "s_1"}
	reply := func(r controlplane.SproutActionReply) map[string]any {
		r.TenantID, r.SproutID = "t_1", "s_1"
		b, _ := json.Marshal(r)
		return replyUpdate(batch, item, b)
	}
	jid := "11111111-1111-1111-1111-111111111111"
	if u := reply(controlplane.SproutActionReply{Status: controlplane.StatusDispatched, JID: jid}); u["status"] != ActionItemRunning || u["jid"] != jid {
		t.Fatalf("dispatched: %v", u)
	}
	// A cmd.run-style completed reply isn't a valid self_update outcome.
	if u := reply(controlplane.SproutActionReply{Status: controlplane.StatusCompleted, Result: &controlplane.CmdRunResult{}}); u["error_code"] != string(controlplane.ErrorInternal) {
		t.Fatalf("completed: %v", u)
	}
	// Today's farmer answers self_update with unsupported_action.
	if u := reply(controlplane.SproutActionReply{Status: controlplane.StatusFailed, ErrorCode: controlplane.ErrorUnsupportedAction}); u["error_code"] != string(controlplane.ErrorUnsupportedAction) {
		t.Fatalf("unsupported: %v", u)
	}
}

func TestLoadConfigFleetUpdateDispatchFlag(t *testing.T) {
	for v, want := range map[string]bool{"": false, "false": false, "0": false, "true": true, "1": true} {
		t.Setenv("SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED", v)
		cfg, err := LoadConfig()
		if err != nil || cfg.FleetUpdateDispatchEnabled != want {
			t.Fatalf("%q: %v, %v; want %v", v, cfg.FleetUpdateDispatchEnabled, err, want)
		}
	}
	t.Setenv("SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED", "yes please")
	if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED") {
		t.Fatalf("invalid value: %v", err)
	}
}

// indexingFarmer answers every self_update with dispatched and jidFor's
// jid, and writes the job's farmer.job_status row the way farmer's jobs
// index (wired into farmer's startup by cmd/farmer's installStorage) would:
// status(sprout) for the sprout, under indexTenant(request tenant). For a
// succeeded job it also stores the sprout's v2.4.1 sprout_version fact,
// under the same tenant, as the sprout reconnecting would.
func indexingFarmer(t *testing.T, ns *server.Server, gdb *gorm.DB,
	indexTenant func(string) string, status func(sprout string) string) *fakeFarmer {
	t.Helper()
	return startFakeFarmer(t, ns, func(req controlplane.SproutActionRequest) any {
		st := status(req.SproutID)
		if err := gdb.Exec(`INSERT INTO farmer.job_status (tenant_id, sprout_id, jid, status, updated_at)
VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`, indexTenant(req.TenantID), req.SproutID, jidFor(req.SproutID), st).Error; err != nil {
			t.Errorf("indexing job for %s: %v", req.SproutID, err)
		}
		// A sprout whose update succeeded restarts on it and reports the
		// new version, which farmer's facts listener stores under the
		// same tenant.
		if st == "succeeded" {
			if err := reportFact(gdb, indexTenant(req.TenantID), req.SproutID, farmerPropSproutVersion, "v2.4.1"); err != nil {
				t.Errorf("reporting version for %s: %v", req.SproutID, err)
			}
		}
		return controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID,
			Status: controlplane.StatusDispatched, JID: jidFor(req.SproutID)}
	})
}

// The default job_status gate, end to end through the production readers
// (farmerJobStatusReader over farmer.job_status, farmerSproutFactsReader
// over farmer.props) rather than fakes: waves pass once sprouts report the
// new version and a failed job halts the rollout.
func TestFleetUpdate_JobStatusGateWithFarmerIndex(t *testing.T) {
	gdb := newUpdateTestDB(t)
	fastRollouts(t, 5*time.Second)
	ns := startTestBus(t)
	connectSaaSBus(t, ns)
	installReader(t, farmerJobStatusReader{})
	tid := mustCreateActiveTenant(t, gdb)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	mustApprove(t, gdb, tid, "v2.4.1")
	assets := mustUpdateFleet(t, gdb, tid, 5)
	farmer := indexingFarmer(t, ns, gdb, func(tenant string) string { return tenant }, func(sprout string) string {
		if sprout == "upd-03" {
			return "failed"
		}
		return "succeeded"
	})

	_, resp := postUpdates(t, tid, map[string]any{"asset_ids": assets, "target_version": "v2.4.1", "batch_size": 2})
	actionDispatches.Wait()
	if reqs, _ := farmer.seen(); len(reqs) != 4 {
		t.Fatalf("farmer got %d requests, want 4 (waves 1 and 2)", len(reqs))
	}
	_, got := getUpdateBatch(t, tid, resp["batch_id"].(string))
	want := []struct {
		status AssetActionItemStatus
		code   string
	}{
		{ActionItemSucceeded, ""}, {ActionItemSucceeded, ""},
		{ActionItemFailed, errCodeJobFailed}, {ActionItemSucceeded, ""},
		{ActionItemFailed, errCodeRolloutHalted},
	}
	for i, it := range got.Items {
		if it.Status != want[i].status || it.Error != want[i].code {
			t.Errorf("item %d = %+v, want %s %s", i, it, want[i].status, want[i].code)
		}
	}
}

// Another tenant's farmer.job_status row, and sprout_version fact, for the
// same sprout_id never pass this tenant's wave: sprout_id is only unique
// per tenant.
func TestFleetUpdate_JobStatusGateIgnoresOtherTenantsIndexRows(t *testing.T) {
	gdb := newUpdateTestDB(t)
	fastRollouts(t, 50*time.Millisecond)
	ns := startTestBus(t)
	connectSaaSBus(t, ns)
	installReader(t, farmerJobStatusReader{})
	tid := mustCreateActiveTenant(t, gdb)
	other := mustCreateActiveTenant(t, gdb)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	mustApprove(t, gdb, tid, "v2.4.1")
	assets := mustUpdateFleet(t, gdb, tid, 2)
	// The only index row for upd-01's job is filed under the other tenant.
	indexingFarmer(t, ns, gdb, func(string) string { return other }, func(string) string { return "succeeded" })

	_, resp := postUpdates(t, tid, map[string]any{"asset_ids": assets, "target_version": "v2.4.1", "batch_size": 1})
	actionDispatches.Wait()
	_, got := getUpdateBatch(t, tid, resp["batch_id"].(string))
	if it := got.Items[0]; it.Status != ActionItemUnresponsiveAfterUpdate {
		t.Errorf("upd-01 = %+v, want unresponsive_after_update", it)
	}
	if it := got.Items[1]; it.Status != ActionItemFailed || it.Error != errCodeRolloutHalted {
		t.Errorf("upd-02 = %+v, want failed rollout_halted", it)
	}
}
