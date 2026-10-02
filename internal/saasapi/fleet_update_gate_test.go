package saasapi

// FU.6b: the wave gate only counts a sprout_version report written after
// the item's dispatch, and the per-tenant rollout claim writes its own
// column instead of the policy's updated_at.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/facts"
	"github.com/yogzblr/imas/internal/props"
)

// propWriteTime's arithmetic is internal/props' own: a fact stored the way
// farmer's facts listener stores it (props.SetPropForTenant) reads back,
// through the reader the gate uses, with the time it was written. If props
// ever stores expiry differently, or with another TTL, this fails instead
// of the gate silently accepting older rows.
func TestPropWriteTimeMatchesProps(t *testing.T) {
	gdb := newUpdateTestDB(t)
	pdb, err := gorm.Open(sqlite.Open("file:saasapi_props_ttl?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := pdb.AutoMigrate(props.Models()...); err != nil {
		t.Fatal(err)
	}
	props.SetDB(pdb)
	t.Cleanup(func() { props.SetDB(nil) })

	before := time.Now()
	if err := props.SetPropForTenant("t_ttl", "web-01", facts.PropSproutVersion, "v2.4.1"); err != nil {
		t.Fatal(err)
	}
	after := time.Now()

	var row struct {
		Value  string
		Static bool
		Expiry time.Time
	}
	if err := pdb.Table("props").Select("value", "static", "expiry").
		Where("tenant_id = ? AND sprout_id = ? AND name = ?", "t_ttl", "web-01", facts.PropSproutVersion).
		Scan(&row).Error; err != nil {
		t.Fatal(err)
	}
	written := propWriteTime(row.Expiry, row.Static)
	if written.Before(before.Truncate(time.Millisecond)) || written.After(after) {
		t.Fatalf("props stored expiry %s for a write between %s and %s: the write time it implies (%s) is not expiry - props.DefaultPropTTL",
			row.Expiry, before, after, written)
	}

	// The same row, as farmer.props holds it, through the gate's reader.
	if err := gdb.Exec(`INSERT INTO farmer.props (tenant_id, sprout_id, name, value, static, expiry) VALUES (?, ?, ?, ?, ?, ?)`,
		"t_ttl", "web-01", farmerPropSproutVersion, row.Value, row.Static, row.Expiry).Error; err != nil {
		t.Fatal(err)
	}
	got, err := farmerSproutFactsReader{}.SproutFactsWithWriteTimes(context.Background(), "t_ttl", []string{"web-01"})
	if err != nil {
		t.Fatal(err)
	}
	f := got[SproutRef{TenantID: "t_ttl", SproutID: "web-01"}]
	if f.Version != "v2.4.1" || !f.Written.Version.Equal(written) {
		t.Fatalf("reader = %+v, want v2.4.1 written %s", f, written)
	}
}

// The second reader method: same rows as SproutFacts (expiry ignored, so
// planning is unchanged), plus each fact's write time. A static prop, which
// no sprout wrote, has none.
func TestFarmerSproutFactsReaderWriteTimes(t *testing.T) {
	gdb := newUpdateTestDB(t)
	old := time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)
	fresh := time.Now().UTC().Truncate(time.Millisecond)
	for _, f := range []struct {
		sprout, name, value string
		written             time.Time
	}{
		{"web-01", farmerPropOS, "linux", old},
		{"web-01", farmerPropArch, "amd64", old},
		{"web-01", farmerPropSproutVersion, "v2.4.1", fresh},
		// Same sprout_id, another tenant: never read for t_a.
		{"web-01", farmerPropSproutVersion, "v9.9.9", fresh},
	} {
		tenant := "t_a"
		if f.value == "v9.9.9" {
			tenant = "t_b"
		}
		if err := reportFactWrittenAt(gdb, tenant, f.sprout, f.name, f.value, f.written); err != nil {
			t.Fatal(err)
		}
	}
	if err := gdb.Exec(`INSERT INTO farmer.props (tenant_id, sprout_id, name, value, static, expiry) VALUES (?, ?, ?, ?, 1, ?)`,
		"t_a", "web-02", farmerPropSproutVersion, "v2.4.1", time.Now().Add(props.StaticPropTTL).UTC()).Error; err != nil {
		t.Fatal(err)
	}

	r := farmerSproutFactsReader{}
	got, err := r.SproutFactsWithWriteTimes(context.Background(), "t_a", []string{"web-01", "web-02"})
	if err != nil {
		t.Fatal(err)
	}
	w1 := got[SproutRef{TenantID: "t_a", SproutID: "web-01"}]
	if w1.SproutFacts != (SproutFacts{OS: "linux", Arch: "amd64", Version: "v2.4.1"}) ||
		!w1.Written.OS.Equal(old) || !w1.Written.Arch.Equal(old) || !w1.Written.Version.Equal(fresh) {
		t.Fatalf("web-01 = %+v", w1)
	}
	if w2 := got[SproutRef{TenantID: "t_a", SproutID: "web-02"}]; w2.Version != "v2.4.1" || !w2.Written.Version.IsZero() {
		t.Fatalf("static web-02 = %+v, want v2.4.1 with no write time", w2)
	}
	if len(got) != 2 {
		t.Fatalf("got %d sprouts: %v", len(got), got)
	}

	plain, err := r.SproutFacts(context.Background(), "t_a", []string{"web-01", "web-02"})
	if err != nil {
		t.Fatal(err)
	}
	for ref, f := range got {
		if plain[ref] != f.SproutFacts {
			t.Fatalf("SproutFacts %v = %+v, SproutFactsWithWriteTimes has %+v", ref, plain[ref], f.SproutFacts)
		}
	}
}

func TestReportFreshBoundaries(t *testing.T) {
	if rolloutClockSkew != 30*time.Second {
		t.Fatalf("rolloutClockSkew = %s; the documented margin (docs/api/saasapi.md) is 30s", rolloutClockSkew)
	}
	dispatched := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	now := dispatched.Add(10 * time.Minute)
	ms := time.Millisecond
	for _, tc := range []struct {
		name    string
		written time.Time
		want    bool
	}{
		{"no write time (static prop)", time.Time{}, false},
		{"an hour before dispatch", dispatched.Add(-time.Hour), false},
		{"exactly the margin before dispatch", dispatched.Add(-rolloutClockSkew), false},
		{"just inside the margin before dispatch", dispatched.Add(-rolloutClockSkew + ms), true},
		{"at dispatch", dispatched, true},
		{"after dispatch", dispatched.Add(time.Minute), true},
		{"at now", now, true},
		{"exactly the margin after now", now.Add(rolloutClockSkew), true},
		{"beyond the margin after now", now.Add(rolloutClockSkew + ms), false},
		{"a static prop's expiry, read as a write", dispatched.Add(props.StaticPropTTL - props.DefaultPropTTL), false},
	} {
		if got := reportFresh(tc.written, dispatched, now); got != tc.want {
			t.Errorf("%s: reportFresh(%s) = %t, want %t", tc.name, tc.written, got, tc.want)
		}
	}
}

// The gate end to end over farmer.props rows, at the skew margin's
// boundaries, on a fixed saasapi clock.
func TestRefreshUpdateItems_FreshnessBoundaries(t *testing.T) {
	gdb := newUpdateTestDB(t)
	dispatched := time.Now().UTC().Truncate(time.Millisecond).Add(-time.Minute)
	now := dispatched.Add(time.Minute)
	prevNow := rolloutNow
	rolloutNow = func() time.Time { return now }
	t.Cleanup(func() { rolloutNow = prevNow })

	tid := mustCreateActiveTenant(t, gdb)
	other := mustCreateActiveTenant(t, gdb)
	batch := AssetActionBatch{ID: "b_fresh_" + tid, TenantID: tid, ActionType: controlplane.ActionSelfUpdate,
		ActionParams: `{"version":"v2.4.1"}`, RequestedAssetIDs: `[]`, RolloutBatchSize: 25, RolloutGate: gateJobStatus}
	if err := gdb.Create(&batch).Error; err != nil {
		t.Fatal(err)
	}
	ms := time.Millisecond
	cases := []struct {
		sprout   string
		value    string
		written  time.Time
		proof    *updateProof // nil: the rollout has no record of it
		succeeds bool
	}{
		{"g-margin", "v2.4.1", dispatched.Add(-rolloutClockSkew), &updateProof{dispatched: dispatched}, false},
		{"g-inside", "v2.4.1", dispatched.Add(-rolloutClockSkew + ms), &updateProof{dispatched: dispatched}, true},
		{"g-after", "v2.4.1", dispatched.Add(20 * time.Second), &updateProof{dispatched: dispatched}, true},
		{"g-future-edge", "v2.4.1", now.Add(rolloutClockSkew), &updateProof{dispatched: dispatched}, true},
		{"g-future", "v2.4.1", now.Add(rolloutClockSkew + ms), &updateProof{dispatched: dispatched}, false},
		{"g-old-version", oldSproutVersion, dispatched.Add(20 * time.Second), &updateProof{dispatched: dispatched}, false},
		{"g-stale", "v2.4.1", dispatched.Add(-time.Hour), &updateProof{dispatched: dispatched}, false},
		// Already on the target at planning: its existing report stands.
		{"g-already", "v2.4.1", dispatched.Add(-time.Hour), &updateProof{dispatched: dispatched, anyReport: true}, true},
		{"g-already-old", oldSproutVersion, dispatched.Add(-time.Hour), &updateProof{dispatched: dispatched, anyReport: true}, false},
		// No dispatch on record: nothing passes it, however fresh.
		{"g-unknown", "v2.4.1", dispatched.Add(20 * time.Second), nil, false},
		// Another tenant's fresh report of the target, for the same
		// sprout_id: this tenant's sprout has reported nothing.
		{"g-elsewhere", "", time.Time{}, &updateProof{dispatched: dispatched}, false},
	}
	var items []AssetActionItem
	proofs := map[string]updateProof{}
	for i, c := range cases {
		items = append(items, AssetActionItem{BatchID: batch.ID, AssetID: "a-" + c.sprout, TenantID: tid, Position: i,
			SproutID: c.sprout, Status: ActionItemRunning, JID: jidFor("upd-01")})
		if c.proof != nil {
			proofs["a-"+c.sprout] = *c.proof
		}
		if c.value != "" {
			if err := reportFactWrittenAt(gdb, tid, c.sprout, farmerPropSproutVersion, c.value, c.written); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := reportFactWrittenAt(gdb, other, "g-elsewhere", farmerPropSproutVersion, "v2.4.1", dispatched.Add(20*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := gdb.Create(&items).Error; err != nil {
		t.Fatal(err)
	}

	w := sentWave{items: items, proofs: proofs}
	refreshUpdateItemsWith(context.Background(), gdb, nil, farmerSproutFactsReader{}, batch, items, w.proof)

	stored, err := loadWaveItems(gdb, batch, items)
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range cases {
		want := ActionItemRunning
		if c.succeeds {
			want = ActionItemSucceeded
		}
		if stored[i].Status != want || items[i].Status != want {
			t.Errorf("%s: stored %s, in memory %s, want %s", c.sprout, stored[i].Status, items[i].Status, want)
		}
	}
}

// A sprout that reports the target version, but in a row written before
// its update was dispatched, doesn't pass the wave: it stays running until
// the wave's deadline, then is unresponsive_after_update, and the rollout
// halts. Its wave-mate, whose report is fresh, succeeds.
func TestFleetUpdate_StaleTargetReportDoesNotPassGate(t *testing.T) {
	gdb := newUpdateTestDB(t)
	fastRollouts(t, 300*time.Millisecond)
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
	var mu sync.Mutex
	var midWave []AssetActionItemStatus
	installReader(t, &waveReader{farmer: farmer, outcome: func(ref JobRef, call int) (JobOutcome, bool) {
		switch ref.SproutID {
		case "upd-01":
			// Planning saw v2.4.0; the row naming v2.4.1 now carries a
			// write time from before this wave was dispatched (well
			// beyond the skew margin): a leftover, not this update.
			_ = reportFactWrittenAt(gdb, tid, ref.SproutID, farmerPropSproutVersion, "v2.4.1", time.Now().Add(-2*rolloutClockSkew))
			if call > 2 {
				var it AssetActionItem
				gdb.Where("tenant_id = ? AND sprout_id = ?", tid, ref.SproutID).First(&it)
				mu.Lock()
				midWave = append(midWave, it.Status)
				mu.Unlock()
			}
		case "upd-02":
			_ = reportFact(gdb, tid, ref.SproutID, farmerPropSproutVersion, "v2.4.1")
		}
		return JobOutcomeSucceeded, true
	}})

	_, resp := postUpdates(t, tid, map[string]any{"asset_ids": assets, "target_version": "v2.4.1", "batch_size": 2})
	actionDispatches.Wait()
	if reqs, _ := farmer.seen(); len(reqs) != 2 {
		t.Fatalf("farmer got %d requests, want only wave 1's 2", len(reqs))
	}
	mu.Lock()
	defer mu.Unlock()
	if len(midWave) == 0 {
		t.Fatal("never looked at upd-01 while its wave was waited on")
	}
	for _, s := range midWave {
		if s != ActionItemRunning {
			t.Fatalf("upd-01 before the deadline: %s, want running (all: %v)", s, midWave)
		}
	}
	_, got := getUpdateBatch(t, tid, resp["batch_id"].(string))
	want := []struct {
		status AssetActionItemStatus
		code   string
	}{
		{ActionItemUnresponsiveAfterUpdate, errCodeUnresponsiveAfterUpdate}, {ActionItemSucceeded, ""},
		{ActionItemFailed, errCodeRolloutHalted}, {ActionItemFailed, errCodeRolloutHalted},
	}
	for i, it := range got.Items {
		if it.Status != want[i].status || it.Error != want[i].code {
			t.Errorf("item %d = %+v, want %s %s", i, it, want[i].status, want[i].code)
		}
	}
}

// A sprout that already reported the target version when the rollout was
// planned is sent the update, answers "already running", and never writes
// a new report. Its existing one still passes the wave, as before FU.6b.
func TestFleetUpdate_AlreadyAtTargetPassesOnItsReport(t *testing.T) {
	gdb := newUpdateTestDB(t)
	fastRollouts(t, 5*time.Second)
	ns := startTestBus(t)
	connectSaaSBus(t, ns)
	tid := mustCreateActiveTenant(t, gdb)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	mustApprove(t, gdb, tid, "v2.4.1")
	assets := mustUpdateFleet(t, gdb, tid, 3)
	// upd-02 reported v2.4.1 an hour ago.
	mustReportFacts(t, gdb, tid, "upd-02", "linux", "amd64", "v2.4.1")
	farmer := startFakeFarmer(t, ns, func(req controlplane.SproutActionRequest) any {
		return controlplane.SproutActionReply{TenantID: req.TenantID, SproutID: req.SproutID,
			Status: controlplane.StatusDispatched, JID: jidFor(req.SproutID)}
	})
	installReader(t, &waveReader{farmer: farmer, outcome: func(ref JobRef, _ int) (JobOutcome, bool) {
		if ref.SproutID != "upd-02" {
			_ = reportFact(gdb, tid, ref.SproutID, farmerPropSproutVersion, "v2.4.1")
		}
		return JobOutcomeSucceeded, true
	}})

	_, resp := postUpdates(t, tid, map[string]any{"asset_ids": assets, "target_version": "v2.4.1", "batch_size": 2})
	actionDispatches.Wait()
	if reqs, _ := farmer.seen(); len(reqs) != 3 {
		t.Fatalf("farmer got %d requests, want 3 (wave 1 passed)", len(reqs))
	}
	_, got := getUpdateBatch(t, tid, resp["batch_id"].(string))
	for _, it := range got.Items {
		if it.Status != ActionItemSucceeded {
			t.Errorf("item = %+v, want succeeded", it)
		}
	}
}

// planUpdateItems' atTarget, rolloutProofs and the rollout's record of
// dispatch times, keyed per tenant: another tenant's sprout with the same
// sprout_id on the target version exempts nothing here.
func TestRolloutProofs(t *testing.T) {
	batch := AssetActionBatch{ID: "b_p", TenantID: "t_a"}
	at := time.Now()
	items := []AssetActionItem{
		{AssetID: "a1", SproutID: "web-01"},
		{AssetID: "a2", SproutID: "web-02"},
		{AssetID: "a3", SproutID: "web-03"},
	}
	proofs := rolloutProofs(batch, items, map[string]time.Time{"a1": at, "a2": at},
		map[SproutRef]bool{{TenantID: "t_a", SproutID: "web-02"}: true, {TenantID: "t_b", SproutID: "web-01"}: true})
	if p := proofs["a1"]; !p.dispatched.Equal(at) || p.anyReport {
		t.Errorf("a1 = %+v, want a fresh report after %s", p, at)
	}
	if p := proofs["a2"]; !p.dispatched.Equal(at) || !p.anyReport {
		t.Errorf("a2 = %+v, want its existing report to count", p)
	}
	if _, ok := (sentWave{proofs: proofs}).proof(items[2]); ok {
		t.Error("a3 was never dispatched, but has a proof")
	}
}

func TestPlanUpdateItemsAtTarget(t *testing.T) {
	gdb := newUpdateTestDB(t)
	tid := mustCreateActiveTenant(t, gdb)
	catalog := []FleetVersion{mustPublishVersion(t, gdb, "v2.4.1", time.Now())}
	mustReportFacts(t, gdb, tid, "p-old", "linux", "amd64", oldSproutVersion)
	mustReportFacts(t, gdb, tid, "p-at", "linux", "amd64", "v2.4.1")
	mustReportFacts(t, gdb, tid, "p-newer", "linux", "amd64", "v2.5.0")
	mustReportFacts(t, gdb, "t_other", "p-old", "linux", "amd64", "v2.4.1")
	rows := []sproutByAssetItem{
		{SproutID: "p-old", KeyState: keyStateAccepted},
		{SproutID: "p-at", KeyState: keyStateAccepted},
		{SproutID: "p-newer", KeyState: keyStateAccepted},
		{SproutID: "p-none", KeyState: keyStateAccepted},
	}
	blocked, atTarget, err := planUpdateItems(context.Background(), farmerSproutFactsReader{}, tid, rows, catalog)
	if err != nil {
		t.Fatal(err)
	}
	ref := func(id string) SproutRef { return SproutRef{TenantID: tid, SproutID: id} }
	if len(atTarget) != 1 || !atTarget[ref("p-at")] {
		t.Fatalf("atTarget = %v, want only p-at", atTarget)
	}
	if len(blocked) != 1 || blocked[ref("p-newer")] != errCodeSproutNewerThanTarget {
		t.Fatalf("blocked = %v", blocked)
	}
}

// The rollout claim writes rollout_claimed_at, always later than the
// stored value, and never updated_at; GET update-policy doesn't change
// when a rollout starts and doesn't show the claim. PATCH still moves
// updated_at, and leaves the claim alone.
func TestRolloutClaimLeavesUpdatedAt(t *testing.T) {
	gdb := newUpdateTestDB(t)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	tid := mustCreateActiveTenant(t, gdb)
	if w := patchPolicy(t, tid, `{"approved_version":"v2.4.1"}`); w.Code != 200 {
		t.Fatalf("PATCH: %d %s", w.Code, w.Body.String())
	}
	load := func() TenantUpdatePolicy {
		t.Helper()
		var p TenantUpdatePolicy
		if err := gdb.First(&p, "tenant_id = ?", tid).Error; err != nil {
			t.Fatal(err)
		}
		return p
	}
	p0 := load()
	get0 := getPolicy(t, tid).Body.String()

	now := time.Now()
	if err := gdb.Transaction(claimRollout(tid, "v2.4.1", now)); err != nil {
		t.Fatalf("claim: %v", err)
	}
	p1 := load()
	if p1.RolloutClaimedAt == nil || !p1.RolloutClaimedAt.Equal(claimTimestamp(now, time.Time{})) || !p1.UpdatedAt.Equal(p0.UpdatedAt) {
		t.Fatalf("after a claim: %+v (before %+v)", p1, p0)
	}
	if get1 := getPolicy(t, tid).Body.String(); get1 != get0 || strings.Contains(get1, "rollout_claimed") {
		t.Fatalf("GET update-policy changed when a rollout started:\n%s\n%s", get0, get1)
	}

	// A second claim at the same instant still writes a later value.
	if err := gdb.Transaction(claimRollout(tid, "v2.4.1", now)); err != nil {
		t.Fatalf("second claim: %v", err)
	}
	p2 := load()
	if p2.RolloutClaimedAt == nil || !p2.RolloutClaimedAt.Equal(p1.RolloutClaimedAt.Add(time.Millisecond)) || !p2.UpdatedAt.Equal(p0.UpdatedAt) {
		t.Fatalf("after a second claim: %+v (after the first %+v)", p2, p1)
	}

	time.Sleep(2 * time.Millisecond)
	w := patchPolicy(t, tid, `{"auto_update":true}`)
	if w.Code != 200 {
		t.Fatalf("PATCH: %d %s", w.Code, w.Body.String())
	}
	p3 := load()
	if !p3.UpdatedAt.After(p0.UpdatedAt) || p3.RolloutClaimedAt == nil || !p3.RolloutClaimedAt.Equal(*p2.RolloutClaimedAt) {
		t.Fatalf("after PATCH: %+v (before %+v)", p3, p2)
	}
	if resp := decodePolicy(t, w); resp.UpdatedAt == nil || !resp.UpdatedAt.Equal(p3.UpdatedAt) || strings.Contains(w.Body.String(), "rollout_claimed") {
		t.Fatalf("PATCH response = %s", w.Body.String())
	}
}

// tenantUpdatePolicyFU6 is TenantUpdatePolicy as the previous release
// (FU.6) has it, without rollout_claimed_at.
type tenantUpdatePolicyFU6 struct {
	TenantID           string     `gorm:"column:tenant_id;primaryKey;size:32"`
	ApprovedVersion    *string    `gorm:"column:approved_version;size:64"`
	AutoUpdate         bool       `gorm:"column:auto_update;not null;default:false"`
	RolloutWindowStart *time.Time `gorm:"column:rollout_window_start"`
	RolloutWindowEnd   *time.Time `gorm:"column:rollout_window_end"`
	UpdatedAt          time.Time  `gorm:"column:updated_at"`
}

func (tenantUpdatePolicyFU6) TableName() string { return "tenant_update_policy" }

// Backward compatible for one release: the previous saasapi's model loads
// a row from a table that has rollout_claimed_at, and its writes (PATCH's
// Save, its claim of updated_at) work and leave the new column alone.
// During a rolling upgrade both releases' claims write the same row, so
// Galera still certifies them against each other.
func TestPreviousPolicyModelWithClaimColumn(t *testing.T) {
	gdb := newUpdateTestDB(t)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	tid := mustCreateActiveTenant(t, gdb)
	mustApprove(t, gdb, tid, "v2.4.1")
	if err := gdb.Transaction(claimRollout(tid, "v2.4.1", time.Now())); err != nil {
		t.Fatal(err)
	}
	var claimed TenantUpdatePolicy
	gdb.First(&claimed, "tenant_id = ?", tid)

	var old tenantUpdatePolicyFU6
	if err := gdb.First(&old, "tenant_id = ?", tid).Error; err != nil {
		t.Fatalf("previous model: %v", err)
	}
	if old.ApprovedVersion == nil || *old.ApprovedVersion != "v2.4.1" {
		t.Fatalf("previous model read %+v", old)
	}
	old.AutoUpdate = true
	if err := gdb.Save(&old).Error; err != nil {
		t.Fatalf("previous model's Save: %v", err)
	}
	if err := gdb.Model(&tenantUpdatePolicyFU6{}).Where("tenant_id = ?", tid).
		UpdateColumn("updated_at", time.Now().Add(time.Hour)).Error; err != nil {
		t.Fatalf("previous release's claim: %v", err)
	}
	var after TenantUpdatePolicy
	gdb.First(&after, "tenant_id = ?", tid)
	if !after.AutoUpdate || after.RolloutClaimedAt == nil || !after.RolloutClaimedAt.Equal(*claimed.RolloutClaimedAt) {
		t.Fatalf("after the previous release's writes: %+v (claimed %+v)", after, claimed)
	}
}

// The GETs' bound: a running item's updated_at, which dispatchItem's
// queued -> dispatching -> running updates move to saasapi's now (GORM
// stamps it on a map update), so it is never earlier than the dispatch.
func TestRunningSinceProofIsTheRunningTransition(t *testing.T) {
	gdb := newUpdateTestDB(t)
	tid := mustCreateActiveTenant(t, gdb)
	created := time.Now().Add(-time.Hour)
	it := AssetActionItem{BatchID: "b_since_" + tid, AssetID: "a1", TenantID: tid, SproutID: "web-01",
		Status: ActionItemQueued, CreatedAt: created, UpdatedAt: created}
	if err := gdb.Create(&it).Error; err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	for _, step := range []struct {
		from AssetActionItemStatus
		to   map[string]any
	}{
		{ActionItemQueued, map[string]any{"status": ActionItemDispatching}},
		{ActionItemDispatching, map[string]any{"status": ActionItemRunning, "jid": jidFor("upd-01")}},
	} {
		if ok, err := updateItem(gdb, it, step.from, step.to); err != nil || !ok {
			t.Fatalf("%s -> %v: %t %v", step.from, step.to, ok, err)
		}
	}
	var stored AssetActionItem
	if err := gdb.First(&stored, "batch_id = ? AND asset_id = ?", it.BatchID, it.AssetID).Error; err != nil {
		t.Fatal(err)
	}
	p, ok := runningSinceProof(stored)
	if !ok || p.anyReport || p.dispatched.Before(before) {
		t.Fatalf("runningSinceProof = %+v %t, want a fresh-report bound no earlier than %s", p, ok, before)
	}
	if _, ok := runningSinceProof(AssetActionItem{}); ok {
		t.Fatal("an item with no updated_at has a proof")
	}
}
