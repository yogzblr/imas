package saasapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/valkey-io/valkey-go"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"github.com/yogzblr/imas/internal/heartbeat"
	"github.com/yogzblr/imas/internal/pki"
)

// newTestDBWithFarmer is newTestDB plus a stand-in for the farmer schema:
// an attached in-memory sqlite database named "farmer" holding a
// job_status table (internal/jobs' index) and a
// pki_nkeys table with internal/pki's nkeyRow columns and primary key
// (TestFarmerNKeysColumnContract checks the columns asset_links.go reads
// against pki.Models()), so §1.4's cross-schema join runs unmodified.
//
// ATTACH is per-connection in sqlite, so the pool is pinned to a single
// connection. asset_links is also cleared: newTestDB's shared-cache
// database outlives each test, and asset_id is globally UNIQUE, so rows
// left by an earlier test would collide.
func newTestDBWithFarmer(t *testing.T) *gorm.DB {
	t.Helper()
	gdb := newTestDB(t)
	sqlDB, err := gdb.DB()
	if err != nil {
		t.Fatalf("getting sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	for _, stmt := range []string{
		`ATTACH DATABASE ':memory:' AS farmer`,
		`CREATE TABLE farmer.pki_nkeys (
			tenant_id TEXT NOT NULL,
			sprout_id TEXT NOT NULL,
			nkey      TEXT NOT NULL,
			state     TEXT NOT NULL,
			PRIMARY KEY (tenant_id, sprout_id)
		)`,
		// internal/jobs' job-status index (sprout_actions.go's
		// farmerJobStatusReader); TestFarmerJobStatusColumnContract pins
		// the columns read.
		`CREATE TABLE farmer.job_status (
			tenant_id  TEXT NOT NULL,
			sprout_id  TEXT NOT NULL,
			jid        TEXT NOT NULL,
			status     TEXT NOT NULL,
			updated_at DATETIME,
			PRIMARY KEY (tenant_id, sprout_id, jid)
		)`,
		`DELETE FROM asset_links`,
	} {
		if err := gdb.Exec(stmt).Error; err != nil {
			t.Fatalf("setting up farmer schema (%q): %v", stmt, err)
		}
	}
	return gdb
}

func mustInsertFarmerSprout(t *testing.T, gdb *gorm.DB, tenantID, sproutID, state string) {
	t.Helper()
	if err := gdb.Exec(`INSERT INTO farmer.pki_nkeys (tenant_id, sprout_id, nkey, state) VALUES (?, ?, ?, ?)`,
		tenantID, sproutID, "U"+strings.ToUpper(sproutID), state).Error; err != nil {
		t.Fatalf("inserting farmer sprout: %v", err)
	}
}

// newTestHeartbeat points internal/heartbeat at an in-process miniredis
// for the duration of the test and returns it, so tests can mark sprouts
// online with markOnline.
func newTestHeartbeat(t *testing.T) *miniredis.Miniredis {
	t.Helper()
	mr := miniredis.RunT(t)
	c, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{mr.Addr()}, DisableCache: true})
	if err != nil {
		t.Fatalf("creating valkey client: %v", err)
	}
	heartbeat.SetClient(c)
	t.Cleanup(func() {
		heartbeat.SetClient(nil)
		c.Close()
	})
	return mr
}

// markOnline writes the heartbeat key internal/heartbeat's CONNECT
// listener would. heartbeat's keyFor is unexported, so the format is
// repeated here, and immediately checked through the real
// heartbeat.IsOnline so a format drift fails loudly instead of silently
// making every sprout look offline.
func markOnline(t *testing.T, mr *miniredis.Miniredis, tenantID, sproutID string) {
	t.Helper()
	if err := mr.Set("imas:heartbeat:{"+tenantID+":"+sproutID+"}", "1"); err != nil {
		t.Fatalf("setting heartbeat key: %v", err)
	}
	if !heartbeat.IsOnline(context.Background(), tenantID, sproutID) {
		t.Fatalf("heartbeat.IsOnline doesn't see the key markOnline wrote; has heartbeat's key format changed?")
	}
}

// TestFarmerNKeysColumnContract pins the pki_nkeys columns asset_links.go
// reads by name in raw SQL (tenant_id, sprout_id, state) to internal/pki's
// own model, so a rename there breaks this test rather than §1.3/§1.4 in
// production.
func TestFarmerNKeysColumnContract(t *testing.T) {
	var found *schema.Schema
	for _, m := range pki.Models() {
		sch, err := schema.Parse(m, &sync.Map{}, schema.NamingStrategy{})
		if err != nil {
			t.Fatalf("parsing pki model %T: %v", m, err)
		}
		if "farmer."+sch.Table == farmerNKeysTable {
			found = sch
		}
	}
	if found == nil {
		t.Fatalf("no pki model has table %q", strings.TrimPrefix(farmerNKeysTable, "farmer."))
	}
	for _, col := range []string{"tenant_id", "sprout_id", "state"} {
		if found.LookUpField(col) == nil {
			t.Fatalf("pki_nkeys has no %q column", col)
		}
	}
	var pk []string
	for _, f := range found.PrimaryFields {
		pk = append(pk, f.DBName)
	}
	if fmt.Sprint(pk) != "[tenant_id sprout_id]" {
		t.Fatalf("pki_nkeys primary key = %v, want [tenant_id sprout_id] (the join key)", pk)
	}
}

func linkAssetReq(t *testing.T, tenantID, sproutID string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return doRequest(t, LinkAsset, "POST", "/v1/tenants/"+tenantID+"/sprouts/"+sproutID+"/asset-link",
		map[string]string{"tenant_id": tenantID, "sprout_id": sproutID}, body)
}

func unlinkAssetReq(t *testing.T, tenantID, sproutID string) *httptest.ResponseRecorder {
	t.Helper()
	return doRequest(t, UnlinkAsset, "DELETE", "/v1/tenants/"+tenantID+"/sprouts/"+sproutID+"/asset-link",
		map[string]string{"tenant_id": tenantID, "sprout_id": sproutID}, nil)
}

func listByAssetReq(t *testing.T, tenantID, rawQuery string) *httptest.ResponseRecorder {
	t.Helper()
	return doRequest(t, ListSproutsByAssetIDs, "GET", "/v1/tenants/"+tenantID+"/sprouts?"+rawQuery,
		map[string]string{"tenant_id": tenantID}, nil)
}

func mustLinkAsset(t *testing.T, tenantID, sproutID, assetID string) {
	t.Helper()
	w := linkAssetReq(t, tenantID, sproutID, linkAssetRequest{AssetID: assetID})
	if w.Code != http.StatusCreated {
		t.Fatalf("linking %s→%s: status = %d, body=%s", sproutID, assetID, w.Code, w.Body.String())
	}
}

func decodeSproutsByAsset(t *testing.T, w *httptest.ResponseRecorder) sproutsByAssetResponse {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	var resp sproutsByAssetResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	return resp
}

func assertErrorCode(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status = %d, want %d, body=%s", w.Code, status, w.Body.String())
	}
	var resp errorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding error response: %v", err)
	}
	if resp.Error != code {
		t.Fatalf("error = %q, want %q", resp.Error, code)
	}
}

// --- §1.3 POST .../asset-link ---

func TestLinkAssetCreatesTenantScopedRow(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	tenantID := mustCreateTenant(t, "Acme Bank")
	mustInsertFarmerSprout(t, gdb, tenantID, "s_1", "accepted")

	w := linkAssetReq(t, tenantID, "s_1", linkAssetRequest{AssetID: "  a1 "})
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", w.Code, w.Body.String())
	}
	var resp assetLinkResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp.SproutID != "s_1" || resp.AssetID != "a1" || resp.LinkedAt.IsZero() {
		t.Fatalf("response = %+v, want sprout s_1, asset a1 (trimmed), non-zero linked_at", resp)
	}

	var stored AssetLink
	if err := gdb.First(&stored, "tenant_id = ? AND sprout_id = ?", tenantID, "s_1").Error; err != nil {
		t.Fatalf("loading stored link: %v", err)
	}
	if stored.TenantID != tenantID || stored.AssetID != "a1" || !strings.HasPrefix(stored.ID, assetLinkIDPrefix) {
		t.Fatalf("stored link = %+v", stored)
	}
}

func TestLinkAssetIsIdempotentForSamePair(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	tenantID := mustCreateTenant(t, "Acme Bank")
	mustInsertFarmerSprout(t, gdb, tenantID, "s_1", "accepted")
	mustLinkAsset(t, tenantID, "s_1", "a1")

	w := linkAssetReq(t, tenantID, "s_1", linkAssetRequest{AssetID: "a1"})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an idempotent re-link, body=%s", w.Code, w.Body.String())
	}
	var count int64
	gdb.Model(&AssetLink{}).Count(&count)
	if count != 1 {
		t.Fatalf("asset_links rows = %d, want 1", count)
	}
}

func TestLinkAssetValidation(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	tenantID := mustCreateTenant(t, "Acme Bank")
	mustInsertFarmerSprout(t, gdb, tenantID, "s_1", "accepted")

	for name, body := range map[string]any{
		"missing asset_id": map[string]string{},
		"blank asset_id":   linkAssetRequest{AssetID: "   "},
		"too long":         linkAssetRequest{AssetID: strings.Repeat("a", maxAssetIDLen+1)},
	} {
		t.Run(name, func(t *testing.T) {
			assertErrorCode(t, linkAssetReq(t, tenantID, "s_1", body), http.StatusBadRequest, "invalid_request")
		})
	}

	r := httptest.NewRequest("POST", "/v1/tenants/"+tenantID+"/sprouts/s_1/asset-link", strings.NewReader("{not json"))
	r.SetPathValue("tenant_id", tenantID)
	r.SetPathValue("sprout_id", "s_1")
	w := httptest.NewRecorder()
	LinkAsset(w, r)
	assertErrorCode(t, w, http.StatusBadRequest, "invalid_request")
}

func TestLinkAssetUnknownTenant(t *testing.T) {
	newTestDBWithFarmer(t)
	assertErrorCode(t, linkAssetReq(t, "t_nope", "s_1", linkAssetRequest{AssetID: "a1"}),
		http.StatusNotFound, "tenant_not_found")
}

// TestLinkAssetOtherTenantsSproutIsIndistinguishableFromMissing: linking
// to a sprout that exists under another tenant must produce exactly the
// same response as linking to a sprout that doesn't exist at all, and
// must not create a row.
func TestLinkAssetOtherTenantsSproutIsIndistinguishableFromMissing(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	tenantA := mustCreateTenant(t, "Tenant A")
	tenantB := mustCreateTenant(t, "Tenant B")
	mustInsertFarmerSprout(t, gdb, tenantA, "s_a", "accepted")

	otherTenants := linkAssetReq(t, tenantB, "s_a", linkAssetRequest{AssetID: "a1"})
	missing := linkAssetReq(t, tenantB, "s_nonexistent", linkAssetRequest{AssetID: "a1"})

	assertErrorCode(t, otherTenants, http.StatusNotFound, "sprout_not_found")
	if otherTenants.Body.String() != missing.Body.String() || otherTenants.Code != missing.Code {
		t.Fatalf("another tenant's sprout is distinguishable from a missing one:\nother tenant: %d %s\nmissing:      %d %s",
			otherTenants.Code, otherTenants.Body.String(), missing.Code, missing.Body.String())
	}
	var count int64
	gdb.Model(&AssetLink{}).Count(&count)
	if count != 0 {
		t.Fatalf("asset_links rows = %d, want 0", count)
	}
}

// TestLinkAssetConflictsShareOneBody: every uniqueness collision is the
// same fixed 409, whether the colliding row is the caller's own or
// another tenant's.
func TestLinkAssetConflictsShareOneBody(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	tenantA := mustCreateTenant(t, "Tenant A")
	tenantB := mustCreateTenant(t, "Tenant B")
	mustInsertFarmerSprout(t, gdb, tenantA, "s_a1", "accepted")
	mustInsertFarmerSprout(t, gdb, tenantA, "s_a2", "accepted")
	mustInsertFarmerSprout(t, gdb, tenantB, "s_b1", "accepted")
	mustLinkAsset(t, tenantA, "s_a1", "asset_a")
	mustLinkAsset(t, tenantB, "s_b1", "asset_b")

	sameTenantAsset := linkAssetReq(t, tenantA, "s_a2", linkAssetRequest{AssetID: "asset_a"})
	sameTenantSprout := linkAssetReq(t, tenantA, "s_a1", linkAssetRequest{AssetID: "asset_new"})
	otherTenantAsset := linkAssetReq(t, tenantA, "s_a2", linkAssetRequest{AssetID: "asset_b"})

	assertErrorCode(t, sameTenantAsset, http.StatusConflict, "asset_link_conflict")
	for name, w := range map[string]*httptest.ResponseRecorder{
		"sprout already linked":          sameTenantSprout,
		"asset linked by another tenant": otherTenantAsset,
	} {
		if w.Code != sameTenantAsset.Code || w.Body.String() != sameTenantAsset.Body.String() {
			t.Fatalf("%s: response differs from a same-tenant conflict:\n got: %d %s\nwant: %d %s",
				name, w.Code, w.Body.String(), sameTenantAsset.Code, sameTenantAsset.Body.String())
		}
	}

	var bLink AssetLink
	if err := gdb.First(&bLink, "asset_id = ?", "asset_b").Error; err != nil || bLink.TenantID != tenantB {
		t.Fatalf("tenant B's link was disturbed: %+v, err=%v", bLink, err)
	}
}

// TestLinkAssetSproutUniquenessIsPerTenant: sprout_id is only unique
// within a tenant (matching pki_nkeys), so two tenants' same-named
// sprouts each take their own link, and one tenant linking or unlinking
// its "web-01" never touches the other's.
func TestLinkAssetSproutUniquenessIsPerTenant(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	tenantA := mustCreateTenant(t, "Tenant A")
	tenantB := mustCreateTenant(t, "Tenant B")
	mustInsertFarmerSprout(t, gdb, tenantA, "web-01", "accepted")
	mustInsertFarmerSprout(t, gdb, tenantB, "web-01", "accepted")

	mustLinkAsset(t, tenantA, "web-01", "asset_a")
	mustLinkAsset(t, tenantB, "web-01", "asset_b")

	// Still one asset per sprout within a tenant.
	assertErrorCode(t, linkAssetReq(t, tenantA, "web-01", linkAssetRequest{AssetID: "asset_a2"}),
		http.StatusConflict, "asset_link_conflict")

	if w := unlinkAssetReq(t, tenantA, "web-01"); w.Code != http.StatusOK {
		t.Fatalf("unlink: status = %d, body=%s", w.Code, w.Body.String())
	}
	var bLink AssetLink
	if err := gdb.First(&bLink, "tenant_id = ? AND sprout_id = ?", tenantB, "web-01").Error; err != nil || bLink.AssetID != "asset_b" {
		t.Fatalf("tenant B's web-01 link was disturbed: %+v, err=%v", bLink, err)
	}
}

// --- §1.3 DELETE .../asset-link ---

func TestUnlinkAsset(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	tenantID := mustCreateTenant(t, "Acme Bank")
	mustInsertFarmerSprout(t, gdb, tenantID, "s_1", "accepted")
	mustLinkAsset(t, tenantID, "s_1", "a1")

	if w := unlinkAssetReq(t, tenantID, "s_1"); w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	var count int64
	gdb.Model(&AssetLink{}).Count(&count)
	if count != 0 {
		t.Fatalf("asset_links rows = %d, want 0", count)
	}
	assertErrorCode(t, unlinkAssetReq(t, tenantID, "s_1"), http.StatusNotFound, "asset_link_not_found")

	// Unlinking frees both the sprout and the asset_id for re-linking.
	mustLinkAsset(t, tenantID, "s_1", "a1")
}

func TestUnlinkAssetOtherTenantsLinkIsIndistinguishableFromNone(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	tenantA := mustCreateTenant(t, "Tenant A")
	tenantB := mustCreateTenant(t, "Tenant B")
	mustInsertFarmerSprout(t, gdb, tenantA, "s_a", "accepted")
	mustLinkAsset(t, tenantA, "s_a", "a1")

	otherTenants := unlinkAssetReq(t, tenantB, "s_a")
	never := unlinkAssetReq(t, tenantB, "s_never_linked")

	assertErrorCode(t, otherTenants, http.StatusNotFound, "asset_link_not_found")
	if otherTenants.Code != never.Code || otherTenants.Body.String() != never.Body.String() {
		t.Fatalf("another tenant's link is distinguishable from no link:\nother tenant: %d %s\nnever:        %d %s",
			otherTenants.Code, otherTenants.Body.String(), never.Code, never.Body.String())
	}
	var count int64
	gdb.Model(&AssetLink{}).Where("tenant_id = ?", tenantA).Count(&count)
	if count != 1 {
		t.Fatalf("tenant A's link was deleted by tenant B")
	}
}

// --- §1.4 GET .../sprouts?asset_ids= ---

func TestListSproutsByAssetIDs(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	mr := newTestHeartbeat(t)
	tenantID := mustCreateTenant(t, "Acme Bank")
	mustInsertFarmerSprout(t, gdb, tenantID, "s_1", "accepted")
	mustInsertFarmerSprout(t, gdb, tenantID, "s_2", "accepted")
	mustLinkAsset(t, tenantID, "s_1", "a1")
	mustLinkAsset(t, tenantID, "s_2", "a2")
	markOnline(t, mr, tenantID, "s_1")

	// Repeated and comma-separated forms combine; duplicates and blanks
	// are dropped; order follows the request.
	resp := decodeSproutsByAsset(t, listByAssetReq(t, tenantID, "asset_ids=a2,a17,,a1&asset_ids=a2"))

	want := []sproutByAssetItem{
		{SproutID: "s_2", AssetID: "a2", KeyState: "accepted", Connected: false},
		{SproutID: "s_1", AssetID: "a1", KeyState: "accepted", Connected: true},
	}
	if fmt.Sprint(resp.Results) != fmt.Sprint(want) {
		t.Fatalf("results = %+v, want %+v", resp.Results, want)
	}
	if fmt.Sprint(resp.Unresolved) != "[a17]" {
		t.Fatalf("unresolved = %v, want [a17]", resp.Unresolved)
	}
}

// TestListSproutsByAssetIDsKeyStateAndConnected covers the two-step
// composition: key_state is pki_nkeys.state as-is, and connected is a
// heartbeat read that — like internal/natsapi's sprouts.list — only
// happens for accepted sprouts.
func TestListSproutsByAssetIDsKeyStateAndConnected(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	mr := newTestHeartbeat(t)
	tenantID := mustCreateTenant(t, "Acme Bank")

	cases := []struct {
		sprout, state string
		online        bool
		wantConnected bool
	}{
		{"s-accepted-on", "accepted", true, true},
		{"s-accepted-off", "accepted", false, false},
		{"s-unaccepted", "unaccepted", true, false},
		{"s-denied", "denied", true, false},
		{"s-rejected", "rejected", true, false},
	}
	var ids []string
	for i, c := range cases {
		mustInsertFarmerSprout(t, gdb, tenantID, c.sprout, c.state)
		asset := fmt.Sprintf("asset-%d", i)
		mustLinkAsset(t, tenantID, c.sprout, asset)
		if c.online {
			markOnline(t, mr, tenantID, c.sprout)
		}
		ids = append(ids, asset)
	}

	resp := decodeSproutsByAsset(t, listByAssetReq(t, tenantID, "asset_ids="+strings.Join(ids, ",")))
	if len(resp.Results) != len(cases) {
		t.Fatalf("results = %+v, want %d rows", resp.Results, len(cases))
	}
	for i, c := range cases {
		got := resp.Results[i]
		if got.SproutID != c.sprout || got.KeyState != c.state || got.Connected != c.wantConnected {
			t.Errorf("%s: got %+v, want key_state=%s connected=%v", c.sprout, got, c.state, c.wantConnected)
		}
	}
}

// TestListSproutsByAssetIDsHeartbeatIsTenantScoped: pki_nkeys only keys a
// sprout_id per tenant, so two tenants can each have (and each link) a
// sprout named "web-01". Each tenant's `connected` must reflect only its
// own web-01's heartbeat.
func TestListSproutsByAssetIDsHeartbeatIsTenantScoped(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	mr := newTestHeartbeat(t)
	tenantA := mustCreateTenant(t, "Tenant A")
	tenantB := mustCreateTenant(t, "Tenant B")
	mustInsertFarmerSprout(t, gdb, tenantA, "web-01", "accepted")
	mustInsertFarmerSprout(t, gdb, tenantB, "web-01", "accepted")
	mustLinkAsset(t, tenantA, "web-01", "asset_a")
	mustLinkAsset(t, tenantB, "web-01", "asset_b")
	markOnline(t, mr, tenantB, "web-01")

	respA := decodeSproutsByAsset(t, listByAssetReq(t, tenantA, "asset_ids=asset_a,asset_b"))
	if len(respA.Results) != 1 || respA.Results[0].AssetID != "asset_a" || respA.Results[0].Connected {
		t.Fatalf("tenant A: results = %+v, want only asset_a, not connected", respA.Results)
	}
	respB := decodeSproutsByAsset(t, listByAssetReq(t, tenantB, "asset_ids=asset_a,asset_b"))
	if len(respB.Results) != 1 || respB.Results[0].AssetID != "asset_b" || !respB.Results[0].Connected {
		t.Fatalf("tenant B: results = %+v, want only asset_b, connected", respB.Results)
	}
}

// TestListSproutsByAssetIDsHeartbeatUnavailable: with no heartbeat client
// (or Valkey down — heartbeat.IsOnline treats both the same), lookups
// still succeed, reporting connected=false.
func TestListSproutsByAssetIDsHeartbeatUnavailable(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	heartbeat.SetClient(nil)
	tenantID := mustCreateTenant(t, "Acme Bank")
	mustInsertFarmerSprout(t, gdb, tenantID, "s_1", "accepted")
	mustLinkAsset(t, tenantID, "s_1", "a1")

	resp := decodeSproutsByAsset(t, listByAssetReq(t, tenantID, "asset_ids=a1"))
	if len(resp.Results) != 1 || resp.Results[0].KeyState != "accepted" || resp.Results[0].Connected {
		t.Fatalf("results = %+v, want s_1 accepted and not connected", resp.Results)
	}
}

func TestListSproutsByAssetIDsAlwaysEmitsBothArrays(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	tenantID := mustCreateTenant(t, "Acme Bank")
	mustInsertFarmerSprout(t, gdb, tenantID, "s_1", "accepted")
	mustLinkAsset(t, tenantID, "s_1", "a1")

	if body := listByAssetReq(t, tenantID, "asset_ids=a1").Body.String(); !strings.Contains(body, `"unresolved":[]`) {
		t.Fatalf("expected an empty unresolved array, got %s", body)
	}
	if body := listByAssetReq(t, tenantID, "asset_ids=zz").Body.String(); !strings.Contains(body, `"results":[]`) {
		t.Fatalf("expected an empty results array, got %s", body)
	}
}

// TestListSproutsByAssetIDsNoCrossTenantExistenceLeak is the §1.4
// tenant-isolation property this task was flagged for: from tenant B's
// point of view, an asset_id linked by tenant A must look exactly like
// one nobody ever linked. Proven two ways:
//
//  1. Same query, before vs. after tenant A links the asset: tenant B's
//     response bytes must not change at all.
//  2. Same point in time, an asset linked by A vs. one never linked:
//     each lands in `unresolved`, and swapping the two ids in the
//     request yields the mirror-image response.
func TestListSproutsByAssetIDsNoCrossTenantExistenceLeak(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	mr := newTestHeartbeat(t)
	tenantA := mustCreateTenant(t, "Tenant A")
	tenantB := mustCreateTenant(t, "Tenant B")
	mustInsertFarmerSprout(t, gdb, tenantA, "s_a", "accepted")
	mustInsertFarmerSprout(t, gdb, tenantB, "s_b", "accepted")
	mustLinkAsset(t, tenantB, "s_b", "asset_b")

	const query = "asset_ids=asset_a,asset_b"
	before := listByAssetReq(t, tenantB, query)

	// Tenant A's sprout is linked *and* live, so neither the join nor
	// the heartbeat step has any excuse to be quiet about it.
	mustLinkAsset(t, tenantA, "s_a", "asset_a")
	markOnline(t, mr, tenantA, "s_a")
	after := listByAssetReq(t, tenantB, query)

	if before.Code != after.Code || before.Body.String() != after.Body.String() {
		t.Fatalf("tenant A linking asset_a changed tenant B's response:\nbefore: %d %s\nafter:  %d %s",
			before.Code, before.Body.String(), after.Code, after.Body.String())
	}
	resp := decodeSproutsByAsset(t, after)
	if fmt.Sprint(resp.Unresolved) != "[asset_a]" || len(resp.Results) != 1 || resp.Results[0].AssetID != "asset_b" {
		t.Fatalf("tenant B's response = %+v, want asset_b resolved and asset_a unresolved", resp)
	}
	if strings.Contains(after.Body.String(), "s_a") {
		t.Fatalf("tenant B's response mentions tenant A's sprout: %s", after.Body.String())
	}

	linkedElsewhere := listByAssetReq(t, tenantB, "asset_ids=asset_a,never_linked")
	swapped := listByAssetReq(t, tenantB, "asset_ids=never_linked,asset_a")
	if got := decodeSproutsByAsset(t, linkedElsewhere); fmt.Sprint(got.Unresolved) != "[asset_a never_linked]" || len(got.Results) != 0 {
		t.Fatalf("response = %+v, want both ids unresolved", got)
	}
	mirrored := strings.NewReplacer("asset_a", "never_linked", "never_linked", "asset_a").Replace(swapped.Body.String())
	if mirrored != linkedElsewhere.Body.String() {
		t.Fatalf("an asset linked by another tenant is distinguishable from a never-linked one:\n%s\nvs (mirrored)\n%s",
			linkedElsewhere.Body.String(), mirrored)
	}

	// Tenant A, meanwhile, resolves its own link normally.
	if got := decodeSproutsByAsset(t, listByAssetReq(t, tenantA, "asset_ids=asset_a")); len(got.Results) != 1 || got.Results[0].SproutID != "s_a" {
		t.Fatalf("tenant A's own lookup = %+v, want asset_a→s_a", got)
	}
}

// TestListSproutsByAssetIDsJoinRequiresSproutTenantMatch covers the join
// being on (tenant_id, sprout_id), not sprout_id alone: even a link row
// that LinkAsset would have refused (tenant B's link pointing at tenant
// A's sprout, inserted directly here) must not surface tenant A's sprout
// state to tenant B. Also covers a link whose sprout has vanished from
// pki_nkeys.
func TestListSproutsByAssetIDsJoinRequiresSproutTenantMatch(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	tenantA := mustCreateTenant(t, "Tenant A")
	tenantB := mustCreateTenant(t, "Tenant B")
	mustInsertFarmerSprout(t, gdb, tenantA, "s_a", "accepted")

	for _, l := range []AssetLink{
		{ID: "al_bad", TenantID: tenantB, SproutID: "s_a", AssetID: "asset_x", LinkedAt: time.Now()},
		{ID: "al_gone", TenantID: tenantB, SproutID: "s_gone", AssetID: "asset_y", LinkedAt: time.Now()},
	} {
		if err := gdb.Create(&l).Error; err != nil {
			t.Fatalf("inserting link: %v", err)
		}
	}

	resp := decodeSproutsByAsset(t, listByAssetReq(t, tenantB, "asset_ids=asset_x,asset_y"))
	if len(resp.Results) != 0 || fmt.Sprint(resp.Unresolved) != "[asset_x asset_y]" {
		t.Fatalf("response = %+v, want both unresolved", resp)
	}
}

func TestListSproutsByAssetIDsCap(t *testing.T) {
	newTestDBWithFarmer(t)
	tenantID := mustCreateTenant(t, "Acme Bank")

	ids := func(n int) string {
		parts := make([]string, n)
		for i := range parts {
			parts[i] = fmt.Sprintf("a%d", i)
		}
		return strings.Join(parts, ",")
	}

	resp := decodeSproutsByAsset(t, listByAssetReq(t, tenantID, "asset_ids="+ids(maxAssetIDsPerLookup)))
	if len(resp.Unresolved) != maxAssetIDsPerLookup {
		t.Fatalf("unresolved = %d ids, want %d", len(resp.Unresolved), maxAssetIDsPerLookup)
	}

	assertErrorCode(t, listByAssetReq(t, tenantID, "asset_ids="+ids(maxAssetIDsPerLookup+1)),
		http.StatusBadRequest, "too_many_asset_ids")

	// The cap counts ids as supplied, across repeated params and
	// including duplicates.
	split := "asset_ids=" + ids(60) + "&asset_ids=" + ids(41)
	assertErrorCode(t, listByAssetReq(t, tenantID, split), http.StatusBadRequest, "too_many_asset_ids")
	dupes := "asset_ids=" + strings.TrimSuffix(strings.Repeat("a1,", maxAssetIDsPerLookup+1), ",")
	assertErrorCode(t, listByAssetReq(t, tenantID, dupes), http.StatusBadRequest, "too_many_asset_ids")
}

func TestListSproutsByAssetIDsValidation(t *testing.T) {
	newTestDBWithFarmer(t)
	tenantID := mustCreateTenant(t, "Acme Bank")

	for name, q := range map[string]string{
		"missing":  "",
		"blank":    "asset_ids=",
		"commas":   "asset_ids=,,%20,",
		"too long": "asset_ids=" + url.QueryEscape(strings.Repeat("a", maxAssetIDLen+1)),
	} {
		t.Run(name, func(t *testing.T) {
			assertErrorCode(t, listByAssetReq(t, tenantID, q), http.StatusBadRequest, "invalid_request")
		})
	}

	assertErrorCode(t, listByAssetReq(t, "t_nope", "asset_ids=a1"), http.StatusNotFound, "tenant_not_found")
}

// TestRouterAssetLinkRoutes checks the three routes are wired through
// NewRouter (and so through Auth): a matching token reaches the handler,
// and a token for a different tenant is refused by Auth before it does.
func TestRouterAssetLinkRoutes(t *testing.T) {
	gdb := newTestDBWithFarmer(t)
	auth := newTestAuthEnv(t)
	mux := NewRouter()
	tenantA := mustCreateTenant(t, "Tenant A")
	tenantB := mustCreateTenant(t, "Tenant B")
	mustInsertFarmerSprout(t, gdb, tenantA, "s_a", "accepted")

	serve := func(method, path, body, tokenTenant string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		auth.setAuthHeaders(r, tokenTenant)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}

	base := "/v1/tenants/" + tenantA + "/sprouts"
	if w := serve("POST", base+"/s_a/asset-link", `{"asset_id":"a1"}`, tenantA); w.Code != http.StatusCreated {
		t.Fatalf("POST: status = %d, want 201, body=%s", w.Code, w.Body.String())
	}
	if w := serve("GET", base+"?asset_ids=a1", "", tenantA); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"sprout_id":"s_a"`) {
		t.Fatalf("GET: status = %d, body=%s", w.Code, w.Body.String())
	}
	for _, c := range []struct{ method, path, body string }{
		{"GET", base + "?asset_ids=a1", ""},
		{"POST", base + "/s_a/asset-link", `{"asset_id":"a2"}`},
		{"DELETE", base + "/s_a/asset-link", ""},
	} {
		if w := serve(c.method, c.path, c.body, tenantB); w.Code != http.StatusForbidden {
			t.Fatalf("%s %s with tenant B's token: status = %d, want 403, body=%s", c.method, c.path, w.Code, w.Body.String())
		}
	}
	if w := serve("DELETE", base+"/s_a/asset-link", "", tenantA); w.Code != http.StatusOK {
		t.Fatalf("DELETE: status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
}
