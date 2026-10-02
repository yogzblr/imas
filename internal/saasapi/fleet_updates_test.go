package saasapi

import (
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// newFleetTestDB is newTestDB with an empty fleet_versions catalog.
// Unlike every other table here, the catalog isn't keyed by a random
// tenant id, so rows another test left in the shared in-memory database
// would show up in this one's results.
func newFleetTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	gdb := newTestDB(t)
	empty := func() {
		if err := gdb.Where("1 = 1").Delete(&FleetVersion{}).Error; err != nil {
			t.Fatalf("clearing fleet_versions: %v", err)
		}
	}
	empty()
	t.Cleanup(empty)
	return gdb
}

func mustPublishVersion(t *testing.T, gdb *gorm.DB, version string, releasedAt time.Time) FleetVersion {
	t.Helper()
	return mustPublishVersionFor(t, gdb, version, "linux", "amd64", releasedAt)
}

// mustPublishVersionFor registers version's package for osName/arch, signed
// with the test fleet key, as the operator plane would.
func mustPublishVersionFor(t *testing.T, gdb *gorm.DB, version, osName, arch string, releasedAt time.Time) FleetVersion {
	t.Helper()
	id, err := newID("fv_")
	if err != nil {
		t.Fatalf("generating fleet version id: %v", err)
	}
	pkgType := "deb"
	if osName == "windows" {
		pkgType = "msi"
	}
	v := FleetVersion{
		ID:               id,
		Version:          version,
		OS:               osName,
		Arch:             arch,
		PackageType:      pkgType,
		FileName:         "imas-sprout_" + strings.TrimPrefix(version, "v") + "_" + arch + "." + pkgType,
		ChecksumSHA256:   strings.Repeat("ab", 32),
		MinSproutVersion: "v0.0.0",
		ReleasedAt:       releasedAt.UTC(),
		Notes:            "notes for " + version,
	}
	v.Signature = signTestRelease(t, v)
	if err := gdb.Create(&v).Error; err != nil {
		t.Fatalf("publishing %s %s/%s: %v", version, osName, arch, err)
	}
	return v
}

// patchPolicy sends a raw JSON body, so tests can express absent vs.
// null fields exactly.
func patchPolicy(t *testing.T, tenantID, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("PATCH", "/v1/tenants/"+tenantID+"/update-policy", strings.NewReader(body))
	r.SetPathValue("tenant_id", tenantID)
	w := httptest.NewRecorder()
	PatchUpdatePolicy(w, r)
	return w
}

func getPolicy(t *testing.T, tenantID string) *httptest.ResponseRecorder {
	t.Helper()
	return doRequest(t, GetUpdatePolicy, "GET", "/v1/tenants/"+tenantID+"/update-policy",
		map[string]string{"tenant_id": tenantID}, nil)
}

func decodePolicy(t *testing.T, w *httptest.ResponseRecorder) updatePolicyResponse {
	t.Helper()
	var resp updatePolicyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding policy response %s: %v", w.Body.String(), err)
	}
	return resp
}

func wantError(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status = %d, want %d, body=%s", w.Code, status, w.Body.String())
	}
	var errResp errorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("decoding error response: %v", err)
	}
	if errResp.Error != code {
		t.Fatalf("error code = %q, want %q (message %q)", errResp.Error, code, errResp.Message)
	}
}

func TestListFleetVersionsEmpty(t *testing.T) {
	newFleetTestDB(t)
	w := doRequest(t, ListFleetVersions, "GET", "/v1/versions", nil, nil)
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	if got := strings.TrimSpace(w.Body.String()); got != `{"versions":[]}` {
		t.Fatalf("body = %s, want an empty (non-null) versions list", got)
	}
}

func TestListFleetVersionsNewestFirstWithoutSignature(t *testing.T) {
	gdb := newFleetTestDB(t)
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	mustPublishVersion(t, gdb, "v2.4.0", base)
	mustPublishVersion(t, gdb, "v2.4.2", base.Add(48*time.Hour))
	mustPublishVersion(t, gdb, "v2.4.1", base.Add(24*time.Hour))

	w := doRequest(t, ListFleetVersions, "GET", "/v1/versions", nil, nil)
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	for _, leaked := range []string{"artifact_url", "signature", `"id"`, "fv_"} {
		if strings.Contains(w.Body.String(), leaked) {
			t.Fatalf("response contains %q: %s", leaked, w.Body.String())
		}
	}

	var resp struct {
		Versions []fleetVersionItem `json:"versions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	var got []string
	for _, v := range resp.Versions {
		got = append(got, v.Version)
	}
	if strings.Join(got, ",") != "v2.4.2,v2.4.1,v2.4.0" {
		t.Fatalf("versions = %v, want newest first", got)
	}
	first := resp.Versions[0]
	if first != (fleetVersionItem{Version: "v2.4.2", OS: "linux", Arch: "amd64", PackageType: "deb",
		FileName: "imas-sprout_2.4.2_amd64.deb", ChecksumSHA256: strings.Repeat("ab", 32), MinSproutVersion: "v0.0.0",
		ReleasedAt: first.ReleasedAt, Notes: "notes for v2.4.2"}) || !first.ReleasedAt.Equal(base.Add(48*time.Hour)) {
		t.Fatalf("unexpected entry %+v", first)
	}
}

// One entry per OS/arch, and a revoked version is listed as revoked.
func TestListFleetVersionsPerOSArchAndRevoked(t *testing.T) {
	gdb := newFleetTestDB(t)
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	mustPublishVersion(t, gdb, "v2.4.1", at)
	mustPublishVersionFor(t, gdb, "v2.4.1", "linux", "arm64", at)
	mustPublishVersionFor(t, gdb, "v2.4.1", "windows", "amd64", at)
	gdb.Model(&FleetVersion{}).Where("version = ?", "v2.4.1").Update("revoked", true)

	w := doRequest(t, ListFleetVersions, "GET", "/v1/versions", nil, nil)
	var resp struct {
		Versions []fleetVersionItem `json:"versions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, v := range resp.Versions {
		got = append(got, v.OS+"/"+v.Arch+"/"+v.PackageType+"/"+strconv.FormatBool(v.Revoked))
	}
	if strings.Join(got, ",") != "linux/amd64/deb/true,linux/arm64/deb/true,windows/amd64/msi/true" {
		t.Fatalf("entries = %v", got)
	}
}

// UNIQUE(version, os, arch, package_type): one row per package of a
// version; a .deb and an .rpm of the same OS/arch are two rows.
func TestFleetVersionUniqueVersionOSArchPackageType(t *testing.T) {
	gdb := newFleetTestDB(t)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	mustPublishVersionFor(t, gdb, "v2.4.1", "linux", "arm64", time.Now())
	mustPublishVersionFor(t, gdb, "v2.4.2", "linux", "amd64", time.Now())
	quiet := gdb.Session(&gorm.Session{Logger: gdb.Logger.LogMode(gormlogger.Silent)})
	rpm := FleetVersion{ID: "fv_rpm", Version: "v2.4.1", OS: "linux", Arch: "amd64", PackageType: "rpm",
		FileName: "x.rpm", ChecksumSHA256: "y", MinSproutVersion: "v0.0.0", ReleasedAt: time.Now()}
	if err := quiet.Create(&rpm).Error; err != nil {
		t.Fatalf("fleet_versions refused an rpm beside the deb of the same version, os and arch: %v", err)
	}
	dup := rpm
	dup.ID, dup.FileName = "fv_dup", "z.rpm"
	if err := quiet.Create(&dup).Error; err == nil {
		t.Fatal("fleet_versions accepted a second row for the same version, os, arch and package_type")
	}
}

func TestGetUpdatePolicyDefault(t *testing.T) {
	newFleetTestDB(t)
	id := mustCreateTenant(t, "Acme Bank")

	w := getPolicy(t, id)
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	resp := decodePolicy(t, w)
	if resp.TenantID != id || resp.ApprovedVersion != nil || resp.AutoUpdate ||
		resp.RolloutWindowStart != nil || resp.RolloutWindowEnd != nil || resp.UpdatedAt != nil {
		t.Fatalf("default policy = %+v, want nothing approved and auto_update off", resp)
	}
	// Unset fields are explicit nulls, not omitted.
	for _, field := range []string{`"approved_version":null`, `"rollout_window_start":null`, `"rollout_window_end":null`} {
		if !strings.Contains(w.Body.String(), field) {
			t.Fatalf("body %s lacks %s", w.Body.String(), field)
		}
	}
}

func TestUpdatePolicyUnknownTenant(t *testing.T) {
	newFleetTestDB(t)
	wantError(t, getPolicy(t, "t_nope"), 404, "tenant_not_found")
	wantError(t, patchPolicy(t, "t_nope", `{"auto_update":false}`), 404, "tenant_not_found")
}

func TestPatchUpdatePolicySetAndGet(t *testing.T) {
	gdb := newFleetTestDB(t)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	id := mustCreateTenant(t, "Acme Bank")

	w := patchPolicy(t, id, `{"approved_version":" v2.4.1 ","auto_update":true}`)
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200, body=%s", w.Code, w.Body.String())
	}
	resp := decodePolicy(t, w)
	if resp.TenantID != id || resp.ApprovedVersion == nil || *resp.ApprovedVersion != "v2.4.1" || !resp.AutoUpdate {
		t.Fatalf("patched policy = %+v", resp)
	}
	if resp.UpdatedAt == nil || resp.UpdatedAt.IsZero() {
		t.Fatalf("updated_at not set: %+v", resp)
	}

	got := decodePolicy(t, getPolicy(t, id))
	if got.ApprovedVersion == nil || *got.ApprovedVersion != "v2.4.1" || !got.AutoUpdate {
		t.Fatalf("GET after PATCH = %+v", got)
	}

	var rows int64
	gdb.Model(&TenantUpdatePolicy{}).Where("tenant_id = ?", id).Count(&rows)
	if rows != 1 {
		t.Fatalf("tenant_update_policy rows = %d, want 1", rows)
	}
}

func TestPatchUpdatePolicyPartialKeepsOtherFields(t *testing.T) {
	gdb := newFleetTestDB(t)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	mustPublishVersion(t, gdb, "v2.4.2", time.Now())
	id := mustCreateTenant(t, "Acme Bank")

	window := `"rollout_window_start":"2026-10-01T02:00:00+02:00","rollout_window_end":"2026-10-01T06:00:00+02:00"`
	if w := patchPolicy(t, id, `{"approved_version":"v2.4.1","auto_update":true,`+window+`}`); w.Code != 200 {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	w := patchPolicy(t, id, `{"approved_version":"v2.4.2"}`)
	if w.Code != 200 {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	resp := decodePolicy(t, w)
	wantStart := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if *resp.ApprovedVersion != "v2.4.2" || !resp.AutoUpdate ||
		resp.RolloutWindowStart == nil || !resp.RolloutWindowStart.Equal(wantStart) ||
		resp.RolloutWindowEnd == nil || !resp.RolloutWindowEnd.Equal(wantStart.Add(4*time.Hour)) {
		t.Fatalf("policy after partial PATCH = %+v", resp)
	}
	if resp.RolloutWindowStart.Location() != time.UTC {
		t.Fatalf("rollout_window_start not normalized to UTC: %v", resp.RolloutWindowStart)
	}
}

func TestPatchUpdatePolicyClear(t *testing.T) {
	gdb := newFleetTestDB(t)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	id := mustCreateTenant(t, "Acme Bank")

	body := `{"approved_version":"v2.4.1","rollout_window_start":"2026-10-01T00:00:00Z","rollout_window_end":"2026-10-02T00:00:00Z"}`
	if w := patchPolicy(t, id, body); w.Code != 200 {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	w := patchPolicy(t, id, `{"approved_version":null,"rollout_window_start":null,"rollout_window_end":null}`)
	if w.Code != 200 {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	resp := decodePolicy(t, w)
	if resp.ApprovedVersion != nil || resp.RolloutWindowStart != nil || resp.RolloutWindowEnd != nil {
		t.Fatalf("policy after clearing = %+v", resp)
	}
}

// TestPatchUpdatePolicyAutoUpdateNeedsApproval pins §1.8's opt-in rule:
// auto_update can't be on without an approved version, whether that's
// asked for directly or reached by clearing the version afterwards.
func TestPatchUpdatePolicyAutoUpdateNeedsApproval(t *testing.T) {
	gdb := newFleetTestDB(t)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	id := mustCreateTenant(t, "Acme Bank")

	wantError(t, patchPolicy(t, id, `{"auto_update":true}`), 400, "invalid_request")
	wantError(t, patchPolicy(t, id, `{"approved_version":null,"auto_update":true}`), 400, "invalid_request")

	if w := patchPolicy(t, id, `{"approved_version":"v2.4.1","auto_update":true}`); w.Code != 200 {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	wantError(t, patchPolicy(t, id, `{"approved_version":null}`), 400, "invalid_request")

	got := decodePolicy(t, getPolicy(t, id))
	if got.ApprovedVersion == nil || *got.ApprovedVersion != "v2.4.1" || !got.AutoUpdate {
		t.Fatalf("rejected PATCH changed the policy: %+v", got)
	}

	// Clearing both together is fine.
	w := patchPolicy(t, id, `{"approved_version":null,"auto_update":false}`)
	if w.Code != 200 {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
}

func TestPatchUpdatePolicyUnknownVersion(t *testing.T) {
	gdb := newFleetTestDB(t)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	id := mustCreateTenant(t, "Acme Bank")

	wantError(t, patchPolicy(t, id, `{"approved_version":"v9.9.9"}`), 400, "unknown_version")

	var rows int64
	gdb.Model(&TenantUpdatePolicy{}).Where("tenant_id = ?", id).Count(&rows)
	if rows != 0 {
		t.Fatalf("a rejected PATCH left %d tenant_update_policy rows", rows)
	}
}

func TestPatchUpdatePolicyInvalidRequests(t *testing.T) {
	gdb := newFleetTestDB(t)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	id := mustCreateTenant(t, "Acme Bank")

	cases := map[string]string{
		"not JSON":                 `{`,
		"no fields":                `{}`,
		"unknown fields only":      `{"approved_versoin":"v2.4.1"}`,
		"null auto_update":         `{"auto_update":null}`,
		"wrong type":               `{"auto_update":"yes"}`,
		"empty version":            `{"approved_version":"  "}`,
		"version too long":         `{"approved_version":"` + strings.Repeat("v", maxFleetVersionLen+1) + `"}`,
		"bad timestamp":            `{"rollout_window_start":"tomorrow","rollout_window_end":"2026-10-02T00:00:00Z"}`,
		"start without end":        `{"rollout_window_start":"2026-10-01T00:00:00Z"}`,
		"end without start":        `{"rollout_window_end":"2026-10-01T00:00:00Z"}`,
		"end before start":         `{"rollout_window_start":"2026-10-02T00:00:00Z","rollout_window_end":"2026-10-01T00:00:00Z"}`,
		"empty window":             `{"rollout_window_start":"2026-10-01T00:00:00Z","rollout_window_end":"2026-10-01T00:00:00Z"}`,
		"end equal across offsets": `{"rollout_window_start":"2026-10-01T02:00:00+02:00","rollout_window_end":"2026-10-01T00:00:00Z"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			wantError(t, patchPolicy(t, id, body), 400, "invalid_request")
		})
	}

	// Clearing one bound of an existing window leaves a half-open one.
	if w := patchPolicy(t, id, `{"rollout_window_start":"2026-10-01T00:00:00Z","rollout_window_end":"2026-10-02T00:00:00Z"}`); w.Code != 200 {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	wantError(t, patchPolicy(t, id, `{"rollout_window_end":null}`), 400, "invalid_request")
}

// TestUpdatePolicyTenantIsolation: one tenant's PATCH never touches
// another tenant's policy.
func TestUpdatePolicyTenantIsolation(t *testing.T) {
	gdb := newFleetTestDB(t)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	mustPublishVersion(t, gdb, "v2.4.2", time.Now())
	a := mustCreateTenant(t, "Tenant A")
	b := mustCreateTenant(t, "Tenant B")

	if w := patchPolicy(t, a, `{"approved_version":"v2.4.1","auto_update":true}`); w.Code != 200 {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	if w := getPolicy(t, b); decodePolicy(t, w).ApprovedVersion != nil {
		t.Fatalf("tenant B sees tenant A's policy: %s", w.Body.String())
	}
	if w := patchPolicy(t, b, `{"approved_version":"v2.4.2"}`); w.Code != 200 {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	got := decodePolicy(t, getPolicy(t, a))
	if *got.ApprovedVersion != "v2.4.1" || !got.AutoUpdate {
		t.Fatalf("tenant A's policy changed after tenant B's PATCH: %+v", got)
	}
}

func TestPatchFieldUnmarshal(t *testing.T) {
	var req patchUpdatePolicyRequest
	if err := json.Unmarshal([]byte(`{"approved_version":null,"auto_update":false}`), &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !req.ApprovedVersion.Set || req.ApprovedVersion.Value != nil {
		t.Fatalf("null approved_version = %+v, want set and nil", req.ApprovedVersion)
	}
	if !req.AutoUpdate.Set || req.AutoUpdate.Value == nil || *req.AutoUpdate.Value {
		t.Fatalf("auto_update = %+v, want set to false", req.AutoUpdate)
	}
	if req.RolloutWindowStart.Set || req.RolloutWindowEnd.Set {
		t.Fatalf("absent window fields marked set: %+v / %+v", req.RolloutWindowStart, req.RolloutWindowEnd)
	}
}

// TestRouterFleetUpdateRoutes runs the §1.8 routes through NewRouter:
// the catalog needs no organization match, the policy routes do, and the
// dispatch routes aren't registered while their feature flag is off (the
// default).
func TestRouterFleetUpdateRoutes(t *testing.T) {
	gdb := newFleetTestDB(t)
	auth := newTestAuthEnv(t)
	mustPublishVersion(t, gdb, "v2.4.1", time.Now())
	a := mustCreateTenant(t, "Tenant A")
	b := mustCreateTenant(t, "Tenant B")
	mux := NewRouter()

	serve := func(method, path, body, tokenTenant string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		auth.setAuthHeaders(r, tokenTenant)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}

	if w := serve("GET", "/v1/versions", "", a); w.Code != 200 || !strings.Contains(w.Body.String(), "v2.4.1") {
		t.Fatalf("GET /v1/versions: status = %d, body=%s", w.Code, w.Body.String())
	}

	unauth := httptest.NewRecorder()
	mux.ServeHTTP(unauth, httptest.NewRequest("GET", "/v1/versions", nil))
	if unauth.Code != 401 {
		t.Fatalf("unauthenticated GET /v1/versions: status = %d, want 401", unauth.Code)
	}

	if w := serve("PATCH", "/v1/tenants/"+a+"/update-policy", `{"approved_version":"v2.4.1"}`, a); w.Code != 200 {
		t.Fatalf("PATCH own policy: status = %d, body=%s", w.Code, w.Body.String())
	}
	if w := serve("GET", "/v1/tenants/"+a+"/update-policy", "", a); w.Code != 200 {
		t.Fatalf("GET own policy: status = %d, body=%s", w.Code, w.Body.String())
	}
	if w := serve("GET", "/v1/tenants/"+a+"/update-policy", "", b); w.Code != 403 {
		t.Fatalf("GET another tenant's policy: status = %d, want 403", w.Code)
	}
	if w := serve("PATCH", "/v1/tenants/"+a+"/update-policy", `{"approved_version":null}`, b); w.Code != 403 {
		t.Fatalf("PATCH another tenant's policy: status = %d, want 403", w.Code)
	}

	for _, req := range []struct{ method, path string }{
		{"POST", "/v1/tenants/" + a + "/sprouts/updates"},
		{"GET", "/v1/tenants/" + a + "/sprouts/updates/b_1"},
	} {
		if w := serve(req.method, req.path, `{}`, a); w.Code != 404 && w.Code != 405 {
			t.Fatalf("%s %s: status = %d, want it unregistered", req.method, req.path, w.Code)
		}
	}
}
