package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// memDBSeq numbers this package's in-memory sqlite test databases, so
// a DSN never repeats across `go test -count=N` runs of the same test.
var memDBSeq atomic.Int64

// openTestPXC returns a real *gorm.DB (in-memory SQLite, standing in for
// PXC the way internal/heartbeat's and internal/pki's tests do).
func openTestPXC(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"-"+strconv.FormatInt(memDBSeq.Add(1), 10)+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("opening test db: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sqlDB.Close() })
	return db
}

// setReadyDeps installs readiness dependencies for one test and restores
// the previous ones afterward. Valkey is stubbed at the ping level: see
// the comment on the readiness vars in ready.go.
func setReadyDeps(t *testing.T, db *gorm.DB, valkey func(context.Context) error, stats func() TenantConnStats) {
	t.Helper()
	origPXC, origValkey, origStats := pxcPing, loadValkeyPing(), tenantStats
	t.Cleanup(func() { pxcPing, tenantStats = origPXC, origStats; setValkeyPing(origValkey) })
	SetReadinessDB(db)
	setValkeyPing(valkey)
	SetTenantConnStats(stats)
}

func valkeyUp(context.Context) error { return nil }

func valkeyDown(context.Context) error {
	return errors.New("dial tcp 127.0.0.1:6379: connect: connection refused")
}

func allTenantsUp() TenantConnStats {
	return TenantConnStats{LegacyReady: true, Connected: 3, Total: 3}
}

func getReady(t *testing.T) (int, ReadyResponse) {
	t.Helper()
	w := httptest.NewRecorder()
	GetReady(w, httptest.NewRequest(http.MethodGet, "/ready", nil))
	resp := w.Result()
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var body ReadyResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decoding /ready response: %v", err)
	}
	return resp.StatusCode, body
}

func TestGetReady_AllUp(t *testing.T) {
	setReadyDeps(t, openTestPXC(t), valkeyUp, allTenantsUp)

	code, body := getReady(t)
	want := ReadyResponse{
		Status: "ready", PXC: "ok", Valkey: "ok", LegacyTenant: "ok",
		TenantsConnected: 3, TenantsTotal: 3,
	}
	if code != http.StatusOK {
		t.Errorf("status code = %d, want 200", code)
	}
	if body != want {
		t.Errorf("body = %+v, want %+v", body, want)
	}
}

func TestGetReady_PXCDown(t *testing.T) {
	db := openTestPXC(t)
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.Close() // every later ping fails, as with an unreachable PXC
	setReadyDeps(t, db, valkeyUp, allTenantsUp)

	code, body := getReady(t)
	if code != http.StatusServiceUnavailable {
		t.Errorf("status code = %d, want 503", code)
	}
	if body.Status != "not_ready" {
		t.Errorf("status = %q, want not_ready", body.Status)
	}
	if body.PXC == "ok" || body.PXC == "" {
		t.Errorf("pxc = %q, want the ping error", body.PXC)
	}
	if body.Valkey != "ok" {
		t.Errorf("valkey = %q, want ok", body.Valkey)
	}
}

func TestGetReady_ValkeyDown(t *testing.T) {
	setReadyDeps(t, openTestPXC(t), valkeyDown, allTenantsUp)

	code, body := getReady(t)
	if code != http.StatusServiceUnavailable {
		t.Errorf("status code = %d, want 503", code)
	}
	if body.Status != "not_ready" {
		t.Errorf("status = %q, want not_ready", body.Status)
	}
	if want := valkeyDown(context.Background()).Error(); body.Valkey != want {
		t.Errorf("valkey = %q, want %q", body.Valkey, want)
	}
	if body.PXC != "ok" {
		t.Errorf("pxc = %q, want ok", body.PXC)
	}
}

// The per-tenant decision documented on GetReady: one dynamically
// provisioned tenant's connection being down is reported, not gated on.
func TestGetReady_OneTenantDownStaysReady(t *testing.T) {
	setReadyDeps(t, openTestPXC(t), valkeyUp, func() TenantConnStats {
		return TenantConnStats{LegacyReady: true, Connected: 2, Total: 3}
	})

	code, body := getReady(t)
	if code != http.StatusOK {
		t.Errorf("status code = %d, want 200", code)
	}
	if body.Status != "ready" {
		t.Errorf("status = %q, want ready", body.Status)
	}
	if body.TenantsConnected != 2 || body.TenantsTotal != 3 {
		t.Errorf("tenants = %d/%d, want 2/3", body.TenantsConnected, body.TenantsTotal)
	}
}

// Before the legacy tenant's boot-time connect finishes, the pod isn't
// ready yet, even though PXC and Valkey are.
func TestGetReady_LegacyTenantStillConnecting(t *testing.T) {
	setReadyDeps(t, openTestPXC(t), valkeyUp, func() TenantConnStats {
		return TenantConnStats{LegacyReady: false, Connected: 0, Total: 1}
	})

	code, body := getReady(t)
	if code != http.StatusServiceUnavailable {
		t.Errorf("status code = %d, want 503", code)
	}
	if body.Status != "not_ready" || body.LegacyTenant != "connecting" {
		t.Errorf("status/legacy_tenant = %q/%q, want not_ready/connecting", body.Status, body.LegacyTenant)
	}
}

// Missing wiring fails closed rather than reporting ready.
func TestGetReady_NotConfigured(t *testing.T) {
	setReadyDeps(t, nil, nil, nil)
	SetReadinessValkey(nil)

	code, body := getReady(t)
	want := ReadyResponse{
		Status: "not_ready", PXC: "not configured", Valkey: "connecting",
		LegacyTenant: "not configured",
	}
	if code != http.StatusServiceUnavailable {
		t.Errorf("status code = %d, want 503", code)
	}
	if body != want {
		t.Errorf("body = %+v, want %+v", body, want)
	}
}

// /health never checks reachability: with a Valkey client installed it
// reports ok even when Valkey, PXC, and every tenant connection are down,
// so a shared-dependency outage can't restart every replica at once.
func TestGetHealth_IgnoresDependencyReachability(t *testing.T) {
	setReadyDeps(t, nil, valkeyDown, func() TenantConnStats { return TenantConnStats{} })

	w := httptest.NewRecorder()
	GetHealth(w, httptest.NewRequest(http.MethodGet, "/health", nil))
	if w.Code != http.StatusOK {
		t.Errorf("GET /health = %d, want 200", w.Code)
	}
	var body HealthResponse
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "ok" || body.Valkey != "ok" {
		t.Errorf("status/valkey = %q/%q, want ok/ok", body.Status, body.Valkey)
	}
}
