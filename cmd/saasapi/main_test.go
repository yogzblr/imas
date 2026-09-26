package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/valkey-io/valkey-go"

	"github.com/yogzblr/imas/internal/heartbeat"
	"github.com/yogzblr/imas/internal/saasapi"
)

// newOnlineSproutStore returns a miniredis holding the heartbeat key farmer's
// listener would write for tenantID/sproutID. internal/heartbeat's key
// format is unexported, so it's repeated here; the wired case below fails
// if it ever drifts.
func newOnlineSproutStore(t *testing.T, tenantID, sproutID string) *miniredis.Miniredis {
	t.Helper()
	mr := miniredis.RunT(t)
	if err := mr.Set("imas:heartbeat:"+tenantID+":"+sproutID, "1"); err != nil {
		t.Fatalf("setting heartbeat key: %v", err)
	}
	return mr
}

func resetHeartbeatClient(t *testing.T) {
	t.Helper()
	heartbeat.SetClient(nil)
	t.Cleanup(func() { heartbeat.SetClient(nil) })
}

// TestInitHeartbeatClientWired: with a Valkey client (SAASAPI_VALKEY_ADDRS
// set), heartbeat.IsOnline reads live keys through it.
func TestInitHeartbeatClientWired(t *testing.T) {
	resetHeartbeatClient(t)
	mr := newOnlineSproutStore(t, "t_acme", "web-01")
	vc, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{mr.Addr()}, DisableCache: true})
	if err != nil {
		t.Fatalf("creating valkey client: %v", err)
	}
	t.Cleanup(vc.Close)

	initHeartbeatClient(vc)

	ctx := context.Background()
	if !heartbeat.IsOnline(ctx, "t_acme", "web-01") {
		t.Fatal("IsOnline = false for a sprout with a live heartbeat key; client not wired")
	}
	if heartbeat.IsOnline(ctx, "t_acme", "web-02") {
		t.Fatal("IsOnline = true for a sprout with no heartbeat key")
	}
	if heartbeat.IsOnline(ctx, "t_other", "web-01") {
		t.Fatal("IsOnline = true for another tenant's same-named sprout")
	}
}

// TestInitHeartbeatClientUnwired: with SAASAPI_VALKEY_ADDRS unset, main's vc
// is nil. initHeartbeatClient must not panic and must leave heartbeat
// unwired, so IsOnline degrades to false — even for a sprout that a
// reachable Valkey would report as online.
func TestInitHeartbeatClientUnwired(t *testing.T) {
	resetHeartbeatClient(t)
	newOnlineSproutStore(t, "t_acme", "web-01")

	initHeartbeatClient(nil)

	if heartbeat.IsOnline(context.Background(), "t_acme", "web-01") {
		t.Fatal("IsOnline = true with no Valkey client configured; want false (connected: false)")
	}
}

// TestNewRouterFleetUpdateRoutes: the §1.8 dispatch routes are registered
// if and only if SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED is true, going
// through the same LoadConfig → newRouter path main uses. The catalog and
// policy routes are always there.
func TestNewRouterFleetUpdateRoutes(t *testing.T) {
	t.Cleanup(func() { saasapi.SetFleetUpdateDispatchEnabled(false) })

	dispatch := []struct{ method, path string }{
		{"POST", "/v1/tenants/t_acme/sprouts/updates"},
		{"GET", "/v1/tenants/t_acme/sprouts/updates/b_1"},
	}
	always := []struct{ method, path string }{
		{"GET", "/v1/versions"},
		{"PATCH", "/v1/tenants/t_acme/update-policy"},
	}
	registered := func(mux *http.ServeMux, method, path string) bool {
		_, pattern := mux.Handler(httptest.NewRequest(method, path, nil))
		return pattern != ""
	}

	for env, want := range map[string]bool{"": false, "false": false, "0": false, "true": true, "1": true} {
		t.Run("env="+env, func(t *testing.T) {
			t.Setenv("SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED", env)
			cfg, err := saasapi.LoadConfig()
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			mux := newRouter(cfg)
			for _, r := range dispatch {
				if got := registered(mux, r.method, r.path); got != want {
					t.Errorf("%s %s registered = %t, want %t", r.method, r.path, got, want)
				}
			}
			for _, r := range always {
				if !registered(mux, r.method, r.path) {
					t.Errorf("%s %s not registered", r.method, r.path)
				}
			}
		})
	}
}
