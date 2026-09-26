package handlers

// GET /ready — farmer's Kubernetes readiness signal, the counterpart to
// GetHealth's liveness GET /health (health.go). /health stays cheap and
// never checks whether a dependency is reachable: a liveness probe that
// pinged PXC or Valkey would get every replica restarted during a
// shared-dependency outage, which fixes nothing. (It does check that a
// Valkey client exists at all; see GetHealth.) /ready is what should flip
// instead — it tells Kubernetes whether to route to this replica, and
// whether a rolling deployment's new pod is safe to proceed on.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/valkey-io/valkey-go"
	"gorm.io/gorm"

	log "github.com/yogzblr/imas/internal/log"
)

// readyCheckTimeout bounds each dependency ping, so a hung PXC or Valkey
// fails the probe instead of stalling it. The two checks run in sequence,
// so the handler's worst case is twice this — keep the readinessProbe's
// timeoutSeconds above that.
const readyCheckTimeout = 2 * time.Second

const (
	readyStatusReady    = "ready"
	readyStatusNotReady = "not_ready"
	readyCheckOK        = "ok"
)

var errNotConfigured = errors.New("not configured")

// TenantConnStats is the per-tenant NATS connection state GET /ready
// reports, supplied by cmd/farmer/main.go (which owns the connections)
// via SetTenantConnStats.
type TenantConnStats struct {
	// LegacyReady is set once the legacy tenant's boot-time connection
	// (ConnectFarmer) is up and its handlers are registered. It never goes
	// back to false: it marks "boot finished", not current link state.
	LegacyReady bool
	// Connected counts tenants whose connection is currently up.
	Connected int
	// Total counts every tenant farmer is trying to serve, including ones
	// whose first connect is still retrying.
	Total int
}

// Readiness dependencies, set once at startup (cmd/farmer/main.go) the
// same way SetRecipeStore/SetGatewaySigner are. The pings are funcs rather
// than the *gorm.DB/valkey.Client themselves so tests can stand in for
// Valkey — see internal/heartbeat's test file on why a faithful
// valkey.Client fake isn't buildable without a live server.
var (
	pxcPing     func(context.Context) error
	valkeyPing  func(context.Context) error
	tenantStats func() TenantConnStats
)

// SetReadinessDB installs the PXC handle GET /ready pings — the same
// *gorm.DB pxc.OpenDB returned and props/pki/rbac read through.
func SetReadinessDB(db *gorm.DB) {
	if db == nil {
		pxcPing = nil
		return
	}
	pxcPing = func(ctx context.Context) error {
		sqlDB, err := db.DB()
		if err != nil {
			return err
		}
		return sqlDB.PingContext(ctx)
	}
}

// SetReadinessValkey installs the Valkey client GET /ready pings — the
// same client heartbeat.SetClient was given. Whether it's been called with
// a non-nil client is also what GET /health's liveness check looks at.
func SetReadinessValkey(c valkey.Client) {
	if c == nil {
		valkeyPing = nil
		return
	}
	valkeyPing = func(ctx context.Context) error {
		return c.Do(ctx, c.B().Ping().Build()).Error()
	}
}

// valkeyConfigured reports whether a Valkey client has been installed.
func valkeyConfigured() bool { return valkeyPing != nil }

// SetTenantConnStats installs the function GET /ready reads per-tenant NATS
// connection state from.
func SetTenantConnStats(fn func() TenantConnStats) { tenantStats = fn }

// ReadyResponse is the JSON payload returned by the readiness endpoint.
// PXC and Valkey are "ok" or the check's error; LegacyTenant is "ok" or
// "connecting".
type ReadyResponse struct {
	Status           string `json:"status"`
	PXC              string `json:"pxc"`
	Valkey           string `json:"valkey"`
	LegacyTenant     string `json:"legacy_tenant"`
	TenantsConnected int    `json:"tenants_connected"`
	TenantsTotal     int    `json:"tenants_total"`
}

// GetReady reports whether this replica can do its job: 200 with status
// "ready", or 503 with status "not_ready" and the failing check's error in
// its field. Unauthenticated, like /health: it's for kubelet and for a
// human debugging a rollout, and Envoy (deploy/envoy/envoy.yaml) doesn't
// route it from the DMZ.
//
// What gates readiness, and what's only reported:
//
//   - PXC and Valkey gate it. Every PKI/props/RBAC read goes through PXC,
//     and sprout online state through Valkey; a replica that can't reach
//     either serves wrong answers or errors.
//
//   - The legacy tenant gates it only until its first connect. ConnectFarmer
//     exits the process (log.Fatalf) if that connect fails, but only after
//     dialTenantBus has retried for several minutes, and the API server is
//     up and passing PXC/Valkey checks that whole time. Without this gate a
//     rolling deployment would count a new pod as ready, retire an old one,
//     and only then learn the new pod can't reach the bus. After the first
//     connect this is a one-way latch: a later disconnect is shared by every
//     replica (they all dial the same bus), so flipping on it would pull
//     every replica out of the Service at once.
//
//   - Per-tenant connection state never gates it. It's reported as
//     tenants_connected/tenants_total. Kubernetes readiness is per pod, not
//     per tenant: marking this pod not ready because one dynamically
//     provisioned tenant is mid-reconnect (connectTenantWithRetry's backoff,
//     or nats.go's own reconnect) would route every other tenant away from a
//     replica that's serving them fine. And the cause is usually shared, since
//     every replica dials the same bus. A tenant with bad credentials or a
//     broken Account fails the same way on every replica, so gating on it
//     would take the whole Service down, or stall every future rollout, for
//     one tenant's problem. Surfacing the counts lets a human or an alert
//     see a stuck tenant without that blast radius.
func GetReady(w http.ResponseWriter, r *http.Request) {
	resp := ReadyResponse{Status: readyStatusReady, LegacyTenant: readyCheckOK}
	ready := true

	check := func(ping func(context.Context) error) string {
		if ping == nil {
			ready = false
			return errNotConfigured.Error()
		}
		ctx, cancel := context.WithTimeout(r.Context(), readyCheckTimeout)
		defer cancel()
		if err := ping(ctx); err != nil {
			ready = false
			return err.Error()
		}
		return readyCheckOK
	}
	resp.PXC = check(pxcPing)
	resp.Valkey = check(valkeyPing)

	if tenantStats == nil {
		ready = false
		resp.LegacyTenant = errNotConfigured.Error()
	} else {
		stats := tenantStats()
		resp.TenantsConnected = stats.Connected
		resp.TenantsTotal = stats.Total
		if !stats.LegacyReady {
			ready = false
			resp.LegacyTenant = "connecting"
		}
	}

	code := http.StatusOK
	if !ready {
		resp.Status = readyStatusNotReady
		code = http.StatusServiceUnavailable
	}
	jr, err := json.Marshal(resp)
	if err != nil {
		log.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	w.Write(jr)
}
