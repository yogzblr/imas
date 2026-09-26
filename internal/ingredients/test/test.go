package test

import (
	"sync"

	nats "github.com/nats-io/nats.go"
)

// nc is the single connection a sprout process registers via
// RegisterNatsConn. Sprout's own SPing never uses it (it only ever answers
// pings locally), but this stays a bare package var since sprout is
// inherently single-tenant.
var nc *nats.Conn

func RegisterNatsConn(n *nats.Conn) {
	nc = n
}

// farmerConns holds farmer's own per-tenant NATS connections — the
// counterpart to nc above, keyed by tenant since a single farmer process
// now holds one connection per tenant (see
// docs/design/imas-tenant-context-threading.md's Option A). Only FPing
// (farmer's outbound leg) reads this.
var (
	farmerConnMu sync.RWMutex
	farmerConns  = map[string]*nats.Conn{}
)

// RegisterFarmerNatsConn installs tenantID's NATS connection for FPing to
// dispatch pings through. Called once per tenant connection by
// cmd/farmer/main.go.
func RegisterFarmerNatsConn(tenantID string, n *nats.Conn) {
	farmerConnMu.Lock()
	defer farmerConnMu.Unlock()
	farmerConns[tenantID] = n
}

// UnregisterFarmerNatsConn removes tenantID's connection — called when
// that tenant is deprovisioned and its connection closed.
func UnregisterFarmerNatsConn(tenantID string) {
	farmerConnMu.Lock()
	defer farmerConnMu.Unlock()
	delete(farmerConns, tenantID)
}

func farmerConnFor(tenantID string) *nats.Conn {
	farmerConnMu.RLock()
	defer farmerConnMu.RUnlock()
	return farmerConns[tenantID]
}
