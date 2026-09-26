package natsapi

import (
	"sync"

	"github.com/nats-io/nats.go"
)

// natsConns is the NATS connection used by handlers that need to
// communicate with sprouts (cook, cmd, test, cancel, probe), keyed by
// tenant ID. cmd/farmer/main.go's ConnectFarmer opens one connection per
// tenant (see docs/design/imas-tenant-context-threading.md's Option A) and
// calls Subscribe(nc, tenantID) once per connection — a bare
// package-level *nats.Conn can't hold "the right connection" once more
// than one tenant is connected at a time, so this is a map instead.
var (
	natsConnMu sync.RWMutex
	natsConns  = map[string]*nats.Conn{}
)

// SetNatsConn installs the NATS connection tenantID's handlers publish and
// request through. Called once per tenant connection, by Subscribe.
func SetNatsConn(tenantID string, nc *nats.Conn) {
	natsConnMu.Lock()
	defer natsConnMu.Unlock()
	natsConns[tenantID] = nc
}

// ClearNatsConn removes tenantID's connection — called when that tenant's
// connection is closed (deprovisioning), so a stale, closed *nats.Conn
// doesn't linger in the map.
func ClearNatsConn(tenantID string) {
	natsConnMu.Lock()
	defer natsConnMu.Unlock()
	delete(natsConns, tenantID)
}

// natsConnFor returns tenantID's connection, or nil if none is registered.
func natsConnFor(tenantID string) *nats.Conn {
	natsConnMu.RLock()
	defer natsConnMu.RUnlock()
	return natsConns[tenantID]
}
