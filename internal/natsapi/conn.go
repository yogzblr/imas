package natsapi

import (
	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/tenantconn"
)

// tenantBus is where handlers that talk to sprouts (cook, cmd, test,
// cancel, box-key rotation, shell) get their tenant's NATS connection:
// farmer's tenantconn.Registry, installed by cmd/farmer (SetConnGetter).
// Every use asks it again, so a connection the idle sweeper closed is
// dialled again rather than reported missing.
var tenantBus tenantconn.Source

// SetConnGetter installs the getter handlers ask for a tenant's
// connection: cmd/farmer's tenant registry.
func SetConnGetter(g tenantconn.ConnGetter) {
	tenantBus.Set(g)
}

// tenantConn returns tenantID's connection, dialing it if it has none.
func tenantConn(tenantID string) (*nats.Conn, error) {
	return tenantBus.Conn(tenantID)
}
