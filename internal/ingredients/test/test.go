package test

import (
	nats "github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/tenantconn"
)

// nc is the single connection a sprout process registers via
// RegisterNatsConn. Sprout's own SPing never uses it (it only ever answers
// pings locally), but this stays a bare package var since sprout is
// inherently single-tenant.
var nc *nats.Conn

func RegisterNatsConn(n *nats.Conn) {
	nc = n
}

// farmerBus is where FPing (farmer's outbound leg) gets a tenant's NATS
// connection: farmer's tenantconn.Registry, installed by cmd/farmer
// (SetFarmerConnGetter). Every send asks it again, so a tenant whose
// connection the idle sweeper closed is dialled again. Sprout never
// installs one.
var farmerBus tenantconn.Source

// SetFarmerConnGetter installs the getter FPing gets a tenant's connection
// from: cmd/farmer's tenant registry.
func SetFarmerConnGetter(g tenantconn.ConnGetter) {
	farmerBus.Set(g)
}
