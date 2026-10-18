package test

import (
	"github.com/yogzblr/imas/internal/tenantconn"
)

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
