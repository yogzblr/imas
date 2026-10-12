// Package tenantconntest has test helpers for code that gets tenant NATS
// connections from a tenantconn.ConnGetter.
package tenantconntest

import (
	"context"
	"testing"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/tenantconn"
)

// Fixed returns a getter that answers every tenant with nc.
func Fixed(nc *nats.Conn) tenantconn.ConnGetter {
	return tenantconn.GetterFunc(func(context.Context, string) (*nats.Conn, error) { return nc, nil })
}

// Use installs g through set (a package's SetConnGetter or
// SetFarmerConnGetter) for the rest of t, and uninstalls it at cleanup.
func Use(t testing.TB, set func(tenantconn.ConnGetter), g tenantconn.ConnGetter) {
	t.Helper()
	set(g)
	t.Cleanup(func() { set(nil) })
}
