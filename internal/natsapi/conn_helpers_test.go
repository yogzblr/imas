package natsapi

import (
	"testing"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/tenantconn/tenantconntest"
)

// useConn has every tenant's handlers use nc for the rest of t.
func useConn(t testing.TB, nc *nats.Conn) {
	t.Helper()
	tenantconntest.Use(t, SetConnGetter, tenantconntest.Fixed(nc))
}
