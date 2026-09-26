// Package tenantconn tracks farmer's per-tenant NATS connections (see
// docs/design/imas-tenant-context-threading.md's Option A: one connection
// per tenant, including the legacy tenant under its own entry like any
// other). It exists as its own package, rather than as the plain map
// cmd/farmer/main.go used to keep, so the bookkeeping GET /ready reports
// from (internal/api/handlers/ready.go) is unit-testable — package main
// can't be, since its init() loads farmer's config from /etc/imas.
//
// Besides the registered connections themselves, a Registry also tracks
// tenants that are *wanted* but not registered yet: a tenant stuck in
// cmd/farmer's connectTenantWithRetry backoff loop has no *nats.Conn to
// record, so a map of connections alone would make it invisible — a
// tenant that can't connect at all would drop out of the total instead of
// showing up as the one tenant that isn't connected.
package tenantconn

import (
	"sync"

	"github.com/nats-io/nats.go"
)

// Registry holds every tenant's registered NATS connection plus the set of
// tenants still waiting on their first successful connect. Safe for
// concurrent use: it's written from ConnectFarmer's own goroutines
// (boot-time enumeration, pki.OnTenantProvisioned/OnTenantDeprovisioned
// callbacks) and read from HTTP handlers.
type Registry struct {
	mu      sync.Mutex
	conns   map[string]*nats.Conn
	pending map[string]struct{}
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		conns:   map[string]*nats.Conn{},
		pending: map[string]struct{}{},
	}
}

// MarkPending records that tenantID should have a connection but doesn't
// have one registered yet (a first connect is in progress or in backoff).
// A tenant that already has a registered connection is left as is.
func (r *Registry) MarkPending(tenantID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.conns[tenantID]; ok {
		return
	}
	r.pending[tenantID] = struct{}{}
}

// Set registers nc as tenantID's connection, clearing any pending entry.
func (r *Registry) Set(tenantID string, nc *nats.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.conns[tenantID] = nc
	delete(r.pending, tenantID)
}

// Remove deletes tenantID's entry (registered or pending) and returns the
// connection that was registered, or nil if none was.
func (r *Registry) Remove(tenantID string) *nats.Conn {
	r.mu.Lock()
	defer r.mu.Unlock()
	nc := r.conns[tenantID]
	delete(r.conns, tenantID)
	delete(r.pending, tenantID)
	return nc
}

// All returns every registered connection. Pending tenants have none, so
// they're not included.
func (r *Registry) All() []*nats.Conn {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*nats.Conn, 0, len(r.conns))
	for _, nc := range r.conns {
		out = append(out, nc)
	}
	return out
}

// Counts reports how many tenants currently have a live connection
// (registered and nats.Conn.IsConnected — so a registered connection that's
// mid-reconnect, or closed after exhausting its reconnect budget, doesn't
// count) out of every tenant farmer is trying to serve (registered plus
// pending).
func (r *Registry) Counts() (connected, total int) {
	r.mu.Lock()
	conns := make([]*nats.Conn, 0, len(r.conns))
	for _, nc := range r.conns {
		conns = append(conns, nc)
	}
	total = len(r.conns) + len(r.pending)
	r.mu.Unlock()
	// IsConnected takes each connection's own lock; checked outside r.mu
	// so a slow connection never holds up the registry's writers.
	for _, nc := range conns {
		if nc != nil && nc.IsConnected() {
			connected++
		}
	}
	return connected, total
}
