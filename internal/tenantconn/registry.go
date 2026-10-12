// Package tenantconn tracks farmer's per-tenant NATS connections (see
// docs/design/imas-tenant-context-threading.md's Option A: one connection
// per tenant, including the legacy tenant under its own entry like any
// other). It exists as its own package, rather than as the plain map
// cmd/farmer/main.go used to keep, so the bookkeeping GET /ready reports
// from (internal/api/handlers/ready.go) is unit-testable — package main
// can't be, since its init() loads farmer's config from /etc/imas.
//
// A Registry is farmer's one source of tenant connections: every package
// that sends to a tenant's bus is handed it as a ConnGetter (getter.go)
// and calls Get on every use. No other package keeps a connection by
// tenant, so nothing reports a tenant "not connected" except a failed
// dial.
//
// Connections are lazy, kept while in use, and closed when idle
// (docs/briefs/P21-slice3-farmer-saasapi-state.md §4.5 and owner decision
// 3):
//
//   - Get dials a tenant the first time something needs it, once per
//     tenant however many callers ask at the same time (a hand-rolled
//     singleflight). Nothing is dialled when the Registry is created.
//   - A connection that closes on its own (the dialer reports it through
//     the onClosed callback Get hands it) is dropped, so the next Get
//     dials again; Config.OnClosed lets the caller dial at once instead.
//   - Sweep closes every connection that has been neither used for
//     Config.IdleTTL nor seen a sprout heartbeat (TouchHeartbeat) for
//     Config.HeartbeatWindow. A tenant with sprouts online keeps its
//     connection, so this replica stays in the tenant's queue groups;
//     only tenants with nothing going on are closed. Keep exempts a
//     tenant from Sweep altogether.
//
// Besides the registered connections themselves, a Registry also tracks
// tenants that are *wanted* but not registered yet: a tenant stuck in
// cmd/farmer's connectTenantWithRetry backoff loop has no *nats.Conn to
// record, so a map of connections alone would make it invisible — a
// tenant that can't connect at all would drop out of the total instead of
// showing up as the one tenant that isn't connected.
package tenantconn

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

// Dialer opens tenantID's connection and registers its handlers on it.
// It must install onClosed as the connection's nats.ClosedHandler (or call
// it however the connection reports that it closed for good), so the
// Registry forgets a dead connection and the next Get dials again.
type Dialer func(ctx context.Context, tenantID string, onClosed func(*nats.Conn)) (*nats.Conn, error)

// Config is a Registry's dialer, idle policy and hooks. Every field is
// optional; a Registry without Dial can only report (Get fails).
type Config struct {
	// Dial opens a tenant's connection for Get.
	Dial Dialer
	// IdleTTL: a connection unused for this long may be closed by Sweep.
	// Zero or negative disables idle close.
	IdleTTL time.Duration
	// HeartbeatWindow: a connection that saw a sprout heartbeat within
	// this long is never closed by Sweep, however long it has been unused.
	HeartbeatWindow time.Duration
	// OnClosed runs, in its own goroutine, when a registered connection
	// closed without the Registry closing it. The entry is already gone.
	OnClosed func(tenantID string)
	// Now is the clock; time.Now when nil. Tests inject a fake one.
	Now func() time.Time
}

// ErrNoDialer means the Registry was built without Config.Dial.
var ErrNoDialer = errors.New("tenantconn: no dialer configured")

// ErrDropped means the tenant was dropped (deprovisioned) while Get was
// dialing it; the new connection was closed instead of registered.
var ErrDropped = errors.New("tenantconn: tenant dropped while connecting")

type entry struct {
	nc            *nats.Conn
	lastUse       time.Time
	lastHeartbeat time.Time
}

// call is one in-flight dial that concurrent Get callers share.
type call struct {
	done    chan struct{}
	nc      *nats.Conn
	err     error
	dropped bool // set under Registry.mu by Drop
}

// Registry holds every tenant's registered NATS connection plus the set of
// tenants still waiting on their first successful connect. Safe for
// concurrent use: it's written from cmd/farmer's own goroutines (boot,
// bus events, pki.OnTenantProvisioned/OnTenantDeprovisioned callbacks, the
// idle sweeper) and read from HTTP handlers.
type Registry struct {
	cfg Config

	mu       sync.Mutex
	conns    map[string]*entry
	pending  map[string]struct{}
	inflight map[string]*call
	kept     map[string]struct{}
}

// New returns an empty Registry; it dials nothing until Get is called.
func New(cfg Config) *Registry {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Registry{
		cfg:      cfg,
		conns:    map[string]*entry{},
		pending:  map[string]struct{}{},
		inflight: map[string]*call{},
		kept:     map[string]struct{}{},
	}
}

// Get returns tenantID's connection, dialing it if there is none. Callers
// that ask for the same tenant while a dial is in progress wait for that
// dial instead of starting their own. The dial runs with the ctx of the
// caller that started it; a waiting caller whose own ctx ends stops
// waiting with ctx.Err(). Every Get counts as use of the connection.
func (r *Registry) Get(ctx context.Context, tenantID string) (*nats.Conn, error) {
	r.mu.Lock()
	if e, ok := r.conns[tenantID]; ok {
		if e.nc == nil || !e.nc.IsClosed() {
			e.lastUse = r.cfg.Now()
			r.mu.Unlock()
			return e.nc, nil
		}
		// Closed, and its ClosedHandler hasn't run yet: forget it now and
		// dial (the handler then finds the entry gone or replaced).
		delete(r.conns, tenantID)
	}
	if c, ok := r.inflight[tenantID]; ok {
		r.mu.Unlock()
		select {
		case <-c.done:
			return c.nc, c.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if r.cfg.Dial == nil {
		r.mu.Unlock()
		return nil, ErrNoDialer
	}
	c := &call{done: make(chan struct{})}
	r.inflight[tenantID] = c
	r.mu.Unlock()

	nc, err := r.cfg.Dial(ctx, tenantID, func(closed *nats.Conn) { r.closed(tenantID, closed) })

	r.mu.Lock()
	delete(r.inflight, tenantID)
	switch {
	case err != nil:
		// Nothing to record: the next Get dials again.
	case c.dropped:
		err = ErrDropped
	default:
		now := r.cfg.Now()
		r.conns[tenantID] = &entry{nc: nc, lastUse: now}
		delete(r.pending, tenantID)
	}
	if err != nil {
		c.err = err
	} else {
		c.nc = nc
	}
	r.mu.Unlock()
	close(c.done)
	if errors.Is(err, ErrDropped) && nc != nil {
		nc.Close()
	}
	return c.nc, c.err
}

// closed is the onClosed callback Get hands the dialer: a connection that
// is still registered closed on its own, so forget it.
func (r *Registry) closed(tenantID string, nc *nats.Conn) {
	if !r.drop(tenantID, nc, false) {
		return
	}
	if r.cfg.OnClosed != nil {
		go r.cfg.OnClosed(tenantID)
	}
}

// Touch records use of tenantID's connection and reports whether it has
// one.
func (r *Registry) Touch(tenantID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.conns[tenantID]
	if ok {
		e.lastUse = r.cfg.Now()
	}
	return ok
}

// TouchHeartbeat records that a sprout heartbeat arrived on tenantID's
// connection. It keeps the connection open for Config.HeartbeatWindow.
func (r *Registry) TouchHeartbeat(tenantID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.conns[tenantID]; ok {
		e.lastHeartbeat = r.cfg.Now()
	}
}

// Keep exempts tenantID from Sweep, now and for any later connection.
func (r *Registry) Keep(tenantID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.kept[tenantID] = struct{}{}
}

// MarkPending records that tenantID should have a connection but doesn't
// have one registered yet (a first connect is in progress or in backoff).
// It reports false, and changes nothing, if the tenant already has a
// registered connection or is already pending: that tenant has an owner.
func (r *Registry) MarkPending(tenantID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.conns[tenantID]; ok {
		return false
	}
	if _, ok := r.pending[tenantID]; ok {
		return false
	}
	r.pending[tenantID] = struct{}{}
	return true
}

// Pending reports whether tenantID is marked pending.
func (r *Registry) Pending(tenantID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.pending[tenantID]
	return ok
}

// Drop removes tenantID (registered, pending or mid-dial) and closes its
// connection: the deprovisioning path. A dial in progress for the tenant
// completes by closing its connection instead of registering it. Reports
// whether a registered connection was removed.
func (r *Registry) Drop(tenantID string) bool {
	return r.drop(tenantID, nil, true)
}

// drop removes tenantID's entry, if only is nil or is the registered
// connection, and closes it. all also clears pending and in-flight state.
func (r *Registry) drop(tenantID string, only *nats.Conn, all bool) bool {
	r.mu.Lock()
	if all {
		delete(r.pending, tenantID)
		if c, ok := r.inflight[tenantID]; ok {
			c.dropped = true
		}
	}
	e, ok := r.conns[tenantID]
	if !ok || (only != nil && e.nc != only) {
		r.mu.Unlock()
		return false
	}
	delete(r.conns, tenantID)
	r.mu.Unlock()
	if e.nc != nil {
		e.nc.Close()
	}
	return true
}

// Sweep closes every connection that is idle: not kept, unused for
// Config.IdleTTL and without a sprout heartbeat for Config.HeartbeatWindow.
// It returns the tenants it closed. It does nothing when IdleTTL is not
// positive.
func (r *Registry) Sweep() []string {
	if r.cfg.IdleTTL <= 0 {
		return nil
	}
	r.mu.Lock()
	now := r.cfg.Now()
	var tenants []string
	var conns []*nats.Conn
	for id, e := range r.conns {
		if _, ok := r.kept[id]; ok {
			continue
		}
		if now.Sub(e.lastUse) < r.cfg.IdleTTL {
			continue
		}
		if !e.lastHeartbeat.IsZero() && now.Sub(e.lastHeartbeat) < r.cfg.HeartbeatWindow {
			continue
		}
		delete(r.conns, id)
		tenants = append(tenants, id)
		conns = append(conns, e.nc)
	}
	r.mu.Unlock()
	// Closed outside the lock: Close flushes, and each connection's
	// ClosedHandler finds its entry already gone.
	for _, nc := range conns {
		if nc != nil {
			nc.Close()
		}
	}
	return tenants
}

// All returns every registered connection. Pending tenants have none, so
// they're not included.
func (r *Registry) All() []*nats.Conn {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*nats.Conn, 0, len(r.conns))
	for _, e := range r.conns {
		out = append(out, e.nc)
	}
	return out
}

// Counts reports how many tenants currently have a live connection
// (registered and nats.Conn.IsConnected — so a registered connection that's
// mid-reconnect doesn't count) out of every tenant farmer is trying to
// serve (registered plus pending). A tenant closed for being idle is
// neither: it is not being served until something needs it again.
func (r *Registry) Counts() (connected, total int) {
	r.mu.Lock()
	conns := make([]*nats.Conn, 0, len(r.conns))
	for _, e := range r.conns {
		conns = append(conns, e.nc)
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
