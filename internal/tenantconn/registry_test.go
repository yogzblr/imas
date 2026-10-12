package tenantconn

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// startTestNATS runs an embedded NATS server, matching internal/facts'
// test setup.
func startTestNATS(t *testing.T) *server.Server {
	t.Helper()
	ns, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1})
	if err != nil {
		t.Fatalf("start test NATS server: %v", err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS server failed to become ready")
	}
	t.Cleanup(ns.Shutdown)
	return ns
}

// fakeClock is a settable clock for Config.Now.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Unix(1_700_000_000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// testDialer dials the embedded server, installing onClosed as the
// connection's ClosedHandler like cmd/farmer's dialer does, and counts
// dials per tenant.
type testDialer struct {
	ns    *server.Server
	mu    sync.Mutex
	dials map[string]int
	fail  map[string]error
	// gate, when set, holds every dial until it is closed.
	gate chan struct{}
}

func newTestDialer(ns *server.Server) *testDialer {
	return &testDialer{ns: ns, dials: map[string]int{}, fail: map[string]error{}}
}

func (d *testDialer) dial(ctx context.Context, tenantID string, onClosed func(*nats.Conn)) (*nats.Conn, error) {
	d.mu.Lock()
	d.dials[tenantID]++
	err := d.fail[tenantID]
	gate := d.gate
	d.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	return nats.Connect(d.ns.ClientURL(), nats.ClosedHandler(onClosed))
}

func (d *testDialer) count(tenantID string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials[tenantID]
}

func newTestRegistry(t *testing.T, ns *server.Server, mutate func(*Config)) (*Registry, *testDialer, *fakeClock) {
	t.Helper()
	d := newTestDialer(ns)
	clk := newFakeClock()
	cfg := Config{Dial: d.dial, IdleTTL: 10 * time.Minute, HeartbeatWindow: 15 * time.Minute, Now: clk.Now}
	if mutate != nil {
		mutate(&cfg)
	}
	r := New(cfg)
	t.Cleanup(func() {
		for _, nc := range r.All() {
			nc.Close()
		}
	})
	return r, d, clk
}

func mustGet(t *testing.T, r *Registry, tenantID string) *nats.Conn {
	t.Helper()
	nc, err := r.Get(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("Get(%s): %v", tenantID, err)
	}
	return nc
}

func assertCounts(t *testing.T, r *Registry, wantConnected, wantTotal int) {
	t.Helper()
	connected, total := r.Counts()
	if connected != wantConnected || total != wantTotal {
		t.Errorf("Counts() = (%d, %d), want (%d, %d)", connected, total, wantConnected, wantTotal)
	}
}

// waitFor polls cond for up to 5s; ClosedHandler runs on nats.go's
// callback goroutine, so its effect is asynchronous.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestCountsEmpty(t *testing.T) {
	assertCounts(t, New(Config{}), 0, 0)
}

func TestGetWithoutDialer(t *testing.T) {
	if _, err := New(Config{}).Get(context.Background(), "tenant-a"); !errors.Is(err, ErrNoDialer) {
		t.Fatalf("Get without a dialer: err = %v, want ErrNoDialer", err)
	}
}

// A tenant stuck retrying its first connect has no *nats.Conn, but must
// still count toward the total — otherwise it would be invisible.
func TestPendingCountsTowardTotalOnly(t *testing.T) {
	r, _, _ := newTestRegistry(t, startTestNATS(t), nil)
	mustGet(t, r, "legacy")
	if !r.MarkPending("tenant-b") {
		t.Fatal("MarkPending(tenant-b) = false, want true")
	}
	assertCounts(t, r, 1, 2)
	if got := len(r.All()); got != 1 {
		t.Errorf("All() returned %d connections, want 1 (pending tenants have none)", got)
	}
}

func TestGetClearsPending(t *testing.T) {
	r, _, _ := newTestRegistry(t, startTestNATS(t), nil)
	mustGet(t, r, "legacy")
	r.MarkPending("tenant-b")
	mustGet(t, r, "tenant-b")
	assertCounts(t, r, 2, 2)
	if r.Pending("tenant-b") {
		t.Error("tenant-b still pending after a successful Get")
	}
}

// MarkPending reports false for a tenant that is connected or already
// pending: cmd/farmer uses that so only one retry loop runs per tenant.
func TestMarkPendingOnlyOnce(t *testing.T) {
	r, _, _ := newTestRegistry(t, startTestNATS(t), nil)
	mustGet(t, r, "tenant-a")
	if r.MarkPending("tenant-a") {
		t.Error("MarkPending(connected tenant) = true, want false")
	}
	if !r.MarkPending("tenant-b") || r.MarkPending("tenant-b") {
		t.Error("MarkPending(tenant-b) twice: want true then false")
	}
	assertCounts(t, r, 1, 2)
}

// A failed dial leaves the tenant neither connected nor pending (a retry
// loop marks it pending itself), and the next Get dials again.
func TestGetDialFailure(t *testing.T) {
	r, d, _ := newTestRegistry(t, startTestNATS(t), nil)
	boom := errors.New("bus unreachable")
	d.fail["tenant-a"] = boom
	if _, err := r.Get(context.Background(), "tenant-a"); !errors.Is(err, boom) {
		t.Fatalf("Get: err = %v, want %v", err, boom)
	}
	assertCounts(t, r, 0, 0)
	delete(d.fail, "tenant-a")
	mustGet(t, r, "tenant-a")
	if got := d.count("tenant-a"); got != 2 {
		t.Errorf("dials = %d, want 2", got)
	}
}

// Drop is deprovisioning: it removes a registered, pending or mid-dial
// tenant and closes its connection.
func TestDrop(t *testing.T) {
	r, _, _ := newTestRegistry(t, startTestNATS(t), nil)
	nc := mustGet(t, r, "tenant-a")
	r.MarkPending("tenant-b")

	if !r.Drop("tenant-a") {
		t.Error("Drop(tenant-a) = false, want true")
	}
	if !nc.IsClosed() {
		t.Error("Drop left tenant-a's connection open")
	}
	if r.Drop("tenant-b") {
		t.Error("Drop(pending tenant-b) = true, want false (no connection)")
	}
	if r.Drop("missing") {
		t.Error("Drop(missing) = true, want false")
	}
	assertCounts(t, r, 0, 0)
}

// A tenant dropped while its dial is in progress is not registered: the
// new connection is closed and Get reports ErrDropped.
func TestDropDuringDial(t *testing.T) {
	ns := startTestNATS(t)
	r, d, _ := newTestRegistry(t, ns, nil)
	d.gate = make(chan struct{})
	errc := make(chan error, 1)
	go func() {
		_, err := r.Get(context.Background(), "tenant-a")
		errc <- err
	}()
	waitFor(t, "the dial to start", func() bool { return d.count("tenant-a") == 1 })
	r.Drop("tenant-a")
	close(d.gate)
	if err := <-errc; !errors.Is(err, ErrDropped) {
		t.Fatalf("Get: err = %v, want ErrDropped", err)
	}
	assertCounts(t, r, 0, 0)
}

// Test 7 (brief §6): a connection that closes is forgotten through the
// ClosedHandler the dialer installed, the next Get dials again, and
// OnClosed fires so the caller can redial at once.
func TestTenantBusReconnectsAfterMax(t *testing.T) {
	ns := startTestNATS(t)
	closedFor := make(chan string, 1)
	r, d, _ := newTestRegistry(t, ns, func(c *Config) {
		c.OnClosed = func(id string) { closedFor <- id }
	})
	first := mustGet(t, r, "tenant-a")
	// What nats.go does once a connection is closed for good.
	first.Close()
	select {
	case id := <-closedFor:
		if id != "tenant-a" {
			t.Fatalf("OnClosed(%s), want tenant-a", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnClosed never fired")
	}
	assertCounts(t, r, 0, 0)
	second := mustGet(t, r, "tenant-a")
	if second == first || second.IsClosed() {
		t.Fatal("Get after close returned the closed connection")
	}
	if got := d.count("tenant-a"); got != 2 {
		t.Errorf("dials = %d, want 2", got)
	}
	// The stale connection's handler must not remove its replacement.
	r.closed("tenant-a", first)
	assertCounts(t, r, 1, 1)
}

// A connection that closed before its ClosedHandler ran is not handed out:
// Get dials a new one.
func TestGetSkipsClosedConn(t *testing.T) {
	r, d, _ := newTestRegistry(t, startTestNATS(t), func(c *Config) {
		c.OnClosed = func(string) {}
	})
	first := mustGet(t, r, "tenant-a")
	r.mu.Lock()
	first.Close() // the handler blocks on r.mu until Get below is done
	r.mu.Unlock()
	if nc := mustGet(t, r, "tenant-a"); nc == first {
		t.Fatal("Get returned the closed connection")
	}
	if got := d.count("tenant-a"); got != 2 {
		t.Errorf("dials = %d, want 2", got)
	}
}

// Closing connections ourselves (Drop, Sweep) does not fire OnClosed.
func TestOwnCloseDoesNotFireOnClosed(t *testing.T) {
	var fired atomic.Int32
	r, _, clk := newTestRegistry(t, startTestNATS(t), func(c *Config) {
		c.OnClosed = func(string) { fired.Add(1) }
	})
	a := mustGet(t, r, "tenant-a")
	b := mustGet(t, r, "tenant-b")
	r.Drop("tenant-a")
	clk.Advance(11 * time.Minute)
	r.Sweep()
	waitFor(t, "both connections to close", func() bool { return a.IsClosed() && b.IsClosed() })
	time.Sleep(50 * time.Millisecond) // let the ClosedHandlers run
	if fired.Load() != 0 {
		t.Errorf("OnClosed fired %d times for connections the registry closed", fired.Load())
	}
}

// Test 8 (brief §6): nothing is dialled at startup; 16 concurrent first
// callers share one dial; Sweep closes an idle tenant after the TTL and
// keeps a busy one open.
func TestTenantBusLazyAndIdleClose(t *testing.T) {
	ns := startTestNATS(t)
	r, d, clk := newTestRegistry(t, ns, nil)
	if got := d.count("tenant-a"); got != 0 {
		t.Fatalf("dials at startup = %d, want 0", got)
	}
	assertCounts(t, r, 0, 0)

	d.gate = make(chan struct{})
	const callers = 16
	conns := make([]*nats.Conn, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conns[i], errs[i] = r.Get(context.Background(), "tenant-a")
		}()
	}
	waitFor(t, "the first dial", func() bool { return d.count("tenant-a") >= 1 })
	time.Sleep(50 * time.Millisecond) // let the other callers queue up
	close(d.gate)
	wg.Wait()
	if got := d.count("tenant-a"); got != 1 {
		t.Fatalf("dials under %d concurrent callers = %d, want 1", callers, got)
	}
	for i := range callers {
		if errs[i] != nil || conns[i] != conns[0] {
			t.Fatalf("caller %d: (%p, %v), want the shared connection %p", i, conns[i], errs[i], conns[0])
		}
	}
	d.gate = nil

	busy := mustGet(t, r, "busy")
	idle := conns[0]

	clk.Advance(9 * time.Minute)
	r.Touch("busy")
	if got := r.Sweep(); len(got) != 0 {
		t.Fatalf("Sweep before the idle TTL closed %v", got)
	}
	clk.Advance(2 * time.Minute) // tenant-a unused for 11m, busy for 2m
	got := r.Sweep()
	if len(got) != 1 || got[0] != "tenant-a" {
		t.Fatalf("Sweep closed %v, want [tenant-a]", got)
	}
	if !idle.IsClosed() {
		t.Error("idle connection not closed")
	}
	if busy.IsClosed() {
		t.Error("busy connection closed")
	}
	assertCounts(t, r, 1, 1)

	// The next use dials again.
	mustGet(t, r, "tenant-a")
	if got := d.count("tenant-a"); got != 2 {
		t.Errorf("dials after idle close = %d, want 2", got)
	}
}

// Owner decision 3: a sprout heartbeat within the window keeps a tenant
// open however long it has been unused; once heartbeats stop for the
// window, it closes.
func TestHeartbeatKeepsTenantOpen(t *testing.T) {
	r, _, clk := newTestRegistry(t, startTestNATS(t), nil)
	nc := mustGet(t, r, "tenant-a")
	for range 6 { // 30 minutes unused, a heartbeat every 5
		clk.Advance(5 * time.Minute)
		r.TouchHeartbeat("tenant-a")
		if got := r.Sweep(); len(got) != 0 {
			t.Fatalf("Sweep closed %v while heartbeats arrive", got)
		}
	}
	clk.Advance(14 * time.Minute)
	if got := r.Sweep(); len(got) != 0 {
		t.Fatalf("Sweep closed %v 14m after the last heartbeat", got)
	}
	clk.Advance(1 * time.Minute)
	if got := r.Sweep(); len(got) != 1 {
		t.Fatalf("Sweep 15m after the last heartbeat closed %v, want [tenant-a]", got)
	}
	if !nc.IsClosed() {
		t.Error("connection not closed")
	}
}

func TestKeepExemptsFromSweep(t *testing.T) {
	r, _, clk := newTestRegistry(t, startTestNATS(t), nil)
	r.Keep("legacy")
	mustGet(t, r, "legacy")
	clk.Advance(24 * time.Hour)
	if got := r.Sweep(); len(got) != 0 {
		t.Fatalf("Sweep closed kept tenants %v", got)
	}
}

func TestSweepDisabledWithoutIdleTTL(t *testing.T) {
	r, _, clk := newTestRegistry(t, startTestNATS(t), func(c *Config) { c.IdleTTL = 0 })
	mustGet(t, r, "tenant-a")
	clk.Advance(24 * time.Hour)
	if got := r.Sweep(); len(got) != 0 {
		t.Fatalf("Sweep with IdleTTL 0 closed %v", got)
	}
}

// A registered connection that has dropped (closed here, with no
// ClosedHandler to forget it) still counts toward the total but not as
// connected.
func TestDisconnectedConnNotCountedAsConnected(t *testing.T) {
	ns := startTestNATS(t)
	r := New(Config{Dial: func(context.Context, string, func(*nats.Conn)) (*nats.Conn, error) {
		return nats.Connect(ns.ClientURL())
	}})
	mustGet(t, r, "legacy")
	down := mustGet(t, r, "tenant-b")
	down.Close()
	assertCounts(t, r, 1, 2)
	for _, nc := range r.All() {
		nc.Close()
	}
}

// A waiting caller whose own ctx ends stops waiting; the dial carries on
// for the caller that started it.
func TestGetWaiterContext(t *testing.T) {
	r, d, _ := newTestRegistry(t, startTestNATS(t), nil)
	d.gate = make(chan struct{})
	first := make(chan error, 1)
	go func() {
		_, err := r.Get(context.Background(), "tenant-a")
		first <- err
	}()
	waitFor(t, "the dial to start", func() bool { return d.count("tenant-a") == 1 })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Get(ctx, "tenant-a"); !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter Get: err = %v, want context.Canceled", err)
	}
	close(d.gate)
	if err := <-first; err != nil {
		t.Fatalf("first Get: %v", err)
	}
	assertCounts(t, r, 1, 1)
}
