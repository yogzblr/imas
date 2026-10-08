package heartbeat

// Tests for the sprout-side periodic heartbeat (UAT.12): a sprout whose
// connection stays up past the TTL stays online, it goes offline after
// DISCONNECT and after its heartbeat stops plus TTL, and a heartbeat from
// an unaccepted sprout, another tenant's sprout or with a bad sprout ID in
// the subject is ignored. Valkey is an in-process miniredis (time moves
// only when the test calls FastForward), the bus a real nats-server.

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	natsserver "github.com/nats-io/nats-server/v2/server"
	nats "github.com/nats-io/nats.go"
	"github.com/valkey-io/valkey-go"

	"github.com/yogzblr/imas/internal/pki"
)

const testTTL = 10 * time.Second

// newTestValkey points the package at a fresh miniredis and shortens the
// TTL it writes. Production values (TTL, Interval) are untouched.
func newTestValkey(t *testing.T) *miniredis.Miniredis {
	t.Helper()
	mr := miniredis.RunT(t)
	c, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{mr.Addr()}, DisableCache: true})
	if err != nil {
		t.Fatalf("creating valkey client: %v", err)
	}
	SetClient(c)
	prev, prevAccepted, prevJitter, prevVerify := ttl, acceptedTTL, acceptedJitter, verifySprout
	ttl = testTTL
	t.Cleanup(func() {
		ttl, acceptedTTL, acceptedJitter, verifySprout = prev, prevAccepted, prevJitter, prevVerify
		SetClient(nil)
		c.Close()
	})
	return mr
}

func startTestBus(t *testing.T) *natsserver.Server {
	t.Helper()
	ns, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: -1})
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

func dialTestBus(t *testing.T, ns *natsserver.Server) *nats.Conn {
	t.Helper()
	nc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatalf("connect to test NATS: %v", err)
	}
	t.Cleanup(nc.Close)
	return nc
}

func acceptSprout(t *testing.T, tenantID, sproutID, nkey string) {
	t.Helper()
	if err := pki.UnacceptNKey(tenantID, sproutID, nkey); err != nil {
		t.Fatalf("UnacceptNKey(%s, %s): %v", tenantID, sproutID, err)
	}
	if err := pki.AcceptNKey(tenantID, sproutID); err != nil {
		t.Fatalf("AcceptNKey(%s, %s): %v", tenantID, sproutID, err)
	}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func TestIntervalIsDerivedFromTTL(t *testing.T) {
	if Interval <= 0 || Interval >= TTL {
		t.Fatalf("Interval = %s, TTL = %s: want 0 < Interval < TTL", Interval, TTL)
	}
}

func TestSproutIDFromHeartbeatSubject(t *testing.T) {
	good := pki.SproutHeartbeatSubject("web-01")
	if id, ok := sproutIDFromHeartbeatSubject(good); !ok || id != "web-01" {
		t.Fatalf("sproutIDFromHeartbeatSubject(%q) = %q, %v", good, id, ok)
	}
	for _, subj := range []string{
		"",
		"imas.heartbeat.sprout.",
		"imas.heartbeat.sprout.a.b",
		"imas.heartbeat.sprout.*",
		"imas.heartbeat.sprout.>",
		"imas.heartbeat.sprout.WEB-01",
		"imas.heartbeat.sprout.announce",
		"imas.heartbeat.sprouts.web-01",
		"imas.sprouts.web-01.facts",
		"web-01",
	} {
		if id, ok := sproutIDFromHeartbeatSubject(subj); ok {
			t.Errorf("sproutIDFromHeartbeatSubject(%q) = %q, true; want false", subj, id)
		}
	}
}

// (a) A sprout whose connection stays up for far longer than the TTL stays
// online, because each heartbeat refreshes the key; (b) once the heartbeat
// stops it goes offline after the TTL.
func TestHeartbeat_ConnectedSproutStaysOnlinePastTTL_ThenExpires(t *testing.T) {
	newTestPKIDB(t)
	mr := newTestValkey(t)
	tenant := pki.CurrentTenantID()
	acceptSprout(t, tenant, "web-01", "UHBWEB01")
	key := keyFor(tenant, "web-01")

	ns := startTestBus(t)
	farmer, sprout := dialTestBus(t, ns), dialTestBus(t, ns)
	if err := RegisterTenant(farmer, tenant); err != nil {
		t.Fatalf("RegisterTenant: %v", err)
	}
	if err := farmer.Flush(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunSprout(ctx, sprout, "web-01", 20*time.Millisecond)
	}()

	// No CONNECT event is involved at all: the first heartbeat alone sets it.
	eventually(t, "first heartbeat sets the key", func() bool { return IsOnline(context.Background(), tenant, "web-01") })

	// Six rounds of 0.8*TTL: 4.8 TTLs of connected time. Each round the key
	// is down to 0.2*TTL, then must be topped back up by a heartbeat.
	for i := 0; i < 6; i++ {
		mr.FastForward(testTTL * 8 / 10)
		eventually(t, "heartbeat refreshes the key's TTL", func() bool { return mr.TTL(key) > testTTL*9/10 })
		if !IsOnline(context.Background(), tenant, "web-01") {
			t.Fatalf("round %d: sprout offline although it is still heartbeating", i)
		}
	}

	// (b) The heartbeat stops (sprout dead, bus never said DISCONNECT).
	cancel()
	<-done
	// Let any heartbeat published just before cancel land first, so the
	// check below is not racing a message still in flight.
	if err := sprout.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := farmer.Flush(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	mr.FastForward(testTTL)
	if IsOnline(context.Background(), tenant, "web-01") {
		t.Fatal("sprout still online TTL after its heartbeat stopped")
	}
}

// (b) DISCONNECT still takes a sprout offline immediately, and CONNECT
// alone (an older sprout with no heartbeat) still sets the key and still
// lapses after the TTL, as before this change.
func TestHeartbeat_DisconnectAndConnectOnlySprout(t *testing.T) {
	newTestPKIDB(t)
	mr := newTestValkey(t)
	tenant := pki.CurrentTenantID()
	accountPub, err := pki.GetTenantAccountPub(tenant)
	if err != nil {
		t.Fatalf("GetTenantAccountPub: %v", err)
	}
	acceptSprout(t, tenant, "web-01", "UHBWEB01")
	acceptSprout(t, tenant, "old-01", "UHBOLD01")
	ctx := context.Background()

	handleConnect(connectEventJSON(t, accountPub, "UHBOLD01"))
	if !IsOnline(ctx, tenant, "old-01") {
		t.Fatal("CONNECT no longer sets the key")
	}
	mr.FastForward(testTTL)
	if IsOnline(ctx, tenant, "old-01") {
		t.Fatal("a CONNECT-only key outlived its TTL")
	}

	handleHeartbeat(tenant, pki.SproutHeartbeatSubject("web-01"))
	if !IsOnline(ctx, tenant, "web-01") {
		t.Fatal("heartbeat did not set the key")
	}
	handleDisconnect(connectEventJSON(t, accountPub, "UHBWEB01"))
	if IsOnline(ctx, tenant, "web-01") {
		t.Fatal("sprout still online after DISCONNECT")
	}
}

// (c) A heartbeat from a sprout that is not accepted, from a sprout that
// is accepted only in another tenant, or with an invalid sprout ID in the
// subject is ignored: no key is written for any of them. A valid heartbeat
// sent last proves the earlier ones were processed, not just slow.
func TestHeartbeat_IgnoresUnacceptedOtherTenantAndInvalid(t *testing.T) {
	newTestPKIDB(t)
	mr := newTestValkey(t)
	tenant := pki.CurrentTenantID()
	acceptSprout(t, tenant, "web-01", "UHBWEB01")
	if err := pki.UnacceptNKey(tenant, "web-02", "UHBWEB02"); err != nil { // never accepted
		t.Fatalf("UnacceptNKey: %v", err)
	}
	acceptSprout(t, "t_b", "web-03", "UHBWEB03") // accepted, but in another tenant
	acceptSprout(t, "t_b", "web-01", "UHBWEB01B")

	ns := startTestBus(t)
	farmer, sprout := dialTestBus(t, ns), dialTestBus(t, ns)
	if err := RegisterTenant(farmer, tenant); err != nil {
		t.Fatalf("RegisterTenant: %v", err)
	}
	if err := farmer.Flush(); err != nil {
		t.Fatal(err)
	}

	for _, id := range []string{"web-02", "web-03", "WEB-01", "announce", "nobody"} {
		if err := sprout.Publish(pki.SproutHeartbeatSubject(id), nil); err != nil {
			t.Fatal(err)
		}
	}
	// Not matched by the single-token wildcard, so never delivered; calling
	// the handler directly shows it would be refused if it were.
	for _, subj := range []string{"imas.heartbeat.sprout.a.b", "imas.heartbeat.sprout.", "imas.heartbeat.sprout.*"} {
		handleHeartbeat(tenant, subj)
	}
	// The body is never trusted: a body naming another sprout changes nothing.
	if err := sprout.Publish(pki.SproutHeartbeatSubject("web-02"), []byte(`{"sprout_id":"web-01","tenant":"t_b"}`)); err != nil {
		t.Fatal(err)
	}
	if err := sprout.Publish(pki.SproutHeartbeatSubject("web-01"), nil); err != nil { // control
		t.Fatal(err)
	}
	if err := sprout.Flush(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "control heartbeat sets its key", func() bool { return IsOnline(context.Background(), tenant, "web-01") })

	// Only the control sprout has keys: its presence key and its marker.
	want := map[string]bool{keyFor(tenant, "web-01"): true, acceptedKeyFor(tenant, "web-01"): true}
	if keys := mr.Keys(); len(keys) != len(want) || !want[keys[0]] || !want[keys[1]] {
		t.Fatalf("keys = %v; want only %v", keys, want)
	}
	for _, c := range []struct{ tenant, id string }{
		{tenant, "web-02"}, {tenant, "web-03"}, {"t_b", "web-03"}, {"t_b", "web-01"},
	} {
		if IsOnline(context.Background(), c.tenant, c.id) {
			t.Errorf("(%s, %s) is online from a heartbeat that must be ignored", c.tenant, c.id)
		}
	}
}

func TestRunSprout_SkipsWhileDisconnectedAndStopsOnCancel(t *testing.T) {
	ns := startTestBus(t)
	farmer, sprout := dialTestBus(t, ns), dialTestBus(t, ns)
	got := make(chan struct{}, 16)
	if _, err := farmer.Subscribe(pki.SproutHeartbeatSubject("web-01"), func(*nats.Msg) { got <- struct{}{} }); err != nil {
		t.Fatal(err)
	}
	if err := farmer.Flush(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunSprout(ctx, sprout, "web-01", 10*time.Millisecond)
	}()
	for i := 0; i < 3; i++ { // once at start, then on every tick
		select {
		case <-got:
		case <-time.After(2 * time.Second):
			t.Fatalf("heartbeat %d never arrived", i)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunSprout did not return after cancel")
	}

	var c fakeConn
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		RunSprout(ctx2, &c, "web-01", 5*time.Millisecond)
	}()
	time.Sleep(50 * time.Millisecond)
	cancel2()
	<-done2
	if n := c.published(); n != 0 {
		t.Fatalf("published %d heartbeats while disconnected", n)
	}
}

type fakeConn struct{ n int }

func (f *fakeConn) Publish(string, []byte) error { f.n++; return nil }
func (f *fakeConn) IsConnected() bool            { return false }
func (f *fakeConn) published() int               { return f.n }
