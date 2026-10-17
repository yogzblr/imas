package main

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	nats "github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/tenantconn"
)

// startAuthServer starts a plain-text NATS server on port (-1: any) that
// accepts user farmer with password.
func startAuthServer(t *testing.T, port int, password string) *server.Server {
	t.Helper()
	ns, err := server.NewServer(&server.Options{
		Host:  "127.0.0.1",
		Port:  port,
		Users: []*server.User{{Username: "farmer", Password: password}},
	})
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

// P5/P17: when the NATS client gives up on a tenant connection (here the
// bus comes back with farmer's old credential refused, and nats.go closes
// the connection after the same authorization error twice, despite
// MaxReconnects(-1)), farmer's registry forgets it and redials at once
// through connectTenantWithRetry, with no caller asking for the tenant.
func TestTenantRedialAfterNATSClientGivesUp(t *testing.T) {
	ns := startAuthServer(t, -1, "first")
	port := ns.Addr().(*net.TCPAddr).Port
	url := ns.ClientURL()

	var mu sync.Mutex
	password := "first"
	dials := 0
	var conns []*nats.Conn
	dialed := make(chan struct{}, 4)
	var dial tenantconn.Dialer = func(_ context.Context, tenantID string, onClosed func(*nats.Conn)) (*nats.Conn, error) {
		mu.Lock()
		pw := password
		dials++
		mu.Unlock()
		// Farmer's own options (Secure dropped: the test server is plain
		// text), with its credential replaced by a password and a short
		// reconnect wait so the test does not wait 15s per attempt.
		opts := tenantBusOptions(tenantID, nil, nats.UserInfo("farmer", pw), onClosed)[1:]
		opts = append(opts, nats.ReconnectWait(20*time.Millisecond), nats.RetryOnFailedConnect(false))
		nc, err := nats.Connect(url, opts...)
		if err != nil {
			return nil, err
		}
		mu.Lock()
		conns = append(conns, nc)
		mu.Unlock()
		dialed <- struct{}{}
		return nc, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	saved := tenantRegistry
	tenantRegistry = newTenantRegistry(ctx, dial)
	t.Cleanup(func() {
		tenantRegistry.Drop("tenant-a")
		tenantRegistry = saved
	})

	first, err := tenantRegistry.Get(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("first Get: %v", err)
	}
	<-dialed
	if c, total := tenantRegistry.Counts(); c != 1 || total != 1 {
		t.Fatalf("Counts = %d, %d after the first dial, want 1, 1", c, total)
	}

	// The bus restarts on the same address with a new credential: every
	// reconnect of the old connection is refused.
	ns.Shutdown()
	ns.WaitForShutdown()
	mu.Lock()
	password = "second"
	mu.Unlock()
	startAuthServer(t, port, "second")

	select {
	case <-dialed:
	case <-time.After(15 * time.Second):
		t.Fatal("farmer never redialled the tenant after the NATS client gave up")
	}
	if !first.IsClosed() {
		t.Error("the first connection is not closed: the NATS client did not give up")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, total := tenantRegistry.Counts()
		if c == 1 && total == 1 && !tenantRegistry.Pending("tenant-a") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Counts = %d, %d, pending %v after the redial, want 1, 1, false", c, total, tenantRegistry.Pending("tenant-a"))
		}
		time.Sleep(10 * time.Millisecond)
	}
	second, err := tenantRegistry.Get(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("Get after the redial: %v", err)
	}
	if second == first || second.IsClosed() {
		t.Fatal("the registry still hands out the connection the client gave up on")
	}
	mu.Lock()
	n := dials
	mu.Unlock()
	if n != 2 {
		t.Errorf("dialled %d times, want 2 (the first connect and one redial)", n)
	}
	// The new connection works.
	sub, err := second.SubscribeSync("ping")
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Publish("ping", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := sub.NextMsg(5 * time.Second); err != nil {
		t.Fatalf("the redialled connection does not carry messages: %v", err)
	}
}
