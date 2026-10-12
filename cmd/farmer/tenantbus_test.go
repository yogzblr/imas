package main

import (
	"context"
	"crypto/tls"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	nats "github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/natsapi"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/tenantconn"
)

// Test 7 (brief §6), farmer's half: a tenant connection never gives up
// reconnecting (the old limit was 30 attempts), and its ClosedHandler is
// the registry's onClosed, so a connection that closes for good is
// forgotten and the next use dials again.
func TestTenantBusReconnectsForever(t *testing.T) {
	var closed *nats.Conn
	opts := nats.GetDefaultOptions()
	for _, o := range tenantBusOptions("tenant-a", &tls.Config{}, nats.Name("test"), func(c *nats.Conn) { closed = c }) {
		if err := o(&opts); err != nil {
			t.Fatalf("applying option: %v", err)
		}
	}
	if opts.MaxReconnect != -1 {
		t.Errorf("MaxReconnect = %d, want -1 (reconnect forever)", opts.MaxReconnect)
	}
	if !opts.RetryOnFailedConnect {
		t.Error("RetryOnFailedConnect is off")
	}
	if opts.ReconnectWait != tenantBusReconnectWait {
		t.Errorf("ReconnectWait = %s, want %s", opts.ReconnectWait, tenantBusReconnectWait)
	}
	if opts.ClosedCB == nil {
		t.Fatal("no ClosedHandler")
	}
	nc := &nats.Conn{}
	opts.ClosedCB(nc)
	if closed != nc {
		t.Error("ClosedHandler did not call onClosed with the connection")
	}
	// The other handlers only log; they must not panic before or after
	// the attempt counter wraps the old limit.
	for range 2 * maxFarmerReconnect {
		if opts.ReconnectErrCB != nil {
			opts.ReconnectErrCB(nc, errors.New("bus away"))
		}
	}
	opts.ReconnectedCB(nc)
	opts.DisconnectedErrCB(nc, errors.New("bus away"))
}

// A real connection built from tenantBusOptions reports its close to
// onClosed.
func TestTenantBusOptionsClosedHandlerFires(t *testing.T) {
	ns, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1})
	if err != nil {
		t.Fatalf("start test NATS server: %v", err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS server failed to become ready")
	}
	t.Cleanup(ns.Shutdown)

	done := make(chan *nats.Conn, 1)
	opts := tenantBusOptions("tenant-a", nil, nats.Name("test"), func(c *nats.Conn) { done <- c })
	// Plain-text test server: drop Secure (the first option).
	nc, err := nats.Connect(ns.ClientURL(), opts[1:]...)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	nc.Close()
	select {
	case c := <-done:
		if c != nc {
			t.Error("onClosed got another connection")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("onClosed never ran")
	}
}

func TestDurationEnv(t *testing.T) {
	const name = "IMAS_TEST_TENANT_CONN_DURATION"
	for _, tc := range []struct {
		val     string
		want    time.Duration
		wantErr bool
	}{
		{"", 7 * time.Minute, false},
		{"  ", 7 * time.Minute, false},
		{"15m", 15 * time.Minute, false},
		{"90s", 90 * time.Second, false},
		{"0s", 0, true},
		{"-1m", 0, true},
		{"soon", 0, true},
	} {
		t.Setenv(name, tc.val)
		got, err := durationEnv(name, 7*time.Minute)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("durationEnv(%q) = (%s, %v), want (%s, error %v)", tc.val, got, err, tc.want, tc.wantErr)
		}
	}
}

func TestTenantConnDefaults(t *testing.T) {
	if defaultTenantConnIdleTTL != 10*time.Minute {
		t.Errorf("idle TTL default = %s, want 10m (brief §3)", defaultTenantConnIdleTTL)
	}
	if defaultTenantConnHeartbeatWindow != 15*time.Minute {
		t.Errorf("heartbeat window default = %s, want 15m (owner decision 3)", defaultTenantConnHeartbeatWindow)
	}
}

func TestTenantForBusConnect(t *testing.T) {
	const farmerPub = "UFARMER"
	tenants := map[string]string{"ATENANTA": "tenant-a"}
	tenantFor := func(acc string) (string, error) {
		if id, ok := tenants[acc]; ok {
			return id, nil
		}
		return "", errors.New("not a tenant")
	}
	for _, tc := range []struct {
		name   string
		data   string
		want   string
		wantOK bool
	}{
		{"sprout", `{"client":{"user":"USPROUT","acc":"ATENANTA"}}`, "tenant-a", true},
		{"farmer itself", `{"client":{"user":"UFARMER","acc":"ATENANTA"}}`, "", false},
		{"not a tenant (SYS)", `{"client":{"user":"USAAS","acc":"ASYS"}}`, "", false},
		{"no account", `{"client":{"user":"USPROUT"}}`, "", false},
		{"malformed", `{"client":`, "", false},
	} {
		got, ok := tenantForBusConnect([]byte(tc.data), farmerPub, tenantFor)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("%s: tenantForBusConnect = (%q, %v), want (%q, %v)", tc.name, got, ok, tc.want, tc.wantOK)
		}
	}
	// Without a known farmer key nothing is excluded by user.
	if got, ok := tenantForBusConnect([]byte(`{"client":{"user":"UFARMER","acc":"ATENANTA"}}`), "", tenantFor); !ok || got != "tenant-a" {
		t.Errorf("with no farmer key: (%q, %v), want (tenant-a, true)", got, ok)
	}
}

// Boot connects only provisioned tenants that have accepted sprouts, and
// never the legacy tenant a second time.
func TestBootTenants(t *testing.T) {
	withSprouts := map[string]bool{"tenant-a": true, "legacy": true, "tenant-c": true}
	got := bootTenants([]string{"tenant-a", "tenant-b", "legacy", "tenant-c"}, "legacy", func(id string) bool { return withSprouts[id] })
	if want := []string{"tenant-a", "tenant-c"}; !slices.Equal(got, want) {
		t.Errorf("bootTenants = %v, want %v", got, want)
	}
}

// A sprout heartbeat and a NATS API request on a tenant connection both
// keep it from being swept as idle, seen by every replica's observer.
func TestWatchTenantActivityKeepsTenantOpen(t *testing.T) {
	ns, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1})
	if err != nil {
		t.Fatalf("start test NATS server: %v", err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS server failed to become ready")
	}
	t.Cleanup(ns.Shutdown)

	var mu sync.Mutex
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }

	for _, tc := range []struct{ name, subject string }{
		{"heartbeat", pki.SproutHeartbeatSubjectPrefix + "sprout-1"},
		{"api request", natsapi.Subject("sprouts.list")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var r *tenantconn.Registry
			r = tenantconn.New(tenantconn.Config{
				IdleTTL:         10 * time.Minute,
				HeartbeatWindow: 15 * time.Minute,
				Now:             clock,
				Dial: func(_ context.Context, id string, _ func(*nats.Conn)) (*nats.Conn, error) {
					nc, err := nats.Connect(ns.ClientURL())
					if err != nil {
						return nil, err
					}
					return nc, watchTenantActivity(nc, id, r)
				},
			})
			nc, err := r.Get(context.Background(), "tenant-a")
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			t.Cleanup(nc.Close)
			pub, err := nats.Connect(ns.ClientURL())
			if err != nil {
				t.Fatalf("connect publisher: %v", err)
			}
			t.Cleanup(pub.Close)

			advance(11 * time.Minute)
			if err := pub.Publish(tc.subject, nil); err != nil {
				t.Fatalf("publish: %v", err)
			}
			if err := pub.Flush(); err != nil {
				t.Fatalf("flush: %v", err)
			}
			if err := nc.Flush(); err != nil { // the observer has run by now
				t.Fatalf("flush: %v", err)
			}
			time.Sleep(50 * time.Millisecond)
			if got := r.Sweep(); len(got) != 0 {
				t.Fatalf("Sweep closed %v right after a %s", got, tc.name)
			}
			advance(16 * time.Minute)
			if got := r.Sweep(); len(got) != 1 {
				t.Fatalf("Sweep with no activity for 16m closed %v, want [tenant-a]", got)
			}
		})
	}
}
