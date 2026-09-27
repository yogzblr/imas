package main

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	nats "github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/busstatus"
)

func startBus(t *testing.T, port int) *natsserver.Server {
	t.Helper()
	ns, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: port})
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

// waitForState polls the status file until it records want.
func waitForState(t *testing.T, path string, want busstatus.State) busstatus.Status {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var st busstatus.Status
	var err error
	for time.Now().Before(deadline) {
		if st, err = busstatus.Read(path); err == nil && st.State == want {
			return st
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("status never became %s: last %+v, %v", want, st, err)
	return st
}

// TestBusConnectOptionsRecordState drives ConnectSprout's nats.go options
// through a connection, its loss, a reconnection and a shutdown, against a
// real NATS server.
func TestBusConnectOptionsRecordState(t *testing.T) {
	ns := startBus(t, -1)
	url := ns.ClientURL()
	_, portStr, err := net.SplitHostPort(ns.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bus-status.json")
	rec := busstatus.NewRecorder(path)
	rec.Starting()
	waitForState(t, path, busstatus.Starting)

	reconnected := make(chan struct{}, 1)
	opts := append(busConnectOptions(rec, func() {
		select {
		case reconnected <- struct{}{}:
		default:
		}
	}),
		nats.ReconnectWait(20*time.Millisecond), nats.ReconnectJitter(0, 0))
	nc, err := nats.Connect(url, opts...)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer nc.Close()

	st := waitForState(t, path, busstatus.Connected)
	if st.Server != url || st.PID != os.Getpid() {
		t.Errorf("connected: %+v, want server %s, pid %d", st, url, os.Getpid())
	}

	ns.Shutdown()
	st = waitForState(t, path, busstatus.Disconnected)
	if st.Server != url {
		t.Errorf("disconnected: server %q, want the lost %s", st.Server, url)
	}

	// The same address, so nats.go reconnects to it.
	startBus(t, port)
	waitForState(t, path, busstatus.Connected)
	select {
	case <-reconnected:
	case <-time.After(10 * time.Second):
		t.Fatal("onReconnect wasn't called")
	}

	// ConnectSprout's shutdown: Stopped, then Close, whose disconnect and
	// close callbacks must not overwrite it.
	rec.Stopped()
	nc.Close()
	time.Sleep(100 * time.Millisecond)
	if st, err := busstatus.Read(path); err != nil || st.State != busstatus.Stopped {
		t.Errorf("after Stopped and Close: %+v, %v", st, err)
	}
}
