package natsretry

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	nats "github.com/nats-io/nats.go"
)

// TestNATSRestartsAttemptCountAfterReconnect pins the nats.go behaviour
// the reset-after-success relies on: CustomReconnectDelay's attempt
// number starts again at 1 in every outage, after a successful
// reconnect. If a nats.go upgrade changed that, a sprout would carry its
// backoff from one outage into the next and never get back to the base
// window.
func TestNATSRestartsAttemptCountAfterReconnect(t *testing.T) {
	ns := startServer(t, -1)
	url := ns.ClientURL()
	port := ns.Addr().(*net.TCPAddr).Port

	var mu sync.Mutex
	var attempts []int
	reconnected := make(chan struct{}, 4)
	nc, err := nats.Connect(url,
		nats.MaxReconnects(-1),
		nats.CustomReconnectDelay(func(n int) time.Duration {
			mu.Lock()
			attempts = append(attempts, n)
			mu.Unlock()
			return 20 * time.Millisecond
		}),
		nats.ReconnectHandler(func(*nats.Conn) { reconnected <- struct{}{} }),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()

	outage := func() []int {
		mu.Lock()
		attempts = nil
		mu.Unlock()
		ns.Shutdown()
		ns.WaitForShutdown()
		// Let several passes fail while the server is down.
		deadline := time.Now().Add(5 * time.Second)
		for {
			mu.Lock()
			n := len(attempts)
			mu.Unlock()
			if n >= 3 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("nats.go did not retry while the server was down")
			}
			time.Sleep(10 * time.Millisecond)
		}
		ns = startServer(t, port)
		select {
		case <-reconnected:
		case <-time.After(5 * time.Second):
			t.Fatal("did not reconnect after the server came back")
		}
		mu.Lock()
		defer mu.Unlock()
		return append([]int(nil), attempts...)
	}

	first := outage()
	second := outage()
	for i, got := range [][]int{first, second} {
		for j, n := range got {
			if n != j+1 {
				t.Fatalf("outage %d: attempt numbers %v, want 1, 2, 3, ...", i+1, got)
			}
		}
	}
}

func startServer(t *testing.T, port int) *server.Server {
	t.Helper()
	ns, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: port, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS server not ready")
	}
	t.Cleanup(ns.Shutdown)
	return ns
}
