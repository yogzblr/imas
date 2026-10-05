package main

import (
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/natsapi"
)

// Farmer's stop ends shell sessions while the tenant buses are still
// connected, so the CLOSE frames (farmer-shutdown) can go out, and only
// then closes them.
func TestCloseTenantConnsEndsShellSessionsFirst(t *testing.T) {
	conns := []*nats.Conn{startTestNATS(t), startTestNATS(t)}
	var called bool
	closeShellSessions = func() {
		called = true
		for i, c := range conns {
			if !c.IsConnected() {
				t.Errorf("tenant connection %d closed before the shell sessions ended", i)
			}
		}
	}
	t.Cleanup(func() { closeShellSessions = natsapi.CloseShellSessions })
	closeTenantConns(conns)
	if !called {
		t.Fatal("farmer's stop never ended the shell sessions")
	}
	for i, c := range conns {
		if !c.IsClosed() {
			t.Errorf("tenant connection %d left open", i)
		}
	}
}

// A shell session that won't end doesn't hold up the rest of the stop.
func TestCloseTenantConnsBoundsShellWait(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	closeShellSessions = func() { <-release }
	shellShutdownTimeout = 50 * time.Millisecond
	t.Cleanup(func() { closeShellSessions = natsapi.CloseShellSessions; shellShutdownTimeout = 5 * time.Second })
	nc := startTestNATS(t)
	start := time.Now()
	closeTenantConns([]*nats.Conn{nc})
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("stop waited %s on a stuck session", d)
	}
	if !nc.IsClosed() {
		t.Fatal("tenant connection left open")
	}
}
