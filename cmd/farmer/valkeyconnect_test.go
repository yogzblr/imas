package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/valkey-io/valkey-go"

	"github.com/yogzblr/imas/internal/accountloader"
	"github.com/yogzblr/imas/internal/api/handlers"
	"github.com/yogzblr/imas/internal/heartbeat"
	"github.com/yogzblr/imas/internal/pki"
)

// freeAddr returns a loopback address nothing listens on.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func healthValkey(t *testing.T, h http.HandlerFunc) (int, string) {
	t.Helper()
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodGet, "/", nil))
	var body struct {
		Valkey string `json:"valkey"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return w.Code, body.Valkey
}

// P30: farmer started before Valkey. /health is 200 throughout, /ready
// reports Valkey as connecting, and once Valkey comes up the background
// retry installs the client and /ready sees it, with no restart.
func TestConnectValkeyAfterValkeyStartsLate(t *testing.T) {
	t.Cleanup(func() {
		handlers.SetReadinessValkey(nil)
		heartbeat.SetClient(nil)
		pki.SetReplayCacheClient(nil)
	})
	handlers.SetReadinessValkey(nil)
	addr := freeAddr(t)
	dial := func() (valkey.Client, error) {
		return valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}, DisableCache: true})
	}
	if _, err := dial(); err == nil {
		t.Fatal("dialled Valkey before it started")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	installed := make(chan valkey.Client, 1)
	go connectValkey(ctx, dial, func(c valkey.Client) {
		installValkeyClient(c)
		installed <- c
	}, accountloader.Backoff{Min: 10 * time.Millisecond, Max: 50 * time.Millisecond})

	if code, v := healthValkey(t, handlers.GetHealth); code != http.StatusOK || v != "connecting" {
		t.Fatalf("/health before Valkey = %d %q, want 200 connecting", code, v)
	}
	if code, v := healthValkey(t, handlers.GetReady); code != http.StatusServiceUnavailable || v != "connecting" {
		t.Fatalf("/ready before Valkey = %d %q, want 503 connecting", code, v)
	}

	time.Sleep(100 * time.Millisecond) // a few failed attempts
	mr := miniredis.NewMiniRedis()
	if err := mr.StartAddr(addr); err != nil {
		t.Fatal(err)
	}
	defer mr.Close()

	var c valkey.Client
	select {
	case c = <-installed:
		defer c.Close()
	case <-time.After(10 * time.Second):
		t.Fatal("the client was not installed after Valkey started")
	}
	if code, v := healthValkey(t, handlers.GetHealth); code != http.StatusOK || v != "ok" {
		t.Fatalf("/health after Valkey = %d %q, want 200 ok", code, v)
	}
	if _, v := healthValkey(t, handlers.GetReady); v != "ok" {
		t.Fatalf("/ready valkey after Valkey = %q, want ok", v)
	}
	// The replay cache has the client too: enrollment no longer fails
	// closed for want of one.
	if err := pki.ClaimSealedMessage(ctx, "t1", "p1", "m1"); err != nil {
		t.Fatalf("claim after Valkey: %v", err)
	}
}

// connectValkey gives up when farmer shuts down.
func TestConnectValkeyStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		connectValkey(ctx, func() (valkey.Client, error) { return nil, net.ErrClosed },
			func(valkey.Client) { t.Error("installed a client that never connected") },
			accountloader.Backoff{Min: time.Millisecond, Max: 5 * time.Millisecond})
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("connectValkey did not return after its context ended")
	}
}
