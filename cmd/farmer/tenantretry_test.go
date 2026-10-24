package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"

	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/tenantconn"
)

// syncBuffer is a bytes.Buffer safe for the logger's writes.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// levels returns the level of every JSON log line mentioning tenantID.
func (b *syncBuffer) levels(t *testing.T, tenantID string) []string {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for _, line := range strings.Split(b.buf.String(), "\n") {
		if !strings.Contains(line, tenantID) {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		lvl, _ := m["level"].(string)
		out = append(out, lvl)
	}
	return out
}

// captureLogs sends farmer's terminal log, as JSON at debug and up, to
// the returned buffer for the rest of the test.
func captureLogs(t *testing.T) *syncBuffer {
	t.Helper()
	b := &syncBuffer{}
	log.SetOutput(b)
	log.SetFormat(log.FormatJSON)
	log.SetLogLevel(log.LDebug)
	t.Cleanup(func() {
		log.SetOutput(nil)
		log.SetFormat(log.FormatText)
	})
	return b
}

// retryHarness runs connectTenantWithRetry against a registry whose dialer
// always fails, with tenantBusStateOf answering state and tenantRetryWait
// recording each wait instead of sleeping. After maxWaits waits it ends
// the loop by cancelling its context.
type retryHarness struct {
	mu    sync.Mutex
	dials int
	waits []time.Duration
}

func runRetryLoop(t *testing.T, tenantID string, state func(string) tenantBusState, maxWaits int) *retryHarness {
	t.Helper()
	h := &retryHarness{}
	var dial tenantconn.Dialer = func(context.Context, string, func(*nats.Conn)) (*nats.Conn, error) {
		h.mu.Lock()
		h.dials++
		h.mu.Unlock()
		return nil, errors.New("NATS connection closed before it connected: authorization violation")
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	savedReg, savedState, savedWait := tenantRegistry, tenantBusStateOf, tenantRetryWait
	tenantRegistry = tenantconn.New(tenantconn.Config{Dial: dial})
	tenantBusStateOf = state
	tenantRetryWait = func(_ context.Context, d time.Duration) bool {
		h.mu.Lock()
		h.waits = append(h.waits, d)
		n := len(h.waits)
		h.mu.Unlock()
		if n >= maxWaits {
			cancel()
			return false
		}
		return true
	}
	t.Cleanup(func() {
		tenantRegistry, tenantBusStateOf, tenantRetryWait = savedReg, savedState, savedWait
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		connectTenantWithRetry(ctx, tenantID)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("connectTenantWithRetry did not return")
	}
	return h
}

// An offboarded tenant (no live pki_tenants row) stops after its first
// failed connect: no wait, no retry, no error log, and it is no longer
// counted as pending.
func TestConnectTenantWithRetryStopsForOffboardedTenant(t *testing.T) {
	logs := captureLogs(t)
	const tenant = "scratch-offboarded-t1"
	h := runRetryLoop(t, tenant, func(id string) tenantBusState {
		if id != tenant {
			t.Errorf("state asked for %q, want %q", id, tenant)
		}
		return tenantBusGone
	}, 100)

	if h.dials != 1 || len(h.waits) != 0 {
		t.Errorf("dials = %d, waits = %v; want one dial and no wait", h.dials, h.waits)
	}
	if tenantRegistry.Pending(tenant) {
		t.Error("the offboarded tenant is still pending")
	}
	if _, total := tenantRegistry.Counts(); total != 0 {
		t.Errorf("Counts total = %d, want 0", total)
	}
	for _, lvl := range logs.levels(t, tenant) {
		if lvl == "error" || lvl == "warn" {
			t.Errorf("logged at %s for an offboarded tenant", lvl)
		}
	}
}

// A tenant whose state can't be read is retried at the long interval and
// logged at debug, never at error.
func TestConnectTenantWithRetryUnknownStateBacksOffLongAtDebug(t *testing.T) {
	logs := captureLogs(t)
	const tenant = "unknown-state-tenant"
	h := runRetryLoop(t, tenant, func(string) tenantBusState { return tenantBusUnknown }, 3)

	want := []time.Duration{unknownTenantRetryInterval, unknownTenantRetryInterval, unknownTenantRetryInterval}
	if !equalDurations(h.waits, want) {
		t.Errorf("waits = %v, want %v", h.waits, want)
	}
	lvls := logs.levels(t, tenant)
	if len(lvls) != 3 {
		t.Fatalf("got %d log lines for the tenant (%v), want 3", len(lvls), lvls)
	}
	for _, lvl := range lvls {
		if lvl != "debug" {
			t.Errorf("retry logged at %q, want debug", lvl)
		}
	}
}

// A live tenant keeps the existing policy: 5s doubling to 5m, at error,
// and stays pending.
func TestConnectTenantWithRetryLiveTenantUnchanged(t *testing.T) {
	logs := captureLogs(t)
	const tenant = "live-tenant"
	h := runRetryLoop(t, tenant, func(string) tenantBusState { return tenantBusLive }, 9)

	want := []time.Duration{
		5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second,
		160 * time.Second, 5 * time.Minute, 5 * time.Minute, 5 * time.Minute,
	}
	if !equalDurations(h.waits, want) {
		t.Errorf("waits = %v, want %v", h.waits, want)
	}
	if !tenantRegistry.Pending(tenant) {
		t.Error("a live tenant stopped being pending")
	}
	lvls := logs.levels(t, tenant)
	if len(lvls) != 9 {
		t.Fatalf("got %d log lines for the tenant (%v), want 9", len(lvls), lvls)
	}
	for _, lvl := range lvls {
		if lvl != "error" {
			t.Errorf("retry logged at %q, want error", lvl)
		}
	}
}

// A tenant whose state read fails and then recovers resumes the live
// backoff where it left off; one found gone later stops.
func TestConnectTenantWithRetryStateChanges(t *testing.T) {
	const tenant = "flapping-tenant"
	states := []tenantBusState{tenantBusLive, tenantBusUnknown, tenantBusLive, tenantBusGone}
	var mu sync.Mutex
	i := 0
	h := runRetryLoop(t, tenant, func(string) tenantBusState {
		mu.Lock()
		defer mu.Unlock()
		s := states[i]
		i++
		return s
	}, 100)
	want := []time.Duration{5 * time.Second, unknownTenantRetryInterval, 10 * time.Second}
	if !equalDurations(h.waits, want) {
		t.Errorf("waits = %v, want %v", h.waits, want)
	}
	if h.dials != 4 {
		t.Errorf("dials = %d, want 4", h.dials)
	}
	if tenantRegistry.Pending(tenant) {
		t.Error("the tenant is still pending after it was found gone")
	}
}

func TestTenantRetryAfterFailure(t *testing.T) {
	cases := []struct {
		name    string
		state   tenantBusState
		backoff time.Duration
		want    tenantRetryStep
	}{
		{"live first", tenantBusLive, 5 * time.Second, tenantRetryStep{tenantRetryLive, 5 * time.Second, 10 * time.Second}},
		{"live capped", tenantBusLive, 4 * time.Minute, tenantRetryStep{tenantRetryLive, 4 * time.Minute, 5 * time.Minute}},
		{"live at cap", tenantBusLive, 5 * time.Minute, tenantRetryStep{tenantRetryLive, 5 * time.Minute, 5 * time.Minute}},
		{"unknown", tenantBusUnknown, 20 * time.Second, tenantRetryStep{tenantRetryUnknown, unknownTenantRetryInterval, 20 * time.Second}},
		{"gone", tenantBusGone, 20 * time.Second, tenantRetryStep{action: tenantRetryStop}},
	}
	for _, c := range cases {
		if got := tenantRetryAfterFailure(c.state, c.backoff); got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
	if unknownTenantRetryInterval <= liveTenantRetryMax {
		t.Errorf("unknownTenantRetryInterval %s is not longer than the live cap %s", unknownTenantRetryInterval, liveTenantRetryMax)
	}
}

func TestTenantStateFromProvisioned(t *testing.T) {
	ids := []string{"acme", "globex"}
	if got := tenantStateFromProvisioned("globex", ids); got != tenantBusLive {
		t.Errorf("provisioned tenant: got %v, want live", got)
	}
	if got := tenantStateFromProvisioned("scratch-t4", ids); got != tenantBusGone {
		t.Errorf("unprovisioned tenant: got %v, want gone", got)
	}
	if got := tenantStateFromProvisioned("acme", nil); got != tenantBusGone {
		t.Errorf("no tenants provisioned: got %v, want gone", got)
	}
}

// The legacy tenant is live without a PXC read (it has no pki_tenants
// row), so its retries keep the existing policy.
func TestTenantBusStateOfLegacyTenantIsLive(t *testing.T) {
	if got := tenantBusStateOf(pki.CurrentTenantID()); got != tenantBusLive {
		t.Errorf("legacy tenant: got %v, want live", got)
	}
}

func equalDurations(a, b []time.Duration) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
