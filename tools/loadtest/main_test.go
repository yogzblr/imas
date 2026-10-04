package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"
)

// TestMain lets the test binary be the local bus's child process, as the
// built tool is (localbus.go).
func TestMain(m *testing.M) {
	if os.Getenv(envRole) == roleBus {
		if err := runBusNode(); err != nil {
			fmt.Fprintln(os.Stderr, "bus node:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestParseOptionsSmokePresetYieldsToExplicitFlags(t *testing.T) {
	o, err := parseOptions([]string{"-smoke", "-sprouts", "50", "-max-p99", "2s"})
	if err != nil {
		t.Fatal(err)
	}
	if o.Sprouts != 50 || o.MaxP99 != 2*time.Second {
		t.Errorf("explicit flags lost: sprouts %d, max-p99 %s", o.Sprouts, o.MaxP99)
	}
	if o.Hold != 20*time.Second || o.Restart != "local" || o.MaxFullReconnect != 60*time.Second || o.Deadline != 170*time.Second {
		t.Errorf("preset not applied: hold %s, restart %s, max-full-reconnect %s, deadline %s", o.Hold, o.Restart, o.MaxFullReconnect, o.Deadline)
	}
}

func TestParseOptionsDefaultsAndErrors(t *testing.T) {
	o, err := parseOptions(nil)
	if err != nil {
		t.Fatal(err)
	}
	if o.Restart != "local" || o.MaxP99 != requirement10 {
		t.Errorf("local bus defaults: restart %q, max-p99 %s", o.Restart, o.MaxP99)
	}
	for _, args := range [][]string{
		{"-servers", "tls://bus:4222"}, // no seeds or CA
		{"-restart", "local", "-servers", "tls://b:1", "-ca", "x", "-operator-signing-seed-file", "y", "-sys-account-seed-file", "z"},
		{"-restart", "cmd"}, // no -restart-cmd
		{"-restart", "sometimes"},
		{"-restart-signal", "hup"},
		{"-id-prefix", "-bad"},
		{"-id-prefix", "a.b"},
		{"-sprouts", "0"},
		{"-bus-max-connections", "-1"},
		{"-proc", "core"},
		{"stray"},
	} {
		if _, err := parseOptions(args); err == nil {
			t.Errorf("parseOptions(%q) accepted", args)
		}
	}
	o, err = parseOptions([]string{"-servers", "tls://b:1", "-ca", "x", "-operator-signing-seed-file", "y", "-sys-account-seed-file", "z", "-proc", "core=42"})
	if err != nil {
		t.Fatal(err)
	}
	if o.Restart != "none" || len(o.Procs) != 1 || o.Procs[0].Label != "core" || o.Procs[0].PID != 42 {
		t.Errorf("external defaults: restart %q, procs %+v", o.Restart, o.Procs)
	}
}

// startTestBus runs a local bus child for one test and returns it with a
// client TLS config and a tenant already pushed to it.
func startTestBus(t *testing.T) (*localBus, *tls.Config, *trust, *tenantFixture) {
	t.Helper()
	return startTestBusMaxConn(t, 0)
}

func startTestBusMaxConn(t *testing.T, maxConn int) (*localBus, *tls.Config, *trust, *tenantFixture) {
	t.Helper()
	dir := t.TempDir()
	tr, seeds, err := newLocalTrust(dir)
	if err != nil {
		t.Fatal(err)
	}
	bus, pool, err := newLocalBus(dir, "127.0.0.1", 0, seeds, false)
	if err != nil {
		t.Fatal(err)
	}
	bus.maxConn = maxConn
	t.Cleanup(bus.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := bus.Start(ctx); err != nil {
		log, _ := os.ReadFile(filepath.Join(dir, "bus.log"))
		t.Fatalf("%v\n%s", err, log)
	}
	tlsCfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	tf, err := tr.newTenant("loadtest-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.pushAccount([]string{bus.URL()}, tlsCfg, tf.accountJWT); err != nil {
		t.Fatal(err)
	}
	return bus, tlsCfg, tr, tf
}

// TestFixtureSproutIsConfinedToItsSubjects checks the bus enforces the
// minted grants: a simulated sprout can't listen on another sprout's
// subjects, and the requester playing core can reach it.
func TestFixtureSproutIsConfinedToItsSubjects(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a bus process")
	}
	bus, tlsCfg, _, tf := startTestBus(t)
	creds, err := tf.mintSprouts("conf", 2)
	if err != nil {
		t.Fatal(err)
	}
	errs := make(chan error, 4)
	nc, err := nats.Connect(bus.URL(), nats.Secure(tlsCfg), nats.UserJWTAndSeed(creds[0].JWT, creds[0].Seed),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) { errs <- err }))
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	if _, err := nc.SubscribeSync(pingSubject(creds[1].ID)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errs:
		if !strings.Contains(strings.ToLower(err.Error()), "permissions violation") {
			t.Fatalf("got %v, want a permissions violation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("subscribing to another sprout's subject was not refused")
	}

	// Its own subject works end to end with the core requester.
	fl := newFleet(creds[:1], fleetOptions{Servers: []string{bus.URL()}, TLS: tlsCfg, ConnectTimeout: 5 * time.Second, Facts: []byte(`{}`)})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fl.startWorkers(ctx)
	defer fl.Close()
	if err := fl.connectOne(0); err != nil {
		t.Fatal(err)
	}
	req, err := newRequester([]string{bus.URL()}, tlsCfg, tf, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer req.Close()
	l := pingWindow(ctx, "t", req, fl, 500*time.Millisecond, 20, 4, 2*time.Second)
	if l.OK == 0 || l.failed() != 0 {
		t.Fatalf("pings: %+v", l)
	}
}

func TestRunLocalEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a bus process and runs for several seconds")
	}
	o, err := parseOptions([]string{
		"-sprouts", "30", "-hold", "1s", "-after", "1s", "-ping-rate", "40",
		"-reconnect-base", "100ms", "-reconnect-cap", "1s", "-settle", "200ms",
		"-restart-downtime", "300ms", "-sample-interval", "300ms",
		"-max-p99", "2s", "-max-ping-fail-ratio", "0.05", "-max-full-reconnect", "30s",
		"-workdir", t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := run(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	res.writeText(&sb)
	if !res.passed() {
		t.Fatalf("checks failed:\n%s", sb.String())
	}
	if res.Connect.Connected != 30 || res.Restart == nil || res.Restart.Disconnected < 30 || res.Restart.FullReconnectSeconds <= 0 {
		t.Fatalf("unexpected result:\n%s", sb.String())
	}
	if res.Restart.PeakReconnectPerSec == 0 || res.Restart.Attempts < 30 {
		t.Errorf("reconnects not counted: peak %d, attempts %d", res.Restart.PeakReconnectPerSec, res.Restart.Attempts)
	}
	if res.Hold.OK == 0 || res.After == nil || res.After.OK == 0 {
		t.Errorf("latency windows empty:\n%s", sb.String())
	}
	if len(res.Bus) != 1 || res.Bus[0].Name != "loadtest-bus" || res.Bus[0].ConnectionsMax < 30 {
		t.Errorf("bus varz: %+v", res.Bus)
	}
	if res.SproutHandledPings < res.Hold.OK {
		t.Errorf("sprouts answered %d pings, requester counted %d", res.SproutHandledPings, res.Hold.OK)
	}
}

// TestBusConnectionLimit checks -bus-max-connections reaches the local
// bus (config.BusMaxConnections) and that the harness names the refusal,
// which a client of the TLS-only bus sees only as a TLS failure.
func TestBusConnectionLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a bus process")
	}
	bus, tlsCfg, _, tf := startTestBusMaxConn(t, 5)
	creds, err := tf.mintSprouts("cap", 8)
	if err != nil {
		t.Fatal(err)
	}
	fl := newFleet(creds, fleetOptions{Servers: []string{bus.URL()}, TLS: tlsCfg, ConnectTimeout: 5 * time.Second})
	defer fl.Close()
	res := fl.connectAll(context.Background(), 0, 1, 0)
	if res.Connected != 5 || res.NotConnected != 3 {
		t.Fatalf("connected %d, not connected %d; want 5 and 3 (reasons %v)", res.Connected, res.NotConnected, res.Reasons)
	}
	if n := res.Reasons["refused during TLS (a bus at its connection limit does this)"]; n != 3 {
		t.Errorf("reasons %v: want 3 connection-limit refusals", res.Reasons)
	}
}
