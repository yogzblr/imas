package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"
	"golang.org/x/crypto/curve25519"

	"github.com/yogzblr/imas/internal/facts"
	"github.com/yogzblr/imas/internal/heartbeat"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
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
	if o.Restart != "local" || o.MaxP99 != requirement10 || o.Heartbeat != heartbeat.Interval {
		t.Errorf("local bus defaults: restart %q, max-p99 %s, heartbeat-interval %s", o.Restart, o.MaxP99, o.Heartbeat)
	}
	for _, args := range [][]string{
		{"-servers", "tls://bus:4222"}, // no CA, tenant, SaaS API or farmer
		append([]string{"-restart", "local"}, externalArgs...),
		append(externalArgs[:len(externalArgs):len(externalArgs)], "-tenant", "not a tenant"),
		append(externalArgs[:len(externalArgs):len(externalArgs)], "-farmer-url", "http://farmer:5405"),
		append(externalArgs[:len(externalArgs):len(externalArgs)], "-saasapi-url", "core.example"),
		append(externalArgs[:len(externalArgs):len(externalArgs)], "-enroll-key-uses", "0"),
		append(externalArgs[:len(externalArgs):len(externalArgs)], "-enroll-key-uses", "10001"),
		append(externalArgs[:len(externalArgs):len(externalArgs)], "-enroll-key-hours", "721"),
		append(externalArgs[:len(externalArgs):len(externalArgs)], "-enroll-workers", "0"),
		// The trust seed flags are gone: a deployed bus has no seed to give.
		append(externalArgs[:len(externalArgs):len(externalArgs)], "-operator-signing-seed-file", "y"),
		append(externalArgs[:len(externalArgs):len(externalArgs)], "-sys-account-seed-file", "z"),
		append(externalArgs[:len(externalArgs):len(externalArgs)], "-lockout=false"),
		{"-restart", "cmd"}, // no -restart-cmd
		{"-restart", "sometimes"},
		{"-restart-signal", "hup"},
		{"-id-prefix", "-bad"},
		{"-id-prefix", "a.b"},
		{"-sprouts", "0"},
		{"-bus-max-connections", "-1"},
		{"-heartbeat-interval", "-1s"},
		{"-proc", "core"},
		{"stray"},
	} {
		if _, err := parseOptions(args); err == nil {
			t.Errorf("parseOptions(%q) accepted", args)
		}
	}
	o, err = parseOptions(append(externalArgs[:len(externalArgs):len(externalArgs)], "-proc", "core=42"))
	if err != nil {
		t.Fatal(err)
	}
	if o.Restart != "none" || len(o.Procs) != 1 || o.Procs[0].Label != "core" || o.Procs[0].PID != 42 {
		t.Errorf("external defaults: restart %q, procs %+v", o.Restart, o.Procs)
	}
	if o.EnrollKeyUses != 1 || o.EnrollKeyHours != 1 || o.EnrollWorkers != 8 || o.EnrollRetries != 2 {
		t.Errorf("enrolment defaults: uses %d, hours %d, workers %d, retries %d", o.EnrollKeyUses, o.EnrollKeyHours, o.EnrollWorkers, o.EnrollRetries)
	}
}

// externalArgs is the least a run against a deployed bus needs: no
// trust key, only what the enrolment path takes.
var externalArgs = []string{
	"-servers", "tls://b:1", "-ca", "x", "-tenant", "t_loadtest1",
	"-saasapi-url", "https://core.example", "-internal-auth-file", "a", "-token-file", "b",
	"-farmer-url", "https://dmz.example:8443",
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
	fl := newFleet(creds[:1], fleetOptions{Servers: []string{bus.URL()}, TLS: tlsCfg, ConnectTimeout: 5 * time.Second, Facts: &facts.SystemFacts{OS: "linux"}})
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

// Load-test sprouts send heartbeats as a sprout does: once at connect and
// then every interval, on their own subject with the connection's ID as
// the body, and the bus lets them (the grant is pki.SproutPermissions').
func TestFleetSproutsSendHeartbeats(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a bus process")
	}
	bus, tlsCfg, _, tf := startTestBus(t)
	creds, err := tf.mintSprouts("hb", 3)
	if err != nil {
		t.Fatal(err)
	}
	core, err := nats.Connect(bus.URL(), nats.Secure(tlsCfg), nats.UserJWTAndSeed(tf.coreJWT, tf.coreSeed))
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	beats, err := core.SubscribeSync(pki.SproutHeartbeatSubjectPattern)
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Flush(); err != nil {
		t.Fatal(err)
	}

	fl := newFleet(creds, fleetOptions{Servers: []string{bus.URL()}, TLS: tlsCfg, ConnectTimeout: 5 * time.Second, HeartbeatInterval: 300 * time.Millisecond})
	defer fl.Close()
	if res := fl.connectAll(context.Background(), 0, 1, 0); res.Connected != 3 {
		t.Fatalf("connected %d of 3 (reasons %v)", res.Connected, res.Reasons)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fl.startHeartbeats(ctx)

	got := map[string]int{}
	deadline := time.Now().Add(10 * time.Second)
	for len(got) < 3 || got[creds[0].ID] < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("heartbeats per sprout %v; want every sprout, the first at least 3 times", got)
		}
		m, err := beats.NextMsg(time.Second)
		if err != nil {
			continue
		}
		id := strings.TrimPrefix(m.Subject, pki.SproutHeartbeatSubjectPrefix)
		nc := fl.conn(slices.IndexFunc(creds, func(c sproutCred) bool { return c.ID == id }))
		cid, _ := nc.GetClientID()
		if want := heartbeat.ConnID(nc.ConnectedServerId(), cid); want == "" || string(m.Data) != want {
			t.Fatalf("heartbeat of %s has body %q, want its connection ID %q", id, m.Data, want)
		}
		got[id]++
	}
	if fl.heartbeatErrors.Load() != 0 {
		t.Fatalf("%d heartbeat publishes failed", fl.heartbeatErrors.Load())
	}
	for i := range creds {
		if err := fl.conn(i).LastError(); err != nil {
			t.Fatalf("sprout %s: %v", creds[i].ID, err)
		}
	}
}

// The fleet's heartbeat rate is one per sprout per interval whatever the
// fleet size: a fleet smaller than the ticks in an interval must not send
// one per tick.
func TestFleetHeartbeatRate(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a bus process")
	}
	bus, tlsCfg, _, tf := startTestBus(t)
	creds, err := tf.mintSprouts("rate", 5)
	if err != nil {
		t.Fatal(err)
	}
	const interval = 2 * time.Second
	fl := newFleet(creds, fleetOptions{Servers: []string{bus.URL()}, TLS: tlsCfg, ConnectTimeout: 5 * time.Second, HeartbeatInterval: interval})
	defer fl.Close()
	if res := fl.connectAll(context.Background(), 0, 1, 0); res.Connected != 5 {
		t.Fatalf("connected %d of 5 (reasons %v)", res.Connected, res.Reasons)
	}
	before := fl.heartbeats.Load() // one per sprout at connect
	ctx, cancel := context.WithCancel(context.Background())
	fl.startHeartbeats(ctx)
	time.Sleep(2 * interval)
	cancel()
	// Two intervals: 10 heartbeats for 5 sprouts. A per-tick minimum would
	// send about 40.
	if n := fl.heartbeats.Load() - before; n < 8 || n > 11 {
		t.Fatalf("%d heartbeats from 5 sprouts in two %s intervals, want about 10", n, interval)
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
	if res.HeartbeatInterval != heartbeat.Interval.String() || res.SproutHeartbeats < 30 || res.SproutHeartbeatErrors != 0 {
		t.Errorf("heartbeats: interval %q, %d sent, %d failed; want %s and at least one per sprout", res.HeartbeatInterval, res.SproutHeartbeats, res.SproutHeartbeatErrors, heartbeat.Interval)
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

// Load-test sprouts seal their facts as a sprout does (s2f.facts, U3):
// at connect and in answer to facts.request, each under its own box key
// to the tenant key, and the run reports what sealing cost.
func TestFleetSealsFacts(t *testing.T) {
	bus, tlsCfg, _, tf := startTestBus(t)
	creds, err := tf.mintSprouts("fs", 1)
	if err != nil {
		t.Fatal(err)
	}
	core, err := nats.Connect(bus.URL(), nats.Secure(tlsCfg), nats.UserJWTAndSeed(tf.coreJWT, tf.coreSeed))
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	reports, err := core.SubscribeSync("imas.sprouts.*.facts")
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Flush(); err != nil {
		t.Fatal(err)
	}
	fl := newFleet(creds, fleetOptions{Servers: []string{bus.URL()}, TLS: tlsCfg, ConnectTimeout: 5 * time.Second, Facts: &facts.SystemFacts{OS: "linux", Hostname: "lt-host"}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fl.startWorkers(ctx)
	defer fl.Close()
	if err := fl.connectOne(0); err != nil {
		t.Fatal(err)
	}
	id := creds[0].ID
	pub, err := curve25519.X25519(creds[0].Box.Priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	var sproutPub [32]byte
	copy(sproutPub[:], pub)
	open := func(m *nats.Msg) facts.SystemFacts {
		t.Helper()
		if m.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 || bytes.Contains(m.Data, []byte("lt-host")) {
			t.Fatalf("facts not sealed: %v %q", m.Header, m.Data)
		}
		msg, err := payloadbox.Open(m.Data, []payloadbox.KeyPair{{PeerPub: &sproutPub, Priv: tf.boxPriv}},
			payloadbox.Expect{Purpose: payloadbox.PurposeFacts, TenantID: tf.name, SproutID: id})
		if err != nil {
			t.Fatalf("facts did not open as farmer opens them: %v", err)
		}
		var sf facts.SystemFacts
		if err := json.Unmarshal(msg.Body, &sf); err != nil {
			t.Fatal(err)
		}
		return sf
	}
	m, err := reports.NextMsg(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if sf := open(m); sf.SproutID != id || sf.Hostname != "lt-host" {
		t.Fatalf("report %+v", sf)
	}
	resp, err := core.Request("imas.sprouts."+id+".facts.request", nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if sf := open(resp); sf.SproutID != id {
		t.Fatalf("facts.request answer %+v", sf)
	}
	cost := fl.factsCost()
	if cost == nil || cost.Messages != 2 || cost.SealedBytes <= cost.PlainBytes || cost.OverheadBytes != cost.SealedBytes-cost.PlainBytes {
		t.Fatalf("facts cost %+v", cost)
	}
}
