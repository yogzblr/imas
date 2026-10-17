package main

// The single-node bus: nats-server's log level (loglevel.go, security
// review 2026-10 L13) and the SYS gate (sysgate.go, L14), on a real node
// built the way cmd/farmerbus builds one (pki.ConfigureBusNats +
// startBus) and, for the gate, a real account loader.

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	nats_server "github.com/nats-io/nats-server/v2/server"
	nats "github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/config"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/pki"
)

func TestParseBusLogLevel(t *testing.T) {
	for _, tc := range []struct {
		in           string
		want         busLogLevel
		debug, trace bool
	}{
		{"", busLogInfo, false, false},
		{"info", busLogInfo, false, false},
		{"debug", busLogDebug, true, false},
		{" TRACE ", busLogTrace, true, true},
	} {
		got, err := parseBusLogLevel(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("parseBusLogLevel(%q) = %v, %v; want %v", tc.in, got, err, tc.want)
			continue
		}
		var opts nats_server.Options
		opts.Trace, opts.Debug = !tc.trace, !tc.debug // apply must set both ways
		got.apply(&opts)
		if opts.Debug != tc.debug || opts.Trace != tc.trace {
			t.Errorf("%q: Debug %v Trace %v, want %v %v", tc.in, opts.Debug, opts.Trace, tc.debug, tc.trace)
		}
	}
	for _, bad := range []string{"warn", "verbose", "1", "true"} {
		if _, err := parseBusLogLevel(bad); err == nil || !strings.Contains(err.Error(), envBusLogLevel) {
			t.Errorf("parseBusLogLevel(%q): err = %v, want one naming %s", bad, err, envBusLogLevel)
		}
	}
}

func TestBusLogLevelTerminalLevel(t *testing.T) {
	for _, tc := range []struct {
		l         busLogLevel
		cur, want log.Level
	}{
		{busLogInfo, log.LInfo, log.LInfo},
		{busLogInfo, log.LTrace, log.LTrace},
		{busLogDebug, log.LInfo, log.LDebug},
		{busLogDebug, log.LTrace, log.LTrace},
		{busLogTrace, log.LWarn, log.LTrace},
	} {
		if got := tc.l.terminalLevel(tc.cur); got != tc.want {
			t.Errorf("%v.terminalLevel(%v) = %v, want %v", tc.l, tc.cur, got, tc.want)
		}
	}
}

// syncBuffer is a bytes.Buffer the logger and the test share.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// startSingleNode starts one node without a cluster from the trust tr.
func startSingleNode(t *testing.T, setup busSetup) *busNode {
	t.Helper()
	config.FarmerPKI = t.TempDir() + "/"
	opts, sysUser := pki.ConfigureBusNats()
	opts.LogFile = ""
	setup.SysUser = sysUser
	if setup.Timing == (fenceTiming{}) {
		setup.Timing = testTiming
	}
	nd, err := startBus(opts, setup)
	if err != nil {
		t.Fatalf("startBus: %v", err)
	}
	t.Cleanup(nd.Shutdown)
	return nd
}

// publishCanary starts a single node at level, publishes a unique payload
// from a sprout and returns the payload and everything the terminal
// logger wrote meanwhile. The terminal logger is at trace, so only the
// bus's own level decides what nats-server logs.
func publishCanary(t *testing.T, level busLogLevel) (string, string) {
	t.Helper()
	tr := newTrust(t)
	out := &syncBuffer{}
	log.SetOutput(out)
	log.SetLogLevel(log.LTrace)
	t.Cleanup(func() {
		log.SetOutput(nil)
		log.SetLogLevel(log.LInfo)
	})
	nd := startSingleNode(t, busSetup{LogLevel: level, SysReady: func() bool { return true }})
	waitFor(t, "the SYS gate to open", 5*time.Second, nd.Ready)

	tn := tr.newTenant(t, "web-01")
	if err := tr.push(nd.srv.ClientURL(), tr.accountJWT(t, tn, false)); err != nil {
		t.Fatalf("pushing the tenant: %v", err)
	}
	nc, err := tr.dialSprout(tn, []string{nd.srv.ClientURL()})
	if err != nil {
		t.Fatalf("sprout connect: %v", err)
	}
	var b [12]byte
	_, _ = rand.Read(b[:])
	canary := "l13-canary-" + hex.EncodeToString(b[:])
	if err := nc.Publish("imas.sprouts."+tn.sproutID+".facts", []byte(canary)); err != nil {
		t.Fatal(err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	nc.Close()
	nd.Shutdown()
	nd.srv.WaitForShutdown()
	log.Flush()
	return canary, out.String()
}

// TestBusDefaultLogLevelLogsNoPayload: at the default level (no
// IMAS_BUS_LOG_LEVEL) a published payload never reaches the log, even
// with farmer's own loglevel at trace. The trace run is the control: it
// shows that nats-server's trace does carry payloads, so the default run
// is not passing for want of a log line.
func TestBusDefaultLogLevelLogsNoPayload(t *testing.T) {
	def, err := parseBusLogLevel("")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("default", func(t *testing.T) {
		canary, logged := publishCanary(t, def)
		if logged == "" {
			t.Fatal("nothing was logged at all: the capture is broken")
		}
		if strings.Contains(logged, canary) {
			t.Fatalf("the payload %q is in the bus log at the default level", canary)
		}
		if strings.Contains(logged, "[TRC]") || strings.Contains(logged, "<<- [PUB") {
			t.Fatal("nats-server trace lines are in the bus log at the default level")
		}
	})
	t.Run("debug", func(t *testing.T) {
		canary, logged := publishCanary(t, busLogDebug)
		if strings.Contains(logged, canary) {
			t.Fatalf("the payload %q is in the bus log at debug", canary)
		}
	})
	t.Run("trace control", func(t *testing.T) {
		canary, logged := publishCanary(t, busLogTrace)
		if !strings.Contains(logged, canary) {
			t.Fatal("at trace the payload is not in the log: the control does not show what the default run proves")
		}
	})
}

func TestLoaderReadyProbe(t *testing.T) {
	if _, err := loaderReadyProbe(""); !errors.Is(err, errNoSysReady) {
		t.Fatalf("empty URL: err = %v, want errNoSysReady", err)
	}
	for _, bad := range []string{
		"https://127.0.0.1:8081/readyz",
		"http://bus.example.com:8081/readyz",
		"http://10.0.0.5:8081/readyz",
		"http://localhost:8081/readyz",
		"http://127.0.0.1/readyz",
		"http://u:p@127.0.0.1:8081/readyz",
		"::bad",
	} {
		if _, err := loaderReadyProbe(bad); err == nil || !strings.Contains(err.Error(), envLoaderReadyURL) {
			t.Errorf("loaderReadyProbe(%q): err = %v, want one naming %s", bad, err, envLoaderReadyURL)
		}
	}

	var status atomic.Int32
	status.Store(http.StatusServiceUnavailable)
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/moved" {
			http.Redirect(w, r, "/readyz", http.StatusFound)
			return
		}
		w.WriteHeader(int(status.Load()))
	}))
	defer hs.Close()
	ready, err := loaderReadyProbe(hs.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	if ready() {
		t.Fatal("ready while the loader answers 503")
	}
	status.Store(http.StatusOK)
	if !ready() {
		t.Fatal("not ready while the loader answers 200")
	}
	moved, err := loaderReadyProbe(hs.URL + "/moved")
	if err != nil {
		t.Fatal(err)
	}
	if moved() {
		t.Fatal("a redirect was followed")
	}
	hs.Close()
	if ready() {
		t.Fatal("ready with the loader gone")
	}
}

// TestSysGateInstall: while closed, the client port refuses a peer that
// is not local and the websocket port refuses every handshake; open, both
// pass to the hooks they wrap.
func TestSysGateInstall(t *testing.T) {
	var prevCalled, nextCalled int
	opts := nats_server.Options{
		TLSConfig: &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			prevCalled++
			return nil, nil
		}},
	}
	opts.Websocket.TLSConfig = &tls.Config{VerifyConnection: func(tls.ConnectionState) error {
		nextCalled++
		return nil
	}}
	g := newSysGate(func() bool { return false }, nil, time.Hour)
	if err := g.install(&opts); err != nil {
		t.Fatal(err)
	}
	remote := &fakeConn{addr: &net.TCPAddr{IP: net.ParseIP("10.1.2.3"), Port: 40000}}
	local := &fakeConn{addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}}
	if _, err := opts.TLSConfig.GetConfigForClient(&tls.ClientHelloInfo{Conn: remote}); !errors.Is(err, errSysNotLoaded) {
		t.Fatalf("remote peer while closed: err = %v", err)
	}
	if _, err := opts.TLSConfig.GetConfigForClient(&tls.ClientHelloInfo{}); !errors.Is(err, errSysNotLoaded) {
		t.Fatalf("no peer address while closed: err = %v", err)
	}
	if _, err := opts.TLSConfig.GetConfigForClient(&tls.ClientHelloInfo{Conn: local}); err != nil || prevCalled != 1 {
		t.Fatalf("loopback peer while closed: err = %v, wrapped hook called %d times", err, prevCalled)
	}
	if err := opts.Websocket.TLSConfig.VerifyConnection(tls.ConnectionState{}); !errors.Is(err, errSysNotLoaded) || nextCalled != 0 {
		t.Fatalf("websocket while closed: err = %v, wrapped hook called %d times", err, nextCalled)
	}
	g.open.Store(true)
	if _, err := opts.TLSConfig.GetConfigForClient(&tls.ClientHelloInfo{Conn: remote}); err != nil || prevCalled != 2 {
		t.Fatalf("remote peer while open: err = %v", err)
	}
	if err := opts.Websocket.TLSConfig.VerifyConnection(tls.ConnectionState{}); err != nil || nextCalled != 1 {
		t.Fatalf("websocket while open: err = %v", err)
	}
	if err := newSysGate(nil, nil, time.Hour).install(&nats_server.Options{}); err == nil {
		t.Fatal("installed on a client port without TLS")
	}
	if _, err := startBus(nats_server.Options{}, busSetup{Timing: testTiming}); !errors.Is(err, errNoSysReady) {
		t.Fatalf("single node without SysReady: err = %v, want errNoSysReady", err)
	}
}

type fakeConn struct {
	net.Conn
	addr net.Addr
}

func (c *fakeConn) RemoteAddr() net.Addr { return c.addr }

// TestSingleNodeServesOnlyAfterSysLoaded: a single node on an empty
// resolver refuses a sprout and core's SYS push, and reports not ready,
// until its account loader has loaded the bucket; then it serves. The
// loader dials from 127.0.0.1, the "remote" clients from 127.0.0.2, and
// the gate counts only 127.0.0.1 as local.
func TestSingleNodeServesOnlyAfterSysLoaded(t *testing.T) {
	e := newLoaderEnv(t, time.Hour)
	tn := e.tr.newTenant(t, "web-01")
	e.bucket.putAccount(t, tn.pub, e.tr.accountJWT(t, tn, false))
	e.bucket.bumpIndex(t)

	var readyURL atomic.Pointer[string]
	sysReady := func() bool {
		u := readyURL.Load()
		if u == nil {
			return false
		}
		probe, err := loaderReadyProbe(*u)
		return err == nil && probe()
	}
	loader := net.ParseIP("127.0.0.1")
	nd := startSingleNode(t, busSetup{
		SysReady: sysReady,
		IsLocal: func(a net.Addr) bool {
			tcp, ok := a.(*net.TCPAddr)
			return ok && tcp.IP.Equal(loader)
		},
	})
	url := nd.srv.ClientURL()
	remote := nats.SetCustomDialer(&net.Dialer{Timeout: 2 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}})

	time.Sleep(5 * testTiming.Interval)
	if nd.Ready() {
		t.Fatal("ready before the loader ran")
	}
	if nc, err := e.tr.dialSprout(tn, []string{url}, remote, nats.NoReconnect()); err == nil {
		nc.Close()
		t.Fatal("a sprout connected before the SYS account was loaded")
	}
	core, err := nats.Connect(url, nats.Secure(e.tr.tlsConfig()), nats.UserJWTAndSeed(e.tr.sysUserJWT, mustSeed(e.tr.sysUser)),
		nats.Timeout(2*time.Second), nats.NoReconnect(), remote)
	if err == nil {
		core.Close()
		t.Fatal("core's SYS connection was admitted before the SYS account was loaded")
	}

	rl := e.startLoader(t, url)
	readyURL.Store(&rl.readyz)
	waitLoaded(t, rl)
	waitFor(t, "the node to report ready", 10*time.Second, nd.Ready)
	nc, err := e.tr.dialSprout(tn, []string{url}, remote, nats.NoReconnect())
	if err != nil {
		t.Fatalf("sprout refused after the SYS account was loaded: %v", err)
	}
	nc.Close()
}
