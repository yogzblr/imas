package log

import (
	"encoding/json"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	nats "github.com/nats-io/nats.go"
	nlog "github.com/taigrr/log-nats/v2/log"
)

func startTestNATS(t *testing.T) *natsserver.Server {
	t.Helper()
	ns, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: -1})
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

func connectTestNATS(t *testing.T, ns *natsserver.Server) *nats.Conn {
	t.Helper()
	nc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatalf("connect to test NATS: %v", err)
	}
	t.Cleanup(nc.Close)
	return nc
}

// detachNATS undoes UseNATSConn/ConnectNATS, so later tests start with
// only the charm logger attached.
func detachNATS(t *testing.T) {
	t.Helper()
	t.Cleanup(DetachNATS)
}

func TestUseNATSConnPublishesOverProvidedConn(t *testing.T) {
	ns := startTestNATS(t)
	pub := connectTestNATS(t, ns)
	sub := connectTestNATS(t, ns)
	detachNATS(t)

	msgs, err := sub.SubscribeSync("imas.logs.sprouts.web01.>")
	if err != nil {
		t.Fatal(err)
	}
	if err := sub.Flush(); err != nil {
		t.Fatal(err)
	}

	if err := UseNATSConn(pub, "imas.logs.sprouts.web01"); err != nil {
		t.Fatalf("UseNATSConn: %v", err)
	}
	before := pub.Stats().OutMsgs
	Warnf("disk %s is %d%% full", "/var", 91)
	Flush()

	msg, err := msgs.NextMsg(2 * time.Second)
	if err != nil {
		t.Fatalf("no log entry published: %v", err)
	}
	if msg.Subject != "imas.logs.sprouts.web01.WARN" {
		t.Errorf("subject = %q, want imas.logs.sprouts.web01.WARN", msg.Subject)
	}
	var e nlog.Entry
	if err := json.Unmarshal(msg.Data, &e); err != nil {
		t.Fatalf("entry does not decode: %v", err)
	}
	if e.Output != "disk /var is 91% full" || e.Level != "WARN" {
		t.Errorf("entry = %+v", e)
	}
	if got := pub.Stats().OutMsgs - before; got != 1 {
		t.Errorf("provided connection sent %d messages, want 1", got)
	}

	// Flush must not close a borrowed connection: its owner still uses it.
	if pub.IsClosed() {
		t.Fatal("Flush closed the connection passed to UseNATSConn")
	}
}

func TestUseNATSConnRejectsBadInput(t *testing.T) {
	ns := startTestNATS(t)
	nc := connectTestNATS(t, ns)
	detachNATS(t)

	if err := UseNATSConn(nil, "imas.logs.farmer"); err == nil {
		t.Error("UseNATSConn(nil) succeeded")
	}
	for _, prefix := range []string{
		"",
		"imas..logs",
		"imas.logs.",
		"imas.logs.*",
		"imas.logs.>",
		"imas.logs.a b",
		"imas.logs.{{.Output}}",
	} {
		if err := UseNATSConn(nc, prefix); err == nil {
			t.Errorf("UseNATSConn(nc, %q) succeeded", prefix)
		}
	}
	mu.RLock()
	defer mu.RUnlock()
	if natsUp || borrowedConn != nil {
		t.Error("a rejected UseNATSConn attached the NATS backend")
	}
}

// H4 (security review 2026-10): by default nothing below Info is shipped,
// and the minimum is configurable.
func TestNATSSinkDropsTraceAndDebugByDefault(t *testing.T) {
	ns := startTestNATS(t)
	pub := connectTestNATS(t, ns)
	sub := connectTestNATS(t, ns)
	detachNATS(t)
	t.Cleanup(func() { SetNATSMinLevel(DefaultNATSMinLevel) })

	msgs, err := sub.SubscribeSync("imas.logs.sprouts.web01.>")
	if err != nil {
		t.Fatal(err)
	}
	if err := sub.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := UseNATSConn(pub, "imas.logs.sprouts.web01"); err != nil {
		t.Fatal(err)
	}
	if NATSMinLevel() != LInfo {
		t.Fatalf("default NATS minimum level = %v, want Info", NATSMinLevel())
	}
	Tracef("trace %s", "x")
	Trace("trace")
	Traceln("trace")
	Debugf("debug %s", "x")
	Debug("debug")
	Debugln("debug")
	Infof("info %s", "x")
	Flush()
	msg, err := msgs.NextMsg(2 * time.Second)
	if err != nil {
		t.Fatalf("no Info entry published: %v", err)
	}
	if msg.Subject != "imas.logs.sprouts.web01.INFO" {
		t.Fatalf("first entry published on %s, want only Info and above", msg.Subject)
	}
	if extra, err := msgs.NextMsg(200 * time.Millisecond); err == nil {
		t.Fatalf("unexpected entry on %s", extra.Subject)
	}

	// Raised to Warn: Info is dropped too. Lowered to Trace: everything.
	SetNATSMinLevel(LWarn)
	Infof("info")
	Warnf("warn")
	Flush()
	if msg, err := msgs.NextMsg(2 * time.Second); err != nil || msg.Subject != "imas.logs.sprouts.web01.WARN" {
		t.Fatalf("with minimum Warn got %v, %v; want only the WARN entry", msg, err)
	}
	SetNATSMinLevel(LTrace)
	Tracef("trace")
	Flush()
	if msg, err := msgs.NextMsg(2 * time.Second); err != nil || msg.Subject != "imas.logs.sprouts.web01.TRACE" {
		t.Fatalf("with minimum Trace got %v, %v; want the TRACE entry", msg, err)
	}
}

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]Level{"trace": LTrace, "DEBUG": LDebug, " info ": LInfo, "notice": LNotice,
		"warn": LWarn, "warning": LWarn, "error": LError, "panic": LPanic, "fatal": LFatal} {
		if got, err := ParseLevel(in); err != nil || got != want {
			t.Errorf("ParseLevel(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseLevel("loud"); err == nil {
		t.Error("ParseLevel accepted an unknown level")
	}
}
