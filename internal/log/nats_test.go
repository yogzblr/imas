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
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		kept := logger.SubLoggers[:0]
		for _, sl := range logger.SubLoggers {
			if _, isNATS := sl.(*nlog.Logger); !isNATS {
				kept = append(kept, sl)
			}
		}
		logger.SubLoggers = kept
		nlog.SetDefaultConn(nil)
		nlog.SetSubjectTemplate("logging.{{.Namespace}}.{{.Level}}")
		borrowedConn = nil
		natsUp = false
	})
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
