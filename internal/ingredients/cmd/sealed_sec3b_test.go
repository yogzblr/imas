package cmd

// Security review 2026-10 (SEC.3b): tenant binding (H3), replay after a
// restart (M2), and no opened command reaching a log sink (H4).

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"

	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

// H3: a cmd.run sealed under this sprout's own tenant key and box key (a
// shared key at its strongest) but naming another tenant is refused and
// never run.
func TestSealedCmdRun_AnotherTenantsCommandRefusedUnderSharedKey(t *testing.T) {
	e := setupSealed(t, "t_sealed_shared")
	marker := filepath.Join(e.dir, "ran")
	active, _, err := pki.ValidSproutBoxKeys(e.tenant, e.sproutID)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := pki.DecodeBoxPubKey(active)
	if err != nil {
		t.Fatal(err)
	}
	tenantKeys, err := pki.TenantBoxKeys(e.tenant)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := payloadbox.NewMessage(payloadbox.PurposeCmdRunRequest, "t_sealed_other", e.sproutID, "",
		apitypes.CmdRun{Command: "touch", Args: []string{marker}, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	data, err := payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: sp, Priv: tenantKeys[0].Priv}})
	if err != nil {
		t.Fatal(err)
	}
	req := nats.NewMsg(cmdRunSubject(e.sproutID))
	req.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	req.Data = data
	reply, err := e.farmer.RequestMsg(req, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if code := reply.Header.Get(payloadbox.ErrorHeader); code != payloadbox.ErrorCodeOpenFailed {
		t.Errorf("refusal code %q, want %q", code, payloadbox.ErrorCodeOpenFailed)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the sprout ran a command sealed for another tenant")
	}
}

// M2: a captured sealed cmd.run replayed after the sprout restarts (its
// in-memory state gone) is still refused, and the command runs once.
func TestSealedCmdRun_ReplayAfterRestartIsRefused(t *testing.T) {
	e := setupSealed(t, "t_sealed_restart")
	t.Cleanup(pki.ForgetSproutReplayGuard)
	spy := spyOnBus(t, e)
	counter := filepath.Join(e.dir, "count")
	run := apitypes.CmdRun{Command: "/bin/sh", Args: []string{"-c", "echo x >> " + counter}, Timeout: 5 * time.Second}
	if _, err := FRun(e.tenant, pki.KeyManager{SproutID: e.sproutID}, run); err != nil {
		t.Fatal(err)
	}
	var captured *nats.Msg
	for _, m := range spy.waitFor(t, 1) {
		if m.Subject == cmdRunSubject(e.sproutID) {
			captured = m
		}
	}
	pki.ForgetSproutReplayGuard() // the sprout restarts
	replay := nats.NewMsg(captured.Subject)
	replay.Header = captured.Header
	replay.Data = captured.Data
	reply, err := e.farmer.RequestMsg(replay, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if code := reply.Header.Get(payloadbox.ErrorHeader); code != payloadbox.ErrorCodeOpenFailed {
		t.Errorf("refusal code %q, want %q", code, payloadbox.ErrorCodeOpenFailed)
	}
	if b, _ := os.ReadFile(counter); strings.Count(string(b), "x") != 1 {
		t.Errorf("command ran %d times, want 1", strings.Count(string(b), "x"))
	}
}

// logSinks captures every log sink at every level: the terminal logger
// (at Trace) and the NATS backend (minimum Trace, so the filter can't
// hide anything), the way the sprout ships logs.
type logSinks struct {
	mu       sync.Mutex
	terminal bytes.Buffer
	bus      [][]byte
}

func (s *logSinks) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.terminal.Write(p)
}

func (s *logSinks) contains(marker string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if bytes.Contains(s.terminal.Bytes(), []byte(marker)) {
		return "terminal", true
	}
	for _, b := range s.bus {
		if bytes.Contains(b, []byte(marker)) {
			return "NATS", true
		}
	}
	return "", false
}

func captureLogSinks(t *testing.T, sproutConn, busConn *nats.Conn, sproutID string) *logSinks {
	t.Helper()
	s := &logSinks{}
	log.SetOutput(s)
	log.SetLogLevel(log.LTrace)
	log.SetNATSMinLevel(log.LTrace)
	t.Cleanup(func() {
		log.DetachNATS()
		log.SetOutput(nil)
		log.SetLogLevel(log.LDebug)
		log.SetNATSMinLevel(log.DefaultNATSMinLevel)
	})
	if _, err := busConn.Subscribe("imas.logs.>", func(m *nats.Msg) {
		s.mu.Lock()
		s.bus = append(s.bus, m.Data)
		s.mu.Unlock()
	}); err != nil {
		t.Fatal(err)
	}
	busConn.Flush()
	if err := log.UseNATSConn(sproutConn, "imas.logs.sprouts."+sproutID); err != nil {
		t.Fatal(err)
	}
	return s
}

// H4: nothing from an opened cmd.run (its command line, arguments,
// environment or output) reaches any log sink, including the NATS one,
// on success, on failure, or on a refusal.
func TestSealedCmdRun_NoOpenedBodyReachesALogSink(t *testing.T) {
	e := setupSealed(t, "t_sealed_logs")
	sinks := captureLogSinks(t, e.sprout, e.farmer, e.sproutID)
	const secret = "s3cret-cmd-91fe"
	runs := []apitypes.CmdRun{
		{Command: "/bin/sh", Args: []string{"-c", "echo " + secret}, Env: map[string]string{"TOKEN": secret}, Timeout: 5 * time.Second},
		{Command: "/bin/sh", Args: []string{"-c", "echo " + secret + " >&2; exit 3"}, Timeout: 5 * time.Second},
		{Command: "/nonexistent/" + secret, Timeout: 5 * time.Second},
	}
	for _, run := range runs {
		_, _ = FRun(e.tenant, pki.KeyManager{SproutID: e.sproutID}, run)
	}
	log.Flush()
	e.sprout.Flush()
	time.Sleep(200 * time.Millisecond) // let the bus deliver the shipped entries
	if where, found := sinks.contains(secret); found {
		t.Fatalf("an opened cmd.run body reached the %s log sink", where)
	}
	sinks.mu.Lock()
	shipped := len(sinks.bus)
	sinks.mu.Unlock()
	if shipped == 0 {
		t.Fatal("control: nothing reached the NATS log sink, so the test proves nothing")
	}
}
