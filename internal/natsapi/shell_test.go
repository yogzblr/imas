package natsapi

// Sealed shell (J.5) end to end. FLAG FOR SECURITY REVIEW.
//
// The bus is an embedded nats-server in operator (JWT) mode, built by
// pki.ConfigureNats exactly as farmer builds it. The sprout connects with
// the User JWT farmer minted for it on accept (pki.AcceptNKey), so its
// real per-sprout permissions apply. Farmer runs the real Subscribe; the
// CLI is the real shell.RunClient over client.SealedRequest; the sprout
// the real shell.Sprout. A "hostile" connection with allow-all
// permissions stands in for a compromised bus, which ignores permissions
// altogether: it records everything routed through it and tries to open
// shells, inject, replay, reorder and drop frames.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	natsjwt "github.com/nats-io/jwt/v2"
	nats_server "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/api/client"
	"github.com/yogzblr/imas/internal/audit"
	intauth "github.com/yogzblr/imas/internal/auth"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/shell"
)

const shellTestSprout = "web-01"

type shellEnv struct {
	tenant  string
	user    *cliUser
	farmer  *nats.Conn
	cli     *nats.Conn
	hostile *nats.Conn
	sprout  *nats.Conn
	sp      *shell.Sprout
	spy     *busSpy
	sproutP *permErrs
	sprPub  string
	audit   string
}

// permErrs collects the sprout connection's async errors (permission
// violations).
type permErrs struct {
	mu   sync.Mutex
	errs []string
}

func (p *permErrs) handler(_ *nats.Conn, _ *nats.Subscription, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.errs = append(p.errs, err.Error())
}

func (p *permErrs) all() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.errs...)
}

// busSpy is what a compromised bus sees: every message on imas.> and
// _INBOX.>, headers and payload.
type busSpy struct {
	mu   sync.Mutex
	msgs []*nats.Msg
}

func (b *busSpy) record(m *nats.Msg) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.msgs = append(b.msgs, m)
}

func (b *busSpy) on(subjectPrefix string) []*nats.Msg {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []*nats.Msg
	for _, m := range b.msgs {
		if strings.HasPrefix(m.Subject, subjectPrefix) {
			out = append(out, m)
		}
	}
	return out
}

// sawPlaintext reports whether any recorded payload contains s.
func (b *busSpy) sawPlaintext(s string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, m := range b.msgs {
		if bytes.Contains(m.Data, []byte(s)) {
			return true
		}
	}
	return false
}

// startJWTBus starts the operator-mode bus farmer runs (pki.ConfigureNats)
// on a free port, registered with pki so accepts push Account updates to
// it.
func startJWTBus(t *testing.T) string {
	t.Helper()
	config.FarmerBusPort = "-1"
	opts := pki.ConfigureNats()
	opts.LogFile, opts.Trace, opts.Debug = "", false, false
	srv, err := nats_server.NewServer(&opts)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		t.Fatal("bus not ready")
	}
	port := srv.Addr().(*net.TCPAddr).Port
	// Farmer pushes Account updates (an accept) over the bus itself.
	origURL := config.FarmerBusURL
	config.FarmerBusURL = fmt.Sprintf("127.0.0.1:%d", port)
	pki.SetNATSServer(srv)
	t.Cleanup(func() {
		pki.SetNATSServer(nil)
		config.FarmerBusURL = origURL
		srv.Shutdown()
	})
	return fmt.Sprintf("tls://127.0.0.1:%d", port)
}

// dialBus connects with a User JWT and seed, over TLS verified against
// the test root CA.
func dialBus(t *testing.T, url, userJWT string, seed []byte, opts ...nats.Option) *nats.Conn {
	t.Helper()
	pem, err := os.ReadFile(config.RootCA)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	nc, err := nats.Connect(url, append([]nats.Option{
		nats.Secure(tlsCfg), nats.UserJWTAndSeed(userJWT, string(seed)), nats.RetryOnFailedConnect(false),
	}, opts...)...)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(nc.Close)
	return nc
}

// fastShellTimings shortens the relay's timers for a test.
func fastShellTimings(t *testing.T) {
	t.Helper()
	oldOpts, oldHello, oldRecheck, oldKeys := shellStreamOptions, shellHelloTimeout, shellRecheckInterval, shellKeyRecheckAfter
	shellStreamOptions = payloadbox.StreamOptions{AckInterval: 20 * time.Millisecond, HeartbeatInterval: 200 * time.Millisecond, PeerTimeout: time.Second}
	shellHelloTimeout = 500 * time.Millisecond
	shellRecheckInterval = 200 * time.Millisecond
	shellKeyRecheckAfter = 0
	t.Cleanup(func() {
		shellStreamOptions, shellHelloTimeout, shellRecheckInterval, shellKeyRecheckAfter = oldOpts, oldHello, oldRecheck, oldKeys
	})
}

func startShellEnv(t *testing.T) *shellEnv {
	t.Helper()
	setupNatsAPIPKI(t)
	fastShellTimings(t)
	// A real farmer NKey, so the test can connect as farmer.
	farmerKP, _ := nkeys.CreateUser()
	farmerPub, _ := farmerKP.PublicKey()
	farmerSeed, _ := farmerKP.Seed()
	if err := os.WriteFile(config.NKeyFarmerPubFile, []byte(farmerPub), 0o600); err != nil {
		t.Fatal(err)
	}
	url := startJWTBus(t)
	setupSealedEnv(t)
	env := &shellEnv{tenant: pki.CurrentTenantID()}

	// The sprout: accepted, its User JWT minted by farmer.
	sproutKP, _ := nkeys.CreateUser()
	sproutNKey, _ := sproutKP.PublicKey()
	sproutSeed, _ := sproutKP.Seed()
	writeNKey(t, "", "accepted", shellTestSprout, sproutNKey)
	sproutJWT, err := pki.GetSproutUserJWT(shellTestSprout)
	if err != nil {
		t.Fatal(err)
	}
	if uc, err := natsjwt.DecodeUserClaims(sproutJWT); err != nil || !uc.Pub.Allow.Contains(pki.SproutShellPublishGrant(shellTestSprout)) {
		t.Fatalf("the sprout's User JWT lacks the shell grant (%v)", err)
	}

	// The sprout's own box key, recorded farmer-side, and its pins.
	dir := t.TempDir()
	origPriv, origPin := config.SproutBoxPrivFile, config.SproutTenantX25519PubFile
	config.SproutBoxPrivFile = filepath.Join(dir, "box.key")
	config.SproutTenantX25519PubFile = filepath.Join(dir, "tenant-x25519.pub")
	pki.ForgetSproutReplayGuard()
	t.Cleanup(func() {
		config.SproutBoxPrivFile, config.SproutTenantX25519PubFile = origPriv, origPin
		pki.ForgetSproutReplayGuard()
	})
	env.sprPub, err = pki.EnsureSproutBoxKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.RotateSproutBoxKey(env.tenant, shellTestSprout, env.sprPub, time.Hour); err != nil {
		t.Fatal(err)
	}
	tenantPub, err := pki.GetTenantX25519PublicKey(env.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.SproutTenantX25519PubFile, []byte(tenantPub), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pki.SproutTenantIDFile(), []byte(env.tenant), 0o644); err != nil {
		t.Fatal(err)
	}
	shell.SetSproutPolicy(shell.SproutPolicy{AllowedShells: []string{"/bin/sh"}})
	t.Cleanup(func() { shell.SetSproutPolicy(shell.SproutPolicy{}) })

	farmerJWT, err := pki.FarmerUserJWT()
	if err != nil {
		t.Fatal(err)
	}
	env.farmer = dialBus(t, url, farmerJWT, farmerSeed)
	if err := Subscribe(env.farmer, env.tenant); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ClearNatsConn(env.tenant) })
	// The CLI's User JWT carries the same allow-all set as farmer's
	// (jwtusers.go's allowAllPermissions), so it connects with farmer's.
	env.cli = dialBus(t, url, farmerJWT, farmerSeed)
	env.hostile = dialBus(t, url, farmerJWT, farmerSeed)
	env.spy = &busSpy{}
	for _, s := range []string{"imas.>", "_INBOX.>"} {
		if _, err := env.hostile.Subscribe(s, env.spy.record); err != nil {
			t.Fatal(err)
		}
	}
	env.sproutP = &permErrs{}
	env.sprout = dialBus(t, url, sproutJWT, sproutSeed, nats.ErrorHandler(env.sproutP.handler))
	env.sp = shell.NewSprout(env.sprout, shellTestSprout)
	env.sp.Stream = shellStreamOptions
	if _, err := env.sprout.Subscribe(shell.StartSubject(shellTestSprout), env.sp.HandleStart); err != nil {
		t.Fatal(err)
	}
	for _, nc := range []*nats.Conn{env.farmer, env.cli, env.hostile, env.sprout} {
		if err := nc.Flush(); err != nil {
			t.Fatal(err)
		}
	}

	env.user = newSealedCLIUserIn(t, env.tenant)
	intauth.CurrentPolicy().Users.SetUsername(env.user.id, "alice")

	env.audit = t.TempDir()
	logger, err := audit.NewLogger(env.audit)
	if err != nil {
		t.Fatal(err)
	}
	audit.SetGlobal(logger)
	t.Cleanup(func() { audit.SetGlobal(nil); logger.Close() })

	t.Cleanup(func() {
		CloseShellSessions()
		waitFor(t, "sessions to end", func() bool { return ShellTracker().Active() == 0 && env.sp.Active() == 0 })
		if errs := env.sproutP.all(); len(errs) != 0 {
			t.Errorf("the sprout hit permission errors: %v", errs)
		}
	})
	return env
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// syncBuf is a goroutine-safe output buffer.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type clientRun struct {
	stdin  *io.PipeWriter
	stdout *syncBuf
	ready  chan shell.OpenResult
	done   chan struct{}
	res    *shell.ClientResult
	err    error
	cancel context.CancelFunc
}

func (e *shellEnv) open(req shell.OpenRequest) (json.RawMessage, error) {
	return client.SealedRequest(e.cli, payloadbox.PurposeShellOpen, MethodShellOpen, req, 5*time.Second)
}

// startClient runs the real CLI side.
func (e *shellEnv) startClient(t *testing.T, mutate func(*shell.ClientOptions)) *clientRun {
	t.Helper()
	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	r := &clientRun{stdin: pw, stdout: &syncBuf{}, ready: make(chan shell.OpenResult, 1), done: make(chan struct{}), cancel: cancel}
	o := shell.ClientOptions{
		NC: e.cli, Open: e.open, TenantID: e.tenant, UserID: e.user.id,
		SproutID: shellTestSprout, Cols: 80, Rows: 24, Stdin: pr, Stdout: r.stdout,
		OnReady: func(res shell.OpenResult) { r.ready <- res },
		Stream:  shellStreamOptions, ReadyTimeout: 5 * time.Second,
	}
	if mutate != nil {
		mutate(&o)
	}
	go func() {
		defer close(r.done)
		r.res, r.err = shell.RunClient(ctx, o)
	}()
	t.Cleanup(func() { cancel(); pw.Close(); <-r.done })
	return r
}

func (r *clientRun) waitReady(t *testing.T) shell.OpenResult {
	t.Helper()
	select {
	case res := <-r.ready:
		return res
	case <-r.done:
		t.Fatalf("session ended before it was ready: %+v %v", r.res, r.err)
	case <-time.After(10 * time.Second):
		t.Fatal("session never became ready")
	}
	return shell.OpenResult{}
}

func (r *clientRun) wait(t *testing.T) *shell.ClientResult {
	t.Helper()
	select {
	case <-r.done:
	case <-time.After(15 * time.Second):
		t.Fatal("session never ended")
	}
	if r.err != nil {
		t.Fatalf("RunClient: %v", r.err)
	}
	return r.res
}

func (r *clientRun) send(t *testing.T, s string) {
	t.Helper()
	if _, err := r.stdin.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
}

// The whole path works for a sprout with a real per-sprout JWT, and a
// compromised bus that sees everything reads none of it.
func TestSealedShellEndToEnd(t *testing.T) {
	env := startShellEnv(t)
	run := env.startClient(t, nil)
	opened := run.waitReady(t)
	run.send(t, "echo secret-$((40+2))\n")
	waitFor(t, "the command's output", func() bool { return strings.Contains(run.stdout.String(), "secret-42") })
	run.send(t, "exit 3\n")
	res := run.wait(t)
	if res.Reason != payloadbox.CloseExit || res.ExitCode != 3 || !res.Remote {
		t.Fatalf("ended %+v, want exit 3", res)
	}
	waitFor(t, "both ends to drop the session", func() bool { return ShellTracker().Active() == 0 && env.sp.Active() == 0 })

	// What the bus saw: the open, the start and frames, all sealed.
	for _, s := range []string{"secret", "echo", "/bin/sh"} {
		if env.spy.sawPlaintext(s) {
			t.Errorf("the bus saw %q in plaintext", s)
		}
	}
	if len(env.spy.on(shell.CLISubject(opened.SessionID, ""))) == 0 || len(env.spy.on("imas.shell.sprout."+shellTestSprout+"."+opened.SessionID)) == 0 {
		t.Fatal("the spy saw no frames: the test isn't watching the session's subjects")
	}
	for _, m := range env.spy.on("imas.sprouts." + shellTestSprout + ".shell.start") {
		if m.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
			t.Error("a start went out unsealed")
		}
	}
	// Audit: the open request, leg 2's start and the end; never content.
	logs := readAudit(t, env.audit)
	for _, want := range []string{`"action":"shell.open"`, `"action":"shell.start"`, `"action":"shell.end"`, `"reason":"exit"`, opened.SessionID} {
		if !strings.Contains(logs, want) {
			t.Errorf("audit log lacks %s", want)
		}
	}
	if strings.Contains(logs, "secret") {
		t.Error("audit log holds session content")
	}
}

func readAudit(t *testing.T, dir string) string {
	t.Helper()
	var all strings.Builder
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err == nil {
			all.Write(b)
		}
	}
	return all.String()
}

// A sprout refuses a plaintext start (from the bus, or anything else)
// without spawning, and so does farmer's API.
func TestSealedShellRefusesPlaintext(t *testing.T) {
	env := startShellEnv(t)
	body, _ := json.Marshal(shell.StartBody{
		SessionID: "0123456789abcdef0123456789abcdef", FarmerEphPub: make([]byte, 32), Cols: 80, Rows: 24,
		User: shell.StartUser{Pubkey: "UHOSTILE"},
	})
	// The old plaintext shape too.
	for _, data := range [][]byte{body, []byte(`{"session_id":"x","shell":"/bin/sh","cols":80,"rows":24}`)} {
		resp, err := env.hostile.Request(shell.StartSubject(shellTestSprout), data, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if code := resp.Header.Get(payloadbox.ErrorHeader); code != payloadbox.ErrorCodeEncryptionRequired || len(resp.Data) != 0 {
			t.Fatalf("plaintext start answered %v %q", resp.Header, resp.Data)
		}
	}
	// A box marker on a payload that isn't a box doesn't help.
	m := nats.NewMsg(shell.StartSubject(shellTestSprout))
	m.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	m.Data = body
	resp, err := env.hostile.RequestMsg(m, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if code := resp.Header.Get(payloadbox.ErrorHeader); code != payloadbox.ErrorCodeOpenFailed {
		t.Fatalf("forged sealed start answered %v %q", resp.Header, resp.Data)
	}
	if env.sp.Active() != 0 {
		t.Fatal("the sprout spawned a shell for the bus")
	}
	// Farmer's API: plaintext shell.open and the removed shell.start.
	for _, method := range []string{MethodShellOpen, "shell.start"} {
		resp, err := env.hostile.Request(Subject(method), []byte(`{"sprout_id":"web-01"}`), 2*time.Second)
		if method == "shell.start" {
			if err == nil { // no responders, or a timeout: nothing serves it
				t.Errorf("shell.start still answered: %v %v", resp, err)
			}
			continue
		}
		if err != nil || resp.Header.Get(payloadbox.ErrorHeader) != payloadbox.ErrorCodeEncryptionRequired {
			t.Errorf("plaintext %s answered %v, %v", method, resp, err)
		}
	}
}

// A captured open replayed by the bus, to this replica, is refused; and
// one replayed in time to be accepted could never be confirmed, since the
// bus lacks the CLI's ephemeral key. A captured start replayed to the
// sprout is refused too.
func TestSealedShellReplayedHandshakes(t *testing.T) {
	env := startShellEnv(t)
	run := env.startClient(t, nil)
	run.waitReady(t)
	run.send(t, "exit\n")
	run.wait(t)

	opens := env.spy.on(Subject(MethodShellOpen))
	starts := env.spy.on(shell.StartSubject(shellTestSprout))
	if len(opens) == 0 || len(starts) == 0 {
		t.Fatal("captured nothing")
	}
	for _, captured := range opens {
		m := nats.NewMsg(captured.Subject)
		m.Header = captured.Header
		m.Data = captured.Data
		resp, err := env.hostile.RequestMsg(m, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Header.Get(payloadbox.ErrorHeader) != payloadbox.ErrorCodeOpenFailed {
			t.Fatalf("replayed open answered %v", resp.Header)
		}
	}
	for _, captured := range starts {
		m := nats.NewMsg(captured.Subject)
		m.Header = captured.Header
		m.Data = captured.Data
		resp, err := env.hostile.RequestMsg(m, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Header.Get(payloadbox.ErrorHeader) != payloadbox.ErrorCodeOpenFailed {
			t.Fatalf("replayed start answered %v %q", resp.Header, resp.Data)
		}
	}
	if env.sp.Active() != 0 {
		t.Fatal("a replay spawned a shell")
	}
}

// An open that never sends HELLO (what a bus replaying an open it can't
// confirm looks like) is dropped without the sprout being contacted.
func TestSealedShellNeedsKeyConfirmation(t *testing.T) {
	env := startShellEnv(t)
	eph, _ := payloadbox.NewEphemeralKey()
	if _, err := env.open(shell.OpenRequest{SproutID: shellTestSprout, CLIEphPub: eph.PublicKey().Bytes()}); err != nil {
		t.Fatal(err)
	}
	if ShellTracker().Active() != 1 {
		t.Fatal("the open wasn't tracked")
	}
	waitFor(t, "the unconfirmed session to be dropped", func() bool { return ShellTracker().Active() == 0 })
	if n := len(env.spy.on(shell.StartSubject(shellTestSprout))); n != 0 {
		t.Fatalf("%d starts sent for an unconfirmed open", n)
	}
	if !strings.Contains(readAudit(t, env.audit), `"code":"no-hello"`) {
		t.Error("the dropped session isn't in the audit log")
	}
}

// Frames the bus injects, replays or garbles end the session on both legs
// (integrity), and the sprout kills the shell.
func TestSealedShellBusInjection(t *testing.T) {
	for name, attack := range map[string]func(env *shellEnv, sessionID string){
		"garbage on c2f": func(env *shellEnv, sid string) {
			_ = env.hostile.Publish(shell.CLISubject(sid, payloadbox.DirC2F), bytes.Repeat([]byte{1}, 64))
		},
		"garbage on f2s": func(env *shellEnv, sid string) {
			_ = env.hostile.Publish(shell.SproutInSubject(shellTestSprout, sid), bytes.Repeat([]byte{1}, 64))
		},
		"garbage on s2f": func(env *shellEnv, sid string) {
			_ = env.hostile.Publish(shell.SproutOutSubject(shellTestSprout, sid), bytes.Repeat([]byte{1}, 64))
		},
		"replayed c2f frame": func(env *shellEnv, sid string) {
			fs := env.spy.on(shell.CLISubject(sid, payloadbox.DirC2F))
			_ = env.hostile.Publish(fs[0].Subject, fs[0].Data)
		},
		"replayed f2s frame": func(env *shellEnv, sid string) {
			fs := env.spy.on(shell.SproutInSubject(shellTestSprout, sid))
			_ = env.hostile.Publish(fs[0].Subject, fs[0].Data)
		},
		"c2f frame moved to f2s": func(env *shellEnv, sid string) {
			fs := env.spy.on(shell.CLISubject(sid, payloadbox.DirC2F))
			_ = env.hostile.Publish(shell.SproutInSubject(shellTestSprout, sid), fs[len(fs)-1].Data)
		},
	} {
		t.Run(name, func(t *testing.T) {
			env := startShellEnv(t)
			run := env.startClient(t, nil)
			opened := run.waitReady(t)
			run.send(t, "echo up\n")
			waitFor(t, "output", func() bool { return strings.Contains(run.stdout.String(), "up") })
			waitFor(t, "frames on both legs", func() bool {
				return len(env.spy.on(shell.SproutInSubject(shellTestSprout, opened.SessionID))) > 0 &&
					len(env.spy.on(shell.CLISubject(opened.SessionID, payloadbox.DirC2F))) > 0
			})
			attack(env, opened.SessionID)
			res := run.wait(t)
			if res.Reason != payloadbox.CloseIntegrity {
				t.Fatalf("ended %+v, want integrity", res)
			}
			waitFor(t, "the sprout to kill the shell", func() bool { return env.sp.Active() == 0 && ShellTracker().Active() == 0 })
		})
	}
}

// manualCLI is a CLI whose leg 1 frames the test controls: it stands in
// for the bus between the CLI and farmer dropping or reordering frames.
type manualCLI struct {
	sessionID string
	stream    *payloadbox.Stream
	held      [][]byte
	mu        sync.Mutex
	hold      bool
}

func (e *shellEnv) openManual(t *testing.T) *manualCLI {
	t.Helper()
	eph, _ := payloadbox.NewEphemeralKey()
	ephPub := eph.PublicKey().Bytes()
	raw, err := e.open(shell.OpenRequest{SproutID: shellTestSprout, CLIEphPub: ephPub})
	if err != nil {
		t.Fatal(err)
	}
	var res shell.OpenResult
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatal(err)
	}
	keys, err := payloadbox.DeriveStreamKeys(eph, res.FarmerEphPub,
		shell.Transcript(payloadbox.LegCLI, e.tenant, shellTestSprout, e.user.id, res.SessionID, ephPub, res.FarmerEphPub))
	if err != nil {
		t.Fatal(err)
	}
	m := &manualCLI{sessionID: res.SessionID}
	subject := shell.CLISubject(res.SessionID, payloadbox.DirC2F)
	m.stream, err = payloadbox.NewStream(keys, true, func(f []byte) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.hold {
			m.held = append(m.held, append([]byte(nil), f...))
			return nil
		}
		return e.cli.Publish(subject, f)
	}, shellStreamOptions)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.cli.Subscribe(shell.CLISubject(res.SessionID, payloadbox.DirF2C), func(msg *nats.Msg) { _ = m.stream.Deliver(msg.Data) }); err != nil {
		t.Fatal(err)
	}
	_ = e.cli.Flush()
	if err := m.stream.SendHello(80, 24); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-m.stream.Frames():
		if f.Type != payloadbox.FrameReady {
			t.Fatalf("got %v, want READY", f.Type)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no READY")
	}
	return m
}

func (m *manualCLI) holdFrames(on bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hold = on
}

// waitClose waits for farmer's CLOSE on leg 1.
func (m *manualCLI) waitClose(t *testing.T) payloadbox.CloseInfo {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case f := <-m.stream.Frames():
			if f.Type == payloadbox.FrameData {
				m.stream.Consumed(f)
				continue
			}
			if f.Type == payloadbox.FrameClose {
				info, err := payloadbox.DecodeClose(f.Payload)
				if err != nil {
					t.Fatal(err)
				}
				return info
			}
		case <-deadline:
			t.Fatal("no CLOSE from farmer")
		}
	}
}

// The bus drops a frame, or delivers two out of order: farmer ends the
// session (integrity) and the sprout kills the shell. Nothing is
// resynchronised.
func TestSealedShellDropAndReorder(t *testing.T) {
	for name, deliver := range map[string]func(cli *nats.Conn, subject string, held [][]byte){
		"drop": func(cli *nats.Conn, subject string, held [][]byte) { _ = cli.Publish(subject, held[1]) },
		"reorder": func(cli *nats.Conn, subject string, held [][]byte) {
			_ = cli.Publish(subject, held[1])
			_ = cli.Publish(subject, held[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			env := startShellEnv(t)
			m := env.openManual(t)
			waitFor(t, "the sprout's shell", func() bool { return env.sp.Active() == 1 })
			m.holdFrames(true)
			ctx := context.Background()
			if err := m.stream.SendData(ctx, []byte("rm -rf /tmp/x")); err != nil {
				t.Fatal(err)
			}
			if err := m.stream.SendData(ctx, []byte("\n")); err != nil {
				t.Fatal(err)
			}
			m.holdFrames(false)
			deliver(env.cli, shell.CLISubject(m.sessionID, payloadbox.DirC2F), m.held)
			if info := m.waitClose(t); info.Reason != payloadbox.CloseIntegrity {
				t.Fatalf("closed %+v, want integrity", info)
			}
			waitFor(t, "the sprout to kill the shell", func() bool { return env.sp.Active() == 0 })
		})
	}
}

// The bus drops everything: both ends notice (peer-lost) and the shell
// is killed.
func TestSealedShellPeerLost(t *testing.T) {
	env := startShellEnv(t)
	m := env.openManual(t)
	waitFor(t, "the sprout's shell", func() bool { return env.sp.Active() == 1 })
	m.holdFrames(true) // the CLI's heartbeats never arrive
	waitFor(t, "farmer to give up", func() bool { return ShellTracker().Active() == 0 })
	waitFor(t, "the sprout to kill the shell", func() bool { return env.sp.Active() == 0 })
	if !strings.Contains(readAudit(t, env.audit), `"reason":"peer-lost"`) {
		t.Error("peer-lost isn't in the audit log")
	}
}

// A user may open a shell only on a sprout of their own tenant: a sprout
// that exists only in another tenant is unknown, and nothing is sent.
// And a start sealed for another tenant's sprout of the same ID doesn't
// open on this one, even under a shared box key.
func TestSealedShellCrossTenant(t *testing.T) {
	env := startShellEnv(t)
	other := "t_2"
	if err := pki.ProvisionTenant(other, "other"); err != nil {
		t.Fatalf("ProvisionTenant: %v", err)
	}
	if err := pki.UnacceptNKey(other, "db-09", "UOTHERTENANTSPROUT"); err != nil {
		t.Fatal(err)
	}
	if err := pki.AcceptNKey(other, "db-09"); err != nil {
		t.Fatal(err)
	}
	eph, _ := payloadbox.NewEphemeralKey()
	if _, err := env.open(shell.OpenRequest{SproutID: "db-09", CLIEphPub: eph.PublicKey().Bytes()}); err == nil || !strings.Contains(err.Error(), "unknown sprout") {
		t.Fatalf("open of another tenant's sprout: %v", err)
	}
	if ShellTracker().Active() != 0 || len(env.spy.on("imas.sprouts.db-09.")) != 0 {
		t.Fatal("a cross-tenant open went anywhere")
	}

	// Tenant t_2 has its own web-01, holding the same box key (the H3
	// case). Farmer's start sealed for t_2's web-01 is refused by ours.
	if err := pki.RotateSproutBoxKey(other, shellTestSprout, env.sprPub, time.Hour); err != nil {
		t.Fatal(err)
	}
	farmerEph, _ := payloadbox.NewEphemeralKey()
	data, _, err := pki.SealToSprout(other, shellTestSprout, payloadbox.PurposeShellStart, "", shell.StartBody{
		SessionID: "0123456789abcdef0123456789abcdef", FarmerEphPub: farmerEph.PublicKey().Bytes(), Cols: 80, Rows: 24,
		User: shell.StartUser{Pubkey: env.user.id},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := nats.NewMsg(shell.StartSubject(shellTestSprout))
	m.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	m.Data = data
	resp, err := env.hostile.RequestMsg(m, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get(payloadbox.ErrorHeader) != payloadbox.ErrorCodeOpenFailed || env.sp.Active() != 0 {
		t.Fatalf("another tenant's start answered %v; sessions %d", resp.Header, env.sp.Active())
	}
}

// A user whose role loses shell is cut off within the recheck interval.
func TestSealedShellRevoked(t *testing.T) {
	env := startShellEnv(t)
	run := env.startClient(t, nil)
	run.waitReady(t)
	intauth.CurrentPolicy().Users.Set(env.user.id, "no-such-role")
	res := run.wait(t)
	if res.Reason != payloadbox.CloseRevoked {
		t.Fatalf("ended %+v, want revoked", res)
	}
	waitFor(t, "the sprout to kill the shell", func() bool { return env.sp.Active() == 0 })
}

// A user without shell can't open one at all.
func TestSealedShellNeedsShellAction(t *testing.T) {
	env := startShellEnv(t)
	intauth.CurrentPolicy().Users.Set(env.user.id, "no-such-role")
	eph, _ := payloadbox.NewEphemeralKey()
	if _, err := env.open(shell.OpenRequest{SproutID: shellTestSprout, CLIEphPub: eph.PublicKey().Bytes()}); err == nil {
		t.Fatal("opened without the shell action")
	}
	if ShellTracker().Active() != 0 {
		t.Fatal("tracked")
	}
}

// --sever ends running sessions (key-severed); a normal rotation doesn't.
// Through imas keys rotate-tenant-key on this replica it is immediate;
// done anywhere else (another replica, OpenBao directly) the periodic
// re-check finds it.
func TestSealedShellSeverEndsSessions(t *testing.T) {
	for name, viaHandler := range map[string]bool{"this replica, at once": true, "elsewhere, periodic re-check": false} {
		t.Run(name, func(t *testing.T) {
			env := startShellEnv(t)
			// A normal rotation keeps the previous key for the grace window
			// (24 hours by default; unset in tests).
			origGrace := config.BoxKeyGraceDuration
			config.BoxKeyGraceDuration = time.Hour
			t.Cleanup(func() { config.BoxKeyGraceDuration = origGrace })
			if viaHandler {
				shellRecheckInterval = time.Hour // only the immediate path can act
			}
			rotate := func(sever bool) {
				t.Helper()
				var err error
				if viaHandler {
					_, err = handlePKIRotateTenantBoxKey(env.tenant, json.RawMessage(fmt.Sprintf(`{"sever":%t}`, sever)))
				} else {
					_, err = pki.RotateTenantX25519Keypair(env.tenant, sever)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			run := env.startClient(t, nil)
			run.waitReady(t)
			rotate(false)
			time.Sleep(600 * time.Millisecond)
			if ShellTracker().Active() != 1 {
				t.Fatal("a normal rotation ended the session")
			}
			rotate(true)
			res := run.wait(t)
			if res.Reason != payloadbox.CloseKeySevered {
				t.Fatalf("ended %+v, want key-severed", res)
			}
			waitFor(t, "the sprout to kill the shell", func() bool { return env.sp.Active() == 0 })
		})
	}
}

// The sprout's local policy refuses before spawning, sealed: the CLI
// learns why, the bus doesn't.
func TestSealedShellSproutPolicy(t *testing.T) {
	for name, c := range map[string]struct {
		policy shell.SproutPolicy
		shell  string
		want   string
	}{
		"disabled":         {shell.SproutPolicy{Disabled: true, AllowedShells: []string{"/bin/sh"}}, "", payloadbox.CloseShellDisabled},
		"not allowed":      {shell.SproutPolicy{AllowedShells: []string{"/bin/sh"}}, "/bin/bash", payloadbox.CloseShellNotAllowed},
		"spawn fails":      {shell.SproutPolicy{AllowedShells: []string{"/nonexistent/shell"}}, "", payloadbox.CloseSpawnFailed},
		"empty allow-list": {shell.SproutPolicy{AllowedShells: []string{"relative"}}, "", payloadbox.CloseShellNotAllowed},
	} {
		t.Run(name, func(t *testing.T) {
			env := startShellEnv(t)
			shell.SetSproutPolicy(c.policy)
			run := env.startClient(t, func(o *shell.ClientOptions) { o.Shell = c.shell })
			res := run.wait(t)
			if res.Reason != c.want || !res.Remote {
				t.Fatalf("ended %+v, want %s", res, c.want)
			}
			if env.sp.Active() != 0 {
				t.Fatal("spawned anyway")
			}
			for _, m := range env.spy.on("_INBOX.") {
				if bytes.Contains(m.Data, []byte(c.want)) {
					t.Fatalf("the refusal code crossed the bus in plaintext")
				}
			}
		})
	}
	t.Run("too many sessions", func(t *testing.T) {
		env := startShellEnv(t)
		shell.SetSproutPolicy(shell.SproutPolicy{AllowedShells: []string{"/bin/sh"}, MaxSessions: 1})
		first := env.startClient(t, nil)
		first.waitReady(t)
		second := env.startClient(t, nil)
		if res := second.wait(t); res.Reason != payloadbox.CloseTooManySessions {
			t.Fatalf("second session ended %+v", res)
		}
	})
}

// The idle timeout ends a session with no input; the CLI may only
// shorten farmer's.
func TestSealedShellIdleTimeout(t *testing.T) {
	env := startShellEnv(t)
	run := env.startClient(t, func(o *shell.ClientOptions) { o.IdleTimeoutSec = 1 })
	opened := run.waitReady(t)
	if opened.IdleTimeoutSec != 1 || opened.MaxDurationSec != int(shell.MaxSessionDuration/time.Second) {
		t.Fatalf("limits %+v", opened)
	}
	if res := run.wait(t); res.Reason != payloadbox.CloseIdle {
		t.Fatalf("ended %+v, want idle", res)
	}
	waitFor(t, "the sprout to kill the shell", func() bool { return env.sp.Active() == 0 })

	eph, _ := payloadbox.NewEphemeralKey()
	raw, err := env.open(shell.OpenRequest{SproutID: shellTestSprout, CLIEphPub: eph.PublicKey().Bytes(), IdleTimeoutSec: 7200})
	if err != nil {
		t.Fatal(err)
	}
	var res shell.OpenResult
	_ = json.Unmarshal(raw, &res)
	if res.IdleTimeoutSec != int(shell.DefaultIdleTimeout/time.Second) {
		t.Fatalf("a CLI asked for a longer idle timeout and got %d s", res.IdleTimeoutSec)
	}
}

// handleShellOpen refuses bad requests before anything is set up.
func TestHandleShellOpenValidation(t *testing.T) {
	env := startShellEnv(t)
	c := apiCaller{TenantID: env.tenant, UserID: env.user.id}
	good, _ := payloadbox.NewEphemeralKey()
	tenantPub, _ := pki.GetTenantX25519PublicKey(env.tenant)
	tk, _ := pki.DecodeBoxPubKey(tenantPub)
	for name, req := range map[string]shell.OpenRequest{
		"bad sprout id":    {SproutID: "Bad.ID", CLIEphPub: good.PublicKey().Bytes()},
		"relative shell":   {SproutID: shellTestSprout, Shell: "sh", CLIEphPub: good.PublicKey().Bytes()},
		"negative idle":    {SproutID: shellTestSprout, IdleTimeoutSec: -1, CLIEphPub: good.PublicKey().Bytes()},
		"no ephemeral key": {SproutID: shellTestSprout},
		"low-order key":    {SproutID: shellTestSprout, CLIEphPub: make([]byte, 32)},
		"the tenant's key": {SproutID: shellTestSprout, CLIEphPub: tk[:]},
		"unknown sprout":   {SproutID: "nope", CLIEphPub: good.PublicKey().Bytes()},
	} {
		params, _ := json.Marshal(req)
		if _, err := handleShellOpen(c, params); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := handleShellOpen(c, json.RawMessage(`{bad`)); err == nil {
		t.Error("bad JSON accepted")
	}
	// A sprout with no box key: refused, no plaintext fallback.
	writeNKey(t, "", "accepted", "old-01", "UOLDSPROUTNOBOXKEY")
	params, _ := json.Marshal(shell.OpenRequest{SproutID: "old-01", CLIEphPub: good.PublicKey().Bytes()})
	if _, err := handleShellOpen(c, params); !errors.Is(err, errShellNoBoxKey) {
		t.Errorf("sprout without a box key: %v", err)
	}
	if ShellTracker().Active() != 0 {
		t.Fatal("a refused open was tracked")
	}
}
