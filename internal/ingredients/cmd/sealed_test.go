package cmd

// End-to-end tests for sealed cmd.run (sealed.go): a real embedded NATS
// server, farmer's real FRun on one connection and the sprout's real
// RespondCmdRun on another, keys from a mock OpenBao (tenant) and the
// sprout's own files, and a third "bus" subscriber standing in for a
// compromised bus that sees everything routed through it.

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/nats-io/nats-server/v2/server"
	nats "github.com/nats-io/nats.go"
	"golang.org/x/crypto/nacl/box"
	"gorm.io/gorm"

	apitypes "github.com/yogzblr/imas/internal/api/types"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/pki/tenantboxtest"
)

type sealedEnv struct {
	tenant, sproutID string
	farmer, sprout   *nats.Conn
	kv               *tenantboxtest.Server
	dir              string
	tenantPub        string
}

func startTestNATS(t *testing.T) string {
	t.Helper()
	ns, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1})
	if err != nil {
		t.Fatal(err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS server not ready")
	}
	t.Cleanup(ns.Shutdown)
	return ns.ClientURL()
}

func connect(t *testing.T, url string) *nats.Conn {
	t.Helper()
	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	return nc
}

// setupSealed wires farmer and one enrolled sprout (sproutID) of tenant
// together: the sprout's box key on record farmer-side, the tenant's
// public key pinned sprout-side, and the sprout answering cmd.run with
// RespondCmdRun.
func setupSealed(t *testing.T, tenant string) *sealedEnv {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open("file:"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := gdb.AutoMigrate(pki.Models()...); err != nil {
		t.Fatal(err)
	}
	pki.SetDB(gdb)
	t.Cleanup(func() {
		if sqlDB, err := gdb.DB(); err == nil {
			sqlDB.Close()
		}
	})

	env := &sealedEnv{tenant: tenant, sproutID: "web-01", dir: t.TempDir()}
	env.kv = tenantboxtest.Start(t)
	pki.InvalidateTenantBoxKeys(tenant)
	t.Cleanup(func() { pki.InvalidateTenantBoxKeys(tenant) })
	origGrace, origPriv, origPin := config.BoxKeyGraceDuration, config.SproutBoxPrivFile, config.SproutTenantX25519PubFile
	t.Cleanup(func() {
		config.BoxKeyGraceDuration, config.SproutBoxPrivFile, config.SproutTenantX25519PubFile = origGrace, origPriv, origPin
	})
	config.BoxKeyGraceDuration = time.Hour
	config.SproutBoxPrivFile = filepath.Join(env.dir, "box.key")
	config.SproutTenantX25519PubFile = filepath.Join(env.dir, "tenant-x25519.pub")

	// The sprout's own keypair, and farmer's record of its public half.
	sproutPub, err := pki.EnsureSproutBoxKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.RotateSproutBoxKey(tenant, env.sproutID, sproutPub, time.Hour); err != nil {
		t.Fatal(err)
	}
	// The tenant key the sprout pinned at enrollment.
	env.tenantPub, err = pki.GetTenantX25519PublicKey(tenant)
	if err != nil {
		t.Fatal(err)
	}
	env.pin(t, env.tenantPub)

	url := startTestNATS(t)
	env.farmer, env.sprout = connect(t, url), connect(t, url)
	RegisterFarmerNatsConn(tenant, env.farmer)
	t.Cleanup(func() { UnregisterFarmerNatsConn(tenant) })
	if _, err := env.sprout.Subscribe(cmdRunSubject(env.sproutID), func(m *nats.Msg) {
		m.RespondMsg(RespondCmdRun(env.sproutID, m))
	}); err != nil {
		t.Fatal(err)
	}
	env.sprout.Flush()
	return env
}

func (e *sealedEnv) pin(t *testing.T, pub string) {
	t.Helper()
	if err := os.WriteFile(config.SproutTenantX25519PubFile, []byte(pub), 0o644); err != nil {
		t.Fatal(err)
	}
}

// busSpy records every payload routed on the sprout's cmd.run subject
// and every reply inbox, as a compromised bus would see them.
type busSpy struct {
	mu   sync.Mutex
	msgs []*nats.Msg
}

func spyOnBus(t *testing.T, e *sealedEnv) *busSpy {
	t.Helper()
	spy := &busSpy{}
	nc := connect(t, e.farmer.ConnectedUrl())
	for _, subj := range []string{cmdRunSubject(e.sproutID), "_INBOX.>"} {
		if _, err := nc.Subscribe(subj, func(m *nats.Msg) {
			spy.mu.Lock()
			spy.msgs = append(spy.msgs, m)
			spy.mu.Unlock()
		}); err != nil {
			t.Fatal(err)
		}
	}
	nc.Flush()
	return spy
}

func (s *busSpy) all() []*nats.Msg {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*nats.Msg(nil), s.msgs...)
}

func (s *busSpy) waitFor(t *testing.T, n int) []*nats.Msg {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if msgs := s.all(); len(msgs) >= n {
			return msgs
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("bus saw %d messages, want %d", len(s.all()), n)
	return nil
}

func TestSealedCmdRun_RoundTripHidesCommandAndOutputFromTheBus(t *testing.T) {
	e := setupSealed(t, "t_sealed_rt")
	spy := spyOnBus(t, e)

	res, err := FRun(e.tenant, pki.KeyManager{SproutID: e.sproutID}, apitypes.CmdRun{
		Command: "echo", Args: []string{"secret-output-4f1c"},
		Env:     apitypes.EnvVar{"API_TOKEN": "secret-env-9b2e"},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("FRun: %v", err)
	}
	if strings.TrimSpace(res.Stdout) != "secret-output-4f1c" || res.ErrCode != 0 {
		t.Fatalf("result %+v", res)
	}

	msgs := spy.waitFor(t, 2) // the request and its reply
	for _, m := range msgs {
		for _, secret := range []string{"secret-output", "secret-env", "API_TOKEN", "echo"} {
			if bytes.Contains(m.Data, []byte(secret)) {
				t.Errorf("the bus saw %q in plaintext on %s: %s", secret, m.Subject, m.Data)
			}
		}
		if m.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
			t.Errorf("message on %s isn't marked sealed", m.Subject)
		}
	}
}

func TestSealedCmdRun_SproutRefusesPlaintext(t *testing.T) {
	e := setupSealed(t, "t_sealed_plain")
	marker := filepath.Join(e.dir, "ran")
	// What a compromised bus would inject: an unsealed command.
	reply, err := e.farmer.Request(cmdRunSubject(e.sproutID),
		[]byte(`{"command":"touch","args":["`+marker+`"]}`), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if code := reply.Header.Get(payloadbox.ErrorHeader); code != payloadbox.ErrorCodeEncryptionRequired {
		t.Errorf("refusal code %q, want %q", code, payloadbox.ErrorCodeEncryptionRequired)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("the sprout ran a plaintext command")
	}
}

func TestSealedCmdRun_ReplayIsRefused(t *testing.T) {
	e := setupSealed(t, "t_sealed_replay")
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
	// The bus re-sends the captured sealed request.
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

// Farmer must not accept anything but a sealed reply to its own request:
// not plaintext (a downgrade), not its own request reflected back, and
// not a refusal dressed as a result.
func TestSealedCmdRun_FarmerRejectsBadReplies(t *testing.T) {
	e := setupSealed(t, "t_sealed_replies")
	e.sprout.Close() // replace the real sprout with hostile responders
	hostile := connect(t, e.farmer.ConnectedUrl())
	var respond func(m *nats.Msg) *nats.Msg
	if _, err := hostile.Subscribe(cmdRunSubject(e.sproutID), func(m *nats.Msg) { m.RespondMsg(respond(m)) }); err != nil {
		t.Fatal(err)
	}
	hostile.Flush()

	cases := map[string]struct {
		respond func(m *nats.Msg) *nats.Msg
		want    error
	}{
		"plaintext": {func(*nats.Msg) *nats.Msg {
			return &nats.Msg{Data: []byte(`{"stdout":"forged"}`)}
		}, ErrReplyNotSealed},
		"reflected request": {func(m *nats.Msg) *nats.Msg {
			r := nats.NewMsg("")
			r.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
			r.Data = m.Data
			return r
		}, payloadbox.ErrOpen},
		"refusal": {func(*nats.Msg) *nats.Msg { return refusal(payloadbox.ErrorCodeOpenFailed) }, ErrSproutRefusedPayload},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			respond = c.respond
			_, err := FRun(e.tenant, pki.KeyManager{SproutID: e.sproutID}, apitypes.CmdRun{Command: "true", Timeout: time.Second})
			if !errors.Is(err, c.want) {
				t.Errorf("FRun error %v, want %v", err, c.want)
			}
		})
	}
}

// A reply the sprout sealed for an earlier request is refused, even
// though it opens: it doesn't answer this one.
func TestSealedCmdRun_FarmerRejectsAReplyToAnotherRequest(t *testing.T) {
	e := setupSealed(t, "t_sealed_stale_reply")
	stale, err := pki.SproutSealForFarmer(e.sproutID, payloadbox.PurposeCmdRunResponse, "some-earlier-request",
		apitypes.CmdRun{Stdout: "forged"})
	if err != nil {
		t.Fatal(err)
	}
	e.sprout.Close()
	hostile := connect(t, e.farmer.ConnectedUrl())
	hostile.Subscribe(cmdRunSubject(e.sproutID), func(m *nats.Msg) {
		r := nats.NewMsg("")
		r.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
		r.Data = stale
		m.RespondMsg(r)
	})
	hostile.Flush()
	if _, err := FRun(e.tenant, pki.KeyManager{SproutID: e.sproutID}, apitypes.CmdRun{Command: "true", Timeout: time.Second}); !errors.Is(err, payloadbox.ErrOpen) {
		t.Fatalf("FRun error %v, want ErrOpen", err)
	}
}

// Across a tenant key rotation, cmd.run keeps working for a sprout still
// pinned to the old key (inside the grace window) and after it re-pins.
func TestSealedCmdRun_AcrossTenantKeyRotation(t *testing.T) {
	e := setupSealed(t, "t_sealed_rotate")
	run := func() {
		t.Helper()
		res, err := FRun(e.tenant, pki.KeyManager{SproutID: e.sproutID}, apitypes.CmdRun{Command: "echo", Args: []string{"ok"}, Timeout: 5 * time.Second})
		if err != nil || strings.TrimSpace(res.Stdout) != "ok" {
			t.Fatalf("FRun: %+v, %v", res, err)
		}
	}
	rot, err := pki.RotateTenantX25519Keypair(e.tenant, false)
	if err != nil {
		t.Fatal(err)
	}
	run() // sprout still pinned to the old key
	e.pin(t, rot.Pub)
	run() // re-pinned

	// After a severing rotation, a sprout pinned to anything older is cut
	// off: it can't open farmer's request.
	if _, err := pki.RotateTenantX25519Keypair(e.tenant, true); err != nil {
		t.Fatal(err)
	}
	_, err = FRun(e.tenant, pki.KeyManager{SproutID: e.sproutID}, apitypes.CmdRun{Command: "true", Timeout: time.Second})
	if !errors.Is(err, ErrSproutRefusedPayload) {
		t.Fatalf("FRun after sever: %v, want the sprout to refuse", err)
	}
}

// A sprout enrolled before workstream J has no box key on record and no
// keys of its own: cmd.run stays plaintext for it, as before.
func TestSealedCmdRun_LegacySproutStaysPlaintext(t *testing.T) {
	e := setupSealed(t, "t_sealed_legacy")
	const legacy = "legacy-01"
	os.Remove(config.SproutTenantX25519PubFile) // this process now plays a keyless sprout
	e.sprout.Subscribe(cmdRunSubject(legacy), func(m *nats.Msg) { m.RespondMsg(RespondCmdRun(legacy, m)) })
	e.sprout.Flush()
	res, err := FRun(e.tenant, pki.KeyManager{SproutID: legacy}, apitypes.CmdRun{Command: "echo", Args: []string{"plain"}, Timeout: 5 * time.Second})
	if err != nil || strings.TrimSpace(res.Stdout) != "plain" {
		t.Fatalf("FRun to a legacy sprout: %+v, %v", res, err)
	}
}

// A sprout with box keys but a farmer that seals for a different key
// (another tenant's sprout with the same ID, say) can't open the request.
func TestSealedCmdRun_OtherTenantsSproutCannotOpen(t *testing.T) {
	e := setupSealed(t, "t_sealed_a")
	// Farmer believes tenant t_sealed_b also has a web-01, with its own key.
	otherPub, _, _ := box.GenerateKey(rand.Reader)
	if err := pki.RotateSproutBoxKey("t_sealed_b", e.sproutID, base64.StdEncoding.EncodeToString(otherPub[:]), time.Hour); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pki.InvalidateTenantBoxKeys("t_sealed_b") })
	sealed, _, err := pki.SealToSprout("t_sealed_b", e.sproutID, payloadbox.PurposeCmdRunRequest, "", apitypes.CmdRun{Command: "true"})
	if err != nil {
		t.Fatal(err)
	}
	// Delivered to tenant t_sealed_a's web-01 (this process's sprout).
	if _, err := pki.SproutOpenFromFarmer(e.sproutID, payloadbox.PurposeCmdRunRequest, sealed); !errors.Is(err, payloadbox.ErrOpen) {
		t.Fatalf("t_sealed_a's sprout opened a request sealed for t_sealed_b's: %v", err)
	}
}
