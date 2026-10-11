package accountloader

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	nats_server "github.com/nats-io/nats-server/v2/server"
	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

// embeddedBus is one nats-server in operator mode with a full (directory)
// account resolver, as a bus node runs, and the loader's SYS user files.
type embeddedBus struct {
	srv               *nats_server.Server
	tr                *testTrust
	sysKP             nkeys.KeyPair
	userJWT, userSeed string
}

func startBus(t *testing.T) *embeddedBus {
	t.Helper()
	tr := newTrust(t)
	sysKP, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	tr.sysPub, _ = sysKP.PublicKey()

	oc := jwt.NewOperatorClaims(tr.opPub)
	oc.SystemAccount = tr.sysPub
	opJWT, err := oc.Encode(tr.op)
	if err != nil {
		t.Fatal(err)
	}
	opClaims, err := jwt.DecodeOperatorClaims(opJWT)
	if err != nil {
		t.Fatal(err)
	}
	sysJWT, err := jwt.NewAccountClaims(tr.sysPub).Encode(tr.op)
	if err != nil {
		t.Fatal(err)
	}

	resolver, err := nats_server.NewDirAccResolver(t.TempDir(), 0, 0, nats_server.NoDelete)
	if err != nil {
		t.Fatal(err)
	}
	if err := resolver.Store(tr.sysPub, sysJWT); err != nil {
		t.Fatal(err)
	}
	opts := &nats_server.Options{
		Host:             "127.0.0.1",
		Port:             -1,
		NoLog:            true,
		NoSigs:           true,
		TrustedOperators: []*jwt.OperatorClaims{opClaims},
		SystemAccount:    tr.sysPub,
		AccountResolver:  resolver,
	}
	srv, err := nats_server.NewServer(opts)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		t.Fatal("embedded bus not ready")
	}
	t.Cleanup(srv.Shutdown)

	// The loader's SYS user, scoped as brief §5.2 says.
	ukp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	upub, _ := ukp.PublicKey()
	useed, _ := ukp.Seed()
	uc := jwt.NewUserClaims(upub)
	uc.Pub.Allow.Add(claimsUpdateSubj, claimsListSubj, "$SYS.REQ.ACCOUNT.*.CLAIMS.LOOKUP")
	uc.Sub.Allow.Add("_INBOX.>", DefaultEventSubject)
	ujwt, err := uc.Encode(sysKP)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	b := &embeddedBus{srv: srv, tr: tr, sysKP: sysKP, userJWT: filepath.Join(dir, "user.jwt"), userSeed: filepath.Join(dir, "user.nk")}
	if err := os.WriteFile(b.userJWT, []byte(ujwt+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b.userSeed, useed, 0o600); err != nil {
		t.Fatal(err)
	}
	return b
}

func (b *embeddedBus) dial(t *testing.T) *NATSNode {
	t.Helper()
	n, err := DialNode(NATSConfig{
		URL:            b.srv.ClientURL(),
		UserJWTFile:    b.userJWT,
		UserSeedFile:   b.userSeed,
		RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(n.Close)
	waitFor(t, "connected", func() bool { return n.ConnectedServerID() != "" })
	return n
}

// publisher connects as a SYS user allowed to publish the event, as
// farmer's is.
func (b *embeddedBus) publisher(t *testing.T) *nats.Conn {
	t.Helper()
	ukp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	upub, _ := ukp.PublicKey()
	useed, _ := ukp.Seed()
	uc := jwt.NewUserClaims(upub)
	uc.Pub.Allow.Add(DefaultEventSubject)
	ujwt, err := uc.Encode(b.sysKP)
	if err != nil {
		t.Fatal(err)
	}
	nc, err := nats.Connect(b.srv.ClientURL(), nats.UserJWTAndSeed(ujwt, string(useed)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	return nc
}

func TestEventIsPlainSubscription(t *testing.T) {
	b := startBus(t)
	a, c := b.dial(t), b.dial(t)
	got := make(chan string, 4)
	for _, n := range []*NATSNode{a, c} {
		if err := n.Subscribe(DefaultEventSubject, func(d []byte) { got <- string(d) }); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.nc.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := c.nc.Flush(); err != nil {
		t.Fatal(err)
	}
	// The loader's own user may not publish the event; farmer's may.
	pub := b.publisher(t)
	if err := pub.Publish(DefaultEventSubject, []byte(`{"v":1}`)); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		select {
		case <-got:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of 2 loaders received the event; it must not be a queue subscription", i)
		}
	}
}

func TestNATSNodePushListLookup(t *testing.T) {
	b := startBus(t)
	n := b.dial(t)
	ctx := context.Background()
	if n.ConnectedServerID() != b.srv.ID() {
		t.Fatalf("connected to %s, want %s", n.ConnectedServerID(), b.srv.ID())
	}

	p := newAccountPub(t)
	j := b.tr.jwt(t, p, time.Now().Unix())
	if err := n.Push(ctx, p, []byte(j)); err != nil {
		t.Fatalf("push: %v", err)
	}
	id, ids, err := n.ListIDs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if id != b.srv.ID() || !slices.Contains(ids, p) || !slices.Contains(ids, b.tr.sysPub) {
		t.Errorf("ListIDs = %s %v, want %s listing the pushed and SYS accounts", id, ids, b.srv.ID())
	}
	lctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	answers, err := n.Lookup(lctx, p)
	cancel()
	if err != nil || len(answers) != 1 || string(answers[0]) != j {
		t.Errorf("Lookup = %d answers, %v; want the pushed JWT", len(answers), err)
	}
	lctx, cancel = context.WithTimeout(ctx, 300*time.Millisecond)
	answers, err = n.Lookup(lctx, newAccountPub(t))
	cancel()
	if err != nil || len(answers) != 1 || len(answers[0]) != 0 {
		t.Errorf("Lookup of an unknown account = %q, %v; want one empty answer", answers, err)
	}

	// An error answer is returned as an error. (The node saves a JWT
	// from an untrusted operator without complaint, which is why the
	// loader validates every JWT before pushing it.)
	if err := n.Push(ctx, p, []byte("not a jwt")); err == nil {
		t.Error("an undecodable JWT was reported as accepted")
	}
}

func TestNATSNodeNotConnected(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "x")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := DialNode(NATSConfig{URL: "nats://127.0.0.1:1", UserJWTFile: f, UserSeedFile: f})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()
	if n.ConnectedServerID() != "" {
		t.Fatal("connected to nothing")
	}
	if err := n.Push(context.Background(), newAccountPub(t), []byte("x")); err != ErrNotConnected {
		t.Errorf("Push while disconnected = %v", err)
	}
	if _, _, err := n.ListIDs(context.Background()); err != ErrNotConnected {
		t.Errorf("ListIDs while disconnected = %v", err)
	}
	if _, err := DialNode(NATSConfig{URL: "nats://127.0.0.1:1"}); err == nil {
		t.Error("DialNode without user files accepted")
	}
}
