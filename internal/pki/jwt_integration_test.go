package pki

// Integration coverage against a real, local embedded nats-server: proves
// the accept/deny/reject lifecycle actually gates bus access end to end via
// JWT issuance and Account-level revocation, and that ReloadNKeys' push
// mechanism (resolver.go) really does reach a running server rather than
// just updating local files.

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	nats_server "github.com/nats-io/nats-server/v2/server"

	"github.com/yogzblr/imas/internal/config"
)

// startTestBus builds NATS options via ConfigureNats(), starts an embedded
// server on a free port, points config.FarmerBusURL at it, and registers it
// with the pki package the same way cmd/farmer/main.go's RunNATSServer
// does. The returned func shuts the server down.
func startTestBus(t *testing.T) func() {
	t.Helper()
	config.FarmerBusPort = "-1" // RANDOM_PORT; "0" would mean nats-server's default 4222

	opts := ConfigureNats()
	srv, err := nats_server.NewServer(&opts)
	if err != nil || srv == nil {
		t.Fatalf("failed to create NATS server: %v", err)
	}
	var noopLogger testNoopLogger
	srv.SetLogger(noopLogger, false, false)
	go srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		t.Fatal("NATS server did not become ready")
	}

	addr, ok := srv.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected listener address type: %T", srv.Addr())
	}
	config.FarmerBusURL = fmt.Sprintf("%s:%d", config.FarmerInterface, addr.Port)

	SetNATSServer(srv)
	t.Cleanup(func() {
		SetNATSServer(nil)
		srv.Shutdown()
	})
	return srv.Shutdown
}

// startTestBusWithoutLocalHandle is startTestBus's counterpart for the
// post-bus/core-split topology: it starts the same embedded test bus, but
// deliberately never calls SetNATSServer, so the calling process (like a
// future split-out core process) has no in-process *nats_server.Server
// handle to it at all. Any push to the resolver must reach the bus purely
// over the network connection pushAccountUpdate opens.
func startTestBusWithoutLocalHandle(t *testing.T) func() {
	t.Helper()
	config.FarmerBusPort = "-1" // RANDOM_PORT; "0" would mean nats-server's default 4222

	opts := ConfigureNats()
	srv, err := nats_server.NewServer(&opts)
	if err != nil || srv == nil {
		t.Fatalf("failed to create NATS server: %v", err)
	}
	var noopLogger testNoopLogger
	srv.SetLogger(noopLogger, false, false)
	go srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		t.Fatal("NATS server did not become ready")
	}

	addr, ok := srv.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected listener address type: %T", srv.Addr())
	}
	config.FarmerBusURL = fmt.Sprintf("%s:%d", config.FarmerInterface, addr.Port)

	// Deliberately do NOT call SetNATSServer(srv): this process must push
	// updates to the bus's resolver over the network, the same way a
	// split-out core process (with no local bus handle) would have to.
	original := NatsServer
	NatsServer = nil
	t.Cleanup(func() {
		NatsServer = original
		srv.Shutdown()
	})
	return srv.Shutdown
}

type testNoopLogger struct{}

func (testNoopLogger) Noticef(string, ...any) {}
func (testNoopLogger) Warnf(string, ...any)   {}
func (testNoopLogger) Fatalf(string, ...any)  {}
func (testNoopLogger) Errorf(string, ...any)  {}
func (testNoopLogger) Debugf(string, ...any)  {}
func (testNoopLogger) Tracef(string, ...any)  {}

// dialAsSprout attempts to connect to the test bus authenticated with the
// given sprout User JWT + NKey seed. It never fatals: callers assert on the
// returned error so both the happy and the revoked path can be tested.
func dialAsSprout(t *testing.T, sproutJWT string, seed []byte, extra ...nats.Option) (*nats.Conn, error) {
	t.Helper()
	rootPEM, err := os.ReadFile(config.RootCA)
	if err != nil {
		t.Fatalf("reading root CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootPEM) {
		t.Fatalf("failed to parse root CA")
	}
	tlsCfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	opts := append([]nats.Option{
		nats.Secure(tlsCfg),
		nats.UserJWTAndSeed(sproutJWT, string(seed)),
		nats.Timeout(5 * time.Second),
		nats.RetryOnFailedConnect(false),
	}, extra...)
	return nats.Connect(config.FarmerBusURL, opts...)
}

func TestJWTLifecycle_AcceptGrantsDenyRevokesReacceptRestores(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	defer startTestBus(t)()

	sproutKP, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("failed to create sprout NKey: %v", err)
	}
	sproutPub, err := sproutKP.PublicKey()
	if err != nil {
		t.Fatalf("failed to get sprout public key: %v", err)
	}
	sproutSeed, err := sproutKP.Seed()
	if err != nil {
		t.Fatalf("failed to get sprout seed: %v", err)
	}
	writeKey(t, "unaccepted", "sprout01", sproutPub)

	// Unaccepted: no User JWT minted yet, so there's nothing valid to
	// connect with regardless of the bus's state.
	if _, err := GetSproutUserJWT("sprout01"); err != ErrSproutIDNotFound {
		t.Fatalf("expected no JWT before acceptance, got err=%v", err)
	}

	// Accept: mints a JWT and pushes the (now-changed) tenant Account JWT
	// to the running bus's resolver.
	if err := AcceptNKey(currentTenantID(), "sprout01"); err != nil {
		t.Fatalf("AcceptNKey failed: %v", err)
	}
	sproutJWT, err := GetSproutUserJWT("sprout01")
	if err != nil {
		t.Fatalf("GetSproutUserJWT failed after accept: %v", err)
	}

	nc, err := dialAsSprout(t, sproutJWT, sproutSeed)
	if err != nil {
		t.Fatalf("expected accepted sprout to connect, got: %v", err)
	}
	if !nc.IsConnected() {
		t.Fatal("expected connection to be established")
	}

	// Permission check: the sprout can talk on its own subject tree. Its
	// permission template (sproutPermissions in jwtusers.go, unchanged from
	// the original NKey allow-list) only grants Publish on a few specific
	// subjects, of which "facts" is the one usable for a round trip here;
	// Subscribe is allowed on the whole "imas.sprouts.<id>.>" subtree.
	sub, err := nc.SubscribeSync("imas.sprouts.sprout01.facts")
	if err != nil {
		t.Fatalf("subscribe on own subject failed: %v", err)
	}
	if err := nc.Publish("imas.sprouts.sprout01.facts", []byte("hello")); err != nil {
		t.Fatalf("publish on own subject failed: %v", err)
	}
	msg, err := sub.NextMsg(3 * time.Second)
	if err != nil {
		t.Fatalf("expected to receive own message, got: %v", err)
	}
	if string(msg.Data) != "hello" {
		t.Errorf("unexpected message payload: %q", msg.Data)
	}

	// ...but not on another sprout's subject tree.
	permErrCh := make(chan error, 1)
	nc.SetErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
		select {
		case permErrCh <- err:
		default:
		}
	})
	if err := nc.Publish("imas.sprouts.other-sprout.jobs", []byte("nope")); err != nil {
		t.Fatalf("unexpected sync error publishing to a denied subject: %v", err)
	}
	nc.Flush()
	select {
	case permErr := <-permErrCh:
		if permErr == nil {
			t.Error("expected a permissions violation error")
		}
	case <-time.After(3 * time.Second):
		t.Error("expected an async permissions violation for publishing outside allowed subjects")
	}
	nc.Close()

	// Deny: revokes the sprout's pubkey on the tenant Account and pushes
	// the update. The exact same JWT + seed must now be rejected.
	if err := DenyNKey(currentTenantID(), "sprout01"); err != nil {
		t.Fatalf("DenyNKey failed: %v", err)
	}
	if _, err := dialAsSprout(t, sproutJWT, sproutSeed); err == nil {
		t.Fatal("expected connection to fail for a denied sprout, but it succeeded")
	}

	// Re-accept (from denied, not unaccepted): AcceptNKey searches all
	// state directories, and clearing the revocation alone is enough to
	// make the *same* previously-minted JWT valid again.
	if err := AcceptNKey(currentTenantID(), "sprout01"); err != nil {
		t.Fatalf("re-AcceptNKey failed: %v", err)
	}
	nc2, err := dialAsSprout(t, sproutJWT, sproutSeed)
	if err != nil {
		t.Fatalf("expected re-accepted sprout to connect again with its original JWT, got: %v", err)
	}
	nc2.Close()
}

func TestJWTLifecycle_RejectAlsoRevokes(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	defer startTestBus(t)()

	sproutKP, _ := nkeys.CreateUser()
	sproutPub, _ := sproutKP.PublicKey()
	sproutSeed, _ := sproutKP.Seed()
	writeKey(t, "unaccepted", "rogue01", sproutPub)

	if err := AcceptNKey(currentTenantID(), "rogue01"); err != nil {
		t.Fatalf("AcceptNKey failed: %v", err)
	}
	sproutJWT, err := GetSproutUserJWT("rogue01")
	if err != nil {
		t.Fatalf("GetSproutUserJWT failed: %v", err)
	}
	if nc, err := dialAsSprout(t, sproutJWT, sproutSeed); err != nil {
		t.Fatalf("expected accepted sprout to connect: %v", err)
	} else {
		nc.Close()
	}

	if err := RejectNKey(currentTenantID(), "rogue01", ""); err != nil {
		t.Fatalf("RejectNKey failed: %v", err)
	}
	if _, err := dialAsSprout(t, sproutJWT, sproutSeed); err == nil {
		t.Fatal("expected connection to fail for a rejected sprout, but it succeeded")
	}
}

// TestReloadNKeys_PushesWithoutLocalNatsServerHandle covers the
// post-bus/core-split topology described in
// docs/design/imas-fork-roadmap.md: once farmer's bus and core processes
// are split, the process where Accept/Deny/API calls happen (and where
// ReloadNKeys runs) will never hold a local *nats_server.Server handle.
// ReloadNKeys must still push the updated tenant Account JWT to the bus
// over the network (pushAccountUpdate/connectSystemAccount), rather than
// silently no-opping because NatsServer is nil.
//
// Against the pre-fix code (which returned early from ReloadNKeys when
// NatsServer == nil) this test fails: the accepted sprout's Account JWT
// update never reaches the bus's resolver, so the bus never learns the
// sprout's key is now valid and the dial below is rejected.
func TestReloadNKeys_PushesWithoutLocalNatsServerHandle(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	defer startTestBusWithoutLocalHandle(t)()

	if NatsServer != nil {
		t.Fatal("test setup invariant violated: NatsServer must be nil to simulate the split topology")
	}

	sproutKP, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("failed to create sprout NKey: %v", err)
	}
	sproutPub, err := sproutKP.PublicKey()
	if err != nil {
		t.Fatalf("failed to get sprout public key: %v", err)
	}
	sproutSeed, err := sproutKP.Seed()
	if err != nil {
		t.Fatalf("failed to get sprout seed: %v", err)
	}
	writeKey(t, "unaccepted", "split-sprout01", sproutPub)

	// Accept: this calls ReloadNKeys via defer with no local NatsServer
	// handle. It must still push the updated tenant Account JWT to the
	// bus's resolver over the network for the sprout to be able to connect.
	if err := AcceptNKey(currentTenantID(), "split-sprout01"); err != nil {
		t.Fatalf("AcceptNKey failed: %v", err)
	}
	sproutJWT, err := GetSproutUserJWT("split-sprout01")
	if err != nil {
		t.Fatalf("GetSproutUserJWT failed after accept: %v", err)
	}

	nc, err := dialAsSprout(t, sproutJWT, sproutSeed)
	if err != nil {
		t.Fatalf("expected accepted sprout to connect once the push reaches the bus, got: %v", err)
	}
	defer nc.Close()
	if !nc.IsConnected() {
		t.Fatal("expected connection to be established")
	}
}

// useRealFarmerKey overrides setupTestPKI's dummy (structurally invalid)
// farmer key with a real NKey, so syncNatsAuth can actually mint the
// farmer's own User JWT during these tests.
func useRealFarmerKey(t *testing.T) {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("failed to create farmer NKey: %v", err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatalf("failed to get farmer public key: %v", err)
	}
	if err := os.WriteFile(config.NKeyFarmerPubFile, []byte(pub), 0o600); err != nil {
		t.Fatalf("failed to write farmer public key: %v", err)
	}
}
