package natskeys

import (
	"testing"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/pki/natskeys/natskeystest"
)

// TestT1_NatsServerAcceptsTransitSignedJWTs is design test T1 over the
// fake Transit: a whole trust chain signed through KeyStore pairs (the
// operator JWT by nats-operator, SYS and tenant account JWTs by
// nats-operator-signing, a user JWT by the tenant signing key) is
// accepted by an in-process nats-server, and a client connects and
// round-trips a message. TestOpenBaoSignerWithNatsServer runs the same
// chain against a real OpenBao.
func TestT1_NatsServerAcceptsTransitSignedJWTs(t *testing.T) {
	f := natskeystest.New(t)
	s := newStore(t, f, nil)
	checkTrustChainWithNatsServer(t, s, "t1")
}

// checkTrustChainWithNatsServer ensures the platform keys and tenant's
// keys in ks, builds the trust chain from them and proves nats-server
// accepts it (and refuses a user JWT signed by a key the account does
// not list).
func checkTrustChainWithNatsServer(t *testing.T, ks KeyStore, tenant string) {
	t.Helper()
	ctx := t.Context()
	ensure := func(name string, prefix Prefix) (nkeys.KeyPair, string) {
		t.Helper()
		kp, err := ks.EnsureKeyPair(ctx, name, prefix)
		if err != nil {
			t.Fatalf("EnsureKeyPair(%s): %v", name, err)
		}
		pub, _ := kp.PublicKey()
		return kp, pub
	}
	operator, operatorPub := ensure(OperatorKey(), nkeys.PrefixByteOperator)
	operatorSigning, operatorSigningPub := ensure(OperatorSigningKey(), nkeys.PrefixByteOperator)
	_, sysPub := ensure(SysAccountKey(), nkeys.PrefixByteAccount)
	tenantSigning, tenantSigningPub := ensure(TenantSigningKey(tenant), nkeys.PrefixByteAccount)
	_, tenantPub := ensure(TenantAccountKey(tenant), nkeys.PrefixByteAccount)

	oc := jwt.NewOperatorClaims(operatorPub)
	oc.Name = "imas"
	oc.SigningKeys.Add(operatorSigningPub)
	oc.SystemAccount = sysPub
	operatorJWT, err := oc.Encode(operator)
	if err != nil {
		t.Fatalf("operator JWT: %v", err)
	}
	oc, err = jwt.DecodeOperatorClaims(operatorJWT)
	if err != nil {
		t.Fatalf("decoding operator JWT: %v", err)
	}

	resolver := &server.MemAccResolver{}
	sysClaims := jwt.NewAccountClaims(sysPub)
	sysClaims.Name = "SYS"
	sysJWT, err := sysClaims.Encode(operatorSigning)
	if err != nil {
		t.Fatalf("SYS JWT: %v", err)
	}
	tc := jwt.NewAccountClaims(tenantPub)
	tc.Name = tenant
	tc.SigningKeys.Add(tenantSigningPub)
	tenantJWT, err := tc.Encode(operatorSigning)
	if err != nil {
		t.Fatalf("tenant JWT: %v", err)
	}
	for pub, j := range map[string]string{sysPub: sysJWT, tenantPub: tenantJWT} {
		if err := resolver.Store(pub, j); err != nil {
			t.Fatal(err)
		}
	}

	user, _ := nkeys.CreateUser()
	userPub, _ := user.PublicKey()
	userSeed, _ := user.Seed()
	uc := jwt.NewUserClaims(userPub)
	uc.IssuerAccount = tenantPub
	userJWT, err := uc.Encode(tenantSigning)
	if err != nil {
		t.Fatalf("user JWT: %v", err)
	}

	srv, err := server.NewServer(&server.Options{
		Host:             "127.0.0.1",
		Port:             -1,
		NoLog:            true,
		NoSigs:           true,
		TrustedOperators: []*jwt.OperatorClaims{oc},
		SystemAccount:    sysPub,
		AccountResolver:  resolver,
	})
	if err != nil {
		t.Fatalf("nats-server rejects the Transit-signed operator: %v", err)
	}
	go srv.Start()
	t.Cleanup(srv.Shutdown)
	if !srv.ReadyForConnections(10 * time.Second) {
		t.Fatal("nats-server not ready")
	}

	nc, err := nats.Connect(srv.ClientURL(), nats.UserJWTAndSeed(userJWT, string(userSeed)), nats.MaxReconnects(0))
	if err != nil {
		t.Fatalf("connect with the Transit-signed user JWT: %v", err)
	}
	defer nc.Close()
	sub, err := nc.SubscribeSync("t1.check")
	if err != nil {
		t.Fatal(err)
	}
	if err := nc.Publish("t1.check", []byte("ok")); err != nil {
		t.Fatal(err)
	}
	if msg, err := sub.NextMsg(5 * time.Second); err != nil || string(msg.Data) != "ok" {
		t.Fatalf("round trip: %v", err)
	}

	// The server really checks: a user JWT signed by a key the tenant
	// account doesn't list is refused.
	rogue, _ := nkeys.CreateAccount()
	rogueJWT, err := uc.Encode(rogue)
	if err != nil {
		t.Fatal(err)
	}
	if nc, err := nats.Connect(srv.ClientURL(), nats.UserJWTAndSeed(rogueJWT, string(userSeed)), nats.MaxReconnects(0)); err == nil {
		nc.Close()
		t.Fatal("nats-server accepted a user JWT signed by an unlisted key")
	}
}
