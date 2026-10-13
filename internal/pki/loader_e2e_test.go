package pki

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/accountloader"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
)

// TestEmptyBusNodeLoadsWhatFarmerPublished checks the stateless bus end
// to end (docs/briefs/E-followups.md, Z item 3), with farmer's own code on
// one side and the loader's on the other, where the other tests play one
// of them: cmd/farmerbus's loader scenarios write the bucket as a fake
// farmer, and accountpublisher_test.go checks the objects farmer writes
// without a loader.
//
// Farmer (this package, with the AccountPublisher cmd/farmer installs)
// provisions two tenants, mints a sprout's User JWT in each and runs its
// start-up ReconcileAccounts. Then a bus node starts as cmd/farmerbus
// starts one (LoadBusNats: the trust directory and a resolver holding only
// the SYS Account JWT), and a loader wired as cmd/farmerbus-loader wires
// it reads the bucket with a credential that cannot write. The loader is
// ready only once the node holds every Account farmer wrote, byte for
// byte, and each tenant's sprout is then admitted by that node.
func TestEmptyBusNodeLoadsWhatFarmerPublished(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	accounts := objectstoretest.NewServer(t)
	useReplicaBuckets(t, accounts.Config(), objectstoretest.NewServer(t).Config())
	defer startTestBus(t)()

	type sprout struct {
		tenant, accountPub, jwt string
		seed                    []byte
	}
	var sprouts []sprout
	for _, tenant := range []string{"t_e2e_a", "t_e2e_b"} {
		if err := ProvisionTenant(tenant, tenant+" Co"); err != nil {
			t.Fatalf("ProvisionTenant %s: %v", tenant, err)
		}
		pub, seed := newUserNKey(t)
		if err := acceptEnrolledNKey(tenant, "s1", pub); err != nil {
			t.Fatalf("accepting %s/s1: %v", tenant, err)
		}
		j, err := MintOrReuseUserJWT(t.Context(), tenant, "s1", pub)
		if err != nil {
			t.Fatalf("minting %s/s1: %v", tenant, err)
		}
		sprouts = append(sprouts, sprout{tenant, tenantAccountPub(t, tenant), j, seed})
	}
	if err := ReconcileAccounts(t.Context()); err != nil {
		t.Fatalf("ReconcileAccounts: %v", err)
	}

	// The trust the bootstrap Job writes for the DMZ, with the loader's
	// SYS user (bus-loader-user.jwt) minted for a key only the loader has.
	loaderKP, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	loaderPub, _ := loaderKP.PublicKey()
	loaderSeed, _ := loaderKP.Seed()
	core, err := LoadNATSTrustDir(testTransit.TrustDir)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := BootstrapNATSTrust(t.Context(), testTransit.Store, BootstrapInput{Existing: core.Files(), BusLoaderUserPub: loaderPub})
	if err != nil {
		t.Fatalf("BootstrapNATSTrust: %v", err)
	}
	trustDir := t.TempDir()
	for name, b := range trust.Files() {
		if err := os.WriteFile(filepath.Join(trustDir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	seedFile := filepath.Join(t.TempDir(), "bus-loader-user.nk")
	if err := os.WriteFile(seedFile, loaderSeed, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(NATSTrustDirEnv, trustDir)

	// Every object the loader needs is farmer's: the SYS Account and each
	// tenant's Account, as farmer holds them.
	want := map[string]string{trust.SysAccountPub: ""}
	for _, s := range sprouts {
		want[s.accountPub] = ""
	}
	for pub := range want {
		obj, ok := accounts.Object(accountloader.AccountKey(pub))
		if !ok {
			t.Fatalf("farmer wrote no %s", accountloader.AccountKey(pub))
		}
		h, ok := heldAccountJWT(pub)
		if !ok || h.jwt != obj {
			t.Fatalf("the bucket's %s is not the Account JWT farmer holds", accountloader.AccountKey(pub))
		}
		want[pub] = obj
	}

	// The node starts empty: the trust's SYS Account and nothing else.
	_, resolver := startBusNode(t, t.TempDir())
	for _, s := range sprouts {
		if j, _ := resolver.LoadAcc(s.accountPub); j != "" {
			t.Fatalf("the new node holds tenant %s before its loader ran", s.tenant)
		}
		if nc, err := dialAsSprout(t, s.jwt, s.seed); err == nil {
			nc.Close()
			t.Fatalf("the new node admits a sprout of %s before its loader ran", s.tenant)
		}
	}

	// The loader's credential reads and cannot write (its start-up check).
	accounts.Deny(func(op, _ string) bool { return op == http.MethodPut || op == http.MethodDelete })
	rootPEM, err := os.ReadFile(config.RootCA)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(rootPEM)
	node, err := accountloader.DialNode(accountloader.NATSConfig{
		URL:            "tls://" + config.FarmerBusURL,
		TLS:            &tls.Config{RootCAs: pool, ServerName: config.FarmerInterface, MinVersion: tls.VersionTLS12},
		UserJWTFile:    filepath.Join(trustDir, TrustBusLoaderUserJWT),
		UserSeedFile:   seedFile,
		RequestTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("the loader's SYS user cannot reach its node: %v", err)
	}
	defer node.Close()
	src := accountloader.NewStoreSource(func() (*objectstore.Store, error) { return objectstore.Open(accounts.Config()) })
	if err := src.CheckReadOnly(t.Context(), objectstore.RetryPolicy{MaxAttempts: 2, InitialBackoff: time.Millisecond, MaxBackoff: time.Millisecond}); err != nil {
		t.Fatalf("the loader's credential: %v", err)
	}
	l, err := accountloader.New(accountloader.Config{
		Source:            src,
		Node:              node,
		Trusted:           []string{trust.OperatorPub, trust.OperatorSigningPub},
		SysAccount:        trust.SysAccountPub,
		ReconcileInterval: time.Hour,
		Backoff:           accountloader.Backoff{Min: 20 * time.Millisecond, Max: 200 * time.Millisecond},
		PushBackoff:       accountloader.Backoff{Min: 10 * time.Millisecond, Max: 100 * time.Millisecond},
		RequestTimeout:    5 * time.Second,
		LookupWindow:      200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("accountloader.New: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("loader Run: %v", err)
		}
	}()

	deadline := time.Now().Add(20 * time.Second)
	for !l.Ready() {
		if time.Now().After(deadline) {
			t.Fatalf("the loader never became ready: %+v", l.Status())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st := l.Status(); st.Target != len(want) || st.Applied != len(want) {
		t.Fatalf("loader status target %d applied %d, want %d and %d", st.Target, st.Applied, len(want), len(want))
	}
	for pub, obj := range want {
		if j, err := resolver.LoadAcc(pub); err != nil || j != obj {
			t.Errorf("the node's %s is not the object farmer wrote (err %v)", pub, err)
		}
	}
	for _, s := range sprouts {
		nc, err := dialAsSprout(t, s.jwt, s.seed)
		if err != nil {
			t.Errorf("a sprout of %s is refused by the loaded node: %v", s.tenant, err)
			continue
		}
		nc.Close()
	}
}
