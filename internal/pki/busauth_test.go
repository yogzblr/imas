package pki

// The DMZ bus reads only the public trust directory and signs nothing
// (busauth.go), and core pushes every Account when its SYS connection
// (re)connects (pushall.go). FLAG FOR SECURITY REVIEW.

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nats_server "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/pki/natskeys"
	"github.com/yogzblr/imas/internal/pki/natskeys/natskeystest"
)

// withFarmerPKI runs fn with config.FarmerPKI pointing at dir.
func withFarmerPKI(dir string, fn func()) {
	prev := config.FarmerPKI
	config.FarmerPKI = dir
	defer func() { config.FarmerPKI = prev }()
	fn()
}

// startBusNode starts a bus the way cmd/farmerbus does (ConfigureBusNats)
// on its own FarmerPKI directory, and points config.FarmerBusURL at it.
// The bus reads the trust directory pkitest.Farmer wrote for core.
func startBusNode(t *testing.T, busDir string) (*nats_server.Server, *nats_server.DirAccResolver) {
	t.Helper()
	var opts nats_server.Options
	withFarmerPKI(busDir, func() {
		config.FarmerBusPort = "-1"
		opts, _ = ConfigureBusNats()
	})
	opts.LogFile, opts.NoLog = "", true
	srv, err := nats_server.NewServer(&opts)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	var noop testNoopLogger
	srv.SetLogger(noop, false, false)
	go srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		t.Fatal("bus did not start")
	}
	t.Cleanup(srv.Shutdown)
	config.FarmerBusURL = fmt.Sprintf("%s:%d", config.FarmerInterface, srv.Addr().(*net.TCPAddr).Port)
	return srv, opts.AccountResolver.(*nats_server.DirAccResolver)
}

// T5: the bus configures itself from the trust directory alone. It makes
// no Transit request (the fake sees none, and the bus is given no
// IMAS_NATSSIGN_* address), seeds the resolver with exactly the trust's
// SYS Account JWT and no tenant, and writes nothing but the resolver.
func TestConfigureBusNatsFromTrustOnly(t *testing.T) {
	setupTestPKI(t)
	mat, err := ensureNatsAuth()
	if err != nil {
		t.Fatalf("ensureNatsAuth: %v", err)
	}
	trust, err := LoadNATSTrustDir(testTransit.TrustDir)
	if err != nil {
		t.Fatal(err)
	}
	testTransit.Fake.ResetCounts()
	t.Setenv(natskeys.EnvPrefixSign+natskeys.EnvOpenBaoAddr, "")
	busDir := t.TempDir()

	srv, dr := startBusNode(t, busDir)

	for _, op := range []natskeystest.Op{natskeystest.OpSign, natskeystest.OpReadKey, natskeystest.OpCreateKey} {
		if n := testTransit.Fake.Count(op); n != 0 {
			t.Errorf("the bus made %d Transit %s requests", n, op)
		}
	}
	if got := srv.SystemAccount().Name; got != trust.SysAccountPub {
		t.Errorf("system account %s, want the trust's %s", got, trust.SysAccountPub)
	}
	sys, err := dr.LoadAcc(trust.SysAccountPub)
	if err != nil {
		t.Fatalf("SYS account missing from the bus resolver: %v", err)
	}
	if sys != trust.SysAccountJWT {
		t.Fatal("the bus resolver holds a SYS Account JWT other than the trust's")
	}
	if j, _ := dr.LoadAcc(mat.tenantPub); j != "" {
		t.Fatal("the bus seeded a legacy tenant Account JWT")
	}
	entries, err := os.ReadDir(filepath.Join(busDir, natsAuthSubdir))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "resolver" {
			t.Errorf("the bus wrote %s to its nats-auth directory", e.Name())
		}
	}
	rs, err := os.ReadDir(filepath.Join(busDir, natsAuthSubdir, "resolver"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range rs {
		if e.Name() != trust.SysAccountPub+".jwt" {
			t.Errorf("the bus resolver holds %s", e.Name())
		}
	}
}

// A bus without its trust directory, or with an incomplete one, does not
// start.
func TestLoadBusNatsRequiresTrust(t *testing.T) {
	setupTestPKI(t)
	empty := t.TempDir()
	t.Setenv(NATSTrustDirEnv, empty)
	withFarmerPKI(t.TempDir(), func() {
		if _, _, err := LoadBusNats(); !errors.Is(err, ErrTrustIncomplete) {
			t.Fatalf("empty trust dir: err = %v, want ErrTrustIncomplete", err)
		}
	})
	partial := copyTrustDir(t, testTransit.TrustDir)
	if err := os.Remove(filepath.Join(partial, TrustSysAccountJWT)); err != nil {
		t.Fatal(err)
	}
	t.Setenv(NATSTrustDirEnv, partial)
	withFarmerPKI(t.TempDir(), func() {
		if _, _, err := LoadBusNats(); !errors.Is(err, ErrTrustIncomplete) {
			t.Fatalf("trust without %s: err = %v, want ErrTrustIncomplete", TrustSysAccountJWT, err)
		}
	})
}

// copyTrustDir copies the trust files of src into a new directory.
func copyTrustDir(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

// trustWithFenceUser writes a copy of core's trust directory with a
// bus-fence-user.jwt for a new user key, as the bootstrap Job mints it
// (BootstrapNATSTrust with BusFenceUserPub), and returns the directory
// and the user's seed.
func trustWithFenceUser(t *testing.T) (dir string, seed []byte) {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := kp.PublicKey()
	seed, _ = kp.Seed()
	existing, err := LoadNATSTrustDir(testTransit.TrustDir)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := BootstrapNATSTrust(t.Context(), testTransit.Store, BootstrapInput{Existing: existing.Files(), BusFenceUserPub: pub})
	if err != nil {
		t.Fatalf("BootstrapNATSTrust: %v", err)
	}
	dir = t.TempDir()
	for name, b := range tr.Files() {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir, seed
}

func writeSeedFile(t *testing.T, seed []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "bus-fence-user.nk")
	if err := os.WriteFile(p, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// T5: the fence user is its seed from IMAS_NATS_BUS_FENCE_USER_SEED_FILE
// paired with bus-fence-user.jwt from the trust; it connects to the bus
// as a SYS user. Half a configuration or a mismatched pair is refused.
func TestBusFenceUserFromSeedAndTrust(t *testing.T) {
	setupTestPKI(t)
	if _, err := ensureNatsAuth(); err != nil {
		t.Fatal(err)
	}
	coreTrust := testTransit.TrustDir
	fenceTrust, seed := trustWithFenceUser(t)
	other, _ := nkeys.CreateUser()
	otherSeed, _ := other.Seed()
	acct, _ := nkeys.CreateAccount()
	acctSeed, _ := acct.Seed()

	load := func(trustDir, seedFile string) (BusSysUser, error) {
		t.Setenv(NATSTrustDirEnv, trustDir)
		t.Setenv(externalSeedEnvPrefix+busFenceUserSeedName+"_SEED_FILE", seedFile)
		var u BusSysUser
		var err error
		withFarmerPKI(t.TempDir(), func() { _, u, err = LoadBusNats() })
		return u, err
	}

	if u, err := load(coreTrust, ""); err != nil || u.Configured() {
		t.Fatalf("no seed, no JWT: user %+v, err %v; want none, no error", u, err)
	}
	for _, tc := range []struct {
		name, trust, seedFile string
	}{
		{"JWT without seed", fenceTrust, ""},
		{"seed without JWT", coreTrust, writeSeedFile(t, seed)},
		{"seed of another user", fenceTrust, writeSeedFile(t, otherSeed)},
		{"account seed", fenceTrust, writeSeedFile(t, acctSeed)},
		{"unreadable seed file", fenceTrust, filepath.Join(t.TempDir(), "missing.nk")},
	} {
		if _, err := load(tc.trust, tc.seedFile); !errors.Is(err, ErrBusFenceUser) {
			t.Errorf("%s: err = %v, want ErrBusFenceUser", tc.name, err)
		}
	}

	u, err := load(fenceTrust, writeSeedFile(t, seed))
	if err != nil {
		t.Fatalf("LoadBusNats: %v", err)
	}
	if !u.Configured() || u.Seed != strings.TrimSpace(string(seed)) {
		t.Fatal("the fence user does not carry the BUS_FENCE_USER seed")
	}
	want, _ := os.ReadFile(filepath.Join(fenceTrust, TrustBusFenceUserJWT))
	if u.JWT != string(want) {
		t.Fatal("the fence user JWT is not the trust's bus-fence-user.jwt")
	}

	// And the pair is a working SYS user on a bus started from that trust.
	startBusNode(t, t.TempDir())
	nc, err := connectSystemAccount(&natsAuthMaterial{sysUserJWT: u.JWT, sysUserSeed: []byte(u.Seed)})
	if err != nil {
		t.Fatalf("fence user refused by the bus: %v", err)
	}
	defer nc.Close()
	tr, err := LoadNATSTrustDir(fenceTrust)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := nc.Request(fmt.Sprintf(claimsLookupSubject, tr.SysAccountPub), nil, 5*time.Second)
	if err != nil || string(resp.Data) != tr.SysAccountJWT {
		t.Fatalf("fence user cannot look up the SYS account: %v", err)
	}
}

// lookupOnBus asks the bus resolver for an Account JWT ("" if none).
func lookupOnBus(t *testing.T, accountPub string) string {
	t.Helper()
	nc, err := ConnectSystemAccount()
	if err != nil {
		t.Fatalf("ConnectSystemAccount: %v", err)
	}
	defer nc.Close()
	resp, err := nc.Request(fmt.Sprintf(claimsLookupSubject, accountPub), nil, 5*time.Second)
	if err != nil {
		t.Fatalf("claims lookup: %v", err)
	}
	return string(resp.Data)
}

// A bus that starts with nothing (a lost volume, a new cluster) learns
// every Account, revocations and lock-outs included, from PushAllAccounts.
func TestPushAllAccounts_FreshBusLearnsEveryAccount(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	mat, err := ensureNatsAuth()
	if err != nil {
		t.Fatalf("ensureNatsAuth: %v", err)
	}
	config.FarmerBusURL = "127.0.0.1:1" // no bus yet: every push below fails

	mkSprout := func(tenantID, sproutID, state string) (pub string, seed []byte) {
		kp, _ := nkeys.CreateUser()
		pub, _ = kp.PublicKey()
		seed, _ = kp.Seed()
		if err := upsertNKeyRow(nkeyRow{TenantID: tenantID, SproutID: sproutID, NKey: pub, State: state}); err != nil {
			t.Fatal(err)
		}
		return pub, seed
	}
	legacy := currentTenantID()
	_, okSeed := mkSprout(legacy, "web-ok", stateAccepted)
	_, deniedSeed := mkSprout(legacy, "web-denied", stateAccepted)
	_ = ReloadNKeys() // mints the User JWTs; the push fails (no bus)
	okJWT, err := GetSproutUserJWT("web-ok")
	if err != nil {
		t.Fatal(err)
	}
	deniedJWT, err := GetSproutUserJWT("web-denied")
	if err != nil {
		t.Fatal(err)
	}
	if err := setStateInTenant(legacy, "web-denied", stateDenied); err != nil {
		t.Fatal(err)
	}
	_ = ReloadNKeys() // revokes web-denied in the legacy Account

	_ = ProvisionTenant("t_live", "Live Co")
	_, liveSeed := mkSprout("t_live", "web-01", stateAccepted)
	_ = ReloadNKeysForTenant("t_live")
	liveJWT, err := sproutUserJWTForTest("t_live", "web-01")
	if err != nil {
		t.Fatal(err)
	}
	_ = ProvisionTenant("t_gone", "Gone Co")
	_ = DeprovisionTenant("t_gone")  // marks the row deleted; the push fails
	_ = DeprovisionTenant("t_never") // a tombstone: nothing to push

	startBusNode(t, t.TempDir())
	if nc, err := dialAsSprout(t, okJWT, okSeed); err == nil {
		nc.Close()
		t.Fatal("a fresh bus admitted the legacy tenant before core pushed it (self-minted claims?)")
	}

	n, err := PushAllAccounts()
	if err != nil {
		t.Fatalf("PushAllAccounts: %v", err)
	}
	if n != 4 { // SYS, legacy, t_live, t_gone
		t.Errorf("pushed %d Account JWTs, want 4", n)
	}
	if nc, err := dialAsSprout(t, okJWT, okSeed); err != nil {
		t.Fatalf("accepted legacy sprout refused after PushAllAccounts: %v", err)
	} else {
		nc.Close()
	}
	if nc, err := dialAsSprout(t, deniedJWT, deniedSeed); err == nil {
		nc.Close()
		t.Fatal("denied legacy sprout admitted: the revocation didn't reach the bus")
	}
	if nc, err := dialAsSprout(t, liveJWT, liveSeed); err != nil {
		t.Fatalf("provisioned tenant's sprout refused: %v", err)
	} else {
		nc.Close()
	}
	if ac := busAccountClaims(t, "t_gone"); !isLockedOut(ac) {
		t.Fatal("the bus doesn't hold a lock-out for the deprovisioned tenant")
	}
	if got := lookupOnBus(t, mat.sysAccountPub); got != mat.sysAccountJWT {
		t.Fatal("the bus does not hold core's SYS Account JWT")
	}
}

// config.BusMaxConnections reaches the bus's MaxConn when positive; zero
// keeps nats-server's default and a negative value never gets through
// (nats-server would refuse every client).
func TestConfigureBusNats_MaxConnections(t *testing.T) {
	setupTestPKI(t)
	prev := config.BusMaxConnections
	t.Cleanup(func() { config.BusMaxConnections = prev })
	for _, tc := range []struct{ set, want int }{{0, 0}, {150000, 150000}, {-1, 0}} {
		config.BusMaxConnections = tc.set
		var opts nats_server.Options
		withFarmerPKI(t.TempDir(), func() { opts, _ = ConfigureBusNats() })
		if opts.MaxConn != tc.want {
			t.Errorf("BusMaxConnections %d: MaxConn = %d, want %d", tc.set, opts.MaxConn, tc.want)
		}
	}

	// And the running bus enforces it.
	config.BusMaxConnections = 1
	mat, err := ensureNatsAuth()
	if err != nil {
		t.Fatal(err)
	}
	startBusNode(t, t.TempDir())
	first, err := connectSystemAccount(mat)
	if err != nil {
		t.Fatalf("first connection: %v", err)
	}
	defer first.Close()
	// nats-server sends a plaintext -ERR 'maximum connections exceeded'
	// and closes; on this TLS-only listener the client is mid-upgrade by
	// then and reports a TLS error (the -ERR read as a TLS record, or
	// the close), not the -ERR itself.
	if second, err := connectSystemAccount(mat); err == nil {
		second.Close()
		t.Fatal("a second connection was accepted with busmaxconnections 1")
	}
	// The refusal was the limit: once the first leaves, a client gets in.
	first.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		third, err := connectSystemAccount(mat)
		if err == nil {
			third.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no connection accepted after the first closed: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
