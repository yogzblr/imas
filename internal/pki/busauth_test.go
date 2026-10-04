package pki

// The DMZ bus signs no claims of its own beyond an epoch-dated SYS
// bootstrap (busauth.go), and core pushes every Account when its SYS
// connection (re)connects (pushall.go). FLAG FOR SECURITY REVIEW.

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	nats_server "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
)

// shareSeedsWithBus points the bus at core's operator, operator signing
// and SYS account seeds through IMAS_NATS_*_SEED_FILE, as the chart's seed
// Secret does, and returns core's material.
func shareSeedsWithBus(t *testing.T) *natsAuthMaterial {
	t.Helper()
	mat, err := ensureNatsAuth()
	if err != nil {
		t.Fatalf("ensureNatsAuth: %v", err)
	}
	for name, file := range map[string]string{
		"OPERATOR":         "operator.nk",
		"OPERATOR_SIGNING": "operator-signing.nk",
		"SYS_ACCOUNT":      "sys-account.nk",
	} {
		t.Setenv("IMAS_NATS_"+name+"_SEED_FILE", filepath.Join(natsAuthDir(), file))
	}
	return mat
}

// withFarmerPKI runs fn with config.FarmerPKI pointing at dir.
func withFarmerPKI(dir string, fn func()) {
	prev := config.FarmerPKI
	config.FarmerPKI = dir
	defer func() { config.FarmerPKI = prev }()
	fn()
}

// startBusNode starts a bus the way cmd/farmerbus does (ConfigureBusNats)
// on its own FarmerPKI directory, and points config.FarmerBusURL at it.
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

func TestConfigureBusNats_SeedsOnlyTheSYSBootstrap(t *testing.T) {
	setupTestPKI(t)
	mat := shareSeedsWithBus(t)
	busDir := t.TempDir()

	_, dr := startBusNode(t, busDir)

	sys, err := dr.LoadAcc(mat.sysAccountPub)
	if err != nil {
		t.Fatalf("SYS account missing from the bus resolver: %v", err)
	}
	sc, err := jwt.DecodeAccountClaims(sys)
	if err != nil {
		t.Fatal(err)
	}
	signingPub, _ := mat.operatorSigningKP.PublicKey()
	if sc.IssuedAt != busBootstrapIssuedAt || sc.Issuer != signingPub {
		t.Fatalf("SYS bootstrap iat=%d iss=%s, want iat=%d iss=%s", sc.IssuedAt, sc.Issuer, busBootstrapIssuedAt, signingPub)
	}
	if j, _ := dr.LoadAcc(mat.tenantPub); j != "" {
		t.Fatal("the bus seeded a legacy tenant Account JWT it minted itself")
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
}

func TestSignAccountClaimsAt(t *testing.T) {
	kp, _ := nkeys.CreateOperator()
	acctKP, _ := nkeys.CreateAccount()
	pub, _ := acctKP.PublicKey()
	ac := jwt.NewAccountClaims(pub)
	ac.Name = "x"
	tok, err := signAccountClaimsAt(ac, kp, 42)
	if err != nil {
		t.Fatal(err)
	}
	back, err := jwt.DecodeAccountClaims(tok)
	if err != nil {
		t.Fatal(err)
	}
	if back.IssuedAt != 42 || back.Name != "x" {
		t.Fatalf("got iat=%d name=%q", back.IssuedAt, back.Name)
	}
	// The jti covers the iat, so it differs from a "now" signing of the
	// same claims, which is what lets the resolver tell the two apart.
	now, err := jwt.NewAccountClaims(pub).Encode(kp)
	if err != nil {
		t.Fatal(err)
	}
	nowClaims, _ := jwt.DecodeAccountClaims(now)
	if back.ID == "" || back.ID == nowClaims.ID {
		t.Fatalf("jti %q not derived from the chosen iat", back.ID)
	}
	vr := jwt.CreateValidationResults()
	back.Validate(vr)
	if vr.IsBlocking(true) {
		t.Fatalf("claims don't validate: %v", vr.Errors())
	}
}

// An older bus minted the legacy tenant's and the SYS Account JWTs for
// itself and stored them in its resolver. They must not survive an
// upgrade; a JWT core pushed (different from the self-minted file) must.
func TestConfigureBusNats_DropsSelfMintedCopiesFromOlderVersions(t *testing.T) {
	setupTestPKI(t)
	mat := shareSeedsWithBus(t)
	busDir := t.TempDir()
	authDir := filepath.Join(busDir, natsAuthSubdir)
	resolverDir := filepath.Join(authDir, "resolver")
	if err := os.MkdirAll(resolverDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sign := func(pub, name string) string {
		ac := jwt.NewAccountClaims(pub)
		ac.Name = name
		s, err := ac.Encode(mat.operatorSigningKP)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	write := func(path, content string) {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	selfTenant := sign(mat.tenantPub, "self-minted")
	write(filepath.Join(authDir, "tenant.jwt"), selfTenant)
	write(filepath.Join(resolverDir, mat.tenantPub+".jwt"), selfTenant)
	// SYS: the old file is self-minted, but core pushed a different one since.
	write(filepath.Join(authDir, "sys-account.jwt"), sign(mat.sysAccountPub, "SYS (bus-minted)"))
	write(filepath.Join(resolverDir, mat.sysAccountPub+".jwt"), mat.sysAccountJWT)

	_, dr := startBusNode(t, busDir)

	if j, _ := dr.LoadAcc(mat.tenantPub); j != "" {
		t.Fatal("the self-minted legacy tenant JWT survived the upgrade")
	}
	if j, _ := dr.LoadAcc(mat.sysAccountPub); j != mat.sysAccountJWT {
		t.Fatal("the SYS Account JWT core pushed was replaced")
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
	mat := shareSeedsWithBus(t)
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
	liveJWT, err := GetSproutUserJWTForTenant("t_live", "web-01")
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
	sc, err := jwt.DecodeAccountClaims(lookupOnBus(t, mat.sysAccountPub))
	if err != nil || sc.IssuedAt <= busBootstrapIssuedAt {
		t.Fatalf("the bus still holds its SYS bootstrap, not core's SYS Account JWT (%v)", err)
	}
}
