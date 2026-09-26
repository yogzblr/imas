package facts

// Two-tenant coverage for storeFacts'/storeHardwareFacts' *ForTenant
// threading (see listener.go's own doc comment on why this matters): it
// provisions two tenants on a real PKI + NATS bus, enrolls a real sprout
// under each, registers RegisterFarmerListener on a distinct per-tenant
// connection for each (mirroring cmd/farmer/main.go calling it once per
// tenant connection), and publishes a facts event from each tenant's own
// sprout. It asserts props.GetPropsForTenant(tenantX, sproutX) returns
// only that tenant's own facts, proving the leak this PR fixes (every
// tenant's facts landing under the legacy tenant regardless of which
// connection they arrived on) is closed.
//
// This mirrors internal/pki/tenant_multitenant_isolation_test.go's own
// pattern for provisioning tenants and enrolling/dialing a real sprout,
// rebuilt here against pki's exported surface only — that test file's own
// scaffolding (setupTestPKI, dialAsSprout, startTestBus, and friends) is
// unexported and lives in package pki, unreachable from here.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	nats_server "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/props"
)

// setupTenantIsolationPKI wires up an in-memory pki store plus the TLS/NKey
// scaffolding a real NATS bus and tenant Account provisioning need, using
// only pki's exported surface (SetDB/Models) — see
// internal/pki/pki_test.go's own setupTestPKI, which this mirrors but
// cannot call directly since it lives in a different package.
func setupTenantIsolationPKI(t *testing.T) {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())
	gdb, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("opening pki test db: %v", err)
	}
	if err := gdb.AutoMigrate(pki.Models()...); err != nil {
		t.Fatalf("migrating pki test db: %v", err)
	}
	pki.SetDB(gdb)
	t.Cleanup(func() { pki.SetDB(nil) })

	oldOrg := config.FarmerOrganization
	t.Cleanup(func() { config.FarmerOrganization = oldOrg })

	tmpDir := t.TempDir()
	config.FarmerPKI = filepath.Join(tmpDir, "pki") + "/"
	config.NKeyFarmerPubFile = filepath.Join(tmpDir, "farmer.pub")
	config.FarmerInterface = "127.0.0.1"
	config.FarmerBusPort = "0"
	config.FarmerOrganization = "imas-facts-test"
	config.CertificateValidTime = 24 * 365 * time.Hour
	config.RootCA = filepath.Join(tmpDir, "rootca.pem")
	config.RootCAPriv = filepath.Join(tmpDir, "rootca-key.pem")
	config.CertFile = filepath.Join(tmpDir, "cert.pem")
	config.KeyFile = filepath.Join(tmpDir, "key.pem")
	config.CertHosts = []string{"127.0.0.1"}

	generateFactsTestCerts(t, tmpDir)
}

// generateFactsTestCerts creates a self-signed CA and leaf certificate for
// pki.ConfigureNats to load — see internal/pki/pki_test.go's
// generateTestCerts, which this mirrors.
func generateFactsTestCerts(t *testing.T, tmpDir string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"imas-facts-test"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	writeFactsPEM(t, filepath.Join(tmpDir, "rootca.pem"), "CERTIFICATE", caDER)

	caPrivBytes, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		t.Fatalf("marshal CA key: %v", err)
	}
	writeFactsPEM(t, filepath.Join(tmpDir, "rootca-key.pem"), "PRIVATE KEY", caPrivBytes)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"imas-facts-test"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, &caTemplate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	writeFactsPEM(t, filepath.Join(tmpDir, "cert.pem"), "CERTIFICATE", leafDER)

	leafPrivBytes, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	writeFactsPEM(t, filepath.Join(tmpDir, "key.pem"), "PRIVATE KEY", leafPrivBytes)
}

func writeFactsPEM(t *testing.T, path, blockType string, data []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: data}); err != nil {
		t.Fatalf("encode PEM to %s: %v", path, err)
	}
}

type factsTestNoopLogger struct{}

func (factsTestNoopLogger) Noticef(string, ...any) {}
func (factsTestNoopLogger) Warnf(string, ...any)   {}
func (factsTestNoopLogger) Fatalf(string, ...any)  {}
func (factsTestNoopLogger) Errorf(string, ...any)  {}
func (factsTestNoopLogger) Debugf(string, ...any)  {}
func (factsTestNoopLogger) Tracef(string, ...any)  {}

// startTenantIsolationBus starts an embedded, TLS-enabled NATS server via
// pki.ConfigureNats/pki.SetNATSServer — the same setup
// cmd/farmer/main.go's RunNATSServer performs — and points config at it so
// pki.ProvisionTenant/pki.AcceptNKey's resolver pushes reach a live bus.
func startTenantIsolationBus(t *testing.T) func() {
	t.Helper()
	opts := pki.ConfigureNats()
	srv, err := nats_server.NewServer(&opts)
	if err != nil || srv == nil {
		t.Fatalf("failed to create NATS server: %v", err)
	}
	srv.SetLogger(factsTestNoopLogger{}, false, false)
	go srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		t.Fatal("NATS server did not become ready")
	}

	addr, ok := srv.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected listener address type: %T", srv.Addr())
	}
	config.FarmerBusURL = fmt.Sprintf("%s:%d", config.FarmerInterface, addr.Port)

	pki.SetNATSServer(srv)
	t.Cleanup(func() {
		pki.SetNATSServer(nil)
		srv.Shutdown()
	})
	return srv.Shutdown
}

// dialTenantIsolationConn connects to the test bus authenticated with the
// given User JWT + NKey seed — see internal/pki/jwt_integration_test.go's
// dialAsSprout, which this mirrors.
func dialTenantIsolationConn(t *testing.T, userJWT string, seed []byte) *nats.Conn {
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
	nc, err := nats.Connect(config.FarmerBusURL,
		nats.Secure(tlsCfg),
		nats.UserJWTAndSeed(userJWT, string(seed)),
		nats.Timeout(5*time.Second),
		nats.RetryOnFailedConnect(false),
	)
	if err != nil {
		t.Fatalf("connecting to test bus: %v", err)
	}
	return nc
}

// enrollTenantIsolationSprout provisions and accepts a fresh NKey identity
// as sproutID under tenantID, then returns its User JWT + seed for dialing.
func enrollTenantIsolationSprout(t *testing.T, tenantID, sproutID string) (jwt string, seed []byte) {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("creating sprout NKey: %v", err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatalf("sprout public key: %v", err)
	}
	seed, err = kp.Seed()
	if err != nil {
		t.Fatalf("sprout seed: %v", err)
	}
	if err := pki.UnacceptNKey(tenantID, sproutID, pub); err != nil {
		t.Fatalf("UnacceptNKey(%s, %s): %v", tenantID, sproutID, err)
	}
	if err := pki.AcceptNKey(tenantID, sproutID); err != nil {
		t.Fatalf("AcceptNKey(%s, %s): %v", tenantID, sproutID, err)
	}
	jwt, err = pki.GetSproutUserJWTForTenant(tenantID, sproutID)
	if err != nil {
		t.Fatalf("GetSproutUserJWTForTenant(%s, %s): %v", tenantID, sproutID, err)
	}
	return jwt, seed
}

// TestStoreFacts_TwoTenantsIsolated is the "actual gap" test for this PR:
// before it, storeFacts wrote every tenant's facts under the bare,
// legacy-tenant-scoped props.SetProp regardless of which tenant connection
// RegisterFarmerListener received them on — inert while farmer had a
// single shared connection, but a live cross-tenant leak once each tenant
// got its own (docs/design/imas-tenant-context-threading.md's Option A,
// landed in a prior PR). It provisions two tenants, opens a real farmer
// connection into each Account, registers RegisterFarmerListener on each
// exactly as cmd/farmer/main.go does per tenant connection, enrolls a real
// sprout under each tenant, and publishes a facts event from each sprout.
// props.GetPropsForTenant must return each tenant's own facts and never
// the other's, and the legacy tenant's own view must stay empty.
func TestStoreFacts_TwoTenantsIsolated(t *testing.T) {
	setupTenantIsolationPKI(t)
	defer startTenantIsolationBus(t)()

	const tenantA = "t_facts_a"
	const tenantB = "t_facts_b"
	const sproutA = "facts-sprout-a"
	const sproutB = "facts-sprout-b"

	// Farmer's NKey identity must exist before ProvisionTenant, which mints
	// farmer's own User JWT under the new tenant Account as part of
	// provisioning (see ProvisionTenant's own doc comment).
	farmerKP, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("creating farmer NKey: %v", err)
	}
	farmerPub, err := farmerKP.PublicKey()
	if err != nil {
		t.Fatalf("farmer public key: %v", err)
	}
	farmerSeed, err := farmerKP.Seed()
	if err != nil {
		t.Fatalf("farmer seed: %v", err)
	}
	if err := os.WriteFile(config.NKeyFarmerPubFile, []byte(farmerPub), 0o600); err != nil {
		t.Fatalf("writing farmer public key: %v", err)
	}

	if err := pki.ProvisionTenant(tenantA, "Facts Tenant A"); err != nil {
		t.Fatalf("ProvisionTenant(%s): %v", tenantA, err)
	}
	if err := pki.ProvisionTenant(tenantB, "Facts Tenant B"); err != nil {
		t.Fatalf("ProvisionTenant(%s): %v", tenantB, err)
	}

	farmerJWTA, err := pki.FarmerUserJWTForTenant(tenantA)
	if err != nil {
		t.Fatalf("FarmerUserJWTForTenant(%s): %v", tenantA, err)
	}
	farmerJWTB, err := pki.FarmerUserJWTForTenant(tenantB)
	if err != nil {
		t.Fatalf("FarmerUserJWTForTenant(%s): %v", tenantB, err)
	}

	// Farmer's own dedicated per-tenant connections — the same shape
	// cmd/farmer/main.go's dialTenantBus produces.
	ncFarmerA := dialTenantIsolationConn(t, farmerJWTA, farmerSeed)
	defer ncFarmerA.Close()
	ncFarmerB := dialTenantIsolationConn(t, farmerJWTB, farmerSeed)
	defer ncFarmerB.Close()

	// Register the facts listener once per tenant connection, exactly as
	// cmd/farmer/main.go does.
	RegisterFarmerListener(tenantA, ncFarmerA)
	RegisterFarmerListener(tenantB, ncFarmerB)
	ncFarmerA.Flush()
	ncFarmerB.Flush()

	sproutJWTA, sproutSeedA := enrollTenantIsolationSprout(t, tenantA, sproutA)
	sproutJWTB, sproutSeedB := enrollTenantIsolationSprout(t, tenantB, sproutB)

	ncSproutA := dialTenantIsolationConn(t, sproutJWTA, sproutSeedA)
	defer ncSproutA.Close()
	ncSproutB := dialTenantIsolationConn(t, sproutJWTB, sproutSeedB)
	defer ncSproutB.Close()

	sfA := SystemFacts{OS: "linux", Arch: "amd64", Hostname: "host-a", SproutID: sproutA}
	dataA, err := json.Marshal(sfA)
	if err != nil {
		t.Fatalf("marshal tenant A facts: %v", err)
	}
	if err := ncSproutA.Publish("imas.sprouts."+sproutA+".facts", dataA); err != nil {
		t.Fatalf("publishing tenant A facts: %v", err)
	}
	ncSproutA.Flush()

	sfB := SystemFacts{OS: "darwin", Arch: "arm64", Hostname: "host-b", SproutID: sproutB}
	dataB, err := json.Marshal(sfB)
	if err != nil {
		t.Fatalf("marshal tenant B facts: %v", err)
	}
	if err := ncSproutB.Publish("imas.sprouts."+sproutB+".facts", dataB); err != nil {
		t.Fatalf("publishing tenant B facts: %v", err)
	}
	ncSproutB.Flush()

	// Give both listeners time to process — there's no ack for a fan-in
	// facts publish.
	time.Sleep(300 * time.Millisecond)

	propsA := props.GetPropsForTenant(tenantA, sproutA)
	if propsA["os"] != "linux" || propsA["hostname"] != "host-a" {
		t.Errorf("tenant A's own props = %v, want os=linux hostname=host-a", propsA)
	}
	propsB := props.GetPropsForTenant(tenantB, sproutB)
	if propsB["os"] != "darwin" || propsB["hostname"] != "host-b" {
		t.Errorf("tenant B's own props = %v, want os=darwin hostname=host-b", propsB)
	}

	// The actual leak this PR closes: tenant A must never see tenant B's
	// sprout's facts under its own tenant scope, and vice versa.
	if got := props.GetPropsForTenant(tenantA, sproutB); got != nil {
		t.Errorf("tenant A saw tenant B's sprout facts: %v", got)
	}
	if got := props.GetPropsForTenant(tenantB, sproutA); got != nil {
		t.Errorf("tenant B saw tenant A's sprout facts: %v", got)
	}

	// And the legacy tenant's own view (what storeFacts used to write
	// under, unconditionally) must stay empty — neither tenant's facts
	// leaked into it.
	if got := props.GetProps(sproutA); got != nil {
		t.Errorf("legacy tenant saw tenant A's sprout facts: %v", got)
	}
	if got := props.GetProps(sproutB); got != nil {
		t.Errorf("legacy tenant saw tenant B's sprout facts: %v", got)
	}
}
