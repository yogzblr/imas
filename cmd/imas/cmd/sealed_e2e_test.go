package cmd

// End to end (J.3, FLAG FOR SECURITY REVIEW): the imas CLI's own commands
// against an embedded farmer and bus. The bus is a nats-server that
// authenticates NKey users over TLS, so the CLI connects with the real
// client.NewNatsClient (its NKey signs the server's nonce, and nothing
// else). Farmer is the real natsapi.Subscribe on its own connection. The
// first admin is bootstrapped from farmer's config (users.admin with a
// boxpub, as Helm's farmer.bootstrapAdmin renders it), never through the
// bus. Tenant keys come from a mock OpenBao, the cluster-wide claim from
// miniredis, the stores from SQLite.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/glebarez/sqlite"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/taigrr/jety"
	"github.com/valkey-io/valkey-go"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/api/client"
	intauth "github.com/yogzblr/imas/internal/auth"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/natsapi"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/pki/tenantboxtest"
	"github.com/yogzblr/imas/internal/rbac"
)

const e2eTenant = "t_e2e"

// e2eIdentity is one CLI user: NKey and CLI box key.
type e2eIdentity struct {
	id      string
	seed    []byte
	keyFile string
	boxPub  string
}

func newE2EIdentity(t *testing.T) *e2eIdentity {
	t.Helper()
	kp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := kp.Seed()
	id, _ := kp.PublicKey()
	u := &e2eIdentity{id: id, seed: seed, keyFile: filepath.Join(t.TempDir(), "cli-box.key")}
	if u.boxPub, err = pki.GenerateCLIBoxKey(u.keyFile, false); err != nil {
		t.Fatal(err)
	}
	return u
}

// e2eBusTLS is a server TLS config for 127.0.0.1 and the CA file the CLI
// pins.
func e2eBusTLS(t *testing.T) (*tls.Config, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "e2e-bus"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "rootca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}, caPath
}

// e2eStores installs fresh SQLite stores for pki (with the users and CLI
// box key tables) and rbac.
func e2eStores(t *testing.T) {
	t.Helper()
	for name, setup := range map[string]struct {
		models []any
		set    func(*gorm.DB)
	}{
		"pki":  {pki.Models(), pki.SetDB},
		"rbac": {rbac.Models(), rbac.SetDB},
	} {
		db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:e2e_%s_%d?mode=memory&cache=shared", name, time.Now().UnixNano())), &gorm.Config{})
		if err != nil {
			t.Fatal(err)
		}
		if err := db.AutoMigrate(setup.models...); err != nil {
			t.Fatal(err)
		}
		setup.set(db)
		set := setup.set
		t.Cleanup(func() { set(nil) })
	}
}

// useCLI makes u this process's CLI user and (re)connects the CLI to the
// bus with the real NewNatsClient.
func useCLI(t *testing.T, u *e2eIdentity, tenantBoxPub string) {
	t.Helper()
	jety.Set("privkey", string(u.seed))
	jety.Set(pki.CLIBoxPrivFileKey, u.keyFile)
	jety.Set(pki.CLITenantBoxPubKey, tenantBoxPub)
	jety.Set(pki.CLITenantIDKey, e2eTenant)
	if client.NatsConn != nil {
		client.NatsConn.Close()
		client.NatsConn = nil
	}
	if err := client.ConnectNats(); err != nil {
		t.Fatalf("CLI connect as %s: %v", u.id, err)
	}
}

func TestSealedCLIEndToEnd(t *testing.T) {
	// Farmer's environment.
	bao := tenantboxtest.Start(t)
	_ = bao
	pki.InvalidateTenantBoxKeys(e2eTenant)
	t.Cleanup(func() { pki.InvalidateTenantBoxKeys(e2eTenant) })
	mr := miniredis.RunT(t)
	vk, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{mr.Addr()}, DisableCache: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(vk.Close)
	pki.SetReplayCacheClient(vk)
	t.Cleanup(func() { pki.SetReplayCacheClient(nil) })
	e2eStores(t)
	origOrg := config.FarmerOrganization
	config.FarmerOrganization = e2eTenant
	t.Cleanup(func() { config.FarmerOrganization = origOrg })
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfgPath, []byte("# e2e\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	jety.SetConfigType("toml")
	jety.SetConfigFile(cfgPath)
	t.Cleanup(func() {
		for _, k := range []string{"privkey", "users", "roles", pki.CLIBoxPrivFileKey, pki.CLITenantBoxPubKey, pki.CLITenantIDKey} {
			jety.Set(k, nil)
		}
		intauth.SetPolicy(nil, nil, nil)
		if client.NatsConn != nil {
			client.NatsConn.Close()
			client.NatsConn = nil
		}
	})

	// The first admin, bootstrapped from farmer's config: their NKey and
	// the CLI box key their own keygen printed. No bus, no token.
	root, bob := newE2EIdentity(t), newE2EIdentity(t)
	jety.Set("users", map[string]any{"admin": []any{map[string]any{
		"pubkey": root.id, "username": "root", intauth.BoxPubConfigField: root.boxPub,
	}}})
	if err := intauth.LoadPolicy(); err != nil {
		t.Fatalf("farmer LoadPolicy: %v", err)
	}
	tenantBoxPub, err := pki.GetTenantX25519PublicKey(e2eTenant)
	if err != nil {
		t.Fatal(err)
	}

	// The bus: NKey users over TLS.
	tlsCfg, caPath := e2eBusTLS(t)
	farmerKP, _ := nkeys.CreateUser()
	farmerPub, _ := farmerKP.PublicKey()
	ns, err := server.NewServer(&server.Options{
		Host: "127.0.0.1", Port: -1, TLSConfig: tlsCfg, TLS: true,
		Nkeys: []*server.NkeyUser{{Nkey: farmerPub}, {Nkey: root.id}, {Nkey: bob.id}},
	})
	if err != nil {
		t.Fatal(err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("bus not ready")
	}
	t.Cleanup(ns.Shutdown)
	busURL := fmt.Sprintf("tls://127.0.0.1:%d", ns.Addr().(*net.TCPAddr).Port)

	// Farmer.
	farmerNC, err := nats.Connect(busURL, nats.Nkey(farmerPub, farmerKP.Sign), nats.RootCAs(caPath))
	if err != nil {
		t.Fatalf("farmer connect: %v", err)
	}
	t.Cleanup(farmerNC.Close)
	if err := natsapi.Subscribe(farmerNC, e2eTenant); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { natsapi.ClearNatsConn(e2eTenant) })
	if err := farmerNC.Flush(); err != nil {
		t.Fatal(err)
	}

	// The CLI.
	origURL, origCA, origName := config.FarmerBusURL, config.ImasRootCA, config.FarmerBusTLSServerName
	config.FarmerBusURL, config.ImasRootCA, config.FarmerBusTLSServerName = busURL, caPath, ""
	t.Cleanup(func() {
		config.FarmerBusURL, config.ImasRootCA, config.FarmerBusTLSServerName = origURL, origCA, origName
	})
	oldMode := outputMode
	outputMode = ""
	t.Cleanup(func() { outputMode = oldMode })

	// imas auth whoami, as the bootstrapped admin.
	useCLI(t, root, tenantBoxPub)
	out := captureStdout(t, func() { authWhoAmICmd.Run(authWhoAmICmd, nil) })
	if !strings.Contains(out, root.id) || !strings.Contains(out, "root") || !strings.Contains(out, "admin") {
		t.Fatalf("root's whoami:\n%s", out)
	}

	// imas users add viewer <bob> --boxpub <bob's key> --username bob
	usersAddBoxPub, usersAddUsername = bob.boxPub, "bob"
	t.Cleanup(func() { usersAddBoxPub, usersAddUsername = "", "" })
	out = captureStdout(t, func() { usersAddCmd.Run(usersAddCmd, []string{"viewer", bob.id}) })
	if !strings.Contains(out, "added with role viewer") {
		t.Fatalf("users add:\n%s", out)
	}
	out = captureStdout(t, func() { usersListCmd.Run(usersListCmd, nil) })
	if !strings.Contains(out, bob.id) || !strings.Contains(out, boxFingerprint(bob.boxPub)) {
		t.Fatalf("users list doesn't show bob's key:\n%s", out)
	}

	// Bob, from his own CLI and his own bus connection.
	useCLI(t, bob, tenantBoxPub)
	out = captureStdout(t, func() { authWhoAmICmd.Run(authWhoAmICmd, nil) })
	if !strings.Contains(out, bob.id) || !strings.Contains(out, "viewer") || !strings.Contains(out, "bob") {
		t.Fatalf("bob's whoami:\n%s", out)
	}
	// A method his role isn't granted: refused inside the sealed reply.
	if _, err := client.AddUser(newE2EIdentity(t).id, "admin", "", newE2EIdentity(t).boxPub); err == nil || err.Error() != rbac.ErrAccessDenied.Error() {
		t.Fatalf("bob adding an admin: %v, want access denied", err)
	}
	// Bob's CLI with the wrong tenant pin: nothing it seals opens on
	// farmer, so nothing runs.
	jety.Set(pki.CLITenantBoxPubKey, root.boxPub)
	if _, err := client.WhoAmI(); err == nil {
		t.Fatal("a reply opened under the wrong tenant pin")
	}
	jety.Set(pki.CLITenantBoxPubKey, tenantBoxPub)

	// Bob rotates his key, then the admin removes him: his next request
	// opens nothing.
	pub, err := rotateCLIBoxKey(client.NatsConn, 5*time.Second)
	if err != nil {
		t.Fatalf("bob's rotate-key: %v", err)
	}
	if active, _, err := intauth.ValidCLIBoxKeys(e2eTenant, bob.id); err != nil || active != pub {
		t.Fatalf("farmer's view of bob's key: %q %v", active, err)
	}
	useCLI(t, root, tenantBoxPub)
	out = captureStdout(t, func() { usersRemoveCmd.Run(usersRemoveCmd, []string{bob.id}) })
	if !strings.Contains(out, "removed") {
		t.Fatalf("users remove:\n%s", out)
	}
	useCLI(t, bob, tenantBoxPub)
	var refused *client.RefusedError
	if _, err := client.WhoAmI(); !errors.As(err, &refused) {
		t.Fatalf("a removed user's request: %v, want a refusal", err)
	}
}
