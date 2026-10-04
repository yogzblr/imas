package pki

// Live-bus proof of sealed shell's subject grants (J.5): a sprout's NATS
// User JWT receives farmer's f2s frames on its own
// imas.sprouts.<id>.shell.<session>.f2s and publishes its s2f frames on
// imas.shell.sprout.<id>.<session>.s2f, which farmer receives. It can't
// publish another sprout's s2f frames, can't read or write the CLI's leg
// (imas.shell.cli.>), and doesn't receive its own frames back. Before the
// grant a per-sprout JWT was refused both ways and shell couldn't work.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
)

const testShellSession = "0123456789abcdef0123456789abcdef"

func TestSproutJWT_ShellSubjects(t *testing.T) {
	setupTestPKI(t)
	farmerKP, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	farmerPub, _ := farmerKP.PublicKey()
	farmerSeed, _ := farmerKP.Seed()
	if err := os.WriteFile(config.NKeyFarmerPubFile, []byte(farmerPub), 0o600); err != nil {
		t.Fatal(err)
	}
	defer startTestBus(t)()

	jwt1, seed1 := acceptTestSprout(t, "sprout01")
	acceptTestSprout(t, "sprout02")

	farmerJWT, err := os.ReadFile(farmerUserJWTPath())
	if err != nil {
		t.Fatal(err)
	}
	farmer, err := dialAsSprout(t, string(farmerJWT), farmerSeed)
	if err != nil {
		t.Fatalf("farmer connect: %v", err)
	}
	defer farmer.Close()
	s2f, err := farmer.SubscribeSync("imas.shell.sprout.*.*.s2f")
	if err != nil {
		t.Fatal(err)
	}
	if err := farmer.Flush(); err != nil {
		t.Fatal(err)
	}

	var perrs permissionErrors
	nc, err := dialAsSprout(t, jwt1, seed1, nats.ErrorHandler(perrs.handler))
	if err != nil {
		t.Fatalf("sprout01 connect: %v", err)
	}
	defer nc.Close()

	// f2s: farmer -> sprout01, inside its Sub grant.
	f2sSubject := "imas.sprouts.sprout01.shell." + testShellSession + ".f2s"
	f2s, err := nc.SubscribeSync(f2sSubject)
	if err != nil {
		t.Fatal(err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := farmer.Publish(f2sSubject, []byte("frame")); err != nil {
		t.Fatal(err)
	}
	if _, err := f2s.NextMsg(2 * time.Second); err != nil {
		t.Fatalf("sprout01 didn't receive its f2s frame: %v (permission errors: %v)", err, perrs.any())
	}

	// s2f: sprout01 -> farmer, the new publish grant.
	own := "imas.shell.sprout.sprout01." + testShellSession + ".s2f"
	if err := nc.Publish(own, []byte("frame")); err != nil {
		t.Fatal(err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	if msg, err := s2f.NextMsg(2 * time.Second); err != nil || msg.Subject != own {
		t.Fatalf("farmer didn't receive sprout01's s2f frame: %v %v (permission errors: %v)", msg, err, perrs.any())
	}
	if errs := perrs.any(); len(errs) != 0 {
		t.Fatalf("permission errors on sprout01's own shell subjects: %v", errs)
	}

	for _, subj := range []string{
		"imas.shell.sprout.sprout02." + testShellSession + ".s2f",
		"imas.shell.cli." + testShellSession + ".f2c",
		"imas.shell.cli." + testShellSession + ".c2f",
		"imas.sprouts.sprout02.shell." + testShellSession + ".f2s",
	} {
		_ = nc.Publish(subj, []byte("nope"))
		_ = nc.Flush()
		if !perrs.waitForOp("Publish", subj) {
			t.Errorf("expected a Permissions Violation publishing to %s; got %v", subj, perrs.any())
		}
	}
	if msg, err := s2f.NextMsg(200 * time.Millisecond); err == nil {
		t.Fatalf("sprout01's publish to %s was delivered", msg.Subject)
	}
	for _, subj := range []string{"imas.shell.cli.>", "imas.shell.sprout.sprout01.>", "imas.sprouts.sprout02.shell.>"} {
		if _, err := nc.SubscribeSync(subj); err != nil {
			t.Fatal(err)
		}
		_ = nc.Flush()
		if !perrs.waitForOp("Subscription", subj) {
			t.Errorf("expected a Permissions Violation subscribing to %s; got %v", subj, perrs.any())
		}
	}
}

// A User JWT minted before the shell grant gets it on the next sync.
func TestMintOrReuseUserJWT_AddsShellGrant(t *testing.T) {
	setupTestPKI(t)
	mat, err := ensureNatsAuth()
	if err != nil {
		t.Fatal(err)
	}
	ukp, _ := nkeys.CreateUser()
	upub, _ := ukp.PublicKey()
	path := filepath.Join(t.TempDir(), "sprout.jwt")
	grant := SproutShellPublishGrant("sprout01")
	grants := func() bool {
		uc, err := jwt.DecodeUserClaims(mustReadFile(t, path))
		if err != nil {
			t.Fatal(err)
		}
		return uc.Pub.Allow.Contains(grant)
	}
	old := sproutPermissions("sprout01")
	old.Pub.Allow.Remove(grant)
	if _, err := mintOrReuseUserJWT(path, upub, "sprout01", old, mat.tenantPub, mat.tenantSigningKP); err != nil {
		t.Fatal(err)
	}
	if grants() {
		t.Fatal("JWT minted without the shell grant has it")
	}
	minted, err := mintOrReuseUserJWT(path, upub, "sprout01", sproutPermissions("sprout01"), mat.tenantPub, mat.tenantSigningKP)
	if err != nil {
		t.Fatal(err)
	}
	if !minted || !grants() {
		t.Fatalf("re-mint = %v; the shell grant must be added", minted)
	}
}
