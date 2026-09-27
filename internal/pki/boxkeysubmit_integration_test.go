package pki

// Live-bus proof of the imas.sprouts.<id>.boxkey.pub grant: a sprout's
// NATS User JWT can submit a new box public key on its own subject, which
// farmer (allow-all imas.>) receives, but is refused, with a Permissions
// Violation, on another sprout's.

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

func TestSproutJWT_BoxKeySubmitOwnSubjectOnly(t *testing.T) {
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
		t.Fatalf("reading farmer's User JWT: %v", err)
	}
	farmer, err := dialAsSprout(t, string(farmerJWT), farmerSeed)
	if err != nil {
		t.Fatalf("farmer connect: %v", err)
	}
	defer farmer.Close()
	// The pattern farmer's handleBoxKeySubmit subscribes on.
	submissions, err := farmer.SubscribeSync("imas.sprouts.*.boxkey.pub")
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

	own := SproutBoxKeySubmitSubject("sprout01")
	if err := nc.Publish(own, []byte(`{"v":1,"s":[]}`)); err != nil {
		t.Fatal(err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	msg, err := submissions.NextMsg(2 * time.Second)
	if err != nil {
		t.Fatalf("farmer didn't receive sprout01's submission: %v (permission errors: %v)", err, perrs.any())
	}
	if msg.Subject != own {
		t.Fatalf("got subject %q, want %q", msg.Subject, own)
	}

	other := SproutBoxKeySubmitSubject("sprout02")
	_ = nc.Publish(other, []byte(`{"v":1,"s":[]}`))
	_ = nc.Flush()
	if !perrs.waitForOp("Publish", other) {
		t.Fatalf("expected a Permissions Violation publishing to %s; got %v", other, perrs.any())
	}
	if msg, err := submissions.NextMsg(200 * time.Millisecond); err == nil {
		t.Fatalf("sprout01's publish to %s was delivered", msg.Subject)
	}
}

// A sprout's User JWT minted before sproutPermissions carried the
// boxkey.pub grant is re-minted with it on the next sync, which the
// sprout then picks up through /v1/refresh.
func TestMintOrReuseUserJWT_AddsBoxKeySubmitGrant(t *testing.T) {
	setupTestPKI(t)
	mat, err := ensureNatsAuth()
	if err != nil {
		t.Fatalf("ensureNatsAuth failed: %v", err)
	}
	ukp, _ := nkeys.CreateUser()
	upub, _ := ukp.PublicKey()
	path := filepath.Join(t.TempDir(), "sprout.jwt")
	submit := SproutBoxKeySubmitSubject("sprout01")
	grants := func() bool {
		uc, err := jwt.DecodeUserClaims(mustReadFile(t, path))
		if err != nil {
			t.Fatal(err)
		}
		return uc.Pub.Allow.Contains(submit)
	}

	old := sproutPermissions("sprout01")
	old.Pub.Allow.Remove(submit)
	if _, err := mintOrReuseUserJWT(path, upub, "sprout01", old, mat.tenantPub, mat.tenantSigningKP); err != nil {
		t.Fatalf("mintOrReuseUserJWT (old permissions) failed: %v", err)
	}
	if grants() {
		t.Fatal("JWT minted without the boxkey.pub grant has it")
	}
	minted, err := mintOrReuseUserJWT(path, upub, "sprout01", sproutPermissions("sprout01"), mat.tenantPub, mat.tenantSigningKP)
	if err != nil {
		t.Fatalf("mintOrReuseUserJWT (current permissions) failed: %v", err)
	}
	if !minted || !grants() {
		t.Fatalf("re-mint = %v; the boxkey.pub grant must be added", minted)
	}
}
