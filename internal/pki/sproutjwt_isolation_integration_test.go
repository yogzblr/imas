package pki

// Live-bus proof that a sprout's NATS User JWT confines it to its own
// subjects: sprout01 is refused, with a Permissions Violation, when it
// publishes to or subscribes on sprout02's imas.sprouts.<id>.> subtree,
// and nothing it sends there is delivered. Asserting on
// sproutPermissions' fields alone wouldn't show nats-server enforces it;
// this does.
//
// It also pins that the retired imas.sprouts.<id>.fleetsigningkeys
// Publish grant (design doc §2.5: sprouts verify releases against the
// keyring shipped in their package) is gone, even on the sprout's own
// subject.

import (
	"os"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
)

// acceptTestSprout registers and accepts sproutID, returning its User JWT
// and seed.
func acceptTestSprout(t *testing.T, sproutID string) (string, []byte) {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := kp.PublicKey()
	seed, _ := kp.Seed()
	writeKey(t, "unaccepted", sproutID, pub)
	if err := AcceptNKey(currentTenantID(), sproutID); err != nil {
		t.Fatalf("AcceptNKey(%s): %v", sproutID, err)
	}
	userJWT, err := GetSproutUserJWT(sproutID)
	if err != nil {
		t.Fatalf("GetSproutUserJWT(%s): %v", sproutID, err)
	}
	return userJWT, seed
}

func TestSproutJWT_CannotReachOtherSproutsSubjects(t *testing.T) {
	setupTestPKI(t)
	// Farmer's own key, with its seed kept so the test can connect as
	// farmer (allow-all imas.>) and watch sprout02's subtree.
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
	// Watches both sprouts' subtrees, to prove nothing sprout01 sends to
	// a denied subject is delivered.
	watch, err := farmer.SubscribeSync("imas.sprouts.*.>")
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

	// Control: sprout01's own facts subject is granted both ways, so the
	// denials below are about whose subject it is, not a broken connection.
	own := "imas.sprouts.sprout01.facts"
	if err := nc.Publish(own, []byte("ok")); err != nil {
		t.Fatal(err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	if msg, err := watch.NextMsg(2 * time.Second); err != nil || msg.Subject != own {
		t.Fatalf("farmer didn't receive sprout01's publish to %s: msg=%v err=%v (permission errors: %v)", own, msg, err, perrs.any())
	}
	if errs := perrs.any(); len(errs) != 0 {
		t.Fatalf("permission errors on sprout01's own subject: %v", errs)
	}

	for _, subj := range []string{
		"imas.sprouts.sprout02.facts",
		"imas.sprouts.sprout02.boxkey.pub",
		"imas.sprouts.sprout02.fleetsigningkeys",
		"imas.sprouts.sprout02.cmd.run",
		// The retired grant: no longer publishable even on its own subject.
		"imas.sprouts.sprout01.fleetsigningkeys",
	} {
		_ = nc.Publish(subj, []byte("nope"))
		_ = nc.Flush()
		if !perrs.waitForOp("Publish", subj) {
			t.Errorf("expected a Permissions Violation publishing to %s; got %v", subj, perrs.any())
		}
	}
	if msg, err := watch.NextMsg(200 * time.Millisecond); err == nil {
		t.Errorf("sprout01's publish to %s was delivered", msg.Subject)
	}

	// ...and it can't listen in on another sprout's subjects, by name or
	// by wildcard.
	for _, subj := range []string{
		"imas.sprouts.sprout02.>",
		"imas.sprouts.sprout02.cmd.run",
		"imas.sprouts.*.cmd.run",
	} {
		_, _ = nc.SubscribeSync(subj)
		_ = nc.Flush()
		if !perrs.waitForOp("Subscription", subj) {
			t.Errorf("expected a Permissions Violation subscribing to %s; got %v", subj, perrs.any())
		}
	}
}
