package pki

// Live-bus proof of the imas.sprouts.<id>.fleetsigningkeys grant (FLAG
// FOR SECURITY REVIEW, design doc §2.5): a sprout's NATS User JWT can
// request the fleet signing keys on its own subject — and get farmer's
// answer back on its own imas.sprouts.<id>.fleetsigningkeys.reply.*
// subject, with no new Subscribe grant — but is refused, with a Permissions
// Violation, on another sprout's. Asserting on sproutPermissions' fields
// alone wouldn't show nats-server enforces it; this does.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
)

// The subjects internal/fleetkeys uses (SproutSubject, ReplyPrefix).
// Spelled out rather than imported: fleetkeys imports this package to
// seal its reply, so importing it here would be a cycle.
const (
	signingSubject01 = "imas.sprouts.sprout01.fleetsigningkeys"
	signingSubject02 = "imas.sprouts.sprout02.fleetsigningkeys"
	signingReply01   = signingSubject01 + ".reply.x"
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

func TestSproutJWT_FleetSigningKeysOwnSubjectOnly(t *testing.T) {
	setupTestPKI(t)
	// Farmer's own key, with its seed kept so the test can connect as
	// farmer (allow-all imas.>) and answer the way cmd/farmer does.
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
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	// Farmer's side, subscribed the way fleetkeys.RegisterFarmerListener
	// is; what it answers is fleetkeys' business, not this test's.
	if _, err := farmer.QueueSubscribe("imas.sprouts.*.fleetsigningkeys", "imas-core", func(m *nats.Msg) {
		_ = m.Respond(pub)
	}); err != nil {
		t.Fatal(err)
	}
	// Watches sprout02's subject, to prove nothing sprout01 sends there
	// is delivered.
	other, _ := farmer.SubscribeSync(signingSubject02)
	if err := farmer.Flush(); err != nil {
		t.Fatal(err)
	}

	var perrs permissionErrors
	nc, err := dialAsSprout(t, jwt1, seed1, nats.ErrorHandler(perrs.handler))
	if err != nil {
		t.Fatalf("sprout01 connect: %v", err)
	}
	defer nc.Close()

	// Allowed: its own subject, answered on its own reply subtree.
	sub, err := nc.SubscribeSync(signingReply01)
	if err != nil {
		t.Fatal(err)
	}
	if err := nc.PublishRequest(signingSubject01, signingReply01, nil); err != nil {
		t.Fatal(err)
	}
	msg, err := sub.NextMsg(5 * time.Second)
	if err != nil {
		t.Fatalf("sprout01 requesting on its own subject: %v (permission errors: %v)", err, perrs.any())
	}
	if !bytes.Equal(msg.Data, pub) {
		t.Fatalf("sprout01 got %x", msg.Data)
	}
	if errs := perrs.any(); len(errs) != 0 {
		t.Fatalf("permission errors on the allowed request: %v", errs)
	}

	// Refused: another sprout's subject.
	subj := signingSubject02
	_ = nc.Publish(subj, nil)
	_ = nc.Flush()
	if !perrs.waitForOp("Publish", subj) {
		t.Fatalf("expected a Permissions Violation publishing to %s; got %v", subj, perrs.any())
	}
	if _, err := other.NextMsg(200 * time.Millisecond); err == nil {
		t.Fatal("sprout01's publish to sprout02's fleetsigningkeys subject was delivered")
	}
	// ...and it can't listen in on another sprout's requests to answer
	// them with its own keys.
	_, _ = nc.SubscribeSync(subj)
	_ = nc.Flush()
	if !perrs.waitForOp("Subscription", subj) {
		t.Fatalf("expected a Permissions Violation subscribing to %s; got %v", subj, perrs.any())
	}
}
