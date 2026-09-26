package pki

// Live-bus proof of the imas.sprouts.<id>.fleetsigningkeys grant (FLAG
// FOR SECURITY REVIEW, design doc §2.5): a sprout's NATS User JWT can
// request the fleet signing keys on its own subject — and get farmer's
// answer back on its own imas.sprouts.<id>.fleetsigningkeys.reply.*
// subject, with no new Subscribe grant — but is refused, with a Permissions
// Violation, on another sprout's. Asserting on sproutPermissions' fields
// alone wouldn't show nats-server enforces it; this does.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/fleetkeys"
	"github.com/yogzblr/imas/internal/fleetsign"
)

type staticFleetKeys struct{ ks fleetsign.KeySet }

func (s staticFleetKeys) KeySet(context.Context) (fleetsign.KeySet, error) { return s.ks, nil }

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
	ks, _ := fleetsign.NewKeySet([]fleetsign.PublicKey{{Version: 1, Key: pub}})
	fleetkeys.SetKeySource(staticFleetKeys{ks: ks})
	defer fleetkeys.SetKeySource(nil)
	if err := fleetkeys.RegisterFarmerListener(currentTenantID(), farmer); err != nil {
		t.Fatal(err)
	}
	// Watches sprout02's subject, to prove nothing sprout01 sends there
	// is delivered.
	other, _ := farmer.SubscribeSync(fleetkeys.SproutSubject("sprout02"))
	if err := farmer.Flush(); err != nil {
		t.Fatal(err)
	}

	var perrs permissionErrors
	nc, err := dialAsSprout(t, jwt1, seed1, nats.ErrorHandler(perrs.handler))
	if err != nil {
		t.Fatalf("sprout01 connect: %v", err)
	}
	defer nc.Close()

	// Allowed: its own subject, full round trip through farmer's listener.
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	got, err := fleetkeys.Fetch(ctx, nc, "sprout01")
	if err != nil {
		t.Fatalf("sprout01 fetching on its own subject: %v (permission errors: %v)", err, perrs.any())
	}
	if len(got) != 1 || !got[0].Key.Equal(pub) {
		t.Fatalf("sprout01 got %+v", got)
	}
	if errs := perrs.any(); len(errs) != 0 {
		t.Fatalf("permission errors on the allowed request: %v", errs)
	}

	// Refused: another sprout's subject.
	subj := fleetkeys.SproutSubject("sprout02")
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
