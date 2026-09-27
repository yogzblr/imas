package pki

// Live-bus proof of the imas.logs.sprouts.<id>.> grant: a sprout's NATS
// User JWT can publish log entries on its own log subjects, which farmer
// (allow-all imas.>) receives in the same tenant Account, but is refused,
// with a Permissions Violation, on another sprout's.

import (
	"os"
	"testing"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
)

func TestSproutJWT_LogSubjectsOwnOnly(t *testing.T) {
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

	if !SproutUserJWTGrantsLogs(jwt1, "sprout01") {
		t.Fatal("sprout01's User JWT should grant its own log subjects")
	}
	if SproutUserJWTGrantsLogs(jwt1, "sprout02") {
		t.Fatal("sprout01's User JWT should not grant sprout02's log subjects")
	}

	farmerJWT, err := os.ReadFile(farmerUserJWTPath())
	if err != nil {
		t.Fatalf("reading farmer's User JWT: %v", err)
	}
	farmer, err := dialAsSprout(t, string(farmerJWT), farmerSeed)
	if err != nil {
		t.Fatalf("farmer connect: %v", err)
	}
	defer farmer.Close()
	logs, err := farmer.SubscribeSync("imas.logs.sprouts.>")
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

	own := SproutLogSubjectPrefix("sprout01") + ".INFO"
	if err := nc.Publish(own, []byte(`{"output":"hello"}`)); err != nil {
		t.Fatal(err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	msg, err := logs.NextMsg(2 * time.Second)
	if err != nil {
		t.Fatalf("farmer didn't receive sprout01's log entry: %v (permission errors: %v)", err, perrs.any())
	}
	if msg.Subject != own {
		t.Fatalf("got subject %q, want %q", msg.Subject, own)
	}

	other := SproutLogSubjectPrefix("sprout02") + ".INFO"
	_ = nc.Publish(other, []byte(`{"output":"spoofed"}`))
	_ = nc.Flush()
	if !perrs.waitForOp("Publish", other) {
		t.Fatalf("expected a Permissions Violation publishing to %s; got %v", other, perrs.any())
	}
	if msg, err := logs.NextMsg(200 * time.Millisecond); err == nil {
		t.Fatalf("sprout01's publish to %s was delivered", msg.Subject)
	}
}
