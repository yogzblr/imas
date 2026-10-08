package pki

// The sprout heartbeat grant (internal/heartbeat): a sprout's User JWT can
// publish exactly its own imas.heartbeat.sprout.<id> subject, which farmer
// (allow-all imas.>) receives through the per-tenant wildcard, and is
// refused, with a Permissions Violation, on another sprout's.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
)

func TestSproutHeartbeatSubject(t *testing.T) {
	if got, want := SproutHeartbeatSubject("web-01"), "imas.heartbeat.sprout.web-01"; got != want {
		t.Fatalf("SproutHeartbeatSubject = %q, want %q", got, want)
	}
	if !strings.HasPrefix(SproutHeartbeatSubjectPattern, SproutHeartbeatSubjectPrefix) ||
		!strings.HasSuffix(SproutHeartbeatSubjectPattern, ".*") {
		t.Fatalf("pattern %q must be the prefix plus a single-token wildcard", SproutHeartbeatSubjectPattern)
	}
}

// The grant is the sprout's own subject only: no wildcard in it, and a
// different sprout's permissions neither contain it nor carry a heartbeat
// grant that could cover it.
func TestSproutPermissions_HeartbeatGrantIsPerSprout(t *testing.T) {
	a, b := sproutPermissions("sprout01"), sproutPermissions("sprout02")
	subjA, subjB := SproutHeartbeatSubject("sprout01"), SproutHeartbeatSubject("sprout02")

	if !a.Pub.Allow.Contains(subjA) {
		t.Fatalf("sprout01 has no publish grant for %s", subjA)
	}
	if a.Pub.Allow.Contains(subjB) {
		t.Fatalf("sprout01 may publish %s", subjB)
	}
	if !b.Pub.Allow.Contains(subjB) || b.Pub.Allow.Contains(subjA) {
		t.Fatalf("sprout02's heartbeat grant is wrong: %v", b.Pub.Allow)
	}
	for _, p := range []jwt.Permissions{a, b} {
		for _, g := range p.Pub.Allow {
			if strings.HasPrefix(g, SproutHeartbeatSubjectPrefix) && (strings.ContainsAny(g, "*>") || g != subjA && g != subjB) {
				t.Fatalf("unexpected heartbeat publish grant %q", g)
			}
		}
	}
}

// A sprout JWT minted before the heartbeat grant existed must be re-minted
// (not reused) on the next sync, or that sprout would be silently denied.
func TestMintOrReuseUserJWT_AddsHeartbeatGrant(t *testing.T) {
	setupTestPKI(t)
	mat, err := ensureNatsAuth()
	if err != nil {
		t.Fatalf("ensureNatsAuth failed: %v", err)
	}
	ukp, _ := nkeys.CreateUser()
	upub, _ := ukp.PublicKey()
	path := filepath.Join(t.TempDir(), "sprout.jwt")
	subj := SproutHeartbeatSubject("sprout01")
	grants := func() bool {
		uc, err := jwt.DecodeUserClaims(mustReadFile(t, path))
		if err != nil {
			t.Fatal(err)
		}
		return uc.Pub.Allow.Contains(subj)
	}

	old := sproutPermissions("sprout01")
	old.Pub.Allow.Remove(subj)
	if _, err := mintOrReuseUserJWT(path, upub, "sprout01", old, mat.tenantPub, mat.tenantSigningKP); err != nil {
		t.Fatalf("mintOrReuseUserJWT (old permissions) failed: %v", err)
	}
	if grants() {
		t.Fatal("JWT minted without the heartbeat grant has it")
	}
	minted, err := mintOrReuseUserJWT(path, upub, "sprout01", sproutPermissions("sprout01"), mat.tenantPub, mat.tenantSigningKP)
	if err != nil {
		t.Fatalf("mintOrReuseUserJWT (current permissions) failed: %v", err)
	}
	if !minted || !grants() {
		t.Fatalf("re-mint = %v; the heartbeat grant must be added", minted)
	}
	// And once current, it is reused, not re-signed on every sync.
	if minted, err = mintOrReuseUserJWT(path, upub, "sprout01", sproutPermissions("sprout01"), mat.tenantPub, mat.tenantSigningKP); err != nil || minted {
		t.Fatalf("second mint = %v, %v; want a reuse", minted, err)
	}
}

func TestSproutJWT_HeartbeatOwnSubjectOnly(t *testing.T) {
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
	beats, err := farmer.SubscribeSync(SproutHeartbeatSubjectPattern)
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

	own := SproutHeartbeatSubject("sprout01")
	if err := nc.Publish(own, nil); err != nil {
		t.Fatal(err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	msg, err := beats.NextMsg(2 * time.Second)
	if err != nil {
		t.Fatalf("farmer didn't receive sprout01's heartbeat: %v (permission errors: %v)", err, perrs.any())
	}
	if msg.Subject != own {
		t.Fatalf("got subject %q, want %q", msg.Subject, own)
	}

	// Another sprout's subject, and wildcard-ish variants of its own.
	other := SproutHeartbeatSubject("sprout02")
	_ = nc.Publish(other, nil)
	_ = nc.Flush()
	if !perrs.waitForOp("Publish", other) {
		t.Fatalf("expected a Permissions Violation publishing to %s; got %v", other, perrs.any())
	}
	if msg, err := beats.NextMsg(200 * time.Millisecond); err == nil {
		t.Fatalf("sprout01's publish to %s was delivered", msg.Subject)
	}
	// A sprout can't listen in on heartbeats either.
	if _, err := nc.Subscribe(own, func(*nats.Msg) {}); err != nil {
		t.Fatal(err)
	}
	_ = nc.Flush()
	if !perrs.waitForOp("Subscription", own) {
		t.Fatalf("expected a Permissions Violation subscribing to %s; got %v", own, perrs.any())
	}
}
