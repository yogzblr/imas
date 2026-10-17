package pki

// A sprout picks up a User JWT a refresh has changed without a restart
// (P12): SproutBus presents its JWT through a callback, ReloadUserJWT
// swaps in the persisted one, and a reconnect makes the bus apply the new
// grant. cmd/sprout's heartbeatGate does this at every heartbeat.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
)

func TestSproutBus_ReconnectsWithRefreshedUserJWT(t *testing.T) {
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

	current, seed := acceptTestSprout(t, "sprout01")
	kp, err := nkeys.FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := kp.PublicKey()
	mat, err := ensureNatsAuth()
	if err != nil {
		t.Fatal(err)
	}
	// The JWT the sprout holds from before the heartbeat grant existed.
	old := SproutPermissions("sprout01")
	old.Pub.Allow.Remove(SproutHeartbeatSubject("sprout01"))
	oldPath := filepath.Join(t.TempDir(), "old.jwt")
	if _, err := mintOrReuseUserJWTFile(oldPath, pub, "sprout01", old, mat.tenantPub, mat.tenantSigningKP); err != nil {
		t.Fatal(err)
	}
	stale := mustReadFile(t, oldPath)
	if SproutUserJWTHasFullGrant(stale, "sprout01") || !SproutUserJWTHasFullGrant(current, "sprout01") {
		t.Fatal("SproutUserJWTHasFullGrant does not tell the stale JWT from the current one")
	}

	busURL := config.FarmerBusURL
	setupSproutFiles(t)
	config.SproutRootCA = config.RootCA
	config.FarmerBusURL = busURL
	if err := os.WriteFile(config.NKeySproutPrivFile, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.SproutUserJWTFile, []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}

	farmerJWT, err := farmerUserJWTBytes()
	if err != nil {
		t.Fatal(err)
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

	bus, err := LoadSproutBus()
	if err != nil {
		t.Fatal(err)
	}
	if bus.UserJWT() != stale {
		t.Fatal("the bus does not present the persisted JWT")
	}
	if changed, err := bus.ReloadUserJWT(); err != nil || changed {
		t.Fatalf("ReloadUserJWT with the file unchanged: %v, %v", changed, err)
	}
	var perrs permissionErrors
	reconnected := make(chan struct{}, 1)
	nc, err := bus.Connect(nats.ErrorHandler(perrs.handler), nats.ReconnectWait(10*time.Millisecond),
		nats.ReconnectHandler(func(*nats.Conn) { reconnected <- struct{}{} }))
	if err != nil {
		t.Fatalf("sprout connect: %v", err)
	}
	defer nc.Close()

	subj := SproutHeartbeatSubject("sprout01")
	_ = nc.Publish(subj, nil)
	_ = nc.Flush()
	if !perrs.waitForOp("Publish", subj) {
		t.Fatalf("the stale JWT may publish its heartbeat: %v", perrs.any())
	}

	// A refresh writes the re-minted JWT; a junk file is ignored first.
	if err := os.WriteFile(config.SproutUserJWTFile, []byte("not a jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := bus.ReloadUserJWT(); err == nil || changed || bus.UserJWT() != stale {
		t.Fatalf("ReloadUserJWT took an unparsable file: %v, %v", changed, err)
	}
	if err := os.WriteFile(config.SproutUserJWTFile, []byte(current+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := bus.ReloadUserJWT(); err != nil || !changed || bus.UserJWT() != current {
		t.Fatalf("ReloadUserJWT after a refresh: %v, %v", changed, err)
	}
	if err := nc.ForceReconnect(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reconnected:
	case <-time.After(10 * time.Second):
		t.Fatal("no reconnect")
	}
	if err := nc.Publish(subj, nil); err != nil {
		t.Fatal(err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := beats.NextMsg(2 * time.Second); err != nil {
		t.Fatalf("no heartbeat after reconnecting with the refreshed JWT: %v (permission errors: %v)", err, perrs.any())
	}
}

// The full-grant check is the whole permission set: a missing subject, an
// extra one, a deny or another sprout's grant all make the JWT stale.
func TestSproutUserJWTHasFullGrant(t *testing.T) {
	account, _ := nkeys.CreateAccount()
	user, _ := nkeys.CreateUser()
	pub, _ := user.PublicKey()
	mint := func(p jwt.Permissions) string {
		uc := jwt.NewUserClaims(pub)
		uc.Permissions = p
		s, err := uc.Encode(account)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	if !SproutUserJWTHasFullGrant(mint(SproutPermissions("web-01")), "web-01") {
		t.Fatal("the current grant is not the full grant")
	}
	missing := SproutPermissions("web-01")
	missing.Pub.Allow.Remove(sproutLogPublishGrant("web-01"))
	extra := SproutPermissions("web-01")
	extra.Pub.Allow.Add("imas.>")
	denied := SproutPermissions("web-01")
	denied.Pub.Deny.Add(SproutHeartbeatSubject("web-01"))
	for name, tok := range map[string]string{
		"missing the log grant": mint(missing),
		"an extra grant":        mint(extra),
		"a deny":                mint(denied),
		"another sprout's":      mint(SproutPermissions("web-02")),
		"not a JWT":             "not a jwt",
		"empty":                 "",
	} {
		if SproutUserJWTHasFullGrant(tok, "web-01") {
			t.Errorf("%s: reported as the full grant", name)
		}
	}
}
