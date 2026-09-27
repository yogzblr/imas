package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/taigrr/jety"
	"golang.org/x/crypto/nacl/box"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/natsapi"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/pki/tenantboxtest"
)

// boxKeyEnv is farmer (its real NATS API, internal/natsapi.Subscribe,
// including handleBoxKeySubmit) and one enrolled sprout, on one bus.
type boxKeyEnv struct {
	tenant, sproutID string
	farmer, sprout   *nats.Conn
	url              string
}

func setupBoxKeyEnv(t *testing.T) *boxKeyEnv {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := gdb.AutoMigrate(pki.Models()...); err != nil {
		t.Fatal(err)
	}
	pki.SetDB(gdb)
	t.Cleanup(func() {
		if sqlDB, err := gdb.DB(); err == nil {
			sqlDB.Close()
		}
	})
	tenantboxtest.Start(t)
	e := &boxKeyEnv{tenant: pki.CurrentTenantID(), sproutID: "web-01"}
	pki.InvalidateTenantBoxKeys(e.tenant)
	t.Cleanup(func() { pki.InvalidateTenantBoxKeys(e.tenant) })

	dir := t.TempDir()
	saved := []*string{&config.FarmerPKI, &config.NKeyFarmerPubFile, &config.SproutBoxPrivFile, &config.SproutBoxPubFile, &config.SproutTenantX25519PubFile}
	old := make([]string, len(saved))
	for i, p := range saved {
		old[i] = *p
	}
	oldGrace := config.BoxKeyGraceDuration
	t.Cleanup(func() {
		for i, p := range saved {
			*p = old[i]
		}
		config.BoxKeyGraceDuration = oldGrace
	})
	config.FarmerPKI = filepath.Join(dir, "farmer") + "/"
	// Registering the sprout reloads farmer's NATS auth, which needs one.
	config.NKeyFarmerPubFile = filepath.Join(dir, "farmer.nkey.pub")
	if err := os.WriteFile(config.NKeyFarmerPubFile, []byte("UFAKE_FARMER_KEY_FOR_TESTING"), 0o600); err != nil {
		t.Fatal(err)
	}
	config.SproutBoxPrivFile = filepath.Join(dir, "sprout-x25519.key")
	config.SproutBoxPubFile = filepath.Join(dir, "sprout-x25519.pub")
	config.SproutTenantX25519PubFile = filepath.Join(dir, "tenant-x25519.pub")
	config.BoxKeyGraceDuration = time.Hour

	// Enrollment's effect: farmer knows the sprout (pki.rotatebox refuses
	// an unknown one) and its box key, and the sprout pinned the tenant
	// key.
	if err := pki.UnacceptNKey(e.tenant, e.sproutID, "UKEY_WEB01"); err != nil {
		t.Fatal(err)
	}
	sproutPub, err := pki.EnsureSproutBoxKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.RotateSproutBoxKey(e.tenant, e.sproutID, sproutPub, time.Hour); err != nil {
		t.Fatal(err)
	}
	tenantPub, err := pki.GetTenantX25519PublicKey(e.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.SproutTenantX25519PubFile, []byte(tenantPub), 0o644); err != nil {
		t.Fatal(err)
	}

	// The admin call below has no token.
	jety.Set("dangerously_allow_root", true)
	t.Cleanup(func() { jety.Set("dangerously_allow_root", false) })

	ns, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1})
	if err != nil {
		t.Fatal(err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS server not ready")
	}
	t.Cleanup(ns.Shutdown)
	e.url = ns.ClientURL()
	e.farmer, e.sprout = e.connect(t), e.connect(t)
	if err := natsapi.Subscribe(e.farmer, e.tenant); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { natsapi.ClearNatsConn(e.tenant) })
	if err := subscribeBoxKeyRotate(e.sprout, e.sproutID); err != nil {
		t.Fatal(err)
	}
	flush(t, e.farmer, e.sprout)
	return e
}

func (e *boxKeyEnv) connect(t *testing.T) *nats.Conn {
	t.Helper()
	nc, err := nats.Connect(e.url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	return nc
}

func flush(t *testing.T, conns ...*nats.Conn) {
	t.Helper()
	for _, nc := range conns {
		if err := nc.Flush(); err != nil {
			t.Fatal(err)
		}
	}
}

func boxPubForTest(t *testing.T) string {
	t.Helper()
	pub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(pub[:])
}

// farmerKeys is farmer's record of the sprout's box keys.
func (e *boxKeyEnv) farmerKeys(t *testing.T) (string, []string) {
	t.Helper()
	active, grace, err := pki.ValidSproutBoxKeys(e.tenant, e.sproutID)
	if err != nil {
		t.Fatal(err)
	}
	return active, grace
}

// waitForActive waits for farmer to record a box key other than old.
func (e *boxKeyEnv) waitForActive(t *testing.T, old string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if active, _ := e.farmerKeys(t); active != old {
			return active
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("farmer never recorded a new box key (still %s)", old)
	return ""
}

// farmerTraffic has farmer seal a request to the sprout, the sprout
// open it and seal a reply, and farmer open that.
func (e *boxKeyEnv) farmerTraffic(t *testing.T) {
	t.Helper()
	req, _, err := pki.SealToSprout(e.tenant, e.sproutID, payloadbox.PurposeCmdRunRequest, "", "uptime")
	if err != nil {
		t.Fatal(err)
	}
	msg, err := pki.SproutOpenFromFarmer(e.sproutID, payloadbox.PurposeCmdRunRequest, req)
	if err != nil {
		t.Fatalf("sprout can't open farmer's request: %v", err)
	}
	reply, err := pki.SproutSealForFarmer(e.sproutID, payloadbox.PurposeCmdRunResponse, msg.ID, "up")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.OpenFromSprout(e.tenant, e.sproutID, payloadbox.PurposeCmdRunResponse, reply); err != nil {
		t.Fatalf("farmer can't open the sprout's reply: %v", err)
	}
}

// sproutCurrentPub is the public half of the key the sprout seals with.
func sproutCurrentPub(t *testing.T) string {
	t.Helper()
	pub, err := pki.EnsureSproutBoxKey() // re-derives it; never replaces the key
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// The subjects the sprout uses are the ones farmer publishes and
// subscribes on.
func TestBoxKeySubjectsMatchFarmer(t *testing.T) {
	if got, want := boxKeyRotateSubject("web-01"), natsapi.SproutSubject("web-01", natsapi.SproutBoxKeyRotateCmd); got != want {
		t.Errorf("rotate subject %q, farmer publishes %q", got, want)
	}
	if got, want := boxKeySubmitSubject("web-01"), strings.Replace(natsapi.SproutBoxKeySubmitPattern, "*", "web-01", 1); got != want {
		t.Errorf("submit subject %q, farmer subscribes %q", got, want)
	}
}

// The full round trip: an admin's pki.rotatebox call to farmer, farmer's
// trigger to the sprout, the sprout's sealed submission, farmer recording
// the new key, and the sprout switching to it once farmer seals to it.
func TestBoxKeyRotation_RoundTrip(t *testing.T) {
	e := setupBoxKeyEnv(t)
	oldPub := sproutCurrentPub(t)

	admin := e.connect(t)
	resp, err := admin.Request(natsapi.Subject(natsapi.MethodPKIRotateBoxKey), []byte(`{"id":"web-01"}`), 5*time.Second)
	if err != nil {
		t.Fatalf("pki.rotatebox: %v", err)
	}
	var result struct {
		Result map[string]bool `json:"result"`
		Error  string          `json:"error"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil || !result.Result["success"] {
		t.Fatalf("pki.rotatebox response %s (%v)", resp.Data, err)
	}

	newPub := e.waitForActive(t, oldPub)
	if _, grace := e.farmerKeys(t); len(grace) != 1 || grace[0] != oldPub {
		t.Fatalf("farmer's grace keys %v, want [%s]", grace, oldPub)
	}
	// Until farmer seals to the new key, the sprout keeps sealing with
	// the old one, which farmer still opens.
	if got := sproutCurrentPub(t); got != oldPub {
		t.Fatalf("sprout switched to %s before farmer sealed to it", got)
	}
	e.farmerTraffic(t) // farmer seals to newPub: the sprout switches
	if got := sproutCurrentPub(t); got != newPub {
		t.Fatalf("sprout seals with %s, farmer has %s active", got, newPub)
	}
	e.farmerTraffic(t)
}

// A rogue bus subscriber publishing the trigger itself. Accepted, low
// severity (see boxkey.go): the sprout rotates exactly as if farmer had
// asked, the submission is sealed and names a key only the sprout holds,
// repeated triggers resubmit the same key, and the rogue's own key is
// never recorded.
func TestBoxKeyRotation_RogueTrigger(t *testing.T) {
	e := setupBoxKeyEnv(t)
	oldPub := sproutCurrentPub(t)
	rogue := e.connect(t)

	var mu sync.Mutex
	var seen []*nats.Msg
	if _, err := rogue.Subscribe(boxKeySubmitSubject(e.sproutID), func(m *nats.Msg) {
		mu.Lock()
		seen = append(seen, m)
		mu.Unlock()
	}); err != nil {
		t.Fatal(err)
	}
	flush(t, rogue)

	const triggers = 3
	for range triggers {
		if err := rogue.Publish(boxKeyRotateSubject(e.sproutID), nil); err != nil {
			t.Fatal(err)
		}
	}
	flush(t, rogue)
	newPub := e.waitForActive(t, oldPub)

	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(seen)
		mu.Unlock()
		if n == triggers {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("saw %d submissions, want %d", n, triggers)
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, m := range seen {
		if m.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
			t.Error("submission not marked sealed")
		}
		if strings.Contains(string(m.Data), newPub) {
			t.Error("submission carries the new key in plaintext")
		}
		// All name the same key: no churn however many triggers arrive.
		opened, err := pki.OpenFromSprout(e.tenant, e.sproutID, payloadbox.PurposeBoxKeySubmit, m.Data)
		if err != nil {
			t.Fatalf("farmer can't open a submission: %v", err)
		}
		var body struct {
			Pub string `json:"pub"`
		}
		if err := json.Unmarshal(opened.Body, &body); err != nil || body.Pub != newPub {
			t.Errorf("submission names %q, want %s", body.Pub, newPub)
		}
	}
	if _, grace := e.farmerKeys(t); len(grace) != 1 || grace[0] != oldPub {
		t.Errorf("farmer's grace keys %v, want [%s]", grace, oldPub)
	}

	// What the rogue can't do: substitute its own key.
	attacker := boxPubForTest(t)
	if err := rogue.Publish(boxKeySubmitSubject(e.sproutID), []byte(`{"pub":"`+attacker+`"}`)); err != nil {
		t.Fatal(err)
	}
	flush(t, rogue, e.farmer)
	time.Sleep(100 * time.Millisecond)
	if active, _ := e.farmerKeys(t); active != newPub {
		t.Fatalf("a rogue submission changed farmer's active key to %s", active)
	}

	// Traffic keeps flowing, the sprout switches, and a further trigger
	// inside the grace window is refused rather than churning keys.
	e.farmerTraffic(t)
	if got := sproutCurrentPub(t); got != newPub {
		t.Fatalf("sprout seals with %s, want %s", got, newPub)
	}
	if err := rogue.Publish(boxKeyRotateSubject(e.sproutID), nil); err != nil {
		t.Fatal(err)
	}
	flush(t, rogue, e.sprout)
	time.Sleep(100 * time.Millisecond)
	if active, _ := e.farmerKeys(t); active != newPub {
		t.Fatalf("a trigger inside the grace window rotated farmer's key to %s", active)
	}
	e.farmerTraffic(t)
}

func TestUserJWTGrantsPub(t *testing.T) {
	account, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	userPub, _ := user.PublicKey()
	mint := func(allow ...string) string {
		uc := jwt.NewUserClaims(userPub)
		uc.Pub.Allow.Add(allow...)
		s, err := uc.Encode(account)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	subject := boxKeySubmitSubject("web-01")
	if !userJWTGrantsPub(mint("imas.sprouts.web-01.facts", subject), subject) {
		t.Error("grant not found")
	}
	if userJWTGrantsPub(mint("imas.sprouts.web-01.facts"), subject) {
		t.Error("grant reported without one")
	}
	if userJWTGrantsPub("not a jwt", subject) {
		t.Error("grant reported for an unparsable JWT")
	}
}
