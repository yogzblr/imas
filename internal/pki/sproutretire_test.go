package pki

// SEC.3a (docs/security-review-2026-10.md H1, M3): deleting or replacing
// a sprout ends its bus credential and its box keys, a reused sprout ID
// ends up with exactly one active box key, and only the active box key
// can change which key is active.

import (
	"crypto/rand"
	"errors"
	"os"
	"testing"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/payloadbox"
)

// testSproutBox is a sprout's box keypair.
type testSproutBox struct {
	pub, priv *[32]byte
}

func newTestSproutBox(t *testing.T) testSproutBox {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testSproutBox{pub: pub, priv: priv}
}

func (k testSproutBox) b64() string { return b64(k.pub) }

// sealAsTestSprout seals body as sproutID would: under its box key and
// the tenant's current key.
func sealAsTestSprout(t *testing.T, tenant, sproutID, purpose string, k testSproutBox, body any) []byte {
	t.Helper()
	keys, err := TenantBoxKeys(tenant)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := payloadbox.NewMessage(purpose, tenant, sproutID, "", body)
	if err != nil {
		t.Fatal(err)
	}
	data, err := payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: keys[0].Pub, Priv: k.priv}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// boxKeyRows returns every pki_sprout_box_keys row of (tenant, sproutID).
func boxKeyRows(t *testing.T, tenant, sproutID string) []sproutBoxKeyRow {
	t.Helper()
	var rows []sproutBoxKeyRow
	if err := db.Where("tenant_id = ? AND sprout_id = ?", tenant, sproutID).Order("pub").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

// activeRows counts (tenant, sproutID)'s active rows, and checks each
// one's active_slot matches its state.
func activeRows(t *testing.T, tenant, sproutID string) []string {
	t.Helper()
	var out []string
	for _, r := range boxKeyRows(t, tenant, sproutID) {
		isActive := r.State == boxKeyStateActive
		if hasSlot := r.ActiveSlot != nil && *r.ActiveSlot == 1; hasSlot != isActive {
			t.Errorf("row %s/%s/%s: state %q with active_slot %v", tenant, sproutID, r.Pub, r.State, r.ActiveSlot)
		}
		if isActive {
			out = append(out, r.Pub)
		}
	}
	return out
}

func newUserNKey(t *testing.T) (pub string, seed []byte) {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ = kp.PublicKey()
	seed, _ = kp.Seed()
	return pub, seed
}

// Deleting a sprout (H1): its User JWT is refused on reconnect, its live
// connection is closed, and its box key no longer seals or opens.
func TestDeleteNKey_EndsBusCredentialAndBoxKey(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	setupTenantBoxOpenBao(t)
	defer startTestBus(t)()
	tenant := currentTenantID()

	userJWT, seed := acceptTestSprout(t, "web")
	nkey, _ := GetNKey(tenant, "web")
	k := newTestSproutBox(t)
	if err := upsertSproutBoxKeyActive(tenant, "web", k.b64()); err != nil {
		t.Fatal(err)
	}
	reply := sealAsTestSprout(t, tenant, "web", payloadbox.PurposeCmdRunResponse, k, "ok")
	if _, err := OpenFromSprout(tenant, "web", payloadbox.PurposeCmdRunResponse, reply); err != nil {
		t.Fatalf("before delete, the sprout's payload doesn't open: %v", err)
	}
	if _, _, err := SealToSprout(tenant, "web", payloadbox.PurposeCmdRunRequest, "", "uptime"); err != nil {
		t.Fatalf("before delete, sealing to the sprout fails: %v", err)
	}

	closed := make(chan struct{})
	live, err := dialAsSprout(t, userJWT, seed, nats.NoReconnect(), nats.ClosedHandler(func(*nats.Conn) { close(closed) }))
	if err != nil {
		t.Fatalf("accepted sprout can't connect: %v", err)
	}
	defer live.Close()

	if err := DeleteNKey(tenant, "web"); err != nil {
		t.Fatalf("DeleteNKey: %v", err)
	}

	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Error("the deleted sprout's live connection was not closed")
	}
	if nc, err := dialAsSprout(t, userJWT, seed); err == nil {
		nc.Close()
		t.Fatal("the deleted sprout's User JWT still connects")
	}

	if _, _, err := SealToSprout(tenant, "web", payloadbox.PurposeCmdRunRequest, "", "uptime"); !errors.Is(err, ErrNoActiveBoxKey) {
		t.Errorf("sealing to a deleted sprout: %v, want ErrNoActiveBoxKey", err)
	}
	if _, err := OpenFromSprout(tenant, "web", payloadbox.PurposeCmdRunResponse, reply); !errors.Is(err, payloadbox.ErrOpen) {
		t.Errorf("a deleted sprout's payload: %v, want ErrOpen", err)
	}
	for _, r := range boxKeyRows(t, tenant, "web") {
		if r.State != boxKeyStateRevoked {
			t.Errorf("box key %s is %q after delete, want revoked", r.Pub, r.State)
		}
	}
	if revoked, err := isNKeyRevoked(tenant, nkey); err != nil || !revoked {
		t.Errorf("isNKeyRevoked = %v, %v", revoked, err)
	}

	// The revocation outlives any further rebuild of the Account, and
	// the same NKey can't be brought back through the legacy register
	// and accept path.
	if err := ReloadNKeys(); err != nil {
		t.Fatal(err)
	}
	if err := UnacceptNKey(tenant, "web", nkey); err != nil {
		t.Fatal(err)
	}
	if err := AcceptNKey(tenant, "web"); !errors.Is(err, ErrNKeyRevoked) {
		t.Fatalf("accepting a revoked NKey: %v, want ErrNKeyRevoked", err)
	}
	if nc, err := dialAsSprout(t, userJWT, seed); err == nil {
		nc.Close()
		t.Fatal("the deleted sprout's User JWT connects after a rebuild")
	}
}

// The revoked list is applied to a per-tenant Account too, and survives a
// rebuild of it.
func TestDeleteNKey_PerTenantAccountCarriesRevocation(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	const tenant = "t_del"
	nkey, _ := newUserNKey(t)
	if err := acceptEnrolledNKey(tenant, "web", nkey); err != nil {
		t.Fatal(err)
	}
	if err := DeleteNKey(tenant, "web"); err != nil {
		t.Fatal(err)
	}
	for _, when := range []string{"after delete", "after a rebuild"} {
		b, err := os.ReadFile(tenantAccountJWTPath(tenant))
		if err != nil {
			t.Fatal(err)
		}
		ac, err := jwt.DecodeAccountClaims(string(b))
		if err != nil {
			t.Fatal(err)
		}
		if !ac.IsClaimRevoked(&jwt.UserClaims{ClaimsData: jwt.ClaimsData{Subject: nkey, IssuedAt: time.Now().Add(-time.Minute).Unix()}}) {
			t.Errorf("%s: the deleted sprout's NKey isn't revoked on %s's Account", when, tenant)
		}
		_ = ReloadNKeysForTenant(tenant)
	}
}

func TestApplyRevokedNKeys(t *testing.T) {
	ac := jwt.NewAccountClaims("A")
	if !applyRevokedNKeys(ac, map[string]int64{"U1": 100}) || ac.Revocations["U1"] != 100 {
		t.Fatalf("revocations %v", ac.Revocations)
	}
	if applyRevokedNKeys(ac, map[string]int64{"U1": 100}) {
		t.Error("re-applying the same revocation reported a change")
	}
	ac.Revocations["U1"] = 200 // a later revocation (e.g. a deny) is kept
	if applyRevokedNKeys(ac, map[string]int64{"U1": 100}) || ac.Revocations["U1"] != 200 {
		t.Errorf("revocations %v", ac.Revocations)
	}
}

// Replacing a sprout by accepting <base>_<n> (H1): the old host's NKey is
// revoked and its box key revoked, and the new host's box key moves to
// <base>, the only active one.
func TestAcceptNKey_ReplaceRetiresOldHost(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	setupTenantBoxOpenBao(t)
	defer startTestBus(t)()
	tenant := currentTenantID()

	oldJWT, oldSeed := acceptTestSprout(t, "web")
	oldNKey, _ := GetNKey(tenant, "web")
	oldBox, newBox := newTestSproutBox(t), newTestSproutBox(t)
	if err := upsertSproutBoxKeyActive(tenant, "web", oldBox.b64()); err != nil {
		t.Fatal(err)
	}
	newNKey, newSeed := newUserNKey(t)
	writeKey(t, "unaccepted", "web_1", newNKey)
	if err := upsertSproutBoxKeyActive(tenant, "web_1", newBox.b64()); err != nil {
		t.Fatal(err)
	}

	if err := AcceptNKey(tenant, "web_1"); err != nil {
		t.Fatalf("AcceptNKey(web_1): %v", err)
	}

	if got, _ := GetNKey(tenant, "web"); got != newNKey {
		t.Errorf("web's NKey is %s, want the new host's", got)
	}
	if _, err := GetNKey(tenant, "web_1"); !errors.Is(err, ErrSproutIDNotFound) {
		t.Errorf("web_1 still on record: %v", err)
	}
	if revoked, _ := isNKeyRevoked(tenant, oldNKey); !revoked {
		t.Error("the replaced host's NKey isn't revoked")
	}
	if revoked, _ := isNKeyRevoked(tenant, newNKey); revoked {
		t.Error("the new host's NKey was revoked")
	}
	if got := activeRows(t, tenant, "web"); len(got) != 1 || got[0] != newBox.b64() {
		t.Errorf("web's active box keys %v, want only the new host's", got)
	}
	if rows := boxKeyRows(t, tenant, "web_1"); len(rows) != 0 {
		t.Errorf("web_1 still has box key rows: %+v", rows)
	}
	if active, _, err := ValidSproutBoxKeys(tenant, "web"); err != nil || active != newBox.b64() {
		t.Errorf("ValidSproutBoxKeys(web) = %s, %v", active, err)
	}
	oldReply := sealAsTestSprout(t, tenant, "web", payloadbox.PurposeCmdRunResponse, oldBox, "ok")
	if _, err := OpenFromSprout(tenant, "web", payloadbox.PurposeCmdRunResponse, oldReply); !errors.Is(err, payloadbox.ErrOpen) {
		t.Errorf("the replaced host's payload: %v, want ErrOpen", err)
	}

	if nc, err := dialAsSprout(t, oldJWT, oldSeed); err == nil {
		nc.Close()
		t.Error("the replaced host's User JWT still connects")
	}
	newJWT, err := GetSproutUserJWT("web")
	if err != nil {
		t.Fatal(err)
	}
	nc, err := dialAsSprout(t, newJWT, newSeed)
	if err != nil {
		t.Fatalf("the new host can't connect as web: %v", err)
	}
	nc.Close()
}

// A sprout ID freed by delete enrols again (H1): the new host gets the
// ID, a fresh NKey and box key, and exactly one active box key; the old
// host's NKey can't enrol again.
func TestEnroll_ReusedSproutIDHasExactlyOneActiveKey(t *testing.T) {
	store, _ := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 5}

	// Each host completes enrollment the way the client does (SEC.3b):
	// the first request issues the identity, and the second, carrying
	// proof of possession of the box key, records it.
	enrollProven := func(kp nkeys.KeyPair) (string, *EnrollResult) {
		t.Helper()
		k := newTestSproutBox(t)
		first, err := Enroll(t.Context(), signedEnroll(t, kp, "ek_1.s", "web-01", k.b64()))
		if err != nil {
			t.Fatalf("Enroll: %v", err)
		}
		proof := enrollProof(t, "t_1", first.SproutID, first.TenantX25519Pub, testNKeyPub(t, kp), k.b64(), k.priv)
		if _, err := Enroll(t.Context(), provenEnroll(t, kp, k.b64(), proof, first.EnrollBinding)); err != nil {
			t.Fatalf("proven Enroll: %v", err)
		}
		return k.b64(), first
	}

	oldKP := testEnrollNKey(t)
	oldBox, res := enrollProven(oldKP)
	if res.SproutID != "web-01" {
		t.Fatalf("first Enroll got sprout %s, want web-01", res.SproutID)
	}
	if got := activeRows(t, "t_1", "web-01"); len(got) != 1 || got[0] != oldBox {
		t.Fatalf("active box keys %v, want exactly the old host's", got)
	}
	if err := DeleteNKey("t_1", "web-01"); err != nil {
		t.Fatal(err)
	}
	if _, err := Enroll(t.Context(), signedEnroll(t, oldKP, "ek_1.s", "web-01", testEnrollBoxPub(t))); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("the deleted host's NKey enrolled again: %v", err)
	}
	if store.rows["ek_1"].UsedCount != 1 {
		t.Errorf("a refused revoked NKey consumed a use: used_count=%d", store.rows["ek_1"].UsedCount)
	}

	newBox, res := enrollProven(testEnrollNKey(t))
	if res.SproutID != "web-01" {
		t.Errorf("the freed ID wasn't reused: got %s", res.SproutID)
	}
	if got := activeRows(t, "t_1", "web-01"); len(got) != 1 || got[0] != newBox {
		t.Errorf("active box keys %v, want exactly the new host's", got)
	}
	if active, _, err := ValidSproutBoxKeys("t_1", "web-01"); err != nil || active != newBox {
		t.Errorf("ValidSproutBoxKeys = %s, %v", active, err)
	}
}

// Dotted hostnames enrol with dashes (M4); a reserved one is refused
// without consuming the token.
func TestEnroll_DottedAndReservedHostnames(t *testing.T) {
	store, _ := setupEnrollTest(t)
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 5}

	res, err := Enroll(t.Context(), signedEnroll(t, testEnrollNKey(t), "ek_1.s", "ip-10-0-0-5.ec2.internal", testEnrollBoxPub(t)))
	if err != nil {
		t.Fatal(err)
	}
	if res.SproutID != "ip-10-0-0-5-ec2-internal" {
		t.Errorf("dotted hostname enrolled as %q", res.SproutID)
	}
	uc, err := jwt.DecodeUserClaims(res.JWT)
	if err != nil {
		t.Fatal(err)
	}
	if !uc.Sub.Allow.Contains("imas.sprouts.ip-10-0-0-5-ec2-internal.>") {
		t.Errorf("grants %v", uc.Sub.Allow)
	}
	// The short name is a different sprout and gets its own ID.
	short, err := Enroll(t.Context(), signedEnroll(t, testEnrollNKey(t), "ek_1.s", "ip-10-0-0-5", testEnrollBoxPub(t)))
	if err != nil || short.SproutID != "ip-10-0-0-5" {
		t.Fatalf("short hostname: %+v, %v", short, err)
	}

	used := store.rows["ek_1"].UsedCount
	if _, err := Enroll(t.Context(), signedEnroll(t, testEnrollNKey(t), "ek_1.s", "announce", testEnrollBoxPub(t))); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("hostname announce: %v, want ErrEnrollmentFailed", err)
	}
	if store.rows["ek_1"].UsedCount != used {
		t.Error("a refused reserved hostname consumed a use")
	}
}

// Enrolling a key over another active key for the same ID revokes the old
// one: exactly one active key.
func TestUpsertSproutBoxKeyActive_RevokesOtherActiveKeys(t *testing.T) {
	setupTestPKI(t)
	pub1, pub2 := testBoxPub(t), testBoxPub(t)
	if err := upsertSproutBoxKeyActive("t_a", "web", pub1); err != nil {
		t.Fatal(err)
	}
	if err := upsertSproutBoxKeyActive("t_a", "web", pub2); err != nil {
		t.Fatal(err)
	}
	if got := activeRows(t, "t_a", "web"); len(got) != 1 || got[0] != pub2 {
		t.Errorf("active %v, want only %s", got, pub2)
	}
	for _, r := range boxKeyRows(t, "t_a", "web") {
		if r.Pub == pub1 && r.State != boxKeyStateRevoked {
			t.Errorf("the replaced key is %q, want revoked", r.State)
		}
	}
	// Another tenant's same-named sprout is untouched.
	if err := upsertSproutBoxKeyActive("t_b", "web", pub1); err != nil {
		t.Fatal(err)
	}
	if got := activeRows(t, "t_a", "web"); len(got) != 1 || got[0] != pub2 {
		t.Errorf("t_a's active keys after t_b's enrollment: %v", got)
	}
}

// The schema itself refuses a second active row, and an active row
// without its slot (or an inactive one with it).
func TestSproutBoxKeys_SchemaAllowsOneActiveRow(t *testing.T) {
	setupTestPKI(t)
	if err := upsertSproutBoxKeyActive("t_a", "web", testBoxPub(t)); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(newActiveBoxKeyRow("t_a", "web", testBoxPub(t))).Error; err == nil {
		t.Error("a second active row was accepted")
	}
	if err := db.Create(&sproutBoxKeyRow{TenantID: "t_a", SproutID: "web", Pub: testBoxPub(t), State: boxKeyStateActive}).Error; err == nil {
		t.Error("an active row without active_slot was accepted")
	}
	slot := boxKeyActiveSlot
	if err := db.Create(&sproutBoxKeyRow{TenantID: "t_a", SproutID: "web", Pub: testBoxPub(t), State: boxKeyStateRevoked, ActiveSlot: &slot}).Error; err == nil {
		t.Error("a revoked row with active_slot was accepted")
	}
	// Any number of inactive rows, and other sprouts' active rows, fit.
	for range 3 {
		if err := db.Create(&sproutBoxKeyRow{TenantID: "t_a", SproutID: "web", Pub: testBoxPub(t), State: boxKeyStateRevoked}).Error; err != nil {
			t.Fatal(err)
		}
	}
	for _, k := range [][2]string{{"t_a", "db"}, {"t_b", "web"}} {
		if err := db.Create(newActiveBoxKeyRow(k[0], k[1], testBoxPub(t))).Error; err != nil {
			t.Fatalf("active row for %v: %v", k, err)
		}
	}
}

// If two rows are somehow active, nothing is sealed to or opened from the
// sprout.
func TestValidSproutBoxKeys_FailsClosedOnTwoActiveRows(t *testing.T) {
	gdb := newTestDB(t)
	// Stand in for a schema without the constraint.
	if err := gdb.Exec("DROP INDEX idx_pki_sprout_box_keys_one_active").Error; err != nil {
		t.Fatal(err)
	}
	pub1, pub2 := testBoxPub(t), testBoxPub(t)
	for _, p := range []string{pub1, pub2} {
		if err := db.Create(newActiveBoxKeyRow("t_a", "web", p)).Error; err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := ValidSproutBoxKeys("t_a", "web"); !errors.Is(err, ErrMultipleActiveBoxKeys) {
		t.Errorf("ValidSproutBoxKeys: %v, want ErrMultipleActiveBoxKeys", err)
	}
	if _, err := OpenFromSprout("t_a", "web", payloadbox.PurposeCmdRunResponse, []byte("{}")); !errors.Is(err, ErrMultipleActiveBoxKeys) {
		t.Errorf("OpenFromSprout: %v, want ErrMultipleActiveBoxKeys", err)
	}
	if _, _, err := SealToSprout("t_a", "web", payloadbox.PurposeCmdRunRequest, "", "x"); !errors.Is(err, ErrMultipleActiveBoxKeys) {
		t.Errorf("SealToSprout: %v, want ErrMultipleActiveBoxKeys", err)
	}
	if err := RecordSproutBoxKeySubmission("t_a", "web", pub1, testBoxPub(t), time.Hour); !errors.Is(err, ErrMultipleActiveBoxKeys) {
		t.Errorf("RecordSproutBoxKeySubmission: %v, want ErrMultipleActiveBoxKeys", err)
	}
}

// M3: only a submission sealed under the active key rotates; one sealed
// under a grace key may only re-assert the active key.
func TestRecordSproutBoxKeySubmission_OnlyActiveKeyRotates(t *testing.T) {
	setupTestPKI(t)
	k1, k2, k3 := testBoxPub(t), testBoxPub(t), testBoxPub(t)
	if err := upsertSproutBoxKeyActive("t_a", "web", k1); err != nil {
		t.Fatal(err)
	}
	if err := RecordSproutBoxKeySubmission("t_a", "web", k1, k2, time.Hour); err != nil {
		t.Fatalf("submission under the active key: %v", err)
	}
	// k1 is now in grace. A leaked k1 can't name its own key.
	if err := RecordSproutBoxKeySubmission("t_a", "web", k1, k3, time.Hour); !errors.Is(err, ErrBoxKeySubmissionNotActive) {
		t.Errorf("submission under a grace key: %v, want ErrBoxKeySubmissionNotActive", err)
	}
	// A retry of the recorded submission, still sealed under k1.
	if err := RecordSproutBoxKeySubmission("t_a", "web", k1, k2, time.Hour); err != nil {
		t.Errorf("a grace key re-asserting the active key: %v", err)
	}
	active, grace, err := ValidSproutBoxKeys("t_a", "web")
	if err != nil || active != k2 || len(grace) != 1 || grace[0] != k1 {
		t.Errorf("after: active %s grace %v err %v; want %s, [%s]", active, grace, err, k2, k1)
	}
	if err := RecordSproutBoxKeySubmission("t_a", "web", testBoxPub(t), k3, time.Hour); !errors.Is(err, ErrBoxKeySubmissionNotActive) {
		t.Errorf("submission under an unknown key: %v", err)
	}
	if err := RecordSproutBoxKeySubmission("t_a", "nobody", k1, k3, time.Hour); !errors.Is(err, ErrNoActiveBoxKey) {
		t.Errorf("submission for a sprout with no key: %v", err)
	}
}

// OpenBoxKeySubmission reports which of the sprout's keys opened the
// submission.
func TestOpenBoxKeySubmission_ReportsKey(t *testing.T) {
	setupTestPKI(t)
	setupTenantBoxOpenBao(t)
	k1, k2 := newTestSproutBox(t), newTestSproutBox(t)
	if err := upsertSproutBoxKeyActive("t_a", "web", k1.b64()); err != nil {
		t.Fatal(err)
	}
	if err := RotateSproutBoxKey("t_a", "web", k2.b64(), time.Hour); err != nil {
		t.Fatal(err)
	}
	for _, k := range []testSproutBox{k2, k1} {
		data := sealAsTestSprout(t, "t_a", "web", payloadbox.PurposeBoxKeySubmit, k, map[string]string{"pub": "x"})
		if _, under, err := OpenBoxKeySubmission("t_a", "web", data); err != nil || under != k.b64() {
			t.Errorf("opened under %s, %v; want %s", under, err, k.b64())
		}
	}
	stranger := sealAsTestSprout(t, "t_a", "web", payloadbox.PurposeBoxKeySubmit, newTestSproutBox(t), nil)
	if _, _, err := OpenBoxKeySubmission("t_a", "web", stranger); !errors.Is(err, payloadbox.ErrOpen) {
		t.Errorf("unknown key: %v, want ErrOpen", err)
	}
	wrongPurpose := sealAsTestSprout(t, "t_a", "web", payloadbox.PurposeCmdRunResponse, k2, nil)
	if _, _, err := OpenBoxKeySubmission("t_a", "web", wrongPurpose); !errors.Is(err, payloadbox.ErrOpen) {
		t.Errorf("wrong purpose: %v, want ErrOpen", err)
	}
}
