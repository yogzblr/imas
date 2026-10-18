package pki

import (
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
)

// A deny racing PushAllAccounts: the deny re-signs the Account JWT and
// pushes it after PushAllAccounts read the old one but before that old
// copy reaches the bus. The bus applies pushes in arrival order, so
// without the re-read after the push the old copy would undo the
// revocation, and the denied sprout would get back in.
func TestPushAllAccounts_DenyRacingThePushStaysDenied(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	defer startTestBus(t)()

	accept := func(tenantID, sproutID string) []byte {
		kp, _ := nkeys.CreateUser()
		pub, _ := kp.PublicKey()
		seed, _ := kp.Seed()
		if err := upsertNKeyRow(nkeyRow{TenantID: tenantID, SproutID: sproutID, NKey: pub, State: stateAccepted}); err != nil {
			t.Fatal(err)
		}
		return seed
	}
	legacy := currentTenantID()
	legacySeed := accept(legacy, "web-legacy")
	if err := ReloadNKeys(); err != nil {
		t.Fatalf("ReloadNKeys: %v", err)
	}
	legacyJWT, err := GetSproutUserJWT("web-legacy")
	if err != nil {
		t.Fatal(err)
	}
	if err := ProvisionTenant("t_race", "Race Co"); err != nil {
		t.Fatalf("ProvisionTenant: %v", err)
	}
	tenantSeed := accept("t_race", "web-01")
	if err := ReloadNKeysForTenant("t_race"); err != nil {
		t.Fatalf("ReloadNKeysForTenant: %v", err)
	}
	tenantJWT, err := sproutUserJWTForTest("t_race", "web-01")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		jwt  string
		seed []byte
	}{{legacyJWT, legacySeed}, {tenantJWT, tenantSeed}} {
		nc, err := dialAsSprout(t, c.jwt, c.seed)
		if err != nil {
			t.Fatalf("precondition: sprout refused before the deny: %v", err)
		}
		nc.Close()
	}

	denied := map[string]bool{}
	testHookPushAllBeforePush = func(what string) {
		var err error
		switch {
		case strings.HasPrefix(what, "legacy tenant") && !denied[what]:
			if err = setStateInTenant(legacy, "web-legacy", stateDenied); err == nil {
				err = ReloadNKeys()
			}
		case what == "tenant t_race" && !denied[what]:
			if err = setStateInTenant("t_race", "web-01", stateDenied); err == nil {
				err = ReloadNKeysForTenant("t_race")
			}
		default:
			return
		}
		denied[what] = true
		if err != nil {
			t.Errorf("concurrent deny of %s: %v", what, err)
		}
	}
	t.Cleanup(func() { testHookPushAllBeforePush = nil })

	if _, err := PushAllAccounts(); err != nil {
		t.Fatalf("PushAllAccounts: %v", err)
	}
	if len(denied) != 2 {
		t.Fatalf("the concurrent deny ran for %v, want the legacy tenant and t_race", denied)
	}
	if nc, err := dialAsSprout(t, legacyJWT, legacySeed); err == nil {
		nc.Close()
		t.Error("legacy sprout denied during PushAllAccounts was re-admitted by its older push")
	}
	if nc, err := dialAsSprout(t, tenantJWT, tenantSeed); err == nil {
		nc.Close()
		t.Error("t_race sprout denied during PushAllAccounts was re-admitted by its older push")
	}
}

// Security review 2026-10, I9: after a restore from an older backup the
// Account JWT core holds predates revocations the database records (here:
// a legacy sprout denied, and a tenant sprout deleted, with the database
// written directly and nothing re-signed). PushAllAccounts re-syncs each
// tenant from the database before pushing, so the stale JWT does not
// re-admit either sprout.
func TestPushAllAccounts_StaleJWTDoesNotReadmitRevokedSprout(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	defer startTestBus(t)()

	accept := func(tenantID, sproutID string) (string, []byte) {
		kp, _ := nkeys.CreateUser()
		pub, _ := kp.PublicKey()
		seed, _ := kp.Seed()
		if err := upsertNKeyRow(nkeyRow{TenantID: tenantID, SproutID: sproutID, NKey: pub, State: stateAccepted}); err != nil {
			t.Fatal(err)
		}
		return pub, seed
	}
	legacy := currentTenantID()
	_, legacySeed := accept(legacy, "web-legacy")
	if err := ReloadNKeys(); err != nil {
		t.Fatalf("ReloadNKeys: %v", err)
	}
	legacyJWT, err := GetSproutUserJWT("web-legacy")
	if err != nil {
		t.Fatal(err)
	}
	if err := ProvisionTenant("t_restore", "Restore Co"); err != nil {
		t.Fatalf("ProvisionTenant: %v", err)
	}
	tenantPub, tenantSeed := accept("t_restore", "web-01")
	if err := ReloadNKeysForTenant("t_restore"); err != nil {
		t.Fatalf("ReloadNKeysForTenant: %v", err)
	}
	tenantJWT, err := sproutUserJWTForTest("t_restore", "web-01")
	if err != nil {
		t.Fatal(err)
	}
	staleLegacy, staleTenant := heldTenantAccountJWT(t, legacy), heldTenantAccountJWT(t, "t_restore")

	// The database moves on without the Account JWTs being re-signed.
	if err := db.Model(&nkeyRow{}).Where("tenant_id = ? AND sprout_id = ?", legacy, "web-legacy").
		Update("state", stateDenied).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Where("tenant_id = ? AND sprout_id = ?", "t_restore", "web-01").Delete(&nkeyRow{}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&revokedNKeyRow{TenantID: "t_restore", NKey: tenantPub, SproutID: "web-01", RevokedAt: time.Now().Unix()}).Error; err != nil {
		t.Fatal(err)
	}
	if heldTenantAccountJWT(t, legacy) != staleLegacy || heldTenantAccountJWT(t, "t_restore") != staleTenant {
		t.Fatal("precondition: an Account JWT was re-signed by the database writes")
	}
	// The pushall leases of the provisioning above have not lapsed; a
	// reconnect after the restore finds them lapsed.
	pushAllNow = func() time.Time { return time.Now().Add(2 * pushAllMinInterval) }
	t.Cleanup(func() { pushAllNow = time.Now })

	if _, err := PushAllAccounts(); err != nil {
		t.Fatalf("PushAllAccounts: %v", err)
	}
	if nc, err := dialAsSprout(t, legacyJWT, legacySeed); err == nil {
		nc.Close()
		t.Error("the stale legacy Account JWT re-admitted a denied sprout")
	}
	if nc, err := dialAsSprout(t, tenantJWT, tenantSeed); err == nil {
		nc.Close()
		t.Error("the stale t_restore Account JWT re-admitted a deleted sprout")
	}
}
