package pki

import (
	"strings"
	"testing"

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
	tenantJWT, err := GetSproutUserJWTForTenant("t_race", "web-01")
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
