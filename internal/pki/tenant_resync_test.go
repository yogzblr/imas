package pki

import (
	"reflect"
	"testing"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// A sprout enrolled under an older release holds a User JWT without the
// permissions added since (the heartbeat publish grant). Farmer's startup
// ResyncProvisionedTenants must re-mint it for every provisioned tenant,
// not only the legacy one.
func TestResyncProvisionedTenants_RemintsOldSproutJWTs(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	defer startTestBus(t)()

	for _, tenantID := range []string{"t_one", "t_two"} {
		kp, _ := nkeys.CreateUser()
		pub, _ := kp.PublicKey()
		if err := upsertNKeyRow(nkeyRow{TenantID: tenantID, SproutID: "web-01", NKey: pub, State: stateAccepted}); err != nil {
			t.Fatalf("upsertNKeyRow(%s): %v", tenantID, err)
		}
		if err := ReloadNKeysForTenant(tenantID); err != nil {
			t.Fatalf("ReloadNKeysForTenant(%s): %v", tenantID, err)
		}

		// Overwrite the JWT with one carrying the old permission set.
		_, tam, _, err := ensureTenantAccount(tenantID, "")
		if err != nil {
			t.Fatal(err)
		}
		old := sproutPermissions("web-01")
		old.Pub.Allow = jwt.StringList{"imas.sprouts.announce.web-01", "_INBOX.>"}
		path := sproutJWTPathForTenant(tenantID, "web-01")
		if _, err := mintOrReuseUserJWT(path, pub, "web-01", old, tam.pub, tam.signingKP); err != nil {
			t.Fatal(err)
		}
	}

	if err := ResyncProvisionedTenants(); err != nil {
		t.Fatalf("ResyncProvisionedTenants: %v", err)
	}

	for _, tenantID := range []string{"t_one", "t_two"} {
		raw, err := GetSproutUserJWTForTenant(tenantID, "web-01")
		if err != nil {
			t.Fatal(err)
		}
		claims, err := jwt.DecodeUserClaims(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(claims.Permissions, sproutPermissions("web-01")) {
			t.Errorf("tenant %s: JWT permissions not re-minted: %+v", tenantID, claims.Permissions)
		}
	}
}
