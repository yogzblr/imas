package pki

import (
	"testing"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// Farmer's startup ResyncProvisionedTenants syncs every provisioned
// tenant's Account from PXC, not only the legacy one: on a replica that
// holds nothing yet (a restart, no bucket in this test), each tenant's
// Account JWT comes back carrying its denied sprout's revocation.
func TestResyncProvisionedTenants_SyncsEveryTenant(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	defer startTestBus(t)()

	denied := map[string]string{}
	for _, tenantID := range []string{"t_one", "t_two"} {
		if err := ProvisionTenant(tenantID, tenantID); err != nil {
			t.Fatalf("ProvisionTenant(%s): %v", tenantID, err)
		}
		kp, _ := nkeys.CreateUser()
		pub, _ := kp.PublicKey()
		if err := upsertNKeyRow(nkeyRow{TenantID: tenantID, SproutID: "web-01", NKey: pub, State: "denied"}); err != nil {
			t.Fatalf("upsertNKeyRow(%s): %v", tenantID, err)
		}
		denied[tenantID] = pub
	}
	forgetHeldJWTs()

	if err := ResyncProvisionedTenants(); err != nil {
		t.Fatalf("ResyncProvisionedTenants: %v", err)
	}

	for tenantID, pub := range denied {
		ac, err := jwt.DecodeAccountClaims(heldTenantAccountJWT(t, tenantID))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := ac.Revocations[pub]; !ok {
			t.Errorf("tenant %s: the denied sprout's NKey is not revoked after the resync", tenantID)
		}
	}
}
