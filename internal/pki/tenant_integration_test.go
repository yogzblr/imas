package pki

// Integration coverage for dynamic tenant Account provisioning (tenant.go)
// against a real, local embedded nats-server — the multi-tenant
// counterpart to jwt_integration_test.go's single-tenant lifecycle
// coverage. Proves ProvisionTenant/ReloadNKeysForTenant/DeprovisionTenant
// don't just write local files but actually change what the bus accepts,
// and that two dynamically-provisioned tenants are genuinely isolated from
// each other (FLAG FOR SECURITY REVIEW: tenant isolation correctness).

import (
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
)

// TestReloadNKeysForTenant_LazyProvisionsAndConnects covers the path
// enroll.go's acceptEnrolledNKey actually exercises: a sprout accepted
// under a tenant ID that has never been provisioned before gets that
// tenant's Account created and pushed to the bus on the spot, and the
// sprout's freshly-minted User JWT is immediately valid against the live
// server.
func TestReloadNKeysForTenant_LazyProvisionsAndConnects(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	defer startTestBus(t)()

	sproutKP, _ := nkeys.CreateUser()
	sproutPub, _ := sproutKP.PublicKey()
	sproutSeed, _ := sproutKP.Seed()

	const tenantID = "t_lazy"
	if err := upsertNKeyRow(nkeyRow{TenantID: tenantID, SproutID: "web-01", NKey: sproutPub, State: stateAccepted}); err != nil {
		t.Fatalf("upsertNKeyRow: %v", err)
	}
	if err := ReloadNKeysForTenant(tenantID); err != nil {
		t.Fatalf("ReloadNKeysForTenant: %v", err)
	}

	row, err := getTenantRow(tenantID)
	if err != nil || row.Deleted {
		t.Fatalf("expected tenant %q to be provisioned, row=%+v err=%v", tenantID, row, err)
	}

	sproutJWT, err := GetSproutUserJWTForTenant(tenantID, "web-01")
	if err != nil {
		t.Fatalf("GetSproutUserJWTForTenant: %v", err)
	}
	nc, err := dialAsSprout(t, sproutJWT, sproutSeed)
	if err != nil {
		t.Fatalf("expected lazily-provisioned tenant's sprout to connect, got: %v", err)
	}
	nc.Close()
}

// TestProvisionTenant_TwoTenantsAreIsolatedAccounts provisions two tenants
// explicitly (the internal.tenant.provision-shaped path, once that's wired
// up) and proves each gets a sprout identity the *other* tenant's Account
// does not vouch for: dialing tenant B's sprout JWT/seed succeeds, but that
// same JWT can never be confused with tenant A's — they're signed by
// different Accounts, which is what "isolation enforced by which Account a
// connection authenticated into" actually rests on.
func TestProvisionTenant_TwoTenantsAreIsolatedAccounts(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	defer startTestBus(t)()

	if err := ProvisionTenant("t_a", "Tenant A"); err != nil {
		t.Fatalf("ProvisionTenant(t_a): %v", err)
	}
	if err := ProvisionTenant("t_b", "Tenant B"); err != nil {
		t.Fatalf("ProvisionTenant(t_b): %v", err)
	}

	tamA, err := loadTenantAccountMaterial("t_a")
	if err != nil {
		t.Fatalf("loadTenantAccountMaterial(t_a): %v", err)
	}
	tamB, err := loadTenantAccountMaterial("t_b")
	if err != nil {
		t.Fatalf("loadTenantAccountMaterial(t_b): %v", err)
	}
	if tamA.pub == tamB.pub {
		t.Fatal("expected tenant A and tenant B to have distinct Account public keys")
	}

	sproutKP, _ := nkeys.CreateUser()
	sproutPub, _ := sproutKP.PublicKey()
	sproutSeed, _ := sproutKP.Seed()
	if err := upsertNKeyRow(nkeyRow{TenantID: "t_b", SproutID: "web-01", NKey: sproutPub, State: stateAccepted}); err != nil {
		t.Fatalf("upsertNKeyRow: %v", err)
	}
	if err := ReloadNKeysForTenant("t_b"); err != nil {
		t.Fatalf("ReloadNKeysForTenant(t_b): %v", err)
	}
	sproutJWT, err := GetSproutUserJWTForTenant("t_b", "web-01")
	if err != nil {
		t.Fatalf("GetSproutUserJWTForTenant: %v", err)
	}

	nc, err := dialAsSprout(t, sproutJWT, sproutSeed)
	if err != nil {
		t.Fatalf("expected tenant B's sprout to connect under tenant B's own Account: %v", err)
	}
	nc.Close()
}

// TestDeprovisionTenant_RevokesLiveBusAccess is the security-critical
// counterpart to ProvisionTenant: once a tenant is deprovisioned, a sprout
// that could connect a moment ago under that tenant's Account must be
// rejected — the same "revocation takes effect immediately" property
// jwt_integration_test.go proves for the legacy single-tenant Deny/Reject
// path, here for a dynamically-provisioned tenant's Account as a whole.
func TestDeprovisionTenant_RevokesLiveBusAccess(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	defer startTestBus(t)()

	const tenantID = "t_offboarding"
	if err := ProvisionTenant(tenantID, "Offboarding Co"); err != nil {
		t.Fatalf("ProvisionTenant: %v", err)
	}

	sproutKP, _ := nkeys.CreateUser()
	sproutPub, _ := sproutKP.PublicKey()
	sproutSeed, _ := sproutKP.Seed()
	if err := upsertNKeyRow(nkeyRow{TenantID: tenantID, SproutID: "web-01", NKey: sproutPub, State: stateAccepted}); err != nil {
		t.Fatalf("upsertNKeyRow: %v", err)
	}
	if err := ReloadNKeysForTenant(tenantID); err != nil {
		t.Fatalf("ReloadNKeysForTenant: %v", err)
	}
	sproutJWT, err := GetSproutUserJWTForTenant(tenantID, "web-01")
	if err != nil {
		t.Fatalf("GetSproutUserJWTForTenant: %v", err)
	}

	if nc, err := dialAsSprout(t, sproutJWT, sproutSeed); err != nil {
		t.Fatalf("expected sprout to connect before deprovisioning: %v", err)
	} else {
		nc.Close()
	}

	if err := DeprovisionTenant(tenantID); err != nil {
		t.Fatalf("DeprovisionTenant: %v", err)
	}

	if _, err := dialAsSprout(t, sproutJWT, sproutSeed); err == nil {
		t.Fatal("expected the same sprout JWT to be rejected after its tenant was deprovisioned")
	}
}

// TestDeprovisionTenant_LatePushStillLocksOut is the regression test for
// deprovisioning by Expires = now: a running nats-server rejects an update
// to an already-loaded Account whose exp is in the past, so a push that
// reached the bus a second or more after signing was dropped and the
// tenant stayed connected. This signs the lockout, waits past the next
// second boundary, and only then pushes it. The bus must still close the
// sprout's live connection, refuse that sprout reconnecting, and refuse a
// User JWT minted under the Account after deprovisioning.
func TestDeprovisionTenant_LatePushStillLocksOut(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	defer startTestBus(t)()

	const tenantID = "t_late_push"
	if err := ProvisionTenant(tenantID, "Late Push Co"); err != nil {
		t.Fatalf("ProvisionTenant: %v", err)
	}
	sproutKP, _ := nkeys.CreateUser()
	sproutPub, _ := sproutKP.PublicKey()
	sproutSeed, _ := sproutKP.Seed()
	if err := upsertNKeyRow(nkeyRow{TenantID: tenantID, SproutID: "web-01", NKey: sproutPub, State: stateAccepted}); err != nil {
		t.Fatalf("upsertNKeyRow: %v", err)
	}
	if err := ReloadNKeysForTenant(tenantID); err != nil {
		t.Fatalf("ReloadNKeysForTenant: %v", err)
	}
	sproutJWT, err := GetSproutUserJWTForTenant(tenantID, "web-01")
	if err != nil {
		t.Fatalf("GetSproutUserJWTForTenant: %v", err)
	}

	// A sprout that stays connected across the deprovisioning.
	closed := make(chan struct{})
	live, err := dialAsSprout(t, sproutJWT, sproutSeed,
		nats.NoReconnect(),
		nats.ClosedHandler(func(*nats.Conn) { close(closed) }),
	)
	if err != nil {
		t.Fatalf("expected sprout to connect before deprovisioning: %v", err)
	}
	defer live.Close()

	mat, err := ensureNatsAuth()
	if err != nil {
		t.Fatalf("ensureNatsAuth: %v", err)
	}
	signed, _, err := deprovisionTenantLocked(mat, tenantID)
	if err != nil {
		t.Fatalf("deprovisionTenantLocked: %v", err)
	}
	// The failure mode needs the push to land in a later wall-clock second
	// than the signing; 1.1s guarantees that.
	time.Sleep(1100 * time.Millisecond)
	if err := pushAccountUpdate(mat, signed); err != nil {
		t.Fatalf("pushAccountUpdate: %v", err)
	}

	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("expected the bus to close the sprout's live connection after a late push")
	}
	if nc, err := dialAsSprout(t, sproutJWT, sproutSeed); err == nil {
		nc.Close()
		t.Fatal("expected the sprout's JWT to be rejected after its tenant was deprovisioned")
	}

	// A User JWT issued after the revocation isn't covered by it; the
	// Account's connection limit of 0 must refuse it anyway.
	tam, err := loadTenantAccountMaterial(tenantID)
	if err != nil {
		t.Fatalf("loadTenantAccountMaterial: %v", err)
	}
	freshKP, _ := nkeys.CreateUser()
	freshPub, _ := freshKP.PublicKey()
	freshSeed, _ := freshKP.Seed()
	uc := jwt.NewUserClaims(freshPub)
	uc.IssuerAccount = tam.pub
	freshJWT, err := uc.Encode(tam.signingKP)
	if err != nil {
		t.Fatalf("minting fresh User JWT: %v", err)
	}
	if nc, err := dialAsSprout(t, freshJWT, freshSeed); err == nil {
		nc.Close()
		t.Fatal("expected a User JWT minted after deprovisioning to be rejected too")
	}
}

// TestDeprovisionTenant_RetryAfterFailedPushLocksOut: the tenant is marked
// deleted before the lock-out is pushed, so when no bus node takes the
// push (every node down, or fenced by cmd/farmerbus during a partition)
// the retry is the only thing left that can lock the tenant out. It must
// push again rather than report "already deprovisioned" and leave the
// tenant live.
func TestDeprovisionTenant_RetryAfterFailedPushLocksOut(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	defer startTestBus(t)()

	const tenantID = "t_retry_lockout"
	if err := ProvisionTenant(tenantID, "Retry Co"); err != nil {
		t.Fatalf("ProvisionTenant: %v", err)
	}
	sproutKP, _ := nkeys.CreateUser()
	sproutPub, _ := sproutKP.PublicKey()
	sproutSeed, _ := sproutKP.Seed()
	if err := upsertNKeyRow(nkeyRow{TenantID: tenantID, SproutID: "web-01", NKey: sproutPub, State: stateAccepted}); err != nil {
		t.Fatalf("upsertNKeyRow: %v", err)
	}
	if err := ReloadNKeysForTenant(tenantID); err != nil {
		t.Fatalf("ReloadNKeysForTenant: %v", err)
	}
	sproutJWT, err := GetSproutUserJWTForTenant(tenantID, "web-01")
	if err != nil {
		t.Fatalf("GetSproutUserJWTForTenant: %v", err)
	}

	// The bus is unreachable for the first attempt.
	busURL := config.FarmerBusURL
	config.FarmerBusURL = "127.0.0.1:1"
	if err := DeprovisionTenant(tenantID); err == nil {
		t.Fatal("expected DeprovisionTenant to fail while the bus is unreachable")
	}
	config.FarmerBusURL = busURL
	if nc, err := dialAsSprout(t, sproutJWT, sproutSeed); err != nil {
		t.Fatalf("precondition: the failed push should have left the tenant live on the bus: %v", err)
	} else {
		nc.Close()
	}

	if err := DeprovisionTenant(tenantID); err != nil {
		t.Fatalf("retrying DeprovisionTenant: %v", err)
	}
	if nc, err := dialAsSprout(t, sproutJWT, sproutSeed); err == nil {
		nc.Close()
		t.Fatal("the retry left the deprovisioned tenant live on the bus")
	}
	// And a third call is a harmless re-push of a lock-out.
	if err := DeprovisionTenant(tenantID); err != nil {
		t.Fatalf("re-pushing an existing lock-out: %v", err)
	}
}

// TestDeprovisionTenant_LockOutHasNewerIssuedAt: the lock-out must carry a
// strictly newer iat (and therefore a different jti) than the live JWT it
// replaces, even when signed in the same second, or a clustered bus node
// still holding the live JWT would treat the lock-out as a JWT it already
// has (see waitPastIssuedAt).
func TestDeprovisionTenant_LockOutHasNewerIssuedAt(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	defer startTestBus(t)()

	const tenantID = "t_same_second"
	if err := ProvisionTenant(tenantID, "Same Second Co"); err != nil {
		t.Fatalf("ProvisionTenant: %v", err)
	}
	tam, err := loadTenantAccountMaterial(tenantID)
	if err != nil {
		t.Fatal(err)
	}
	live, err := jwt.DecodeAccountClaims(tam.jwt)
	if err != nil {
		t.Fatal(err)
	}
	if err := DeprovisionTenant(tenantID); err != nil {
		t.Fatalf("DeprovisionTenant: %v", err)
	}
	tam, err = loadTenantAccountMaterial(tenantID)
	if err != nil {
		t.Fatal(err)
	}
	locked, err := jwt.DecodeAccountClaims(tam.jwt)
	if err != nil {
		t.Fatal(err)
	}
	if !isLockedOut(locked) {
		t.Fatal("stored Account JWT is not locked out")
	}
	if locked.IssuedAt <= live.IssuedAt || locked.ID == live.ID {
		t.Fatalf("lock-out iat=%d jti=%s, live iat=%d jti=%s: want a strictly newer iat and a new jti",
			locked.IssuedAt, locked.ID, live.IssuedAt, live.ID)
	}
}
