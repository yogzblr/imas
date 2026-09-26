package pki

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
)

func TestIsValidTenantID(t *testing.T) {
	valid := []string{"t_1", "t_8f2a", "imas", "a", "A_b-C9"}
	for _, id := range valid {
		if !IsValidTenantID(id) {
			t.Errorf("expected %q to be a valid tenant ID", id)
		}
	}
	invalid := []string{"", "../etc/passwd", "t/1", "t 1", "t.1"}
	for _, id := range invalid {
		if IsValidTenantID(id) {
			t.Errorf("expected %q to be an invalid tenant ID", id)
		}
	}
}

func TestProvisionTenant_InvalidTenantID(t *testing.T) {
	setupTestPKI(t)
	if err := ProvisionTenant("../evil", "Evil Corp"); err == nil {
		t.Fatal("expected ProvisionTenant to reject a malformed tenant ID")
	}
}

// TestEnsureTenantAccount_DistinctAccountsPerTenant proves two different
// tenants get their own, distinct Account keypair and their own on-disk
// namespace — the structural property workstream E's tenant isolation
// rests on (FLAG FOR SECURITY REVIEW).
func TestEnsureTenantAccount_DistinctAccountsPerTenant(t *testing.T) {
	setupTestPKI(t)

	matA, tamA, provisionedA, err := ensureTenantAccount("t_a", "Tenant A")
	if err != nil {
		t.Fatalf("ensureTenantAccount(t_a): %v", err)
	}
	if !provisionedA {
		t.Error("expected t_a to be reported as newly provisioned")
	}
	matB, tamB, provisionedB, err := ensureTenantAccount("t_b", "Tenant B")
	if err != nil {
		t.Fatalf("ensureTenantAccount(t_b): %v", err)
	}
	if !provisionedB {
		t.Error("expected t_b to be reported as newly provisioned")
	}

	if tamA.pub == tamB.pub {
		t.Fatal("expected distinct tenants to get distinct Account public keys")
	}
	if matA.operatorPub != matB.operatorPub {
		t.Error("expected both tenants to share the same platform-wide operator")
	}

	row, err := getTenantRow("t_a")
	if err != nil || row.Name != "Tenant A" {
		t.Errorf("expected pki_tenants row for t_a named %q, got %+v err=%v", "Tenant A", row, err)
	}

	// Calling again must be idempotent: same Account, not re-provisioned.
	_, tamA2, provisionedAgain, err := ensureTenantAccount("t_a", "ignored on repeat")
	if err != nil {
		t.Fatalf("second ensureTenantAccount(t_a): %v", err)
	}
	if provisionedAgain {
		t.Error("expected the second call for an existing tenant to report provisioned=false")
	}
	if tamA2.pub != tamA.pub {
		t.Error("expected the same Account public key across repeated calls")
	}
}

func TestEnsureTenantAccount_RefusesDeletedTenant(t *testing.T) {
	setupTestPKI(t)

	if _, _, _, err := ensureTenantAccount("t_gone", "Gone Inc"); err != nil {
		t.Fatalf("initial provision: %v", err)
	}
	if err := markTenantDeleted("t_gone"); err != nil {
		t.Fatalf("markTenantDeleted: %v", err)
	}
	if _, _, _, err := ensureTenantAccount("t_gone", "Gone Inc"); err == nil {
		t.Fatal("expected ensureTenantAccount to refuse a deprovisioned tenant")
	}
}

func TestSproutJWTPathForTenant_IsolatedPerTenant(t *testing.T) {
	setupTestPKI(t)

	pathA := sproutJWTPathForTenant("t_a", "web-01")
	pathB := sproutJWTPathForTenant("t_b", "web-01")
	if pathA == pathB {
		t.Fatalf("expected the same sprout ID under different tenants to resolve to different paths, both got %q", pathA)
	}
}

func TestGetSproutUserJWTForTenant_FallsBackToLegacyPath(t *testing.T) {
	setupTestPKI(t)
	config.FarmerOrganization = "legacy-tenant"

	// Simulate a sprout accepted through the legacy, current-tenant-only
	// admin path (AcceptNKey/ReloadNKeys/mintOrReuseUserJWT), which writes
	// to sproutJWTPath, not the tenant-scoped sproutJWTPathForTenant.
	if err := os.MkdirAll(sproutJWTDir(), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(sproutJWTPath("legacy-sprout"), []byte("legacy-jwt"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := GetSproutUserJWTForTenant("legacy-tenant", "legacy-sprout")
	if err != nil {
		t.Fatalf("expected legacy fallback to succeed, got err=%v", err)
	}
	if got != "legacy-jwt" {
		t.Errorf("expected the legacy JWT content, got %q", got)
	}

	// A different tenant must NOT see the legacy-tenant's fallback JWT.
	if _, err := GetSproutUserJWTForTenant("other-tenant", "legacy-sprout"); err != ErrSproutIDNotFound {
		t.Errorf("expected ErrSproutIDNotFound for a non-current tenant, got %v", err)
	}
}

func TestDeprovisionTenant_NotFound(t *testing.T) {
	setupTestPKI(t)
	if err := DeprovisionTenant("t_never_existed"); err == nil {
		t.Fatal("expected DeprovisionTenant to fail for an unknown tenant")
	}
}

// TestTenantLookup_NotFoundVsDBError pins the distinction the SaaS API's
// deprovision path relies on (internal/natsapi treats ErrTenantNotFound
// from DeprovisionTenant as "never provisioned, nothing to tear down"):
// only a genuinely absent row is ErrTenantNotFound; a database failure is
// a different error, so it can never be mistaken for a successful
// offboarding while the tenant's Account is still live.
func TestTenantLookup_NotFoundVsDBError(t *testing.T) {
	setupTestPKI(t)

	if _, err := getTenantRow("t_absent"); !errors.Is(err, ErrTenantNotFound) {
		t.Fatalf("getTenantRow(absent) = %v, want ErrTenantNotFound", err)
	}
	if err := DeprovisionTenant("t_absent"); !errors.Is(err, ErrTenantNotFound) {
		t.Fatalf("DeprovisionTenant(absent) = %v, want ErrTenantNotFound", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db.DB(): %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("closing test db: %v", err)
	}
	if _, err := getTenantRow("t_absent"); err == nil || errors.Is(err, ErrTenantNotFound) {
		t.Fatalf("getTenantRow with a broken DB = %v, want a non-ErrTenantNotFound error", err)
	}
	if err := DeprovisionTenant("t_absent"); err == nil || errors.Is(err, ErrTenantNotFound) {
		t.Fatalf("DeprovisionTenant with a broken DB = %v, want a non-ErrTenantNotFound error", err)
	}
	if err := ProvisionTenant("t_absent", "x"); err == nil || errors.Is(err, ErrTenantNotFound) {
		t.Fatalf("ProvisionTenant with a broken DB = %v, want a real lookup error", err)
	}
}

func TestLockOutAccount(t *testing.T) {
	kp, _ := nkeys.CreateAccount()
	pub, _ := kp.PublicKey()
	ac := jwt.NewAccountClaims(pub)
	ac.Expires = 123
	now := time.Unix(1_700_000_000, 0)

	lockOutAccount(ac, now)

	if ac.Expires != 0 {
		t.Errorf("Expires = %d, want 0 (a past exp makes a live server drop the update)", ac.Expires)
	}
	if got := ac.Revocations[jwt.All]; got != now.Unix() {
		t.Errorf("Revocations[*] = %d, want %d", got, now.Unix())
	}
	if ac.Limits.Conn != 0 || ac.Limits.LeafNodeConn != 0 {
		t.Errorf("connection limits = %d/%d, want 0/0", ac.Limits.Conn, ac.Limits.LeafNodeConn)
	}

	// The lockout survives an encode/decode round trip (Conn is omitempty,
	// so 0 must still decode as 0, not as "no limit").
	opKP, _ := nkeys.CreateOperator()
	signed, err := ac.Encode(opKP)
	if err != nil {
		t.Fatal(err)
	}
	back, err := jwt.DecodeAccountClaims(signed)
	if err != nil {
		t.Fatal(err)
	}
	if back.Limits.Conn != 0 || back.Revocations[jwt.All] != now.Unix() || back.Expires != 0 {
		t.Errorf("decoded lockout = conn %d, revoked-at %d, exp %d", back.Limits.Conn, back.Revocations[jwt.All], back.Expires)
	}
}
