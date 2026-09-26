package pki

// Coverage for VerifySproutInTenant, the point-of-effect tenant check
// behind internal.sprout.action (FLAG FOR SECURITY REVIEW).

import (
	"errors"
	"testing"

	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/config"
)

func seedSprout(t *testing.T, tenantID, sproutID, state string) {
	t.Helper()
	if err := upsertNKeyRow(nkeyRow{TenantID: tenantID, SproutID: sproutID, NKey: "U" + tenantID + sproutID, State: state}); err != nil {
		t.Fatalf("seeding sprout %s/%s: %v", tenantID, sproutID, err)
	}
}

func seedTenant(t *testing.T, id string, deleted bool) {
	t.Helper()
	if err := db.Create(&tenantRow{ID: id, Name: id, Deleted: deleted, CreatedAt: 1}).Error; err != nil {
		t.Fatalf("seeding tenant %s: %v", id, err)
	}
}

func TestVerifySproutInTenant(t *testing.T) {
	newTestDB(t)
	config.FarmerOrganization = "imas-test"
	legacy := CurrentTenantID()

	seedTenant(t, "t_a", false)
	seedTenant(t, "t_b", false)
	seedTenant(t, "t_gone", true)

	seedSprout(t, legacy, "legacy-01", stateAccepted)
	seedSprout(t, legacy, "legacy-pending", stateUnaccepted)
	seedSprout(t, legacy, "legacy-denied", stateDenied)
	seedSprout(t, legacy, "legacy-rejected", stateRejected)
	seedSprout(t, "t_a", "only-in-a", stateAccepted)
	// The same sprout ID in two tenants: sprout_id is unique per tenant only.
	seedSprout(t, "t_a", "web-01", stateAccepted)
	seedSprout(t, "t_b", "web-01", stateUnaccepted)
	seedSprout(t, "t_gone", "gone-01", stateAccepted)
	// A sprout row whose tenant has no pki_tenants row at all.
	seedSprout(t, "t_ghost", "ghost-01", stateAccepted)

	cases := []struct {
		name, tenant, sprout string
		want                 error
	}{
		{"legacy accepted", legacy, "legacy-01", nil},
		{"provisioned accepted", "t_a", "only-in-a", nil},
		{"shared ID, own tenant accepted", "t_a", "web-01", nil},
		{"shared ID, other tenant not accepted", "t_b", "web-01", ErrSproutIDNotFound},
		{"another tenant's sprout", "t_b", "only-in-a", ErrSproutIDNotFound},
		{"another tenant's sprout, asserted legacy", legacy, "only-in-a", ErrSproutIDNotFound},
		{"legacy sprout, asserted provisioned tenant", "t_a", "legacy-01", ErrSproutIDNotFound},
		{"unaccepted", legacy, "legacy-pending", ErrSproutIDNotFound},
		{"denied", legacy, "legacy-denied", ErrSproutIDNotFound},
		{"rejected", legacy, "legacy-rejected", ErrSproutIDNotFound},
		{"unknown sprout", "t_a", "nope", ErrSproutIDNotFound},
		{"deprovisioned tenant", "t_gone", "gone-01", ErrTenantNotFound},
		{"never-provisioned tenant", "t_ghost", "ghost-01", ErrTenantNotFound},
		{"invalid tenant ID", "../t_a", "only-in-a", ErrTenantIDInvalid},
		{"empty tenant ID", "", "only-in-a", ErrTenantIDInvalid},
		{"invalid sprout ID", "t_a", "_bad", ErrSproutIDInvalid},
		{"empty sprout ID", "t_a", "", ErrSproutIDInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := VerifySproutInTenant(tc.tenant, tc.sprout); !errors.Is(got, tc.want) || (tc.want == nil && got != nil) {
				t.Fatalf("VerifySproutInTenant(%q, %q) = %v, want %v", tc.tenant, tc.sprout, got, tc.want)
			}
		})
	}
}

// TestVerifySproutInTenant_CaseInsensitiveCollation reproduces PXC's
// default case-insensitive collation (here with SQLite's COLLATE NOCASE)
// and proves the explicit post-query comparison, not the WHERE clause,
// is what rejects a tenant ID that differs only in case.
func TestVerifySproutInTenant_CaseInsensitiveCollation(t *testing.T) {
	gdb := newTestDB(t)
	config.FarmerOrganization = "imas-test"
	for _, stmt := range []string{
		`DROP TABLE pki_nkeys`,
		`DROP TABLE pki_tenants`,
		`CREATE TABLE pki_nkeys (tenant_id TEXT COLLATE NOCASE, sprout_id TEXT COLLATE NOCASE, nkey TEXT NOT NULL, state TEXT NOT NULL, PRIMARY KEY (tenant_id, sprout_id))`,
		`CREATE TABLE pki_tenants (id TEXT COLLATE NOCASE PRIMARY KEY, name TEXT NOT NULL, deleted NUMERIC NOT NULL DEFAULT false, created_at INTEGER NOT NULL, account_pub TEXT)`,
	} {
		if err := gdb.Exec(stmt).Error; err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	seedTenant(t, "T_Case", false)
	seedSprout(t, "T_Case", "web-01", stateAccepted)
	seedSprout(t, "IMAS-TEST", "legacy-01", stateAccepted)

	// Sanity: the collation really does make the WHERE clause match.
	var n int64
	gdb.Model(&nkeyRow{}).Where("tenant_id = ? AND sprout_id = ?", "t_case", "web-01").Count(&n)
	if n != 1 {
		t.Fatalf("expected the NOCASE collation to match across case, got %d rows", n)
	}

	if err := VerifySproutInTenant("T_Case", "web-01"); err != nil {
		t.Fatalf("exact-case lookup: %v", err)
	}
	if err := VerifySproutInTenant("t_case", "web-01"); err == nil {
		t.Fatal("a tenant ID differing only in case passed the point-of-effect check")
	}
	// The legacy tenant skips the pki_tenants lookup, so this exercises
	// the nkey row's own tenant_id comparison.
	if err := VerifySproutInTenant("imas-test", "legacy-01"); !errors.Is(err, ErrSproutIDNotFound) {
		t.Fatalf("legacy tenant, row stored under a different-case tenant ID: got %v, want ErrSproutIDNotFound", err)
	}
}

// TestVerifySproutInTenant_DBErrorIsNotNotFound: a lookup that couldn't be
// made must not read as a clean "no" (or a "yes").
func TestVerifySproutInTenant_DBErrorIsNotNotFound(t *testing.T) {
	gdb := newTestDB(t)
	config.FarmerOrganization = "imas-test"
	seedSprout(t, CurrentTenantID(), "legacy-01", stateAccepted)
	seedTenant(t, "t_a", false)
	sqlDB, _ := gdb.DB()
	sqlDB.Close()

	for _, tenant := range []string{CurrentTenantID(), "t_a"} {
		err := VerifySproutInTenant(tenant, "legacy-01")
		if err == nil || errors.Is(err, ErrSproutIDNotFound) || errors.Is(err, ErrTenantNotFound) || errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("tenant %q: expected a wrapped database error, got %v", tenant, err)
		}
	}
}
