package pki

import (
	"errors"
	"strings"
	"testing"

	"gorm.io/gorm/clause"
)

// acceptForGateway puts sproutID into tenant's accepted state under a
// fresh NKey through the real Unaccept/Accept path, and returns the NKey.
func acceptForGateway(t *testing.T, tenant, sproutID string) string {
	t.Helper()
	nkey, _ := newUserNKey(t)
	if err := UnacceptNKey(tenant, sproutID, nkey); err != nil {
		t.Fatalf("UnacceptNKey(%s): %v", sproutID, err)
	}
	if err := AcceptNKey(tenant, sproutID); err != nil {
		t.Fatalf("AcceptNKey(%s): %v", sproutID, err)
	}
	return nkey
}

func TestVerifyGatewaySubject_LiveSproutPasses(t *testing.T) {
	setupTestPKI(t)
	tenant := currentTenantID()
	nkey := acceptForGateway(t, tenant, "web-01")

	if err := VerifyGatewaySubject(tenant, "web-01", nkey); err != nil {
		t.Fatalf("live sprout's own NKey: %v", err)
	}
}

func TestVerifyGatewaySubject_RefusesWrongOrUnacceptedNKey(t *testing.T) {
	setupTestPKI(t)
	tenant := currentTenantID()
	nkey := acceptForGateway(t, tenant, "web-01")
	other, _ := newUserNKey(t)
	pending, _ := newUserNKey(t)
	if err := UnacceptNKey(tenant, "web-02", pending); err != nil {
		t.Fatal(err)
	}

	for name, c := range map[string][3]string{
		"another NKey":              {tenant, "web-01", other},
		"empty NKey":                {tenant, "web-01", ""},
		"NKey in another case":      {tenant, "web-01", strings.ToLower(nkey)},
		"own NKey, another sprout":  {tenant, "web-02", nkey},
		"unaccepted sprout":         {tenant, "web-02", pending},
		"no such sprout":            {tenant, "web-03", nkey},
		"same sprout, other tenant": {"t_other", "web-01", nkey},
		"invalid sprout ID":         {tenant, "web/01", nkey},
		"invalid tenant ID":         {"", "web-01", nkey},
	} {
		t.Run(name, func(t *testing.T) {
			if err := VerifyGatewaySubject(c[0], c[1], c[2]); err == nil {
				t.Errorf("VerifyGatewaySubject(%q, %q, %q) passed", c[0], c[1], c[2])
			}
		})
	}
}

// A deleted sprout's NKey is refused as revoked.
func TestVerifyGatewaySubject_DeletedSproutRefused(t *testing.T) {
	setupTestPKI(t)
	tenant := currentTenantID()
	nkey := acceptForGateway(t, tenant, "web-01")
	if err := DeleteNKey(tenant, "web-01"); err != nil {
		t.Fatal(err)
	}
	if err := VerifyGatewaySubject(tenant, "web-01", nkey); !errors.Is(err, ErrNKeyRevoked) {
		t.Fatalf("deleted sprout: got %v, want ErrNKeyRevoked", err)
	}
}

// Delete then re-enrol under a new NKey (the review's B3 sequence): the
// old NKey is refused, the new one passes.
func TestVerifyGatewaySubject_DeleteThenReacceptRefusesOldNKey(t *testing.T) {
	setupTestPKI(t)
	tenant := currentTenantID()
	oldNKey := acceptForGateway(t, tenant, "web-01")
	if err := DeleteNKey(tenant, "web-01"); err != nil {
		t.Fatal(err)
	}
	newNKey := acceptForGateway(t, tenant, "web-01")

	if err := VerifyGatewaySubject(tenant, "web-01", oldNKey); !errors.Is(err, ErrNKeyRevoked) {
		t.Errorf("old host after re-accept: got %v, want ErrNKeyRevoked", err)
	}
	if err := VerifyGatewaySubject(tenant, "web-01", newNKey); err != nil {
		t.Errorf("new host: %v", err)
	}
}

// AcceptNKey's replace path (web-01_1 takes web-01): the replaced host is
// refused at once, the new host passes under the base ID only.
func TestVerifyGatewaySubject_ReplaceRefusesOldHost(t *testing.T) {
	setupTestPKI(t)
	tenant := currentTenantID()
	oldNKey := acceptForGateway(t, tenant, "web-01")
	newNKey, _ := newUserNKey(t)
	if err := UnacceptNKey(tenant, "web-01_1", newNKey); err != nil {
		t.Fatal(err)
	}
	if err := AcceptNKey(tenant, "web-01_1"); err != nil {
		t.Fatal(err)
	}

	if err := VerifyGatewaySubject(tenant, "web-01", oldNKey); err == nil {
		t.Error("replaced host's NKey still passes for web-01")
	}
	if err := VerifyGatewaySubject(tenant, "web-01", newNKey); err != nil {
		t.Errorf("new host under web-01: %v", err)
	}
	if err := VerifyGatewaySubject(tenant, "web-01_1", newNKey); err == nil {
		t.Error("new host still passes under its old suffixed ID")
	}
}

// The superseded-NKey check stands on its own: a row whose NKey moved on
// refuses the old one even if the revoked list somehow lacks it.
func TestVerifyGatewaySubject_SupersededNKeyRefusedWithoutRevocation(t *testing.T) {
	newTestDB(t)
	tenant := currentTenantID()
	oldNKey, _ := newUserNKey(t)
	newNKey, _ := newUserNKey(t)
	if err := upsertNKeyRow(nkeyRow{TenantID: tenant, SproutID: "web-01", NKey: newNKey, State: stateAccepted}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyGatewaySubject(tenant, "web-01", oldNKey); !errors.Is(err, ErrSproutIDNotFound) {
		t.Errorf("superseded NKey: got %v, want ErrSproutIDNotFound", err)
	}
}

// Revocation is per tenant: the same NKey revoked in another tenant does
// not touch this one, and a tenant's own revocation is found only under
// its own tenant_id.
func TestVerifyGatewaySubject_RevocationKeyedOnTenant(t *testing.T) {
	gdb := newTestDB(t)
	nkey, _ := newUserNKey(t)
	for _, id := range []string{"t_acme", "t_other"} {
		if err := gdb.Create(&tenantRow{ID: id, Name: id}).Error; err != nil {
			t.Fatal(err)
		}
		if err := upsertNKeyRow(nkeyRow{TenantID: id, SproutID: "web-01", NKey: nkey, State: stateAccepted}); err != nil {
			t.Fatal(err)
		}
	}
	if err := gdb.Clauses(clause.OnConflict{DoNothing: true}).Create(&revokedNKeyRow{
		TenantID: "t_other", NKey: nkey, SproutID: "web-01", RevokedAt: 1,
	}).Error; err != nil {
		t.Fatal(err)
	}

	if err := VerifyGatewaySubject("t_acme", "web-01", nkey); err != nil {
		t.Errorf("t_acme, not revoked there: %v", err)
	}
	if err := VerifyGatewaySubject("t_other", "web-01", nkey); !errors.Is(err, ErrNKeyRevoked) {
		t.Errorf("t_other: got %v, want ErrNKeyRevoked", err)
	}
}

func TestVerifyGatewaySubject_DeprovisionedTenantRefused(t *testing.T) {
	gdb := newTestDB(t)
	nkey, _ := newUserNKey(t)
	if err := gdb.Create(&tenantRow{ID: "t_gone", Name: "gone", Deleted: true}).Error; err != nil {
		t.Fatal(err)
	}
	if err := upsertNKeyRow(nkeyRow{TenantID: "t_gone", SproutID: "web-01", NKey: nkey, State: stateAccepted}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyGatewaySubject("t_gone", "web-01", nkey); !errors.Is(err, ErrTenantNotFound) {
		t.Errorf("deprovisioned tenant: got %v, want ErrTenantNotFound", err)
	}
	if err := VerifyGatewaySubject("t_never", "web-01", nkey); !errors.Is(err, ErrTenantNotFound) {
		t.Errorf("unknown tenant: got %v, want ErrTenantNotFound", err)
	}
}

// A database error, or no database, is an error that is none of the
// "refused" sentinels — and never nil.
func TestVerifyGatewaySubject_DatabaseErrorFailsClosed(t *testing.T) {
	gdb := newTestDB(t)
	tenant := currentTenantID()
	nkey, _ := newUserNKey(t)
	if err := upsertNKeyRow(nkeyRow{TenantID: tenant, SproutID: "web-01", NKey: nkey, State: stateAccepted}); err != nil {
		t.Fatal(err)
	}
	sqlDB, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.Close()

	err = VerifyGatewaySubject(tenant, "web-01", nkey)
	if err == nil {
		t.Fatal("closed database: VerifyGatewaySubject passed")
	}
	for _, sentinel := range []error{ErrNKeyRevoked, ErrSproutIDNotFound, ErrTenantNotFound} {
		if errors.Is(err, sentinel) {
			t.Errorf("closed database reported as %v", sentinel)
		}
	}

	SetDB(nil)
	if err := VerifyGatewaySubject(tenant, "web-01", nkey); !errors.Is(err, errNoStore) {
		t.Errorf("no database: got %v, want errNoStore", err)
	}
}
