package pki

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	jwt "github.com/nats-io/jwt/v2"
)

// Security review 2026-10, I8: an Account or SYS Account JWT lost from
// this process and the accounts bucket (once a file on the PVC, held in
// memory since E3) is minted again with the revocations the database
// has, never without them, and a database error fails the mint closed
// with the tenant named.

// i8Revocations files, for tenantID, one denied sprout and one deleted
// sprout's NKey on the revoked list, plus one accepted sprout, and
// returns the two NKeys that must stay revoked and the accepted one.
func i8Revocations(t *testing.T, tenantID string) (denied, deleted, accepted string) {
	t.Helper()
	denied, deleted, accepted = newUserPub(t), newUserPub(t), newUserPub(t)
	for _, r := range []nkeyRow{
		{TenantID: tenantID, SproutID: "denied-01", NKey: denied, State: stateDenied},
		{TenantID: tenantID, SproutID: "web-01", NKey: accepted, State: stateAccepted},
	} {
		if err := upsertNKeyRow(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Create(&revokedNKeyRow{TenantID: tenantID, NKey: deleted, SproutID: "gone-01", RevokedAt: time.Now().Unix()}).Error; err != nil {
		t.Fatal(err)
	}
	return denied, deleted, accepted
}

func requireRevoked(t *testing.T, what, accountJWT string, revoked []string, live string) {
	t.Helper()
	ac, err := jwt.DecodeAccountClaims(accountJWT)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range revoked {
		if _, ok := ac.Revocations[k]; !ok {
			t.Errorf("%s: re-minted without the revocation of %s (revocations %v)", what, k, ac.Revocations)
		}
	}
	if _, ok := ac.Revocations[live]; ok {
		t.Errorf("%s: the accepted sprout's NKey is revoked", what)
	}
}

func TestLostTenantAccountJWTRebuiltFromDatabase(t *testing.T) {
	setupTestPKI(t)
	const tenant = "t_i8"
	// ProvisionTenant without the push: the row and the Transit keys.
	if _, _, _, err := ensureTenantAccount(tenant, "I8 Co", true); err != nil {
		t.Fatal(err)
	}
	denied, deleted, accepted := i8Revocations(t, tenant)

	mint := func() (*tenantAccountMaterial, bool, error) {
		t.Helper()
		mat, err := ensureNatsAuth()
		if err != nil {
			t.Fatal(err)
		}
		tenantAuthMu.Lock()
		defer tenantAuthMu.Unlock()
		return ensureTenantAccountMaterial(mat, tenant, tenant, false)
	}

	// The held JWT is lost (a restart) and the bucket has none.
	forgetHeldJWTs()
	tam, minted, err := mint()
	if err != nil {
		t.Fatal(err)
	}
	if !minted {
		t.Fatal("precondition: the Account JWT was not minted afresh")
	}
	requireRevoked(t, "tenant "+tenant, tam.jwt, []string{denied, deleted}, accepted)
	if h, _ := heldAccountJWT(tam.pub); h.jwt != tam.jwt {
		t.Error("the re-minted JWT is not the one held")
	}

	// A database error: nothing is minted, and the error names the tenant.
	forgetHeldJWTs()
	if _, err := ensureNatsAuth(); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrator().DropTable(&revokedNKeyRow{}); err != nil {
		t.Fatal(err)
	}
	mat, _ := ensureNatsAuth()
	tenantAuthMu.Lock()
	_, _, err = ensureTenantAccountMaterial(mat, tenant, tenant, false)
	tenantAuthMu.Unlock()
	if err == nil || !strings.Contains(err.Error(), `tenant "`+tenant+`"`) {
		t.Fatalf("mint with the revoked list unreadable: err = %v, want an error naming tenant %q", err, tenant)
	}
	if h, ok := heldAccountJWT(tam.pub); ok {
		t.Errorf("a JWT was held after the failed mint: %v", h.jwt != "")
	}
}

func TestLostLegacyAccountJWTRebuiltFromDatabase(t *testing.T) {
	setupTestPKI(t)
	legacy := currentTenantID()
	denied, deleted, accepted := i8Revocations(t, legacy)

	forgetHeldJWTs()
	mat, err := ensureNatsAuth()
	if err != nil {
		t.Fatal(err)
	}
	if !mat.tenantMinted {
		t.Fatal("precondition: the legacy Account JWT was not minted afresh")
	}
	requireRevoked(t, "legacy tenant", mat.tenantJWT, []string{denied, deleted}, accepted)

	forgetHeldJWTs()
	if err := db.Migrator().DropTable(&revokedNKeyRow{}); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureNatsAuth(); err == nil || !strings.Contains(err.Error(), `tenant "`+legacy+`"`) {
		t.Fatalf("ensureNatsAuth with the revoked list unreadable: err = %v, want an error naming tenant %q", err, legacy)
	}
}

func TestLostSysAccountJWTRebuiltFromDatabase(t *testing.T) {
	setupTestPKI(t)
	rec := useTestSaaSAPICredentialState(t)
	oldPub, newPub := newUserPub(t), newUserPub(t)
	recordSaaSAPIKey(t, rec, oldPub)
	recordSaaSAPIKey(t, rec, newPub)

	forgetHeldJWTs()
	mat, err := ensurePlatformAuth()
	if err != nil {
		t.Fatal(err)
	}
	trust, err := LoadNATSTrustDir(NATSTrustDir())
	if err != nil {
		t.Fatal(err)
	}
	if mat.sysAccountJWT == trust.SysAccountJWT {
		t.Fatal("the trust's SYS Account JWT was used without the rotated-out key's revocation")
	}
	requireRevoked(t, "SYS account", mat.sysAccountJWT, []string{oldPub}, newPub)
	if heldSysAccountJWT(t) != mat.sysAccountJWT {
		t.Error("the rebuilt SYS Account JWT is not the one held")
	}

	forgetHeldJWTs()
	orig := readSaaSAPICredentialState
	readSaaSAPICredentialState = func(context.Context) (*SaaSAPICredentialState, error) {
		return nil, errors.New("boom")
	}
	t.Cleanup(func() { readSaaSAPICredentialState = orig })
	if _, err := ensurePlatformAuth(); err == nil || !strings.Contains(err.Error(), "SYS account "+trust.SysAccountPub) {
		t.Fatalf("ensurePlatformAuth with the rotation state unreadable: err = %v, want an error naming the SYS account", err)
	}
	if _, ok := heldAccountJWT(trust.SysAccountPub); ok {
		t.Error("a SYS Account JWT was held after the failed rebuild")
	}
}
