package pki

// The Transit cut-over (P21 slice 1 PR4b, brief §2 and §6.2): the farmer
// signs through Transit, writes no trust chain seed, creates tenant keys
// only at provisioning and retires them at offboarding.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"testing"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/pki/natskeys"
	"github.com/yogzblr/imas/internal/pki/natskeys/natskeystest"
)

// assertNoRemovedSeedFiles fails if any seed file of the old seed-backed
// trust chain exists anywhere under the farmer's PKI directory.
func assertNoRemovedSeedFiles(t *testing.T) {
	t.Helper()
	// Farmer writes no seed, and no file at all, under its old PKI
	// directory: it does not even exist.
	if _, err := os.Stat(config.FarmerPKI); !os.IsNotExist(err) {
		t.Errorf("farmer's old PKI directory %s exists (stat: %v)", config.FarmerPKI, err)
	}
}

func TestNATSKeyRefTransitNames(t *testing.T) {
	setupTestPKI(t)
	cases := []struct {
		ref  natsKeyRef
		want string
	}{
		{natsKeyRef{role: natsKeyOperator}, "nats-operator"},
		{natsKeyRef{role: natsKeyOperatorSigning}, "nats-operator-signing"},
		{natsKeyRef{role: natsKeySysAccount}, "nats-sys-account"},
		{natsKeyRef{role: natsKeyTenantAccount}, "nats-tacct-" + currentTenantID()},
		{natsKeyRef{role: natsKeyTenantSigning}, "nats-tsign-" + currentTenantID()},
		{natsKeyRef{role: natsKeyTenantAccount, tenantID: "t_a"}, "nats-tacct-t_a"},
		{natsKeyRef{role: natsKeyTenantSigning, tenantID: "t_a"}, "nats-tsign-t_a"},
	}
	for _, c := range cases {
		got, err := c.ref.transitName()
		if err != nil || got != c.want {
			t.Errorf("%v: transitName = %q, %v; want %q", c.ref, got, err, c.want)
		}
	}
	if _, err := (natsKeyRef{role: natsKeyRole(99)}).transitName(); err == nil {
		t.Error("unknown role: want an error")
	}
}

func TestEnsureNatsAuthWritesNoRemovedSeedFiles(t *testing.T) {
	setupTestPKI(t)
	mat, err := ensureNatsAuth()
	if err != nil {
		t.Fatalf("ensureNatsAuth: %v", err)
	}
	config.FarmerBusURL = "127.0.0.1:1" // no bus: only the push fails
	_ = ProvisionTenant("t_seeds", "Seeds Co")
	if !testTransit.Fake.Has(natskeys.TenantSigningKey("t_seeds")) {
		t.Fatal("ProvisionTenant created no tenant keys")
	}
	assertNoRemovedSeedFiles(t)

	// The trust chain is the fake's: operator signing and SYS account
	// pairs sign through Transit and match the trust directory.
	trust, err := LoadNATSTrustDir(NATSTrustDir())
	if err != nil {
		t.Fatal(err)
	}
	if mat.operatorJWT != trust.OperatorJWT || mat.operatorPub != trust.OperatorPub || mat.sysAccountPub != trust.SysAccountPub {
		t.Error("ensureNatsAuth's operator/SYS material is not the trust directory's")
	}
	if _, err := mat.operatorSigningKP.Seed(); !errors.Is(err, nkeys.ErrPublicKeyOnly) {
		t.Errorf("operator signing pair has a seed (err %v): not a Transit pair", err)
	}
	if testTransit.Fake.Count(natskeystest.OpSign) == 0 {
		t.Error("nothing was signed through Transit")
	}
	tc, err := jwt.DecodeAccountClaims(mat.tenantJWT)
	if err != nil || tc.Issuer != trust.OperatorSigningPub {
		t.Errorf("legacy tenant JWT not issued by the operator signing key: %v", err)
	}
	// The farmer's SYS copy, held in memory, is the trust's.
	if h, ok := heldAccountJWT(trust.SysAccountPub); !ok || h.jwt != trust.SysAccountJWT || mat.sysAccountJWT != trust.SysAccountJWT {
		t.Errorf("the held SYS account JWT is not the trust's (held %v)", ok)
	}
}

func TestEnsureNatsAuthRequiresSysUserSeed(t *testing.T) {
	setupTestPKI(t)
	t.Setenv("IMAS_NATS_SYS_USER_SEED_FILE", "")
	if _, err := ensureNatsAuth(); err == nil {
		t.Fatal("ensureNatsAuth without a SYS_USER seed: want an error")
	}
	// No seed was generated: setupTestPKI's requireNoFarmerPKIWrites.
}

func TestCheckNATSAuth(t *testing.T) {
	setupTestPKI(t)
	if err := CheckNATSAuth(context.Background()); err != nil {
		t.Fatalf("CheckNATSAuth: %v", err)
	}

	// A trust directory naming other keys than Transit's.
	testTransit.Fake.NewKey(natskeys.OperatorKey())
	if err := CheckNATSAuth(context.Background()); !errors.Is(err, ErrTrustMismatch) {
		t.Errorf("operator key replaced in Transit: err = %v, want ErrTrustMismatch", err)
	}

	t.Setenv(NATSTrustDirEnv, t.TempDir())
	if err := CheckNATSAuth(context.Background()); !errors.Is(err, ErrTrustIncomplete) {
		t.Errorf("empty trust dir: err = %v, want ErrTrustIncomplete", err)
	}

	t.Setenv(NATSTrustDirEnv, testTransit.TrustDir)
	t.Setenv(natskeys.EnvPrefixSign+natskeys.EnvOpenBaoAddr, "")
	if err := CheckNATSAuth(context.Background()); !errors.Is(err, natskeys.ErrNotConfigured) {
		t.Errorf("no Transit configured: err = %v, want ErrNotConfigured", err)
	}
}

func TestEnsureNatsAuthRefusesSigningKeyMismatch(t *testing.T) {
	setupTestPKI(t)
	testTransit.Fake.NewKey(natskeys.SysAccountKey())
	if _, err := ensureNatsAuth(); !errors.Is(err, ErrTrustMismatch) {
		t.Fatalf("SYS account key replaced in Transit: err = %v, want ErrTrustMismatch", err)
	}
}

func TestProvisionCreatesTenantKeys(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	defer startTestBus(t)()

	const tenant = "t_keys"
	if err := ProvisionTenant(tenant, "Keys Co"); err != nil {
		t.Fatalf("ProvisionTenant: %v", err)
	}
	for _, name := range []string{natskeys.TenantAccountKey(tenant), natskeys.TenantSigningKey(tenant)} {
		if !testTransit.Fake.Has(name) {
			t.Errorf("ProvisionTenant did not create %s", name)
		}
	}
	row, err := getTenantRow(tenant)
	if err != nil {
		t.Fatal(err)
	}
	if want := fakePub(t, natskeys.TenantAccountKey(tenant)); row.AccountPub != want {
		t.Errorf("recorded Account %s is not nats-tacct-%s's public key %s", row.AccountPub, tenant, want)
	}
	ac, err := jwt.DecodeAccountClaims(heldTenantAccountJWT(t, tenant))
	if err != nil {
		t.Fatal(err)
	}
	if !ac.SigningKeys.Contains(fakePub(t, natskeys.TenantSigningKey(tenant))) {
		t.Errorf("Account JWT does not list nats-tsign-%s as a signing key", tenant)
	}

	// Provisioning again creates nothing.
	testTransit.Fake.ResetCounts()
	if err := ProvisionTenant(tenant, "Keys Co"); err != nil {
		t.Fatalf("second ProvisionTenant: %v", err)
	}
	if n := testTransit.Fake.Count(natskeystest.OpCreateKey); n != 0 {
		t.Errorf("second ProvisionTenant created %d keys", n)
	}
	assertNoRemovedSeedFiles(t)
}

func TestEnrollExistingTenantCreatesNoKeys(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	defer startTestBus(t)()

	const tenant = "t_enroll"
	if err := ProvisionTenant(tenant, "Enroll Co"); err != nil {
		t.Fatalf("ProvisionTenant: %v", err)
	}
	testTransit.Fake.ResetCounts()
	if err := ReloadNKeysForTenant(tenant); err != nil {
		t.Fatalf("ReloadNKeysForTenant: %v", err)
	}
	if err := ResyncProvisionedTenants(); err != nil {
		t.Fatalf("ResyncProvisionedTenants: %v", err)
	}
	if _, err := PushAllAccounts(); err != nil {
		t.Fatalf("PushAllAccounts: %v", err)
	}
	if n := testTransit.Fake.Count(natskeystest.OpCreateKey); n != 0 {
		t.Errorf("enrollment/resync/push-all of a provisioned tenant created %d keys", n)
	}

	// An already-registered tenant whose keys are gone is an error, not
	// a silent re-creation (which would change its Account identity).
	testTransit.Fake.Delete(natskeys.TenantSigningKey(tenant))
	natsKeys = &transitNATSKeys{getenv: os.Getenv} // drop the cached pairs
	t.Cleanup(func() { natsKeys = &transitNATSKeys{getenv: os.Getenv} })
	if err := ReloadNKeysForTenant(tenant); !errors.Is(err, natskeys.ErrKeyNotFound) {
		t.Errorf("ReloadNKeysForTenant with a missing key: err = %v, want ErrKeyNotFound", err)
	}
	if testTransit.Fake.Has(natskeys.TenantSigningKey(tenant)) {
		t.Error("enrollment re-created a missing tenant key")
	}
}

func TestFirstEnrollmentProvisionsTenantKeys(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	defer startTestBus(t)()

	// A first enrollment registers the tenant (lazy provisioning) and so
	// creates its keys.
	const tenant = "t_lazy"
	if err := ReloadNKeysForTenant(tenant); err != nil {
		t.Fatalf("ReloadNKeysForTenant: %v", err)
	}
	if !testTransit.Fake.Has(natskeys.TenantAccountKey(tenant)) || !testTransit.Fake.Has(natskeys.TenantSigningKey(tenant)) {
		t.Error("first enrollment did not create the tenant's keys")
	}
}

func TestDeprovisionRetiresKeysAfterPush(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	defer startTestBus(t)()
	resetRaceHooks(t)

	const tenant = "t_retire"
	if err := ProvisionTenant(tenant, "Retire Co"); err != nil {
		t.Fatalf("ProvisionTenant: %v", err)
	}
	names := []string{natskeys.TenantAccountKey(tenant), natskeys.TenantSigningKey(tenant)}

	retiredBeforePush := false
	testHookDeprovisionBeforePush = func(string) {
		for _, n := range names {
			retiredBeforePush = retiredBeforePush || testTransit.Fake.SoftDeleted(n)
		}
	}
	if err := DeprovisionTenant(tenant); err != nil {
		t.Fatalf("DeprovisionTenant: %v", err)
	}
	if retiredBeforePush {
		t.Error("a tenant key was retired before the lockout push")
	}
	for _, n := range names {
		if !testTransit.Fake.SoftDeleted(n) {
			t.Errorf("%s not soft-deleted after DeprovisionTenant", n)
		}
	}
	if ac := busAccountClaims(t, tenant); !isLockedOut(ac) {
		t.Error("the bus does not hold the lockout")
	}

	// A retried deprovision still locks out, and retiring again is fine.
	if err := DeprovisionTenant(tenant); err != nil {
		t.Fatalf("second DeprovisionTenant: %v", err)
	}

	// A failed retire is returned.
	const other = "t_retire_fail"
	if err := ProvisionTenant(other, "Retire Fail Co"); err != nil {
		t.Fatalf("ProvisionTenant: %v", err)
	}
	testTransit.Fake.FailNext(natskeystest.OpSoftDelete, 400, 10)
	if err := DeprovisionTenant(other); err == nil {
		t.Error("DeprovisionTenant with a failing soft delete: want an error")
	}
}

func TestDeprovisionNeverRetiresLegacyTenantKeys(t *testing.T) {
	setupTestPKI(t)
	if err := retireTenantKeys(currentTenantID()); err != nil {
		t.Fatal(err)
	}
	if n := testTransit.Fake.Count(natskeystest.OpSoftDelete); n != 0 {
		t.Errorf("the legacy tenant's keys were retired (%d soft deletes)", n)
	}
}

func TestLockoutWithoutTenantKeys(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	defer startTestBus(t)()
	resetRaceHooks(t)

	const tenant = "t_nokeys"
	if err := ProvisionTenant(tenant, "No Keys Co"); err != nil {
		t.Fatalf("ProvisionTenant: %v", err)
	}
	// The tenant's keys are gone (an operator purged them) and this
	// replica holds no Account JWT (a restart; no publisher, so no
	// bucket): the lockout is built from the row's Account pub and signed
	// by the operator signing key alone.
	testTransit.Fake.Delete(natskeys.TenantAccountKey(tenant))
	testTransit.Fake.Delete(natskeys.TenantSigningKey(tenant))
	forgetHeldJWTs()
	if err := DeprovisionTenant(tenant); err != nil {
		t.Fatalf("DeprovisionTenant without tenant keys: %v", err)
	}
	ac := busAccountClaims(t, tenant)
	if !isLockedOut(ac) {
		t.Fatal("the bus does not hold a lockout")
	}
	trust, _ := LoadNATSTrustDir(NATSTrustDir())
	if ac.Issuer != trust.OperatorSigningPub {
		t.Errorf("lockout issued by %s, want the operator signing key", ac.Issuer)
	}
	// PushAllAccounts re-signs it the same way.
	if _, err := PushAllAccounts(); err != nil {
		t.Fatalf("PushAllAccounts: %v", err)
	}
	if testTransit.Fake.Has(natskeys.TenantAccountKey(tenant)) {
		t.Error("a lockout re-created the tenant's key")
	}
}

func TestResolverSeedingWithoutTransit(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	config.FarmerBusURL = "127.0.0.1:1" // no bus: the push fails, the JWT is held

	const tenant = "t_seeded"
	_ = ProvisionTenant(tenant, "Seeded Co")
	heldTenantAccountJWT(t, tenant)
	// Seeding uses the Account JWT this process holds; its Transit keys
	// are neither needed nor created.
	testTransit.Fake.Delete(natskeys.TenantAccountKey(tenant))
	testTransit.Fake.Delete(natskeys.TenantSigningKey(tenant))
	testTransit.Fake.ResetCounts()

	startTestBus(t)
	if n := testTransit.Fake.Count(natskeystest.OpCreateKey); n != 0 {
		t.Errorf("resolver seeding created %d keys", n)
	}
	if ac := busAccountClaims(t, tenant); ac.Name != "Seeded Co" {
		t.Errorf("the bus was not seeded with %s's Account (name %q)", tenant, ac.Name)
	}
}

// fakePub is the account public key of the fake's key name.
func fakePub(t *testing.T, name string) string {
	t.Helper()
	priv := testTransit.Fake.PrivateKey(name, 1)
	if priv == nil {
		t.Fatalf("no key %s", name)
	}
	pub, err := nkeys.Encode(nkeys.PrefixByteAccount, priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return string(pub)
}
