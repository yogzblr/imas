package pki

import (
	"context"
	"os"
	"testing"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// heldTenantAccountJWT returns the Account JWT this process holds for
// tenantID: the legacy Account for the current tenant, else the Account
// recorded on its pki_tenants row. It fails the test when none is held.
func heldTenantAccountJWT(t *testing.T, tenantID string) string {
	t.Helper()
	pub := tenantAccountPub(t, tenantID)
	h, ok := heldAccountJWT(pub)
	if !ok {
		t.Fatalf("no Account JWT held for tenant %s (%s)", tenantID, pub)
	}
	return h.jwt
}

// tenantAccountPub is tenantID's Account public key: its pki_tenants row's,
// or, for the legacy current tenant without one, the legacy Account's.
func tenantAccountPub(t *testing.T, tenantID string) string {
	t.Helper()
	if row, err := getTenantRow(tenantID); err == nil && row.AccountPub != "" {
		return row.AccountPub
	}
	if tenantID != currentTenantID() {
		t.Fatalf("tenant %s has no recorded Account", tenantID)
	}
	mat, err := ensureNatsAuth()
	if err != nil {
		t.Fatalf("ensureNatsAuth: %v", err)
	}
	return mat.tenantPub
}

// sproutUserJWTForTest returns the User JWT the sprout JWT store serves
// sprout sproutID of tenantID (MintOrReuseUserJWT), or ErrSproutIDNotFound
// when the sprout is not accepted: what the enrolment and refresh paths
// hand out.
func sproutUserJWTForTest(tenantID, sproutID string) (string, error) {
	row, err := findNKeyRowInTenant(tenantID, sproutID)
	if err != nil {
		return "", err
	}
	if row.State != stateAccepted {
		return "", ErrSproutIDNotFound
	}
	return MintOrReuseUserJWT(context.Background(), tenantID, sproutID, row.NKey)
}

// requireNoFarmerPKIWrites fails t, when it ends, if anything was created
// under config.FarmerPKI: farmer writes no JWT or key file (E3). Every
// test that sets up the PKI through setupTestPKI runs it.
func requireNoFarmerPKIWrites(t *testing.T, dir string) {
	t.Helper()
	t.Cleanup(func() {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("farmer wrote under its old PKI directory %s (stat: %v)", dir, err)
		}
	})
}

// farmerUserJWTBytes is FarmerUserJWT as bytes, for tests that dial the
// bus as farmer.
func farmerUserJWTBytes() ([]byte, error) {
	j, err := FarmerUserJWT()
	return []byte(j), err
}

// mintOrReuseUserJWTFile is mintOrReuseUserJWT over a file in the test's
// own temp directory, for tests that check a JWT's re-mint: it reuses
// the JWT at path or writes the fresh one there.
func mintOrReuseUserJWTFile(path, pubkey, name string, perms jwt.Permissions, issuerAccountPub string, signingKP nkeys.KeyPair) (bool, error) {
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	signed, minted, err := mintOrReuseUserJWT(string(existing), pubkey, name, perms, issuerAccountPub, signingKP)
	if err != nil || !minted {
		return minted, err
	}
	return true, os.WriteFile(path, []byte(signed), 0o600)
}

// heldSysAccountJWT returns the SYS Account JWT this process holds.
func heldSysAccountJWT(t *testing.T) string {
	t.Helper()
	trust, err := LoadNATSTrustDir(NATSTrustDir())
	if err != nil {
		t.Fatal(err)
	}
	h, ok := heldAccountJWT(trust.SysAccountPub)
	if !ok {
		t.Fatal("no SYS Account JWT held")
	}
	return h.jwt
}

// holdAccountJWT keeps the newest JWT it was given for an account: an
// older one finishing late, or a minimal mint, does not replace it, and
// holding the same JWT again as synced clears its minted mark.
func TestHoldAccountJWTKeepsTheNewest(t *testing.T) {
	setupTestPKI(t)
	op, _ := nkeys.CreateOperator()
	acct, _ := nkeys.CreateAccount()
	pub, _ := acct.PublicKey()
	// Encode stamps the current second as iat: each JWT is signed in a
	// later second than the one before.
	var last int64
	sign := func(name string) string {
		waitPastIssuedAt(last)
		ac := jwt.NewAccountClaims(pub)
		ac.Name = name
		s, err := ac.Encode(op)
		if err != nil {
			t.Fatal(err)
		}
		last = time.Now().Unix()
		return s
	}
	older, newer := sign("older"), sign("newer")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	held := func() heldAccount {
		t.Helper()
		h, ok := heldAccountJWT(pub)
		if !ok {
			t.Fatal("nothing held")
		}
		return h
	}

	must(holdAccountJWT(older, true))
	must(holdAccountJWT(older, false))
	if h := held(); h.jwt != older || h.minted {
		t.Fatalf("holding the same JWT as synced: held %+v", h)
	}
	must(holdAccountJWT(newer, false))
	must(holdAccountJWT(older, false))
	if h := held(); h.jwt != newer {
		t.Fatal("an older JWT replaced the newer one held")
	}
	must(holdAccountJWT(sign("minted"), true))
	if h := held(); h.jwt != newer {
		t.Fatal("a minimal mint replaced a synced JWT")
	}
	if got := heldAccountJWTs(true); len(got) != 1 || got[0] != newer {
		t.Fatalf("heldAccountJWTs(true) = %d JWTs, want the one synced", len(got))
	}
}
