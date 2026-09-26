package pki

import (
	"os"
	"reflect"
	"testing"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// TestSaaSAPIUserPermissions_ExactAllowLists pins the SaaS API User's
// entire NATS reach. It exists to fail loudly on any widening — this
// credential lives in the SYS Account, where an over-broad allow-list
// means server-administration reach (docs/design/imas-internal-api-account.md).
// If you're changing these lists, that's a security-review change: update
// the design doc's permission table alongside this test.
func TestSaaSAPIUserPermissions_ExactAllowLists(t *testing.T) {
	p := saasAPIUserPermissions()
	wantPub := jwt.StringList{"internal.tenant.provision", "internal.tenant.deprovision", "internal.sprout.action"}
	wantSub := jwt.StringList{"internal.tenant.provisioned.*", "internal.tenant.deprovisioned.*", "_INBOX.saasapi.>"}
	if !reflect.DeepEqual(p.Pub.Allow, wantPub) {
		t.Fatalf("pub allow = %v, want %v", p.Pub.Allow, wantPub)
	}
	if !reflect.DeepEqual(p.Sub.Allow, wantSub) {
		t.Fatalf("sub allow = %v, want %v", p.Sub.Allow, wantSub)
	}
	if len(p.Pub.Deny) != 0 || len(p.Sub.Deny) != 0 || p.Resp != nil {
		t.Fatalf("unexpected deny lists / response permission: %+v", p)
	}
	if got := saasAPIUserConnectionTypes(); !reflect.DeepEqual(got, jwt.StringList{jwt.ConnectionTypeStandard}) {
		t.Fatalf("allowed connection types = %v, want [STANDARD]", got)
	}
}

func TestEnsureSaaSAPICredential_MintsScopedSYSUserAndIsIdempotent(t *testing.T) {
	setupTestPKI(t)

	userJWT, seed, err := EnsureSaaSAPICredential()
	if err != nil {
		t.Fatalf("EnsureSaaSAPICredential: %v", err)
	}
	mat, err := ensureNatsAuth()
	if err != nil {
		t.Fatalf("ensureNatsAuth: %v", err)
	}

	kp, err := nkeys.FromSeed(seed)
	if err != nil {
		t.Fatalf("returned seed is not a valid NKey seed: %v", err)
	}
	pub, _ := kp.PublicKey()
	if nkeys.Prefix(pub) != nkeys.PrefixByteUser {
		t.Fatalf("expected a User NKey, got prefix %v", nkeys.Prefix(pub))
	}

	uc, err := jwt.DecodeUserClaims(userJWT)
	if err != nil {
		t.Fatalf("decoding minted JWT: %v", err)
	}
	if uc.Subject != pub {
		t.Fatalf("subject = %s, want the seed's public key %s", uc.Subject, pub)
	}
	if uc.Issuer != mat.sysAccountPub {
		t.Fatalf("issuer = %s, want the SYS Account %s", uc.Issuer, mat.sysAccountPub)
	}
	if uc.Issuer == mat.tenantPub || uc.IssuerAccount != "" {
		t.Fatalf("expected the credential to be issued directly by SYS, not a tenant Account or signing key: %+v", uc)
	}
	if !reflect.DeepEqual(uc.Permissions, saasAPIUserPermissions()) {
		t.Fatalf("permissions = %+v, want %+v", uc.Permissions, saasAPIUserPermissions())
	}
	if !reflect.DeepEqual(uc.AllowedConnectionTypes, saasAPIUserConnectionTypes()) {
		t.Fatalf("connection types = %v", uc.AllowedConnectionTypes)
	}
	if onDisk := mustReadFile(t, SaaSAPIUserJWTPath()); onDisk != userJWT {
		t.Fatal("expected the minted JWT to be persisted to SaaSAPIUserJWTPath")
	}

	again, seedAgain, err := EnsureSaaSAPICredential()
	if err != nil {
		t.Fatalf("second EnsureSaaSAPICredential: %v", err)
	}
	if again != userJWT || string(seedAgain) != string(seed) {
		t.Fatal("expected a second call to reuse the same JWT and seed")
	}
}

// TestEnsureSaaSAPICredential_RemintsOnPermissionDrift covers a JWT left on
// disk from an older build with a different (here: wider) permission set
// for the same key: it must be replaced, not reused just because the
// subject still matches.
func TestEnsureSaaSAPICredential_RemintsOnPermissionDrift(t *testing.T) {
	setupTestPKI(t)
	if _, _, err := EnsureSaaSAPICredential(); err != nil {
		t.Fatalf("EnsureSaaSAPICredential: %v", err)
	}
	mat, _ := ensureNatsAuth()
	stale, _ := jwt.DecodeUserClaims(mustReadFile(t, SaaSAPIUserJWTPath()))
	stale.Permissions = jwt.Permissions{
		Pub: jwt.Permission{Allow: jwt.StringList{">"}},
		Sub: jwt.Permission{Allow: jwt.StringList{">"}},
	}
	staleJWT, err := stale.Encode(mat.sysAccountKP)
	if err != nil {
		t.Fatalf("encoding stale JWT: %v", err)
	}
	if err := os.WriteFile(SaaSAPIUserJWTPath(), []byte(staleJWT), 0o600); err != nil {
		t.Fatalf("writing stale JWT: %v", err)
	}

	fresh, _, err := EnsureSaaSAPICredential()
	if err != nil {
		t.Fatalf("EnsureSaaSAPICredential: %v", err)
	}
	if fresh == staleJWT {
		t.Fatal("expected the over-broad JWT on disk to be re-minted")
	}
	uc, _ := jwt.DecodeUserClaims(fresh)
	if !reflect.DeepEqual(uc.Permissions, saasAPIUserPermissions()) {
		t.Fatalf("re-minted permissions = %+v", uc.Permissions)
	}
}

// TestEnsureSaaSAPICredential_ExternalSeedIsUsedAndNeverPersisted mirrors
// loadOrCreateSeed's contract for the production shape: the seed comes
// from OpenBao via ESO, and farmer never writes a local copy of it.
func TestEnsureSaaSAPICredential_ExternalSeedIsUsedAndNeverPersisted(t *testing.T) {
	setupTestPKI(t)
	kp, _ := nkeys.CreateUser()
	seed, _ := kp.Seed()
	pub, _ := kp.PublicKey()
	t.Setenv("IMAS_NATS_SAASAPI_USER_SEED", string(seed))

	userJWT, gotSeed, err := EnsureSaaSAPICredential()
	if err != nil {
		t.Fatalf("EnsureSaaSAPICredential: %v", err)
	}
	if string(gotSeed) != string(seed) {
		t.Fatal("expected the externally-supplied seed to be returned")
	}
	uc, _ := jwt.DecodeUserClaims(userJWT)
	if uc.Subject != pub {
		t.Fatalf("subject = %s, want %s", uc.Subject, pub)
	}
	if _, err := os.Stat(saasAPIUserSeedPath()); !os.IsNotExist(err) {
		t.Fatalf("expected no local seed file for an externally-supplied seed, stat err = %v", err)
	}
}

func TestEnsureSaaSAPICredential_RejectsNonUserSeed(t *testing.T) {
	setupTestPKI(t)
	kp, _ := nkeys.CreateAccount()
	seed, _ := kp.Seed()
	t.Setenv("IMAS_NATS_SAASAPI_USER_SEED", string(seed))
	if _, _, err := EnsureSaaSAPICredential(); err == nil {
		t.Fatal("expected an Account seed to be rejected as the SaaS API's User key")
	}
}
