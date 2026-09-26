package pki

import (
	"os"
	"path/filepath"
	"testing"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
)

func TestEnsureNatsAuth_BootstrapsAndIsIdempotent(t *testing.T) {
	setupTestPKI(t)

	mat, err := ensureNatsAuth()
	if err != nil {
		t.Fatalf("ensureNatsAuth failed: %v", err)
	}
	if !nkeys.IsValidPublicOperatorKey(mat.operatorPub) {
		t.Errorf("expected a valid operator public key, got %q", mat.operatorPub)
	}
	if !nkeys.IsValidPublicAccountKey(mat.sysAccountPub) {
		t.Errorf("expected a valid SYS account public key, got %q", mat.sysAccountPub)
	}
	if !nkeys.IsValidPublicAccountKey(mat.tenantPub) {
		t.Errorf("expected a valid tenant account public key, got %q", mat.tenantPub)
	}
	if !nkeys.IsValidPublicUserKey(mat.sysUserPub) {
		t.Errorf("expected a valid SYS user public key, got %q", mat.sysUserPub)
	}

	opClaims, err := jwt.DecodeOperatorClaims(mat.operatorJWT)
	if err != nil {
		t.Fatalf("operator JWT does not decode: %v", err)
	}
	if opClaims.SystemAccount != mat.sysAccountPub {
		t.Errorf("operator JWT SystemAccount = %q, want %q", opClaims.SystemAccount, mat.sysAccountPub)
	}

	// Re-running bootstrap must be idempotent: same keys, same JWTs.
	mat2, err := ensureNatsAuth()
	if err != nil {
		t.Fatalf("second ensureNatsAuth failed: %v", err)
	}
	if mat2.operatorPub != mat.operatorPub {
		t.Error("operator public key changed across ensureNatsAuth calls")
	}
	if mat2.tenantPub != mat.tenantPub {
		t.Error("tenant account public key changed across ensureNatsAuth calls")
	}
	if mat2.operatorJWT != mat.operatorJWT {
		t.Error("operator JWT changed across ensureNatsAuth calls without cause")
	}

	// Seeds must be persisted with restrictive permissions.
	for _, name := range []string{"operator.nk", "operator-signing.nk", "sys-account.nk", "sys-user.nk", "tenant.nk", "tenant-signing.nk"} {
		info, statErr := os.Stat(filepath.Join(natsAuthDir(), name))
		if statErr != nil {
			t.Errorf("expected %s to exist: %v", name, statErr)
			continue
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s has perm %v, want 0600", name, info.Mode().Perm())
		}
	}
}

func TestLoadOrCreateSeed_ExternalSeedFile(t *testing.T) {
	setupTestPKI(t)

	kp, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatalf("failed to create operator NKey: %v", err)
	}
	wantPub, _ := kp.PublicKey()
	seed, _ := kp.Seed()

	seedFile := filepath.Join(t.TempDir(), "operator.seed")
	if err := os.WriteFile(seedFile, seed, 0o600); err != nil {
		t.Fatalf("failed to write seed file: %v", err)
	}
	t.Setenv("IMAS_NATS_OPERATOR_SEED_FILE", seedFile)

	localPath := filepath.Join(t.TempDir(), "operator.nk")
	got, err := loadOrCreateSeed(localPath, "OPERATOR", nkeys.CreateOperator)
	if err != nil {
		t.Fatalf("loadOrCreateSeed failed: %v", err)
	}
	gotPub, _ := got.PublicKey()
	if gotPub != wantPub {
		t.Errorf("expected the externally-supplied operator key %q, got %q", wantPub, gotPub)
	}
	if _, statErr := os.Stat(localPath); !os.IsNotExist(statErr) {
		t.Error("expected no local copy to be written when the seed comes from an external file")
	}
}

func TestLoadOrCreateSeed_ExternalSeedEnvVar(t *testing.T) {
	setupTestPKI(t)

	kp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatalf("failed to create account NKey: %v", err)
	}
	wantPub, _ := kp.PublicKey()
	seed, _ := kp.Seed()
	t.Setenv("IMAS_NATS_TENANT_SEED", string(seed))

	localPath := filepath.Join(t.TempDir(), "tenant.nk")
	got, err := loadOrCreateSeed(localPath, "TENANT", nkeys.CreateAccount)
	if err != nil {
		t.Fatalf("loadOrCreateSeed failed: %v", err)
	}
	gotPub, _ := got.PublicKey()
	if gotPub != wantPub {
		t.Errorf("expected the externally-supplied tenant key %q, got %q", wantPub, gotPub)
	}
	if _, statErr := os.Stat(localPath); !os.IsNotExist(statErr) {
		t.Error("expected no local copy to be written when the seed comes from an env var")
	}
}

func TestLoadOrCreateSeed_SeedFileTakesPrecedenceOverEnvVar(t *testing.T) {
	setupTestPKI(t)

	fileKP, _ := nkeys.CreateUser()
	filePub, _ := fileKP.PublicKey()
	fileSeed, _ := fileKP.Seed()
	seedFile := filepath.Join(t.TempDir(), "sys-user.seed")
	if err := os.WriteFile(seedFile, fileSeed, 0o600); err != nil {
		t.Fatalf("failed to write seed file: %v", err)
	}

	envKP, _ := nkeys.CreateUser()
	envSeed, _ := envKP.Seed()

	t.Setenv("IMAS_NATS_SYS_USER_SEED_FILE", seedFile)
	t.Setenv("IMAS_NATS_SYS_USER_SEED", string(envSeed))

	got, err := loadOrCreateSeed(filepath.Join(t.TempDir(), "sys-user.nk"), "SYS_USER", nkeys.CreateUser)
	if err != nil {
		t.Fatalf("loadOrCreateSeed failed: %v", err)
	}
	gotPub, _ := got.PublicKey()
	if gotPub != filePub {
		t.Errorf("expected _SEED_FILE to take precedence, got a different key")
	}
}

func TestEnsureNatsAuth_DefaultTenantName(t *testing.T) {
	setupTestPKI(t)
	config.FarmerOrganization = ""

	mat, err := ensureNatsAuth()
	if err != nil {
		t.Fatalf("ensureNatsAuth failed: %v", err)
	}
	if mat.tenantName != "imas" {
		t.Errorf("expected default tenant name %q, got %q", "imas", mat.tenantName)
	}
}

func TestEnsureUserGrantedAndRevoked(t *testing.T) {
	akp, _ := nkeys.CreateAccount()
	apub, _ := akp.PublicKey()
	ac := jwt.NewAccountClaims(apub)

	ukp, _ := nkeys.CreateUser()
	upub, _ := ukp.PublicKey()

	if changed := ensureUserGranted(ac, upub); changed {
		t.Error("granting an already-unrevoked key should report no change")
	}

	if changed := ensureUserRevoked(ac, upub); !changed {
		t.Error("revoking a fresh key should report a change")
	}
	if _, revoked := ac.Revocations[upub]; !revoked {
		t.Fatal("expected a revocation entry after ensureUserRevoked")
	}

	// Re-revoking is a no-op (idempotent, no unnecessary account churn).
	if changed := ensureUserRevoked(ac, upub); changed {
		t.Error("re-revoking an already-revoked key should report no change")
	}

	if changed := ensureUserGranted(ac, upub); !changed {
		t.Error("clearing an existing revocation should report a change")
	}
	if _, revoked := ac.Revocations[upub]; revoked {
		t.Fatal("expected revocation entry to be cleared after ensureUserGranted")
	}

	// Clearing an already-clear entry is a no-op.
	if changed := ensureUserGranted(ac, upub); changed {
		t.Error("re-granting an already-granted key should report no change")
	}
}

func TestMintOrReuseUserJWT(t *testing.T) {
	setupTestPKI(t)
	mat, err := ensureNatsAuth()
	if err != nil {
		t.Fatalf("ensureNatsAuth failed: %v", err)
	}

	ukp, _ := nkeys.CreateUser()
	upub, _ := ukp.PublicKey()
	path := filepath.Join(t.TempDir(), "sprout.jwt")

	minted, err := mintOrReuseUserJWT(path, upub, "sprout01", sproutPermissions("sprout01"), mat.tenantPub, mat.tenantSigningKP)
	if err != nil {
		t.Fatalf("mintOrReuseUserJWT failed: %v", err)
	}
	if !minted {
		t.Error("expected a fresh mint on first call")
	}

	uc, err := jwt.DecodeUserClaims(mustReadFile(t, path))
	if err != nil {
		t.Fatalf("minted JWT does not decode: %v", err)
	}
	if uc.Subject != upub {
		t.Errorf("minted JWT subject = %q, want %q", uc.Subject, upub)
	}
	if uc.IssuerAccount != mat.tenantPub {
		t.Errorf("minted JWT IssuerAccount = %q, want %q", uc.IssuerAccount, mat.tenantPub)
	}
	if !uc.Permissions.Sub.Allow.Contains("imas.sprouts.sprout01.>") {
		t.Errorf("minted JWT missing expected subscribe permission: %+v", uc.Permissions)
	}

	// Calling again for the same pubkey should reuse the file, not re-mint.
	minted, err = mintOrReuseUserJWT(path, upub, "sprout01", sproutPermissions("sprout01"), mat.tenantPub, mat.tenantSigningKP)
	if err != nil {
		t.Fatalf("mintOrReuseUserJWT (reuse) failed: %v", err)
	}
	if minted {
		t.Error("expected reuse (no re-mint) on second call for the same pubkey")
	}

	// A different pubkey at the same path must trigger a re-mint.
	ukp2, _ := nkeys.CreateUser()
	upub2, _ := ukp2.PublicKey()
	minted, err = mintOrReuseUserJWT(path, upub2, "sprout01", sproutPermissions("sprout01"), mat.tenantPub, mat.tenantSigningKP)
	if err != nil {
		t.Fatalf("mintOrReuseUserJWT (rotate) failed: %v", err)
	}
	if !minted {
		t.Error("expected a re-mint when the underlying NKey pubkey changes")
	}
}

func TestGetSproutUserJWT(t *testing.T) {
	setupTestPKI(t)
	mat, err := ensureNatsAuth()
	if err != nil {
		t.Fatalf("ensureNatsAuth failed: %v", err)
	}

	ukp, _ := nkeys.CreateUser()
	upub, _ := ukp.PublicKey()
	if _, err := mintOrReuseUserJWT(sproutJWTPath("sprout01"), upub, "sprout01", sproutPermissions("sprout01"), mat.tenantPub, mat.tenantSigningKP); err != nil {
		t.Fatalf("mintOrReuseUserJWT failed: %v", err)
	}

	got, err := GetSproutUserJWT("sprout01")
	if err != nil {
		t.Fatalf("GetSproutUserJWT failed: %v", err)
	}
	uc, err := jwt.DecodeUserClaims(got)
	if err != nil {
		t.Fatalf("returned JWT does not decode: %v", err)
	}
	if uc.Subject != upub {
		t.Errorf("returned JWT subject = %q, want %q", uc.Subject, upub)
	}

	if _, err := GetSproutUserJWT("no-such-sprout"); err != ErrSproutIDNotFound {
		t.Errorf("expected ErrSproutIDNotFound, got %v", err)
	}
	if _, err := GetSproutUserJWT("-bad"); err != ErrSproutIDInvalid {
		t.Errorf("expected ErrSproutIDInvalid, got %v", err)
	}
}

func TestFarmerUserJWT(t *testing.T) {
	setupTestPKI(t)

	// setupTestPKI seeds config.NKeyFarmerPubFile with a placeholder string
	// that isn't a valid NKey, so mintOrReuseUserJWT would reject it as the
	// farmer User JWT's subject. Overwrite it with a real farmer NKey
	// keypair's public key, the way certs.GenNKey(true) would in main().
	fkp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("failed to create test farmer NKey: %v", err)
	}
	farmerPub, err := fkp.PublicKey()
	if err != nil {
		t.Fatalf("failed to get test farmer NKey public key: %v", err)
	}
	if err := os.WriteFile(config.NKeyFarmerPubFile, []byte(farmerPub), 0o600); err != nil {
		t.Fatalf("failed to write test farmer NKey public key: %v", err)
	}

	if _, err := FarmerUserJWT(); err == nil {
		t.Error("expected an error before ReloadNKeys has minted the farmer's User JWT")
	}

	if err := ReloadNKeys(); err != nil {
		t.Fatalf("ReloadNKeys failed: %v", err)
	}

	got, err := FarmerUserJWT()
	if err != nil {
		t.Fatalf("FarmerUserJWT failed: %v", err)
	}
	uc, err := jwt.DecodeUserClaims(got)
	if err != nil {
		t.Fatalf("returned JWT does not decode: %v", err)
	}
	if uc.Subject != farmerPub {
		t.Errorf("returned JWT subject = %q, want %q", uc.Subject, farmerPub)
	}
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	return string(b)
}
