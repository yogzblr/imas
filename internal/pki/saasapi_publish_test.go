package pki

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
)

// fakeCredStore is an in-memory SaaSAPICredentialStore.
type fakeCredStore struct {
	data     map[string]string
	reads    int
	writes   int
	readErr  error
	writeErr error
}

func (f *fakeCredStore) Read(context.Context) (map[string]string, error) {
	f.reads++
	if f.readErr != nil {
		return nil, f.readErr
	}
	if f.data == nil {
		return nil, nil
	}
	out := make(map[string]string, len(f.data))
	for k, v := range f.data {
		out[k] = v
	}
	return out, nil
}

func (f *fakeCredStore) Write(_ context.Context, data map[string]string) error {
	f.writes++
	if f.writeErr != nil {
		return f.writeErr
	}
	f.data = data
	return nil
}

// useExternalSaaSAPISeed hands the SaaS API seed to pki the way ESO does
// in production (a mounted file named by IMAS_NATS_SAASAPI_USER_SEED_FILE)
// and returns its public key.
func useExternalSaaSAPISeed(t *testing.T) (pub string, seed []byte) {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	seed, _ = kp.Seed()
	pub, _ = kp.PublicKey()
	p := filepath.Join(t.TempDir(), "saasapi-user.nk")
	if err := os.WriteFile(p, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IMAS_NATS_SAASAPI_USER_SEED", "")
	t.Setenv("IMAS_NATS_SAASAPI_USER_SEED_FILE", p)
	return pub, seed
}

func clearExternalSeedEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{"SYS_ACCOUNT", saasAPIUserSeedName} {
		t.Setenv(externalSeedEnvPrefix+name+"_SEED", "")
		t.Setenv(externalSeedEnvPrefix+name+"_SEED_FILE", "")
	}
}

func TestPublishSaaSAPICredential_WritesJWTAndPublicKeyOnly(t *testing.T) {
	setupTestPKI(t)
	clearExternalSeedEnv(t)
	if _, err := ensureNatsAuth(); err != nil { // farmer's existing SYS key on disk
		t.Fatal(err)
	}
	pub, _ := useExternalSaaSAPISeed(t)

	store := &fakeCredStore{}
	res, err := PublishSaaSAPICredential(context.Background(), store)
	if err != nil {
		t.Fatalf("PublishSaaSAPICredential: %v", err)
	}
	if !res.Written || res.PublicKey != pub {
		t.Fatalf("result = %+v, want Written for %s", res, pub)
	}
	if len(store.data) != 2 || store.data[SaaSAPICredentialPublicKeyField] != pub {
		t.Fatalf("published fields = %v, want exactly jwt + public_key", store.data)
	}
	onDisk, err := os.ReadFile(SaaSAPIUserJWTPath())
	if err != nil {
		t.Fatal(err)
	}
	if store.data[SaaSAPICredentialJWTField] != string(onDisk) {
		t.Error("published JWT differs from the one EnsureSaaSAPICredential persisted")
	}
}

func TestPublishSaaSAPICredential_IdempotentByClaims(t *testing.T) {
	setupTestPKI(t)
	clearExternalSeedEnv(t)
	if _, err := ensureNatsAuth(); err != nil {
		t.Fatal(err)
	}
	useExternalSaaSAPISeed(t)
	store := &fakeCredStore{}
	ctx := context.Background()
	if _, err := PublishSaaSAPICredential(ctx, store); err != nil {
		t.Fatal(err)
	}
	published := store.data[SaaSAPICredentialJWTField]

	// Same state: nothing written.
	res, err := PublishSaaSAPICredential(ctx, store)
	if err != nil || res.Written || store.writes != 1 {
		t.Fatalf("second run: res=%+v err=%v writes=%d, want a no-op", res, err, store.writes)
	}

	// A byte-different but equivalent JWT on disk (what a Job with a fresh
	// emptyDir mints every run) is still a no-op: equivalence is by claims.
	if err := os.Remove(SaaSAPIUserJWTPath()); err != nil {
		t.Fatal(err)
	}
	res, err = PublishSaaSAPICredential(ctx, store)
	if err != nil || res.Written || store.writes != 1 {
		t.Fatalf("re-mint run: res=%+v err=%v writes=%d, want a no-op", res, err, store.writes)
	}
	if store.data[SaaSAPICredentialJWTField] != published {
		t.Fatal("published JWT changed on a no-op run")
	}
}

func TestPublishSaaSAPICredential_RewritesStaleOrForged(t *testing.T) {
	setupTestPKI(t)
	clearExternalSeedEnv(t)
	mat, err := ensureNatsAuth()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := useExternalSaaSAPISeed(t)

	stalePerms := jwt.NewUserClaims(pub)
	stalePerms.Permissions.Pub.Allow.Add("internal.tenant.provision")
	stalePerms.AllowedConnectionTypes = saasAPIUserConnectionTypes()
	staleJWT, err := stalePerms.Encode(mat.sysAccountKP)
	if err != nil {
		t.Fatal(err)
	}

	otherAcct, _ := nkeys.CreateAccount()
	forged := jwt.NewUserClaims(pub)
	forged.Permissions = saasAPIUserPermissions()
	forged.AllowedConnectionTypes = saasAPIUserConnectionTypes()
	forgedJWT, err := forged.Encode(otherAcct)
	if err != nil {
		t.Fatal(err)
	}

	otherUser, _ := nkeys.CreateUser()
	otherPub, _ := otherUser.PublicKey()

	for name, existing := range map[string]map[string]string{
		"stale permissions":         {SaaSAPICredentialJWTField: staleJWT, SaaSAPICredentialPublicKeyField: pub},
		"signed by another account": {SaaSAPICredentialJWTField: forgedJWT, SaaSAPICredentialPublicKeyField: pub},
		"garbage JWT":               {SaaSAPICredentialJWTField: "not-a-jwt", SaaSAPICredentialPublicKeyField: pub},
		"rotated-out key":           {SaaSAPICredentialJWTField: staleJWT, SaaSAPICredentialPublicKeyField: otherPub},
		"public_key field missing":  {SaaSAPICredentialJWTField: staleJWT},
	} {
		t.Run(name, func(t *testing.T) {
			store := &fakeCredStore{data: existing}
			res, err := PublishSaaSAPICredential(context.Background(), store)
			if err != nil {
				t.Fatalf("PublishSaaSAPICredential: %v", err)
			}
			if !res.Written || store.writes != 1 {
				t.Fatalf("expected a rewrite, got res=%+v writes=%d", res, store.writes)
			}
			uc, err := jwt.DecodeUserClaims(store.data[SaaSAPICredentialJWTField])
			if err != nil || !saasAPIUserJWTIsCurrent(uc, pub, mat.sysAccountPub) {
				t.Fatalf("rewritten JWT isn't current: %v", err)
			}
		})
	}
}

func TestPublishSaaSAPICredential_RefusesToGenerateKeyMaterial(t *testing.T) {
	setupTestPKI(t)
	clearExternalSeedEnv(t)

	// Fresh PKI dir, no SYS Account key: a Job misconfigured without the
	// SYS seed mount must not mint under a random SYS key.
	useExternalSaaSAPISeed(t)
	store := &fakeCredStore{}
	if _, err := PublishSaaSAPICredential(context.Background(), store); !errors.Is(err, ErrSaaSAPIKeyMaterialMissing) {
		t.Fatalf("missing SYS key: expected ErrSaaSAPIKeyMaterialMissing, got %v", err)
	}

	// SYS key present, no SaaS API seed: must not mint for a random key
	// nobody else holds.
	clearExternalSeedEnv(t)
	if _, err := ensureNatsAuth(); err != nil {
		t.Fatal(err)
	}
	if _, err := PublishSaaSAPICredential(context.Background(), store); !errors.Is(err, ErrSaaSAPIKeyMaterialMissing) {
		t.Fatalf("missing SaaS API key: expected ErrSaaSAPIKeyMaterialMissing, got %v", err)
	}
	if store.reads != 0 || store.writes != 0 {
		t.Fatalf("store touched despite refusing: reads=%d writes=%d", store.reads, store.writes)
	}
	if _, err := os.Stat(saasAPIUserSeedPath()); !os.IsNotExist(err) {
		t.Fatalf("a SaaS API seed was generated on disk (stat err=%v)", err)
	}
}

func TestPublishSaaSAPICredential_AcceptsSeedsAlreadyOnDisk(t *testing.T) {
	// Run against farmer's own PKI directory, where both keys already
	// exist from farmer's boot: no external env needed.
	setupTestPKI(t)
	clearExternalSeedEnv(t)
	if _, _, err := EnsureSaaSAPICredential(); err != nil {
		t.Fatal(err)
	}
	store := &fakeCredStore{}
	if res, err := PublishSaaSAPICredential(context.Background(), store); err != nil || !res.Written {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestPublishSaaSAPICredential_StoreErrors(t *testing.T) {
	setupTestPKI(t)
	clearExternalSeedEnv(t)
	if _, err := ensureNatsAuth(); err != nil {
		t.Fatal(err)
	}
	useExternalSaaSAPISeed(t)
	boom := errors.New("boom")

	store := &fakeCredStore{readErr: boom}
	if _, err := PublishSaaSAPICredential(context.Background(), store); !errors.Is(err, boom) || store.writes != 0 {
		t.Fatalf("read error: err=%v writes=%d, want the error and no write", err, store.writes)
	}
	store = &fakeCredStore{writeErr: boom}
	res, err := PublishSaaSAPICredential(context.Background(), store)
	if !errors.Is(err, boom) || res.Written {
		t.Fatalf("write error: res=%+v err=%v", res, err)
	}
}

// A failed resolver push of a rotation revocation still publishes the
// (valid) new credential, then reports the push error.
func TestPublishSaaSAPICredential_PublishesDespitePushFailure(t *testing.T) {
	setupTestPKI(t)
	clearExternalSeedEnv(t)
	config.FarmerBusURL = "127.0.0.1:1" // nothing listening: any push fails
	useExternalSaaSAPISeed(t)
	if _, _, err := EnsureSaaSAPICredential(); err != nil { // old key, no push needed
		t.Fatal(err)
	}
	newPub, _ := useExternalSaaSAPISeed(t) // rotate: revocation + push

	store := &fakeCredStore{}
	res, err := PublishSaaSAPICredential(context.Background(), store)
	if err == nil {
		t.Fatal("expected the push failure to be reported")
	}
	if !res.Written || store.data[SaaSAPICredentialPublicKeyField] != newPub {
		t.Fatalf("expected the rotated-in credential to be published anyway, got res=%+v data=%v", res, store.data)
	}
}
