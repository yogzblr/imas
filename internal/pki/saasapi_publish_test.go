package pki

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	for _, name := range []string{saasAPIUserSeedName} {
		t.Setenv(externalSeedEnvPrefix+name+"_SEED", "")
		t.Setenv(externalSeedEnvPrefix+name+"_SEED_FILE", "")
	}
}

func TestPublishSaaSAPICredential_WritesJWTAndPublicKeyOnly(t *testing.T) {
	setupTestPKI(t)
	clearExternalSeedEnv(t)
	if _, err := ensureNatsAuth(); err != nil { // farmer's SYS key, in Transit
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
	uc, err := jwt.DecodeUserClaims(store.data[SaaSAPICredentialJWTField])
	if err != nil || uc.Subject != pub {
		t.Fatalf("published JWT does not decode to the SaaS API key: %v", err)
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

	// Every run mints a byte-different but equivalent JWT; it is still a
	// no-op, since equivalence is by claims.
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
			if err != nil || !saasAPIUserJWTIsCurrent(uc, pub, mat.sysAccountPub, saasAPINow(), DefaultSaaSAPIUserJWTTTL) {
				t.Fatalf("rewritten JWT isn't current: %v", err)
			}
		})
	}
}

func TestPublishSaaSAPICredential_RefusesToGenerateKeyMaterial(t *testing.T) {
	setupTestPKI(t)
	clearExternalSeedEnv(t)

	// No NATS trust mounted: a Job misconfigured without the trust
	// ConfigMap must not mint at all.
	useExternalSaaSAPISeed(t)
	t.Setenv(NATSTrustDirEnv, t.TempDir())
	store := &fakeCredStore{}
	if _, err := PublishSaaSAPICredential(context.Background(), store); !errors.Is(err, ErrSaaSAPIKeyMaterialMissing) {
		t.Fatalf("missing NATS trust: expected ErrSaaSAPIKeyMaterialMissing, got %v", err)
	}

	// Trust present, no SaaS API seed: must not mint for a random key
	// nobody else holds.
	t.Setenv(NATSTrustDirEnv, testTransit.TrustDir)
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
	// No seed was generated: setupTestPKI's requireNoFarmerPKIWrites.
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
	rec := useTestSaaSAPICredentialState(t)
	oldPub, _ := useExternalSaaSAPISeed(t)
	recordSaaSAPIKey(t, rec, oldPub)
	if _, _, err := EnsureSaaSAPICredential(); err != nil { // old key, no push needed
		t.Fatal(err)
	}
	newPub, _ := useExternalSaaSAPISeed(t)
	recordSaaSAPIKey(t, rec, newPub) // saasapi rotates: revocation + push

	store := &fakeCredStore{}
	res, err := PublishSaaSAPICredential(context.Background(), store)
	if err == nil {
		t.Fatal("expected the push failure to be reported")
	}
	if !res.Written || store.data[SaaSAPICredentialPublicKeyField] != newPub {
		t.Fatalf("expected the rotated-in credential to be published anyway, got res=%+v data=%v", res, store.data)
	}
}

// TestPublishSaaSAPICredential_ExpiresAndIsRefreshed (security review
// 2026-10, L14): the published JWT expires DefaultSaaSAPIUserJWTTTL after
// it is minted; a run while more than a third of that is left writes
// nothing; a run after that writes a fresh one, as does a run on a JWT
// without exp (one published before the expiry existed).
func TestPublishSaaSAPICredential_ExpiresAndIsRefreshed(t *testing.T) {
	setupTestPKI(t)
	clearExternalSeedEnv(t)
	t.Setenv(EnvSaaSAPIUserJWTTTL, "")
	mat, err := ensureNatsAuth()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := useExternalSaaSAPISeed(t)
	start := time.Now()
	now := start
	saasAPINow = func() time.Time { return now }
	t.Cleanup(func() { saasAPINow = time.Now })
	expOf := func(store *fakeCredStore) time.Time {
		t.Helper()
		uc, err := jwt.DecodeUserClaims(store.data[SaaSAPICredentialJWTField])
		if err != nil {
			t.Fatal(err)
		}
		return time.Unix(uc.Expires, 0)
	}

	store := &fakeCredStore{}
	ctx := context.Background()
	if _, err := PublishSaaSAPICredential(ctx, store); err != nil {
		t.Fatal(err)
	}
	first := expOf(store)
	if d := first.Sub(start); d < DefaultSaaSAPIUserJWTTTL-time.Second || d > DefaultSaaSAPIUserJWTTTL+time.Second {
		t.Fatalf("exp is %v after minting, want %v", d, DefaultSaaSAPIUserJWTTTL)
	}

	// 15h in: 9h of 24h left, more than a third. Nothing written.
	now = start.Add(15 * time.Hour)
	if res, err := PublishSaaSAPICredential(ctx, store); err != nil || res.Written {
		t.Fatalf("15h in: res=%+v err=%v, want no write", res, err)
	}
	// 17h in: 7h left, less than a third. A fresh JWT, exp 24h from now.
	now = start.Add(17 * time.Hour)
	res, err := PublishSaaSAPICredential(ctx, store)
	if err != nil || !res.Written || store.writes != 2 {
		t.Fatalf("17h in: res=%+v err=%v writes=%d, want a rewrite", res, err, store.writes)
	}
	if got := expOf(store).Sub(now); got < DefaultSaaSAPIUserJWTTTL-time.Second || got > DefaultSaaSAPIUserJWTTTL+time.Second {
		t.Fatalf("refreshed exp is %v from now, want %v", got, DefaultSaaSAPIUserJWTTTL)
	}

	// A JWT with the right claims but no exp is replaced.
	noExp := jwt.NewUserClaims(pub)
	noExp.Name = saasAPIUserName
	noExp.Permissions = saasAPIUserPermissions()
	noExp.AllowedConnectionTypes = saasAPIUserConnectionTypes()
	noExpJWT, err := noExp.Encode(mat.sysAccountKP)
	if err != nil {
		t.Fatal(err)
	}
	store = &fakeCredStore{data: map[string]string{SaaSAPICredentialJWTField: noExpJWT, SaaSAPICredentialPublicKeyField: pub}}
	if res, err := PublishSaaSAPICredential(ctx, store); err != nil || !res.Written {
		t.Fatalf("no exp: res=%+v err=%v, want a rewrite", res, err)
	}

	// A shorter TTL replaces a JWT that outlives one minted now.
	t.Setenv(EnvSaaSAPIUserJWTTTL, "2h")
	if res, err := PublishSaaSAPICredential(ctx, store); err != nil || !res.Written {
		t.Fatalf("shortened ttl: res=%+v err=%v, want a rewrite", res, err)
	}
	if got := expOf(store).Sub(now); got > 2*time.Hour+time.Second {
		t.Fatalf("exp is %v from now with a 2h ttl", got)
	}
}

func TestSaaSAPIUserJWTTTL(t *testing.T) {
	for v, want := range map[string]time.Duration{"": DefaultSaaSAPIUserJWTTTL, "1h": time.Hour, "720h": MaxSaaSAPIUserJWTTTL, "36h": 36 * time.Hour} {
		t.Setenv(EnvSaaSAPIUserJWTTTL, v)
		if got, err := saasAPIUserJWTTTL(); err != nil || got != want {
			t.Errorf("%q: %v, %v; want %v", v, got, err, want)
		}
	}
	for _, v := range []string{"59m", "721h", "0", "-1h", "1d", "soon"} {
		t.Setenv(EnvSaaSAPIUserJWTTTL, v)
		if _, err := saasAPIUserJWTTTL(); err == nil {
			t.Errorf("%q accepted", v)
		}
	}
	// A bad TTL fails the mint, so no JWT is published with a wrong exp.
	setupTestPKI(t)
	clearExternalSeedEnv(t)
	if _, err := ensureNatsAuth(); err != nil {
		t.Fatal(err)
	}
	useExternalSaaSAPISeed(t)
	t.Setenv(EnvSaaSAPIUserJWTTTL, "soon")
	store := &fakeCredStore{}
	if _, err := PublishSaaSAPICredential(context.Background(), store); err == nil || store.writes != 0 {
		t.Fatalf("bad ttl: err=%v writes=%d, want an error and no write", err, store.writes)
	}
}
