package pki

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/glebarez/sqlite"

	"github.com/yogzblr/imas/internal/lease"
)

// TestSaaSAPIUserPermissions_ExactAllowLists pins the SaaS API User's
// entire NATS reach. It exists to fail loudly on any widening — this
// credential lives in the SYS Account, where an over-broad allow-list
// means server-administration reach (docs/design/imas-internal-api-account.md).
// If you're changing these lists, that's a security-review change: update
// the design doc's permission table alongside this test.
func TestSaaSAPIUserPermissions_ExactAllowLists(t *testing.T) {
	p := saasAPIUserPermissions()
	wantPub := jwt.StringList{"internal.tenant.provision", "internal.tenant.deprovision", "internal.tenant.purge", "internal.sprout.action"}
	wantSub := jwt.StringList{"internal.tenant.provisioned.*", "internal.tenant.deprovisioned.*", "internal.tenant.purged.*", "_INBOX.saasapi.>"}
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

	again, seedAgain, err := EnsureSaaSAPICredential()
	if err != nil {
		t.Fatalf("second EnsureSaaSAPICredential: %v", err)
	}
	if string(seedAgain) != string(seed) {
		t.Fatal("expected a second call to reuse the same seed")
	}
	if uc, err := jwt.DecodeUserClaims(again); err != nil || !saasAPIUserJWTIsCurrent(uc, pub, mat.sysAccountPub) {
		t.Fatalf("expected a second call to mint an equivalent JWT: %v", err)
	}
	// No User JWT file: setupTestPKI's requireNoFarmerPKIWrites.
}

// TestEnsureSaaSAPICredential_ExternalSeedIsUsedAndNeverPersisted mirrors
// loadRequiredSeed's contract for the production shape: the seed comes
// from OpenBao via ESO, and farmer never writes a local copy of it.
func TestEnsureSaaSAPICredential_ExternalSeedIsUsedAndNeverPersisted(t *testing.T) {
	setupTestPKI(t)
	kp, _ := nkeys.CreateUser()
	seed, _ := kp.Seed()
	pub, _ := kp.PublicKey()
	t.Setenv("IMAS_NATS_SAASAPI_USER_SEED_FILE", "")
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
	// No local seed file: setupTestPKI's requireNoFarmerPKIWrites.
}

func TestEnsureSaaSAPICredential_RejectsNonUserSeed(t *testing.T) {
	setupTestPKI(t)
	kp, _ := nkeys.CreateAccount()
	seed, _ := kp.Seed()
	t.Setenv("IMAS_NATS_SAASAPI_USER_SEED_FILE", "")
	t.Setenv("IMAS_NATS_SAASAPI_USER_SEED", string(seed))
	if _, _, err := EnsureSaaSAPICredential(); err == nil {
		t.Fatal("expected an Account seed to be rejected as the SaaS API's User key")
	}
}

// testSaaSAPICredentialState is the saas database farmer's
// EnsureSaaSAPICredential reads the rotation state from in this package's
// tests: sqlite has no saas schema to qualify the table with. Nil means
// no row, as before saasapi records its first credential.
var testSaaSAPICredentialState atomic.Pointer[SaaSAPICredentialRecorder]

func init() {
	readSaaSAPICredentialState = func(ctx context.Context) (*SaaSAPICredentialState, error) {
		if r := testSaaSAPICredentialState.Load(); r != nil {
			return r.State(ctx)
		}
		return nil, nil
	}
}

// newSaaSTestDB opens a sqlite database holding the
// saasapi_credential_state table, standing in for saasapi's saas schema.
// One connection: sqlite serialises writers anyway.
func newSaaSTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "saas.db")),
		&gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { sqlDB.Close() })
	if err := gdb.AutoMigrate(SaaSAPICredentialStateModels()...); err != nil {
		t.Fatal(err)
	}
	return gdb
}

// useTestSaaSAPICredentialState installs a fresh saas database as the
// one farmer reads the rotation state from, and returns a recorder on it.
func useTestSaaSAPICredentialState(t *testing.T) *SaaSAPICredentialRecorder {
	t.Helper()
	rec := NewSaaSAPICredentialRecorder(newSaaSTestDB(t))
	testSaaSAPICredentialState.Store(rec)
	t.Cleanup(func() { testSaaSAPICredentialState.Store(nil) })
	return rec
}

func recordSaaSAPIKey(t *testing.T, rec *SaaSAPICredentialRecorder, pub string) *SaaSAPICredentialState {
	t.Helper()
	st, _, err := rec.Record(context.Background(), pub)
	if err != nil {
		t.Fatalf("Record(%s): %v", pub, err)
	}
	return st
}

func newUserPub(t *testing.T) string {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := kp.PublicKey()
	return pub
}

// replicaRecorder is a second saasapi replica's recorder on the same
// database: its own lease owner and clock.
func replicaRecorder(saasDB *gorm.DB, name string, now func() time.Time) *SaaSAPICredentialRecorder {
	r := NewSaaSAPICredentialRecorder(saasDB)
	r.owner = name
	r.now = now
	r.leases = lease.New(saasDB, now)
	return r
}

func TestSaaSAPICredentialRecorder_FirstRecordAndNoOp(t *testing.T) {
	rec := NewSaaSAPICredentialRecorder(newSaaSTestDB(t))
	ctx := context.Background()
	if st, err := rec.State(ctx); err != nil || st != nil {
		t.Fatalf("State before any record = %+v, %v; want nil", st, err)
	}
	pub := newUserPub(t)
	st, rotated, err := rec.Record(ctx, pub)
	if err != nil || !rotated || st.CurrentPub != pub || st.PrevPub != "" || st.Version != 1 {
		t.Fatalf("first Record = %+v, %v, %v", st, rotated, err)
	}
	st, rotated, err = rec.Record(ctx, pub)
	if err != nil || rotated || st.Version != 1 {
		t.Fatalf("Record of the current key = %+v, %v, %v; want a no-op", st, rotated, err)
	}
	if _, _, err := rec.Record(ctx, "not-a-key"); err == nil {
		t.Fatal("expected an invalid key to be refused")
	}
	acct, _ := nkeys.CreateAccount()
	acctPub, _ := acct.PublicKey()
	if _, _, err := rec.Record(ctx, acctPub); err == nil {
		t.Fatal("expected an Account key to be refused")
	}
}

func TestSaaSAPICredentialRecorder_RotatesAndRefusesRotatingBack(t *testing.T) {
	rec := NewSaaSAPICredentialRecorder(newSaaSTestDB(t))
	ctx := context.Background()
	oldPub, newPub := newUserPub(t), newUserPub(t)
	recordSaaSAPIKey(t, rec, oldPub)
	st, rotated, err := rec.Record(ctx, newPub)
	if err != nil || !rotated || st.CurrentPub != newPub || st.PrevPub != oldPub || st.Version != 2 {
		t.Fatalf("rotation = %+v, %v, %v", st, rotated, err)
	}
	if got, _ := rec.State(ctx); *got != *st {
		t.Fatalf("stored state %+v, returned %+v", got, st)
	}
	// A replica still on the old seed must not undo the rotation.
	if _, _, err := rec.Record(ctx, oldPub); !errors.Is(err, ErrSaaSAPICredentialRotatedOut) {
		t.Fatalf("recording the rotated-out key: err = %v, want ErrSaaSAPICredentialRotatedOut", err)
	}
	if got, _ := rec.State(ctx); got.CurrentPub != newPub || got.Version != 2 {
		t.Fatalf("state changed by a refused record: %+v", got)
	}
	// The lease is released after a rotation.
	var row saasAPICredentialStateRow
	if err := rec.db.Take(&row).Error; err != nil || row.LeaseOwner != nil || row.LeaseUntil != nil {
		t.Fatalf("lease left held: %+v, %v", row, err)
	}
}

// TestSaasapiCredentialRotationConcurrent is the brief's test 11: two
// saasapi replicas rotate; the version check lets exactly one win,
// prev_pub is set, and farmer's SYS Account revocation list includes it.
func TestSaasapiCredentialRotationConcurrent(t *testing.T) {
	setupTestPKI(t)
	clearExternalSeedEnv(t)
	rec := useTestSaaSAPICredentialState(t)
	saasDB := rec.db
	ctx := context.Background()
	oldPub, _ := useExternalSaaSAPISeed(t)
	recordSaaSAPIKey(t, rec, oldPub)

	t.Run("same new key at once: one rotation", func(t *testing.T) {
		newPub := newUserPub(t)
		const n = 8
		var wg sync.WaitGroup
		var rotations, busy atomic.Int32
		errs := make(chan error, n)
		for i := 0; i < n; i++ {
			r := replicaRecorder(saasDB, "replica-"+string(rune('a'+i)), time.Now)
			wg.Add(1)
			go func() {
				defer wg.Done()
				// A replica that loses the lease retries, as saasapi's
				// boot would, until the key is current.
				for {
					_, rotated, err := r.Record(ctx, newPub)
					if errors.Is(err, ErrSaaSAPICredentialBusy) {
						busy.Add(1)
						time.Sleep(time.Millisecond)
						continue
					}
					if err != nil {
						errs <- err
					} else if rotated {
						rotations.Add(1)
					}
					return
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Fatal(err)
		}
		if rotations.Load() != 1 {
			t.Fatalf("%d replicas rotated, want exactly 1", rotations.Load())
		}
		st, err := rec.State(ctx)
		if err != nil || st.CurrentPub != newPub || st.PrevPub != oldPub || st.Version != 2 {
			t.Fatalf("state after concurrent rotation = %+v, %v", st, err)
		}
		oldPub = newPub
	})

	t.Run("lease lapses mid-rotation: the version check decides", func(t *testing.T) {
		clock := &testClock{t: time.Now()}
		keyA, keyB := newUserPub(t), newUserPub(t)
		a := replicaRecorder(saasDB, "replica-a", clock.Now)
		b := replicaRecorder(saasDB, "replica-b", clock.Now)
		var bErr error
		var bRotated bool
		// A takes the lease and re-reads, then stalls past its TTL; B takes
		// the lapsed lease and rotates first.
		a.beforeUpdate = func() {
			clock.Advance(saasAPICredentialLeaseTTL + time.Second)
			_, bRotated, bErr = b.Record(ctx, keyB)
		}
		_, aRotated, aErr := a.Record(ctx, keyA)
		if bErr != nil || !bRotated {
			t.Fatalf("replica B: rotated=%v err=%v, want its rotation to win", bRotated, bErr)
		}
		if !errors.Is(aErr, ErrSaaSAPICredentialBusy) || aRotated {
			t.Fatalf("replica A: rotated=%v err=%v, want ErrSaaSAPICredentialBusy", aRotated, aErr)
		}
		st, err := rec.State(ctx)
		if err != nil || st.CurrentPub != keyB || st.PrevPub != oldPub || st.Version != 3 {
			t.Fatalf("state = %+v, %v; want B's rotation from %s at version 3", st, err, oldPub)
		}
	})

	// Farmer: its seed is the key saasapi rotates to next; the
	// revocation list it builds includes prev_pub.
	newPub, _ := useExternalSaaSAPISeed(t)
	recordSaaSAPIKey(t, rec, newPub)
	st, err := rec.State(ctx)
	if err != nil || st.PrevPub == "" || st.CurrentPub != newPub {
		t.Fatalf("state = %+v", st)
	}
	// No bus in this test: the push fails, after the SYS Account JWT is
	// re-signed and held.
	userJWT, _, _ := EnsureSaaSAPICredential()
	if uc, err := jwt.DecodeUserClaims(userJWT); err != nil || uc.Subject != newPub {
		t.Fatalf("minted JWT for the wrong key: %v", err)
	}
	sysClaims, err := jwt.DecodeAccountClaims(heldSysAccountJWT(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := sysClaims.Revocations[st.PrevPub]; !ok {
		t.Fatalf("SYS Account revocations %v do not include prev_pub %s", sysClaims.Revocations, st.PrevPub)
	}
	if _, ok := sysClaims.Revocations[newPub]; ok {
		t.Fatal("the current key is revoked")
	}
}

// TestEnsureSaaSAPICredential_NoStateNoRevocation: before saasapi records
// any credential, farmer revokes nothing.
func TestEnsureSaaSAPICredential_NoStateNoRevocation(t *testing.T) {
	setupTestPKI(t)
	clearExternalSeedEnv(t)
	useTestSaaSAPICredentialState(t)
	useExternalSaaSAPISeed(t)
	if _, _, err := EnsureSaaSAPICredential(); err != nil {
		t.Fatal(err)
	}
	sysClaims, err := jwt.DecodeAccountClaims(heldSysAccountJWT(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(sysClaims.Revocations) != 0 {
		t.Fatalf("revocations = %v, want none", sysClaims.Revocations)
	}
}

// TestEnsureSaaSAPICredential_StateReadErrorStillMints: a failed state
// read is logged; the credential is still minted.
func TestEnsureSaaSAPICredential_StateReadErrorStillMints(t *testing.T) {
	setupTestPKI(t)
	clearExternalSeedEnv(t)
	orig := readSaaSAPICredentialState
	readSaaSAPICredentialState = func(context.Context) (*SaaSAPICredentialState, error) {
		return nil, errors.New("boom")
	}
	t.Cleanup(func() { readSaaSAPICredentialState = orig })
	pub, _ := useExternalSaaSAPISeed(t)
	userJWT, _, err := EnsureSaaSAPICredential()
	if err != nil {
		t.Fatal(err)
	}
	if uc, err := jwt.DecodeUserClaims(userJWT); err != nil || uc.Subject != pub {
		t.Fatalf("minted JWT: %v", err)
	}
}
