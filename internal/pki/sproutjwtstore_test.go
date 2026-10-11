package pki

// Tests for the per-sprout User JWT store (jwtusers.go,
// MintOrReuseUserJWT): P21 slice 3 brief §6 tests 1-3, plus reuse and
// refusal cases. Each "replica" is its own sproutJWTStore with its own
// lease owner, sharing one sqlite database, one fake bucket and one
// counting signer.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/lease"
	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
)

// countingKP counts Sign calls on an account key pair.
type countingKP struct {
	nkeys.KeyPair
	signs *atomic.Int64
}

// Sign counts the call and signs.
func (k countingKP) Sign(b []byte) ([]byte, error) {
	k.signs.Add(1)
	return k.KeyPair.Sign(b)
}

// sproutJWTEnv is the shared state every replica in a test uses.
type sproutJWTEnv struct {
	db         *gorm.DB
	srv        *objectstoretest.Server
	objects    *objectstore.Store
	accountKP  nkeys.KeyPair
	accountPub string
	signs      atomic.Int64
	issuerHits atomic.Int64
	clock      *testClock
}

// testClock is a settable clock; sleep advances it.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

// Now returns the clock's time.
func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Advance moves the clock on by d.
func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newSproutJWTEnv opens the shared database, bucket and account key.
func newSproutJWTEnv(t *testing.T) *sproutJWTEnv {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "farmer.db")),
		&gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := gdb.DB()
	if err != nil {
		t.Fatal(err)
	}
	// One connection: sqlite serialises writers anyway, and this keeps
	// the concurrent tests from failing with "database is locked".
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := gdb.AutoMigrate(&nkeyRow{}, &revokedNKeyRow{}, &sproutUserJWTRow{}); err != nil {
		t.Fatal(err)
	}
	srv := objectstoretest.NewServer(t)
	objs, err := objectstore.Open(srv.Config())
	if err != nil {
		t.Fatal(err)
	}
	akp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	apub, _ := akp.PublicKey()
	return &sproutJWTEnv{
		db: gdb, srv: srv, objects: objs, accountKP: akp, accountPub: apub,
		clock: &testClock{t: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)},
	}
}

// replica returns one replica's store. realTime selects the wall clock
// (concurrency tests) over the env's settable clock.
func (e *sproutJWTEnv) replica(owner string, realTime bool) *sproutJWTStore {
	now := e.clock.Now
	sleep := func(ctx context.Context, d time.Duration) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		e.clock.Advance(d)
		return nil
	}
	if realTime {
		now, sleep = time.Now, sleepCtx
	}
	return &sproutJWTStore{
		db:      e.db,
		objects: e.objects,
		leases:  lease.New(e.db, now),
		owner:   owner,
		issuer: func(context.Context, string) (string, nkeys.KeyPair, error) {
			e.issuerHits.Add(1)
			return e.accountPub, countingKP{KeyPair: e.accountKP, signs: &e.signs}, nil
		},
		now:   now,
		sleep: sleep,
	}
}

// accept records sprout as accepted in tenant with a fresh user NKey and
// returns its public key.
func (e *sproutJWTEnv) accept(t *testing.T, tenant, sprout string) string {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := kp.PublicKey()
	if err := e.db.Create(&nkeyRow{TenantID: tenant, SproutID: sprout, NKey: pub, State: stateAccepted}).Error; err != nil {
		t.Fatal(err)
	}
	return pub
}

// row reads the sprout_user_jwt row of tenant/sprout.
func (e *sproutJWTEnv) row(t *testing.T, tenant, sprout string) sproutUserJWTRow {
	t.Helper()
	var r sproutUserJWTRow
	if err := e.db.Where("tenant_id = ? AND sprout_id = ?", tenant, sprout).Take(&r).Error; err != nil {
		t.Fatalf("reading sprout_user_jwt row %s/%s: %v", tenant, sprout, err)
	}
	return r
}

// countRows counts sprout_user_jwt rows.
func (e *sproutJWTEnv) countRows(t *testing.T) int64 {
	t.Helper()
	var n int64
	if err := e.db.Model(&sproutUserJWTRow{}).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

// checkStored asserts the row for tenant/sprout points at an object that
// exists, hashes to the row's jwt_sha256, and is a valid User JWT for
// pubkey issued under the env's account.
func (e *sproutJWTEnv) checkStored(t *testing.T, tenant, sprout, pubkey string) string {
	t.Helper()
	r := e.row(t, tenant, sprout)
	if r.ObjectKey == nil || r.JWTSHA256 == nil || r.UserPubkey == nil {
		t.Fatalf("row %s/%s is still pending: %+v", tenant, sprout, r)
	}
	if *r.UserPubkey != pubkey {
		t.Fatalf("row user_pubkey = %s, want %s", *r.UserPubkey, pubkey)
	}
	if r.LeaseOwner != nil {
		t.Errorf("row lease still held by %s after mint", *r.LeaseOwner)
	}
	body, ok := e.srv.Object(*r.ObjectKey)
	if !ok {
		t.Fatalf("row points at %s, which is not in the bucket", *r.ObjectKey)
	}
	sum := sha256.Sum256([]byte(body))
	if hex.EncodeToString(sum[:]) != *r.JWTSHA256 {
		t.Fatalf("object %s does not hash to the row's jwt_sha256", *r.ObjectKey)
	}
	if want := sproutJWTObjectKey(tenant, sprout, *r.JWTSHA256); *r.ObjectKey != want {
		t.Fatalf("object key = %s, want %s", *r.ObjectKey, want)
	}
	uc, err := jwt.DecodeUserClaims(body)
	if err != nil {
		t.Fatalf("stored JWT does not decode: %v", err)
	}
	if uc.Subject != pubkey || uc.IssuerAccount != e.accountPub || uc.Name != sprout {
		t.Fatalf("stored JWT subject %s, issuer account %s, name %s; want %s, %s, %s",
			uc.Subject, uc.IssuerAccount, uc.Name, pubkey, e.accountPub, sprout)
	}
	return body
}

// Brief §6 test 1.
func TestEnrollConcurrentReplicas(t *testing.T) {
	const n = 8
	t.Run("same sprout", func(t *testing.T) {
		e := newSproutJWTEnv(t)
		pub := e.accept(t, "t1", "web-1")
		results := make([]string, n)
		errs := make([]error, n)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r := e.replica(fmt.Sprintf("replica-%d", i), true)
				<-start
				results[i], errs[i] = r.mintOrReuse(context.Background(), "t1", "web-1", pub)
			}()
		}
		close(start)
		wg.Wait()
		for i := range n {
			if errs[i] != nil {
				t.Fatalf("replica %d: %v", i, errs[i])
			}
			if results[i] != results[0] {
				t.Fatalf("replica %d got a different JWT than replica 0", i)
			}
		}
		if got := e.signs.Load(); got != 1 {
			t.Errorf("signer used %d times, want 1", got)
		}
		if got := len(e.srv.Keys()); got != 1 {
			t.Errorf("%d objects in the bucket, want 1: %v", got, e.srv.Keys())
		}
		if got := e.countRows(t); got != 1 {
			t.Errorf("%d rows, want 1", got)
		}
		if body := e.checkStored(t, "t1", "web-1", pub); body != results[0] {
			t.Error("stored JWT is not the one handed out")
		}
	})

	t.Run("distinct sprouts", func(t *testing.T) {
		e := newSproutJWTEnv(t)
		pubs := make([]string, n)
		for i := range n {
			pubs[i] = e.accept(t, "t1", fmt.Sprintf("web-%d", i))
		}
		errs := make([]error, n)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r := e.replica(fmt.Sprintf("replica-%d", i), true)
				<-start
				_, errs[i] = r.mintOrReuse(context.Background(), "t1", fmt.Sprintf("web-%d", i), pubs[i])
			}()
		}
		close(start)
		wg.Wait()
		seen := map[string]bool{}
		for i := range n {
			if errs[i] != nil {
				t.Fatalf("sprout %d: %v", i, errs[i])
			}
			e.checkStored(t, "t1", fmt.Sprintf("web-%d", i), pubs[i])
			r := e.row(t, "t1", fmt.Sprintf("web-%d", i))
			if seen[*r.UserPubkey] {
				t.Fatalf("pubkey %s recorded for two sprouts", *r.UserPubkey)
			}
			seen[*r.UserPubkey] = true
		}
		if got := e.countRows(t); got != n {
			t.Errorf("%d rows, want %d", got, n)
		}
		if got := e.signs.Load(); got != n {
			t.Errorf("signer used %d times, want %d", got, n)
		}
		if got := len(e.srv.Keys()); got != n {
			t.Errorf("%d objects, want %d", got, n)
		}
	})
}

// Concurrent calls on one replica (one owner prefix) still mint once: each
// call holds the lease under its own token.
func TestSproutJWTConcurrentCallsOneReplica(t *testing.T) {
	const n = 8
	e := newSproutJWTEnv(t)
	pub := e.accept(t, "t1", "web-1")
	r := e.replica("replica-a", true)
	results := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results[i], errs[i] = r.mintOrReuse(context.Background(), "t1", "web-1", pub)
		}()
	}
	close(start)
	wg.Wait()
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("call %d: %v", i, errs[i])
		}
		if results[i] != results[0] {
			t.Fatalf("call %d got a different JWT", i)
		}
	}
	if got := e.signs.Load(); got != 1 {
		t.Errorf("signer used %d times on one replica, want 1", got)
	}
}

// Brief §6 test 2.
func TestEnrollReplicaKilledMidMint(t *testing.T) {
	e := newSproutJWTEnv(t)
	pub := e.accept(t, "t1", "web-1")

	a := e.replica("replica-a", false)
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	errKilled := errors.New("replica A killed")
	// Killed after the PUT, before the row UPDATE: its context is gone
	// and it never releases the lease.
	a.afterPut = func() error { cancelA(); return errKilled }
	if _, err := a.mintOrReuse(ctxA, "t1", "web-1", pub); !errors.Is(err, errKilled) {
		t.Fatalf("replica A: err = %v, want it killed mid-mint", err)
	}
	if got := len(e.srv.Keys()); got != 1 {
		t.Fatalf("after A: %d objects, want A's one", got)
	}
	r := e.row(t, "t1", "web-1")
	if r.UserPubkey != nil || r.ObjectKey != nil {
		t.Fatalf("A's row was updated although A died before the UPDATE: %+v", r)
	}
	if r.LeaseOwner == nil || !strings.HasPrefix(*r.LeaseOwner, "replica-a-") {
		t.Fatalf("A's lease is not left behind: %+v", r)
	}

	// B, while A's lease is live, gives up as busy; past lease_until it
	// takes over.
	b := e.replica("replica-b", false)
	if _, err := b.mintOrReuse(context.Background(), "t1", "web-1", pub); !errors.Is(err, ErrSproutJWTBusy) {
		t.Fatalf("B during A's lease: err = %v, want ErrSproutJWTBusy", err)
	}
	e.clock.Advance(sproutJWTLeaseTTL)
	got, err := b.mintOrReuse(context.Background(), "t1", "web-1", pub)
	if err != nil {
		t.Fatalf("B after A's lease lapsed: %v", err)
	}
	if body := e.checkStored(t, "t1", "web-1", pub); body != got {
		t.Error("B handed out a JWT other than the stored one")
	}
	// Every row points at an object (no orphan row); A's object, if its
	// key differs from B's, is harmless and unreferenced.
	if n := e.countRows(t); n != 1 {
		t.Errorf("%d rows, want 1", n)
	}
}

// Brief §6 test 3.
func TestEnrollLeaseNotAcquiredReturnsRetry(t *testing.T) {
	e := newSproutJWTEnv(t)
	pub := e.accept(t, "t1", "web-1")
	if err := e.db.Create(&sproutUserJWTRow{TenantID: "t1", SproutID: "web-1", UpdatedAt: e.clock.Now()}).Error; err != nil {
		t.Fatal(err)
	}
	holder := lease.New(e.db, e.clock.Now)
	if ok, err := holder.Acquire(context.Background(), lease.SproutUserJWT, []any{"t1", "web-1"}, "other", sproutJWTLeaseTTL); err != nil || !ok {
		t.Fatalf("holder Acquire = %v, %v", ok, err)
	}

	r := e.replica("replica-a", false)
	start := e.clock.Now()
	wall := time.Now()
	_, err := r.mintOrReuse(context.Background(), "t1", "web-1", pub)
	if !errors.Is(err, ErrSproutJWTBusy) {
		t.Fatalf("err = %v, want ErrSproutJWTBusy", err)
	}
	if waited := e.clock.Now().Sub(start); waited > sproutJWTPollWait+sproutJWTPollInterval {
		t.Errorf("waited %v on the clock, want at most %v", waited, sproutJWTPollWait)
	}
	if time.Since(wall) > 5*time.Second {
		t.Errorf("took %v of wall time", time.Since(wall))
	}
	if e.signs.Load() != 0 || e.issuerHits.Load() != 0 {
		t.Errorf("signed %d times (issuer loaded %d times) without the lease", e.signs.Load(), e.issuerHits.Load())
	}
	if len(e.srv.Keys()) != 0 {
		t.Errorf("objects written without the lease: %v", e.srv.Keys())
	}
}

func TestSproutJWTReuseAndRemint(t *testing.T) {
	ctx := context.Background()
	e := newSproutJWTEnv(t)
	pub := e.accept(t, "t1", "web-1")
	r := e.replica("replica-a", false)

	first, err := r.mintOrReuse(ctx, "t1", "web-1", pub)
	if err != nil {
		t.Fatal(err)
	}
	again, err := r.mintOrReuse(ctx, "t1", "web-1", pub)
	if err != nil || again != first {
		t.Fatalf("second call = %v; want the stored JWT reused", err)
	}
	if e.signs.Load() != 1 || e.issuerHits.Load() != 1 {
		t.Fatalf("reuse signed (signs %d, issuer loads %d)", e.signs.Load(), e.issuerHits.Load())
	}

	t.Run("tampered object is re-minted", func(t *testing.T) {
		row := e.row(t, "t1", "web-1")
		e.srv.Set(*row.ObjectKey, first+"x")
		got, err := r.mintOrReuse(ctx, "t1", "web-1", pub)
		if err != nil {
			t.Fatal(err)
		}
		if got == first+"x" {
			t.Fatal("handed out an object that does not match its recorded hash")
		}
		e.checkStored(t, "t1", "web-1", pub)
	})

	t.Run("stale permissions are re-minted", func(t *testing.T) {
		uc := jwt.NewUserClaims(pub)
		uc.Name = "web-1"
		uc.IssuerAccount = e.accountPub
		signed, err := uc.Encode(e.accountKP)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(signed))
		hexSum := hex.EncodeToString(sum[:])
		key := sproutJWTObjectKey("t1", "web-1", hexSum)
		e.srv.Set(key, signed)
		if err := e.db.Model(&sproutUserJWTRow{}).Where("tenant_id = ? AND sprout_id = ?", "t1", "web-1").
			Updates(map[string]any{"object_key": key, "jwt_sha256": hexSum}).Error; err != nil {
			t.Fatal(err)
		}
		got, err := r.mintOrReuse(ctx, "t1", "web-1", pub)
		if err != nil {
			t.Fatal(err)
		}
		uc2, _ := jwt.DecodeUserClaims(got)
		if uc2 == nil || !uc2.Pub.Allow.Contains(SproutHeartbeatSubject("web-1")) {
			t.Fatal("JWT with stale permissions was reused")
		}
	})

	t.Run("new key is re-minted", func(t *testing.T) {
		kp, _ := nkeys.CreateUser()
		pub2, _ := kp.PublicKey()
		if err := e.db.Model(&nkeyRow{}).Where("tenant_id = ? AND sprout_id = ?", "t1", "web-1").Update("nkey", pub2).Error; err != nil {
			t.Fatal(err)
		}
		got, err := r.mintOrReuse(ctx, "t1", "web-1", pub2)
		if err != nil {
			t.Fatal(err)
		}
		uc, _ := jwt.DecodeUserClaims(got)
		if uc == nil || uc.Subject != pub2 {
			t.Fatal("JWT not re-minted for the sprout's new key")
		}
		e.checkStored(t, "t1", "web-1", pub2)
	})
}

func TestSproutJWTRefusesIneligible(t *testing.T) {
	ctx := context.Background()
	e := newSproutJWTEnv(t)
	pub := e.accept(t, "t1", "web-1")
	other, _ := nkeys.CreateUser()
	otherPub, _ := other.PublicKey()
	r := e.replica("replica-a", false)

	if _, err := r.mintOrReuse(ctx, "t1", "web-1", otherPub); err == nil {
		t.Error("minted for a key the sprout is not accepted with")
	}
	if _, err := r.mintOrReuse(ctx, "t2", "web-1", pub); !errors.Is(err, ErrSproutIDNotFound) {
		t.Errorf("other tenant: err = %v, want ErrSproutIDNotFound", err)
	}
	if err := e.db.Model(&nkeyRow{}).Where("tenant_id = ? AND sprout_id = ?", "t1", "web-1").Update("state", stateDenied).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := r.mintOrReuse(ctx, "t1", "web-1", pub); err == nil {
		t.Error("minted for a denied sprout")
	}
	if err := e.db.Model(&nkeyRow{}).Where("tenant_id = ? AND sprout_id = ?", "t1", "web-1").Update("state", stateAccepted).Error; err != nil {
		t.Fatal(err)
	}
	if err := e.db.Create(&revokedNKeyRow{TenantID: "t1", NKey: pub, SproutID: "web-1", RevokedAt: 1}).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := r.mintOrReuse(ctx, "t1", "web-1", pub); !errors.Is(err, ErrNKeyRevoked) {
		t.Errorf("revoked key: err = %v, want ErrNKeyRevoked", err)
	}
	if _, err := r.mintOrReuse(ctx, "t1", "-bad", pub); !errors.Is(err, ErrSproutIDInvalid) {
		t.Errorf("bad sprout ID: err = %v", err)
	}
	if e.signs.Load() != 0 || len(e.srv.Keys()) != 0 {
		t.Errorf("signed %d times / wrote %v for ineligible requests", e.signs.Load(), e.srv.Keys())
	}
}

// The same sprout ID in two tenants gets two rows and two JWTs: the store
// keys on (tenant_id, sprout_id).
func TestSproutJWTSameSproutIDTwoTenants(t *testing.T) {
	ctx := context.Background()
	e := newSproutJWTEnv(t)
	pub1 := e.accept(t, "t1", "web-1")
	pub2 := e.accept(t, "t2", "web-1")
	r := e.replica("replica-a", false)
	j1, err := r.mintOrReuse(ctx, "t1", "web-1", pub1)
	if err != nil {
		t.Fatal(err)
	}
	j2, err := r.mintOrReuse(ctx, "t2", "web-1", pub2)
	if err != nil {
		t.Fatal(err)
	}
	if j1 == j2 {
		t.Fatal("two tenants' sprouts share a JWT")
	}
	e.checkStored(t, "t1", "web-1", pub1)
	e.checkStored(t, "t2", "web-1", pub2)
}

func TestSproutJWTBucketMustBePrivate(t *testing.T) {
	SetSproutJWTStore(nil)
	t.Cleanup(func() { SetSproutJWTStore(nil) })
	t.Setenv(SproutJWTBucketEnv, "")
	if _, err := sproutJWTBucket(); !errors.Is(err, ErrSproutJWTStoreNotConfigured) {
		t.Errorf("unset bucket: err = %v", err)
	}
	t.Setenv(SproutJWTBucketEnv, "recipes")
	old := config.S3Bucket
	config.S3Bucket = "recipes"
	t.Cleanup(func() { config.S3Bucket = old })
	if _, err := sproutJWTBucket(); !errors.Is(err, ErrSproutJWTStoreNotConfigured) {
		t.Errorf("recipe bucket reused: err = %v", err)
	}
}

// grantEnrolledSprout, for a tenant that already exists, grants only the
// enrolled NKey (clears its revocation) and applies the tenant's revoked
// list, and refuses a revoked NKey. No bus runs here, so the push fails;
// the re-signed Account JWT is on disk before it.
func TestGrantEnrolledSproutGrantsOnlyThatKey(t *testing.T) {
	setupTestPKI(t)
	if _, _, _, err := ensureTenantAccount("t_g", "Tenant G", true); err != nil {
		t.Fatal(err)
	}
	mk := func() string {
		kp, _ := nkeys.CreateUser()
		pub, _ := kp.PublicKey()
		return pub
	}
	enrolled, other, replaced := mk(), mk(), mk()

	// Start from an Account that revokes the enrolled key and another one.
	mat, tam, _, err := ensureTenantAccount("t_g", "", false)
	if err != nil {
		t.Fatal(err)
	}
	ac, _ := jwt.DecodeAccountClaims(tam.jwt)
	ac.Revoke(enrolled)
	ac.Revoke(other)
	signed, err := ac.Encode(mat.operatorSigningKP)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(tenantAccountJWTPath("t_g"), []byte(signed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&revokedNKeyRow{TenantID: "t_g", NKey: replaced, SproutID: "old", RevokedAt: time.Now().Unix()}).Error; err != nil {
		t.Fatal(err)
	}

	if err := grantEnrolledSprout("t_g", enrolled); !errors.Is(err, errAccountPushFailed) {
		t.Fatalf("grant with no bus: err = %v, want only the push to fail", err)
	}
	b, err := os.ReadFile(tenantAccountJWTPath("t_g"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := jwt.DecodeAccountClaims(string(b))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Revocations[enrolled]; ok {
		t.Error("enrolled NKey is still revoked on the Account")
	}
	if _, ok := got.Revocations[other]; !ok {
		t.Error("another sprout's revocation was cleared")
	}
	if _, ok := got.Revocations[replaced]; !ok {
		t.Error("an NKey on the revoked list is not revoked on the Account")
	}

	if err := grantEnrolledSprout("t_g", replaced); !errors.Is(err, ErrNKeyRevoked) {
		t.Errorf("granting a revoked NKey: err = %v, want ErrNKeyRevoked", err)
	}
	// A refused grant fails enrolment; a failed push alone does not.
	if err := acceptEnrolledNKey("t_g", "web-2", replaced); !errors.Is(err, ErrNKeyRevoked) {
		t.Errorf("acceptEnrolledNKey with a revoked NKey: err = %v, want ErrNKeyRevoked", err)
	}
	if err := acceptEnrolledNKey("t_g", "web-3", mk()); err != nil {
		t.Errorf("acceptEnrolledNKey with only the push failing: %v", err)
	}
}

// A caller that goes away after taking the lease still releases it, so a
// retry is not held off until lease_until.
func TestSproutJWTLeaseReleasedOnCancelledContext(t *testing.T) {
	e := newSproutJWTEnv(t)
	pub := e.accept(t, "t1", "web-1")
	a := e.replica("replica-a", false)
	ctx, cancel := context.WithCancel(context.Background())
	a.afterPut = func() error { cancel(); return nil }
	if _, err := a.mintOrReuse(ctx, "t1", "web-1", pub); err == nil {
		t.Fatal("mint finished with its context cancelled before the row UPDATE")
	}
	if r := e.row(t, "t1", "web-1"); r.LeaseOwner != nil {
		t.Fatalf("lease still held by %s after the caller went away", *r.LeaseOwner)
	}
	b := e.replica("replica-b", false)
	if _, err := b.mintOrReuse(context.Background(), "t1", "web-1", pub); err != nil {
		t.Fatalf("retry without waiting for lease_until: %v", err)
	}
	e.checkStored(t, "t1", "web-1", pub)
}

// A sprout denied or revoked while its JWT is being minted is not handed
// the JWT: eligibility is checked again after signing.
func TestSproutJWTDeniedDuringMintNotReturned(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(e *sproutJWTEnv, pub string) error
	}{
		{"denied", func(e *sproutJWTEnv, _ string) error {
			return e.db.Model(&nkeyRow{}).Where("tenant_id = ? AND sprout_id = ?", "t1", "web-1").Update("state", stateDenied).Error
		}},
		{"deleted and revoked", func(e *sproutJWTEnv, pub string) error {
			if err := e.db.Create(&revokedNKeyRow{TenantID: "t1", NKey: pub, SproutID: "web-1", RevokedAt: 1}).Error; err != nil {
				return err
			}
			return e.db.Where("tenant_id = ? AND sprout_id = ?", "t1", "web-1").Delete(&nkeyRow{}).Error
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newSproutJWTEnv(t)
			pub := e.accept(t, "t1", "web-1")
			r := e.replica("replica-a", false)
			r.afterPut = func() error { return tc.change(e, pub) }
			got, err := r.mintOrReuse(context.Background(), "t1", "web-1", pub)
			if err == nil || got != "" {
				t.Fatalf("got a JWT (err %v) for a sprout %s during its mint", err, tc.name)
			}
			if _, err := r.mintOrReuse(context.Background(), "t1", "web-1", pub); err == nil {
				t.Fatal("a later call served the JWT stored during the mint")
			}
		})
	}
}
