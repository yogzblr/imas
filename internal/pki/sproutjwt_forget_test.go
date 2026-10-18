package pki

// Deleting a sprout removes its stored User JWT (DeleteNKey,
// forgetSproutUserJWT): the sprout_user_jwt row and the bucket object,
// for that tenant only, including when the delete lands mid-mint.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/lease"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
)

// forgetEnv is the package database and fake bucket setupTestPKI
// installs, plus a store on them that signs with a test account key.
type forgetEnv struct {
	srv   *objectstoretest.Server
	store *sproutJWTStore
}

func newForgetEnv(t *testing.T) *forgetEnv {
	t.Helper()
	setupTestPKI(t)
	srv := useTestSproutJWTStore(t)
	objs, err := sproutJWTBucket()
	if err != nil {
		t.Fatal(err)
	}
	akp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	apub, _ := akp.PublicKey()
	return &forgetEnv{srv: srv, store: &sproutJWTStore{
		db:      db,
		objects: objs,
		leases:  lease.New(db, nil),
		owner:   "replica-a",
		issuer: func(context.Context, string) (string, nkeys.KeyPair, error) {
			return apub, akp, nil
		},
		now:   time.Now,
		sleep: sleepCtx,
	}}
}

// accept records sprout as accepted in tenant and returns its NKey.
func (e *forgetEnv) accept(t *testing.T, tenant, sprout string) string {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := kp.PublicKey()
	if err := db.Create(&nkeyRow{TenantID: tenant, SproutID: sprout, NKey: pub, State: stateAccepted}).Error; err != nil {
		t.Fatal(err)
	}
	return pub
}

// stored returns tenant/sprout's sprout_user_jwt row, or ok false.
func (e *forgetEnv) stored(t *testing.T, tenant, sprout string) (sproutUserJWTRow, bool) {
	t.Helper()
	var r sproutUserJWTRow
	res := db.Where("tenant_id = ? AND sprout_id = ?", tenant, sprout).Limit(1).Find(&r)
	if res.Error != nil {
		t.Fatal(res.Error)
	}
	return r, res.RowsAffected == 1
}

// objectsOf lists the bucket keys under tenant/sprout/.
func (e *forgetEnv) objectsOf(tenant, sprout string) []string {
	var out []string
	for _, k := range e.srv.Keys() {
		if strings.HasPrefix(k, tenant+"/"+sprout+"/") {
			out = append(out, k)
		}
	}
	return out
}

func TestDeleteNKeyForgetsSproutUserJWT(t *testing.T) {
	ctx := context.Background()
	e := newForgetEnv(t)
	pub1 := e.accept(t, "t1", "web-1")
	pub2 := e.accept(t, "t2", "web-1")
	if _, err := e.store.mintOrReuse(ctx, "t1", "web-1", pub1); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.mintOrReuse(ctx, "t2", "web-1", pub2); err != nil {
		t.Fatal(err)
	}
	r1, ok := e.stored(t, "t1", "web-1")
	if !ok || r1.ObjectKey == nil {
		t.Fatalf("t1/web-1 has no stored JWT before the delete: %+v", r1)
	}
	r2, _ := e.stored(t, "t2", "web-1")

	if err := DeleteNKey("t1", "web-1"); err != nil {
		t.Fatal(err)
	}
	if r, ok := e.stored(t, "t1", "web-1"); ok {
		t.Errorf("t1/web-1's sprout_user_jwt row survived the delete: %+v", r)
	}
	if _, ok := e.srv.Object(*r1.ObjectKey); ok {
		t.Errorf("t1/web-1's JWT object %s survived the delete", *r1.ObjectKey)
	}
	// Same sprout ID, other tenant: untouched.
	if r, ok := e.stored(t, "t2", "web-1"); !ok || r.ObjectKey == nil || *r.ObjectKey != *r2.ObjectKey {
		t.Errorf("t2/web-1's row changed: %+v, want object %s", r, *r2.ObjectKey)
	}
	if _, ok := e.srv.Object(*r2.ObjectKey); !ok {
		t.Errorf("t2/web-1's JWT object %s was deleted", *r2.ObjectKey)
	}
	// And a mint for the deleted sprout cannot bring the row back.
	if _, err := e.store.mintOrReuse(ctx, "t1", "web-1", pub1); !errors.Is(err, ErrSproutIDNotFound) {
		t.Errorf("mint after delete: err = %v, want ErrSproutIDNotFound", err)
	}
	if r, ok := e.stored(t, "t1", "web-1"); ok {
		t.Errorf("mint after delete recreated the row: %+v", r)
	}
}

// A delete that lands while a mint is in flight (after its first
// eligibility check) leaves no row or object either.
func TestDeleteNKeyMidMintLeavesNoSproutUserJWT(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		// del runs between the mint's object PUT and its row UPDATE.
		del func(t *testing.T)
	}{
		{"row forgotten before the update", func(t *testing.T) {
			if err := DeleteNKey("t1", "web-1"); err != nil {
				t.Fatal(err)
			}
		}},
		{"row recreated after the forget", func(t *testing.T) {
			// The pki_nkeys row goes, but the forget ran before this
			// mint's INSERT IGNORE: the mint's last check must clean up.
			if err := db.Where("tenant_id = ? AND sprout_id = ?", "t1", "web-1").Delete(&nkeyRow{}).Error; err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newForgetEnv(t)
			pub := e.accept(t, "t1", "web-1")
			e.store.afterPut = func() error {
				tc.del(t)
				return nil
			}
			if _, err := e.store.mintOrReuse(ctx, "t1", "web-1", pub); err == nil {
				t.Fatal("mint for a sprout deleted mid-mint succeeded")
			}
			if r, ok := e.stored(t, "t1", "web-1"); ok {
				t.Errorf("row left behind: %+v", r)
			}
			if keys := e.objectsOf("t1", "web-1"); len(keys) != 0 {
				t.Errorf("objects left behind: %v", keys)
			}
		})
	}
}

// A row naming a key outside the sprout's own layout is deleted, but the
// object it names is not (the re-mint rule, ownSproutJWTObject).
func TestForgetSproutUserJWTKeepsForeignObject(t *testing.T) {
	ctx := context.Background()
	e := newForgetEnv(t)
	pub := e.accept(t, "t1", "web-1")
	if _, err := e.store.mintOrReuse(ctx, "t1", "web-1", pub); err != nil {
		t.Fatal(err)
	}
	const foreign = "t1/web-2/other.jwt"
	e.srv.Set(foreign, "x")
	if err := db.Model(&sproutUserJWTRow{}).Where("tenant_id = ? AND sprout_id = ?", "t1", "web-1").
		Update("object_key", foreign).Error; err != nil {
		t.Fatal(err)
	}
	e.store.forget(ctx, "t1", "web-1")
	if _, ok := e.stored(t, "t1", "web-1"); ok {
		t.Error("row survived forget")
	}
	if _, ok := e.srv.Object(foreign); !ok {
		t.Errorf("forget deleted %s, which is not the sprout's own object", foreign)
	}
}

// forgetSproutUserJWT with no bucket configured is a no-op, not a panic.
func TestForgetSproutUserJWTWithoutBucket(t *testing.T) {
	newTestDB(t)
	SetSproutJWTStore(nil)
	t.Setenv(SproutJWTBucketEnv, "")
	forgetSproutUserJWT(context.Background(), "t1", "web-1")
}
