package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/yogzblr/imas/internal/pki"
)

// newCredentialStateDB opens a sqlite database holding the
// saasapi_credential_state table, standing in for the saas schema.
func newCredentialStateDB(t *testing.T) *gorm.DB {
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
	if err := gdb.AutoMigrate(pki.SaaSAPICredentialStateModels()...); err != nil {
		t.Fatal(err)
	}
	return gdb
}

// newUserJWT returns a User JWT for a fresh key, signed by a fresh
// Account, and the key.
func newUserJWT(t *testing.T) (userJWT, pub string) {
	t.Helper()
	user, _ := nkeys.CreateUser()
	pub, _ = user.PublicKey()
	acct, _ := nkeys.CreateAccount()
	signed, err := jwt.NewUserClaims(pub).Encode(acct)
	if err != nil {
		t.Fatal(err)
	}
	return signed, pub
}

func noSleep(context.Context, time.Duration) error { return nil }

func TestRecordBusCredential_RecordsAndRotates(t *testing.T) {
	rec := pki.NewSaaSAPICredentialRecorder(newCredentialStateDB(t))
	ctx := context.Background()
	oldJWT, oldPub := newUserJWT(t)
	if err := recordBusCredential(ctx, rec, " "+oldJWT+"\n", noSleep); err != nil {
		t.Fatalf("first record: %v", err)
	}
	// A restart with the same credential changes nothing.
	if err := recordBusCredential(ctx, rec, oldJWT, noSleep); err != nil {
		t.Fatalf("re-record: %v", err)
	}
	newJWT, newPub := newUserJWT(t)
	if err := recordBusCredential(ctx, rec, newJWT, noSleep); err != nil {
		t.Fatalf("rotation: %v", err)
	}
	st, err := rec.State(ctx)
	if err != nil || st.CurrentPub != newPub || st.PrevPub != oldPub || st.Version != 2 {
		t.Fatalf("state = %+v, %v; want %s rotated from %s at version 2", st, err, newPub, oldPub)
	}
	// A replica still on the rotated-out credential fails to boot.
	if err := recordBusCredential(ctx, rec, oldJWT, noSleep); !errors.Is(err, pki.ErrSaaSAPICredentialRotatedOut) {
		t.Fatalf("rotated-out credential: err = %v, want ErrSaaSAPICredentialRotatedOut", err)
	}
}

func TestRecordBusCredential_RejectsInvalidJWT(t *testing.T) {
	rec := &fakeRecorder{}
	if err := recordBusCredential(context.Background(), rec, "not-a-jwt", noSleep); err == nil {
		t.Fatal("expected an invalid JWT to fail")
	}
	if rec.calls != 0 {
		t.Fatalf("Record called %d times for an invalid JWT", rec.calls)
	}
}

// fakeRecorder returns errs in turn, then succeeds.
type fakeRecorder struct {
	errs  []error
	calls int
}

func (f *fakeRecorder) Record(_ context.Context, pub string) (*pki.SaaSAPICredentialState, bool, error) {
	f.calls++
	if len(f.errs) > 0 {
		err := f.errs[0]
		f.errs = f.errs[1:]
		return nil, false, err
	}
	return &pki.SaaSAPICredentialState{CurrentPub: pub, Version: 1}, true, nil
}

func TestRecordBusCredential_RetriesWhileBusy(t *testing.T) {
	userJWT, _ := newUserJWT(t)
	rec := &fakeRecorder{errs: []error{pki.ErrSaaSAPICredentialBusy, pki.ErrSaaSAPICredentialBusy}}
	sleeps := 0
	sleep := func(context.Context, time.Duration) error { sleeps++; return nil }
	if err := recordBusCredential(context.Background(), rec, userJWT, sleep); err != nil {
		t.Fatalf("recordBusCredential: %v", err)
	}
	if rec.calls != 3 || sleeps != 2 {
		t.Fatalf("calls=%d sleeps=%d, want 3 calls and 2 waits", rec.calls, sleeps)
	}
}

func TestRecordBusCredential_GivesUpAtDeadline(t *testing.T) {
	userJWT, _ := newUserJWT(t)
	rec := &fakeRecorder{errs: []error{pki.ErrSaaSAPICredentialBusy, pki.ErrSaaSAPICredentialBusy}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := recordBusCredential(ctx, rec, userJWT, sleepCtx)
	if !errors.Is(err, pki.ErrSaaSAPICredentialBusy) {
		t.Fatalf("err = %v, want ErrSaaSAPICredentialBusy once the deadline passes", err)
	}
	if rec.calls != 1 {
		t.Fatalf("calls = %d, want 1", rec.calls)
	}
}

func TestRecordBusCredential_OtherErrorsAreNotRetried(t *testing.T) {
	userJWT, _ := newUserJWT(t)
	boom := errors.New("boom")
	rec := &fakeRecorder{errs: []error{boom}}
	if err := recordBusCredential(context.Background(), rec, userJWT, noSleep); !errors.Is(err, boom) || rec.calls != 1 {
		t.Fatalf("err = %v, calls = %d; want boom after one call", err, rec.calls)
	}
}
