package migrations

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"
)

// LockTable holds a schema's migration lock: at most one row, id 1, naming
// the run that holds it and until when. cmd/migrate creates it as the
// schema owner.
//
// A row rather than GET_LOCK: GET_LOCK is local to the node it ran on, and
// on Galera two runs connected to different nodes would both get it. An
// INSERT of the same primary key is certified cluster-wide, so only one
// can win. goose's own MySQL table locker isn't used because it covers one
// goose run, not the whole of `migrate up`, and it keeps going when its
// heartbeat fails; this one cancels the run once it can no longer show it
// still holds the lock.
const LockTable = "imas_migrate_lock"

// LockOptions tunes AcquireLock. Zero fields take the defaults.
type LockOptions struct {
	// Lease is how long the lock outlives its holder's last heartbeat
	// before another run may take it over. PXC's total order isolation
	// stalls every write, the heartbeat's included, for as long as a DDL
	// statement runs, so keep it above the longest one. Default 30m.
	Lease time.Duration
	// Wait is how long AcquireLock waits for a held lock. Default 15m.
	Wait time.Duration
	// Poll is how often a waiting AcquireLock retries. Default 5s.
	Poll time.Duration
}

func (o LockOptions) withDefaults() LockOptions {
	if o.Lease <= 0 {
		o.Lease = 30 * time.Minute
	}
	if o.Wait <= 0 {
		o.Wait = 15 * time.Minute
	}
	if o.Poll <= 0 {
		o.Poll = 5 * time.Second
	}
	return o
}

// ErrLockHeld is returned by AcquireLock when another run still held the
// lock at the end of LockOptions.Wait.
var ErrLockHeld = errors.New("migration lock is held by another run")

// errLockLost is the cause a lock's context is cancelled with.
var errLockLost = errors.New("lost the migration lock")

// lockStore is the lock table's SQL, behind an interface so the
// heartbeat and wait logic is testable without a server.
type lockStore interface {
	// ensure creates the lock table if it's missing.
	ensure(ctx context.Context) error
	// tryAcquire takes the lock for owner if it's free or expired.
	// Contention is (false, nil), not an error.
	tryAcquire(ctx context.Context, owner string, lease time.Duration) (bool, error)
	// refresh extends owner's lease; false when owner no longer holds it.
	refresh(ctx context.Context, owner string, lease time.Duration) (bool, error)
	// release drops the lock if owner holds it.
	release(ctx context.Context, owner string) error
	// holder names the current holder, "" if none.
	holder(ctx context.Context) (owner string, remaining time.Duration, err error)
}

// Lock is a held migration lock.
type Lock struct {
	store  lockStore
	owner  string
	cancel context.CancelCauseFunc
	stop   chan struct{}
	done   chan struct{}
	once   sync.Once
}

// AcquireLock takes the migration lock of the schema db is connected to,
// waiting up to opts.Wait for another run to release it or for its lease
// to lapse. db should be a pool of its own, not the one the migrations
// run on, so the heartbeat isn't queued behind a long statement.
//
// The returned context is ctx, cancelled if the lock is lost: when a
// heartbeat finds another run holding it, or heartbeats have failed for a
// whole lease. Run the migrations under it. Release the lock when done.
func AcquireLock(ctx context.Context, db *sql.DB, opts LockOptions, logf func(string, ...any)) (*Lock, context.Context, error) {
	return acquireLock(ctx, mysqlLockStore{db}, newOwnerID(), opts.withDefaults(), logf)
}

func acquireLock(ctx context.Context, store lockStore, owner string, opts LockOptions, logf func(string, ...any)) (*Lock, context.Context, error) {
	if err := store.ensure(ctx); err != nil {
		return nil, nil, err
	}
	deadline := time.Now().Add(opts.Wait)
	for {
		ok, err := store.tryAcquire(ctx, owner, opts.Lease)
		if err != nil {
			return nil, nil, err
		}
		if ok {
			break
		}
		holder, remaining, err := store.holder(ctx)
		if err != nil {
			return nil, nil, err
		}
		if holder == "" { // released or lost a race since tryAcquire
			holder = "another run"
		}
		if !time.Now().Before(deadline) {
			return nil, nil, fmt.Errorf("%w: %s, lease ends in %s", ErrLockHeld, holder, remaining.Round(time.Second))
		}
		logf("migration lock is held by %s (lease ends in %s); waiting", holder, remaining.Round(time.Second))
		t := time.NewTimer(opts.Poll)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, nil, ctx.Err()
		case <-t.C:
		}
	}
	lockedCtx, cancel := context.WithCancelCause(ctx)
	l := &Lock{store: store, owner: owner, cancel: cancel, stop: make(chan struct{}), done: make(chan struct{})}
	go l.heartbeat(lockedCtx, opts.Lease, logf)
	return l, lockedCtx, nil
}

// heartbeat refreshes the lease every third of it. The lock is lost when
// a refresh finds another holder, or when no refresh has succeeded for a
// whole lease (by then another run may have taken it over).
func (l *Lock) heartbeat(ctx context.Context, lease time.Duration, logf func(string, ...any)) {
	defer close(l.done)
	t := time.NewTicker(lease / 3)
	defer t.Stop()
	lastOK := time.Now()
	for {
		select {
		case <-l.stop:
			return
		case <-ctx.Done():
			return
		case <-t.C:
		}
		ok, err := l.store.refresh(ctx, l.owner, lease)
		switch {
		case err == nil && ok:
			lastOK = time.Now()
		case err == nil:
			logf("migration lock: another run now holds it; stopping")
			l.cancel(errLockLost)
			return
		case time.Since(lastOK) >= lease:
			logf("migration lock: no heartbeat has succeeded for %s (%v); stopping", lease, err)
			l.cancel(errLockLost)
			return
		default:
			logf("migration lock: heartbeat failed, will retry: %v", err)
		}
	}
}

// Release stops the heartbeat and drops the lock, even if ctx is already
// cancelled. Safe to call more than once.
func (l *Lock) Release(ctx context.Context) error {
	var err error
	l.once.Do(func() {
		close(l.stop)
		<-l.done
		l.cancel(nil)
		err = l.store.release(context.WithoutCancel(ctx), l.owner)
	})
	return err
}

// LockLost reports whether ctx, a context AcquireLock returned (or one
// derived from it), was cancelled because the lock was lost.
func LockLost(ctx context.Context) bool { return errors.Is(context.Cause(ctx), errLockLost) }

// newOwnerID names this run in the lock row: host, pid and a random
// suffix. It's shown to a run waiting on the lock.
func newOwnerID() string {
	host, _ := os.Hostname()
	if host == "" {
		host = "unknown-host"
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s/%d/%s", host, os.Getpid(), hex.EncodeToString(b))
}

type mysqlLockStore struct{ db *sql.DB }

func (s mysqlLockStore) ensure(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS `"+LockTable+"` ("+
		"`id` tinyint unsigned NOT NULL,"+
		"`owner` varchar(255) NOT NULL,"+
		"`acquired_at` datetime(6) NOT NULL,"+
		"`expires_at` datetime(6) NOT NULL,"+
		"PRIMARY KEY (`id`)) ENGINE=InnoDB")
	if err != nil {
		return fmt.Errorf("creating %s: %w", LockTable, err)
	}
	return nil
}

// Times are the server's (NOW(6)), so client clock skew doesn't matter;
// Galera nodes' clocks are assumed to agree to well within a lease.
func (s mysqlLockStore) tryAcquire(ctx context.Context, owner string, lease time.Duration) (bool, error) {
	_, err := s.db.ExecContext(ctx, "INSERT INTO `"+LockTable+"` (`id`, `owner`, `acquired_at`, `expires_at`)"+
		" VALUES (1, ?, NOW(6), NOW(6) + INTERVAL ? MICROSECOND)", owner, lease.Microseconds())
	if err == nil {
		return true, nil
	}
	if !isContention(err) {
		return false, fmt.Errorf("taking the migration lock: %w", err)
	}
	// Held: take it over only if its lease has lapsed.
	r, err := s.db.ExecContext(ctx, "UPDATE `"+LockTable+"` SET `owner` = ?, `acquired_at` = NOW(6),"+
		" `expires_at` = NOW(6) + INTERVAL ? MICROSECOND WHERE `id` = 1 AND `expires_at` < NOW(6)", owner, lease.Microseconds())
	if err != nil {
		if isContention(err) {
			return false, nil
		}
		return false, fmt.Errorf("taking over the migration lock: %w", err)
	}
	n, err := r.RowsAffected()
	return n == 1, err
}

func (s mysqlLockStore) refresh(ctx context.Context, owner string, lease time.Duration) (bool, error) {
	r, err := s.db.ExecContext(ctx, "UPDATE `"+LockTable+"` SET `expires_at` = NOW(6) + INTERVAL ? MICROSECOND"+
		" WHERE `id` = 1 AND `owner` = ?", lease.Microseconds(), owner)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}

func (s mysqlLockStore) release(ctx context.Context, owner string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM `"+LockTable+"` WHERE `id` = 1 AND `owner` = ?", owner)
	return err
}

func (s mysqlLockStore) holder(ctx context.Context) (string, time.Duration, error) {
	var owner string
	var us int64
	err := s.db.QueryRowContext(ctx, "SELECT `owner`, TIMESTAMPDIFF(MICROSECOND, NOW(6), `expires_at`) FROM `"+LockTable+"` WHERE `id` = 1").
		Scan(&owner, &us)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, nil
	}
	if err != nil {
		return "", 0, fmt.Errorf("reading the migration lock: %w", err)
	}
	return owner, time.Duration(us) * time.Microsecond, nil
}

// isContention: the row is there (duplicate key), or another node's
// write to it won certification (Galera reports that as a deadlock), or
// a row lock wait timed out.
func isContention(err error) bool {
	var me *mysql.MySQLError
	if !errors.As(err, &me) {
		return false
	}
	switch me.Number {
	case 1062, 1213, 1205: // ER_DUP_ENTRY, ER_LOCK_DEADLOCK, ER_LOCK_WAIT_TIMEOUT
		return true
	}
	return false
}
