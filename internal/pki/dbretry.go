package pki

// Retrying a transaction the database rolled back for contention, and
// telling such a transient failure from a refusal.
//
// Sprouts enrolled in the same second write pki_nkeys and
// pki_sprout_box_keys concurrently. InnoDB (REPEATABLE READ) gives each
// transaction's locking read next-key locks that cover the gap the others
// insert into, so two first enrolments, even in different tenants,
// deadlock (1213), and PXC reports a Galera certification conflict with
// the same number. The server has rolled the whole transaction back, so
// running it again is safe and is what it asks for ("try restarting
// transaction"). A lock wait timeout (1205) rolls back only the statement
// unless innodb_rollback_on_timeout is set, so a transaction that sees one
// is abandoned (its function returns the error and db.Transaction rolls it
// back) and run again the same way.

import (
	"database/sql/driver"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/go-sql-driver/mysql"
)

// ErrEnrollmentUnavailable marks an enrolment or refresh failure caused by
// a transient database condition (contention that outlasted the retries,
// a lost connection, a node not ready), wrapped together with
// ErrEnrollmentFailed. Nothing was spent: no use of the join token, no
// sprout accepted. The HTTP layer answers it 503 with a Retry-After, not
// the 401 a refused credential gets, and the sprout retries.
var ErrEnrollmentUnavailable = errors.New("pki: enrollment temporarily unavailable; retry")

// MySQL and PXC error numbers this file classifies.
const (
	mysqlLockWaitTimeout  = 1205 // ER_LOCK_WAIT_TIMEOUT
	mysqlDeadlock         = 1213 // ER_LOCK_DEADLOCK; also a Galera certification conflict
	mysqlServerShutdown   = 1053 // ER_SERVER_SHUTDOWN
	mysqlWSREPNotReady    = 1047 // ER_UNKNOWN_COM_ERROR: PXC's "WSREP has not yet prepared node for application use"
	mysqlQueryInterrupted = 1317 // ER_QUERY_INTERRUPTED: aborted by a replicated DDL on PXC
	mysqlServerGone       = 2006 // CR_SERVER_GONE_ERROR
	mysqlServerLost       = 2013 // CR_SERVER_LOST
)

// SQLite's primary result codes for a database another connection has
// locked (the test databases; modernc's error carries the extended code,
// whose low byte is the primary one).
const (
	sqliteBusy   = 5
	sqliteLocked = 6
)

// isDeadlockError reports whether err is, or wraps, the driver's error
// number 1213. The number is checked, not the message text. The driver is
// MPL-2.0, used unmodified as internal/migrations already does
// (CLAUDE.md, licensing).
func isDeadlockError(err error) bool {
	return mysqlErrorNumber(err) == mysqlDeadlock
}

// mysqlErrorNumber returns the MySQL error number err is or wraps, or 0.
func mysqlErrorNumber(err error) uint16 {
	var me *mysql.MySQLError
	if errors.As(err, &me) {
		return me.Number
	}
	return 0
}

// sqliteErrorCode returns the primary SQLite result code err is or wraps,
// or 0. It matches on the Code method modernc.org/sqlite's error has,
// rather than importing the driver into the farmer build.
func sqliteErrorCode(err error) int {
	var coded interface {
		error
		Code() int
	}
	if errors.As(err, &coded) {
		return coded.Code() & 0xff
	}
	return 0
}

// isRetryableTxError reports whether err means the database gave up on the
// transaction because of contention with another one, so running the
// whole transaction again can succeed: MySQL/PXC's deadlock (1213) and
// lock wait timeout (1205), and SQLite's busy and locked.
func isRetryableTxError(err error) bool {
	switch mysqlErrorNumber(err) {
	case mysqlDeadlock, mysqlLockWaitTimeout:
		return true
	}
	switch sqliteErrorCode(err) {
	case sqliteBusy, sqliteLocked:
		return true
	}
	return false
}

// isTransientDBError reports whether err is a database failure a later
// try can get past: contention (isRetryableTxError), a dropped or broken
// connection, a server shutting down or a PXC node not yet synced. A
// constraint violation, a missing table or a bad query is not.
func isTransientDBError(err error) bool {
	if err == nil {
		return false
	}
	if isRetryableTxError(err) || errors.Is(err, driver.ErrBadConn) || errors.Is(err, mysql.ErrInvalidConn) {
		return true
	}
	switch mysqlErrorNumber(err) {
	case mysqlServerShutdown, mysqlWSREPNotReady, mysqlQueryInterrupted, mysqlServerGone, mysqlServerLost:
		return true
	}
	return false
}

// txRetries is how many times retryTx runs a transaction, and
// txBackoff and txMaxBackoff the first pause and the most it grows to
// (doubling each time) before the jitter. Six tries pause at most about
// 25+50+100+200+400 ms, plus up to as much again in jitter: a sprout's
// request stays well inside its 30 s client timeout. Variables for tests.
var (
	txRetries    = 6
	txBackoff    = 25 * time.Millisecond
	txMaxBackoff = 400 * time.Millisecond
)

// retryTx runs write, which must be one whole transaction, again while it
// fails with an error retryable reports true for, up to txRetries times,
// and returns the last error. The pause after each failure doubles from
// txBackoff (capped at txMaxBackoff) and has random jitter of up to as
// much again, so transactions that collided don't collide again in step.
func retryTx(retryable func(error) bool, write func() error) error {
	var err error
	pause := txBackoff
	for attempt := range txRetries {
		if err = write(); err == nil || !retryable(err) {
			return err
		}
		if pause > 0 && attempt < txRetries-1 {
			time.Sleep(pause + time.Duration(rand.Int64N(int64(pause))))
			pause = min(pause*2, txMaxBackoff)
		}
	}
	return err
}

// retryOnDeadlock is retryTx for the database's own contention errors
// (isRetryableTxError).
func retryOnDeadlock(write func() error) error {
	return retryTx(isRetryableTxError, write)
}
