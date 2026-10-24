package pki

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"gorm.io/gorm"
)

// txEnrollmentKeyStore is a join token store in this package's own test
// database whose redeem runs inside the enrolment transaction it is
// handed, as the production store's does: unlike the in-memory fakes, a
// rolled-back transaction gives its use back. SQLite has no NOW() or
// saas schema, which is why the production store itself can't run here.
type txEnrollmentKeyStore struct{}

func (txEnrollmentKeyStore) lookup(keyID string) (*enrollmentKeyRow, error) {
	var row enrollmentKeyRow
	err := db.Raw(`SELECT tenant_id, key_hash, expiry, max_uses, used_count, revoked FROM test_enrollment_keys WHERE key_id = ?`, keyID).
		Row().Scan(&row.TenantID, &row.KeyHash, &row.Expiry, &row.MaxUses, &row.UsedCount, &row.Revoked)
	if err != nil {
		return nil, err
	}
	return &row, nil
}

func (txEnrollmentKeyStore) redeem(tx *gorm.DB, keyID string) (bool, error) {
	res := tx.Exec(`UPDATE test_enrollment_keys SET used_count = used_count + 1
		WHERE key_id = ? AND used_count < max_uses AND revoked = FALSE AND expiry > ?`, keyID, time.Now().UTC())
	return res.RowsAffected == 1, res.Error
}

// enrollTxHarness is a database to run the enrolment transaction tests
// on: addKey adds a join token and returns it, uses reads a key's
// used_count.
type enrollTxHarness struct {
	addKey func(t *testing.T, keyID, tenantID string, maxUses int) string
	uses   func(t *testing.T, keyID string) int
	// concurrentWriters is whether another connection can write
	// pki_nkeys while the enrolment transaction is open (MySQL's row
	// locks; SQLite locks the whole database for one writer).
	concurrentWriters bool
}

// sqliteEnrollTxHarness is setupEnrollTest with txEnrollmentKeyStore.
func sqliteEnrollTxHarness(t *testing.T) enrollTxHarness {
	t.Helper()
	setupEnrollTest(t)
	if err := db.Exec(`CREATE TABLE test_enrollment_keys (key_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,
		key_hash TEXT NOT NULL, expiry DATETIME NOT NULL, max_uses INTEGER NOT NULL,
		used_count INTEGER NOT NULL DEFAULT 0, revoked BOOLEAN NOT NULL DEFAULT FALSE)`).Error; err != nil {
		t.Fatal(err)
	}
	orig := enrollKeyStore
	enrollKeyStore = txEnrollmentKeyStore{}
	t.Cleanup(func() { enrollKeyStore = orig })
	return enrollTxHarness{
		addKey: func(t *testing.T, keyID, tenantID string, maxUses int) string {
			t.Helper()
			if err := db.Exec(`INSERT INTO test_enrollment_keys (key_id, tenant_id, key_hash, expiry, max_uses) VALUES (?, ?, ?, ?, ?)`,
				keyID, tenantID, hashSecret("s-"+keyID), time.Now().UTC().Add(time.Hour), maxUses).Error; err != nil {
				t.Fatal(err)
			}
			return keyID + ".s-" + keyID
		},
		uses: func(t *testing.T, keyID string) int {
			t.Helper()
			row, err := txEnrollmentKeyStore{}.lookup(keyID)
			if err != nil {
				t.Fatal(err)
			}
			return row.UsedCount
		},
	}
}

// mysqlEnrollTxHarness is setupMySQLEnrollTest, with the production store.
func mysqlEnrollTxHarness(t *testing.T) enrollTxHarness {
	t.Helper()
	saas := setupMySQLEnrollTest(t)
	return enrollTxHarness{
		addKey: func(t *testing.T, keyID, tenantID string, maxUses int) string {
			return insertMySQLEnrollmentKey(t, saas, keyID, tenantID, maxUses)
		},
		uses:              func(t *testing.T, keyID string) int { return mysqlKeyUses(t, saas, keyID) },
		concurrentWriters: true,
	}
}

// withEnrollTxFault installs fault as enrollTxFault and returns how many
// times it has run.
func withEnrollTxFault(t *testing.T, fault func(call int) error) (calls func() int) {
	t.Helper()
	n := 0
	enrollTxFault = func() error {
		n++
		return fault(n)
	}
	t.Cleanup(func() { enrollTxFault = nil })
	return func() int { return n }
}

// errLockWaitTimeout is MySQL's ER_LOCK_WAIT_TIMEOUT.
var errLockWaitTimeout = driverError(1205, "Lock wait timeout exceeded; try restarting transaction")

// runEnrollTxTests runs the enrolment transaction tests on harness.
func runEnrollTxTests(t *testing.T, harness func(t *testing.T) enrollTxHarness) {
	// A deadlock (or lock wait timeout) between the redeem and the accept
	// rolls the attempt back with the use unspent, and the transaction
	// is run again and succeeds: one use spent, the sprout accepted.
	for name, contention := range map[string]error{"deadlock": errDeadlock, "lock wait timeout": errLockWaitTimeout} {
		t.Run(name+" mid-transaction is retried and spends one use", func(t *testing.T) {
			h := harness(t)
			fastDeadlockRetries(t)
			token := h.addKey(t, "ek_retry", "t_retry", 1)
			calls := withEnrollTxFault(t, func(call int) error {
				if call <= 2 {
					return fmt.Errorf("accepting: %w", contention)
				}
				return nil
			})
			kp := testEnrollNKey(t)
			res, err := Enroll(t.Context(), signedEnroll(t, kp, token, "alma-01", testEnrollBoxPub(t)))
			if err != nil {
				t.Fatalf("Enroll after two %s failures: %v", name, err)
			}
			if calls() != 3 {
				t.Errorf("transaction ran %d times, want 3", calls())
			}
			if n := h.uses(t, "ek_retry"); n != 1 {
				t.Errorf("used_count = %d, want 1", n)
			}
			if gotTenant, id, err := SproutIDAndTenantForNKey(testNKeyPub(t, kp)); err != nil || gotTenant != "t_retry" || id != "alma-01" || res.SproutID != "alma-01" {
				t.Errorf("accepted as %q in %q (%v), result %q; want alma-01 in t_retry", id, gotTenant, err, res.SproutID)
			}
		})
	}

	// The rig's failure: contention that outlasts every retry. Nothing is
	// spent and the answer is retryable (ErrEnrollmentUnavailable, 503),
	// so the sprout's next try, with the same single-use token, enrols.
	t.Run("persistent deadlock spends nothing and is retryable", func(t *testing.T) {
		h := harness(t)
		fastDeadlockRetries(t)
		token := h.addKey(t, "ek_single", "t_hydbugp7pz2jjd7t", 1)
		failing := true
		calls := withEnrollTxFault(t, func(int) error {
			if failing {
				return errDeadlock
			}
			return nil
		})
		kp := testEnrollNKey(t)
		_, err := Enroll(t.Context(), signedEnroll(t, kp, token, "alma-01", testEnrollBoxPub(t)))
		if !errors.Is(err, ErrEnrollmentFailed) || !errors.Is(err, ErrEnrollmentUnavailable) {
			t.Fatalf("Enroll under persistent deadlock = %v, want ErrEnrollmentFailed wrapping ErrEnrollmentUnavailable", err)
		}
		if calls() != txRetries {
			t.Errorf("transaction ran %d times, want txRetries (%d)", calls(), txRetries)
		}
		if n := h.uses(t, "ek_single"); n != 0 {
			t.Fatalf("used_count = %d after a rolled-back enrolment, want 0: the token was burned", n)
		}
		if _, _, err := SproutIDAndTenantForNKey(testNKeyPub(t, kp)); !errors.Is(err, ErrSproutIDNotFound) {
			t.Fatalf("a rolled-back enrolment left the sprout accepted (err %v)", err)
		}

		failing = false
		if _, err := Enroll(t.Context(), signedEnroll(t, kp, token, "alma-01", testEnrollBoxPub(t))); err != nil {
			t.Fatalf("retry with the same single-use token: %v", err)
		}
		if n := h.uses(t, "ek_single"); n != 1 {
			t.Errorf("used_count = %d after the retry, want 1", n)
		}
	})

	// Any other error mid-transaction is not retried and is the generic
	// refusal, but rolls back all the same: the use stays on the token.
	t.Run("other error mid-transaction rolls back and is not retried", func(t *testing.T) {
		h := harness(t)
		fastDeadlockRetries(t)
		token := h.addKey(t, "ek_boom", "t_boom", 1)
		calls := withEnrollTxFault(t, func(int) error { return errors.New("boom") })
		_, err := Enroll(t.Context(), signedEnroll(t, testEnrollNKey(t), token, "web-01", testEnrollBoxPub(t)))
		if !errors.Is(err, ErrEnrollmentFailed) || errors.Is(err, ErrEnrollmentUnavailable) {
			t.Fatalf("Enroll = %v, want the bare ErrEnrollmentFailed", err)
		}
		if calls() != 1 {
			t.Errorf("transaction ran %d times, want 1", calls())
		}
		if n := h.uses(t, "ek_boom"); n != 0 {
			t.Errorf("used_count = %d, want 0", n)
		}
	})

	// An exhausted token is a refusal (401), not a retryable answer.
	t.Run("exhausted token is not retryable", func(t *testing.T) {
		h := harness(t)
		token := h.addKey(t, "ek_once", "t_once", 1)
		if _, err := Enroll(t.Context(), signedEnroll(t, testEnrollNKey(t), token, "web-01", testEnrollBoxPub(t))); err != nil {
			t.Fatal(err)
		}
		_, err := Enroll(t.Context(), signedEnroll(t, testEnrollNKey(t), token, "web-02", testEnrollBoxPub(t)))
		if !errors.Is(err, ErrEnrollmentFailed) || errors.Is(err, ErrEnrollmentUnavailable) {
			t.Fatalf("Enroll with an exhausted token = %v, want the bare ErrEnrollmentFailed", err)
		}
		if n := h.uses(t, "ek_once"); n != 1 {
			t.Errorf("used_count = %d, want 1", n)
		}
	})

	// Two hosts of one name enrolling at once: the one whose transaction
	// finds the ID taken by the other's NKey resolves it again (web-01_1)
	// rather than moving web-01 to its own NKey.
	t.Run("sprout ID taken mid-enrolment is resolved again", func(t *testing.T) {
		h := harness(t)
		if !h.concurrentWriters {
			t.Skip("needs a second writer while the transaction is open (TestAcceptEnrolledNKeyTx covers the check)")
		}
		fastDeadlockRetries(t)
		token := h.addKey(t, "ek_twins", "t_twins", 2)
		other := testNKeyPub(t, testEnrollNKey(t))
		withEnrollTxFault(t, func(call int) error {
			if call == 1 {
				// The other host commits web-01 between this enrolment's
				// resolve and its accept.
				return db.Create(&nkeyRow{TenantID: "t_twins", SproutID: "web-01", NKey: other, State: stateAccepted}).Error
			}
			return nil
		})
		kp := testEnrollNKey(t)
		res, err := Enroll(t.Context(), signedEnroll(t, kp, token, "web-01", testEnrollBoxPub(t)))
		if err != nil {
			t.Fatal(err)
		}
		if res.SproutID != "web-01_1" {
			t.Errorf("enrolled as %q, want web-01_1", res.SproutID)
		}
		var row nkeyRow
		if err := db.Where("tenant_id = ? AND sprout_id = ?", "t_twins", "web-01").Take(&row).Error; err != nil || row.NKey != other {
			t.Errorf("web-01 = %+v (%v), want it kept by the other host's NKey", row, err)
		}
		if n := h.uses(t, "ek_twins"); n != 1 {
			t.Errorf("used_count = %d, want 1", n)
		}
	})
}

func TestEnrollTx(t *testing.T) { runEnrollTxTests(t, sqliteEnrollTxHarness) }

func TestMySQLEnrollTx(t *testing.T) { runEnrollTxTests(t, mysqlEnrollTxHarness) }

// sqliteCodedError is a stand-in for modernc.org/sqlite's error, which
// carries its result code through a Code method.
type sqliteCodedError int

func (e sqliteCodedError) Error() string { return fmt.Sprintf("sqlite error %d", int(e)) }
func (e sqliteCodedError) Code() int     { return int(e) }

func TestIsRetryableTxError(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		err                  error
		retryable, transient bool
	}{
		{"nil", nil, false, false},
		{"deadlock", errDeadlock, true, true},
		{"wrapped lock wait timeout", fmt.Errorf("accept: %w", errLockWaitTimeout), true, true},
		{"sqlite busy", sqliteCodedError(5), true, true},
		{"sqlite busy snapshot (extended code)", sqliteCodedError(5 | 2<<8), true, true},
		{"sqlite locked", sqliteCodedError(6), true, true},
		{"sqlite constraint", sqliteCodedError(19), false, false},
		{"bad conn", fmt.Errorf("query: %w", driver.ErrBadConn), false, true},
		{"invalid conn", mysql.ErrInvalidConn, false, true},
		{"server gone", driverError(2006, "MySQL server has gone away"), false, true},
		{"wsrep not ready", driverError(1047, "WSREP has not yet prepared node for application use"), false, true},
		{"duplicate entry", driverError(1062, "Duplicate entry"), false, false},
		{"no rows", sql.ErrNoRows, false, false},
		// The number is what counts, not the text.
		{"text only", errors.New("Error 1213 (40001): Deadlock found"), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRetryableTxError(tc.err); got != tc.retryable {
				t.Errorf("isRetryableTxError(%v) = %v, want %v", tc.err, got, tc.retryable)
			}
			if got := isTransientDBError(tc.err); got != tc.transient {
				t.Errorf("isTransientDBError(%v) = %v, want %v", tc.err, got, tc.transient)
			}
		})
	}
}

// enrollDBError tells the sprout to retry only for a transient failure.
func TestEnrollDBError(t *testing.T) {
	for _, tc := range []struct {
		err         error
		unavailable bool
	}{
		{errDeadlock, true},
		{driver.ErrBadConn, true},
		{fmt.Errorf("x: %w", errSproutIDTaken), true},
		{sql.ErrNoRows, false},
		{errors.New("boom"), false},
		{ErrTenantDeprovisioned, false},
	} {
		got := enrollDBError(tc.err)
		if !errors.Is(got, ErrEnrollmentFailed) || errors.Is(got, ErrEnrollmentUnavailable) != tc.unavailable {
			t.Errorf("enrollDBError(%v) = %v, want ErrEnrollmentFailed, unavailable %v", tc.err, got, tc.unavailable)
		}
	}
}

// acceptEnrolledNKeyTx inserts a new sprout, re-accepts an NKey already
// under the ID, and refuses an ID another NKey holds (errSproutIDTaken)
// or an NKey held under another ID (errNKeyAmbiguous), leaving both rows
// as they were.
func TestAcceptEnrolledNKeyTx(t *testing.T) {
	newTestDB(t)
	a, b := testNKeyPub(t, testEnrollNKey(t)), testNKeyPub(t, testEnrollNKey(t))
	accept := func(id, nkey string) error {
		return db.Transaction(func(tx *gorm.DB) error {
			return acceptEnrolledNKeyTx(tx, nkeyRow{TenantID: "t_1", SproutID: id, NKey: nkey, State: stateAccepted})
		})
	}
	if err := accept("web-01", a); err != nil {
		t.Fatalf("new sprout: %v", err)
	}
	if err := db.Model(&nkeyRow{}).Where("tenant_id = ? AND sprout_id = ?", "t_1", "web-01").Update("state", stateUnaccepted).Error; err != nil {
		t.Fatal(err)
	}
	if err := accept("web-01", a); err != nil {
		t.Fatalf("same NKey again: %v", err)
	}
	if err := accept("web-01", b); !errors.Is(err, errSproutIDTaken) {
		t.Errorf("another NKey's ID: err = %v, want errSproutIDTaken", err)
	}
	if err := accept("web-02", a); !errors.Is(err, errNKeyAmbiguous) {
		t.Errorf("an NKey held under another ID: err = %v, want errNKeyAmbiguous", err)
	}
	// The same ID in another tenant is another sprout.
	if err := db.Transaction(func(tx *gorm.DB) error {
		return acceptEnrolledNKeyTx(tx, nkeyRow{TenantID: "t_2", SproutID: "web-01", NKey: b, State: stateAccepted})
	}); err != nil {
		t.Fatalf("same ID in another tenant: %v", err)
	}
	var rows []nkeyRow
	if err := db.Order("tenant_id, sprout_id").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	want := []nkeyRow{{TenantID: "t_1", SproutID: "web-01", NKey: a, State: stateAccepted}, {TenantID: "t_2", SproutID: "web-01", NKey: b, State: stateAccepted}}
	if fmt.Sprint(rows) != fmt.Sprint(want) {
		t.Errorf("rows = %+v, want %+v", rows, want)
	}
}
