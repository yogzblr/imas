package pki

import (
	"errors"
	"fmt"
	"testing"

	"github.com/go-sql-driver/mysql"
)

// driverError is the error go-sql-driver returns for a MySQL error number.
func driverError(number uint16, message string) error {
	return &mysql.MySQLError{Number: number, SQLState: [5]byte{'4', '0', '0', '0', '1'}, Message: message}
}

// errDeadlock is what go-sql-driver returns for ER_LOCK_DEADLOCK; PXC returns
// it too for a Galera certification conflict.
var errDeadlock = driverError(1213, "Deadlock found when trying to get lock; try restarting transaction")

func fastDeadlockRetries(t *testing.T) {
	t.Helper()
	oldRetries, oldBackoff := deadlockRetries, deadlockBackoff
	deadlockBackoff = 0
	t.Cleanup(func() { deadlockRetries, deadlockBackoff = oldRetries, oldBackoff })
}

func TestIsDeadlockError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"deadlock", errDeadlock, true},
		{"wrapped deadlock", fmt.Errorf("write box key: %w", errDeadlock), true},
		{"joined deadlock", errors.Join(errors.New("write box key"), errDeadlock), true},
		{"duplicate entry", driverError(1062, "Duplicate entry"), false},
		{"lock wait timeout", driverError(1205, "Lock wait timeout exceeded"), false},
		// The number is what counts, not the text.
		{"text only", errors.New("Error 1213 (40001): Deadlock found"), false},
		{"other", errors.New("connection refused"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isDeadlockError(tc.err); got != tc.want {
				t.Errorf("isDeadlockError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestRetryOnDeadlock(t *testing.T) {
	fastDeadlockRetries(t)

	t.Run("succeeds first time, runs once", func(t *testing.T) {
		calls := 0
		if err := retryOnDeadlock(func() error { calls++; return nil }); err != nil || calls != 1 {
			t.Fatalf("err = %v after %d calls, want nil after 1", err, calls)
		}
	})

	t.Run("repeats a deadlock until it succeeds", func(t *testing.T) {
		calls := 0
		err := retryOnDeadlock(func() error {
			calls++
			if calls < 3 {
				return errDeadlock
			}
			return nil
		})
		if err != nil || calls != 3 {
			t.Fatalf("err = %v after %d calls, want nil after 3", err, calls)
		}
	})

	t.Run("gives up after deadlockRetries and returns the deadlock", func(t *testing.T) {
		calls := 0
		err := retryOnDeadlock(func() error { calls++; return errDeadlock })
		if !isDeadlockError(err) || calls != deadlockRetries {
			t.Fatalf("err = %v after %d calls, want the deadlock after %d", err, calls, deadlockRetries)
		}
	})

	t.Run("does not repeat any other error", func(t *testing.T) {
		boom := errors.New("connection refused")
		calls := 0
		err := retryOnDeadlock(func() error { calls++; return boom })
		if !errors.Is(err, boom) || calls != 1 {
			t.Fatalf("err = %v after %d calls, want %v after 1", err, calls, boom)
		}
	})
}
