// Security-sensitive: the row lease that keeps two farmer or saasapi
// replicas from running the same singleton work or minting the same
// credential twice. FLAG FOR SECURITY REVIEW per the P21 slice 3 brief.
//
// Package lease is a row lease on a PXC table: one conditional UPDATE
// takes it, so two replicas racing for one row can't both win. It is the
// outbox lease (internal/saasapi/outbox_lease.go) extracted for the
// farmer's stateless work: the job_leases rows (one per periodic job), the
// per-sprout user JWT index and the saasapi credential state row. It is
// never GET_LOCK, which on PXC is local to the node that took it.
//
//   - Acquire: UPDATE lease_owner and lease_until WHERE the row's key
//     matches and the lease is free: never set, released, lapsed
//     (lease_until < now), or already held by the same owner. The caller
//     holds the lease only if that UPDATE affected the row. The row must
//     exist; callers create it first (INSERT IGNORE or a seed row).
//   - Renew: UPDATE lease_until WHERE lease_owner = the holder's owner.
//     Affecting nothing means another owner has taken the row.
//   - Release: set both columns to NULL WHERE lease_owner = the holder's
//     owner, so the next Acquire need not wait for the lease to lapse.
//
// Table and column names come only from the allow-list below: a caller
// names a Table, and the SQL is built from that table's fixed key
// columns. No caller string is ever interpolated into SQL; key values and
// the owner are bound arguments.
//
// Times are on the caller's clock (New's now), stored UTC at lease_until's
// millisecond precision. As with the outbox lease, replica clocks must
// agree to well within the TTL.
package lease

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

// Table names a leased table. Only the tables in the allow-list are
// accepted.
type Table string

// The leased tables (P21 slice 3 schema). Names are unqualified: each
// service's connection already selects its own schema.
const (
	// JobLeases is farmer.job_leases, keyed by the job name.
	JobLeases Table = "job_leases"
	// SproutUserJWT is farmer.sprout_user_jwt, keyed by (tenant_id,
	// sprout_id): sprout_id is unique per tenant only.
	SproutUserJWT Table = "sprout_user_jwt"
	// SaasapiCredentialState is saas.saasapi_credential_state, keyed by
	// its single row's id.
	SaasapiCredentialState Table = "saasapi_credential_state"
)

// keyColumns is the allow-list: each leased table and the columns of its
// primary key, in the order Acquire, Renew and Release take key values.
var keyColumns = map[Table][]string{
	JobLeases:              {"name"},
	SproutUserJWT:          {"tenant_id", "sprout_id"},
	SaasapiCredentialState: {"id"},
}

// MaxOwnerLen is lease_owner's width (VARCHAR(128)).
const MaxOwnerLen = 128

// ErrInvalid reports a call the package refuses before touching the
// database: a table not on the allow-list, the wrong number of key
// values, an empty or over-long owner, or a TTL that isn't positive.
var ErrInvalid = errors.New("lease: invalid request")

// Leases takes, renews and releases row leases on one database.
type Leases struct {
	db  *gorm.DB
	now func() time.Time
}

// New returns Leases on db using now as its clock; a nil now means
// time.Now.
func New(db *gorm.DB, now func() time.Time) *Leases {
	if now == nil {
		now = time.Now
	}
	return &Leases{db: db, now: now}
}

// dbTime is t as lease_until stores it: UTC, truncated to datetime(3)'s
// milliseconds, so a value read back compares equal.
func dbTime(t time.Time) time.Time { return t.UTC().Truncate(time.Millisecond) }

// where returns the key WHERE clause for table, built only from the
// allow-listed column names, after checking key has one value per column.
func where(table Table, key []any) (string, error) {
	cols, ok := keyColumns[table]
	if !ok {
		return "", fmt.Errorf("%w: table %q is not leasable", ErrInvalid, string(table))
	}
	if len(key) != len(cols) {
		return "", fmt.Errorf("%w: %s takes %d key values, got %d", ErrInvalid, table, len(cols), len(key))
	}
	parts := make([]string, len(cols))
	for i, c := range cols {
		parts[i] = c + " = ?"
	}
	return strings.Join(parts, " AND "), nil
}

func checkOwner(owner string) error {
	if owner == "" || len(owner) > MaxOwnerLen {
		return fmt.Errorf("%w: owner must be 1 to %d bytes", ErrInvalid, MaxOwnerLen)
	}
	return nil
}

// Acquire tries to take the lease on the row of table with key for owner
// until now+ttl. It reports whether owner holds the lease afterwards. A
// lease owner already holds is extended, as by Renew. A missing row is
// not an error: it reports false.
func (l *Leases) Acquire(ctx context.Context, table Table, key []any, owner string, ttl time.Duration) (bool, error) {
	w, err := where(table, key)
	if err != nil {
		return false, err
	}
	if err := checkOwner(owner); err != nil {
		return false, err
	}
	if ttl <= 0 {
		return false, fmt.Errorf("%w: ttl must be positive", ErrInvalid)
	}
	now := dbTime(l.now())
	until := now.Add(ttl)
	r := l.db.WithContext(ctx).Table(string(table)).Where(w, key...).
		Where("(lease_owner IS NULL OR lease_until IS NULL OR lease_until < ? OR lease_owner = ?)", now, owner).
		UpdateColumns(map[string]any{"lease_owner": owner, "lease_until": until})
	if r.Error != nil {
		return false, r.Error
	}
	if r.RowsAffected == 1 {
		return true, nil
	}
	return l.holds(ctx, table, w, key, owner, until)
}

// Renew extends owner's lease on the row of table with key to now+ttl. It
// reports whether owner still holds the lease; false means another owner
// has taken the row (or it was released) and the work it guards must stop.
func (l *Leases) Renew(ctx context.Context, table Table, key []any, owner string, ttl time.Duration) (bool, error) {
	w, err := where(table, key)
	if err != nil {
		return false, err
	}
	if err := checkOwner(owner); err != nil {
		return false, err
	}
	if ttl <= 0 {
		return false, fmt.Errorf("%w: ttl must be positive", ErrInvalid)
	}
	until := dbTime(l.now()).Add(ttl)
	r := l.db.WithContext(ctx).Table(string(table)).Where(w, key...).
		Where("lease_owner = ?", owner).
		UpdateColumn("lease_until", until)
	if r.Error != nil {
		return false, r.Error
	}
	if r.RowsAffected == 1 {
		return true, nil
	}
	return l.holds(ctx, table, w, key, owner, until)
}

// Release gives up owner's lease on the row of table with key. It reports
// whether owner held it; releasing a lease another owner has taken changes
// nothing.
func (l *Leases) Release(ctx context.Context, table Table, key []any, owner string) (bool, error) {
	w, err := where(table, key)
	if err != nil {
		return false, err
	}
	if err := checkOwner(owner); err != nil {
		return false, err
	}
	r := l.db.WithContext(ctx).Table(string(table)).Where(w, key...).
		Where("lease_owner = ?", owner).
		UpdateColumns(map[string]any{"lease_owner": nil, "lease_until": nil})
	if r.Error != nil {
		return false, r.Error
	}
	return r.RowsAffected == 1, nil
}

// holds reports whether the row already carries exactly owner and until.
// MySQL counts changed rows, not matched ones, so an UPDATE that writes
// the values the row already has (a second Acquire or Renew by the same
// owner within one millisecond) reports zero rows; this read tells that
// apart from losing the race.
func (l *Leases) holds(ctx context.Context, table Table, w string, key []any, owner string, until time.Time) (bool, error) {
	var n int64
	r := l.db.WithContext(ctx).Table(string(table)).Where(w, key...).
		Where("lease_owner = ? AND lease_until = ?", owner, until).Count(&n)
	if r.Error != nil {
		return false, r.Error
	}
	return n == 1, nil
}
