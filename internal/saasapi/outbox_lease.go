// Security-sensitive: the row lease that keeps two saasapi replicas from
// dispatching the same outbox work. FLAG FOR SECURITY REVIEW per the CL.3
// brief — a lease that two processes both believe they hold can send an
// update wave twice as fast as the tenant asked for.
package saasapi

import (
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gorm.io/gorm"

	log "github.com/yogzblr/imas/internal/log"
)

// Outbox row leases (migration saas/00006).
//
// A lease is a pair of columns on the row whose work it guards:
// lease_owner, a token naming one holder, and lease_until, when the lease
// lapses unless renewed. The work is a provisioning_jobs row (one publish)
// or an asset_action_batches row (dispatching a §1.5 batch's items, or
// running an update rollout's waves). It is never GET_LOCK, which on PXC
// is local to the node that took it.
//
//   - Claim: one conditional UPDATE that writes a new token and expiry
//     WHERE the lease has lapsed (lease_until < now) or was never set
//     (lease_until IS NULL), plus whatever else the caller requires of the
//     row. The caller holds the lease only if that UPDATE affected the row.
//     Two replicas racing for one row both run the same UPDATE; on a single
//     node InnoDB's row lock serializes them and the second matches
//     nothing, and on PXC the two commits write the same row, so Galera
//     certification refuses one, which then sees an error. An error is
//     never taken as a claim.
//   - Renew: UPDATE lease_until WHERE lease_owner = the holder's token.
//     The new expiry is always later than the stored one, so MySQL never
//     reports the update as a no-op (it counts changed rows, not matched
//     ones). Affecting nothing means another holder has taken the row: the
//     lease is lost at once. An error is retried on the next tick, and the
//     lease is lost anyway once its own expiry passes.
//   - Hold: work under a lease checks held() before each step that sends
//     something (each item, each wave). held() is false once the lease is
//     lost or has expired on this process's clock, so a holder that can't
//     renew stops sending before anyone else can claim the row.
//   - Release: never. A holder that finishes simply stops renewing, so
//     lease_until IS NULL keeps meaning "never leased" (a row the previous
//     release wrote), which the rollout sweep treats differently.
//
// Times are on each replica's own clock (outboxNow), UTC at lease_until's
// millisecond precision. The design assumes replica clocks agree to well
// within the lease TTL (NTP keeps them within milliseconds); a replica
// whose clock runs ahead by more than that could claim a row early.
//
// The token is this replica's name plus a fresh random suffix per claim,
// so two leases taken by one process (its request handler's and its own
// sweeper's) are as distinct as two replicas'.

// outboxNow is the outbox's clock, replaceable in tests.
var outboxNow = time.Now

// dbTime is t as a lease or dispatch column stores it: UTC, truncated to
// datetime(3)'s milliseconds, so a value read back compares equal.
func dbTime(t time.Time) time.Time { return t.UTC().Truncate(time.Millisecond) }

// maxReplicaNameLen leaves room in lease_owner (varchar(64)) for "/" and a
// newID suffix.
const maxReplicaNameLen = 40

// replicaName identifies this process in lease tokens and logs: the pod's
// hostname, cut to maxReplicaNameLen.
var replicaName = func() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		h = "saasapi"
	}
	h = strings.Map(func(r rune) rune {
		if r < 0x21 || r > 0x7e {
			return '_'
		}
		return r
	}, h)
	if len(h) > maxReplicaNameLen {
		h = h[:maxReplicaNameLen]
	}
	return h
}()

// newLeaseToken returns a fresh lease_owner value.
func newLeaseToken() (string, error) {
	return newID(replicaName + "/")
}

// leaseFree is the WHERE fragment a claim requires: the lease lapsed
// before now, or was never set. It takes now as its one argument.
const leaseFree = "(lease_until IS NULL OR lease_until < ?)"

// rowLease is a lease held on one row of table, identified by key (a WHERE
// clause with its arguments, always including tenant_id).
type rowLease struct {
	d     *gorm.DB
	table string
	key   string
	args  []any
	token string
	ttl   time.Duration

	mu    sync.Mutex
	until time.Time
	lost  atomic.Bool

	stopOnce sync.Once
	stop     chan struct{}
}

// claimRowLease tries to take the lease on the row of table matching key
// and the extra condition cond (with condArgs), with one conditional
// UPDATE. set is merged into the UPDATE, so a claim can change the row in
// the same statement (provisioning_jobs counts an attempt this way). It
// returns nil, nil if the row wasn't free or didn't match.
func claimRowLease(d *gorm.DB, table, key string, keyArgs []any, cond string, condArgs []any,
	set map[string]any, ttl time.Duration) (*rowLease, error) {
	token, err := newLeaseToken()
	if err != nil {
		return nil, err
	}
	now := dbTime(outboxNow())
	until := now.Add(ttl)
	update := map[string]any{"lease_owner": token, "lease_until": until}
	for k, v := range set {
		update[k] = v
	}
	q := d.Table(table).Where(key, keyArgs...).Where(leaseFree, now)
	if cond != "" {
		q = q.Where(cond, condArgs...)
	}
	r := q.UpdateColumns(update)
	if r.Error != nil {
		return nil, r.Error
	}
	if r.RowsAffected != 1 {
		return nil, nil
	}
	return &rowLease{d: d, table: table, key: key, args: keyArgs, token: token, ttl: ttl, until: until, stop: make(chan struct{})}, nil
}

// leaseFor wraps a lease this process wrote itself when it created the
// row (createBatch), so the work started on it can renew it like a claimed
// one.
func leaseFor(d *gorm.DB, table, key string, keyArgs []any, token string, until time.Time, ttl time.Duration) *rowLease {
	return &rowLease{d: d, table: table, key: key, args: keyArgs, token: token, ttl: ttl, until: until, stop: make(chan struct{})}
}

// held reports whether the holder may still act on the row: not lost, and
// not past its expiry on this process's clock. A nil lease is always held:
// it is how code paths that predate leases (and tests driving them
// directly) run.
func (l *rowLease) held() bool {
	if l == nil {
		return true
	}
	if l.lost.Load() {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return outboxNow().Before(l.until)
}

// renew extends the lease by its TTL. It reports whether the lease is
// still held afterwards.
func (l *rowLease) renew() bool {
	if l == nil {
		return true
	}
	if l.lost.Load() {
		return false
	}
	l.mu.Lock()
	next := dbTime(outboxNow()).Add(l.ttl)
	if !next.After(l.until) {
		next = l.until.Add(time.Millisecond)
	}
	l.mu.Unlock()
	r := l.d.Table(l.table).Where(l.key, l.args...).Where("lease_owner = ?", l.token).
		UpdateColumn("lease_until", next)
	switch {
	case r.Error != nil:
		log.Warnf("saasapi: renewing the outbox lease on a %s row: %v", l.table, r.Error)
		return l.held()
	case r.RowsAffected == 0:
		l.lost.Store(true)
		log.Warnf("saasapi: lost the outbox lease on a %s row to another holder; stopping work on it", l.table)
		return false
	}
	l.mu.Lock()
	l.until = next
	l.mu.Unlock()
	return true
}

// keepAlive renews the lease every third of its TTL until stopKeepAlive is
// called or the lease is lost.
func (l *rowLease) keepAlive() {
	if l == nil {
		return
	}
	interval := l.ttl / 3
	if interval <= 0 {
		interval = time.Millisecond
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-l.stop:
				return
			case <-t.C:
				if !l.renew() {
					return
				}
			}
		}
	}()
}

// stopKeepAlive stops renewing. The lease is left to lapse, never
// released (see the top of this file).
func (l *rowLease) stopKeepAlive() {
	if l == nil {
		return
	}
	l.stopOnce.Do(func() { close(l.stop) })
}

// Batch leases: the key every asset_action_batches lease uses.
const batchLeaseKey = "id = ? AND tenant_id = ?"

// batchLeaseOf wraps the lease createBatch wrote on batch.
func batchLeaseOf(d *gorm.DB, batch AssetActionBatch) *rowLease {
	if batch.LeaseOwner == "" || batch.LeaseUntil == nil {
		return nil
	}
	return leaseFor(d, AssetActionBatch{}.TableName(), batchLeaseKey, []any{batch.ID, batch.TenantID},
		batch.LeaseOwner, *batch.LeaseUntil, outboxSettings.LeaseTTL)
}
