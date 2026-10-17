package pki

// A deprovisioned tenant fails closed (security review 2026-10, L10 and
// L11; docs/briefs/T-pre-azure.md T4). FLAG FOR SECURITY REVIEW.
//
// Every path that issues or reads a sprout identity (the enrollment
// replay, RefreshSprout and its sealed request, reissueExistingIdentity,
// the gateway JWT check of /files/ and the update manifest) asks
// refuseDeprovisionedTenant first, and refuses on its error: a
// deprovisioned tenant (pki_tenants.deleted) is ErrTenantDeprovisioned
// on every one of them, and a failed database read is an error too,
// never a pass.
//
// The bus side: whenever any path sees a deleted tenant it pushes a fresh
// lock-out (noteDeprovisionedTenant, rate limited; ProvisionTenant always,
// relockDeprovisionedTenant), and StartTenantRelocker pushes one, every
// IMAS_TENANT_RELOCK_INTERVAL, for each deleted tenant whose Account is
// still live on the bus or in the accounts bucket. Together with the
// retried re-check after a live push (pushLiveTenantAccount), a database
// error at the moment of a provision/deprovision race no longer leaves a
// deprovisioned tenant admitted until core's next SYS reconnect.

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	nats "github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/lease"
	log "github.com/yogzblr/imas/internal/log"
)

// refuseDeprovisionedTenant returns an error wrapping
// ErrTenantDeprovisioned if tenantID's pki_tenants row is marked deleted,
// and then has a fresh lock-out pushed (noteDeprovisionedTenant). It
// returns a wrapped database error if the row can't be read, or no
// database is installed: the caller refuses either way. A tenant with no
// row (the legacy current tenant, or one whose first enrollment
// provisions it lazily) is not deprovisioned; callers that need the row
// to exist check that themselves (VerifyGatewaySubject).
func refuseDeprovisionedTenant(tenantID string) error {
	_, err := liveTenantRow(tenantID)
	return err
}

// liveTenantRow is refuseDeprovisionedTenant returning the row it read:
// nil, with no error, when tenantID has none.
func liveTenantRow(tenantID string) (*tenantRow, error) {
	if db == nil {
		return nil, errNoStore
	}
	row, err := getTenantRow(tenantID)
	switch {
	case errors.Is(err, ErrTenantNotFound):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("pki: checking whether tenant %q is deprovisioned: %w", tenantID, err)
	case row.Deleted:
		noteDeprovisionedTenant(tenantID)
		return nil, fmt.Errorf("pki: tenant %q: %w", tenantID, ErrTenantDeprovisioned)
	}
	return row, nil
}

// relockDeprovisionedTenant signs a fresh lock-out for tenantID and
// pushes it, if its row is deleted and it ever had an Account (a
// tombstone has nothing on the bus to lock out; relockForPushAll). It
// reports whether it pushed one. As after the re-check in
// pushLiveTenantAccount, it then has the tenant's farmer connection
// closed (OnTenantDeprovisioned).
func relockDeprovisionedTenant(tenantID string) (bool, error) {
	mat, err := ensureNatsAuth()
	if err != nil {
		return false, err
	}
	signed, ok, err := relockForPushAll(mat, tenantID)
	if err != nil || !ok {
		return false, err
	}
	if err := pushAccountUpdate(mat, signed); err != nil {
		return false, fmt.Errorf("pki: pushing tenant %q's fresh lock-out: %w", tenantID, err)
	}
	if tenantDeprovisionedHook != nil {
		go tenantDeprovisionedHook(tenantID)
	}
	return true, nil
}

// relockPush is what noteDeprovisionedTenant and the periodic relock
// push with; tests replace it to count pushes without a bus.
var relockPush = relockDeprovisionedTenant

// relockSleep waits d or until ctx ends; tests replace it to run the
// rate limit without waiting.
var relockSleep = func(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// relockPushGap is the least time between two lock-out pushes of the
// periodic relock, and of noteDeprovisionedTenant (at most 10 a second
// each), so a sweep over many deleted tenants, or many sprouts of deleted
// tenants calling in at once, never floods the bus resolver.
const relockPushGap = 100 * time.Millisecond

// Lock-outs pushed because a path saw a deleted tenant.
const (
	// seenRelockMinInterval: a tenant seen deleted again within this time
	// of its last pushed lock-out on this replica gets no new push. Its
	// sprouts may call in many times a minute; one push covers them all.
	seenRelockMinInterval = time.Minute
	// seenRelockMaxTracked bounds the tenants seenRelocker remembers; past
	// it, entries older than seenRelockMinInterval are dropped.
	seenRelockMaxTracked = 4096
)

// seenRelocker pushes the lock-outs noteDeprovisionedTenant asks for: at
// most one at a time in this process, relockPushGap apart, and at most
// once per tenant per seenRelockMinInterval. A note that finds a push
// running, or one too recent, pushes nothing (the caller has refused its
// request either way); the tenant's next refused request, or the
// periodic relock, pushes it.
type seenRelocker struct {
	mu       sync.Mutex
	busy     bool
	lastPush time.Time
	last     map[string]time.Time
	now      func() time.Time
}

var seenRelocks = newSeenRelocker()

func newSeenRelocker() *seenRelocker {
	return &seenRelocker{last: map[string]time.Time{}, now: time.Now}
}

// noteDeprovisionedTenant pushes a fresh lock-out for tenantID, which a
// path just found deleted, unless seenRelocker's limits say not now. It
// runs in the caller's goroutine, outside every lock this package holds.
func noteDeprovisionedTenant(tenantID string) { seenRelocks.note(tenantID) }

func (r *seenRelocker) note(tenantID string) {
	r.mu.Lock()
	now := r.now()
	if r.busy || now.Sub(r.lastPush) < relockPushGap || now.Sub(r.last[tenantID]) < seenRelockMinInterval {
		r.mu.Unlock()
		return
	}
	r.busy = true
	r.mu.Unlock()

	pushed, err := relockPush(tenantID)
	switch {
	case err != nil:
		log.Errorf("tenant %q is deprovisioned; pushing a fresh lock-out failed (the periodic relock retries it): %v", tenantID, err)
	case pushed:
		log.Warnf("tenant %q is deprovisioned and was still in use; pushed a fresh lock-out", tenantID)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.busy = false
	r.lastPush = r.now()
	if err == nil {
		r.last[tenantID] = r.lastPush
	}
	if len(r.last) > seenRelockMaxTracked {
		for id, at := range r.last {
			if r.lastPush.Sub(at) >= seenRelockMinInterval {
				delete(r.last, id)
			}
		}
	}
}

// Periodic relock settings (IMAS_TENANT_RELOCK_INTERVAL, a Go duration).
const (
	TenantRelockIntervalEnv     = "IMAS_TENANT_RELOCK_INTERVAL"
	DefaultTenantRelockInterval = 10 * time.Minute
	MinTenantRelockInterval     = time.Minute
	MaxTenantRelockInterval     = 24 * time.Hour
)

// TenantRelockInterval returns the periodic relock interval
// IMAS_TENANT_RELOCK_INTERVAL sets, DefaultTenantRelockInterval when it
// is unset or empty. A value that doesn't parse, or is outside
// MinTenantRelockInterval to MaxTenantRelockInterval, is an error: farmer
// refuses to start rather than run without the relock.
func TenantRelockInterval() (time.Duration, error) {
	v := strings.TrimSpace(os.Getenv(TenantRelockIntervalEnv))
	if v == "" {
		return DefaultTenantRelockInterval, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s=%q: %w", TenantRelockIntervalEnv, v, err)
	}
	if d < MinTenantRelockInterval || d > MaxTenantRelockInterval {
		return 0, fmt.Errorf("%s=%q: must be from %s to %s", TenantRelockIntervalEnv, v, MinTenantRelockInterval, MaxTenantRelockInterval)
	}
	return d, nil
}

// tenantRelockJobName is the periodic relock's farmer.job_leases row.
const tenantRelockJobName = "tenant_relock"

// StartTenantRelocker runs RelockDeprovisionedTenants every interval
// until ctx ends; the returned channel is closed when it has stopped.
// Every farmer replica ticks, but a sweep runs only under the
// tenant_relock row lease, and only if no replica swept within nine
// tenths of interval, so the sweep runs once per interval across
// replicas.
func StartTenantRelocker(ctx context.Context, interval time.Duration) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		log.Infof("Relocking deprovisioned tenants every %s (%s)", interval, TenantRelockIntervalEnv)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				relockSweepLeased(ctx, interval, time.Now)
			}
		}
	}()
	return done
}

// relockSweepLeased is one relocker tick: RelockDeprovisionedTenants
// under the tenant_relock lease, with now as the lease clock. With no
// database installed it sweeps unconditionally (and finds nothing).
func relockSweepLeased(ctx context.Context, interval time.Duration, now func() time.Time) {
	sweep := func(ctx context.Context) error {
		_, err := RelockDeprovisionedTenants(ctx)
		return err
	}
	l := JobLeases(now)
	var err error
	if l == nil {
		err = sweep(ctx)
	} else {
		_, err = l.Run(ctx, tenantRelockJobName, lease.JobTTL(), interval-interval/10, sweep)
	}
	if err != nil {
		log.Errorf("Relocking deprovisioned tenants: %v", err)
	}
}

// relockBatchSize is how many deleted tenants a sweep reads from the
// database at a time.
const relockBatchSize = 100

// RelockDeprovisionedTenants pushes a fresh lock-out for every
// deprovisioned tenant whose Account is still live somewhere a bus node
// reads it: on a bus node (each node's CLAIMS.LOOKUP answer) or in the
// accounts bucket the bus loaders apply. A tenant already locked out
// everywhere is not pushed, so a sweep over a thousand deleted tenants
// that are all locked out pushes nothing. The deleted tenants are read
// in batches of relockBatchSize, and pushes are relockPushGap apart. A
// tenant whose bus state can't be read is pushed (fail closed). It
// returns how many lock-outs it pushed; every tenant is attempted, and
// the errors are joined.
func RelockDeprovisionedTenants(ctx context.Context) (int, error) {
	if db == nil {
		return 0, errNoStore
	}
	view, err := openBusAccountView()
	if err != nil {
		return 0, fmt.Errorf("pki: reading the bus's Account JWTs: %w", err)
	}
	defer view.close()

	var errs []error
	pushed, after := 0, ""
	for {
		rows, err := deletedTenantsWithAccount(after, relockBatchSize)
		if err != nil {
			return pushed, errors.Join(append(errs, err)...)
		}
		for _, row := range rows {
			if err := ctx.Err(); err != nil {
				return pushed, errors.Join(append(errs, err)...)
			}
			live, err := accountLiveOnBus(ctx, view, row.AccountPub)
			if err != nil {
				log.Warnf("tenant %q is deprovisioned and its bus state can't be read (%v); pushing a fresh lock-out", row.ID, err)
				live = true
			}
			if !live {
				continue
			}
			if pushed > 0 {
				if err := relockSleep(ctx, relockPushGap); err != nil {
					return pushed, errors.Join(append(errs, err)...)
				}
			}
			ok, err := relockPush(row.ID)
			switch {
			case err != nil:
				errs = append(errs, fmt.Errorf("tenant %q: %w", row.ID, err))
			case ok:
				pushed++
				log.Warnf("tenant %q is deprovisioned but its Account was live on the bus; pushed a fresh lock-out", row.ID)
			}
		}
		if len(rows) < relockBatchSize {
			break
		}
		after = rows[len(rows)-1].ID
	}
	if err := errors.Join(errs...); err != nil {
		return pushed, err
	}
	if pushed > 0 {
		log.Infof("Relocked %d deprovisioned tenants", pushed)
	}
	return pushed, nil
}

// deletedTenantsWithAccount returns up to limit deleted pki_tenants rows
// that recorded an Account, with IDs after after, in ID order.
func deletedTenantsWithAccount(after string, limit int) ([]tenantRow, error) {
	var rows []tenantRow
	if err := db.Where("deleted = ? AND account_pub <> '' AND id > ?", true, after).
		Order("id").Limit(limit).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("pki: listing deprovisioned tenants: %w", err)
	}
	return rows, nil
}

// accountLiveOnBus reports whether any copy of accountPub's Account JWT
// that a bus node holds or loads is not a lock-out: a bus node's
// CLAIMS.LOOKUP answer, or the newest of the accounts bucket's and this
// replica's held copy (the bus loaders apply the bucket).
func accountLiveOnBus(ctx context.Context, view busAccountView, accountPub string) (bool, error) {
	onBus, err := view.lookup(accountPub)
	if err != nil {
		return false, err
	}
	latest, _, err := latestAccountJWT(ctx, accountPub, func(*jwt.AccountClaims) bool { return true })
	if err != nil {
		return false, err
	}
	for _, raw := range append(onBus, latest) {
		if raw == "" {
			continue
		}
		ac, err := jwt.DecodeAccountClaims(raw)
		if err != nil || ac.Subject != accountPub {
			return false, fmt.Errorf("an Account JWT held for %s does not decode as its own", accountPub)
		}
		if !accountIsLockedOut(ac) {
			return true, nil
		}
	}
	return false, nil
}

// accountIsLockedOut reports whether ac carries lockOutAccount's
// lock-out: no connections, and every User JWT revoked.
func accountIsLockedOut(ac *jwt.AccountClaims) bool {
	return ac.Limits.Conn == 0 && ac.Revocations[jwt.All] > 0
}

// busAccountView reads the Account JWTs the bus nodes hold.
type busAccountView interface {
	// lookup returns every bus node's Account JWT for accountPub; a node
	// that holds none answers "", which is dropped. Fewer answers than
	// the bus has nodes is an error.
	lookup(accountPub string) ([]string, error)
	close()
}

// openBusAccountView opens the relock sweep's view of the bus; tests
// replace it.
var openBusAccountView = dialBusAccountView

// relockLookupWait bounds how long one CLAIMS.LOOKUP waits for every bus
// node's answer.
const relockLookupWait = 2 * time.Second

// natsBusAccountView is the busAccountView over one SYS connection.
type natsBusAccountView struct {
	nc   *nats.Conn
	want int // the bus nodes that should answer
}

func dialBusAccountView() (busAccountView, error) {
	nc, err := ConnectSystemAccount()
	if err != nil {
		return nil, err
	}
	nodes := discoverBusNodes(nc, config.BusExpectedNodes)
	return &natsBusAccountView{nc: nc, want: max(config.BusExpectedNodes, len(nodes), 1)}, nil
}

func (v *natsBusAccountView) lookup(accountPub string) ([]string, error) {
	inbox := v.nc.NewRespInbox()
	sub, err := v.nc.SubscribeSync(inbox)
	if err != nil {
		return nil, err
	}
	defer func() { _ = sub.Unsubscribe() }()
	if err := v.nc.PublishRequest(fmt.Sprintf(claimsLookupSubject, accountPub), inbox, nil); err != nil {
		return nil, err
	}
	var out []string
	answers := 0
	deadline := time.Now().Add(relockLookupWait)
	for answers < v.want {
		wait := time.Until(deadline)
		if wait <= 0 {
			break
		}
		msg, err := sub.NextMsg(wait)
		if err != nil {
			break
		}
		answers++
		if len(msg.Data) > 0 {
			out = append(out, string(msg.Data))
		}
	}
	// A node that didn't answer may hold a live copy: the lookup is
	// incomplete, which the sweep takes as live (fail closed).
	if answers < v.want {
		return nil, fmt.Errorf("only %d of %d bus nodes answered the claims lookup", answers, v.want)
	}
	return out, nil
}

func (v *natsBusAccountView) close() { v.nc.Close() }

// errTenantRecheckFailed marks pushLiveTenantAccount's error when no
// re-check after the live push could read the tenant's row: the tenant
// may have been deprovisioned meanwhile, so nothing may be issued on the
// strength of that push (L10).
var errTenantRecheckFailed = errors.New("re-checking the tenant after pushing its Account JWT failed")

// recheckAttempts is how often pushLiveTenantAccount reads the tenant's
// row after its live push before it gives up (L11).
const recheckAttempts = 3

// recheckBackoff is the wait before the second re-check; it doubles
// before the third. Each wait is jittered (recheckJitter).
const recheckBackoff = 250 * time.Millisecond

// recheckSleep waits between re-checks; tests replace it.
var recheckSleep = time.Sleep

// relockIfDeleted is the re-check; tests replace it to fail it.
var relockIfDeleted = relockIfDeletedLocked

// recheckJitter returns a wait drawn uniformly from [d/2, d].
func recheckJitter(d time.Duration) time.Duration {
	return d/2 + rand.N(d/2+1)
}

// recheckTenantDeleted is pushLiveTenantAccount's re-check, retried: up
// to recheckAttempts reads of the tenant's row (relockIfDeletedLocked),
// with jittered, doubling waits between them. It returns the first
// answer; only when every attempt failed does it return their errors,
// joined.
func recheckTenantDeleted(mat *natsAuthMaterial, tenantID string) (signedJWT string, deleted bool, err error) {
	var errs []error
	wait := recheckBackoff
	for attempt := 1; ; attempt++ {
		signed, deleted, err := relockIfDeleted(mat, tenantID)
		if err == nil {
			return signed, deleted, nil
		}
		errs = append(errs, fmt.Errorf("attempt %d: %w", attempt, err))
		if attempt == recheckAttempts {
			return "", false, errors.Join(errs...)
		}
		log.Warnf("re-checking tenant %q after pushing its Account JWT failed (attempt %d of %d): %v", tenantID, attempt, recheckAttempts, err)
		recheckSleep(recheckJitter(wait))
		wait *= 2
	}
}
