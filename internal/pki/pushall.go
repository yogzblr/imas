package pki

// PushAllAccounts is core's half of "the bus signs nothing of its own"
// (busauth.go). FLAG FOR SECURITY REVIEW.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/yogzblr/imas/internal/lease"
	log "github.com/yogzblr/imas/internal/log"
)

// pushAllMinInterval is how long after one replica pushed a tenant's
// Account in PushAllAccounts no replica pushes it there again.
const pushAllMinInterval = 60 * time.Second

// pushAllJobName is tenantID's farmer.job_leases row for PushAllAccounts.
// A tenant ID is at most 32 characters, so the name fits the column.
func pushAllJobName(tenantID string) string { return "pushall:" + tenantID }

// pushAllNow is PushAllAccounts' lease clock; tests replace it.
var pushAllNow = time.Now

// JobLeases returns the farmer background job leases (farmer.job_leases)
// on this package's database with clock now (nil: time.Now), or nil when
// no database is installed. Farmer's periodic jobs outside this package
// (the cohort refresher) take their lease through it.
func JobLeases(now func() time.Time) *lease.Leases {
	if db == nil {
		return nil
	}
	return lease.New(db, now)
}

// leasedPush runs push as tenantID's share of PushAllAccounts under the
// pushall:<tenant_id> lease: on one replica at a time, and not again
// within pushAllMinInterval of a successful push by any replica. It
// reports whether push ran. With no database it runs push directly.
func leasedPush(tenantID string, push func() error) (bool, error) {
	l := JobLeases(pushAllNow)
	if l == nil {
		return true, push()
	}
	return l.Run(context.Background(), pushAllJobName(tenantID), lease.JobTTL(), pushAllMinInterval,
		func(context.Context) error { return push() })
}

// pushAllMu serialises PushAllAccounts runs (a reconnect can fire while
// the previous run is still pushing).
var pushAllMu sync.Mutex

// PushAllAccounts pushes every Account JWT core holds to the bus resolver:
// the SYS account, the legacy tenant, every provisioned tenant (live), and
// a fresh lock-out for every deprovisioned tenant that ever had an
// Account. cmd/farmer runs it whenever its SYS connection connects or
// reconnects.
//
// The bus no longer mints any Account JWT for itself (see busauth.go), so
// a bus that lost its volume, or a whole cluster started fresh, learns the
// Accounts only from core; until now core pushed an Account only when its
// claims changed, so an unchanged tenant would never have reached it. A
// new node joining an existing cluster gets them from its peers instead,
// through the fence's pull.
//
// Live tenants go through pushLiveTenantAccount, so a deprovision racing
// this push (on this replica or another) still ends with the lock-out
// applied last. Deprovisioned tenants are re-signed, not re-pushed as
// stored, so the lock-out also carries the newest issued-at, which is what
// the resolver sync between bus nodes compares.
//
// Each push re-reads the Account JWT this process holds once the bus has
// answered, and pushes again if it changed (pushUntilCurrent), so a deny, reject or
// key rotation racing this run can't be undone by the older copy this run
// read first.
//
// Every farmer replica runs this on each (re)connect. Each tenant's push
// (live, legacy or deprovisioned) runs under its pushall:<tenant_id> row
// lease with a 60s minimum interval (leasedPush), so N replicas
// reconnecting together push each tenant once, not N times; a tenant
// another replica is pushing, or pushed successfully within the
// interval, is skipped and neither counted nor an error. A failed push
// doesn't count toward the interval, so the next attempt on any replica
// retries it. The SYS Account is pushed every time: it is one push, and
// it carries the revocations.
//
// With an AccountPublisher installed, ReconcileAll runs first, under the
// reconcile-accounts job lease, and every push writes the accounts bucket
// before it reaches the bus (pushAccountUpdate); an Account JWT the
// bucket already holds a newer copy of (another replica signed and pushed
// it) is not pushed again.
//
// Every push is attempted; the errors are joined. The returned count is
// the number of Account JWTs the bus accepted.
func PushAllAccounts() (int, error) {
	pushAllMu.Lock()
	defer pushAllMu.Unlock()

	mat, err := ensureNatsAuth()
	if err != nil {
		return 0, fmt.Errorf("bootstrapping NATS auth material: %w", err)
	}
	var errs []error
	pushed := 0
	// The accounts bucket first (docs/briefs/P21-slice2-bus-loader.md
	// §7.5): whatever this replica holds that the bucket lacks, or holds
	// older, is written before anything is pushed.
	if err := reconcileAccountsLeased(context.Background()); err != nil {
		errs = append(errs, fmt.Errorf("reconciling the accounts bucket: %w", err))
	}
	pushCurrent := func(what, accountJWT, accountPub string) error {
		return pushUntilCurrent(what, accountJWT,
			func(j string) error { return pushAccountUpdate(mat, j) },
			func() (string, error) { return currentHeldAccountJWT(accountPub, accountJWT) })
	}
	// leased runs a tenant's push under its lease (leasedPush). push
	// reports whether it pushed anything; it is counted if it did and
	// succeeded. ErrTenantDeprovisioned (pushLiveTenantAccount pushed the
	// lock-out last) is neither counted nor an error.
	leased := func(tenantID, what string, push func() (bool, error)) {
		sent := false
		_, err := leasedPush(tenantID, func() error {
			var err error
			sent, err = push()
			return err
		})
		switch {
		case errors.Is(err, ErrTenantDeprovisioned):
		case err != nil:
			errs = append(errs, fmt.Errorf("%s: %w", what, err))
		case sent:
			pushed++
		}
	}

	// SYS first: the bus may hold only its epoch-dated bootstrap, without
	// core's revocations (rotated-out SaaS API keys).
	if err := pushCurrent("SYS account", mat.sysAccountJWT, mat.sysAccountPub); err != nil {
		errs = append(errs, fmt.Errorf("SYS account: %w", err))
	} else {
		pushed++
	}
	legacy := currentTenantID()
	leased(legacy, "legacy tenant "+legacy, func() (bool, error) {
		return true, pushCurrent("legacy tenant "+legacy, mat.tenantJWT, mat.tenantPub)
	})

	live, err := ListProvisionedTenantIDs()
	if err != nil {
		errs = append(errs, fmt.Errorf("listing provisioned tenants: %w", err))
	}
	for _, id := range live {
		if id == legacy {
			continue
		}
		leased(id, fmt.Sprintf("tenant %q", id), func() (bool, error) {
			tam, err := loadTenantAccountMaterial(id)
			if err != nil {
				return false, err
			}
			return true, pushUntilCurrent("tenant "+id, tam.jwt,
				func(j string) error { return pushLiveTenantAccount(mat, id, j) },
				func() (string, error) { return currentHeldAccountJWT(tam.pub, tam.jwt) })
		})
	}

	deleted, err := listDeletedTenantIDs()
	if err != nil {
		errs = append(errs, fmt.Errorf("listing deprovisioned tenants: %w", err))
	}
	for _, id := range deleted {
		leased(id, fmt.Sprintf("deprovisioned tenant %q", id), func() (bool, error) {
			signed, ok, err := relockForPushAll(mat, id)
			if err != nil || !ok {
				return false, err
			}
			return true, pushAccountUpdate(mat, signed)
		})
	}

	if err := errors.Join(errs...); err != nil {
		log.Errorf("pushed %d Account JWTs to the bus resolver; some failed: %v", pushed, err)
		return pushed, err
	}
	log.Infof("Pushed all %d Account JWTs to the bus resolver.", pushed)
	return pushed, nil
}

// maxRepushes bounds pushUntilCurrent: each round needs another change
// to land within one push round trip.
const maxRepushes = 5

// testHookPushAllBeforePush runs in pushUntilCurrent before each push,
// standing in for a concurrent writer (a deny or reject re-signing and
// pushing the same Account). Always nil in production.
var testHookPushAllBeforePush func(what string)

// pushUntilCurrent pushes accountJWT, then, once the bus has answered (or
// the push failed: a request that timed out may still have been applied),
// re-reads the Account JWT with current; if it changed, it pushes the new
// one and checks again.
//
// This is what keeps an older copy from undoing a newer one. Every writer
// in this process (syncNatsAuth, syncTenantSprouts, the SaaS API key
// rotation, a lock-out) holds its JWT (holdAccountJWT) before pushing it;
// a writer on another replica is ordered by the accounts bucket, which
// takes no JWT older than the one it has (pushAccountUpdate). Either the re-read sees that write,
// and the newer JWT is pushed after this push was answered; or the write
// came after the re-read, so the writer's own push started after this one
// was applied. Either way the newest JWT reaches the bus last, which is
// what counts: the bus applies claims pushes in arrival order.
func pushUntilCurrent(what, accountJWT string, push func(string) error, current func() (string, error)) error {
	pushed := accountJWT
	for i := 0; ; i++ {
		if testHookPushAllBeforePush != nil {
			testHookPushAllBeforePush(what)
		}
		err := push(pushed)
		if errors.Is(err, ErrTenantDeprovisioned) {
			return err // pushLiveTenantAccount pushed the lock-out last
		}
		now, rerr := current()
		if rerr != nil {
			return errors.Join(err, fmt.Errorf("re-reading after the push (bus state unconfirmed): %w", rerr))
		}
		if now == pushed {
			return err
		}
		if i == maxRepushes {
			return fmt.Errorf("still changing after %d re-pushes; the next push of this Account will carry it", maxRepushes)
		}
		log.Infof("%s changed while it was being pushed; pushing the current Account JWT", what)
		pushed = now
	}
}

// currentHeldAccountJWT is pushUntilCurrent's re-check: the Account JWT
// this process holds for accountPub now, or pushed when it holds none.
func currentHeldAccountJWT(accountPub, pushed string) (string, error) {
	if h, ok := heldAccountJWT(accountPub); ok {
		return h.jwt, nil
	}
	return pushed, nil
}

// relockForPushAll re-signs a deprovisioned tenant's lock-out, like
// relockIfDeletedLocked, but skips a tombstone (a tenant deprovisioned
// before it ever had an Account), so pushing everything never mints keys
// just to lock them out. ok is false when there is nothing to push.
func relockForPushAll(mat *natsAuthMaterial, tenantID string) (signed string, ok bool, err error) {
	tenantAuthMu.Lock()
	defer tenantAuthMu.Unlock()

	row, err := getTenantRow(tenantID)
	if err != nil {
		return "", false, err
	}
	if !row.Deleted {
		return "", false, nil // re-provisioned since the listing
	}
	if row.AccountPub == "" {
		return "", false, nil
	}
	signed, err = signLockedOutTenantJWT(mat, row)
	if err != nil {
		return "", false, err
	}
	return signed, true, nil
}
