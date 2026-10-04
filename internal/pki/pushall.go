package pki

// PushAllAccounts is core's half of "the bus signs nothing of its own"
// (busauth.go). FLAG FOR SECURITY REVIEW.

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	jwt "github.com/nats-io/jwt/v2"

	log "github.com/yogzblr/imas/internal/log"
)

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
// Each push re-reads the Account JWT from disk once the bus has answered,
// and pushes again if it changed (pushUntilCurrent), so a deny, reject or
// key rotation racing this run can't be undone by the older copy this run
// read first.
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
	push := func(what, accountJWT string) {
		if err := pushAccountUpdate(mat, accountJWT); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", what, err))
			return
		}
		pushed++
	}
	pushCurrent := func(what, accountJWT, path string) {
		err := pushUntilCurrent(what, accountJWT,
			func(j string) error { return pushAccountUpdate(mat, j) },
			func() (string, error) { return readAccountJWTFile(path) })
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", what, err))
			return
		}
		pushed++
	}

	// SYS first: the bus may hold only its epoch-dated bootstrap, without
	// core's revocations (rotated-out SaaS API keys).
	pushCurrent("SYS account", mat.sysAccountJWT, sysAccountJWTPath())
	pushCurrent("legacy tenant "+currentTenantID(), mat.tenantJWT, tenantJWTPath())

	live, err := ListProvisionedTenantIDs()
	if err != nil {
		errs = append(errs, fmt.Errorf("listing provisioned tenants: %w", err))
	}
	for _, id := range live {
		if id == currentTenantID() {
			continue
		}
		tam, err := loadTenantAccountMaterial(id)
		if err != nil {
			errs = append(errs, fmt.Errorf("tenant %q: %w", id, err))
			continue
		}
		err = pushUntilCurrent("tenant "+id, tam.jwt,
			func(j string) error { return pushLiveTenantAccount(mat, id, j) },
			func() (string, error) { return readAccountJWTFile(tenantAccountJWTPath(id)) })
		if err != nil {
			if !errors.Is(err, ErrTenantDeprovisioned) {
				errs = append(errs, fmt.Errorf("tenant %q: %w", id, err))
			}
			continue
		}
		pushed++
	}

	deleted, err := listDeletedTenantIDs()
	if err != nil {
		errs = append(errs, fmt.Errorf("listing deprovisioned tenants: %w", err))
	}
	for _, id := range deleted {
		signed, ok, err := relockForPushAll(mat, id)
		if err != nil {
			errs = append(errs, fmt.Errorf("deprovisioned tenant %q: %w", id, err))
			continue
		}
		if ok {
			push("deprovisioned tenant "+id, signed)
		}
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
// (syncNatsAuth, syncTenantSprouts, the SaaS API key rotation, a lock-out)
// persists its JWT before pushing it. Either the re-read sees that write,
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

// readAccountJWTFile reads an Account JWT that core persisted, for
// pushUntilCurrent's re-check. It reads the file directly rather than
// through ensureNatsAuth or ensureTenantAccountMaterial, which re-mint a
// JWT without revocations when the file doesn't decode: the writers use
// a plain os.WriteFile, so a read can land mid-write. An undecodable read
// is retried briefly and then reported, never replaced.
func readAccountJWTFile(path string) (string, error) {
	var lastErr error
	for i := 0; i < 5; i++ {
		b, err := os.ReadFile(path)
		if err == nil {
			_, err = jwt.DecodeAccountClaims(string(b))
		}
		if err == nil {
			return string(b), nil
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	return "", fmt.Errorf("reading %s: %w", path, lastErr)
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
		if _, statErr := os.Stat(tenantAccountJWTPath(tenantID)); os.IsNotExist(statErr) {
			return "", false, nil
		}
	}
	signed, err = signLockedOutTenantJWT(mat, tenantID, row.Name)
	if err != nil {
		return "", false, err
	}
	return signed, true, nil
}
