package pki

// PushAllAccounts is core's half of "the bus signs nothing of its own"
// (busauth.go). FLAG FOR SECURITY REVIEW.

import (
	"errors"
	"fmt"
	"os"
	"sync"

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

	// SYS first: the bus may hold only its epoch-dated bootstrap, without
	// core's revocations (rotated-out SaaS API keys).
	push("SYS account", mat.sysAccountJWT)
	push("legacy tenant "+currentTenantID(), mat.tenantJWT)

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
		if err := pushLiveTenantAccount(mat, id, tam.jwt); err != nil {
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
