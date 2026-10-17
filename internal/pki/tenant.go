package pki

// Dynamic tenant Account provisioning — workstream E
// (docs/design/imas-fork-roadmap.md, docs/design/imas-nats-jwt-auth-design.md
// "one Account per tenant"). This file is what actually makes
// FarmerOrganization dynamic: jwtauth.go's natsAuthMaterial still holds
// exactly one "current" tenant Account (named by the static
// config.FarmerOrganization string, decided once at boot — see its own doc
// comment), which every existing Accept/Deny/Reject/Unaccept/Delete call
// and the SIGHUP-driven ReloadNKeys() still operate against unchanged. What
// this file adds is a second, independent way to get a tenant Account: any
// tenant ID can have its own Account minted and pushed to the bus resolver
// at any time, not just the one config names at boot — via ProvisionTenant,
// called either explicitly (the internal.tenant.provision round trip from
// internal/saasapi, handled by internal/natsapi's tenant_provision.go) or
// lazily by ReloadNKeysForTenant the first time a sprout enrolls for a
// tenant (enroll.go), whichever happens first.
//
// FLAG FOR SECURITY REVIEW (tenant isolation correctness): every
// dynamically-provisioned tenant gets its own Account keypair, its own
// Account JWT (held in memory and kept in the accounts bucket, under the
// Account's own public key), and its sprouts' User JWTs under its own
// tenant ID in the sprout JWT bucket — structurally separate from every
// other tenant's, the same "isolation enforced by which Account a
// connection authenticated into" property the design doc describes for the legacy single-tenant
// seam. The operator (and its delegated signing key) remain shared across
// every tenant by design — that's the trust anchor the whole chain rests
// on, not a tenant boundary itself; see jwtauth.go's own security-review
// note on operator key custody, which applies identically here.
import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	log "github.com/yogzblr/imas/internal/log"
)

var tenantIDMatcher = regexp.MustCompile(`^[0-9A-Za-z_-]{1,191}$`)

// IsValidTenantID reports whether id is safe to use both as a PXC primary
// key and as an object key prefix in the sprout JWT bucket (so this also
// guards against key traversal via a malicious/malformed tenant ID).
func IsValidTenantID(id string) bool {
	return tenantIDMatcher.MatchString(id)
}

// tenantAccountMaterial is one tenant's NATS Account trust material:
// its Account public key (the Transit key nats-tacct-<id>, which never
// signs), a delegated signing pair (Transit key nats-tsign-<id>, mirroring
// the operator/operator-signing split in jwtauth.go), and the current
// signed Account JWT (held in memory, accountjwts.go).
type tenantAccountMaterial struct {
	signingKP  nkeys.KeyPair
	signingPub string
	pub        string
	jwt        string
	// minted: jwt was minted by this load and not yet pushed or
	// published, so a re-sign need not outrank its iat.
	minted bool
}

// tenantAuthMu guards concurrent bootstrap/holding of any tenant's
// Account material below (a pki_tenants row plus its Account keys and
// JWT) — the tenant-scoped counterpart to jwtauth.go's authMu, which
// guards only the legacy single "current tenant"'s material and the
// platform-wide operator/SYS material. Deliberately a separate lock rather
// than reusing authMu: every entry point below (ensureTenantAccountLocked,
// used by ProvisionTenant/ReloadNKeysForTenant/loadTenantAccountMaterial/
// DeprovisionTenant) first calls ensureNatsAuth(), which takes authMu
// itself — holding authMu across that call here would deadlock, since
// Go's sync.Mutex isn't reentrant.
var tenantAuthMu sync.Mutex

// ensureTenantAccountMaterial loads tenantID's Account keys from Transit
// and its Account JWT (the one this process holds, or else the accounts
// bucket's), minting a minimal one and holding it if neither has one —
// idempotent, but relies on the caller already holding
// tenantAuthMu (every call site in this file does, via
// ensureTenantAccountLocked or loadTenantAccountMaterial) for safety
// under concurrent calls for the same tenant. Only provisioning passes
// create, which creates the tenant's two Transit keys when they don't
// exist; otherwise a missing key is an error wrapping
// natskeys.ErrKeyNotFound and nothing is created.
func ensureTenantAccountMaterial(mat *natsAuthMaterial, tenantID, name string, create bool) (*tenantAccountMaterial, bool, error) {
	tam := &tenantAccountMaterial{}
	ctx := context.Background()

	getKey := natsKeys.keyPair
	if create {
		getKey = natsKeys.ensureKeyPair
	}
	var err error
	tam.signingKP, err = getKey(ctx, natsKeyRef{role: natsKeyTenantSigning, tenantID: tenantID})
	if err != nil {
		return nil, false, err
	}
	if tam.signingPub, err = tam.signingKP.PublicKey(); err != nil {
		return nil, false, err
	}
	accountKP, err := getKey(ctx, natsKeyRef{role: natsKeyTenantAccount, tenantID: tenantID})
	if err != nil {
		return nil, false, err
	}
	if tam.pub, err = accountKP.PublicKey(); err != nil {
		return nil, false, err
	}
	signingPub := tam.signingPub

	held, heldMinted, err := loadAccountJWT(ctx, tam.pub, signsWith(signingPub))
	if err != nil {
		return nil, false, err
	}
	if held != "" {
		tam.jwt, tam.minted = held, heldMinted
		return tam, false, nil
	}
	ac := jwt.NewAccountClaims(tam.pub)
	ac.Name = name
	ac.SigningKeys.Add(signingPub)
	signed, err := ac.Encode(mat.operatorSigningKP)
	if err != nil {
		return nil, false, err
	}
	if err := holdAccountJWT(signed, true); err != nil {
		return nil, false, err
	}
	tam.jwt = signed
	tam.minted = true
	return tam, true, nil
}

// loadTenantAccountMaterial loads a tenant's Account material without
// creating a new pki_tenants row — used where the caller expects the
// tenant to already be provisioned (PushAllAccounts) and a missing tenant
// should surface as an error rather than silently registering one: the
// tenant must have a pki_tenants row with its Account recorded. It never
// creates Transit keys: a tenant whose keys are missing is an error.
func loadTenantAccountMaterial(tenantID string) (*tenantAccountMaterial, error) {
	mat, err := ensureNatsAuth()
	if err != nil {
		return nil, err
	}
	row, err := getTenantRow(tenantID)
	if err != nil {
		return nil, fmt.Errorf("pki: no Account material found for tenant %q: %w", tenantID, err)
	}
	if row.AccountPub == "" {
		return nil, fmt.Errorf("pki: no Account material found for tenant %q: no Account recorded", tenantID)
	}
	tenantAuthMu.Lock()
	defer tenantAuthMu.Unlock()
	tam, _, err := ensureTenantAccountMaterial(mat, tenantID, tenantID, false)
	return tam, err
}

// ensureTenantAccount is the shared bootstrap path for ProvisionTenant and
// ReloadNKeysForTenant: it ensures a pki_tenants row exists for tenantID
// (creating one, named nameHint, if this is the first time this tenant has
// ever been provisioned) and that its Account material exists.
// provisioned reports whether either the tenant row or the Account
// material was newly created by this call — callers use it to decide
// whether a resolver push is required even if syncing sprouts found
// nothing to change.
//
// createKeys is true only for ProvisionTenant: it creates the tenant's
// Transit keys if they don't exist. Enrollment and resync pass false and
// create keys only when this call registered the tenant (a first
// enrollment, which provisions it lazily); for an already-registered
// tenant a missing key is an error.
func ensureTenantAccount(tenantID, nameHint string, createKeys bool) (mat *natsAuthMaterial, tam *tenantAccountMaterial, provisioned bool, err error) {
	if !IsValidTenantID(tenantID) {
		return nil, nil, false, ErrTenantIDInvalid
	}
	// ensureNatsAuth takes authMu itself — called before tenantAuthMu below
	// (never while holding it) to avoid a lock-ordering deadlock with
	// anything else that might one day take both.
	mat, err = ensureNatsAuth()
	if err != nil {
		return nil, nil, false, err
	}
	tam, provisioned, err = ensureTenantAccountLocked(mat, tenantID, nameHint, createKeys)
	if err != nil {
		return nil, nil, false, err
	}
	// Notify cmd/farmer/main.go's ConnectFarmer that this tenant is newly
	// live, so it can open a dedicated NATS connection and boot that
	// tenant's registrations at runtime (see OnTenantProvisioned's doc
	// comment and docs/design/imas-tenant-context-threading.md's Option A).
	// Fired outside tenantAuthMu (already released above) and in its own
	// goroutine: the hook dials the bus over the network, which must never
	// block an enrollment request or an explicit ProvisionTenant call
	// waiting on it.
	if provisioned && tenantProvisionedHook != nil {
		go tenantProvisionedHook(tenantID)
	}
	return mat, tam, provisioned, nil
}

// tenantProvisionedHook and tenantDeprovisionedHook let cmd/farmer/main.go
// react to a tenant becoming newly live or going away without internal/pki
// depending on cmd/farmer's connection-lifecycle code. See
// OnTenantProvisioned/OnTenantDeprovisioned.
var (
	tenantProvisionedHook   func(tenantID string)
	tenantDeprovisionedHook func(tenantID string)
)

// OnTenantProvisioned registers fn to be called, in its own goroutine,
// whenever a brand-new tenant Account is provisioned — via an explicit
// ProvisionTenant call or ReloadNKeysForTenant's lazy first-enrollment path
// (enroll.go's acceptEnrolledNKey). cmd/farmer/main.go uses this to open
// that tenant's dedicated NATS connection and register its full handler
// set at runtime (docs/design/imas-tenant-context-threading.md's Option A),
// instead of only ever connecting the tenants known at boot. Call once at
// startup, before enrollment can occur; only the most recently registered
// callback is kept — this package supports exactly one subscriber, not a
// general pub/sub mechanism.
func OnTenantProvisioned(fn func(tenantID string)) { tenantProvisionedHook = fn }

// OnTenantDeprovisioned registers fn to be called, in its own goroutine,
// whenever DeprovisionTenant tears down a tenant's Account. cmd/farmer/main.go
// uses this to close that tenant's NATS connection and unregister its
// handlers cleanly (no leaked goroutines/subscriptions — closing the
// underlying *nats.Conn tears down every subscription registered on it in
// one call). See OnTenantProvisioned's doc comment for the same
// single-subscriber caveat.
func OnTenantDeprovisioned(fn func(tenantID string)) { tenantDeprovisionedHook = fn }

// ensureTenantAccountLocked is ensureTenantAccount's body once mat (the
// platform-wide operator/SYS material) is already in hand — split out so
// loadTenantAccountMaterial can reuse the same tenantAuthMu-guarded section
// without re-deriving mat.
func ensureTenantAccountLocked(mat *natsAuthMaterial, tenantID, nameHint string, createKeys bool) (tam *tenantAccountMaterial, provisioned bool, err error) {
	tenantAuthMu.Lock()
	defer tenantAuthMu.Unlock()

	row, lookupErr := getTenantRow(tenantID)
	if testHookProvisionAfterLookup != nil {
		testHookProvisionAfterLookup(tenantID)
	}
	if errors.Is(lookupErr, ErrTenantNotFound) {
		// Absent when read; a DeprovisionTenant on another replica may
		// write its tombstone before this insert (tenantAuthMu orders only
		// this process), so insert only if still absent and re-read either
		// way: the row this proceeds on is the one in the database.
		name := nameHint
		if name == "" {
			name = tenantID
		}
		inserted, err := insertTenantRowIfAbsent(tenantRow{ID: tenantID, Name: name, CreatedAt: time.Now().Unix()})
		if err != nil {
			return nil, false, fmt.Errorf("pki: recording tenant %q: %w", tenantID, err)
		}
		provisioned = inserted
		row, lookupErr = getTenantRow(tenantID)
	}
	switch {
	case lookupErr != nil:
		// A real lookup failure, never taken as an absent row.
		return nil, false, lookupErr
	case row.Deleted:
		return nil, false, fmt.Errorf("pki: tenant %q: %w", tenantID, ErrTenantDeprovisioned)
	}
	nameHint = row.Name

	tam, minted, err := ensureTenantAccountMaterial(mat, tenantID, nameHint, createKeys || provisioned)
	if err != nil {
		return nil, false, err
	}
	// Record the Account pubkey on the tenant row so TenantIDForAccountPub
	// (store.go) can reverse-map it later — see
	// docs/design/imas-tenant-context-threading.md. Idempotent: a tenant's
	// Account keypair never changes once minted, so this is a no-op update
	// on every call after the first.
	if err := setTenantAccountPub(tenantID, tam.pub); err != nil {
		return nil, false, fmt.Errorf("pki: recording tenant %q's Account pubkey: %w", tenantID, err)
	}
	return tam, provisioned || minted, nil
}

// ProvisionTenant creates (or, called again, confirms/refreshes) tenantID's
// dedicated NATS Account and pushes it to the bus resolver — the concrete
// "one Account created/pushed per tenant at onboarding" workstream E asks
// for, replacing the old single static config-loaded FarmerOrganization
// string as the only way a tenant Account ever came into being. Idempotent:
// safe to call again for an already-provisioned tenant (e.g. a retried
// internal.tenant.provision delivery — NATS core gives no dedup on its
// own), and always (re-)pushes so a resolver that missed an earlier push
// (bus node started after this call, or a prior push failed) catches up.
//
// A copy of the request re-published by saasapi's outbox sweeper can run
// on one replica while DeprovisionTenant runs on another. After its push,
// ProvisionTenant re-reads the tenant's deleted state from the database
// and, if the deprovision won, pushes the locked-out JWT again and returns
// an error wrapping ErrTenantDeprovisioned (see pushLiveTenantAccount for
// the ordering this gives). A tenant already deleted when the call starts
// is refused before anything is pushed (ensureTenantAccountLocked).
func ProvisionTenant(tenantID, name string) error {
	mat, tam, _, err := ensureTenantAccount(tenantID, name, true)
	if err != nil {
		log.Errorf("failed to provision tenant %q: %v", tenantID, err)
		return err
	}
	// Mint (or reuse) farmer's own User JWT under this tenant's Account
	// immediately, rather than waiting for this tenant's first sprout to be
	// accepted (syncTenantSprouts, below, is also what ReloadNKeysForTenant
	// calls) — cmd/farmer/main.go's OnTenantProvisioned callback dials this
	// tenant's connection right after this call returns, and needs
	// FarmerUserJWTForTenant to already have something to read. Harmless to
	// also sync sprout state here even though a freshly-provisioned tenant
	// may not have any yet.
	if _, err := syncTenantSprouts(mat, tam, tenantID); err != nil {
		log.Errorf("failed to sync tenant %q's Account JWT during provisioning: %v", tenantID, err)
		return err
	}
	if err := pushLiveTenantAccount(mat, tenantID, tam.jwt); err != nil {
		log.Errorf("failed to push tenant %q's Account JWT to the bus resolver: %v", tenantID, err)
		return err
	}
	log.Infof("Provisioned NATS Account for tenant %q and pushed it to the bus resolver.", tenantID)
	return nil
}

// DeprovisionTenant reverses ProvisionTenant: it marks tenantID deleted in
// the pki_tenants registry and pushes a locked-out Account JWT to the
// resolver (see lockOutAccount), so the bus closes the tenant's live
// connections and refuses new ones, effective immediately. Once the
// lockout is on the bus it retires (soft-deletes) the tenant's two
// Transit keys, so nothing can sign for the tenant again; an operator can
// restore them (soft-delete-restore) until the tenant's data is purged.
// The tenant's sprout state, stored JWTs and keys stay until then: the
// purge (tenantpurge.go, internal.tenant.purge) erases them after the
// SaaS API's retention delay, or earlier on an operator's request. A
// failed retire is returned; calling DeprovisionTenant again retries it.
//
// It is also the repair for a bus that still holds a live JWT for a
// deleted tenant (a crash between marking the row and pushing, or a lost
// push): called again for a tenant whose row is already deleted, it signs
// and pushes a fresh locked-out JWT rather than returning early, so a
// retried deprovision always leaves the bus locked out. See
// ProvisionTenant for the other half of the provision/deprovision race fix.
func DeprovisionTenant(tenantID string) error {
	if !IsValidTenantID(tenantID) {
		return ErrTenantIDInvalid
	}
	// Same lock-ordering reason as ensureTenantAccount: derive mat (takes
	// authMu internally) before touching tenantAuthMu, never while holding
	// it.
	mat, err := ensureNatsAuth()
	if err != nil {
		return err
	}
	signedJWT, alreadyDeleted, err := deprovisionTenantLocked(mat, tenantID)
	if err != nil {
		return err
	}
	if testHookDeprovisionBeforePush != nil {
		testHookDeprovisionBeforePush(tenantID)
	}
	if err := pushAccountUpdate(mat, signedJWT); err != nil {
		log.Errorf("failed to push tenant %q's locked-out Account JWT to the bus resolver: %v", tenantID, err)
		return err
	}
	if alreadyDeleted {
		log.Infof("Tenant %q was already deprovisioned: locked-out Account JWT pushed to the bus resolver again.", tenantID)
	} else {
		log.Infof("Deprovisioned tenant %q: locked-out Account JWT pushed to the bus resolver.", tenantID)
	}
	// See OnTenantDeprovisioned's doc comment: lets cmd/farmer/main.go close
	// this tenant's NATS connection and unregister its handlers. Fired on a
	// retry too: disconnectTenant is a no-op for a tenant with no
	// connection, and closes one a late provision copy may have opened.
	if tenantDeprovisionedHook != nil {
		go tenantDeprovisionedHook(tenantID)
	}
	return retireTenantKeys(tenantID)
}

// retireTenantKeys soft-deletes tenantID's account and signing keys in
// Transit. Idempotent: a missing or already retired key is success. The
// legacy current tenant is never retired: its keys sign for the farmer's
// own legacy Account (ensureNatsAuth), which a deprovision of that ID
// does not end.
func retireTenantKeys(tenantID string) error {
	if tenantID == currentTenantID() {
		return nil
	}
	ctx := context.Background()
	var errs []error
	for _, role := range []natsKeyRole{natsKeyTenantSigning, natsKeyTenantAccount} {
		if err := natsKeys.retireKey(ctx, natsKeyRef{role: role, tenantID: tenantID}); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		log.Errorf("tenant %q is locked out but its NATS keys were not all retired: %v", tenantID, err)
		return err
	}
	return nil
}

// deprovisionTenantLocked is DeprovisionTenant's tenantAuthMu-guarded body:
// it marks tenantID deleted (unless it already is) and then re-signs its
// Account JWT locked out (see lockOutAccount), leaving the bus push to the
// caller (network I/O shouldn't happen while holding this lock).
// alreadyDeleted reports that the row was deleted before this call.
//
// The row is marked deleted before the lockout is signed, not after. On
// one bus only the order of the pushes matters (see
// pushLiveTenantAccount), but the resolver compares iat where it
// reconciles copies (re-seeding from the accounts bucket at bus start, a future bus
// cluster), and this order means a provision copy that read the row as not
// deleted signed its live JWT before this lockout. If the process fails
// between the two steps the row is deleted but the bus is still live; a
// retried DeprovisionTenant repairs that.
func deprovisionTenantLocked(mat *natsAuthMaterial, tenantID string) (signedJWT string, alreadyDeleted bool, err error) {
	tenantAuthMu.Lock()
	defer tenantAuthMu.Unlock()

	row, err := getTenantRow(tenantID)
	if testHookDeprovisionAfterLookup != nil {
		testHookDeprovisionAfterLookup(tenantID)
	}
	if errors.Is(err, ErrTenantNotFound) && tenantID != currentTenantID() {
		// Never provisioned: nothing to lock out, but leave a deleted
		// tombstone so a provision copy or an enrollment arriving later,
		// on any replica, is refused (ensureTenantAccountLocked) rather
		// than creating a live Account for an offboarded tenant. The
		// legacy current tenant is exempt: it is not deprovisioned this
		// way and must stay enrollable. If a concurrent provision inserted
		// the row first, deprovision it like any other.
		inserted, insErr := insertTenantRowIfAbsent(tenantRow{ID: tenantID, Name: tenantID, Deleted: true, CreatedAt: time.Now().Unix()})
		if insErr != nil {
			return "", false, fmt.Errorf("pki: recording tenant %q's tombstone: %w", tenantID, insErr)
		}
		if inserted {
			return "", false, ErrTenantNotFound
		}
		row, err = getTenantRow(tenantID)
	}
	if err != nil {
		return "", false, err
	}
	if !row.Deleted {
		if err := markTenantDeleted(tenantID); err != nil {
			return "", false, err
		}
	}
	// No Account was ever recorded or written for this tenant (a tombstone,
	// or a provision that hasn't minted yet): nothing can be on the bus, so
	// don't mint keys just to lock them out. The Account is read again
	// after the mark has committed, not taken from the row read above: a
	// provision on another replica can record its Account and push between
	// that read and the mark. Every push follows setTenantAccountPub, so if
	// this read still finds none, the provision records it after the mark,
	// and its post-push re-check sees the row deleted and locks it out.
	wasDeleted := row.Deleted
	if row, err = getTenantRow(tenantID); err != nil {
		return "", false, err
	}
	if row.AccountPub == "" {
		return "", wasDeleted, ErrTenantNotFound
	}
	signed, err := signLockedOutTenantJWT(mat, row)
	if err != nil {
		return "", false, err
	}
	return signed, wasDeleted, nil
}

// signLockedOutTenantJWT re-signs row's Account JWT locked out (see
// lockOutAccount) as of now and holds it, replacing whatever this process
// held: the held JWT may be live again if a provision on this replica
// re-signed it after an earlier lockout (syncTenantSprouts holds it
// outside tenantAuthMu). It needs no tenant key, only the operator
// signing key: it starts from the newest of the held and the accounts
// bucket's Account JWT for row.AccountPub or, when there is none (or the
// bucket can't be read: a lock-out revokes everything whatever it starts
// from), from minimal claims for row.AccountPub. So a tenant whose
// Transit keys were retired can still be locked out again. The caller
// must hold tenantAuthMu, must already have seen the tenant's row marked
// deleted, and must have checked that row.AccountPub is set.
func signLockedOutTenantJWT(mat *natsAuthMaterial, row *tenantRow) (string, error) {
	tenantID := row.ID
	if row.AccountPub == "" {
		return "", fmt.Errorf("pki: tenant %q has no recorded Account public key to lock out", tenantID)
	}
	var ac *jwt.AccountClaims
	base, _, err := latestAccountJWT(context.Background(), row.AccountPub, func(*jwt.AccountClaims) bool { return true })
	if err != nil {
		log.Warnf("locking out tenant %q: %v; signing the lock-out from minimal claims", tenantID, err)
	}
	if base != "" {
		ac, _ = jwt.DecodeAccountClaims(base)
	}
	if ac == nil {
		ac = jwt.NewAccountClaims(row.AccountPub)
		ac.Name = row.Name
	}
	waitPastIssuedAt(ac.IssuedAt)
	lockOutAccount(ac, time.Now())
	signed, err := ac.Encode(mat.operatorSigningKP)
	if err != nil {
		return "", fmt.Errorf("pki: re-signing tenant %q's Account JWT locked out: %w", tenantID, err)
	}
	if err := holdAccountJWT(signed, false); err != nil {
		return "", err
	}
	return signed, nil
}

// relockIfDeletedLocked takes tenantAuthMu, reads tenantID's row from the
// database (the source of truth shared by every replica; tenantAuthMu
// only orders this process), and, if the row is deleted, re-signs the
// locked-out JWT. deleted is false, with no JWT, for a live tenant.
func relockIfDeletedLocked(mat *natsAuthMaterial, tenantID string) (signedJWT string, deleted bool, err error) {
	tenantAuthMu.Lock()
	defer tenantAuthMu.Unlock()

	row, err := getTenantRow(tenantID)
	if err != nil {
		return "", false, err
	}
	if !row.Deleted {
		return "", false, nil
	}
	signed, err := signLockedOutTenantJWT(mat, row)
	if err != nil {
		return "", true, err
	}
	return signed, true, nil
}

// pushLiveTenantAccount pushes a live (not locked-out) Account JWT for
// tenantID, the push ProvisionTenant and ReloadNKeysForTenant make, and
// then closes the race with a concurrent DeprovisionTenant, possibly on
// another replica (PKI.1).
//
// Both callers checked that the tenant wasn't deleted before building the
// JWT, but under tenantAuthMu, which is local to this process: a
// deprovision on another replica can mark the row deleted and push its
// lockout between that check and this push, and this push would then
// replace the lockout on the bus with the live JWT. So once the push has
// returned, this re-reads the row from the database, and if it is now
// deleted, signs a fresh lockout, pushes it, and returns an error
// wrapping ErrTenantDeprovisioned.
//
// The ordering this gives, across replicas: the bus applies a claims
// update before it answers it, and applies updates in the order they
// arrive, whatever their iat (nats-server's full resolver stores a pushed
// JWT unconditionally; TestResolverPush_LastArrivalWins pins that). The
// re-check is a database read that starts after the bus has answered this
// push. Either it sees the row deleted, and this pushes a lockout after
// its live JWT; or it doesn't, so the deprovision marked the row after
// this read, and pushes its lockout after that (deprovisionTenantLocked),
// so after this push was applied. Either way the last push the bus applies
// for a deleted tenant is a lockout, with no assumption about clocks. It
// relies on the re-check seeing a deprovision's committed write: one
// database, or PXC read and written through one node (the HAProxy
// Service), or wsrep_sync_wait. Where the resolver orders copies by iat
// instead (re-seeding from the accounts bucket at bus start, a future bus cluster), the
// lockout also has to carry the later iat, which holds when replica clocks
// agree to within the time between the two signings.
//
// The re-check runs even when the push failed: a request that timed out
// may still have been applied. If the re-check itself can't read the
// database, the error is returned and the bus state is unknown; a retried
// DeprovisionTenant repairs it.
func pushLiveTenantAccount(mat *natsAuthMaterial, tenantID, accountJWT string) error {
	if testHookBeforeLivePush != nil {
		testHookBeforeLivePush(tenantID)
	}
	pushErr := pushAccountUpdate(mat, accountJWT)
	if testHookAfterLivePush != nil {
		testHookAfterLivePush(tenantID)
	}
	signed, deleted, err := relockIfDeletedLocked(mat, tenantID)
	if err != nil {
		return fmt.Errorf("pki: re-checking tenant %q after pushing its Account JWT (bus state unconfirmed): %w", tenantID, errors.Join(err, pushErr))
	}
	if !deleted {
		return pushErr
	}
	log.Warnf("tenant %q was deprovisioned while its live Account JWT was being pushed; pushing the locked-out JWT again", tenantID)
	if err := pushAccountUpdate(mat, signed); err != nil {
		return fmt.Errorf("pki: re-pushing tenant %q's locked-out Account JWT: %w", tenantID, err)
	}
	if tenantDeprovisionedHook != nil {
		go tenantDeprovisionedHook(tenantID)
	}
	return fmt.Errorf("pki: tenant %q was deprovisioned during provisioning; its locked-out Account JWT was pushed again: %w", tenantID, ErrTenantDeprovisioned)
}

// Test hooks for the provision/deprovision interleaving tests
// (tenant_race_test.go). Always nil in production.
var (
	// testHookBeforeLivePush runs in pushLiveTenantAccount after the
	// caller's deleted check and before the live push.
	testHookBeforeLivePush func(tenantID string)
	// testHookAfterLivePush runs after the live push and before the
	// database re-check.
	testHookAfterLivePush func(tenantID string)
	// testHookProvisionAfterLookup and testHookDeprovisionAfterLookup run
	// under tenantAuthMu right after each path's first pki_tenants read,
	// standing in for another replica writing the row in between.
	testHookProvisionAfterLookup   func(tenantID string)
	testHookDeprovisionAfterLookup func(tenantID string)
	// testHookDeprovisionBeforePush runs in DeprovisionTenant after the
	// row is marked deleted and the lockout signed, before it is pushed.
	testHookDeprovisionBeforePush func(tenantID string)
)

// lockOutAccount edits ac so that, once pushed, the bus closes every
// connection under the Account and accepts no new ones:
//
//   - Every User JWT issued up to now is revoked (jwt.All). The server
//     closes live connections that use a revoked JWT when it applies the
//     update, and rejects them at connect time afterwards.
//   - The connection limits drop to 0, which also kicks any remaining
//     client and refuses connections with a User JWT minted after now,
//     which the revocation alone wouldn't cover.
//
// It deliberately does not set Expires, which is what deprovisioning used
// to do (Expires = now). A running nats-server validates an update to an
// Account it already has loaded with time checks included, and rejects a
// claim whose exp is already in the past. So a push that reached the bus
// even one second after signing was dropped, and the tenant's old,
// unlocked claims stayed live. Revocations and limits have no such time
// check, so a late push still takes effect.
func lockOutAccount(ac *jwt.AccountClaims, now time.Time) {
	ac.Expires = 0
	ac.RevokeAt(jwt.All, now)
	ac.Limits.Conn = 0
	ac.Limits.LeafNodeConn = 0
}

// waitPastIssuedAt sleeps, at most about a second, until the wall clock is
// in a later second than prevIssuedAt, so the JWT signed next gets a
// strictly newer iat than the one it replaces.
//
// The bus resolver syncs Account JWTs between nodes by "newest iat wins",
// and treats two JWTs with the same jti as the same JWT. jwt/v2 derives
// the jti from the generic claims only (subject, issuer, name, iat), not
// from limits or revocations, so a lock-out signed in the same second as
// the live JWT before it has the same jti, and a cluster node holding the
// live one would never take the lock-out from its peers (see
// cmd/farmerbus/fence.go).
func waitPastIssuedAt(prevIssuedAt int64) {
	if d := time.Until(time.Unix(prevIssuedAt+1, 0)); d > 0 {
		time.Sleep(d)
	}
}

// syncTenantSprouts is syncNatsAuth (jwtusers.go) parameterized by an
// explicit tenant instead of the package's current-tenant seam — it
// rebuilds tenantID's Account revocation list and mints/reuses User JWTs
// for that tenant's own accepted/unaccepted/denied/rejected sprouts (each
// already tenant-scoped at the nkeyRow level — see store.go), re-signing
// the Account JWT, and holding it, only if its revocation list changed. It
// starts from the newest of the held and the accounts bucket's Account
// JWT (resignBase), so it builds on what another replica signed. It mints
// no User JWT: a sprout's is minted where it is served
// (MintOrReuseUserJWT), the farmer's own on first use
// (FarmerUserJWTForTenant).
func syncTenantSprouts(mat *natsAuthMaterial, tam *tenantAccountMaterial, tenantID string) (bool, error) {
	ac, raw, minted, err := resignBase(context.Background(), tam.pub, tam.jwt, tam.minted, signsWith(tam.signingPub))
	if err != nil {
		return false, err
	}
	tam.jwt, tam.minted = raw, minted

	changed := false

	// Farmer's own key stays unrevoked on this tenant's Account: it is
	// farmer's connection identity for the per-tenant NATS connection (see
	// FarmerUserJWTForTenant and docs/design/imas-tenant-context-threading.md).
	farmerKey, err := GetPubNKey(FarmerPubNKey)
	if err != nil {
		return false, fmt.Errorf("pki: loading farmer's NKey: %w", err)
	}
	if ensureUserGranted(ac, farmerKey) {
		changed = true
	}

	// See syncNatsAuth: read before granting, and fail closed.
	revoked, err := revokedNKeys(tenantID)
	if err != nil {
		return false, err
	}

	for _, s := range getNKeysByTypeForTenant(tenantID, "accepted").Sprouts {
		row, errGet := findNKeyRowInTenant(tenantID, s.SproutID)
		if errGet != nil {
			log.Errorf("failed to get NKey for sprout %s in tenant %s: %v", s.SproutID, tenantID, errGet)
			continue
		}
		if _, isRevoked := revoked[row.NKey]; isRevoked {
			log.Errorf("sprout %s in tenant %s is accepted with a revoked NKey; keeping it revoked", s.SproutID, tenantID)
			continue
		}
		if ensureUserGranted(ac, row.NKey) {
			changed = true
		}
	}

	for _, state := range []string{"unaccepted", "denied", "rejected"} {
		for _, s := range getNKeysByTypeForTenant(tenantID, state).Sprouts {
			row, errGet := findNKeyRowInTenant(tenantID, s.SproutID)
			if errGet != nil {
				log.Errorf("failed to get NKey for sprout %s in tenant %s: %v", s.SproutID, tenantID, errGet)
				continue
			}
			if ensureUserRevoked(ac, row.NKey) {
				changed = true
			}
		}
	}
	if applyRevokedNKeys(ac, revoked) {
		changed = true
	}

	if changed {
		// Strictly newer iat, as in syncNatsAuth.
		if !tam.minted {
			waitPastIssuedAt(ac.IssuedAt)
		}
		signed, encErr := ac.Encode(mat.operatorSigningKP)
		if encErr != nil {
			return false, encErr
		}
		if holdErr := holdAccountJWT(signed, false); holdErr != nil {
			return false, holdErr
		}
		tam.jwt = signed
		tam.minted = false
	} else {
		// Unchanged: hold the JWT it started from (the bucket's, or a
		// minimal mint that already is the tenant's state) as synced.
		if holdErr := holdAccountJWT(tam.jwt, false); holdErr != nil {
			return false, holdErr
		}
	}
	return changed, nil
}

// ReloadNKeysForTenant is ReloadNKeys (nats.go) scoped to a single explicit
// tenant instead of the package's current-tenant seam: it lazily
// provisions tenantID's Account if this is the first time it's been seen
// (see ensureTenantAccount) — this is what lets a sprout enrolling under a
// brand-new tenant get a working Account even before/without the explicit
// internal.tenant.provision round trip from internal/saasapi having run —
// then syncs that tenant's sprout state onto its Account JWT and pushes if
// anything changed. Called by enroll.go for every enrollment, keyed by the
// enrollment key's own tenant, not config.FarmerOrganization.
func ReloadNKeysForTenant(tenantID string) error {
	mat, tam, provisioned, err := ensureTenantAccount(tenantID, "", false)
	if err != nil {
		log.Errorf("failed to bootstrap NATS auth material for tenant %s: %v", tenantID, err)
		return err
	}
	changed, err := syncTenantSprouts(mat, tam, tenantID)
	if err != nil {
		log.Errorf("failed to sync tenant %s's Account JWT: %v", tenantID, err)
		return err
	}
	if !provisioned && !changed {
		return nil
	}
	if err := pushLiveTenantAccount(mat, tenantID, tam.jwt); err != nil {
		log.Errorf("failed to push tenant %s's updated Account JWT to the bus resolver: %v", tenantID, err)
		return err
	}
	log.Tracef("Pushed tenant %s's updated Account JWT to the bus resolver.", tenantID)
	return nil
}

// ResyncProvisionedTenants runs ReloadNKeysForTenant for every provisioned
// tenant other than the legacy one, which ReloadNKeys covers. Farmer calls
// it once at startup, before it connects each tenant to the bus, so each
// tenant's Account JWT carries its current revocations from PXC and the
// replica holds it. A sprout's User JWT with a permission added in a
// newer release (for example the heartbeat publish grant) is re-minted
// where it is served (MintOrReuseUserJWT compares the permissions), not
// here. A failure for one tenant is logged by ReloadNKeysForTenant and
// does not stop the others; the errors are returned joined.
func ResyncProvisionedTenants() error {
	ids, err := ListProvisionedTenantIDs()
	if err != nil {
		return err
	}
	legacy := CurrentTenantID()
	var errs []error
	for _, id := range ids {
		if id == legacy {
			continue
		}
		if err := ReloadNKeysForTenant(id); err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", id, err))
		}
	}
	return errors.Join(errs...)
}

// hasOwnTenantAccount reports whether tenantID has an Account of its own
// recorded on its pki_tenants row (ensureTenantAccountLocked records it).
// The legacy current tenant usually has none: its sprouts are under the
// legacy Account (ensureNatsAuth).
func hasOwnTenantAccount(tenantID string) bool {
	row, err := getTenantRow(tenantID)
	return err == nil && row.AccountPub != ""
}

// FarmerUserJWTForTenant is FarmerUserJWT (jwtusers.go) scoped to an
// explicit tenant — farmer's own connection identity for the dedicated
// per-tenant NATS connection cmd/farmer/main.go's ConnectFarmer opens (see
// docs/design/imas-tenant-context-threading.md's Option A). It is signed
// with the tenant's signing key on first use and held in memory
// (farmerUserJWT), so any replica can connect any provisioned tenant
// without anything another process wrote. The legacy current tenant gets
// FarmerUserJWT, under the legacy Account.
func FarmerUserJWTForTenant(tenantID string) (string, error) {
	if !IsValidTenantID(tenantID) {
		return "", ErrTenantIDInvalid
	}
	if tenantID == currentTenantID() {
		return FarmerUserJWT()
	}
	tam, err := loadTenantAccountMaterial(tenantID)
	if err != nil {
		return "", err
	}
	return farmerUserJWT(tam.pub, tam.signingKP)
}
