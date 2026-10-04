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
// Account JWT, and its own namespace of sprout/user JWTs on disk
// (tenantAuthDir) — structurally separate from every other tenant's, the
// same "isolation enforced by which Account a connection authenticated
// into" property the design doc describes for the legacy single-tenant
// seam. The operator (and its delegated signing key) remain shared across
// every tenant by design — that's the trust anchor the whole chain rests
// on, not a tenant boundary itself; see jwtauth.go's own security-review
// note on operator key custody, which applies identically here.
import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	log "github.com/yogzblr/imas/internal/log"
)

var tenantIDMatcher = regexp.MustCompile(`^[0-9A-Za-z_-]{1,191}$`)

// IsValidTenantID reports whether id is safe to use both as a PXC primary
// key and as a path component under natsAuthDir (tenantAuthDir joins it
// directly into a filesystem path, so this also guards against path
// traversal via a malicious/malformed tenant ID).
func IsValidTenantID(id string) bool {
	return tenantIDMatcher.MatchString(id)
}

// tenantAccountMaterial is one tenant's NATS Account trust material:
// its own Account keypair, a delegated signing key (so the Account's own
// root key need not be online at runtime, mirroring the
// operator/operator-signing split in jwtauth.go), and the current signed
// Account JWT.
type tenantAccountMaterial struct {
	kp        nkeys.KeyPair
	signingKP nkeys.KeyPair
	pub       string
	jwt       string
}

func tenantsRootDir() string {
	return filepath.Join(natsAuthDir(), "tenants")
}

// tenantAuthDir is where a specific tenant's Account keys, Account JWT,
// and every sprout/cli/farmer User JWT minted under that Account live —
// the re-keyed-by-tenant counterpart to jwtauth.go's flat, single-tenant
// natsAuthDir/sproutJWTDir. id must already be validated (IsValidTenantID)
// by every exported entry point below before reaching here.
func tenantAuthDir(id string) string {
	return filepath.Join(tenantsRootDir(), id)
}

func tenantAccountKeyPath(id string) string { return filepath.Join(tenantAuthDir(id), "account.nk") }
func tenantAccountSigningKeyPath(id string) string {
	return filepath.Join(tenantAuthDir(id), "account-signing.nk")
}
func tenantAccountJWTPath(id string) string { return filepath.Join(tenantAuthDir(id), "account.jwt") }
func tenantSproutJWTDir(id string) string   { return filepath.Join(tenantAuthDir(id), "sprouts") }

// farmerUserJWTPathForTenant is farmerUserJWTPath (jwtauth.go) re-keyed by
// tenant — farmer's own connection identity under tenantID's Account, one
// per dynamically-provisioned tenant, the counterpart to
// sproutJWTPathForTenant above. See FarmerUserJWTForTenant and
// docs/design/imas-tenant-context-threading.md's Option A: farmer opens one
// NATS connection per tenant, each authenticated with its own User JWT
// minted under that tenant's own Account (same underlying farmer NKey
// identity, reused across every tenant — see mintOrReuseUserJWT's doc
// comment on why one NKey can hold distinct User JWTs under many Accounts
// simultaneously).
func farmerUserJWTPathForTenant(id string) string {
	return filepath.Join(tenantAuthDir(id), "farmer.jwt")
}

// sproutJWTPathForTenant is sproutJWTPath (jwtauth.go) re-keyed by tenant —
// see this file's package doc comment. Two different tenants may each have
// a sprout named "web-01"; each gets its own file under its own tenant's
// directory, rather than colliding on config.FarmerPKI/sprouts/jwt/web-01.jwt
// the way the legacy single-tenant path still does (deliberately — see
// jwtauth.go, that path is unchanged).
func sproutJWTPathForTenant(tenantID, sproutID string) string {
	return filepath.Join(tenantSproutJWTDir(tenantID), sproutID+".jwt")
}

// externalSeedNameForTenant derives an env-var-safe name for
// loadOrCreateSeed's external-seed override (loadExternalSeed in
// jwtauth.go), following the same IMAS_NATS_<NAME>_SEED[_FILE] convention
// the fixed platform-wide identities use — e.g. tenant ID "t_8f2a" maps to
// IMAS_NATS_TENANT_T_8F2A_SEED_FILE. Not expected to be set for most
// tenants today (this is groundwork for OpenBao/per-tenant secret custody,
// workstream F), but keeps the override mechanism available uniformly
// rather than only for the handful of fixed identities jwtauth.go names
// directly.
func externalSeedNameForTenant(tenantID string) string {
	return "TENANT_" + strings.ToUpper(strings.ReplaceAll(tenantID, "-", "_"))
}

// tenantAuthMu guards concurrent bootstrap/persistence of any tenant's
// Account material below (a pki_tenants row plus its on-disk Account
// keys/JWT) — the tenant-scoped counterpart to jwtauth.go's authMu, which
// guards only the legacy single "current tenant"'s material and the
// platform-wide operator/SYS material. Deliberately a separate lock rather
// than reusing authMu: every entry point below (ensureTenantAccountLocked,
// used by ProvisionTenant/ReloadNKeysForTenant/loadTenantAccountMaterial/
// DeprovisionTenant) first calls ensureNatsAuth(), which takes authMu
// itself — holding authMu across that call here would deadlock, since
// Go's sync.Mutex isn't reentrant.
var tenantAuthMu sync.Mutex

// ensureTenantAccountMaterial loads tenantID's Account keys/JWT from disk,
// minting and persisting whatever's missing — idempotent, but relies on the
// caller already holding tenantAuthMu (every call site in this file does,
// via ensureTenantAccountLocked or loadTenantAccountMaterial) for safety
// under concurrent calls for the same tenant.
func ensureTenantAccountMaterial(mat *natsAuthMaterial, tenantID, name string) (*tenantAccountMaterial, bool, error) {
	if err := os.MkdirAll(tenantAuthDir(tenantID), 0o700); err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(tenantSproutJWTDir(tenantID), 0o700); err != nil {
		return nil, false, err
	}

	tam := &tenantAccountMaterial{}
	seedName := externalSeedNameForTenant(tenantID)

	var err error
	tam.kp, err = loadOrCreateSeed(tenantAccountKeyPath(tenantID), seedName, nkeys.CreateAccount)
	if err != nil {
		return nil, false, err
	}
	tam.pub, err = tam.kp.PublicKey()
	if err != nil {
		return nil, false, err
	}
	tam.signingKP, err = loadOrCreateSeed(tenantAccountSigningKeyPath(tenantID), seedName+"_SIGNING", nkeys.CreateAccount)
	if err != nil {
		return nil, false, err
	}
	signingPub, err := tam.signingKP.PublicKey()
	if err != nil {
		return nil, false, err
	}

	minted := false
	needJWT := true
	if b, rerr := os.ReadFile(tenantAccountJWTPath(tenantID)); rerr == nil {
		if ac, derr := jwt.DecodeAccountClaims(string(b)); derr == nil &&
			ac.Subject == tam.pub && ac.SigningKeys.Contains(signingPub) {
			tam.jwt = string(b)
			needJWT = false
		}
	}
	if needJWT {
		ac := jwt.NewAccountClaims(tam.pub)
		ac.Name = name
		ac.SigningKeys.Add(signingPub)
		signed, encErr := ac.Encode(mat.operatorSigningKP)
		if encErr != nil {
			return nil, false, encErr
		}
		if werr := os.WriteFile(tenantAccountJWTPath(tenantID), []byte(signed), 0o600); werr != nil {
			return nil, false, werr
		}
		tam.jwt = signed
		minted = true
	}

	return tam, minted, nil
}

// loadTenantAccountMaterial loads a tenant's Account material without
// creating a new pki_tenants row — used where the caller expects the
// tenant to already be provisioned (ConfigureNats' resolver-seeding loop)
// and a missing tenant should surface as an error rather than silently
// registering one. It does still fill in any missing key/JWT *file* for an
// already-registered tenant, the same as ensureTenantAccountLocked, since a
// partially-written tenant directory (e.g. a prior crash mid-provision)
// should self-heal rather than wedge the resolver.
func loadTenantAccountMaterial(tenantID string) (*tenantAccountMaterial, error) {
	mat, err := ensureNatsAuth()
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(tenantAccountJWTPath(tenantID)); err != nil {
		return nil, fmt.Errorf("pki: no Account material found for tenant %q: %w", tenantID, err)
	}
	tenantAuthMu.Lock()
	defer tenantAuthMu.Unlock()
	tam, _, err := ensureTenantAccountMaterial(mat, tenantID, tenantID)
	return tam, err
}

// ensureTenantAccount is the shared bootstrap path for ProvisionTenant and
// ReloadNKeysForTenant: it ensures a pki_tenants row exists for tenantID
// (creating one, named nameHint, if this is the first time this tenant has
// ever been provisioned) and that its Account material exists on disk.
// provisioned reports whether either the tenant row or the Account
// material was newly created by this call — callers use it to decide
// whether a resolver push is required even if syncing sprouts found
// nothing to change.
func ensureTenantAccount(tenantID, nameHint string) (mat *natsAuthMaterial, tam *tenantAccountMaterial, provisioned bool, err error) {
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
	tam, provisioned, err = ensureTenantAccountLocked(mat, tenantID, nameHint)
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
func ensureTenantAccountLocked(mat *natsAuthMaterial, tenantID, nameHint string) (tam *tenantAccountMaterial, provisioned bool, err error) {
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

	tam, minted, err := ensureTenantAccountMaterial(mat, tenantID, nameHint)
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
	mat, tam, _, err := ensureTenantAccount(tenantID, name)
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
// connections and refuses new ones, effective immediately. It does not
// delete on-disk key material or sprout state.
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
// reconciles copies (re-seeding from disk at bus start, a future bus
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
	// don't mint keys just to lock them out. Every push follows
	// setTenantAccountPub, and a provision still in flight sees the row
	// deleted when it re-checks after its push.
	if row.AccountPub == "" {
		if _, statErr := os.Stat(tenantAccountJWTPath(tenantID)); os.IsNotExist(statErr) {
			return "", row.Deleted, ErrTenantNotFound
		}
	}
	signed, err := signLockedOutTenantJWT(mat, tenantID, row.Name)
	if err != nil {
		return "", false, err
	}
	return signed, row.Deleted, nil
}

// signLockedOutTenantJWT re-signs tenantID's Account JWT locked out (see
// lockOutAccount) as of now and persists it to disk, replacing whatever is
// there: the on-disk JWT may be live again if a provision on this replica
// re-signed it after an earlier lockout (syncTenantSprouts writes it
// outside tenantAuthMu). The caller must hold tenantAuthMu and must
// already have seen the tenant's row marked deleted.
func signLockedOutTenantJWT(mat *natsAuthMaterial, tenantID, name string) (string, error) {
	tam, _, err := ensureTenantAccountMaterial(mat, tenantID, name)
	if err != nil {
		return "", err
	}
	ac, err := jwt.DecodeAccountClaims(tam.jwt)
	if err != nil {
		return "", fmt.Errorf("pki: decoding tenant %q's Account JWT: %w", tenantID, err)
	}
	lockOutAccount(ac, time.Now())
	signed, err := ac.Encode(mat.operatorSigningKP)
	if err != nil {
		return "", fmt.Errorf("pki: re-signing tenant %q's Account JWT locked out: %w", tenantID, err)
	}
	if err := os.WriteFile(tenantAccountJWTPath(tenantID), []byte(signed), 0o600); err != nil {
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
	signed, err := signLockedOutTenantJWT(mat, tenantID, row.Name)
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
// instead (re-seeding from disk at bus start, a future bus cluster), the
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

// syncTenantSprouts is syncNatsAuth (jwtusers.go) parameterized by an
// explicit tenant instead of the package's current-tenant seam — it
// rebuilds tenantID's Account revocation list and mints/reuses User JWTs
// for that tenant's own accepted/unaccepted/denied/rejected sprouts (each
// already tenant-scoped at the nkeyRow level — see store.go), re-signing
// and persisting the Account JWT only if its revocation list changed.
func syncTenantSprouts(mat *natsAuthMaterial, tam *tenantAccountMaterial, tenantID string) (bool, error) {
	ac, err := jwt.DecodeAccountClaims(tam.jwt)
	if err != nil {
		return false, err
	}

	changed := false

	// Mint/refresh farmer's own User JWT under this tenant's Account —
	// jwtusers.go's syncNatsAuth does the same for the legacy Account.
	// This is farmer's connection identity for the dedicated per-tenant
	// NATS connection cmd/farmer/main.go's ConnectFarmer opens (see
	// FarmerUserJWTForTenant and docs/design/imas-tenant-context-threading.md).
	farmerKey, err := GetPubNKey(FarmerPubNKey)
	if err != nil {
		return false, fmt.Errorf("pki: loading farmer's NKey: %w", err)
	}
	if ensureUserGranted(ac, farmerKey) {
		changed = true
	}
	if _, mintErr := mintOrReuseUserJWT(farmerUserJWTPathForTenant(tenantID), farmerKey, "farmer", allowAllPermissions(), tam.pub, tam.signingKP); mintErr != nil {
		log.Errorf("failed to mint farmer User JWT for tenant %s: %v", tenantID, mintErr)
	}

	for _, s := range getNKeysByTypeForTenant(tenantID, "accepted").Sprouts {
		row, errGet := findNKeyRowInTenant(tenantID, s.SproutID)
		if errGet != nil {
			log.Errorf("failed to get NKey for sprout %s in tenant %s: %v", s.SproutID, tenantID, errGet)
			continue
		}
		if ensureUserGranted(ac, row.NKey) {
			changed = true
		}
		path := sproutJWTPathForTenant(tenantID, s.SproutID)
		if _, mintErr := mintOrReuseUserJWT(path, row.NKey, s.SproutID, sproutPermissions(s.SproutID), tam.pub, tam.signingKP); mintErr != nil {
			log.Errorf("failed to mint User JWT for sprout %s in tenant %s: %v", s.SproutID, tenantID, mintErr)
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

	if changed {
		signed, encErr := ac.Encode(mat.operatorSigningKP)
		if encErr != nil {
			return false, encErr
		}
		if writeErr := os.WriteFile(tenantAccountJWTPath(tenantID), []byte(signed), 0o600); writeErr != nil {
			return false, writeErr
		}
		tam.jwt = signed
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
	mat, tam, provisioned, err := ensureTenantAccount(tenantID, "")
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

// tenantIDsProvisionedOnDisk lists every tenant ID with Account material on
// disk under tenantsRootDir, by directory name. Used by ConfigureNats
// (nats.go) to seed the bus resolver with every provisioned tenant's
// Account — deliberately a filesystem scan rather than a query against the
// pki_tenants PXC table (see store.go's tenantRow): ConfigureNats runs in
// both cmd/farmer (core, has a PXC connection) and cmd/farmerbus (the DMZ-side
// bus process, which by design never calls pki.SetDB — see
// cmd/farmerbus/main.go's RunNATSServer doc comment on why that process
// has no business holding a database connection). A PXC-backed lookup here
// would nil-panic on the bus binary; this only touches config.FarmerPKI,
// which both binaries already read from for the platform-wide operator/SYS
// material.
func tenantIDsProvisionedOnDisk() ([]string, error) {
	entries, err := os.ReadDir(tenantsRootDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		if !e.IsDir() || !IsValidTenantID(e.Name()) {
			continue
		}
		if _, err := os.Stat(tenantAccountJWTPath(e.Name())); err != nil {
			continue
		}
		ids = append(ids, e.Name())
	}
	return ids, nil
}

// GetSproutUserJWTForTenant is GetSproutUserJWT (jwtusers.go) scoped to an
// explicit tenant — see this file's package doc comment. Falls back to the
// legacy flat, single-tenant path (jwtusers.go's sproutJWTPath) when
// tenantID is the package's current-tenant seam (tenantID()) and no
// tenant-scoped file exists yet: a sprout accepted via the legacy
// AcceptNKey/ReloadNKeys admin path (every Accept/Deny/Reject/Unaccept
// call still uses it, not just Enroll) mints its User JWT there, not under
// this tenant's own directory. Without this fallback, Enroll's idempotency
// replay (the only caller today) would wrongly report "accepted but no
// readable JWT" for any sprout that was only ever admin-accepted, never
// enrolled through Enroll itself.
func GetSproutUserJWTForTenant(tenantID, sproutID string) (string, error) {
	if !IsValidTenantID(tenantID) {
		return "", ErrTenantIDInvalid
	}
	if !IsValidSproutID(sproutID) {
		return "", ErrSproutIDInvalid
	}
	b, err := os.ReadFile(sproutJWTPathForTenant(tenantID, sproutID))
	if err == nil {
		return string(b), nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	if tenantID == currentTenantID() {
		if legacy, legacyErr := os.ReadFile(sproutJWTPath(sproutID)); legacyErr == nil {
			return string(legacy), nil
		}
	}
	return "", ErrSproutIDNotFound
}

// FarmerUserJWTForTenant is FarmerUserJWT (jwtusers.go) scoped to an
// explicit tenant — farmer's own connection identity for the dedicated
// per-tenant NATS connection cmd/farmer/main.go's ConnectFarmer opens (see
// docs/design/imas-tenant-context-threading.md's Option A). Minted by
// syncTenantSprouts (via ReloadNKeysForTenant or ProvisionTenant, both of
// which call it) into farmerUserJWTPathForTenant. Falls back to the legacy
// flat single-tenant path (FarmerUserJWT) when tenantID is the package's
// current-tenant seam, mirroring GetSproutUserJWTForTenant's fallback for
// the same reason: the legacy tenant's farmer JWT is minted by syncNatsAuth
// into farmerUserJWTPath, not under tenants/<id>/.
func FarmerUserJWTForTenant(tenantID string) (string, error) {
	if !IsValidTenantID(tenantID) {
		return "", ErrTenantIDInvalid
	}
	if tenantID == currentTenantID() {
		return FarmerUserJWT()
	}
	b, err := os.ReadFile(farmerUserJWTPathForTenant(tenantID))
	if err != nil {
		return "", err
	}
	return string(b), nil
}
