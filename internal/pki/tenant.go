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
	switch {
	case lookupErr == nil && row.Deleted:
		return nil, false, fmt.Errorf("pki: tenant %q was deprovisioned; call ProvisionTenant explicitly to re-provision it", tenantID)
	case lookupErr == nil:
		nameHint = row.Name
	case !errors.Is(lookupErr, ErrTenantNotFound):
		// A real lookup failure, not an absent row: don't fall through to
		// upsertTenantRow, whose upsert would also reset Deleted and so
		// silently un-delete a deprovisioned tenant.
		return nil, false, lookupErr
	default:
		name := nameHint
		if name == "" {
			name = tenantID
		}
		if err := upsertTenantRow(tenantRow{ID: tenantID, Name: name, CreatedAt: time.Now().Unix()}); err != nil {
			return nil, false, fmt.Errorf("pki: recording tenant %q: %w", tenantID, err)
		}
		nameHint = name
		provisioned = true
	}

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
	if err := pushAccountUpdate(mat, tam.jwt); err != nil {
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
// delete on-disk key material or sprout state — only ProvisionTenant
// re-establishing trust can bring a deprovisioned tenant back,
// deliberately (see ensureTenantAccount).
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
	if alreadyDeleted {
		return nil
	}
	if err := pushAccountUpdate(mat, signedJWT); err != nil {
		log.Errorf("failed to push tenant %q's locked-out Account JWT to the bus resolver: %v", tenantID, err)
		return err
	}
	log.Infof("Deprovisioned tenant %q: locked-out Account JWT pushed to the bus resolver.", tenantID)
	// See OnTenantDeprovisioned's doc comment: lets cmd/farmer/main.go close
	// this tenant's NATS connection and unregister its handlers.
	if tenantDeprovisionedHook != nil {
		go tenantDeprovisionedHook(tenantID)
	}
	return nil
}

// deprovisionTenantLocked is DeprovisionTenant's tenantAuthMu-guarded body:
// it marks tenantID deleted and re-signs its Account JWT locked out (see
// lockOutAccount), but leaves the actual bus push to the caller (network
// I/O shouldn't happen while holding this lock).
func deprovisionTenantLocked(mat *natsAuthMaterial, tenantID string) (signedJWT string, alreadyDeleted bool, err error) {
	tenantAuthMu.Lock()
	defer tenantAuthMu.Unlock()

	row, err := getTenantRow(tenantID)
	if err != nil {
		return "", false, err
	}
	if row.Deleted {
		return "", true, nil
	}
	tam, _, err := ensureTenantAccountMaterial(mat, tenantID, row.Name)
	if err != nil {
		return "", false, err
	}
	ac, err := jwt.DecodeAccountClaims(tam.jwt)
	if err != nil {
		return "", false, fmt.Errorf("pki: decoding tenant %q's Account JWT: %w", tenantID, err)
	}
	lockOutAccount(ac, time.Now())
	signed, err := ac.Encode(mat.operatorSigningKP)
	if err != nil {
		return "", false, fmt.Errorf("pki: re-signing tenant %q's Account JWT locked out: %w", tenantID, err)
	}
	if err := os.WriteFile(tenantAccountJWTPath(tenantID), []byte(signed), 0o600); err != nil {
		return "", false, err
	}
	if err := markTenantDeleted(tenantID); err != nil {
		return "", false, err
	}
	return signed, false, nil
}

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
	if err := pushAccountUpdate(mat, tam.jwt); err != nil {
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
