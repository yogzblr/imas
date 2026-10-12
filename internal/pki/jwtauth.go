package pki

// Decentralized NATS JWT auth bootstrap: Operator -> SYSTEM account ->
// tenant Account. See docs/design/imas-nats-jwt-auth-design.md.
//
// FLAG FOR SECURITY REVIEW: the trust chain's private keys (operator,
// operator signing, SYS account, tenant account and signing) live only in
// OpenBao Transit (natskeysource.go, internal/pki/natskeys); the farmer
// signs through it and never holds them. The public trust (operator JWT,
// SYS account JWT, public keys) is written once by the bootstrap Job and
// read here from the trust directory (natstrust.go). The only seeds left
// are user-kind keys: SYS_USER (required, from a Secret) and SAASAPI_USER.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/config"
	log "github.com/yogzblr/imas/internal/log"
)

const natsAuthSubdir = "nats-auth"

// natsAuthMaterial holds the loaded/generated decentralized-JWT trust chain
// for this farmer: the Operator (root trust anchor, plus a delegated
// signing key used for day-to-day Account issuance), the SYSTEM account
// (used only to push claims updates to the bus's resolver) and the single
// tenant Account that sprouts, the farmer, and imas CLI admins belong to.
//
// Multi-tenancy (workstream E) generalizes tenantPub/tenantJWT into one
// Account per tenant; this struct intentionally holds just one for now.
type natsAuthMaterial struct {
	operatorSigningKP nkeys.KeyPair
	operatorPub       string
	operatorJWT       string

	sysAccountKP  nkeys.KeyPair
	sysAccountPub string
	sysAccountJWT string

	sysUserKP   nkeys.KeyPair
	sysUserPub  string
	sysUserJWT  string
	sysUserSeed []byte

	tenantSigningKP nkeys.KeyPair
	tenantPub       string
	tenantJWT       string
	tenantName      string
	// tenantMinted: tenantJWT was minted by this ensureNatsAuth call and
	// not yet pushed or published, so a re-sign need not outrank its iat.
	tenantMinted bool
}

// authMu guards concurrent bootstrap/persistence of the auth material below
// (concurrent Accept/Deny/Reject calls, or a SIGHUP racing one of them).
var authMu sync.Mutex

func natsAuthDir() string {
	return filepath.Join(config.FarmerPKI, natsAuthSubdir)
}

// resolverStoreDir is the DMZ bus's resolver directory (LoadBusNats),
// on cmd/farmerbus's data emptyDir; its account loader refills it from
// the accounts bucket at every start. The in-process test bus uses a
// directory of its own (newTempDirResolver).
func resolverStoreDir() string {
	return filepath.Join(natsAuthDir(), "resolver")
}

func sproutJWTDir() string {
	return filepath.Join(config.FarmerPKI, "sprouts", "jwt")
}

func tenantJWTPath() string {
	return filepath.Join(natsAuthDir(), "tenant.jwt")
}

func farmerUserJWTPath() string {
	return filepath.Join(natsAuthDir(), "users", "farmer.jwt")
}

func cliUserJWTPath(pubkey string) string {
	return filepath.Join(natsAuthDir(), "users", "cli-"+pubkey+".jwt")
}

func sproutJWTPath(id string) string {
	return filepath.Join(sproutJWTDir(), id+".jwt")
}

// ensurePlatformAuth loads the platform part of the trust chain: the
// public trust (operator JWT, operator, operator-signing and SYS account
// public keys, SYS account JWT) from the trust directory the bootstrap
// Job's ConfigMap is mounted at, and the operator-signing and SYS account
// signing pairs from Transit (read, never created), and checks the
// pairs' public keys are the trust's. It mints nothing: the bootstrap Job
// owns the operator and SYS account JWTs. The one thing it writes is the
// farmer's own copy of the SYS account JWT (sys-account.jwt), seeded from
// the trust when missing or not about the trust's SYS account; the farmer
// re-signs that copy with its revocations (saasapi_user.go). The SaaS API
// credential Job needs only this.
func ensurePlatformAuth() (*natsAuthMaterial, error) {
	authMu.Lock()
	defer authMu.Unlock()
	return ensurePlatformAuthLocked(context.Background())
}

func ensurePlatformAuthLocked(ctx context.Context) (*natsAuthMaterial, error) {
	dir := natsAuthDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, "users"), 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(sproutJWTDir(), 0o700); err != nil {
		return nil, err
	}

	trust, err := LoadNATSTrustDir(NATSTrustDir())
	if err != nil {
		return nil, err
	}
	mat := &natsAuthMaterial{
		operatorPub:   trust.OperatorPub,
		operatorJWT:   trust.OperatorJWT,
		sysAccountPub: trust.SysAccountPub,
	}
	mat.operatorSigningKP, err = natsKeys.keyPair(ctx, natsKeyRef{role: natsKeyOperatorSigning})
	if err != nil {
		return nil, err
	}
	mat.sysAccountKP, err = natsKeys.keyPair(ctx, natsKeyRef{role: natsKeySysAccount})
	if err != nil {
		return nil, err
	}
	for _, c := range []struct {
		name  string
		kp    nkeys.KeyPair
		trust string
	}{
		{TrustOperatorSigningPub, mat.operatorSigningKP, trust.OperatorSigningPub},
		{TrustSysAccountPub, mat.sysAccountKP, trust.SysAccountPub},
	} {
		pub, err := c.kp.PublicKey()
		if err != nil {
			return nil, err
		}
		if pub != c.trust {
			return nil, fmt.Errorf("%w: %s is %s, transit has %s", ErrTrustMismatch, c.name, c.trust, pub)
		}
	}

	if b, rerr := os.ReadFile(sysAccountJWTPath()); rerr == nil {
		if ac, derr := jwt.DecodeAccountClaims(string(b)); derr == nil &&
			ac.Subject == trust.SysAccountPub && ac.Issuer == trust.OperatorSigningPub {
			mat.sysAccountJWT = string(b)
		}
	}
	if mat.sysAccountJWT == "" {
		if werr := writeFileAtomic(sysAccountJWTPath(), []byte(trust.SysAccountJWT), 0o600); werr != nil {
			return nil, werr
		}
		mat.sysAccountJWT = trust.SysAccountJWT
	}
	return mat, nil
}

// ensureSysUserLocked loads the SYSTEM user into mat: the identity
// ReloadNKeys() connects as to push claims updates to the bus's resolver
// (see resolver.go). Its seed is the SYS_USER Secret
// (IMAS_NATS_SYS_USER_SEED_FILE or _SEED), required: it is a user-kind
// key, not a trust chain key, so it stays a seed, but the farmer no
// longer generates one. Its JWT is signed directly by the SYS account
// key (through Transit); a dedicated signing key isn't worth the extra
// moving part for a single, low-privilege internal user.
func ensureSysUserLocked(mat *natsAuthMaterial) error {
	kp, ok, err := loadExternalSeed("SYS_USER")
	if !ok {
		return fmt.Errorf("pki: the SYS user seed is required: set %sSYS_USER_SEED_FILE", externalSeedEnvPrefix)
	}
	if err != nil {
		return err
	}
	if mat.sysUserPub, err = kp.PublicKey(); err != nil {
		return err
	}
	if nkeys.Prefix(mat.sysUserPub) != nkeys.PrefixByteUser {
		return fmt.Errorf("pki: the SYS user seed is not a user key")
	}
	if mat.sysUserSeed, err = kp.Seed(); err != nil {
		return err
	}
	mat.sysUserKP = kp
	path := filepath.Join(natsAuthDir(), "sys-user.jwt")
	if b, rerr := os.ReadFile(path); rerr == nil {
		if uc, derr := jwt.DecodeUserClaims(string(b)); derr == nil &&
			uc.Subject == mat.sysUserPub && uc.Issuer == mat.sysAccountPub {
			mat.sysUserJWT = string(b)
			return nil
		}
	}
	uc := jwt.NewUserClaims(mat.sysUserPub)
	uc.Name = "imas-farmer-sys-push"
	signed, err := uc.Encode(mat.sysAccountKP)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(path, []byte(signed), 0o600); err != nil {
		return err
	}
	mat.sysUserJWT = signed
	return nil
}

// ensureNatsAuth loads the whole trust chain the farmer works with: the
// platform part (ensurePlatformAuth), the SYS user, and the legacy
// single tenant's Account. It is idempotent and safe to call repeatedly
// (from ReloadNKeys, the tenant paths and anywhere else that needs the
// current keys/claims).
//
// The legacy tenant's keys are the Transit keys nats-tacct-<id> and
// nats-tsign-<id> for currentTenantID(). They are created only when its
// Account JWT does not exist yet (its first creation); otherwise they are
// only read, and a missing key is an error.
func ensureNatsAuth() (*natsAuthMaterial, error) {
	authMu.Lock()
	defer authMu.Unlock()

	ctx := context.Background()
	mat, err := ensurePlatformAuthLocked(ctx)
	if err != nil {
		return nil, err
	}
	if err := ensureSysUserLocked(mat); err != nil {
		return nil, err
	}

	getKey := natsKeys.keyPair
	if _, serr := os.Stat(tenantJWTPath()); os.IsNotExist(serr) {
		getKey = natsKeys.ensureKeyPair
	} else if serr != nil {
		return nil, serr
	}
	tenantKP, err := getKey(ctx, natsKeyRef{role: natsKeyTenantAccount})
	if err != nil {
		return nil, err
	}
	mat.tenantPub, err = tenantKP.PublicKey()
	if err != nil {
		return nil, err
	}
	mat.tenantSigningKP, err = getKey(ctx, natsKeyRef{role: natsKeyTenantSigning})
	if err != nil {
		return nil, err
	}
	tenantSigningPub, err := mat.tenantSigningKP.PublicKey()
	if err != nil {
		return nil, err
	}
	mat.tenantName = config.FarmerOrganization
	if mat.tenantName == "" {
		mat.tenantName = "imas"
	}

	// Tenant Account claims: signed by the operator's signing key, with its
	// own delegated signing key used to mint every sprout/farmer/cli User
	// JWT. Loaded (not regenerated) when present, since this file also
	// carries the live revocation list that syncNatsAuth maintains.
	needTenantJWT := true
	if b, rerr := os.ReadFile(tenantJWTPath()); rerr == nil {
		if ac, derr := jwt.DecodeAccountClaims(string(b)); derr == nil &&
			ac.Subject == mat.tenantPub &&
			ac.SigningKeys.Contains(tenantSigningPub) {
			mat.tenantJWT = string(b)
			needTenantJWT = false
		}
	}
	if needTenantJWT {
		ac := jwt.NewAccountClaims(mat.tenantPub)
		ac.Name = mat.tenantName
		ac.SigningKeys.Add(tenantSigningPub)
		signed, encErr := ac.Encode(mat.operatorSigningKP)
		if encErr != nil {
			return nil, encErr
		}
		if werr := writeFileAtomic(tenantJWTPath(), []byte(signed), 0o600); werr != nil {
			return nil, werr
		}
		mat.tenantJWT = signed
		mat.tenantMinted = true
	}

	return mat, nil
}

// CheckNATSAuth is the farmer's start-up check of its NATS signing: the
// trust directory loads and validates, Transit answers, and the three
// platform keys' public keys there are the trust's. cmd/farmer calls it
// before anything else touches the trust chain, so a farmer without
// trust, without Transit or with a mismatched anchor fails fast.
func CheckNATSAuth(ctx context.Context) error {
	trust, err := LoadNATSTrustDir(NATSTrustDir())
	if err != nil {
		return err
	}
	ks, err := natsKeys.store()
	if err != nil {
		return err
	}
	if err := trust.VerifyAgainst(ctx, ks); err != nil {
		return err
	}
	authMu.Lock()
	defer authMu.Unlock()
	_, err = ensurePlatformAuthLocked(ctx)
	return err
}

// externalSeedEnvPrefix namespaces the env vars loadOrCreateSeed checks
// before touching disk, so a seed can be handed to the farmer process by
// whatever secrets pipeline it's deployed with (e.g. Vault via External
// Secrets Operator, materialized as a Kubernetes Secret) instead of being
// generated and stored locally at all. IMAS_NATS_<NAME>_SEED_FILE takes a
// path — the shape an ESO-synced Secret normally takes once mounted into
// the pod as a volume — and IMAS_NATS_<NAME>_SEED takes the raw seed value
// directly, for a Secret wired in via envFrom/secretKeyRef instead. The
// _FILE form is preferred: unlike an env var, a mounted Secret volume isn't
// inherited by child processes or liable to end up in a crash dump.
const externalSeedEnvPrefix = "IMAS_NATS_"

// loadExternalSeed checks IMAS_NATS_<name>_SEED_FILE and IMAS_NATS_<name>_SEED
// for an externally-supplied seed, in that order. It returns ok=false (no
// error) when neither is set, so callers fall back to local generation.
func loadExternalSeed(name string) (kp nkeys.KeyPair, ok bool, err error) {
	envBase := externalSeedEnvPrefix + name
	if path := os.Getenv(envBase + "_SEED_FILE"); path != "" {
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil, true, fmt.Errorf("reading %s from %s: %w", envBase+"_SEED_FILE", path, rerr)
		}
		kp, err = nkeys.FromSeed(bytes.TrimSpace(b))
		return kp, true, err
	}
	if seed := os.Getenv(envBase + "_SEED"); seed != "" {
		kp, err = nkeys.FromSeed(bytes.TrimSpace([]byte(seed)))
		return kp, true, err
	}
	return nil, false, nil
}

// loadOrCreateSeed resolves the NKey seed identified by name: first from an
// external secret (see loadExternalSeed), then from path on disk, and only
// generates a fresh keypair via create — persisting it to path (0600) — if
// neither is present. A seed sourced externally is never written to path:
// the whole point is that it doesn't get a second, farmer-local plaintext
// copy.
func loadOrCreateSeed(path, name string, create func() (nkeys.KeyPair, error)) (nkeys.KeyPair, error) {
	if kp, ok, err := loadExternalSeed(name); ok {
		return kp, err
	}
	if b, err := os.ReadFile(path); err == nil {
		kp, kerr := nkeys.FromSeed(bytes.TrimSpace(b))
		if kerr != nil {
			return nil, kerr
		}
		return kp, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	kp, err := create()
	if err != nil {
		return nil, err
	}
	seed, err := kp.Seed()
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(path, seed, 0o600); err != nil {
		return nil, err
	}
	log.Tracef("Generated new NATS auth keypair at %s", path)
	return kp, nil
}

// loadTenantClaims decodes the current on-disk tenant Account JWT into a
// mutable *jwt.AccountClaims for syncNatsAuth to update in place.
func loadTenantClaims(mat *natsAuthMaterial) (*jwt.AccountClaims, error) {
	return jwt.DecodeAccountClaims(mat.tenantJWT)
}
