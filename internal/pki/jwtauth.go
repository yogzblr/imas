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

// authMu guards concurrent bootstrap/holding of the auth material below
// (concurrent Accept/Deny/Reject calls, or a SIGHUP racing one of them).
var authMu sync.Mutex

func natsAuthDir() string {
	return filepath.Join(config.FarmerPKI, natsAuthSubdir)
}

// resolverStoreDir is the DMZ bus's resolver directory (LoadBusNats),
// on cmd/farmerbus's data emptyDir; its account loader refills it from
// the accounts bucket at every start. The in-process test bus uses a
// directory of its own (newTempDirResolver). Farmer writes nothing under
// config.FarmerPKI: the JWTs it signs are held in memory
// (accountjwts.go).
func resolverStoreDir() string {
	return filepath.Join(natsAuthDir(), "resolver")
}

// ensurePlatformAuth loads the platform part of the trust chain: the
// public trust (operator JWT, operator, operator-signing and SYS account
// public keys, SYS account JWT) from the trust directory the bootstrap
// Job's ConfigMap is mounted at, and the operator-signing and SYS account
// signing pairs from Transit (read, never created), and checks the
// pairs' public keys are the trust's. It mints nothing: the bootstrap Job
// owns the operator and SYS account JWTs. The SYS account JWT it holds
// (accountjwts.go) is the one this process holds, or else the accounts
// bucket's (both only if signed by the operator signing key for the
// trust's SYS account), or else the trust's; farmer re-signs it with its
// revocations (saasapi_user.go). It writes no file. The SaaS API
// credential Job needs only this.
func ensurePlatformAuth() (*natsAuthMaterial, error) {
	authMu.Lock()
	defer authMu.Unlock()
	return ensurePlatformAuthLocked(context.Background())
}

func ensurePlatformAuthLocked(ctx context.Context) (*natsAuthMaterial, error) {
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

	mat.sysAccountJWT, _, err = loadAccountJWT(ctx, trust.SysAccountPub, issuedBy(trust.OperatorSigningPub))
	if err != nil {
		return nil, err
	}
	if mat.sysAccountJWT == "" {
		j, err := sysAccountJWTFromTrust(ctx, mat, trust.SysAccountJWT)
		if err != nil {
			return nil, err
		}
		if err := holdAccountJWT(j, false); err != nil {
			return nil, err
		}
		mat.sysAccountJWT = j
	}
	return mat, nil
}

// sysAccountJWTFromTrust is the SYS Account JWT a process starts from
// when neither it nor the accounts bucket holds one: the trust's, which
// the bootstrap Job signed before any revocation existed, with the SYS
// account's revocations as the database has them put back first
// (security review 2026-10, I8): the SaaS API key saasapi_credential_state
// names as rotated out (prev_pub), the one revocation farmer makes on the
// SYS account (EnsureSaaSAPICredential). A failed read is returned, never
// taken for no revocation. Without a database (the SaaS API credential
// publish Job) there is no rotation state, and the trust's JWT is used
// as it is.
func sysAccountJWTFromTrust(ctx context.Context, mat *natsAuthMaterial, trustJWT string) (string, error) {
	if db == nil {
		return trustJWT, nil
	}
	state, err := readSaaSAPICredentialState(ctx)
	if isMissingTableError(err) {
		// The saas migration that creates the table has not run yet
		// (farmer waits only for its own schema, and cmd/migrate applies
		// the saas set after it): saasapi has recorded no credential, so
		// there is nothing to revoke. Every other error still fails.
		log.Warnf("SYS account %s: %s does not exist yet; no SaaS API key has been rotated out", mat.sysAccountPub, saasAPICredentialStateTable)
		state, err = nil, nil
	}
	if err != nil {
		return "", fmt.Errorf("pki: SYS account %s: rebuilding its revocations from the database (%s) before using the trust's SYS Account JWT: %w", mat.sysAccountPub, saasAPICredentialStateTable, err)
	}
	if state == nil || state.PrevPub == "" || state.PrevPub == state.CurrentPub {
		return trustJWT, nil
	}
	ac, err := jwt.DecodeAccountClaims(trustJWT)
	if err != nil {
		return "", fmt.Errorf("%w: %s: %v", ErrTrustInvalid, TrustSysAccountJWT, err)
	}
	if !ensureUserRevoked(ac, state.PrevPub) {
		return trustJWT, nil
	}
	waitPastIssuedAt(ac.IssuedAt)
	signed, err := ac.Encode(mat.operatorSigningKP)
	if err != nil {
		return "", fmt.Errorf("pki: SYS account %s: re-signing the trust's SYS Account JWT with its revocations: %w", mat.sysAccountPub, err)
	}
	log.Infof("No SYS Account JWT held or in the accounts bucket; using the trust's with rotated-out SaaS API key %s revoked.", state.PrevPub)
	return signed, nil
}

// ensureSysUserLocked loads the SYSTEM user into mat: the identity
// ReloadNKeys() connects as to push claims updates to the bus's resolver
// (see resolver.go). Its seed is the SYS_USER Secret
// (IMAS_NATS_SYS_USER_SEED_FILE or _SEED), required: it is a user-kind
// key, not a trust chain key, so it stays a seed, but the farmer no
// longer generates one. Its JWT is signed directly by the SYS account
// key (through Transit) on first use and held in memory
// (accountjwts.go); a dedicated signing key isn't worth the extra moving
// part for a single, low-privilege internal user.
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
	heldMu.Lock()
	held := heldSysUser
	heldMu.Unlock()
	if uc, derr := jwt.DecodeUserClaims(held); held != "" && derr == nil &&
		uc.Subject == mat.sysUserPub && uc.Issuer == mat.sysAccountPub {
		mat.sysUserJWT = held
		return nil
	}
	uc := jwt.NewUserClaims(mat.sysUserPub)
	uc.Name = "imas-farmer-sys-push"
	signed, err := uc.Encode(mat.sysAccountKP)
	if err != nil {
		return err
	}
	heldMu.Lock()
	heldSysUser = signed
	heldMu.Unlock()
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
// nats-tsign-<id> for currentTenantID(), created when missing. That is
// what every farmer start did before E3 too: the legacy Account JWT whose
// presence once decided it lived in the pod's tmp emptyDir, so a start
// never found it. Unlike a provisioned tenant's (tenant.go), the legacy
// tenant's keys are never retired.
//
// Its Account JWT is the one this process holds, or else the accounts
// bucket's, or else a minimal one minted here (tenantMinted) with the
// tenant's revocations as the database has them (applyStoredRevocations;
// a database error fails the call), which syncNatsAuth re-signs with any
// grant before it is published.
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

	tenantKP, err := natsKeys.ensureKeyPair(ctx, natsKeyRef{role: natsKeyTenantAccount})
	if err != nil {
		return nil, err
	}
	mat.tenantPub, err = tenantKP.PublicKey()
	if err != nil {
		return nil, err
	}
	mat.tenantSigningKP, err = natsKeys.ensureKeyPair(ctx, natsKeyRef{role: natsKeyTenantSigning})
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
	// own delegated signing key used to mint every sprout/farmer User JWT.
	// Loaded (not regenerated) when held or in the bucket, since it also
	// carries the live revocation list that syncNatsAuth maintains.
	j, minted, err := loadAccountJWT(ctx, mat.tenantPub, signsWith(tenantSigningPub))
	if err != nil {
		return nil, err
	}
	if j == "" {
		ac := jwt.NewAccountClaims(mat.tenantPub)
		ac.Name = mat.tenantName
		ac.SigningKeys.Add(tenantSigningPub)
		if err := applyStoredRevocations(ac, currentTenantID()); err != nil {
			return nil, err
		}
		if j, err = ac.Encode(mat.operatorSigningKP); err != nil {
			return nil, err
		}
		if err := holdAccountJWT(j, true); err != nil {
			return nil, err
		}
		minted = true
	}
	mat.tenantJWT = j
	mat.tenantMinted = minted

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

// externalSeedEnvPrefix namespaces the env vars a user seed is read from
// (loadExternalSeed), so a seed is handed to the farmer process by
// whatever secrets pipeline it's deployed with (e.g. OpenBao via External
// Secrets Operator, materialized as a Kubernetes Secret); farmer never
// generates or stores one. IMAS_NATS_<NAME>_SEED_FILE takes a
// path — the shape an ESO-synced Secret normally takes once mounted into
// the pod as a volume — and IMAS_NATS_<NAME>_SEED takes the raw seed value
// directly, for a Secret wired in via envFrom/secretKeyRef instead. The
// _FILE form is preferred: unlike an env var, a mounted Secret volume isn't
// inherited by child processes or liable to end up in a crash dump.
const externalSeedEnvPrefix = "IMAS_NATS_"

// loadExternalSeed checks IMAS_NATS_<name>_SEED_FILE and IMAS_NATS_<name>_SEED
// for an externally-supplied seed, in that order. It returns ok=false (no
// error) when neither is set.
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

// loadRequiredSeed is loadExternalSeed for a seed that must be supplied:
// farmer generates no seed and writes none (SYS_USER, SAASAPI_USER).
func loadRequiredSeed(name string) (nkeys.KeyPair, error) {
	kp, ok, err := loadExternalSeed(name)
	if !ok {
		return nil, fmt.Errorf("pki: the %s seed is required: set %s%s_SEED_FILE", name, externalSeedEnvPrefix, name)
	}
	return kp, err
}

// loadTenantClaims returns the legacy tenant Account claims syncNatsAuth
// updates in place: the newest of what this process holds and the
// accounts bucket's copy (resignBase), or mat's own. It updates
// mat.tenantJWT and mat.tenantMinted to match.
func loadTenantClaims(mat *natsAuthMaterial) (*jwt.AccountClaims, error) {
	signingPub, err := mat.tenantSigningKP.PublicKey()
	if err != nil {
		return nil, err
	}
	ac, raw, minted, err := resignBase(context.Background(), mat.tenantPub, mat.tenantJWT, mat.tenantMinted, signsWith(signingPub))
	if err != nil {
		return nil, err
	}
	mat.tenantJWT, mat.tenantMinted = raw, minted
	return ac, nil
}
