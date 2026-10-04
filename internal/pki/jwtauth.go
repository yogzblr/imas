package pki

// Decentralized NATS JWT auth bootstrap: Operator -> SYSTEM account ->
// tenant Account. See docs/design/imas-nats-jwt-auth-design.md.
//
// FLAG FOR SECURITY REVIEW: this file mints and persists the root Operator
// keypair, which is the trust anchor for every tenant's isolation on the
// bus. By default it's written to disk here as an interim measure; every
// seed below can instead be supplied externally (see loadExternalSeed) so
// it's never generated or stored locally at all — the intended production
// shape being Vault, synced into the farmer's pod as a Kubernetes Secret via
// External Secrets Operator. Per the design doc's "Key custody" section,
// wiring that up for real (short-lived credentials, or signing without ever
// releasing the key) is workstream F. Until a given seed is supplied
// externally, treat {FarmerPKI}/nats-auth/operator.nk as the single most
// sensitive file this farmer writes.

import (
	"bytes"
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
	operatorKP        nkeys.KeyPair
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

	tenantKP        nkeys.KeyPair
	tenantSigningKP nkeys.KeyPair
	tenantPub       string
	tenantJWT       string
	tenantName      string
}

// authMu guards concurrent bootstrap/persistence of the auth material below
// (concurrent Accept/Deny/Reject calls, or a SIGHUP racing one of them).
var authMu sync.Mutex

func natsAuthDir() string {
	return filepath.Join(config.FarmerPKI, natsAuthSubdir)
}

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

// ensureNatsAuth loads the operator/system/tenant trust-chain material from
// disk, generating and persisting any piece that doesn't exist yet. It is
// idempotent and safe to call repeatedly (from ConfigureNats, ReloadNKeys,
// and anywhere else that needs the current keys/claims).
func ensureNatsAuth() (*natsAuthMaterial, error) {
	authMu.Lock()
	defer authMu.Unlock()

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

	mat := &natsAuthMaterial{}

	var err error
	mat.operatorKP, err = loadOrCreateSeed(filepath.Join(dir, "operator.nk"), "OPERATOR", nkeys.CreateOperator)
	if err != nil {
		return nil, err
	}
	mat.operatorPub, err = mat.operatorKP.PublicKey()
	if err != nil {
		return nil, err
	}
	mat.operatorSigningKP, err = loadOrCreateSeed(filepath.Join(dir, "operator-signing.nk"), "OPERATOR_SIGNING", nkeys.CreateOperator)
	if err != nil {
		return nil, err
	}
	operatorSigningPub, err := mat.operatorSigningKP.PublicKey()
	if err != nil {
		return nil, err
	}

	mat.sysAccountKP, err = loadOrCreateSeed(filepath.Join(dir, "sys-account.nk"), "SYS_ACCOUNT", nkeys.CreateAccount)
	if err != nil {
		return nil, err
	}
	mat.sysAccountPub, err = mat.sysAccountKP.PublicKey()
	if err != nil {
		return nil, err
	}

	mat.tenantKP, err = loadOrCreateSeed(filepath.Join(dir, "tenant.nk"), "TENANT", nkeys.CreateAccount)
	if err != nil {
		return nil, err
	}
	mat.tenantPub, err = mat.tenantKP.PublicKey()
	if err != nil {
		return nil, err
	}
	mat.tenantSigningKP, err = loadOrCreateSeed(filepath.Join(dir, "tenant-signing.nk"), "TENANT_SIGNING", nkeys.CreateAccount)
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

	// Operator claims: self-signed, names the SYSTEM account and delegates
	// day-to-day Account signing to operatorSigningKP so the root operator
	// key need not be online at runtime (see the security-review note above).
	needOperatorJWT := true
	if b, rerr := os.ReadFile(filepath.Join(dir, "operator.jwt")); rerr == nil {
		if oc, derr := jwt.DecodeOperatorClaims(string(b)); derr == nil &&
			oc.Subject == mat.operatorPub &&
			oc.SystemAccount == mat.sysAccountPub &&
			oc.SigningKeys.Contains(operatorSigningPub) {
			mat.operatorJWT = string(b)
			needOperatorJWT = false
		}
	}
	if needOperatorJWT {
		oc := jwt.NewOperatorClaims(mat.operatorPub)
		oc.Name = mat.tenantName + "-operator"
		oc.SystemAccount = mat.sysAccountPub
		oc.SigningKeys.Add(operatorSigningPub)
		signed, encErr := oc.Encode(mat.operatorKP)
		if encErr != nil {
			return nil, encErr
		}
		if werr := writeFileAtomic(filepath.Join(dir, "operator.jwt"), []byte(signed), 0o600); werr != nil {
			return nil, werr
		}
		mat.operatorJWT = signed
	}

	// SYSTEM account claims: signed by the operator's signing key.
	needSysJWT := true
	if b, rerr := os.ReadFile(filepath.Join(dir, "sys-account.jwt")); rerr == nil {
		if ac, derr := jwt.DecodeAccountClaims(string(b)); derr == nil && ac.Subject == mat.sysAccountPub {
			mat.sysAccountJWT = string(b)
			needSysJWT = false
		}
	}
	if needSysJWT {
		ac := jwt.NewAccountClaims(mat.sysAccountPub)
		ac.Name = "SYS"
		signed, encErr := ac.Encode(mat.operatorSigningKP)
		if encErr != nil {
			return nil, encErr
		}
		if werr := writeFileAtomic(filepath.Join(dir, "sys-account.jwt"), []byte(signed), 0o600); werr != nil {
			return nil, werr
		}
		mat.sysAccountJWT = signed
	}

	// SYSTEM user: the identity ReloadNKeys() connects as to push claims
	// updates to the bus's resolver (see resolver.go). Signed directly by
	// the SYS account's own key; a dedicated signing key isn't worth the
	// extra moving part for a single, low-privilege internal user.
	mat.sysUserKP, err = loadOrCreateSeed(filepath.Join(dir, "sys-user.nk"), "SYS_USER", nkeys.CreateUser)
	if err != nil {
		return nil, err
	}
	mat.sysUserPub, err = mat.sysUserKP.PublicKey()
	if err != nil {
		return nil, err
	}
	mat.sysUserSeed, err = mat.sysUserKP.Seed()
	if err != nil {
		return nil, err
	}
	needSysUserJWT := true
	if b, rerr := os.ReadFile(filepath.Join(dir, "sys-user.jwt")); rerr == nil {
		if uc, derr := jwt.DecodeUserClaims(string(b)); derr == nil && uc.Subject == mat.sysUserPub {
			mat.sysUserJWT = string(b)
			needSysUserJWT = false
		}
	}
	if needSysUserJWT {
		uc := jwt.NewUserClaims(mat.sysUserPub)
		uc.Name = "imas-farmer-sys-push"
		signed, encErr := uc.Encode(mat.sysAccountKP)
		if encErr != nil {
			return nil, encErr
		}
		if werr := writeFileAtomic(filepath.Join(dir, "sys-user.jwt"), []byte(signed), 0o600); werr != nil {
			return nil, werr
		}
		mat.sysUserJWT = signed
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
	}

	return mat, nil
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
