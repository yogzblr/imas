package pki

// Maps imas's accept/deny/reject/unaccept sprout lifecycle onto NATS JWT
// issuance and revocation, per docs/design/imas-nats-jwt-auth-design.md's
// "Revocation semantics" open item.
//
// Two independent pieces of state are kept in sync here, and it's worth
// keeping them distinct:
//   - The tenant Account's revocation list (inside its signed JWT) is what
//     the bus actually enforces. A pubkey with a revocation entry can never
//     authenticate with a User JWT issued at or before that timestamp,
//     regardless of whether such a JWT exists. Changing this list is the
//     only thing that requires re-signing the Account JWT and pushing it to
//     the resolver (see resolver.go) — that's the expensive, network-facing
//     operation.
//   - Each sprout/farmer/cli-admin's own signed User JWT is minted once and
//     cached to a local file so it can be handed back out (e.g. by the
//     enrollment endpoint workstream H builds) without re-signing. Minting
//     or reusing this file never itself requires a push: the resolver never
//     stores User JWTs, only Account JWTs.
import (
	"os"
	"path/filepath"
	"reflect"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/auth"
	log "github.com/yogzblr/imas/internal/log"
)

func allowAllPermissions() jwt.Permissions {
	return jwt.Permissions{
		Pub: jwt.Permission{Allow: jwt.StringList{"imas.>", "_INBOX.>"}},
		Sub: jwt.Permission{Allow: jwt.StringList{"imas.>", "_INBOX.>"}},
	}
}

func sproutPermissions(id string) jwt.Permissions {
	return jwt.Permissions{
		Pub: jwt.Permission{Allow: jwt.StringList{
			"imas.sprouts.announce." + id,
			"_INBOX.>",
			"imas.cook." + id + ".>",
			"imas.sprouts." + id + ".facts",
			// Request imas-fleet-signing's current key versions from farmer
			// (internal/fleetkeys). The reply comes back on
			// imas.sprouts.<id>.fleetsigningkeys.reply.<random>, covered by
			// the existing Sub grant below; no Sub grant on _INBOX.> (which
			// would expose every reply in the Account to every sprout).
			"imas.sprouts." + id + ".fleetsigningkeys",
			// Ship this sprout's own log entries over its bus connection
			// (internal/log.UseNATSConn), one subject per level. Outside
			// imas.sprouts.<id>.>, so the sprout never receives its own
			// logs back through its Sub grant.
			sproutLogPublishGrant(id),
		}},
		Sub: jwt.Permission{Allow: jwt.StringList{
			"imas.sprouts." + id + ".>",
		}},
	}
}

// SproutLogSubjectPrefix is the subject prefix sprout id publishes its log
// entries under: imas.logs.sprouts.<id>.<LEVEL>, in its tenant's Account.
func SproutLogSubjectPrefix(id string) string {
	return "imas.logs.sprouts." + id
}

func sproutLogPublishGrant(id string) string {
	return SproutLogSubjectPrefix(id) + ".>"
}

// SproutUserJWTGrantsLogs reports whether userJWT lets sprout id publish
// its log entries. A sprout whose User JWT was minted before
// sproutPermissions carried the grant keeps using it until a refresh
// fetches the re-minted one and the sprout restarts; until then shipping
// logs would draw a permissions violation for every entry.
func SproutUserJWTGrantsLogs(userJWT, id string) bool {
	uc, err := jwt.DecodeUserClaims(userJWT)
	if err != nil {
		return false
	}
	grant := sproutLogPublishGrant(id)
	return uc.Pub.Allow.Contains(grant) && !uc.Pub.Deny.Contains(grant)
}

// ensureUserGranted clears any revocation entry for pubkey in ac. It
// reports whether it actually changed ac (i.e. a push is now needed).
func ensureUserGranted(ac *jwt.AccountClaims, pubkey string) bool {
	if _, revoked := ac.Revocations[pubkey]; revoked {
		ac.ClearRevocation(pubkey)
		return true
	}
	return false
}

// ensureUserRevoked adds a revocation entry (effective now) for pubkey in
// ac, if one isn't already present. It reports whether it actually changed
// ac (i.e. a push is now needed).
func ensureUserRevoked(ac *jwt.AccountClaims, pubkey string) bool {
	if _, revoked := ac.Revocations[pubkey]; revoked {
		return false
	}
	ac.Revoke(pubkey)
	return true
}

// mintOrReuseUserJWT (re)mints a signed User JWT for pubkey under the
// Account identified by issuerAccountPub/signingKP and persists it to
// path, unless a JWT already on disk at path is still current (same
// subject pubkey and permissions). Returns whether a new JWT was written.
//
// Comparing the permissions is what makes a change to sproutPermissions or
// allowAllPermissions reach JWTs minted before it, on the next sync; a
// sprout picks its re-minted JWT up through /v1/refresh.
//
// Parameterized by the issuing Account rather than a *natsAuthMaterial so
// this same function serves both the legacy single "current tenant" Account
// (syncNatsAuth, below, passing mat.tenantPub/mat.tenantSigningKP) and any
// number of dynamically-provisioned tenant Accounts (tenant.go's
// syncTenantSprouts, passing a *tenantAccountMaterial's fields) — workstream
// E, FLAG FOR SECURITY REVIEW: this is exactly the seam that must never mix
// up which Account a given sprout's User JWT gets issued under.
func mintOrReuseUserJWT(path, pubkey, name string, perms jwt.Permissions, issuerAccountPub string, signingKP nkeys.KeyPair) (bool, error) {
	if b, err := os.ReadFile(path); err == nil {
		if existing, derr := jwt.DecodeUserClaims(string(b)); derr == nil && existing.Subject == pubkey &&
			reflect.DeepEqual(existing.Permissions, perms) {
			return false, nil
		}
	} else if !os.IsNotExist(err) {
		return false, err
	}
	uc := jwt.NewUserClaims(pubkey)
	uc.Name = name
	uc.IssuerAccount = issuerAccountPub
	uc.Permissions = perms
	signed, err := uc.Encode(signingKP)
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, err
	}
	if err := os.WriteFile(path, []byte(signed), 0o600); err != nil {
		return false, err
	}
	return true, nil
}

// syncNatsAuth recomputes the tenant Account's User JWTs and revocation
// list from the current accept/deny/reject/unaccept directory state (the
// same "rebuild from directory state" shape the old NKey-allow-list
// ReloadNKeys used), re-signing and persisting the Account JWT if its
// revocation list changed. It reports whether the Account JWT changed
// (i.e. whether ReloadNKeys needs to push an update to the bus).
func syncNatsAuth(mat *natsAuthMaterial) (bool, error) {
	ac, err := loadTenantClaims(mat)
	if err != nil {
		return false, err
	}

	changed := false

	farmerKey, err := GetPubNKey(FarmerPubNKey)
	if err != nil {
		log.Fatalf("Could not load the Farmer's NKey, aborting")
	}
	log.Tracef("Loaded farmer's public key: %s", farmerKey)
	if ensureUserGranted(ac, farmerKey) {
		changed = true
	}
	if _, mintErr := mintOrReuseUserJWT(farmerUserJWTPath(), farmerKey, "farmer", allowAllPermissions(), mat.tenantPub, mat.tenantSigningKP); mintErr != nil {
		log.Errorf("failed to mint farmer User JWT: %v", mintErr)
	}

	imasKeys, err := auth.GetPubkeysByRole("admin")
	if err != nil {
		log.Errorf("Could not load the imas cli's NKey(s), please edit the config")
	} else {
		log.Tracef("Loaded imas cli's public key(s): %v", imasKeys)
	}
	for _, key := range imasKeys {
		if ensureUserGranted(ac, key) {
			changed = true
		}
		if _, mintErr := mintOrReuseUserJWT(cliUserJWTPath(key), key, "imas-cli", allowAllPermissions(), mat.tenantPub, mat.tenantSigningKP); mintErr != nil {
			log.Errorf("failed to mint imas cli User JWT for %s: %v", key, mintErr)
		}
	}

	for _, s := range GetNKeysByType(currentTenantID(), "accepted").Sprouts {
		log.Tracef("Syncing accepted sprout `%s` onto the tenant Account JWT", s.SproutID)
		key, errGet := GetNKey(currentTenantID(), s.SproutID)
		if errGet != nil {
			log.Errorf("failed to get NKey for sprout %s: %v", s.SproutID, errGet)
			continue
		}
		if ensureUserGranted(ac, key) {
			changed = true
		}
		if _, mintErr := mintOrReuseUserJWT(sproutJWTPath(s.SproutID), key, s.SproutID, sproutPermissions(s.SproutID), mat.tenantPub, mat.tenantSigningKP); mintErr != nil {
			log.Errorf("failed to mint User JWT for sprout %s: %v", s.SproutID, mintErr)
		}
	}

	for _, state := range []string{"unaccepted", "denied", "rejected"} {
		for _, s := range GetNKeysByType(currentTenantID(), state).Sprouts {
			key, errGet := GetNKey(currentTenantID(), s.SproutID)
			if errGet != nil {
				log.Errorf("failed to get NKey for sprout %s: %v", s.SproutID, errGet)
				continue
			}
			if ensureUserRevoked(ac, key) {
				changed = true
			}
		}
	}

	log.Tracef("Completed syncing authorized clients onto the tenant Account JWT.")

	if changed {
		signed, encErr := ac.Encode(mat.operatorSigningKP)
		if encErr != nil {
			return false, encErr
		}
		if writeErr := os.WriteFile(tenantJWTPath(), []byte(signed), 0o600); writeErr != nil {
			return false, writeErr
		}
		mat.tenantJWT = signed
	}
	return changed, nil
}

// FarmerUserJWT returns the farmer's own signed User JWT, minted by
// syncNatsAuth (via ReloadNKeys) into farmerUserJWTPath. cmd/farmer/main.go's
// ConnectFarmer reads this to authenticate the core process's own bus
// connection alongside its NKey seed (config.NKeyFarmerPrivFile) — the same
// User-JWT-plus-seed shape ConnectSystemAccount uses for the SYS push
// connection, replacing the bare-NKey connect that predates this file's JWT
// auth model and can't satisfy a server configured with TrustedOperators.
// ReloadNKeys must have run at least once (main() calls it during farmer
// startup, before ConnectFarmer) so this file exists by the time it's read.
func FarmerUserJWT() (string, error) {
	b, err := os.ReadFile(farmerUserJWTPath())
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// GetSproutUserJWT returns the signed User JWT minted for an accepted
// sprout, if any. This is groundwork for the enrollment endpoint
// (docs/design/imas-envoy-enrollment-design.md, workstream H) that will
// hand it back to the sprout; nothing in this repo serves it over the wire
// yet.
func GetSproutUserJWT(id string) (string, error) {
	if !IsValidSproutID(id) {
		return "", ErrSproutIDInvalid
	}
	b, err := os.ReadFile(sproutJWTPath(id))
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrSproutIDNotFound
		}
		return "", err
	}
	return string(b), nil
}
