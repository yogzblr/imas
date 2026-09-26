package pki

// The SaaS API's own NATS identity — a narrowly-scoped User under the SYS
// Account, carrying exactly the platform-level internal.* subjects
// internal/saasapi needs to drive tenant provisioning and sprout actions
// through farmer. See
// docs/design/imas-internal-api-account.md for why SYS (rather than the
// legacy tenant Account, or a new dedicated one), and why these
// permissions and nothing more.
//
// FLAG FOR SECURITY REVIEW: this mints a new privileged, cross-tenant
// credential. Its only guard against $SYS-level administrative reach is
// saasAPIUserPermissions below — NATS enforces a User's JWT permissions
// uniformly, $SYS.> included, but being in the SYS Account means a widened
// allow-list here would be far worse than the same mistake in a tenant
// Account. TestSaaSAPIUserPermissions_ExactAllowLists pins the exact
// lists, and saasapi_user_integration_test.go proves the scoping against a
// live bus.

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"github.com/yogzblr/imas/internal/controlplane"
	log "github.com/yogzblr/imas/internal/log"
)

const (
	saasAPIUserName = "imas-saasapi"
	// saasAPIUserSeedName is the loadOrCreateSeed/loadExternalSeed name,
	// so IMAS_NATS_SAASAPI_USER_SEED_FILE / IMAS_NATS_SAASAPI_USER_SEED
	// supply the seed externally (OpenBao via ESO) instead of farmer
	// generating and persisting one.
	saasAPIUserSeedName = "SAASAPI_USER"
)

func saasAPIUserSeedPath() string { return filepath.Join(natsAuthDir(), "saasapi-user.nk") }

// SaaSAPIUserJWTPath is where EnsureSaaSAPICredential persists the SaaS
// API's minted User JWT. It reaches OpenBao KV (and, via External Secrets
// Operator, saasapi's SAASAPI_NATS_USER_JWT) through
// PublishSaaSAPICredential, run by `farmer publish-saasapi-credential`
// (see saasapi_publish.go and the design doc's "JWT -> OpenBao hand-off").
func SaaSAPIUserJWTPath() string { return filepath.Join(natsAuthDir(), "users", "saasapi.jwt") }

func sysAccountJWTPath() string { return filepath.Join(natsAuthDir(), "sys-account.jwt") }

// saasAPIUserPermissions is the SaaS API's entire NATS reach: publish the
// two tenant request subjects and internal.sprout.action; subscribe to the
// tenant flows' per-job result subjects and to its own reply inboxes.
//
// The inbox grant is scoped to controlplane.SaaSAPIInboxWildcard
// (_INBOX.saasapi.>), never a bare _INBOX.>: every SYS user's default
// inbox lives under _INBOX, so the bare form would let this credential
// subscribe to farmer's own SYS user's replies. The SaaS API has to dial
// with nats.CustomInboxPrefix(controlplane.SaaSAPIInboxPrefix) for its
// requests to get replies at all. Pub on the inbox is deliberately not
// granted: replies come from farmer.
//
// Deliberately absent: imas.> (any tenant's business traffic), $SYS.>
// (server administration), subscribe on any internal.* request subject
// (only farmer receives requests), and the internal.sprout.* subjects
// that have no farmer handler yet (mint, revoke, enrolled,
// internal.sprouts.list) — add each here when its handler lands.
func saasAPIUserPermissions() jwt.Permissions {
	return jwt.Permissions{
		Pub: jwt.Permission{Allow: jwt.StringList{
			controlplane.SubjectTenantProvision,
			controlplane.SubjectTenantDeprovision,
			controlplane.SubjectSproutAction,
		}},
		Sub: jwt.Permission{Allow: jwt.StringList{
			controlplane.SubjectTenantProvisionedWildcard,
			controlplane.SubjectTenantDeprovisionedWildcard,
			controlplane.SaaSAPIInboxWildcard,
		}},
	}
}

// saasAPIUserConnectionTypes restricts the credential to plain NATS
// client connections: the SaaS API connects from inside the control
// plane, never through Envoy's DMZ websocket route, and never as a
// leafnode/MQTT client.
func saasAPIUserConnectionTypes() jwt.StringList {
	return jwt.StringList{jwt.ConnectionTypeStandard}
}

// saasAPIUserJWTIsCurrent reports whether an already-minted User JWT
// still matches what EnsureSaaSAPICredential would mint now: same subject
// key, issued by the SYS Account's own key, and the exact same
// permissions/connection types. Comparing the permissions (not just the
// subject, as mintOrReuseUserJWT does for sprouts) is what makes a change
// to saasAPIUserPermissions take effect on the next farmer boot rather
// than being silently shadowed by a stale JWT on disk.
func saasAPIUserJWTIsCurrent(uc *jwt.UserClaims, pub, sysAccountPub string) bool {
	if uc.Subject != pub || uc.Issuer != sysAccountPub || uc.IssuerAccount != "" {
		return false
	}
	want := saasAPIUserPermissions()
	return reflect.DeepEqual(uc.Pub.Allow, want.Pub.Allow) &&
		reflect.DeepEqual(uc.Sub.Allow, want.Sub.Allow) &&
		len(uc.Pub.Deny) == 0 && len(uc.Sub.Deny) == 0 &&
		uc.Resp == nil &&
		reflect.DeepEqual(uc.AllowedConnectionTypes, saasAPIUserConnectionTypes())
}

// EnsureSaaSAPICredential returns the SaaS API's NATS User JWT and NKey
// seed, minting (or re-minting) the JWT if needed and persisting it to
// SaaSAPIUserJWTPath. Idempotent: call at every farmer boot.
//
// The User is signed directly by the SYS Account's identity key, exactly
// like imas-farmer-sys-push (jwtauth.go) — no Account JWT change, and so
// no resolver push, is needed for the bus to accept it; the SYS Account
// JWT it chains to is already seeded into every bus node's resolver by
// ConfigureNats.
//
// Rotation: if the seed changed since the JWT on disk was minted (a new
// IMAS_NATS_SAASAPI_USER_SEED[_FILE] from OpenBao), the previous public
// key is added to the SYS Account JWT's revocation list, which is
// re-signed, persisted, and pushed to the bus resolver over the same
// pushAccountUpdate path every tenant Account update uses — otherwise the
// old credential would stay valid forever, since the User JWT carries no
// expiry. Whenever the SYS Account JWT carries any revocation, it is
// (re-)pushed on every call, so a push that failed at one boot is retried
// at the next rather than leaving a rotated-out key live on the bus.
//
// A push failure is returned as an error, but only after the new
// credential has been persisted: the returned JWT/seed are still valid,
// and the caller should log rather than abort.
func EnsureSaaSAPICredential() (userJWT string, seed []byte, err error) {
	// ensureNatsAuth takes authMu itself; call it first, then take authMu
	// for the section below that reads and rewrites sys-account.jwt — the
	// same file ensureNatsAuth reads under that lock.
	mat, err := ensureNatsAuth()
	if err != nil {
		return "", nil, fmt.Errorf("bootstrapping NATS auth material: %w", err)
	}

	signed, seed, sysJWT, push, err := ensureSaaSAPICredentialLocked(mat)
	if err != nil {
		return "", nil, err
	}
	if push {
		if perr := pushAccountUpdate(mat, sysJWT); perr != nil {
			return signed, seed, fmt.Errorf("pushing the SYS Account JWT (SaaS API key rotation) to the bus resolver: %w", perr)
		}
		log.Infof("Pushed the SYS Account JWT (SaaS API credential revocations) to the bus resolver.")
	}
	return signed, seed, nil
}

func ensureSaaSAPICredentialLocked(mat *natsAuthMaterial) (userJWT string, seed []byte, sysJWT string, push bool, err error) {
	authMu.Lock()
	defer authMu.Unlock()

	kp, err := loadOrCreateSeed(saasAPIUserSeedPath(), saasAPIUserSeedName, nkeys.CreateUser)
	if err != nil {
		return "", nil, "", false, fmt.Errorf("loading the SaaS API NKey seed: %w", err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		return "", nil, "", false, err
	}
	if nkeys.Prefix(pub) != nkeys.PrefixByteUser {
		return "", nil, "", false, fmt.Errorf("SaaS API NKey seed is not a User key")
	}
	seed, err = kp.Seed()
	if err != nil {
		return "", nil, "", false, err
	}

	// Re-read the SYS Account JWT from disk under authMu rather than
	// trusting mat's snapshot: another EnsureSaaSAPICredential call may
	// have added a revocation since ensureNatsAuth returned.
	sysBytes, err := os.ReadFile(sysAccountJWTPath())
	if err != nil {
		return "", nil, "", false, fmt.Errorf("reading the SYS Account JWT: %w", err)
	}
	sysClaims, err := jwt.DecodeAccountClaims(string(sysBytes))
	if err != nil || sysClaims.Subject != mat.sysAccountPub {
		return "", nil, "", false, fmt.Errorf("SYS Account JWT on disk is invalid or doesn't match the SYS Account key: %v", err)
	}

	var prevPub string
	if b, rerr := os.ReadFile(SaaSAPIUserJWTPath()); rerr == nil {
		if uc, derr := jwt.DecodeUserClaims(string(b)); derr == nil {
			prevPub = uc.Subject
			if saasAPIUserJWTIsCurrent(uc, pub, mat.sysAccountPub) {
				userJWT = string(b)
			}
		}
	} else if !os.IsNotExist(rerr) {
		return "", nil, "", false, rerr
	}

	sysChanged := false
	if prevPub != "" && prevPub != pub && ensureUserRevoked(sysClaims, prevPub) {
		log.Infof("SaaS API NATS key rotated: revoking previous key %s on the SYS Account.", prevPub)
		sysChanged = true
	}
	// Clear any stale revocation for the current key (e.g. a seed rotated
	// back to a previously-revoked one) — otherwise a JWT minted in the
	// same second as that revocation would be rejected.
	if ensureUserGranted(sysClaims, pub) {
		sysChanged = true
	}

	if userJWT == "" {
		uc := jwt.NewUserClaims(pub)
		uc.Name = saasAPIUserName
		uc.Permissions = saasAPIUserPermissions()
		uc.AllowedConnectionTypes = saasAPIUserConnectionTypes()
		userJWT, err = uc.Encode(mat.sysAccountKP)
		if err != nil {
			return "", nil, "", false, err
		}
		if err := os.MkdirAll(filepath.Dir(SaaSAPIUserJWTPath()), 0o700); err != nil {
			return "", nil, "", false, err
		}
		if err := os.WriteFile(SaaSAPIUserJWTPath(), []byte(userJWT), 0o600); err != nil {
			return "", nil, "", false, err
		}
		log.Infof("Minted the SaaS API's NATS User JWT under the SYS Account (%s).", SaaSAPIUserJWTPath())
	}

	sysJWT = string(sysBytes)
	if sysChanged {
		sysJWT, err = sysClaims.Encode(mat.operatorSigningKP)
		if err != nil {
			return "", nil, "", false, fmt.Errorf("re-signing the SYS Account JWT: %w", err)
		}
		if err := os.WriteFile(sysAccountJWTPath(), []byte(sysJWT), 0o600); err != nil {
			return "", nil, "", false, err
		}
	}
	return userJWT, seed, sysJWT, sysChanged || len(sysClaims.Revocations) > 0, nil
}
