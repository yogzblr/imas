package auth

import (
	"errors"
	"fmt"
	"sync"

	"github.com/nats-io/nkeys"
	"github.com/taigrr/jety"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/rbac"
)

var (
	ErrInvalidPubkey = errors.New("invalid pubkey format in config")
	ErrMissingAdmin  = errors.New("no admin pubkey found in config")
	ErrNoPrivkey     = errors.New("no private key found in config")
	ErrPrivkeyExists = errors.New("private key already exists in config")
	ErrNoPubkeys     = errors.New("no pubkeys found in config")
	ErrUserExists    = errors.New("pubkey is already assigned to a role")
	ErrUserNotFound  = errors.New("pubkey is not assigned to any role")
)

// policyState holds the loaded RBAC policy. It is populated by LoadPolicy
// during farmer startup and used by all auth checks.
//
// This policy has no tenant concept — one config-file-driven policy for
// the whole farmer process, regardless of which tenant a request concerns.
// Flagged as an open gap in docs/design/imas-tenant-context-threading.md
// while workstream E's tenant-isolation work (PRs #28, #39-#41) was
// landing; resolved as a deliberate non-issue, not deferred work, once
// confirmed against this codebase's actual access model rather than
// against RBAC's role model in the abstract:
//
//   - Farmer's entire NATS API surface is called exclusively by the SaaS
//     API's own privileged service credential (see
//     cloudxp-machine-manager-api-design.md's "Internal API — Farmer
//     (SaaS API only)"). A tenant, a human, or CloudXP itself never calls
//     farmer directly.
//   - cmd/imas, the only other code path that authenticates to farmer's
//     bus independently of the SaaS API (internal/api/client/nats.go
//     dials config.FarmerBusURL directly), is never issued to anyone —
//     confirmed, not assumed. If that ever changes — the CLI gets handed
//     to ops/support for direct access, or any caller other than the
//     SaaS API's own credential is ever granted access to farmer's
//     internal subjects — this decision needs revisiting, since RBAC
//     would then be the only thing standing between that caller's
//     permitted actions and which tenant they can perform them against.
//   - Tenant boundary enforcement itself was never RBAC's job on the
//     SaaS-API path regardless: it happens via the point-of-effect
//     data-ownership checks in internal/pki, internal/props, and
//     internal/facts (a request's asserted tenant_id checked against a
//     sprout's actually-stored tenant_id) — RBAC's role model answers
//     "is this kind of action allowed," never "for which tenant," so it
//     was never the right tool for this boundary in the first place.
var (
	policyMu    sync.RWMutex
	roleStore   *rbac.RoleStore
	userRoleMap *rbac.UserRoleMap
	cohortReg   *rbac.Registry
)

// LoadPolicy reads roles, users, and cohorts from the farmer config.
// It must be called during farmer startup before serving requests.
// Returns an error if the config contains duplicate pubkey assignments
// (same pubkey under multiple roles).
// It validates the policy and logs warnings for misconfigurations.
func LoadPolicy() error {
	policyMu.Lock()
	defer policyMu.Unlock()

	// Validate pubkey uniqueness before loading — reject configs where
	// the same key appears under multiple roles.
	if err := rbac.ValidateUserUniqueness(); err != nil {
		return err
	}

	// Validate username uniqueness — reject configs where two pubkeys
	// share the same username (ambiguous audit logs).
	if err := rbac.ValidateUsernameUniqueness(); err != nil {
		return err
	}

	var err error
	roleStore, err = rbac.LoadRolesFromConfig()
	if err != nil {
		return err
	}
	if err := ensureBuiltinAdminRoleLocked(); err != nil {
		return err
	}
	userRoleMap = rbac.LoadUsersFromConfig()
	// Users registered through the API live in the users store, not the
	// config file: put them back after the config reload above wiped
	// them (store.go).
	if err := applyRegisteredUsersLocked(); err != nil {
		return err
	}
	// The first admin's CLI box key, from the config file's boxpub
	// field, imported once (bootstrapkeys.go). Never fails the load.
	importConfigCLIBoxKeys()
	cohortReg, err = rbac.LoadCohortsFromConfig()
	if err != nil {
		return err
	}

	// Validate the assembled policy and log warnings.
	policy := currentPolicyLocked()
	warnings := rbac.ValidatePolicy(policy)
	for _, w := range warnings {
		log.Warnf("rbac policy: [%s] %s", w.Kind, w.Message)
	}

	return nil
}

// AdminRoleName is the built-in role that grants every action on every
// scope. The first admin is assigned it in farmer's config file
// (users.admin, or Helm's farmer.bootstrapAdmin).
const AdminRoleName = "admin"

// ensureBuiltinAdminRoleLocked registers the built-in admin role unless
// the config file defines a role of that name, so a users.admin or legacy
// pubkeys.admin entry means what it says without a roles section. (The
// check this replaces only ran when no role at all was defined, which
// never happens: the viewer and operator roles are always registered, so
// a config-file admin had no role.) Must be called with policyMu held.
func ensureBuiltinAdminRoleLocked() error {
	if _, err := roleStore.Get(AdminRoleName); err == nil {
		return nil
	}
	return roleStore.Register(&rbac.Role{
		Name:  AdminRoleName,
		Rules: []rbac.Rule{{Action: rbac.ActionAdmin, Scope: "*"}},
	})
}

// currentPolicyLocked returns a Policy snapshot. Must be called with
// policyMu held (at least read).
func currentPolicyLocked() *rbac.Policy {
	return &rbac.Policy{
		Roles:   roleStore,
		Users:   userRoleMap,
		Cohorts: cohortReg,
	}
}

// CurrentPolicy returns the current RBAC policy for inspection.
func CurrentPolicy() *rbac.Policy {
	policyMu.RLock()
	defer policyMu.RUnlock()
	return currentPolicyLocked()
}

// SetPolicy sets the policy stores directly (for testing).
func SetPolicy(rs *rbac.RoleStore, urm *rbac.UserRoleMap, cr *rbac.Registry) {
	policyMu.Lock()
	defer policyMu.Unlock()
	roleStore = rs
	userRoleMap = urm
	cohortReg = cr
}

// CohortResolver returns a function that resolves a cohort name to its
// member sprouts, using the loaded cohort registry. Returns nil if no
// registry is loaded.
func CohortResolver(allSproutIDs []string) func(string) (map[string]bool, error) {
	policyMu.RLock()
	reg := cohortReg
	policyMu.RUnlock()

	if reg == nil {
		return nil
	}
	return func(name string) (map[string]bool, error) {
		return reg.Resolve(name, allSproutIDs)
	}
}

func GetPubkey() (string, error) {
	seed, err := getPrivateSeed()
	if err != nil {
		return "", err
	}
	kp, err := nkeys.FromSeed([]byte(seed))
	if err != nil {
		return "", err
	}
	pubkey, err := kp.PublicKey()
	if err != nil {
		return "", err
	}
	return pubkey, nil
}

func CreatePrivkey() error {
	_, err := getPrivateSeed()
	if !errors.Is(err, ErrNoPrivkey) {
		return ErrPrivkeyExists
	}
	_, err = createPrivateSeed()
	return err
}

func getPrivateSeed() (string, error) {
	seed := jety.GetString("privkey")
	if seed == "" {
		return "", ErrNoPrivkey
	}
	return seed, nil
}

// Sign signs a bus nonce with the local private key: the CLI's NKey
// authenticates its NATS connection (nats.Nkey) and signs nothing else.
// The bus chooses the nonce, so a signature from this key proves nothing
// to farmer, and farmer accepts no proof that rests on one: requests are
// sealed under the CLI box key instead (docs/design/
// imas-payload-encryption-design.md, Decision A, P1). There are no bearer
// tokens any more (J.3): nothing turns a signature into a credential.
func Sign(nonce []byte) ([]byte, error) {
	seed, err := getPrivateSeed()
	if err != nil {
		return nil, err
	}
	kp, err := nkeys.FromSeed([]byte(seed))
	if err != nil {
		return nil, err
	}
	b, err := kp.Sign(nonce)
	kp.Wipe()
	return b, err
}

// DangerouslyAllowRoot returns true if the farmer config has
// dangerously_allow_root set (dev only). It bypasses authentication on
// farmer's HTTP API for GET /files/ and the GET /v1/recipes routes
// (internal/api's Auth), and nothing else. It has no effect on the NATS
// API: every sealed imas.api.* request goes through the role and scope
// checks below for the user it opened under (owner decision 2026-10-04,
// PR #95).
func DangerouslyAllowRoot() bool {
	return jety.GetBool("dangerously_allow_root")
}

// ---- what a verified user may do ----------------------------------------
//
// Every check below takes a user ID (an NKey public key) that a sealed
// request opened under: internal/natsapi's router derives it from the
// registered CLI box key that opened the request, never from a field in
// the request. These functions only answer what that user may do.

// UserIdentity returns userID's role name and username, as the policy
// has them (config file, legacy pubkeys section, or the users store).
// Both are empty for a user the policy doesn't know.
func UserIdentity(userID string) (roleName, username string) {
	policyMu.RLock()
	defer policyMu.RUnlock()
	if userRoleMap != nil {
		roleName = userRoleMap.RoleName(userID)
		username = userRoleMap.Username(userID)
	}
	if roleName == "" {
		roleName = legacyRoleName(userID)
	}
	return roleName, username
}

// UserHasAction reports whether userID's role includes action, without
// scope checking (UserHasScopedAccess checks scope).
func UserHasAction(userID string, action rbac.Action) bool {
	role := lookupRole(userID)
	return role != nil && role.HasAction(action)
}

// UserHasScopedAccess reports whether userID's role permits action on
// every one of sproutIDs. allSproutIDs is the tenant's accepted sprouts,
// for resolving dynamic cohorts.
func UserHasScopedAccess(userID string, action rbac.Action, sproutIDs []string, allSproutIDs []string) bool {
	role := lookupRole(userID)
	if role == nil {
		return false
	}
	return role.HasScopedAccessMulti(action, sproutIDs, CohortResolver(allSproutIDs))
}

// UserScopeFilter returns the subset of sproutIDs userID's role permits
// for action: nil for a user with no role.
func UserScopeFilter(userID string, action rbac.Action, sproutIDs []string, allSproutIDs []string) []string {
	role := lookupRole(userID)
	if role == nil {
		return nil
	}
	return role.ScopeFilter(action, sproutIDs, CohortResolver(allSproutIDs))
}

// lookupRole returns the Role object for a pubkey, or nil if not found.
func lookupRole(pubkey string) *rbac.Role {
	policyMu.RLock()
	defer policyMu.RUnlock()

	if userRoleMap == nil || roleStore == nil {
		return nil
	}

	name := userRoleMap.RoleName(pubkey)
	if name == "" {
		name = legacyRoleName(pubkey)
	}
	if name == "" {
		return nil
	}

	role, err := roleStore.Get(name)
	if err != nil {
		return nil
	}
	return role
}

// legacyRoleName checks the legacy pubkeys config section.
// Must be called with policyMu held (at least read).
func legacyRoleName(pubkey string) string {
	pubkeysMap := jety.GetStringMap("pubkeys")
	for roleName, v := range pubkeysMap {
		keys := extractStringSlice(v)
		for _, k := range keys {
			if k == pubkey {
				return roleName
			}
		}
	}
	return ""
}

// extractStringSlice handles both []any and []string from config values.
func extractStringSlice(v any) []string {
	switch s := v.(type) {
	case []any:
		result := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	case []string:
		return s
	case string:
		return []string{s}
	default:
		return nil
	}
}

// ListAllUsers returns all configured users as a map of pubkey → role name.
func ListAllUsers() map[string]string {
	policyMu.RLock()
	defer policyMu.RUnlock()

	result := make(map[string]string)
	if userRoleMap != nil {
		for k, v := range userRoleMap.All() {
			result[k] = v
		}
	}

	// Add legacy users not already present
	pubkeysMap := jety.GetStringMap("pubkeys")
	for roleName, v := range pubkeysMap {
		keys := extractStringSlice(v)
		for _, k := range keys {
			if _, exists := result[k]; !exists {
				result[k] = roleName
			}
		}
	}

	return result
}

// ListRoles returns all configured role names.
func ListRoles() []string {
	policyMu.RLock()
	defer policyMu.RUnlock()
	if roleStore == nil {
		return nil
	}
	return roleStore.List()
}

// GetRole returns the full role definition by name.
func GetRole(name string) (*rbac.Role, error) {
	policyMu.RLock()
	defer policyMu.RUnlock()
	if roleStore == nil {
		return nil, rbac.ErrUnknownRole
	}
	return roleStore.Get(name)
}

// ErrBoxPubRequired: a user registered through the API must come with
// their CLI box public key (imas auth keygen), since a user with no key
// can't make a single request.
var ErrBoxPubRequired = errors.New("auth: the user's CLI box public key is required (they print it with imas auth keygen)")

// AddUser registers pubkey with roleName (and username, which may be
// empty) in the users store (store.go), together with boxPub as their
// first CLI box key, in one transaction: an auth_users row and an
// auth_cli_box_keys row every farmer replica reads, mirrored into the
// policy's user map. Nothing is written to farmer's config file. A pubkey
// the config file defines, or one already registered, is ErrUserExists;
// a box key any principal holds, or a farmer-side key, is refused
// (boxKeyClaimCheck, then the table's unique index).
//
// It is reached only through a sealed auth.users.add from an admin, so
// the bus can no longer forge it (Decision A).
func AddUser(pubkey, roleName, username, boxPub string) error {
	policyMu.Lock()
	defer policyMu.Unlock()

	// Validate the pubkey looks like an nkey.
	if !nkeys.IsValidPublicAccountKey(pubkey) {
		return ErrInvalidPubkey
	}
	if boxPub == "" {
		return ErrBoxPubRequired
	}
	if _, err := DecodeCLIBoxPub(boxPub); err != nil {
		return err
	}

	// Check that the role exists.
	if roleStore != nil {
		if _, err := roleStore.Get(roleName); err != nil {
			return err
		}
	}

	// Check the user isn't already assigned, by config or registration.
	if (userRoleMap != nil && userRoleMap.RoleName(pubkey) != "") || legacyRoleName(pubkey) != "" {
		return ErrUserExists
	}
	tenantID := usersTenantID()
	if boxKeyClaimCheck != nil {
		if err := boxKeyClaimCheck(tenantID, boxPub); err != nil {
			return err
		}
	}
	if err := registerUser(tenantID, pubkey, roleName, username, boxPub); err != nil {
		return err
	}

	// Mirror into the policy's map, which every lookup reads.
	if userRoleMap != nil {
		userRoleMap.Set(pubkey, roleName)
		if username != "" {
			userRoleMap.SetUsername(pubkey, username)
		}
	}
	return nil
}

// ResetUserCLIBoxKey is an admin's reset of userID's CLI box key, for a
// lost or stolen key: every key the user holds in the users tenant is
// retired and boxPub becomes their only active key, in one transaction.
// The user must be known to the policy (config file or users store). A
// retired key never comes back and a key any principal holds is refused,
// as at registration. Reached only through a sealed
// auth.users.resetkey from an admin.
func ResetUserCLIBoxKey(userID, boxPub string) error {
	if db == nil {
		return ErrStoreNotConfigured
	}
	if _, err := DecodeCLIBoxPub(boxPub); err != nil {
		return err
	}
	tenantID := usersTenantID()
	if lookupRole(userID) == nil {
		if _, _, found, err := RegisteredUser(tenantID, userID); err != nil || !found {
			if err != nil {
				return err
			}
			return ErrUnknownUser
		}
	}
	if boxKeyClaimCheck != nil {
		if err := boxKeyClaimCheck(tenantID, boxPub); err != nil {
			return err
		}
	}
	return db.Transaction(func(tx *gorm.DB) error {
		if err := retireCLIBoxKeysTx(tx, "tenant_id = ? AND user_id = ?", tenantID, userID); err != nil {
			return err
		}
		return createActiveCLIBoxKeyTx(tx, tenantID, userID, boxPub)
	})
}

// UserCLIBoxKeyFingerprints returns, for every user with an active CLI box
// key in the users tenant, that key's fingerprint (for auth.users).
func UserCLIBoxKeyFingerprints() (map[string]string, error) {
	if db == nil {
		return nil, ErrStoreNotConfigured
	}
	var rows []cliBoxKeyRow
	if err := db.Where("tenant_id = ? AND status = ?", usersTenantID(), CLIBoxKeyActive).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]string, len(rows))
	for _, r := range rows {
		if pub, err := DecodeCLIBoxPub(r.Pub); err == nil {
			out[r.UserID] = payloadbox.Fingerprint(pub)
		}
	}
	return out, nil
}

// UsersTenantID is the tenant CLI users, and their CLI box keys, belong
// to: farmer's farmerorganization (users are deployment-wide operators,
// owner decision 2026-10-04). A CLI pins this tenant and its box key, and
// its requests open only on that tenant's connection.
func UsersTenantID() string { return usersTenantID() }

// RemoveUser removes a user registered through the API: their auth_users
// row, every CLI box key they hold (retired, in the same transaction),
// and their entry in the policy's map. A user defined in farmer's config
// file is ErrUserInConfig: the API can't remove them consistently, since
// each replica re-reads its own file at start. Remove them from the file
// on every replica instead.
func RemoveUser(pubkey string) error {
	policyMu.Lock()
	defer policyMu.Unlock()

	_, _, registered, err := RegisteredUser(usersTenantID(), pubkey)
	if err != nil && !errors.Is(err, ErrStoreNotConfigured) {
		return err
	}
	if !registered {
		if (userRoleMap != nil && userRoleMap.RoleName(pubkey) != "") || legacyRoleName(pubkey) != "" {
			return ErrUserInConfig
		}
		return ErrUserNotFound
	}
	if _, err := deregisterUser(usersTenantID(), pubkey); err != nil {
		return err
	}
	if userRoleMap != nil {
		userRoleMap.Delete(pubkey)
	}
	return nil
}

// applyRegisteredUsersLocked mirrors every user registered through the
// API into the policy's user map, after LoadPolicy rebuilt it from the
// config file. A user the config file also defines keeps the config
// file's role. Must be called with policyMu held.
func applyRegisteredUsersLocked() error {
	if db == nil || userRoleMap == nil {
		return nil
	}
	roles, usernames, err := RegisteredUsers(usersTenantID())
	if err != nil {
		return fmt.Errorf("loading registered users: %w", err)
	}
	for id, role := range roles {
		if existing := userRoleMap.RoleName(id); existing != "" {
			if existing != role {
				log.Warnf("auth: user %s is in farmer's config as %q and registered as %q; the config file wins", id, existing, role)
			}
			continue
		}
		userRoleMap.Set(id, role)
		if u := usernames[id]; u != "" {
			userRoleMap.SetUsername(id, u)
		}
	}
	return nil
}

func GetPubkeysByRole(role string) ([]string, error) {
	err := jety.ReadInConfig()
	if err != nil {
		return []string{}, err
	}
	authKeySet := jety.GetStringMap("pubkeys")
	if len(authKeySet) == 0 {
		return []string{}, ErrNoPubkeys
	}
	i, ok := authKeySet[role]
	if !ok {
		return []string{}, ErrMissingAdmin
	}
	keys := []string{}
	if adminKey, ok := i.(string); !ok {
		if adminKeyList, ok := i.([]interface{}); ok {
			for _, k := range adminKeyList {
				if str, ok := k.(string); ok {
					keys = append(keys, str)
				} else {
					return []string{}, ErrInvalidPubkey
				}
			}
			return keys, nil
		} else {
			return []string{}, ErrInvalidPubkey
		}
	} else {
		return []string{adminKey}, nil
	}
}

func containsKey(slice []string, key string) bool {
	for _, s := range slice {
		if s == key {
			return true
		}
	}
	return false
}

func createPrivateSeed() (string, error) {
	kp, err := nkeys.CreateAccount()
	if err != nil {
		return "", err
	}
	seed, err := kp.Seed()
	if err != nil {
		return "", err
	}
	jety.Set("privkey", string(seed))
	jety.WriteConfig()
	return string(seed), nil
}
