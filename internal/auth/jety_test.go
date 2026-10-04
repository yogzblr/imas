package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nats-io/nkeys"
	"github.com/taigrr/jety"

	"github.com/yogzblr/imas/internal/rbac"
)

// setupJetyForTest points jety at a temp config file (needed for WriteConfig)
// and clears all auth-related keys.
func setupJetyForTest(t *testing.T) {
	t.Helper()
	newTestDB(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte("# test config\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	jety.SetConfigType("toml")
	jety.SetConfigFile(path)
	// Clear all auth-related keys.
	jety.Set("privkey", "")
	jety.Set("pubkeys", nil)
	jety.Set("users", nil)
	jety.Set("roles", nil)
	jety.Set("cohorts", nil)
	jety.Set("dangerously_allow_root", false)
}

// clearJetyKeys resets jety keys used by auth to avoid test pollution.
func clearJetyKeys(t *testing.T) {
	t.Helper()
	jety.Set("privkey", "")
	jety.Set("pubkeys", nil)
	jety.Set("users", nil)
	jety.Set("dangerously_allow_root", false)
	jety.Set("roles", nil)
	jety.Set("cohorts", nil)
}

// --- getPrivateSeed / GetPubkey / CreatePrivkey / Sign ---

func TestGetPrivateSeedEmpty(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)

	_, err := getPrivateSeed()
	if err != ErrNoPrivkey {
		t.Errorf("expected ErrNoPrivkey, got %v", err)
	}
}

func TestGetPrivateSeedPresent(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)

	kp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	seed, err := kp.Seed()
	if err != nil {
		t.Fatal(err)
	}
	jety.Set("privkey", string(seed))

	got, err := getPrivateSeed()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != string(seed) {
		t.Error("seed mismatch")
	}
}

func TestGetPubkeyNoPrivkey(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)

	_, err := GetPubkey()
	if err != ErrNoPrivkey {
		t.Errorf("expected ErrNoPrivkey, got %v", err)
	}
}

func TestGetPubkeyWithPrivkey(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)

	kp, _ := nkeys.CreateAccount()
	seed, _ := kp.Seed()
	expectedPK, _ := kp.PublicKey()
	jety.Set("privkey", string(seed))

	pk, err := GetPubkey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pk != expectedPK {
		t.Errorf("got pubkey %q, want %q", pk, expectedPK)
	}
}

func TestCreatePrivkeyWhenAlreadyExists(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)

	kp, _ := nkeys.CreateAccount()
	seed, _ := kp.Seed()
	jety.Set("privkey", string(seed))

	err := CreatePrivkey()
	if err != ErrPrivkeyExists {
		t.Errorf("expected ErrPrivkeyExists, got %v", err)
	}
}

func TestCreatePrivkeyWhenMissing(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)

	err := CreatePrivkey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	seed, err := getPrivateSeed()
	if err != nil {
		t.Fatalf("after CreatePrivkey, getPrivateSeed failed: %v", err)
	}
	if seed == "" {
		t.Error("seed should not be empty after CreatePrivkey")
	}
}

func TestSignNoPrivkey(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)

	_, err := Sign([]byte("test-nonce"))
	if err != ErrNoPrivkey {
		t.Errorf("expected ErrNoPrivkey, got %v", err)
	}
}

func TestSignWithPrivkey(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)

	kp, _ := nkeys.CreateAccount()
	seed, _ := kp.Seed()
	jety.Set("privkey", string(seed))

	nonce := []byte("test-nonce-12345")
	sig, err := Sign(nonce)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sig) == 0 {
		t.Error("expected non-empty signature")
	}

	pk, _ := kp.PublicKey()
	verifier, _ := nkeys.FromPublicKey(pk)
	if err := verifier.Verify(nonce, sig); err != nil {
		t.Errorf("signature verification failed: %v", err)
	}
}

// --- GetPubkeysByRole ---

func TestGetPubkeysByRoleNoPubkeys(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)

	_, err := GetPubkeysByRole("admin")
	if err != ErrNoPubkeys {
		t.Errorf("expected ErrNoPubkeys, got %v", err)
	}
}

func TestGetPubkeysByRoleMissingRole(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)

	jety.Set("pubkeys", map[string]interface{}{
		"admin": []interface{}{"AKEY123"},
	})

	_, err := GetPubkeysByRole("operator")
	if err != ErrMissingAdmin {
		t.Errorf("expected ErrMissingAdmin, got %v", err)
	}
}

func TestGetPubkeysByRoleSingleKey(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)

	jety.Set("pubkeys", map[string]interface{}{
		"admin": "AKEY123",
	})

	keys, err := GetPubkeysByRole("admin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 || keys[0] != "AKEY123" {
		t.Errorf("expected [AKEY123], got %v", keys)
	}
}

func TestGetPubkeysByRoleMultipleKeys(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)

	jety.Set("pubkeys", map[string]interface{}{
		"admin": []interface{}{"AKEY1", "AKEY2", "AKEY3"},
	})

	keys, err := GetPubkeysByRole("admin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d: %v", len(keys), keys)
	}
}

// --- legacyRoleName ---

func TestLegacyRoleNameFound(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)

	jety.Set("pubkeys", map[string]interface{}{
		"admin":    []interface{}{"AADMINKEY1"},
		"operator": []interface{}{"AOPKEY1", "AOPKEY2"},
	})

	policyMu.RLock()
	name := legacyRoleName("AOPKEY2")
	policyMu.RUnlock()

	if name != "operator" {
		t.Errorf("expected 'operator', got %q", name)
	}
}

func TestLegacyRoleNameNotFound(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)

	jety.Set("pubkeys", map[string]interface{}{
		"admin": []interface{}{"AADMINKEY1"},
	})

	policyMu.RLock()
	name := legacyRoleName("AUNKNOWNKEY")
	policyMu.RUnlock()

	if name != "" {
		t.Errorf("expected empty, got %q", name)
	}
}

// --- AddUser / RemoveUser ---

func TestAddUserSuccess(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)

	rs := rbac.NewRoleStore()
	rs.Register(&rbac.Role{
		Name:  "admin",
		Rules: []rbac.Rule{{Action: rbac.ActionAdmin, Scope: "*"}},
	})
	urm := rbac.NewUserRoleMap()
	SetPolicy(rs, urm, nil)
	defer SetPolicy(nil, nil, nil)

	kp, _ := nkeys.CreateAccount()
	pk, _ := kp.PublicKey()

	err := AddUser(pk, "admin", "", newBoxPub(t))
	if err != nil {
		t.Fatalf("AddUser failed: %v", err)
	}

	if urm.RoleName(pk) != "admin" {
		t.Error("user should be assigned admin role")
	}
}

func TestAddUserInvalidPubkey(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)

	rs := rbac.NewRoleStore()
	rs.Register(&rbac.Role{
		Name:  "admin",
		Rules: []rbac.Rule{{Action: rbac.ActionAdmin, Scope: "*"}},
	})
	SetPolicy(rs, rbac.NewUserRoleMap(), nil)
	defer SetPolicy(nil, nil, nil)

	err := AddUser("not-a-valid-key", "admin", "", newBoxPub(t))
	if err != ErrInvalidPubkey {
		t.Errorf("expected ErrInvalidPubkey, got %v", err)
	}
}

func TestAddUserUnknownRole(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)

	rs := rbac.NewRoleStore()
	rs.Register(&rbac.Role{
		Name:  "admin",
		Rules: []rbac.Rule{{Action: rbac.ActionAdmin, Scope: "*"}},
	})
	SetPolicy(rs, rbac.NewUserRoleMap(), nil)
	defer SetPolicy(nil, nil, nil)

	kp, _ := nkeys.CreateAccount()
	pk, _ := kp.PublicKey()

	err := AddUser(pk, "nonexistent-role", "", newBoxPub(t))
	if err == nil {
		t.Error("expected error for unknown role")
	}
}

func TestAddUserAlreadyExists(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)

	rs := rbac.NewRoleStore()
	rs.Register(&rbac.Role{
		Name:  "admin",
		Rules: []rbac.Rule{{Action: rbac.ActionAdmin, Scope: "*"}},
	})
	urm := rbac.NewUserRoleMap()

	kp, _ := nkeys.CreateAccount()
	pk, _ := kp.PublicKey()
	urm.Set(pk, "admin")

	SetPolicy(rs, urm, nil)
	defer SetPolicy(nil, nil, nil)

	err := AddUser(pk, "admin", "", newBoxPub(t))
	if err != ErrUserExists {
		t.Errorf("expected ErrUserExists, got %v", err)
	}
}

// A user added through the API can be removed through it; their row and
// their policy entry go, and nothing is written to the config file.
func TestRemoveUserSuccess(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)

	rs := rbac.NewRoleStore()
	rs.Register(&rbac.Role{
		Name:  "admin",
		Rules: []rbac.Rule{{Action: rbac.ActionAdmin, Scope: "*"}},
	})
	urm := rbac.NewUserRoleMap()
	SetPolicy(rs, urm, nil)
	defer SetPolicy(nil, nil, nil)

	kp, _ := nkeys.CreateAccount()
	pk, _ := kp.PublicKey()
	if err := AddUser(pk, "admin", "", newBoxPub(t)); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if err := RemoveUser(pk); err != nil {
		t.Fatalf("RemoveUser failed: %v", err)
	}
	if urm.RoleName(pk) != "" {
		t.Error("user should be removed after RemoveUser")
	}
	if _, _, found, _ := RegisteredUser(usersTenantID(), pk); found {
		t.Error("registration should be gone after RemoveUser")
	}
	if err := RemoveUser(pk); err != ErrUserNotFound {
		t.Errorf("second RemoveUser = %v, want ErrUserNotFound", err)
	}
}

// A user defined in the config file (users or legacy pubkeys) can't be
// removed through the API: each replica re-reads its own file at start,
// so a removal there wouldn't hold (Open item 11).
func TestRemoveUserDefinedInConfigIsRefused(t *testing.T) {
	for _, section := range []string{"users", "pubkeys"} {
		t.Run(section, func(t *testing.T) {
			setupJetyForTest(t)
			defer clearJetyKeys(t)

			kp, _ := nkeys.CreateAccount()
			pk, _ := kp.PublicKey()
			jety.Set(section, map[string]interface{}{"admin": []interface{}{pk}})

			urm := rbac.NewUserRoleMap()
			urm.Set(pk, "admin")
			SetPolicy(rbac.NewRoleStore(), urm, nil)
			defer SetPolicy(nil, nil, nil)

			if err := RemoveUser(pk); err != ErrUserInConfig {
				t.Fatalf("RemoveUser = %v, want ErrUserInConfig", err)
			}
			if urm.RoleName(pk) != "admin" {
				t.Error("a config-defined user lost their role")
			}
		})
	}
}

func TestRemoveUserNotFound(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)

	SetPolicy(rbac.NewRoleStore(), rbac.NewUserRoleMap(), nil)
	defer SetPolicy(nil, nil, nil)

	err := RemoveUser("AUNKNOWNKEY")
	if err != ErrUserNotFound {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}
}

// --- LoadPolicy ---

func TestLoadPolicyEmpty(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)
	defer SetPolicy(nil, nil, nil)

	err := LoadPolicy()
	if err != nil {
		t.Fatalf("LoadPolicy with empty config: %v", err)
	}
}

func TestLoadPolicyWithRolesAndUsers(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)
	defer SetPolicy(nil, nil, nil)

	kp, _ := nkeys.CreateAccount()
	pk, _ := kp.PublicKey()

	jety.Set("roles", map[string]interface{}{
		"admin": []interface{}{
			map[string]interface{}{"action": "admin", "scope": "*"},
		},
	})
	jety.Set("users", map[string]interface{}{
		"admin": []interface{}{pk},
	})

	err := LoadPolicy()
	if err != nil {
		t.Fatalf("LoadPolicy failed: %v", err)
	}

	p := CurrentPolicy()
	if p == nil {
		t.Fatal("CurrentPolicy nil after LoadPolicy")
	}

	roles := ListRoles()
	found := false
	for _, r := range roles {
		if r == "admin" {
			found = true
		}
	}
	if !found {
		t.Error("expected admin role after LoadPolicy")
	}

	users := ListAllUsers()
	if users[pk] != "admin" {
		t.Errorf("expected user %q to be admin, got %q", pk, users[pk])
	}
}

func TestLoadPolicyWithLegacyPubkeys(t *testing.T) {
	// When no explicit roles are defined beyond builtins,
	// legacy pubkeys should still be resolvable via legacyRoleName.
	setupJetyForTest(t)
	defer clearJetyKeys(t)
	defer SetPolicy(nil, nil, nil)

	kp, _ := nkeys.CreateAccount()
	pk, _ := kp.PublicKey()

	jety.Set("pubkeys", map[string]interface{}{
		"admin": []interface{}{pk},
	})

	err := LoadPolicy()
	if err != nil {
		t.Fatalf("LoadPolicy failed: %v", err)
	}

	// The legacy key should be visible via ListAllUsers.
	users := ListAllUsers()
	if users[pk] != "admin" {
		t.Errorf("expected legacy user %q to be admin, got %q", pk, users[pk])
	}

	// Builtins (viewer, operator) should be present.
	roles := ListRoles()
	if len(roles) < 2 {
		t.Errorf("expected at least 2 builtin roles, got %d", len(roles))
	}
}

func TestLoadPolicyWithCohorts(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)
	defer SetPolicy(nil, nil, nil)

	jety.Set("cohorts", map[string]interface{}{
		"web-servers": map[string]interface{}{
			"type":    "static",
			"members": []interface{}{"web-1", "web-2"},
		},
	})

	err := LoadPolicy()
	if err != nil {
		t.Fatalf("LoadPolicy with cohorts failed: %v", err)
	}

	resolver := CohortResolver([]string{"web-1", "web-2", "db-1"})
	if resolver == nil {
		t.Fatal("expected cohort resolver after LoadPolicy with cohorts")
	}

	members, err := resolver("web-servers")
	if err != nil {
		t.Fatalf("resolver error: %v", err)
	}
	if len(members) != 2 {
		t.Errorf("expected 2 members, got %d", len(members))
	}
}

func TestLoadPolicyRejectsDuplicateUsernames(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)
	defer SetPolicy(nil, nil, nil)

	jety.Set("users", map[string]interface{}{
		"admin": []interface{}{
			map[string]interface{}{"pubkey": "KEY_A", "username": "alice"},
		},
		"viewer": []interface{}{
			map[string]interface{}{"pubkey": "KEY_B", "username": "alice"},
		},
	})

	err := LoadPolicy()
	if err == nil {
		t.Fatal("expected LoadPolicy to reject config with duplicate usernames")
	}
	if !strings.Contains(err.Error(), "duplicate username") {
		t.Errorf("error should mention duplicate username, got: %v", err)
	}
}

func TestLoadPolicyAcceptsUniqueUsernames(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)
	defer SetPolicy(nil, nil, nil)

	jety.Set("users", map[string]interface{}{
		"admin": []interface{}{
			map[string]interface{}{"pubkey": "KEY_A", "username": "alice"},
		},
		"viewer": []interface{}{
			map[string]interface{}{"pubkey": "KEY_B", "username": "bob"},
		},
	})

	err := LoadPolicy()
	if err != nil {
		t.Fatalf("LoadPolicy should accept unique usernames, got: %v", err)
	}
}

// --- DangerouslyAllowRoot bypass with jety ---

func TestDangerouslyAllowRootEnabled(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)

	jety.Set("dangerously_allow_root", true)

	if !DangerouslyAllowRoot() {
		t.Error("expected DangerouslyAllowRoot to return true")
	}

	// The bypass is RBAC only: the user is still one a sealed request
	// opened under (internal/natsapi), never a value from a body.
	if !UserHasAction("AUNKNOWN", rbac.ActionCook) {
		t.Error("UserHasAction should return true with bypass")
	}
	if !UserHasScopedAccess("AUNKNOWN", rbac.ActionCook, []string{"s1"}, nil) {
		t.Error("UserHasScopedAccess should return true with bypass")
	}

	sprouts := []string{"s1", "s2"}
	filtered := UserScopeFilter("AUNKNOWN", rbac.ActionCook, sprouts, nil)
	if len(filtered) != 2 {
		t.Errorf("UserScopeFilter should return all sprouts with bypass, got %d", len(filtered))
	}
}

// --- createPrivateSeed ---

func TestCreatePrivateSeed(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)

	seed, err := createPrivateSeed()
	if err != nil {
		t.Fatalf("createPrivateSeed failed: %v", err)
	}
	if seed == "" {
		t.Error("expected non-empty seed")
	}

	kp, err := nkeys.FromSeed([]byte(seed))
	if err != nil {
		t.Fatalf("invalid seed: %v", err)
	}
	pk, err := kp.PublicKey()
	if err != nil {
		t.Fatalf("couldn't get pubkey from seed: %v", err)
	}
	if !nkeys.IsValidPublicAccountKey(pk) {
		t.Error("pubkey from seed is not valid account key")
	}
}

// --- ListAllUsers with legacy keys ---

func TestListAllUsersWithLegacyKeys(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)

	jety.Set("pubkeys", map[string]interface{}{
		"admin":    []interface{}{"ALEGACY1", "ALEGACY2"},
		"operator": []interface{}{"ALEGACY3"},
	})

	SetPolicy(rbac.NewRoleStore(), rbac.NewUserRoleMap(), nil)
	defer SetPolicy(nil, nil, nil)

	users := ListAllUsers()
	if len(users) < 3 {
		t.Errorf("expected at least 3 legacy users, got %d: %v", len(users), users)
	}
	if users["ALEGACY1"] != "admin" {
		t.Errorf("ALEGACY1 role = %q, want admin", users["ALEGACY1"])
	}
	if users["ALEGACY3"] != "operator" {
		t.Errorf("ALEGACY3 role = %q, want operator", users["ALEGACY3"])
	}
}

func TestListAllUsersMixedModernAndLegacy(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)

	jety.Set("pubkeys", map[string]interface{}{
		"admin": []interface{}{"ALEGACYKEY"},
	})

	urm := rbac.NewUserRoleMap()
	urm.Set("AMODERNKEY", "operator")

	SetPolicy(rbac.NewRoleStore(), urm, nil)
	defer SetPolicy(nil, nil, nil)

	users := ListAllUsers()
	if users["AMODERNKEY"] != "operator" {
		t.Errorf("modern key role = %q, want operator", users["AMODERNKEY"])
	}
	if users["ALEGACYKEY"] != "admin" {
		t.Errorf("legacy key role = %q, want admin", users["ALEGACYKEY"])
	}
}

// --- End-to-end: a config-file admin with no roles section ---

// users.admin in farmer's config (the first admin, or Helm's
// farmer.bootstrapAdmin) means the built-in admin role, even though the
// viewer and operator roles are always registered: the check this
// replaced only ran when no role was defined at all, so such an admin had
// no role.
func TestConfigAdminGetsBuiltinAdminRole(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)

	kp, _ := nkeys.CreateAccount()
	pk, _ := kp.PublicKey()
	legacy, _ := nkeys.CreateAccount()
	legacyPK, _ := legacy.PublicKey()
	jety.Set("users", map[string]any{"admin": []any{map[string]any{"pubkey": pk, "username": "alice"}}})
	jety.Set("pubkeys", map[string]any{"admin": []any{legacyPK}})
	if err := LoadPolicy(); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	defer SetPolicy(nil, nil, nil)

	for _, u := range []string{pk, legacyPK} {
		if !UserHasAction(u, rbac.ActionAdmin) || !UserHasAction(u, rbac.ActionPKI) {
			t.Errorf("config admin %s has no admin access", u)
		}
	}
	if role, name := UserIdentity(pk); role != "admin" || name != "alice" {
		t.Errorf("UserIdentity = %q, %q", role, name)
	}
}

// A config file that defines its own admin role keeps it.
func TestConfigAdminRoleNotReplaced(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)

	kp, _ := nkeys.CreateAccount()
	pk, _ := kp.PublicKey()
	jety.Set("roles", map[string]any{"admin": []any{map[string]any{"action": "view"}}})
	jety.Set("users", map[string]any{"admin": []any{pk}})
	if err := LoadPolicy(); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	defer SetPolicy(nil, nil, nil)

	if UserHasAction(pk, rbac.ActionPKI) || !UserHasAction(pk, rbac.ActionView) {
		t.Error("the config file's own admin role was replaced by the built-in one")
	}
}
