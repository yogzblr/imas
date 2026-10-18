package pki

import (
	"os"
	"path/filepath"
	"testing"

	jwt "github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
	"github.com/taigrr/jety"

	"github.com/yogzblr/imas/internal/auth"
	"github.com/yogzblr/imas/internal/rbac"
)

// useAdminConfig points farmer's config at a readable file (as in
// production, /etc/imas/farmer) whose pubkeys.admin is keys.
func useAdminConfig(t *testing.T, keys ...string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "farmer.toml")
	if err := os.WriteFile(path, []byte("# test config\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	jety.SetConfigType("toml")
	jety.SetConfigFile(path)
	setAdminKeys(keys...)
	t.Cleanup(func() {
		jety.Set("pubkeys", nil)
		jety.Set("users", nil)
		jety.Set("roles", nil)
		jety.SetConfigFile("")
	})
}

// loadPolicy loads farmer's auth policy from the config, as farmer does at
// start (loadAuthPolicy), on the test database.
func loadPolicy(t *testing.T) {
	t.Helper()
	if err := db.AutoMigrate(rbac.Models()...); err != nil {
		t.Fatal(err)
	}
	rbac.SetDB(db)
	t.Cleanup(func() { rbac.SetDB(nil); auth.SetPolicy(nil, nil, nil) })
	if err := auth.LoadPolicy(); err != nil {
		t.Fatal(err)
	}
}

func setAdminKeys(keys ...string) {
	if len(keys) == 0 {
		jety.Set("pubkeys", nil)
		return
	}
	list := make([]interface{}, len(keys))
	for i, k := range keys {
		list[i] = k
	}
	jety.Set("pubkeys", map[string]interface{}{"admin": list})
}

func newUserKey(t *testing.T) string {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := kp.PublicKey()
	return pub
}

// syncTenantAccount runs the Account rebuild as ReloadNKeys does and
// returns whether it re-signed, and the Account it holds.
func syncTenantAccount(t *testing.T) (bool, *jwt.AccountClaims) {
	t.Helper()
	mat, err := ensureNatsAuth()
	if err != nil {
		t.Fatal(err)
	}
	changed, err := syncNatsAuth(mat)
	if err != nil {
		t.Fatalf("syncNatsAuth: %v", err)
	}
	ac, err := jwt.DecodeAccountClaims(mat.tenantJWT)
	if err != nil {
		t.Fatal(err)
	}
	return changed, ac
}

func cliAdminKeyRecorded(t *testing.T, key string) bool {
	t.Helper()
	var n int64
	if err := db.Model(&cliAdminKeyRow{}).Where("tenant_id = ? AND nkey = ?", currentTenantID(), key).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// Removing a CLI admin key from farmer's config revokes it (security
// review 2026-10, I6): the Account is re-signed with its revocation, the
// NKey is on the tenant's revoked list, its CLI box key no longer opens
// anything, and putting it back in the config doesn't grant it again.
func TestRemovedCLIAdminKeyIsRevoked(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	keep, removed := newUserKey(t), newUserKey(t)
	useAdminConfig(t, keep, removed)

	_, ac := syncTenantAccount(t)
	for _, k := range []string{keep, removed} {
		if _, revoked := ac.Revocations[k]; revoked {
			t.Fatalf("configured admin key %s is revoked", k)
		}
		if !cliAdminKeyRecorded(t, k) {
			t.Fatalf("configured admin key %s was not recorded as granted", k)
		}
	}
	loadPolicy(t)
	boxPub := otherBoxPub(t)
	if err := auth.RegisterCLIBoxKey(auth.UsersTenantID(), removed, boxPub); err != nil {
		t.Fatal(err)
	}
	if changed, _ := syncTenantAccount(t); changed {
		t.Fatal("an unchanged config re-signed the Account")
	}

	// A SIGHUP's rebuild re-reads the config; the policy loaded at start
	// still has the key, and that mustn't keep it.
	setAdminKeys(keep)
	changed, ac := syncTenantAccount(t)
	if !changed {
		t.Fatal("removing an admin key didn't re-sign the Account")
	}
	if ac.Revocations[removed] == 0 {
		t.Fatal("the removed admin key isn't revoked on the Account")
	}
	if _, revoked := ac.Revocations[keep]; revoked {
		t.Fatal("the admin key still in the config was revoked")
	}
	if ok, err := isNKeyRevoked(currentTenantID(), removed); err != nil || !ok {
		t.Fatalf("removed key on the tenant's revoked list: %v, %v; want true", ok, err)
	}
	if active, grace, err := auth.ValidCLIBoxKeys(auth.UsersTenantID(), removed); active != "" || len(grace) != 0 {
		t.Fatalf("the removed key's CLI box key still opens requests: active %q, grace %v, %v", active, grace, err)
	}
	if cliAdminKeyRecorded(t, removed) {
		t.Fatal("the removed key is still recorded as granted")
	}

	// Back in the config: it stays revoked, and isn't recorded again.
	setAdminKeys(keep, removed)
	_, ac = syncTenantAccount(t)
	if ac.Revocations[removed] == 0 {
		t.Fatal("putting the removed key back in the config granted it again")
	}
	if cliAdminKeyRecorded(t, removed) {
		t.Fatal("a revoked admin key was recorded as granted")
	}
}

// Taking pubkeys.admin out of the config altogether removes its keys too.
func TestCLIAdminKeysRemovedWithTheirSection(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	key := newUserKey(t)
	useAdminConfig(t, key)
	syncTenantAccount(t)

	setAdminKeys()
	if _, ac := syncTenantAccount(t); ac.Revocations[key] == 0 {
		t.Fatal("an admin key whose pubkeys section was removed isn't revoked")
	}
}

// A config that can't be read revokes nothing: only a config read without
// error that no longer names a key removes it.
func TestUnreadableConfigRevokesNoCLIAdminKey(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	key := newUserKey(t)
	useAdminConfig(t, key)
	syncTenantAccount(t)

	jety.SetConfigFile(filepath.Join(t.TempDir(), "missing.toml"))
	setAdminKeys()
	if _, ac := syncTenantAccount(t); ac.Revocations[key] != 0 {
		t.Fatal("an unreadable config revoked an admin key")
	}
	if !cliAdminKeyRecorded(t, key) {
		t.Fatal("an unreadable config dropped an admin key's record")
	}
	if ok, _ := isNKeyRevoked(currentTenantID(), key); ok {
		t.Fatal("an unreadable config put an admin key on the revoked list")
	}
}

// The admins farmer's config names today are users.admin entries: one
// removed from there is revoked like a legacy pubkeys.admin key, and one
// moved between the two sections stays granted.
func TestUsersSectionAdminKeyRemovedIsRevoked(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	moved, removed := newUserKey(t), newUserKey(t)
	useAdminConfig(t, moved)
	jety.Set("users", map[string]interface{}{"admin": []interface{}{map[string]interface{}{"pubkey": removed, "username": "ops"}}})
	if _, ac := syncTenantAccount(t); !cliAdminKeyRecorded(t, removed) || !cliAdminKeyRecorded(t, moved) || ac.Revocations[removed] != 0 {
		t.Fatal("the users.admin and pubkeys.admin keys weren't both granted and recorded")
	}

	setAdminKeys()
	jety.Set("users", map[string]interface{}{"admin": []interface{}{moved}})
	_, ac := syncTenantAccount(t)
	if ac.Revocations[removed] == 0 {
		t.Fatal("an admin removed from users.admin isn't revoked")
	}
	if ac.Revocations[moved] != 0 || !cliAdminKeyRecorded(t, moved) {
		t.Fatal("an admin moved from pubkeys.admin to users.admin lost its grant")
	}
}

// A key that leaves the admins but is still a user (another role in the
// config, or registered through the API) is no longer an admin key, and
// is not revoked either; once it is no user at all, it is.
func TestDemotedCLIAdminKeyIsNotRevoked(t *testing.T) {
	setupTestPKI(t)
	useRealFarmerKey(t)
	setupTenantBoxOpenBao(t) // AddUser checks the box key against the tenant's
	key := newUserKey(t)
	useAdminConfig(t, key)
	syncTenantAccount(t)

	setAdminKeys()
	jety.Set("users", map[string]interface{}{"operator": []interface{}{map[string]interface{}{"pubkey": key}}})
	if _, ac := syncTenantAccount(t); ac.Revocations[key] != 0 {
		t.Fatal("an admin key demoted to operator was revoked")
	}
	if ok, _ := isNKeyRevoked(currentTenantID(), key); ok {
		t.Fatal("a demoted admin key is on the revoked list")
	}
	jety.Set("users", nil)
	if _, ac := syncTenantAccount(t); ac.Revocations[key] == 0 {
		t.Fatal("an admin key removed from the users section too isn't revoked")
	}

	// A CLI user ID is an NKey public key of the Account kind (AddUser
	// checks it).
	akp, _ := nkeys.CreateAccount()
	registered, _ := akp.PublicKey()
	setAdminKeys(registered)
	syncTenantAccount(t)
	// Out of the config and registered through the API instead.
	setAdminKeys()
	loadPolicy(t)
	if err := auth.AddUser(registered, auth.AdminRoleName, "ops", otherBoxPub(t)); err != nil {
		t.Fatal(err)
	}
	if _, ac := syncTenantAccount(t); ac.Revocations[registered] != 0 {
		t.Fatal("an admin key registered in the users store was revoked when it left the config")
	}
}
