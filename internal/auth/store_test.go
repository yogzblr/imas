package auth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nkeys"
	"github.com/taigrr/jety"
	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/rbac"
)

func newBoxPub(t *testing.T) string {
	t.Helper()
	pub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(pub[:])
}

func newUserID(t *testing.T) string {
	t.Helper()
	kp, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := kp.PublicKey()
	return pk
}

// adminPolicyConfig sets a config with an admin role and the given
// config-file users, and loads it, as a farmer start does.
func adminPolicyConfig(t *testing.T, configUsers ...string) {
	t.Helper()
	jety.Set("roles", map[string]interface{}{
		"admin": []interface{}{map[string]interface{}{"action": "admin", "scope": "*"}},
	})
	users := []interface{}{}
	for _, u := range configUsers {
		users = append(users, u)
	}
	jety.Set("users", map[string]interface{}{"admin": users})
	if err := LoadPolicy(); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
}

// Open item 11: a user added through the API on one replica must survive
// another replica's start, which rebuilds the policy from its own config
// file. Two replicas share the database; the file is never written.
func TestAddedUserSurvivesAnotherReplicasStart(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)
	defer SetPolicy(nil, nil, nil)
	cfgPath := jety.ConfigFileUsed()
	before, _ := os.ReadFile(cfgPath)

	firstAdmin := newUserID(t)
	adminPolicyConfig(t, firstAdmin)
	added := newUserID(t)
	if err := AddUser(added, "admin", "", newBoxPub(t)); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if after, _ := os.ReadFile(cfgPath); string(after) != string(before) {
		t.Errorf("AddUser wrote the config file:\n%s", after)
	}

	// "Replica B" starts with the same (unchanged) config file.
	adminPolicyConfig(t, firstAdmin)
	if r := lookupRole(added); r == nil || r.Name != "admin" {
		t.Fatalf("added user's role after another replica's start = %v, want admin", r)
	}
	if ListAllUsers()[added] != "admin" {
		t.Error("added user missing from ListAllUsers")
	}

	// Removed on "replica B", it stays removed after "replica A" starts.
	if err := RemoveUser(added); err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	adminPolicyConfig(t, firstAdmin)
	if r := lookupRole(added); r != nil {
		t.Fatalf("removed user came back as %s", r.Name)
	}
	if lookupRole(firstAdmin) == nil {
		t.Fatal("the config file's admin lost their role")
	}
}

func TestAddUserRefusesConfigAndRegisteredUsers(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)
	defer SetPolicy(nil, nil, nil)
	firstAdmin := newUserID(t)
	adminPolicyConfig(t, firstAdmin)
	if err := AddUser(firstAdmin, "admin", "", newBoxPub(t)); !errors.Is(err, ErrUserExists) {
		t.Errorf("adding a config user: %v, want ErrUserExists", err)
	}
	u := newUserID(t)
	if err := AddUser(u, "admin", "", newBoxPub(t)); err != nil {
		t.Fatal(err)
	}
	if err := AddUser(u, "admin", "", newBoxPub(t)); !errors.Is(err, ErrUserExists) {
		t.Errorf("adding twice: %v, want ErrUserExists", err)
	}
}

func TestAddUserWithoutStoreFails(t *testing.T) {
	setupJetyForTest(t)
	defer clearJetyKeys(t)
	defer SetPolicy(nil, nil, nil)
	adminPolicyConfig(t)
	SetDB(nil)
	if err := AddUser(newUserID(t), "admin", "", newBoxPub(t)); !errors.Is(err, ErrStoreNotConfigured) {
		t.Fatalf("AddUser without a store: %v, want ErrStoreNotConfigured", err)
	}
}

// setupKeyStore loads a policy with one config admin and returns it.
func setupKeyStore(t *testing.T) string {
	t.Helper()
	setupJetyForTest(t)
	t.Cleanup(func() { clearJetyKeys(t); SetPolicy(nil, nil, nil) })
	admin := newUserID(t)
	adminPolicyConfig(t, admin)
	return admin
}

func TestRegisterCLIBoxKey(t *testing.T) {
	user := setupKeyStore(t)
	k1 := newBoxPub(t)

	if err := RegisterCLIBoxKey("t_a", newUserID(t), k1); !errors.Is(err, ErrUnknownUser) {
		t.Errorf("unknown user: %v, want ErrUnknownUser", err)
	}
	if err := RegisterCLIBoxKey("t_a", user, base64.StdEncoding.EncodeToString(make([]byte, 32))); err == nil {
		t.Error("an all-zero (low-order) key registered")
	}
	if err := RegisterCLIBoxKey("t_a", user, "not base64"); err == nil {
		t.Error("a malformed key registered")
	}
	if err := RegisterCLIBoxKey("t_a", user, k1); err != nil {
		t.Fatal(err)
	}
	if err := RegisterCLIBoxKey("t_a", user, k1); err != nil {
		t.Errorf("re-registering the active key: %v, want nil", err)
	}
	if err := RegisterCLIBoxKey("t_a", user, newBoxPub(t)); !errors.Is(err, ErrCLIBoxKeyExists) {
		t.Errorf("a second key: %v, want ErrCLIBoxKeyExists", err)
	}
	// The same key for anyone else, in any tenant, is refused.
	other := newUserID(t)
	if err := AddUser(other, "admin", "", newBoxPub(t)); err != nil {
		t.Fatal(err)
	}
	if err := RegisterCLIBoxKey("t_a", other, k1); !errors.Is(err, ErrCLIBoxKeyInUse) {
		t.Errorf("another user's key: %v, want ErrCLIBoxKeyInUse", err)
	}
	if err := RegisterCLIBoxKey("t_b", user, k1); !errors.Is(err, ErrCLIBoxKeyInUse) {
		t.Errorf("the same key in another tenant: %v, want ErrCLIBoxKeyInUse", err)
	}
	if ok, err := CLIBoxKeyRegistered(k1); err != nil || !ok {
		t.Errorf("CLIBoxKeyRegistered = %v, %v", ok, err)
	}
	active, grace, err := ValidCLIBoxKeys("t_a", user)
	if err != nil || active != k1 || len(grace) != 0 {
		t.Fatalf("ValidCLIBoxKeys = %q %v %v", active, grace, err)
	}
	keys, err := CLIBoxKeys("t_a", user)
	if err != nil || len(keys) != 1 || keys[0].Status != CLIBoxKeyActive || keys[0].Fingerprint == "" || keys[0].CreatedAt.IsZero() {
		t.Fatalf("CLIBoxKeys = %+v, %v", keys, err)
	}
}

// Keys are per (tenant_id, user_id): a key registered in one tenant opens
// nothing in another, and the same user can hold one in each.
func TestCLIBoxKeysAreKeyedOnTenantAndUser(t *testing.T) {
	user := setupKeyStore(t)
	ka, kb := newBoxPub(t), newBoxPub(t)
	if err := RegisterCLIBoxKey("t_a", user, ka); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ValidCLIBoxKeys("t_b", user); !errors.Is(err, ErrNoActiveCLIBoxKey) {
		t.Fatalf("tenant b before registration: %v, want ErrNoActiveCLIBoxKey", err)
	}
	if err := RegisterCLIBoxKey("t_b", user, kb); err != nil {
		t.Fatal(err)
	}
	a, _, _ := ValidCLIBoxKeys("t_a", user)
	b, _, _ := ValidCLIBoxKeys("t_b", user)
	if a != ka || b != kb {
		t.Fatalf("t_a=%s t_b=%s", a, b)
	}
	if err := RevokeCLIBoxKeys("t_a", user); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ValidCLIBoxKeys("t_a", user); !errors.Is(err, ErrNoActiveCLIBoxKey) {
		t.Errorf("t_a after revoke: %v", err)
	}
	if b, _, err := ValidCLIBoxKeys("t_b", user); err != nil || b != kb {
		t.Errorf("t_b after revoking t_a: %q %v", b, err)
	}
	// A revoked key is never registered again.
	if err := RegisterCLIBoxKey("t_a", user, ka); !errors.Is(err, ErrCLIBoxKeyInUse) {
		t.Errorf("re-registering a revoked key: %v, want ErrCLIBoxKeyInUse", err)
	}
}

func TestRecordCLIBoxKeySubmission(t *testing.T) {
	user := setupKeyStore(t)
	k1, k2, k3 := newBoxPub(t), newBoxPub(t), newBoxPub(t)
	if err := RecordCLIBoxKeySubmission("t_a", user, k1, k2, time.Minute); !errors.Is(err, ErrNoActiveCLIBoxKey) {
		t.Errorf("rotation with no key: %v", err)
	}
	if err := RegisterCLIBoxKey("t_a", user, k1); err != nil {
		t.Fatal(err)
	}
	if err := RecordCLIBoxKeySubmission("t_a", user, k1, k2, time.Minute); err != nil {
		t.Fatalf("rotation sealed under the active key: %v", err)
	}
	active, grace, err := ValidCLIBoxKeys("t_a", user)
	if err != nil || active != k2 || len(grace) != 1 || grace[0] != k1 {
		t.Fatalf("after rotation: %q %v %v", active, grace, err)
	}
	keys, _ := CLIBoxKeys("t_a", user)
	for _, k := range keys {
		if k.Pub == k1 && (k.Status != CLIBoxKeyGrace || k.RotatedAt == nil || k.GraceUntil == nil) {
			t.Errorf("old key row = %+v", k)
		}
	}
	// A retry sealed under the grace key re-asserting k2 is fine; naming
	// anything else is refused (M3's rule, for CLI keys).
	if err := RecordCLIBoxKeySubmission("t_a", user, k1, k2, time.Minute); err != nil {
		t.Errorf("grace-sealed re-assertion: %v", err)
	}
	if err := RecordCLIBoxKeySubmission("t_a", user, k1, k3, time.Minute); !errors.Is(err, ErrCLIBoxKeySubmissionNotActive) {
		t.Errorf("grace-sealed new key: %v, want ErrCLIBoxKeySubmissionNotActive", err)
	}
	// Rolling back to the superseded key is refused.
	if err := RecordCLIBoxKeySubmission("t_a", user, k2, k1, time.Minute); !errors.Is(err, ErrCLIBoxKeySuperseded) {
		t.Errorf("rollback: %v, want ErrCLIBoxKeySuperseded", err)
	}
	if err := RecordCLIBoxKeySubmission("t_a", user, k2, "bad", time.Minute); err == nil {
		t.Error("a malformed key was recorded")
	}
}

func TestCLIBoxKeyGraceExpires(t *testing.T) {
	user := setupKeyStore(t)
	k1, k2 := newBoxPub(t), newBoxPub(t)
	if err := RegisterCLIBoxKey("t_a", user, k1); err != nil {
		t.Fatal(err)
	}
	if err := RecordCLIBoxKeySubmission("t_a", user, k1, k2, -time.Second); err != nil {
		t.Fatal(err)
	}
	_, grace, err := ValidCLIBoxKeys("t_a", user)
	if err != nil || len(grace) != 0 {
		t.Fatalf("expired grace key still valid: %v %v", grace, err)
	}
	keys, _ := CLIBoxKeys("t_a", user)
	for _, k := range keys {
		if k.Pub == k1 && k.Status != CLIBoxKeyRetired {
			t.Errorf("expired grace key status %s, want retired", k.Status)
		}
	}
}

// Removing a user retires their CLI box keys in every tenant, in the
// same transaction as the deregistration.
func TestRemoveUserRetiresCLIBoxKeys(t *testing.T) {
	setupKeyStore(t)
	u := newUserID(t)
	if err := AddUser(u, "admin", "", newBoxPub(t)); err != nil {
		t.Fatal(err)
	}
	ka, kb := newBoxPub(t), newBoxPub(t)
	if err := RegisterCLIBoxKey("t_a", u, ka); err != nil {
		t.Fatal(err)
	}
	if err := RegisterCLIBoxKey("t_b", u, kb); err != nil {
		t.Fatal(err)
	}
	if err := RemoveUser(u); err != nil {
		t.Fatal(err)
	}
	for _, tid := range []string{"t_a", "t_b"} {
		if _, _, err := ValidCLIBoxKeys(tid, u); !errors.Is(err, ErrNoActiveCLIBoxKey) {
			t.Errorf("%s: %v, want ErrNoActiveCLIBoxKey", tid, err)
		}
	}
}

// The schema allows one active key per (tenant_id, user_id), whatever
// the code does.
func TestSchemaAllowsOneActiveCLIBoxKey(t *testing.T) {
	user := setupKeyStore(t)
	if err := RegisterCLIBoxKey("t_a", user, newBoxPub(t)); err != nil {
		t.Fatal(err)
	}
	slot := activeSlot
	err := db.Create(&cliBoxKeyRow{TenantID: "t_a", UserID: user, Pub: newBoxPub(t), Status: CLIBoxKeyActive, ActiveSlot: &slot, CreatedAt: time.Now()}).Error
	if err == nil {
		t.Fatal("a second active key was stored")
	}
	err = db.Create(&cliBoxKeyRow{TenantID: "t_a", UserID: user, Pub: newBoxPub(t), Status: CLIBoxKeyActive, CreatedAt: time.Now()}).Error
	if err == nil {
		t.Fatal("an active key without its slot was stored")
	}
}

func TestStoreNotConfigured(t *testing.T) {
	SetDB(nil)
	SetPolicy(rbac.NewRoleStore(), nil, nil)
	defer SetPolicy(nil, nil, nil)
	for name, err := range map[string]error{
		"register": RegisterCLIBoxKey("t_a", "U", newBoxPub(t)),
		"record":   RecordCLIBoxKeySubmission("t_a", "U", "a", newBoxPub(t), time.Minute),
		"revoke":   RevokeCLIBoxKeys("t_a", "U"),
	} {
		if !errors.Is(err, ErrStoreNotConfigured) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, _, err := ValidCLIBoxKeys("t_a", "U"); !errors.Is(err, ErrStoreNotConfigured) {
		t.Errorf("valid: %v", err)
	}
	if err := ResetUserCLIBoxKey("U", newBoxPub(t)); !errors.Is(err, ErrStoreNotConfigured) {
		t.Errorf("reset: %v", err)
	}
	if _, err := UserCLIBoxKeyFingerprints(); !errors.Is(err, ErrStoreNotConfigured) {
		t.Errorf("fingerprints: %v", err)
	}
}

// A user added through the API comes with their CLI box key, registered
// in the same transaction; without one (or with a bad or claimed one) the
// user isn't added at all.
func TestAddUserRegistersTheBoxKey(t *testing.T) {
	setupKeyStore(t)
	u, pub := newUserID(t), newBoxPub(t)
	if err := AddUser(u, "admin", "bob", pub); err != nil {
		t.Fatal(err)
	}
	if active, _, err := ValidCLIBoxKeys(usersTenantID(), u); err != nil || active != pub {
		t.Fatalf("active key %q, %v; want the key AddUser was given", active, err)
	}
	if role, name := UserIdentity(u); role != "admin" || name != "bob" {
		t.Errorf("UserIdentity = %q, %q", role, name)
	}
	fps, err := UserCLIBoxKeyFingerprints()
	if err != nil || fps[u] == "" || fps[u] != boxFingerprintOf(t, pub) {
		t.Errorf("fingerprints %v, %v", fps, err)
	}

	for name, bp := range map[string]string{"none": "", "malformed": "x", "weak": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "in use": pub} {
		v := newUserID(t)
		if err := AddUser(v, "admin", "", bp); err == nil {
			t.Errorf("%s box key: user added", name)
		}
		if _, _, found, _ := RegisteredUser(usersTenantID(), v); found {
			t.Errorf("%s box key: user row left behind", name)
		}
	}
	SetBoxKeyClaimCheck(func(string, string) error { return errors.New("a sprout holds it") })
	t.Cleanup(func() { SetBoxKeyClaimCheck(nil) })
	if err := AddUser(newUserID(t), "admin", "", newBoxPub(t)); err == nil {
		t.Error("a key another principal holds was registered")
	}
}

func boxFingerprintOf(t *testing.T, pub string) string {
	t.Helper()
	k, err := DecodeCLIBoxPub(pub)
	if err != nil {
		t.Fatal(err)
	}
	return payloadbox.Fingerprint(k)
}

// An admin's reset retires every key the user holds and makes the new one
// the only active key; a retired key never comes back, and an unknown user
// gets nothing.
func TestResetUserCLIBoxKey(t *testing.T) {
	admin := setupKeyStore(t)
	first, second := newBoxPub(t), newBoxPub(t)
	if err := RegisterCLIBoxKey(usersTenantID(), admin, first); err != nil {
		t.Fatal(err)
	}
	if err := ResetUserCLIBoxKey(admin, second); err != nil {
		t.Fatal(err)
	}
	active, grace, err := ValidCLIBoxKeys(usersTenantID(), admin)
	if err != nil || active != second || len(grace) != 0 {
		t.Fatalf("after reset: %q %v %v", active, grace, err)
	}
	if err := ResetUserCLIBoxKey(admin, first); !errors.Is(err, ErrCLIBoxKeyInUse) {
		t.Errorf("resetting back to a retired key: %v, want ErrCLIBoxKeyInUse", err)
	}
	if err := ResetUserCLIBoxKey(newUserID(t), newBoxPub(t)); !errors.Is(err, ErrUnknownUser) {
		t.Errorf("reset for an unknown user: %v, want ErrUnknownUser", err)
	}
	if err := ResetUserCLIBoxKey(admin, "x"); err == nil {
		t.Error("reset to a malformed key")
	}
}
