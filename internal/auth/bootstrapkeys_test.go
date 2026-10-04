package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/taigrr/jety"
)

// loadWithBoxPub loads a policy whose config file defines admin with
// boxpub, as a farmer start does.
func loadWithBoxPub(t *testing.T, admin, boxpub string) {
	t.Helper()
	jety.Set("roles", map[string]interface{}{
		"admin": []interface{}{map[string]interface{}{"action": "admin", "scope": "*"}},
	})
	entry := map[string]interface{}{"pubkey": admin, "username": "alice"}
	if boxpub != "" {
		entry[BoxPubConfigField] = boxpub
	}
	jety.Set("users", map[string]interface{}{"admin": []interface{}{entry}})
	if err := LoadPolicy(); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
}

func setupBootstrapKeys(t *testing.T) string {
	t.Helper()
	setupJetyForTest(t)
	t.Cleanup(func() { clearJetyKeys(t); SetPolicy(nil, nil, nil); SetBoxKeyClaimCheck(nil) })
	return newUserID(t)
}

func keyRows(t *testing.T, tenantID, userID string) []CLIBoxKey {
	t.Helper()
	keys, err := CLIBoxKeys(tenantID, userID)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

// Imported once, under (the policy's tenant, the user), and every later
// start (any replica) leaves it alone.
func TestConfigBoxPubImportedOnce(t *testing.T) {
	admin := setupBootstrapKeys(t)
	k1 := newBoxPub(t)
	loadWithBoxPub(t, admin, k1)
	if active, _, err := ValidCLIBoxKeys(usersTenantID(), admin); err != nil || active != k1 {
		t.Fatalf("after import: %q, %v", active, err)
	}
	loadWithBoxPub(t, admin, k1)
	loadWithBoxPub(t, admin, k1)
	if rows := keyRows(t, usersTenantID(), admin); len(rows) != 1 {
		t.Fatalf("%d rows after three starts, want 1", len(rows))
	}
	// Only that tenant: nothing is registered elsewhere.
	if _, _, err := ValidCLIBoxKeys("t_other", admin); !errors.Is(err, ErrNoActiveCLIBoxKey) {
		t.Errorf("another tenant: %v", err)
	}
}

// Once the user rotated, the config file's (old) boxpub never comes back.
func TestConfigBoxPubNeverOverridesARotation(t *testing.T) {
	admin := setupBootstrapKeys(t)
	k1, k2 := newBoxPub(t), newBoxPub(t)
	loadWithBoxPub(t, admin, k1)
	if err := RecordCLIBoxKeySubmission(usersTenantID(), admin, k1, k2, -time.Second); err != nil {
		t.Fatal(err)
	}
	loadWithBoxPub(t, admin, k1)
	active, grace, err := ValidCLIBoxKeys(usersTenantID(), admin)
	if err != nil || active != k2 || len(grace) != 0 {
		t.Fatalf("after restart: active %q grace %v %v; want k2 and no grace", active, grace, err)
	}
	// A new boxpub in the config doesn't replace the active key either.
	loadWithBoxPub(t, admin, newBoxPub(t))
	if active, _, _ := ValidCLIBoxKeys(usersTenantID(), admin); active != k2 {
		t.Fatalf("a changed boxpub replaced the active key")
	}
}

// Revoked keys stay revoked: neither the old boxpub nor a new one is
// imported for a user who has any key history.
func TestConfigBoxPubNeverReactivatesARevokedKey(t *testing.T) {
	admin := setupBootstrapKeys(t)
	k1 := newBoxPub(t)
	loadWithBoxPub(t, admin, k1)
	if err := RevokeCLIBoxKeys(usersTenantID(), admin); err != nil {
		t.Fatal(err)
	}
	loadWithBoxPub(t, admin, k1)
	loadWithBoxPub(t, admin, newBoxPub(t))
	if _, _, err := ValidCLIBoxKeys(usersTenantID(), admin); !errors.Is(err, ErrNoActiveCLIBoxKey) {
		t.Fatalf("a revoked user got a key back: %v", err)
	}
	for _, k := range keyRows(t, usersTenantID(), admin) {
		if k.Status != CLIBoxKeyRetired {
			t.Errorf("row %s is %s", k.Fingerprint, k.Status)
		}
	}
}

// A key in another tenant doesn't count as history in the policy's
// tenant: the import is scoped to (tenant_id, user_id).
func TestConfigBoxPubScopedToTenantAndUser(t *testing.T) {
	admin := setupBootstrapKeys(t)
	loadWithBoxPub(t, admin, "")
	if err := RegisterCLIBoxKey("t_other", admin, newBoxPub(t)); err != nil {
		t.Fatal(err)
	}
	k := newBoxPub(t)
	loadWithBoxPub(t, admin, k)
	if active, _, err := ValidCLIBoxKeys(usersTenantID(), admin); err != nil || active != k {
		t.Fatalf("import with history in another tenant: %q, %v", active, err)
	}
}

// Bad imports are refused and logged, and farmer still starts.
func TestConfigBoxPubRefusals(t *testing.T) {
	admin := setupBootstrapKeys(t)
	for name, bp := range map[string]string{"malformed": "not-a-key", "weak": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="} {
		loadWithBoxPub(t, admin, bp)
		if _, _, err := ValidCLIBoxKeys(usersTenantID(), admin); !errors.Is(err, ErrNoActiveCLIBoxKey) {
			t.Errorf("%s boxpub was imported", name)
		}
	}
	// Another user's key.
	other := newUserID(t)
	if err := AddUser(other, "admin"); err != nil {
		t.Fatal(err)
	}
	taken := newBoxPub(t)
	if err := RegisterCLIBoxKey(usersTenantID(), other, taken); err != nil {
		t.Fatal(err)
	}
	loadWithBoxPub(t, admin, taken)
	if _, _, err := ValidCLIBoxKeys(usersTenantID(), admin); !errors.Is(err, ErrNoActiveCLIBoxKey) {
		t.Error("another user's key was imported")
	}
	// The cross-principal check (a sprout's key, a farmer-side key).
	SetBoxKeyClaimCheck(func(string, string) error { return errors.New("a sprout holds it") })
	loadWithBoxPub(t, admin, newBoxPub(t))
	if _, _, err := ValidCLIBoxKeys(usersTenantID(), admin); !errors.Is(err, ErrNoActiveCLIBoxKey) {
		t.Error("a claimed key was imported")
	}
}
