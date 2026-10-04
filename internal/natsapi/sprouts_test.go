package natsapi

import (
	"encoding/json"
	"testing"

	"github.com/nats-io/nkeys"
	"github.com/taigrr/jety"
	"github.com/yogzblr/imas/internal/pki"
)

// --- handleSproutsList tests ---

func TestHandleSproutsList_Empty(t *testing.T) {
	setupNatsAPIPKI(t)
	setDangerouslyAllowRoot(t, true)

	result, err := handleSproutsList(adminCaller(t, pki.CurrentTenantID()), nil)
	if err != nil {
		t.Fatalf("handleSproutsList: unexpected error: %v", err)
	}

	m, ok := result.(map[string][]SproutInfo)
	if !ok {
		t.Fatalf("result type = %T, want map[string][]SproutInfo", result)
	}
	sprouts := m["sprouts"]
	if len(sprouts) != 0 {
		t.Errorf("expected 0 sprouts, got %d", len(sprouts))
	}
}

func TestHandleSproutsList_AcceptedSprouts(t *testing.T) {
	pkiDir := setupNatsAPIPKI(t)
	setDangerouslyAllowRoot(t, true)
	// Ensure natsConn is nil so probeSprout is skipped.
	ClearNatsConn(pki.CurrentTenantID())

	nkey := generateTestNKey(t)
	writeTestSproutKey(t, pkiDir, "accepted", "web-01", nkey)

	result, err := handleSproutsList(adminCaller(t, pki.CurrentTenantID()), nil)
	if err != nil {
		t.Fatalf("handleSproutsList: %v", err)
	}

	m := result.(map[string][]SproutInfo)
	sprouts := m["sprouts"]
	if len(sprouts) != 1 {
		t.Fatalf("expected 1 sprout, got %d", len(sprouts))
	}
	if sprouts[0].ID != "web-01" {
		t.Errorf("sprout ID = %q, want %q", sprouts[0].ID, "web-01")
	}
	if sprouts[0].KeyState != "accepted" {
		t.Errorf("key state = %q, want %q", sprouts[0].KeyState, "accepted")
	}
	if sprouts[0].NKey != nkey {
		t.Errorf("NKey = %q, want %q", sprouts[0].NKey, nkey)
	}
	if sprouts[0].Connected {
		t.Error("expected Connected=false when natsConn is nil")
	}
}

func TestHandleSproutsList_MixedStates(t *testing.T) {
	pkiDir := setupNatsAPIPKI(t)
	setDangerouslyAllowRoot(t, true)
	ClearNatsConn(pki.CurrentTenantID())

	writeTestSproutKey(t, pkiDir, "accepted", "prod-01", generateTestNKey(t))
	writeTestSproutKey(t, pkiDir, "unaccepted", "staging-01", generateTestNKey(t))
	writeTestSproutKey(t, pkiDir, "denied", "bad-actor", generateTestNKey(t))
	writeTestSproutKey(t, pkiDir, "rejected", "old-key", generateTestNKey(t))

	result, err := handleSproutsList(adminCaller(t, pki.CurrentTenantID()), nil)
	if err != nil {
		t.Fatalf("handleSproutsList: %v", err)
	}

	m := result.(map[string][]SproutInfo)
	sprouts := m["sprouts"]
	if len(sprouts) != 4 {
		t.Fatalf("expected 4 sprouts, got %d", len(sprouts))
	}

	states := map[string]bool{}
	for _, s := range sprouts {
		states[s.KeyState] = true
	}
	for _, want := range []string{"accepted", "unaccepted", "denied", "rejected"} {
		if !states[want] {
			t.Errorf("expected sprout with state %q", want)
		}
	}
}

func TestHandleSproutsList_MultipleSameState(t *testing.T) {
	pkiDir := setupNatsAPIPKI(t)
	setDangerouslyAllowRoot(t, true)
	ClearNatsConn(pki.CurrentTenantID())

	writeTestSproutKey(t, pkiDir, "accepted", "web-01", generateTestNKey(t))
	writeTestSproutKey(t, pkiDir, "accepted", "web-02", generateTestNKey(t))
	writeTestSproutKey(t, pkiDir, "accepted", "web-03", generateTestNKey(t))

	result, err := handleSproutsList(adminCaller(t, pki.CurrentTenantID()), nil)
	if err != nil {
		t.Fatalf("handleSproutsList: %v", err)
	}

	m := result.(map[string][]SproutInfo)
	sprouts := m["sprouts"]
	if len(sprouts) != 3 {
		t.Fatalf("expected 3 sprouts, got %d", len(sprouts))
	}
}

// --- handleSproutsGet tests ---

func TestHandleSproutsGet_Found(t *testing.T) {
	pkiDir := setupNatsAPIPKI(t)
	ClearNatsConn(pki.CurrentTenantID())

	nkey := generateTestNKey(t)
	writeTestSproutKey(t, pkiDir, "accepted", "db-01", nkey)

	params, _ := json.Marshal(pki.KeyManager{SproutID: "db-01"})
	result, err := handleSproutsGet(pki.CurrentTenantID(), params)
	if err != nil {
		t.Fatalf("handleSproutsGet: %v", err)
	}

	info, ok := result.(SproutInfo)
	if !ok {
		t.Fatalf("result type = %T, want SproutInfo", result)
	}
	if info.ID != "db-01" {
		t.Errorf("ID = %q, want %q", info.ID, "db-01")
	}
	if info.KeyState != "accepted" {
		t.Errorf("KeyState = %q, want %q", info.KeyState, "accepted")
	}
	if info.NKey != nkey {
		t.Errorf("NKey = %q, want %q", info.NKey, nkey)
	}
}

func TestHandleSproutsGet_NotFound(t *testing.T) {
	setupNatsAPIPKI(t)
	ClearNatsConn(pki.CurrentTenantID())

	params, _ := json.Marshal(pki.KeyManager{SproutID: "nonexistent"})
	_, err := handleSproutsGet(pki.CurrentTenantID(), params)
	if err == nil {
		t.Fatal("expected error for nonexistent sprout")
	}
	if err.Error() != "sprout not found" {
		t.Errorf("error = %q, want %q", err.Error(), "sprout not found")
	}
}

func TestHandleSproutsGet_InvalidID(t *testing.T) {
	setupNatsAPIPKI(t)
	ClearNatsConn(pki.CurrentTenantID())

	params, _ := json.Marshal(pki.KeyManager{SproutID: "INVALID-CAPS"})
	_, err := handleSproutsGet(pki.CurrentTenantID(), params)
	if err == nil {
		t.Fatal("expected error for invalid sprout ID")
	}
	if err.Error() != "invalid sprout ID" {
		t.Errorf("error = %q, want %q", err.Error(), "invalid sprout ID")
	}
}

func TestHandleSproutsGet_InvalidJSON(t *testing.T) {
	setupNatsAPIPKI(t)

	_, err := handleSproutsGet(pki.CurrentTenantID(), json.RawMessage(`{bad json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestHandleSproutsGet_EmptyParams(t *testing.T) {
	setupNatsAPIPKI(t)
	ClearNatsConn(pki.CurrentTenantID())

	_, err := handleSproutsGet(pki.CurrentTenantID(), nil)
	if err == nil {
		t.Fatal("expected error for nil params")
	}
}

func TestHandleSproutsGet_UnacceptedSprout(t *testing.T) {
	pkiDir := setupNatsAPIPKI(t)
	ClearNatsConn(pki.CurrentTenantID())

	nkey := generateTestNKey(t)
	writeTestSproutKey(t, pkiDir, "unaccepted", "pending-01", nkey)

	params, _ := json.Marshal(pki.KeyManager{SproutID: "pending-01"})
	result, err := handleSproutsGet(pki.CurrentTenantID(), params)
	if err != nil {
		t.Fatalf("handleSproutsGet: %v", err)
	}

	info := result.(SproutInfo)
	if info.KeyState != "unaccepted" {
		t.Errorf("KeyState = %q, want %q", info.KeyState, "unaccepted")
	}
	if info.Connected {
		t.Error("unaccepted sprout should not be connected")
	}
}

// --- resolveKeyState tests ---

func TestResolveKeyState_AllStates(t *testing.T) {
	pkiDir := setupNatsAPIPKI(t)

	tests := []struct {
		state string
		id    string
	}{
		{"accepted", "s-accepted"},
		{"unaccepted", "s-unaccepted"},
		{"denied", "s-denied"},
		{"rejected", "s-rejected"},
	}

	for _, tt := range tests {
		writeTestSproutKey(t, pkiDir, tt.state, tt.id, generateTestNKey(t))
	}

	for _, tt := range tests {
		t.Run(tt.state, func(t *testing.T) {
			got := resolveKeyState(pki.CurrentTenantID(), tt.id)
			if got != tt.state {
				t.Errorf("resolveKeyState(%q) = %q, want %q", tt.id, got, tt.state)
			}
		})
	}
}

func TestResolveKeyState_Unknown(t *testing.T) {
	setupNatsAPIPKI(t)

	got := resolveKeyState(pki.CurrentTenantID(), "no-such-sprout")
	if got != "unknown" {
		t.Errorf("resolveKeyState for missing sprout = %q, want %q", got, "unknown")
	}
}

// --- probeSprout tests ---

func TestProbeSprout_NilConn(t *testing.T) {
	ClearNatsConn(pki.CurrentTenantID())

	if probeSprout("acme", "any-sprout") {
		t.Error("expected false when natsConn is nil")
	}
}

// --- Test helpers ---

// writeTestSproutKey registers id at the given lifecycle state via the
// pki package's own lifecycle functions — see writeNKey in
// pki_handlers_test.go, which this delegates to.
func writeTestSproutKey(t *testing.T, pkiDir, state, id, nkey string) {
	t.Helper()
	writeNKey(t, pkiDir, state, id, nkey)
}

func generateTestNKey(t *testing.T) string {
	t.Helper()
	kp, err := nkeys.CreateUser()
	if err != nil {
		t.Fatalf("create test nkey: %v", err)
	}
	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatalf("get public key: %v", err)
	}
	return pub
}

// setDangerouslyAllowRoot enables/disables the root bypass for tests.
func setDangerouslyAllowRoot(t *testing.T, enabled bool) {
	t.Helper()
	jety.Set("dangerously_allow_root", enabled)
	t.Cleanup(func() {
		jety.Set("dangerously_allow_root", false)
	})
}
