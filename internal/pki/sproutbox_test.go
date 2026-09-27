package pki

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/payloadbox"
)

func pinnedTenantKey(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(config.SproutTenantX25519PubFile)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// After an ordinary tenant key rotation, the sprout's next refresh
// verifies the continuity proof under the key it pinned and re-pins.
func TestRefreshGatewayJWT_RepinsAfterTenantKeyRotation(t *testing.T) {
	enrollForTest(t)
	before := pinnedTenantKey(t)
	rot, err := RotateTenantX25519Keypair("t_1", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RefreshGatewayJWT(t.Context()); err != nil {
		t.Fatalf("RefreshGatewayJWT after rotation: %v", err)
	}
	if got := pinnedTenantKey(t); got != rot.Pub || got == before {
		t.Errorf("pin is %s, want the rotated key %s", got, rot.Pub)
	}
	// And the next refresh is an ordinary one.
	if _, err := RefreshGatewayJWT(t.Context()); err != nil {
		t.Fatalf("refresh after re-pinning: %v", err)
	}
}

// A sprout that was offline through several rotations re-pins straight
// to the current key.
func TestRefreshGatewayJWT_RepinsAcrossSeveralRotations(t *testing.T) {
	enrollForTest(t)
	var last *TenantKeyRotation
	for range 3 {
		rot, err := RotateTenantX25519Keypair("t_1", false)
		if err != nil {
			t.Fatal(err)
		}
		last = rot
	}
	if _, err := RefreshGatewayJWT(t.Context()); err != nil {
		t.Fatalf("RefreshGatewayJWT: %v", err)
	}
	if got := pinnedTenantKey(t); got != last.Pub {
		t.Errorf("pin is %s, want %s", got, last.Pub)
	}
}

// A severing rotation carries no proof: the sprout's refresh fails with
// ErrTenantKeyMismatch (fatal; it must be re-enrolled) and the pin stays.
func TestRefreshGatewayJWT_SeveredRotationIsFatal(t *testing.T) {
	enrollForTest(t)
	before := pinnedTenantKey(t)
	if _, err := RotateTenantX25519Keypair("t_1", true); err != nil {
		t.Fatal(err)
	}
	if _, err := RefreshGatewayJWT(t.Context()); !errors.Is(err, ErrTenantKeyMismatch) {
		t.Fatalf("RefreshGatewayJWT after a severing rotation = %v, want ErrTenantKeyMismatch", err)
	}
	if got := pinnedTenantKey(t); got != before {
		t.Error("the pin moved without a proof")
	}
}

// reconcileTenantKeyPin only moves the pin for a proof that opens under
// the pinned key, is for this sprout, and names exactly the new key.
func TestReconcileTenantKeyPin_RejectsBadProofs(t *testing.T) {
	enrollForTest(t)
	pinned := pinnedTenantKey(t)
	sproutPub, err := EnsureSproutBoxKey()
	if err != nil {
		t.Fatal(err)
	}
	sp, _ := DecodeBoxPubKey(sproutPub)
	attacker := newTestBoxKeyPair(t)
	newKey := otherBoxPub(t)

	proof := func(signer *[32]byte, sproutID, purpose, to string) json.RawMessage {
		t.Helper()
		msg, err := payloadbox.NewMessage(purpose, sproutID, "", tenantKeyContinuityBody{To: to})
		if err != nil {
			t.Fatal(err)
		}
		data, err := payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: sp, Priv: signer}})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	cases := map[string]json.RawMessage{
		"no proof":                 nil,
		"sealed by an unknown key": proof(attacker.priv, "web-01", payloadbox.PurposeTenantKeyContinuity, newKey),
		"garbage":                  json.RawMessage(`{"v":1,"s":[]}`),
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if err := reconcileTenantKeyPin("web-01", newKey, c); !errors.Is(err, ErrTenantKeyMismatch) {
				t.Errorf("reconcileTenantKeyPin = %v, want ErrTenantKeyMismatch", err)
			}
			if pinnedTenantKey(t) != pinned {
				t.Error("pin moved")
			}
		})
	}

	// Proofs genuinely sealed under the pinned tenant key, but for the
	// wrong sprout, the wrong purpose, or naming a different key.
	set, err := loadTenantKeySet("t_1")
	if err != nil {
		t.Fatal(err)
	}
	genuine := set.current.priv
	for name, c := range map[string]json.RawMessage{
		"another sprout":    proof(genuine, "web-02", payloadbox.PurposeTenantKeyContinuity, newKey),
		"another purpose":   proof(genuine, "web-01", payloadbox.PurposeCmdRunRequest, newKey),
		"names another key": proof(genuine, "web-01", payloadbox.PurposeTenantKeyContinuity, otherBoxPub(t)),
	} {
		t.Run(name, func(t *testing.T) {
			if err := reconcileTenantKeyPin("web-01", newKey, c); !errors.Is(err, ErrTenantKeyMismatch) {
				t.Errorf("reconcileTenantKeyPin = %v, want ErrTenantKeyMismatch", err)
			}
			if pinnedTenantKey(t) != pinned {
				t.Error("pin moved")
			}
		})
	}
	// The control: the same construction, correct in every field, moves it.
	if err := reconcileTenantKeyPin("web-01", newKey, proof(genuine, "web-01", payloadbox.PurposeTenantKeyContinuity, newKey)); err != nil {
		t.Fatalf("a valid proof was refused: %v", err)
	}
	if pinnedTenantKey(t) != newKey {
		t.Error("a valid proof didn't move the pin")
	}
}

// The sprout's seal/open against farmer's: a request farmer seals opens
// once on the sprout and never again; the sprout's reply opens on farmer.
func TestSproutBox_RoundTripWithFarmer(t *testing.T) {
	enrollForTest(t)
	data, id, err := SealToSprout("t_1", "web-01", payloadbox.PurposeCmdRunRequest, "", map[string]string{"c": "uptime"})
	if err != nil {
		t.Fatalf("SealToSprout: %v", err)
	}
	msg, err := SproutOpenFromFarmer("web-01", payloadbox.PurposeCmdRunRequest, data)
	if err != nil || msg.ID != id {
		t.Fatalf("SproutOpenFromFarmer: %+v, %v", msg, err)
	}
	if _, err := SproutOpenFromFarmer("web-01", payloadbox.PurposeCmdRunRequest, data); !errors.Is(err, payloadbox.ErrReplayed) {
		t.Errorf("second open of the same request = %v, want ErrReplayed", err)
	}
	reply, err := SproutSealForFarmer("web-01", payloadbox.PurposeCmdRunResponse, msg.ID, "up 3 days")
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenFromSprout("t_1", "web-01", payloadbox.PurposeCmdRunResponse, reply)
	if err != nil || got.ReplyTo != id || string(got.Body) != `"up 3 days"` {
		t.Fatalf("OpenFromSprout: %+v, %v", got, err)
	}
}

// Without both keys the sprout can't take part, and says so.
func TestSproutBox_NotReadyWithoutPin(t *testing.T) {
	setupSproutFiles(t)
	if _, err := EnsureSproutBoxKey(); err != nil {
		t.Fatal(err)
	}
	if SproutBoxReady() {
		t.Fatal("ready with no pinned tenant key")
	}
	if _, err := SproutSealForFarmer("web-01", payloadbox.PurposeCmdRunResponse, "", "x"); !errors.Is(err, ErrSproutBoxNotReady) {
		t.Errorf("SproutSealForFarmer = %v, want ErrSproutBoxNotReady", err)
	}
}

// A replica whose cached tenant keys are stale (another replica rotated,
// and the sprout already re-pinned) re-reads OpenBao when a sprout's
// payload doesn't open, rather than failing it.
func TestOpenFromSprout_RereadsStaleTenantKeys(t *testing.T) {
	enrollForTest(t)
	if _, err := TenantBoxKeys("t_1"); err != nil { // populate the cache
		t.Fatal(err)
	}
	// Another replica rotates: write v2 straight to OpenBao, bypassing
	// this process's cache.
	client, err := newTenantBoxClientFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	next := newTestBoxKeyPair(t)
	if ok, err := client.writeKeypair(t.Context(), client.tenantPath("t_1"), next.pub, next.priv, 1, nil); err != nil || !ok {
		t.Fatalf("out-of-band rotation: %v, %v", ok, err)
	}
	if err := os.WriteFile(config.SproutTenantX25519PubFile, []byte(b64(next.pub)), 0o644); err != nil {
		t.Fatal(err)
	}
	reply, err := SproutSealForFarmer("web-01", payloadbox.PurposeCmdRunResponse, "", "x")
	if err != nil {
		t.Fatal(err)
	}
	// Age the cache past tenantBoxRereadAfter.
	e := tenantBoxEntryFor("t_1")
	e.mu.Lock()
	e.set.loaded = time.Now().Add(-time.Minute + 30*time.Second)
	e.mu.Unlock()
	if _, err := OpenFromSprout("t_1", "web-01", payloadbox.PurposeCmdRunResponse, reply); err != nil {
		t.Fatalf("OpenFromSprout with a stale cache: %v", err)
	}
}

type testBoxKeyPair struct{ pub, priv *[32]byte }

func newTestBoxKeyPair(t *testing.T) testBoxKeyPair {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testBoxKeyPair{pub, priv}
}
