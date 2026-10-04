package pki

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/gatewayjwt"
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

// A severing rotation cuts the sprout off: farmer no longer holds the key
// it pinned, so it can't open the sprout's sealed refresh, and nothing it
// could answer would be authenticated to the sprout. The refresh fails
// (an ordinary, retried error: the refusal itself is unauthenticated),
// nothing is persisted, and the pin stays. The sprout must be re-enrolled.
func TestRefreshGatewayJWT_SeveredRotationCutsTheSproutOff(t *testing.T) {
	enrollForTest(t)
	before := pinnedTenantKey(t)
	if _, err := RotateTenantX25519Keypair("t_1", true); err != nil {
		t.Fatal(err)
	}
	gwBefore := CurrentGatewayJWT()
	if _, err := RefreshGatewayJWT(t.Context()); err == nil {
		t.Fatal("RefreshGatewayJWT succeeded after a severing rotation")
	}
	if got := pinnedTenantKey(t); got != before {
		t.Error("the pin moved without a proof")
	}
	if CurrentGatewayJWT() != gwBefore {
		t.Error("a refused refresh installed a gateway JWT")
	}
}

// A sprout whose tenant pin is older than the grace window (it was off
// through a rotation) still refreshes: farmer opens its request under the
// retained key it pinned, seals the reply under that same key, and the
// continuity proof inside re-pins it.
func TestRefreshGatewayJWT_StalePinOutsideTheGraceWindow(t *testing.T) {
	_, minter, _ := enrollForTest(t)
	// No grace window at all (withTenantBoxGrace zeroes the gateway JWT
	// lifetime too, so mint this test's tokens for an hour regardless).
	withTenantBoxGrace(t, 0)
	gatewayMinter = hourLongMinter{minter}
	before := pinnedTenantKey(t)
	rot, err := RotateTenantX25519Keypair("t_1", false)
	if err != nil {
		t.Fatal(err)
	}
	if keys, err := TenantBoxKeys("t_1"); err != nil || len(keys) != 1 {
		t.Fatalf("TenantBoxKeys = %d keys, %v; want only the new one (no grace)", len(keys), err)
	}
	if _, err := RefreshGatewayJWT(t.Context()); err != nil {
		t.Fatalf("RefreshGatewayJWT with a pin from before the grace window: %v", err)
	}
	if got := pinnedTenantKey(t); got != rot.Pub || got == before {
		t.Errorf("pin is %s, want the rotated key %s", got, rot.Pub)
	}
	farmerOpensReply(t)
}

// hourLongMinter mints through m with an expiry an hour out, whatever
// config.GatewayJWTTTL says.
type hourLongMinter struct{ m *jwsGatewayMinter }

func (h hourLongMinter) MintGatewayJWT(ctx context.Context, c gatewayjwt.GatewayClaims) (string, error) {
	c.Expiry = time.Now().Add(time.Hour)
	return h.m.MintGatewayJWT(ctx, c)
}

// A box key rotation in flight at refresh time, every way it can stand.
func TestRefreshGatewayJWT_DuringABoxKeyRotation(t *testing.T) {
	// The sprout submitted its new key; farmer hasn't recorded it. The
	// refresh opens under the current key and the reply comes back to it:
	// nothing is promoted.
	t.Run("submitted, not recorded", func(t *testing.T) {
		enrollForTest(t)
		oldPub := sproutCurrentPub(t)
		if _, _, err := BeginSproutBoxKeyRotation("web-01"); err != nil {
			t.Fatal(err)
		}
		if _, err := RefreshGatewayJWT(t.Context()); err != nil {
			t.Fatalf("RefreshGatewayJWT: %v", err)
		}
		if got := sproutCurrentPub(t); got != oldPub || !fileExists(sproutPendingBoxPrivFile()) {
			t.Error("a reply sealed to the current key promoted the pending one")
		}
	})
	// Farmer recorded the new key: it seals the reply to it, which is the
	// sprout's confirmation, so the refresh promotes the pending key.
	t.Run("recorded", func(t *testing.T) {
		enrollForTest(t)
		submission, newPub, err := BeginSproutBoxKeyRotation("web-01")
		if err != nil {
			t.Fatal(err)
		}
		farmerAcceptsSubmission(t, submission)
		if _, err := RefreshGatewayJWT(t.Context()); err != nil {
			t.Fatalf("RefreshGatewayJWT: %v", err)
		}
		if got := sproutCurrentPub(t); got != newPub {
			t.Errorf("current key is %s, want the promoted %s", got, newPub)
		}
		if active, _ := farmerActive(t); active != newPub {
			t.Errorf("farmer's active key is %s, want %s", active, newPub)
		}
		farmerOpensReply(t)
	})
	// Farmer recorded the new key and the old one's grace there has run
	// out (the sprout heard nothing from farmer for that long). Only the
	// copy sealed under the pending key opens; the sprout still recovers.
	t.Run("recorded, old key past farmer's grace", func(t *testing.T) {
		enrollForTest(t)
		submission, newPub, err := BeginSproutBoxKeyRotation("web-01")
		if err != nil {
			t.Fatal(err)
		}
		msg, err := OpenFromSprout("t_1", "web-01", payloadbox.PurposeBoxKeySubmit, submission)
		if err != nil {
			t.Fatal(err)
		}
		var body sproutBoxKeySubmitBody
		if err := json.Unmarshal(msg.Body, &body); err != nil {
			t.Fatal(err)
		}
		if err := RotateSproutBoxKey("t_1", "web-01", body.Pub, 0); err != nil {
			t.Fatal(err)
		}
		if _, grace := farmerActive(t); len(grace) != 0 {
			t.Fatalf("farmer still holds %d grace key(s)", len(grace))
		}
		if _, err := RefreshGatewayJWT(t.Context()); err != nil {
			t.Fatalf("RefreshGatewayJWT with only the pending key on farmer: %v", err)
		}
		if got := sproutCurrentPub(t); got != newPub {
			t.Errorf("current key is %s, want the promoted %s", got, newPub)
		}
	})
	// Already promoted: the old key is the sprout's previous one, and the
	// refresh is an ordinary one under the new key.
	t.Run("promoted", func(t *testing.T) {
		enrollForTest(t)
		submission, newPub, err := BeginSproutBoxKeyRotation("web-01")
		if err != nil {
			t.Fatal(err)
		}
		farmerAcceptsSubmission(t, submission)
		sproutOpens(t, farmerSeals(t))
		if _, err := RefreshGatewayJWT(t.Context()); err != nil {
			t.Fatalf("RefreshGatewayJWT: %v", err)
		}
		if got := sproutCurrentPub(t); got != newPub {
			t.Errorf("current key is %s, want %s", got, newPub)
		}
	})
}

// The tenant ID pin is what the sealed refresh names. A sprout whose pin
// has been changed names a tenant farmer doesn't hold it under, and is
// refused; one with no pin can't refresh at all (fatal).
func TestRefreshGatewayJWT_TenantPinIsWhatItSeals(t *testing.T) {
	srv, _, _ := enrollForTest(t)
	if err := os.WriteFile(SproutTenantIDFile(), []byte("t_2"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := RefreshGatewayJWT(t.Context()); err == nil || IsFatalRefreshError(err) {
		t.Fatalf("refresh naming another tenant = %v, want farmer's refusal", err)
	}
	if n := srv.refreshCount(); n != 1 {
		t.Errorf("refresh requests = %d, want 1", n)
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
		msg, err := payloadbox.NewMessage(purpose, "t_1", sproutID, "", tenantKeyContinuityBody{To: to})
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

// Box key rotation, the sprout's side (BeginSproutBoxKeyRotation and the
// pending/current/previous key files). farmerAcceptsSubmission stands in
// for internal/natsapi's handleBoxKeySubmit, which this package can't
// import; cmd/sprout's round-trip test runs the real one.

func farmerAcceptsSubmission(t *testing.T, submission []byte) string {
	t.Helper()
	msg, err := OpenFromSprout("t_1", "web-01", payloadbox.PurposeBoxKeySubmit, submission)
	if err != nil {
		t.Fatalf("farmer can't open the submission: %v", err)
	}
	var body sproutBoxKeySubmitBody
	if err := json.Unmarshal(msg.Body, &body); err != nil {
		t.Fatal(err)
	}
	if err := RotateSproutBoxKey("t_1", "web-01", body.Pub, time.Hour); err != nil {
		t.Fatalf("RotateSproutBoxKey: %v", err)
	}
	return body.Pub
}

func farmerSeals(t *testing.T) []byte {
	t.Helper()
	data, _, err := SealToSprout("t_1", "web-01", payloadbox.PurposeCmdRunRequest, "", "uptime")
	if err != nil {
		t.Fatalf("SealToSprout: %v", err)
	}
	return data
}

func sproutOpens(t *testing.T, data []byte) {
	t.Helper()
	if _, err := SproutOpenFromFarmer("web-01", payloadbox.PurposeCmdRunRequest, data); err != nil {
		t.Fatalf("SproutOpenFromFarmer: %v", err)
	}
}

// farmerOpensReply checks farmer opens what the sprout seals now.
func farmerOpensReply(t *testing.T) {
	t.Helper()
	reply, err := SproutSealForFarmer("web-01", payloadbox.PurposeCmdRunResponse, "", "ok")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFromSprout("t_1", "web-01", payloadbox.PurposeCmdRunResponse, reply); err != nil {
		t.Fatalf("farmer can't open the sprout's reply: %v", err)
	}
}

func sproutCurrentPub(t *testing.T) string {
	t.Helper()
	priv, err := readBoxPrivKeyFile(config.SproutBoxPrivFile, false)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := boxPubFromPriv(priv)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func farmerActive(t *testing.T) (string, []string) {
	t.Helper()
	active, grace, err := ValidSproutBoxKeys("t_1", "web-01")
	if err != nil {
		t.Fatal(err)
	}
	return active, grace
}

// The window the grace design is for: farmer seals a payload to the old
// key, records the new one, seals the next payload to it, and the two
// arrive in the opposite order. The first promotes the new key; the
// second, still under the old one, opens under the kept previous key.
func TestSproutBoxKeyRotation_InFlightPayloadDuringRotation(t *testing.T) {
	enrollForTest(t)
	oldPub := sproutCurrentPub(t)

	inFlight := farmerSeals(t) // sealed to the old key
	submission, newPub, err := BeginSproutBoxKeyRotation("web-01")
	if err != nil {
		t.Fatalf("BeginSproutBoxKeyRotation: %v", err)
	}
	if newPub == oldPub {
		t.Fatal("the rotation reused the current key")
	}
	// Nothing the sprout uses has changed yet.
	if got := sproutCurrentPub(t); got != oldPub {
		t.Fatalf("current key changed to %s before farmer confirmed the new one", got)
	}
	if got := farmerAcceptsSubmission(t, submission); got != newPub {
		t.Fatalf("submission names %s, want %s", got, newPub)
	}
	if active, grace := farmerActive(t); active != newPub || len(grace) != 1 || grace[0] != oldPub {
		t.Fatalf("farmer has active %s, grace %v", active, grace)
	}
	// Farmer's grace keeps the sprout's old key valid for its replies
	// until the sprout learns of the switch.
	farmerOpensReply(t)

	sproutOpens(t, farmerSeals(t)) // sealed to the new key: promotes it
	if got := sproutCurrentPub(t); got != newPub {
		t.Fatalf("current key is %s after farmer sealed to the new one, want %s", got, newPub)
	}
	if fileExists(sproutPendingBoxPrivFile()) {
		t.Error("pending key file left behind after promotion")
	}
	if pub, _ := os.ReadFile(config.SproutBoxPubFile); string(pub) != newPub {
		t.Errorf("public key file holds %q, want %s", pub, newPub)
	}
	sproutOpens(t, inFlight) // the old key's payload, arriving late
	farmerOpensReply(t)
}

// A submission that never reaches farmer (dropped by the bus, or refused)
// costs nothing: the sprout keeps its current key, and triggering again
// resubmits the same pending key rather than stacking another.
func TestSproutBoxKeyRotation_LostSubmission(t *testing.T) {
	enrollForTest(t)
	oldPub := sproutCurrentPub(t)
	first, pending, err := BeginSproutBoxKeyRotation("web-01")
	if err != nil {
		t.Fatal(err)
	}
	_ = first // lost

	sproutOpens(t, farmerSeals(t))
	farmerOpensReply(t)
	if got := sproutCurrentPub(t); got != oldPub {
		t.Fatalf("current key moved to %s without farmer confirming it", got)
	}

	retry, again, err := BeginSproutBoxKeyRotation("web-01")
	if err != nil {
		t.Fatal(err)
	}
	if again != pending {
		t.Fatalf("second trigger submitted %s, want the pending %s", again, pending)
	}
	if bytes.Equal(retry, first) {
		t.Error("resubmission reused the first envelope; it must be freshly sealed")
	}
	farmerAcceptsSubmission(t, retry)
	sproutOpens(t, farmerSeals(t))
	if got := sproutCurrentPub(t); got != pending {
		t.Fatalf("current key is %s, want %s", got, pending)
	}
}

// The previous key is deleted once its grace window closes, and a
// rotation isn't started while it's open.
func TestSproutBoxKeyRotation_PreviousKeyGraceWindow(t *testing.T) {
	enrollForTest(t)
	inFlight := farmerSeals(t)
	submission, _, err := BeginSproutBoxKeyRotation("web-01")
	if err != nil {
		t.Fatal(err)
	}
	farmerAcceptsSubmission(t, submission)
	sproutOpens(t, farmerSeals(t))

	if _, _, err := BeginSproutBoxKeyRotation("web-01"); !errors.Is(err, ErrSproutBoxKeyRotationTooSoon) {
		t.Fatalf("rotation inside the grace window = %v, want ErrSproutBoxKeyRotationTooSoon", err)
	}
	if fileExists(sproutPendingBoxPrivFile()) {
		t.Fatal("a refused rotation left a pending key")
	}

	past := time.Now().Add(-SproutBoxKeyPrevGrace() - time.Minute)
	if err := os.Chtimes(sproutPrevBoxPrivFile(), past, past); err != nil {
		t.Fatal(err)
	}
	if _, err := SproutOpenFromFarmer("web-01", payloadbox.PurposeCmdRunRequest, inFlight); !errors.Is(err, payloadbox.ErrOpen) {
		t.Fatalf("old-key payload after the grace window = %v, want ErrOpen", err)
	}
	if fileExists(sproutPrevBoxPrivFile()) {
		t.Fatal("previous key not deleted after its grace window")
	}
	if _, _, err := BeginSproutBoxKeyRotation("web-01"); err != nil {
		t.Fatalf("rotation after the grace window: %v", err)
	}
}

// Only farmer can promote the pending key: a payload sealed to it by
// anyone without a tenant private key doesn't open, so a bus that saw the
// (public) pending key in the submission can't switch the sprout over.
func TestSproutBoxKeyRotation_ForgedPayloadDoesNotPromote(t *testing.T) {
	enrollForTest(t)
	oldPub := sproutCurrentPub(t)
	_, pendingB64, err := BeginSproutBoxKeyRotation("web-01")
	if err != nil {
		t.Fatal(err)
	}
	pending, err := DecodeBoxPubKey(pendingB64)
	if err != nil {
		t.Fatal(err)
	}
	attacker := newTestBoxKeyPair(t)
	msg, err := payloadbox.NewMessage(payloadbox.PurposeCmdRunRequest, "t_1", "web-01", "", "rm -rf /")
	if err != nil {
		t.Fatal(err)
	}
	forged, err := payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: pending, Priv: attacker.priv}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SproutOpenFromFarmer("web-01", payloadbox.PurposeCmdRunRequest, forged); !errors.Is(err, payloadbox.ErrOpen) {
		t.Fatalf("forged payload = %v, want ErrOpen", err)
	}
	if got := sproutCurrentPub(t); got != oldPub || !fileExists(sproutPendingBoxPrivFile()) {
		t.Fatal("a forged payload promoted the pending key")
	}
}

// A crash between writing the previous key and renaming the pending one
// over the current one leaves previous a copy of current; the next
// payload sealed to the pending key finishes the promotion.
func TestSproutBoxKeyRotation_RecoversFromInterruptedPromotion(t *testing.T) {
	enrollForTest(t)
	oldPub := sproutCurrentPub(t)
	submission, newPub, err := BeginSproutBoxKeyRotation("web-01")
	if err != nil {
		t.Fatal(err)
	}
	farmerAcceptsSubmission(t, submission)
	current, err := os.ReadFile(config.SproutBoxPrivFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sproutPrevBoxPrivFile(), current, 0o600); err != nil {
		t.Fatal(err)
	}
	sproutOpens(t, farmerSeals(t))
	if got := sproutCurrentPub(t); got != newPub {
		t.Fatalf("current key is %s, want %s", got, newPub)
	}
	prev, err := readBoxPrivKeyFile(sproutPrevBoxPrivFile(), false)
	if err != nil {
		t.Fatal(err)
	}
	if pub, _ := boxPubFromPriv(prev); pub != oldPub {
		t.Fatalf("previous key is %s, want %s", pub, oldPub)
	}
}

// A sprout that sees no farmer payload between farmer recording its new
// key and the next tenant key rotation learns of the switch from the
// refresh's continuity proof, which farmer seals to the active key.
func TestSproutBoxKeyRotation_ContinuityProofPromotes(t *testing.T) {
	enrollForTest(t)
	submission, newPub, err := BeginSproutBoxKeyRotation("web-01")
	if err != nil {
		t.Fatal(err)
	}
	farmerAcceptsSubmission(t, submission)
	rot, err := RotateTenantX25519Keypair("t_1", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RefreshGatewayJWT(t.Context()); err != nil {
		t.Fatalf("RefreshGatewayJWT: %v", err)
	}
	if got := pinnedTenantKey(t); got != rot.Pub {
		t.Errorf("pin is %s, want %s", got, rot.Pub)
	}
	if got := sproutCurrentPub(t); got != newPub {
		t.Fatalf("current key is %s, want %s", got, newPub)
	}
}

// Payloads opened concurrently while the new key is promoted all open,
// whichever key each was sealed to (run with -race).
func TestSproutBoxKeyRotation_ConcurrentOpensDuringPromotion(t *testing.T) {
	enrollForTest(t)
	var payloads [][]byte
	for range 8 {
		payloads = append(payloads, farmerSeals(t))
	}
	submission, newPub, err := BeginSproutBoxKeyRotation("web-01")
	if err != nil {
		t.Fatal(err)
	}
	farmerAcceptsSubmission(t, submission)
	for range 8 {
		payloads = append(payloads, farmerSeals(t))
	}
	var wg sync.WaitGroup
	errs := make(chan error, len(payloads))
	for _, p := range payloads {
		wg.Go(func() {
			if _, err := SproutOpenFromFarmer("web-01", payloadbox.PurposeCmdRunRequest, p); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("SproutOpenFromFarmer: %v", err)
	}
	if got := sproutCurrentPub(t); got != newPub {
		t.Fatalf("current key is %s, want %s", got, newPub)
	}
}

// The previous key's grace window follows config.SproutBoxKeyPrevGrace:
// unset means the default, anything shorter than
// MinSproutBoxKeyPrevGrace is raised to it.
func TestSproutBoxKeyPrevGrace(t *testing.T) {
	orig := config.SproutBoxKeyPrevGrace
	t.Cleanup(func() { config.SproutBoxKeyPrevGrace = orig })
	for _, tc := range []struct{ set, want time.Duration }{
		{0, config.DefaultSproutBoxKeyPrevGrace},
		{-time.Minute, config.DefaultSproutBoxKeyPrevGrace},
		{time.Minute, MinSproutBoxKeyPrevGrace},
		{time.Hour, time.Hour},
	} {
		config.SproutBoxKeyPrevGrace = tc.set
		if got := SproutBoxKeyPrevGrace(); got != tc.want {
			t.Errorf("SproutBoxKeyPrevGrace() with %v configured = %v, want %v", tc.set, got, tc.want)
		}
	}
	// The default is the documented 3*DefaultMaxSkew.
	if config.DefaultSproutBoxKeyPrevGrace != 3*payloadbox.DefaultMaxSkew {
		t.Errorf("DefaultSproutBoxKeyPrevGrace = %v, want 3*DefaultMaxSkew", config.DefaultSproutBoxKeyPrevGrace)
	}
}

// A configured longer grace window keeps the previous key, and refuses
// another rotation, for that long.
func TestSproutBoxKeyRotation_ConfiguredGraceWindow(t *testing.T) {
	enrollForTest(t)
	orig := config.SproutBoxKeyPrevGrace
	t.Cleanup(func() { config.SproutBoxKeyPrevGrace = orig })
	config.SproutBoxKeyPrevGrace = time.Hour

	inFlight := farmerSeals(t)
	submission, _, err := BeginSproutBoxKeyRotation("web-01")
	if err != nil {
		t.Fatal(err)
	}
	farmerAcceptsSubmission(t, submission)
	sproutOpens(t, farmerSeals(t))

	// Past the default window, inside the configured one.
	replaced := time.Now().Add(-30 * time.Minute)
	if err := os.Chtimes(sproutPrevBoxPrivFile(), replaced, replaced); err != nil {
		t.Fatal(err)
	}
	if _, _, err := BeginSproutBoxKeyRotation("web-01"); !errors.Is(err, ErrSproutBoxKeyRotationTooSoon) {
		t.Fatalf("rotation inside the configured window = %v, want ErrSproutBoxKeyRotationTooSoon", err)
	}
	sproutOpens(t, inFlight)
	if !fileExists(sproutPrevBoxPrivFile()) {
		t.Fatal("previous key deleted inside the configured window")
	}
}
