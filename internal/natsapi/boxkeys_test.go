package natsapi

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
)

func TestHandlePKIRotateBoxKey_NoConnection(t *testing.T) {
	setupNatsAPIPKI(t)
	writeNKey(t, "", "accepted", "web-01", "UKEY_WEB01")

	tenantID := pki.CurrentTenantID()
	ClearNatsConn(tenantID)

	if _, err := handlePKIRotateBoxKey(tenantID, json.RawMessage(`{"id":"web-01"}`)); err == nil {
		t.Fatal("expected an error when no NATS connection is available")
	}
}

func TestHandlePKIRotateBoxKey_MissingID(t *testing.T) {
	setupNatsAPIPKI(t)

	if _, err := handlePKIRotateBoxKey(pki.CurrentTenantID(), json.RawMessage(`{}`)); err == nil {
		t.Fatal("expected an error when id is missing")
	}
}

func TestHandlePKIRotateBoxKey_UnknownSprout(t *testing.T) {
	setupNatsAPIPKI(t)

	if _, err := handlePKIRotateBoxKey(pki.CurrentTenantID(), json.RawMessage(`{"id":"does-not-exist"}`)); err == nil {
		t.Fatal("expected an error for an unknown sprout")
	}
}

func TestHandlePKIRotateBoxKey_InvalidJSON(t *testing.T) {
	setupNatsAPIPKI(t)

	if _, err := handlePKIRotateBoxKey(pki.CurrentTenantID(), json.RawMessage(`{invalid`)); err == nil {
		t.Fatal("expected an error for invalid JSON")
	}
}

// TestHandlePKIRotateBoxKey_PublishesInstructionOnly asserts the rotate
// command carries no key material — see this file's header comment and
// the design doc's explicit rejection of farmer ever generating or
// transmitting a sprout's private key.
func TestHandlePKIRotateBoxKey_PublishesInstructionOnly(t *testing.T) {
	setupNatsAPIPKI(t)
	writeNKey(t, "", "accepted", "web-01", "UKEY_WEB01")

	nc, cleanup := startEmbeddedNATS(t)
	t.Cleanup(cleanup)
	tenantID := pki.CurrentTenantID()
	SetNatsConn(tenantID, nc)
	t.Cleanup(func() { ClearNatsConn(tenantID) })

	sub, err := nc.SubscribeSync(SproutSubject("web-01", SproutBoxKeyRotateCmd))
	if err != nil {
		t.Fatalf("subscribing: %v", err)
	}

	result, err := handlePKIRotateBoxKey(tenantID, json.RawMessage(`{"id":"web-01"}`))
	if err != nil {
		t.Fatalf("handlePKIRotateBoxKey: %v", err)
	}
	if m, ok := result.(map[string]bool); !ok || !m["success"] {
		t.Fatalf("expected success=true, got %v", result)
	}

	msg, err := sub.NextMsg(2 * time.Second)
	if err != nil {
		t.Fatalf("expected the sprout to receive a rotate instruction: %v", err)
	}
	if len(msg.Data) != 0 {
		t.Errorf("expected an empty (no key material) instruction payload, got %q", msg.Data)
	}
}

// sealedSubmission is a box key submission as a real sprout would send
// it: sealed under its current key (signer) and pinned tenant key.
func sealedSubmission(t *testing.T, signer sproutKeypair, sproutID, newPub string) *nats.Msg {
	t.Helper()
	msg := nats.NewMsg(SproutSubject(sproutID, "boxkey.pub"))
	msg.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	msg.Data = sealAsSprout(t, signer, pki.CurrentTenantID(), pinnedTenantPub(t, pki.CurrentTenantID()), sproutID,
		payloadbox.PurposeBoxKeySubmit, boxKeySubmitRequest{Pub: newPub})
	return msg
}

func activeAndGrace(t *testing.T, sproutID string) (string, []string) {
	t.Helper()
	active, grace, err := pki.ValidSproutBoxKeys(pki.CurrentTenantID(), sproutID)
	if err != nil {
		t.Fatalf("ValidSproutBoxKeys: %v", err)
	}
	return active, grace
}

func TestHandleBoxKeySubmit_SealedUnderCurrentKeyRotates(t *testing.T) {
	setupCryptoTest(t)
	current, next := newSproutKeypair(t), newSproutKeypair(t)
	enrollSprout(t, pki.CurrentTenantID(), "web-01", current)

	handleBoxKeySubmit(pki.CurrentTenantID(), sealedSubmission(t, current, "web-01", next.pubB64()))

	active, grace := activeAndGrace(t, "web-01")
	if active != next.pubB64() {
		t.Errorf("expected active key %q, got %q", next.pubB64(), active)
	}
	if len(grace) != 1 || grace[0] != current.pubB64() {
		t.Errorf("expected the old key in grace, got %v", grace)
	}
}

// What a compromised bus would try: substitute its own key, so farmer
// seals everything for that sprout to it from then on.
func TestHandleBoxKeySubmit_RefusesKeySubstitution(t *testing.T) {
	setupCryptoTest(t)
	current, attacker := newSproutKeypair(t), newSproutKeypair(t)
	enrollSprout(t, pki.CurrentTenantID(), "web-01", current)

	plaintext := &nats.Msg{
		Subject: SproutSubject("web-01", "boxkey.pub"),
		Data:    mustMarshal(t, boxKeySubmitRequest{Pub: attacker.pubB64()}),
	}
	cases := map[string]*nats.Msg{
		"plaintext": plaintext,
		// Marked sealed, but sealed under the attacker's own key, which
		// farmer has no record of.
		"sealed under an unknown key": sealedSubmission(t, attacker, "web-01", attacker.pubB64()),
	}
	for name, msg := range cases {
		t.Run(name, func(t *testing.T) {
			handleBoxKeySubmit(pki.CurrentTenantID(), msg)
			if active, _ := activeAndGrace(t, "web-01"); active != current.pubB64() {
				t.Fatalf("active key changed to %q", active)
			}
		})
	}
}

func TestHandleBoxKeySubmit_RefusesStaleSubmission(t *testing.T) {
	setupCryptoTest(t)
	current, next := newSproutKeypair(t), newSproutKeypair(t)
	enrollSprout(t, pki.CurrentTenantID(), "web-01", current)

	body := mustMarshal(t, boxKeySubmitRequest{Pub: next.pubB64()})
	stale := payloadbox.Message{V: payloadbox.Version, Purpose: payloadbox.PurposeBoxKeySubmit, TenantID: pki.CurrentTenantID(), SproutID: "web-01",
		ID: "stale", IssuedAt: time.Now().Add(-time.Hour).Unix(), Body: body}
	data, err := payloadbox.Seal(stale, []payloadbox.KeyPair{{PeerPub: pinnedTenantPub(t, pki.CurrentTenantID()), Priv: current.priv}})
	if err != nil {
		t.Fatal(err)
	}
	msg := nats.NewMsg(SproutSubject("web-01", "boxkey.pub"))
	msg.Header.Set(payloadbox.Header, payloadbox.HeaderBox1)
	msg.Data = data
	handleBoxKeySubmit(pki.CurrentTenantID(), msg)
	if active, _ := activeAndGrace(t, "web-01"); active != current.pubB64() {
		t.Fatalf("a stale submission changed the active key to %q", active)
	}
}

// Replaying an earlier, genuine submission while its signing key is
// still in grace must not roll the sprout back to a key it already left.
func TestHandleBoxKeySubmit_RefusesRollback(t *testing.T) {
	setupCryptoTest(t)
	k1, k2, k3 := newSproutKeypair(t), newSproutKeypair(t), newSproutKeypair(t)
	enrollSprout(t, pki.CurrentTenantID(), "web-01", k1)
	toK2 := sealedSubmission(t, k1, "web-01", k2.pubB64())
	handleBoxKeySubmit(pki.CurrentTenantID(), toK2)
	handleBoxKeySubmit(pki.CurrentTenantID(), sealedSubmission(t, k2, "web-01", k3.pubB64()))
	// k1 and k2 are both still in grace; replay k1's submission of k2.
	handleBoxKeySubmit(pki.CurrentTenantID(), toK2)
	if active, _ := activeAndGrace(t, "web-01"); active != k3.pubB64() {
		t.Fatalf("replayed submission rolled the active key back to %q", active)
	}
}

// Security review 2026-10, M3: a submission sealed under a key that is
// only in its grace window can't change the active key. Under the active
// key it can.
func TestHandleBoxKeySubmit_GraceKeyRefusedActiveKeyAccepted(t *testing.T) {
	setupCryptoTest(t)
	k1, k2, attacker := newSproutKeypair(t), newSproutKeypair(t), newSproutKeypair(t)
	enrollSprout(t, pki.CurrentTenantID(), "web-01", k1)
	handleBoxKeySubmit(pki.CurrentTenantID(), sealedSubmission(t, k1, "web-01", k2.pubB64()))
	if active, grace := activeAndGrace(t, "web-01"); active != k2.pubB64() || len(grace) != 1 || grace[0] != k1.pubB64() {
		t.Fatalf("setup: active %s grace %v", active, grace)
	}

	// k1 leaked: sealed under it (now grace), naming the attacker's key.
	handleBoxKeySubmit(pki.CurrentTenantID(), sealedSubmission(t, k1, "web-01", attacker.pubB64()))
	if active, _ := activeAndGrace(t, "web-01"); active != k2.pubB64() {
		t.Fatalf("a submission under a grace key changed the active key to %q", active)
	}

	// The same key may re-assert the active one (a sprout retrying):
	// accepted, and nothing changes.
	handleBoxKeySubmit(pki.CurrentTenantID(), sealedSubmission(t, k1, "web-01", k2.pubB64()))
	if active, grace := activeAndGrace(t, "web-01"); active != k2.pubB64() || len(grace) != 1 {
		t.Fatalf("re-assertion changed the keys: active %s grace %v", active, grace)
	}

	// Under the active key, the same request goes through.
	handleBoxKeySubmit(pki.CurrentTenantID(), sealedSubmission(t, k2, "web-01", attacker.pubB64()))
	if active, _ := activeAndGrace(t, "web-01"); active != attacker.pubB64() {
		t.Fatalf("a submission under the active key was refused: active %q", active)
	}
}

// Security review 2026-10, M4: the sprout ID is exactly one subject
// token. A dotted or reserved one, or any other subject shape, is
// ignored.
func TestHandleBoxKeySubmit_RefusesInvalidSproutIDs(t *testing.T) {
	setupCryptoTest(t)
	current, next := newSproutKeypair(t), newSproutKeypair(t)
	enrollSprout(t, pki.CurrentTenantID(), "web-01", current)
	for _, subject := range []string{
		"imas.sprouts.web-01.example.boxkey.pub", // a dotted ID
		"imas.sprouts.announce.boxkey.pub",
		"imas.sprouts.web-01.boxkey.pub.extra",
		"imas.other.web-01.boxkey.pub",
	} {
		msg := sealedSubmission(t, current, "web-01", next.pubB64())
		msg.Subject = subject
		handleBoxKeySubmit(pki.CurrentTenantID(), msg) // must not panic
		if active, _ := activeAndGrace(t, "web-01"); active != current.pubB64() {
			t.Fatalf("submission on %s changed the active key", subject)
		}
	}
}

func TestHandleBoxKeySubmit_IgnoresMalformedSubject(t *testing.T) {
	setupCryptoTest(t)
	// Fewer than 4 dot-separated components: no sprout ID to key off of.
	msg := &nats.Msg{Subject: "imas.sprouts.boxkey.pub", Data: mustMarshal(t, boxKeySubmitRequest{Pub: testBoxPubForNatsAPI(t)})}
	handleBoxKeySubmit(pki.CurrentTenantID(), msg) // must not panic
}

func TestHandleBoxKeySubmit_IgnoresEmptyPub(t *testing.T) {
	setupCryptoTest(t)
	current := newSproutKeypair(t)
	enrollSprout(t, pki.CurrentTenantID(), "web-01", current)
	handleBoxKeySubmit(pki.CurrentTenantID(), sealedSubmission(t, current, "web-01", ""))
	if active, _ := activeAndGrace(t, "web-01"); active != current.pubB64() {
		t.Fatalf("an empty submission changed the active key to %q", active)
	}
}

// Rotating the tenant key over the API rotates the calling tenant's key,
// and only that tenant's.
func TestHandlePKIRotateTenantBoxKey(t *testing.T) {
	setupCryptoTest(t)
	beforeA, _ := pki.GetTenantX25519PublicKey("t_a")
	beforeB, _ := pki.GetTenantX25519PublicKey("t_b")

	result, err := handlePKIRotateTenantBoxKey("t_a", json.RawMessage(`{"token":"ignored"}`))
	if err != nil {
		t.Fatalf("handlePKIRotateTenantBoxKey: %v", err)
	}
	rot, ok := result.(*pki.TenantKeyRotation)
	if !ok || rot.TenantID != "t_a" || rot.Severed || rot.Version != 2 {
		t.Fatalf("result %#v", result)
	}
	if afterA, _ := pki.GetTenantX25519PublicKey("t_a"); afterA == beforeA || afterA != rot.Pub {
		t.Errorf("t_a key %q after rotation, want %q", afterA, rot.Pub)
	}
	if afterB, _ := pki.GetTenantX25519PublicKey("t_b"); afterB != beforeB {
		t.Error("rotating t_a changed t_b's key")
	}

	result, err = handlePKIRotateTenantBoxKey("t_a", json.RawMessage(`{"sever":true}`))
	if err != nil || !result.(*pki.TenantKeyRotation).Severed {
		t.Fatalf("severing rotation: %#v, %v", result, err)
	}
	if _, err := handlePKIRotateTenantBoxKey("t_a", json.RawMessage(`{bad`)); err == nil {
		t.Error("expected an error for invalid JSON")
	}
}

func testBoxPubForNatsAPI(t *testing.T) string {
	t.Helper()
	pub, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating box key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(pub[:])
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}
