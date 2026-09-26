package natsapi

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/config"
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

func TestHandleBoxKeySubmit_RecordsNewActiveKey(t *testing.T) {
	setupNatsAPIPKI(t)
	pub := testBoxPubForNatsAPI(t)

	msg := &nats.Msg{
		Subject: SproutSubject("web-01", "boxkey.pub"),
		Data:    mustMarshal(t, boxKeySubmitRequest{Pub: pub}),
	}
	handleBoxKeySubmit(pki.CurrentTenantID(), msg)

	active, _, err := pki.ValidSproutBoxKeys(pki.CurrentTenantID(), "web-01")
	if err != nil {
		t.Fatalf("ValidSproutBoxKeys: %v", err)
	}
	if active != pub {
		t.Errorf("expected active key %q, got %q", pub, active)
	}
}

func TestHandleBoxKeySubmit_GracesThePreviousKey(t *testing.T) {
	setupNatsAPIPKI(t)
	origGrace := config.BoxKeyGraceDuration
	config.BoxKeyGraceDuration = time.Hour
	t.Cleanup(func() { config.BoxKeyGraceDuration = origGrace })

	oldPub := testBoxPubForNatsAPI(t)
	newPub := testBoxPubForNatsAPI(t)

	if err := pki.RotateSproutBoxKey(pki.CurrentTenantID(), "web-01", oldPub, time.Hour); err != nil {
		t.Fatalf("seeding initial key: %v", err)
	}

	msg := &nats.Msg{
		Subject: SproutSubject("web-01", "boxkey.pub"),
		Data:    mustMarshal(t, boxKeySubmitRequest{Pub: newPub}),
	}
	handleBoxKeySubmit(pki.CurrentTenantID(), msg)

	active, grace, err := pki.ValidSproutBoxKeys(pki.CurrentTenantID(), "web-01")
	if err != nil {
		t.Fatalf("ValidSproutBoxKeys: %v", err)
	}
	if active != newPub {
		t.Errorf("expected active key %q, got %q", newPub, active)
	}
	if len(grace) != 1 || grace[0] != oldPub {
		t.Errorf("expected old key %q in grace, got %v", oldPub, grace)
	}
}

func TestHandleBoxKeySubmit_IgnoresMalformedSubject(t *testing.T) {
	setupNatsAPIPKI(t)
	// Fewer than 4 dot-separated components: no sprout ID to key off of.
	msg := &nats.Msg{Subject: "imas.sprouts.boxkey.pub", Data: mustMarshal(t, boxKeySubmitRequest{Pub: testBoxPubForNatsAPI(t)})}
	handleBoxKeySubmit(pki.CurrentTenantID(), msg) // must not panic
}

func TestHandleBoxKeySubmit_IgnoresEmptyPub(t *testing.T) {
	setupNatsAPIPKI(t)
	msg := &nats.Msg{Subject: SproutSubject("web-01", "boxkey.pub"), Data: mustMarshal(t, boxKeySubmitRequest{Pub: ""})}
	handleBoxKeySubmit(pki.CurrentTenantID(), msg)

	if _, _, err := pki.ValidSproutBoxKeys(pki.CurrentTenantID(), "web-01"); err == nil {
		t.Fatal("expected no box key to be recorded for an empty pub")
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
