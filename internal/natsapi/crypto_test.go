package natsapi

// Round-trips crypto.go's helpers against a stand-in sprout that uses its
// own real X25519 keypair with internal/payloadbox directly (not
// internal/pki's farmer-side lookups), so a round trip here exercises the
// same wire format and key-lookup logic a real farmer<->sprout exchange
// would.
import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/payloadbox"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/pki/tenantboxtest"
)

// setupCryptoTest wires up an isolated PKI store (setupNatsAPIPKI,
// pki_handlers_test.go) plus a mock OpenBao KV v2 server backing tenant
// keypairs, with every tenant these tests use dropped from pki's
// in-process key cache before and after.
func setupCryptoTest(t *testing.T) *tenantboxtest.Server {
	t.Helper()
	setupNatsAPIPKI(t)
	srv := tenantboxtest.Start(t)
	tenants := []string{pki.CurrentTenantID(), "t_a", "t_b"}
	for _, id := range tenants {
		pki.InvalidateTenantBoxKeys(id)
	}
	t.Cleanup(func() {
		for _, id := range tenants {
			pki.InvalidateTenantBoxKeys(id)
		}
	})
	orig := config.BoxKeyGraceDuration
	config.BoxKeyGraceDuration = time.Hour
	t.Cleanup(func() { config.BoxKeyGraceDuration = orig })
	return srv
}

// sproutKeypair is a test stand-in for a real sprout's locally-generated,
// never-transmitted X25519 keypair.
type sproutKeypair struct {
	pub, priv *[32]byte
}

func newSproutKeypair(t *testing.T) sproutKeypair {
	t.Helper()
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating sprout keypair: %v", err)
	}
	return sproutKeypair{pub: pub, priv: priv}
}

func (k sproutKeypair) pubB64() string {
	return base64.StdEncoding.EncodeToString(k.pub[:])
}

// enrollSprout records sprout as sproutID's active box key under tenantID.
func enrollSprout(t *testing.T, tenantID, sproutID string, sprout sproutKeypair) {
	t.Helper()
	if err := pki.RotateSproutBoxKey(tenantID, sproutID, sprout.pubB64(), time.Hour); err != nil {
		t.Fatalf("seeding %s/%s box key: %v", tenantID, sproutID, err)
	}
}

// pinnedTenantPub is the tenant public key a sprout of tenantID pins.
func pinnedTenantPub(t *testing.T, tenantID string) *[32]byte {
	t.Helper()
	b64, err := pki.GetTenantX25519PublicKey(tenantID)
	if err != nil {
		t.Fatalf("GetTenantX25519PublicKey(%s): %v", tenantID, err)
	}
	pub, err := pki.DecodeBoxPubKey(b64)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// sealAsSprout seals body the way a real sprout would: under its own
// private key and its pinned tenant public key.
func sealAsSprout(t *testing.T, sprout sproutKeypair, tenantPub *[32]byte, sproutID, purpose string, body any) []byte {
	t.Helper()
	msg, err := payloadbox.NewMessage(purpose, sproutID, "", body)
	if err != nil {
		t.Fatal(err)
	}
	data, err := payloadbox.Seal(msg, []payloadbox.KeyPair{{PeerPub: tenantPub, Priv: sprout.priv}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// openAsSprout opens data the way a real sprout would.
func openAsSprout(sprout sproutKeypair, tenantPub *[32]byte, sproutID, purpose string, data []byte) (*payloadbox.Message, error) {
	return payloadbox.Open(data, []payloadbox.KeyPair{{PeerPub: tenantPub, Priv: sprout.priv}},
		payloadbox.Expect{Purpose: purpose, SproutID: sproutID})
}

func TestPublishEncryptedTo_NoConnection(t *testing.T) {
	setupCryptoTest(t)
	enrollSprout(t, pki.CurrentTenantID(), "web-01", newSproutKeypair(t))
	ClearNatsConn(pki.CurrentTenantID())

	if err := PublishEncryptedTo(pki.CurrentTenantID(), "web-01", "imas.sprouts.web-01.test", payloadbox.PurposeCmdRunRequest, map[string]string{"msg": "hi"}); err == nil {
		t.Fatal("expected an error when no NATS connection is available")
	}
}

func TestPublishEncryptedTo_SproutOpensIt(t *testing.T) {
	setupCryptoTest(t)
	tenantID := pki.CurrentTenantID()
	sprout := newSproutKeypair(t)
	enrollSprout(t, tenantID, "web-01", sprout)

	nc, cleanup := startEmbeddedNATS(t)
	t.Cleanup(cleanup)
	SetNatsConn(tenantID, nc)
	t.Cleanup(func() { ClearNatsConn(tenantID) })
	sub, err := nc.SubscribeSync("imas.sprouts.web-01.test")
	if err != nil {
		t.Fatal(err)
	}

	if err := PublishEncryptedTo(tenantID, "web-01", "imas.sprouts.web-01.test", payloadbox.PurposeCmdRunRequest, map[string]string{"cmd": "reboot"}); err != nil {
		t.Fatalf("PublishEncryptedTo: %v", err)
	}
	m, err := sub.NextMsg(2 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if m.Header.Get(payloadbox.Header) != payloadbox.HeaderBox1 {
		t.Error("published message isn't marked sealed")
	}
	msg, err := openAsSprout(sprout, pinnedTenantPub(t, tenantID), "web-01", payloadbox.PurposeCmdRunRequest, m.Data)
	if err != nil {
		t.Fatalf("sprout couldn't open it: %v", err)
	}
	if string(msg.Body) != `{"cmd":"reboot"}` {
		t.Errorf("unexpected body: %s", msg.Body)
	}
}

func TestDecryptEncryptedFrom_DecryptsRealSproutPayload(t *testing.T) {
	setupCryptoTest(t)
	sprout := newSproutKeypair(t)
	enrollSprout(t, pki.CurrentTenantID(), "web-01", sprout)

	sealed := sealAsSprout(t, sprout, pinnedTenantPub(t, pki.CurrentTenantID()), "web-01", payloadbox.PurposeCmdRunResponse, map[string]string{"os": "linux"})
	var out struct {
		OS string `json:"os"`
	}
	if _, err := DecryptEncryptedFrom(pki.CurrentTenantID(), "web-01", payloadbox.PurposeCmdRunResponse, sealed, &out); err != nil {
		t.Fatalf("DecryptEncryptedFrom: %v", err)
	}
	if out.OS != "linux" {
		t.Errorf("expected os=linux, got %q", out.OS)
	}
	// The same bytes, expected as another boundary's payload, don't open.
	if _, err := DecryptEncryptedFrom(pki.CurrentTenantID(), "web-01", payloadbox.PurposeBoxKeySubmit, sealed, nil); !errors.Is(err, ErrDecryptFailed) {
		t.Errorf("opened under the wrong purpose: %v", err)
	}
}

func TestDecryptEncryptedFrom_SproutKeyGracePeriod(t *testing.T) {
	setupCryptoTest(t)
	tenantID := pki.CurrentTenantID()
	oldSprout, newSprout, expiredSprout := newSproutKeypair(t), newSproutKeypair(t), newSproutKeypair(t)
	tenantPub := pinnedTenantPub(t, tenantID)

	enrollSprout(t, tenantID, "web-01", oldSprout)
	enrollSprout(t, tenantID, "web-01", newSprout) // old key now in grace
	sealed := sealAsSprout(t, oldSprout, tenantPub, "web-01", payloadbox.PurposeCmdRunResponse, "in flight")
	if _, err := DecryptEncryptedFrom(tenantID, "web-01", payloadbox.PurposeCmdRunResponse, sealed, nil); err != nil {
		t.Fatalf("expected the graced old key to still decrypt, got: %v", err)
	}

	enrollSprout(t, tenantID, "web-02", expiredSprout)
	// A negative grace duration: the old key's window has already closed.
	if err := pki.RotateSproutBoxKey(tenantID, "web-02", newSproutKeypair(t).pubB64(), -time.Hour); err != nil {
		t.Fatal(err)
	}
	sealed = sealAsSprout(t, expiredSprout, tenantPub, "web-02", payloadbox.PurposeCmdRunResponse, "late")
	if _, err := DecryptEncryptedFrom(tenantID, "web-02", payloadbox.PurposeCmdRunResponse, sealed, nil); err == nil {
		t.Fatal("expected decryption under an expired grace-period key to fail")
	}
}

// A sprout that hasn't re-pinned since a tenant key rotation still seals
// under the old tenant key; farmer opens it inside the grace window.
func TestDecryptEncryptedFrom_TenantKeyGracePeriod(t *testing.T) {
	setupCryptoTest(t)
	tenantID := pki.CurrentTenantID()
	sprout := newSproutKeypair(t)
	enrollSprout(t, tenantID, "web-01", sprout)
	oldTenantPub := pinnedTenantPub(t, tenantID)
	if _, err := pki.RotateTenantX25519Keypair(tenantID, false); err != nil {
		t.Fatal(err)
	}
	sealed := sealAsSprout(t, sprout, oldTenantPub, "web-01", payloadbox.PurposeCmdRunResponse, "not re-pinned yet")
	if _, err := DecryptEncryptedFrom(tenantID, "web-01", payloadbox.PurposeCmdRunResponse, sealed, nil); err != nil {
		t.Fatalf("payload under the previous tenant key, inside grace: %v", err)
	}
}

func TestDecryptEncryptedFrom_WrongSproutTamperedAndMalformedFail(t *testing.T) {
	setupCryptoTest(t)
	tenantID := pki.CurrentTenantID()
	sproutA, sproutB := newSproutKeypair(t), newSproutKeypair(t)
	enrollSprout(t, tenantID, "web-a", sproutA)
	enrollSprout(t, tenantID, "web-b", sproutB)
	tenantPub := pinnedTenantPub(t, tenantID)

	// Sealed as sprout A, but farmer is told it came from sprout B.
	sealed := sealAsSprout(t, sproutA, tenantPub, "web-a", payloadbox.PurposeCmdRunResponse, "x")
	if _, err := DecryptEncryptedFrom(tenantID, "web-b", payloadbox.PurposeCmdRunResponse, sealed, nil); !errors.Is(err, ErrDecryptFailed) {
		t.Errorf("wrong sprout: %v", err)
	}

	var env payloadbox.Envelope
	json.Unmarshal(sealed, &env)
	env.Copies[0].Box[0] ^= 0xFF
	tampered, _ := json.Marshal(env)
	if _, err := DecryptEncryptedFrom(tenantID, "web-a", payloadbox.PurposeCmdRunResponse, tampered, nil); !errors.Is(err, ErrDecryptFailed) {
		t.Errorf("tampered: %v", err)
	}
	for _, bad := range []string{"not json", `{"n":"aGk=","c":"aGk="}`} {
		if _, err := DecryptEncryptedFrom(tenantID, "web-a", payloadbox.PurposeCmdRunResponse, []byte(bad), nil); !errors.Is(err, ErrDecryptFailed) {
			t.Errorf("malformed %q: %v", bad, err)
		}
	}
	// A sprout farmer has no box key for.
	if _, err := DecryptEncryptedFrom(tenantID, "web-unknown", payloadbox.PurposeCmdRunResponse, sealed, nil); !errors.Is(err, ErrDecryptFailed) {
		t.Errorf("unknown sprout: %v", err)
	}
}

// TestDecryptEncryptedFrom_TwoTenantsSameSproutID_DecryptConcurrentlyWithoutCrossing
// exercises the decrypt path against two distinct tenants that both have
// a sprout named "web-01", each with its own box key and now each with
// its own tenant key too. Both tenants' payloads are decrypted
// concurrently, and each must only ever decrypt under its own tenant's
// keys: sprout_id is only unique per tenant (CLAUDE.md, "Tenant safety"),
// so any lookup keyed on sprout_id alone would show up here.
func TestDecryptEncryptedFrom_TwoTenantsSameSproutID_DecryptConcurrentlyWithoutCrossing(t *testing.T) {
	setupCryptoTest(t)
	const sproutID = "web-01"
	sproutA, sproutB := newSproutKeypair(t), newSproutKeypair(t)
	enrollSprout(t, "t_a", sproutID, sproutA)
	enrollSprout(t, "t_b", sproutID, sproutB)
	pubA, pubB := pinnedTenantPub(t, "t_a"), pinnedTenantPub(t, "t_b")
	if *pubA == *pubB {
		t.Fatal("two tenants share a tenant key")
	}

	sealedA := sealAsSprout(t, sproutA, pubA, sproutID, payloadbox.PurposeCmdRunResponse, map[string]string{"tenant": "a"})
	sealedB := sealAsSprout(t, sproutB, pubB, sproutID, payloadbox.PurposeCmdRunResponse, map[string]string{"tenant": "b"})

	type result struct {
		tenant string
		out    map[string]string
		err    error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for tenant, sealed := range map[string][]byte{"t_a": sealedA, "t_b": sealedB} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var out map[string]string
			_, err := DecryptEncryptedFrom(tenant, sproutID, payloadbox.PurposeCmdRunResponse, sealed, &out)
			results <- result{tenant, out, err}
		}()
	}
	wg.Wait()
	close(results)
	for r := range results {
		if r.err != nil {
			t.Fatalf("DecryptEncryptedFrom(%s) failed: %v", r.tenant, r.err)
		}
		if r.out["tenant"] != r.tenant[len(r.tenant)-1:] {
			t.Errorf("%s decrypted %v", r.tenant, r.out)
		}
	}

	if _, err := DecryptEncryptedFrom("t_b", sproutID, payloadbox.PurposeCmdRunResponse, sealedA, nil); err == nil {
		t.Error("t_a's payload decrypted as t_b's")
	}
	if _, err := DecryptEncryptedFrom("t_a", sproutID, payloadbox.PurposeCmdRunResponse, sealedB, nil); err == nil {
		t.Error("t_b's payload decrypted as t_a's")
	}
}
