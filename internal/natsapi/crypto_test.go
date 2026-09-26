package natsapi

// Round-trips crypto.go's shared encrypt/decrypt helper against real NaCl
// box operations on both ends: the "sprout" side in these tests uses its
// own real X25519 keypair directly (golang.org/x/crypto/nacl/box), not
// this package's helper, so a round trip here exercises the same wire
// format and key-lookup logic a real farmer<->sprout exchange would.
import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/yogzblr/imas/internal/pki"
)

// mockTenantBoxKVServer serves a fixed, pre-seeded tenant keypair from
// OpenBao's KV v2 read endpoint — enough for pki.GetTenantX25519KeyPair
// to succeed without ever needing to write (this package doesn't need to
// exercise tenantbox.go's bootstrap-race handling; internal/pki's own
// tests already cover that). See internal/pki/tenantbox_test.go's
// mockKVv2Server for the same shape, duplicated here since that type is
// unexported in a different package.
type mockTenantBoxKVServer struct {
	mount, path, token string
	pub, priv          [32]byte
}

func (m *mockTenantBoxKVServer) start(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/"+m.mount+"/data/"+m.path, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != m.token {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"data": map[string]string{
					"pub":  base64.StdEncoding.EncodeToString(m.pub[:]),
					"priv": base64.StdEncoding.EncodeToString(m.priv[:]),
				},
			},
		})
	})
	return httptest.NewServer(mux)
}

// setupCryptoTest wires up an isolated PKI store (setupNatsAPIPKI,
// pki_handlers_test.go) plus a mock OpenBao KV server backing the tenant
// keypair. Only the first test in this package to reach
// pki.GetTenantX25519KeyPair actually needs the server to be live — once
// bootstrapped, the keypair is cached in-process for the rest of the test
// binary (see tenantbox.go) — but every test sets it up the same way so
// none of them depend on run order.
func setupCryptoTest(t *testing.T) *mockTenantBoxKVServer {
	t.Helper()
	setupNatsAPIPKI(t)

	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating mock tenant keypair: %v", err)
	}
	srv := &mockTenantBoxKVServer{mount: "secret", path: "imas/tenant-x25519", token: "test-token", pub: *pub, priv: *priv}
	ts := srv.start(t)
	t.Cleanup(ts.Close)

	t.Setenv(pki.EnvTenantBoxOpenBaoAddr, ts.URL)
	t.Setenv(pki.EnvTenantBoxOpenBaoKVMount, srv.mount)
	t.Setenv(pki.EnvTenantBoxOpenBaoKVPath, srv.path)
	t.Setenv(pki.EnvTenantBoxOpenBaoAuthMethod, pki.TenantBoxAuthMethodToken)
	t.Setenv(pki.EnvTenantBoxOpenBaoToken, srv.token)

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

// sealAsSprout seals plaintext the way a real sprout would: under its own
// private key and the tenant's public key, using the same
// EncryptedEnvelope wire shape crypto.go defines.
func sealAsSprout(t *testing.T, sprout sproutKeypair, tenantPub *[32]byte, plaintext []byte) []byte {
	t.Helper()
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatalf("generating nonce: %v", err)
	}
	sealed := box.Seal(nil, plaintext, &nonce, tenantPub, sprout.priv)
	data, err := json.Marshal(EncryptedEnvelope{Nonce: nonce[:], Ciphertext: sealed})
	if err != nil {
		t.Fatalf("marshaling envelope: %v", err)
	}
	return data
}

// openAsSprout opens data the way a real sprout would: under its own
// private key and the tenant's public key.
func openAsSprout(t *testing.T, sprout sproutKeypair, tenantPub *[32]byte, data []byte) ([]byte, bool) {
	t.Helper()
	var env EncryptedEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("unmarshaling envelope: %v", err)
	}
	var nonce [24]byte
	copy(nonce[:], env.Nonce)
	return box.Open(nil, env.Ciphertext, &nonce, tenantPub, sprout.priv)
}

// TestPublishEncryptedTo_NoConnection covers PublishEncryptedTo's own
// guard; the actual sealing logic it delegates to is exercised directly
// (without needing a live NATS connection) by
// TestSealForSprout_RoundTripsWithSprout below.
func TestPublishEncryptedTo_NoConnection(t *testing.T) {
	setupCryptoTest(t)
	sprout := newSproutKeypair(t)
	if err := pki.RotateSproutBoxKey(pki.CurrentTenantID(), "web-01", sprout.pubB64(), time.Hour); err != nil {
		t.Fatalf("seeding sprout box key: %v", err)
	}

	ClearNatsConn(pki.CurrentTenantID())

	type payload struct {
		Msg string `json:"msg"`
	}
	if err := PublishEncryptedTo(pki.CurrentTenantID(), "web-01", "imas.sprouts.web-01.test", payload{Msg: "hi"}); err == nil {
		t.Fatal("expected an error when no NATS connection is available")
	}
}

func TestSealForSprout_RoundTripsWithSprout(t *testing.T) {
	setupCryptoTest(t)
	sprout := newSproutKeypair(t)
	if err := pki.RotateSproutBoxKey(pki.CurrentTenantID(), "web-01", sprout.pubB64(), time.Hour); err != nil {
		t.Fatalf("seeding sprout box key: %v", err)
	}
	tenantPub, _, err := pki.GetTenantX25519KeyPair()
	if err != nil {
		t.Fatalf("GetTenantX25519KeyPair: %v", err)
	}

	sealed, err := sealForSprout(pki.CurrentTenantID(), "web-01", []byte(`{"cmd":"reboot"}`))
	if err != nil {
		t.Fatalf("sealForSprout: %v", err)
	}

	plaintext, ok := openAsSprout(t, sprout, tenantPub, sealed)
	if !ok {
		t.Fatal("expected the sprout to be able to open the sealed payload")
	}
	if string(plaintext) != `{"cmd":"reboot"}` {
		t.Errorf("unexpected plaintext: %s", plaintext)
	}
}

func TestOpenFromSprout_DecryptsRealSproutPayload(t *testing.T) {
	setupCryptoTest(t)
	sprout := newSproutKeypair(t)
	if err := pki.RotateSproutBoxKey(pki.CurrentTenantID(), "web-01", sprout.pubB64(), time.Hour); err != nil {
		t.Fatalf("seeding sprout box key: %v", err)
	}
	tenantPub, _, err := pki.GetTenantX25519KeyPair()
	if err != nil {
		t.Fatalf("GetTenantX25519KeyPair: %v", err)
	}

	sealed := sealAsSprout(t, sprout, tenantPub, []byte(`{"os":"linux"}`))

	var out struct {
		OS string `json:"os"`
	}
	if err := DecryptEncryptedFrom(pki.CurrentTenantID(), "web-01", sealed, &out); err != nil {
		t.Fatalf("DecryptEncryptedFrom: %v", err)
	}
	if out.OS != "linux" {
		t.Errorf("expected os=linux, got %q", out.OS)
	}
}

func TestOpenFromSprout_GracePeriodStillDecrypts(t *testing.T) {
	setupCryptoTest(t)
	oldSprout := newSproutKeypair(t)
	newSprout := newSproutKeypair(t)
	if err := pki.RotateSproutBoxKey(pki.CurrentTenantID(), "web-01", oldSprout.pubB64(), time.Hour); err != nil {
		t.Fatalf("seeding initial sprout box key: %v", err)
	}
	// Rotate to a new key; the old one should remain valid for the grace
	// window per the design doc's "Key rotation".
	if err := pki.RotateSproutBoxKey(pki.CurrentTenantID(), "web-01", newSprout.pubB64(), time.Hour); err != nil {
		t.Fatalf("rotating sprout box key: %v", err)
	}
	tenantPub, _, err := pki.GetTenantX25519KeyPair()
	if err != nil {
		t.Fatalf("GetTenantX25519KeyPair: %v", err)
	}

	// A message still in flight, encrypted under the now-graced old key,
	// must still decrypt.
	sealed := sealAsSprout(t, oldSprout, tenantPub, []byte(`{"still":"valid"}`))
	var out map[string]string
	if err := DecryptEncryptedFrom(pki.CurrentTenantID(), "web-01", sealed, &out); err != nil {
		t.Fatalf("expected the graced old key to still decrypt, got: %v", err)
	}
	if out["still"] != "valid" {
		t.Errorf("unexpected plaintext: %v", out)
	}
}

func TestOpenFromSprout_ExpiredGraceKeyFailsToDecrypt(t *testing.T) {
	setupCryptoTest(t)
	oldSprout := newSproutKeypair(t)
	newSprout := newSproutKeypair(t)
	if err := pki.RotateSproutBoxKey(pki.CurrentTenantID(), "web-01", oldSprout.pubB64(), time.Hour); err != nil {
		t.Fatalf("seeding initial sprout box key: %v", err)
	}
	// A negative grace duration means the old key's grace window has
	// already closed by the time we try to use it.
	if err := pki.RotateSproutBoxKey(pki.CurrentTenantID(), "web-01", newSprout.pubB64(), -time.Hour); err != nil {
		t.Fatalf("rotating sprout box key: %v", err)
	}
	tenantPub, _, err := pki.GetTenantX25519KeyPair()
	if err != nil {
		t.Fatalf("GetTenantX25519KeyPair: %v", err)
	}

	sealed := sealAsSprout(t, oldSprout, tenantPub, []byte(`{"expired":"key"}`))
	if err := DecryptEncryptedFrom(pki.CurrentTenantID(), "web-01", sealed, new(map[string]string)); err == nil {
		t.Fatal("expected decryption under an expired grace-period key to fail")
	}
}

func TestOpenFromSprout_WrongSproutFailsToDecrypt(t *testing.T) {
	setupCryptoTest(t)
	sproutA := newSproutKeypair(t)
	sproutB := newSproutKeypair(t)
	if err := pki.RotateSproutBoxKey(pki.CurrentTenantID(), "web-a", sproutA.pubB64(), time.Hour); err != nil {
		t.Fatalf("seeding sprout a box key: %v", err)
	}
	if err := pki.RotateSproutBoxKey(pki.CurrentTenantID(), "web-b", sproutB.pubB64(), time.Hour); err != nil {
		t.Fatalf("seeding sprout b box key: %v", err)
	}
	tenantPub, _, err := pki.GetTenantX25519KeyPair()
	if err != nil {
		t.Fatalf("GetTenantX25519KeyPair: %v", err)
	}

	// Sealed as sprout A, but the farmer is told to decrypt it as if it
	// came from sprout B (wrong key on the decrypt side).
	sealed := sealAsSprout(t, sproutA, tenantPub, []byte(`{"x":"y"}`))
	if err := DecryptEncryptedFrom(pki.CurrentTenantID(), "web-b", sealed, new(map[string]string)); err == nil {
		t.Fatal("expected decryption against the wrong sprout's key to fail")
	}
}

func TestOpenFromSprout_TamperedCiphertextFails(t *testing.T) {
	setupCryptoTest(t)
	sprout := newSproutKeypair(t)
	if err := pki.RotateSproutBoxKey(pki.CurrentTenantID(), "web-01", sprout.pubB64(), time.Hour); err != nil {
		t.Fatalf("seeding sprout box key: %v", err)
	}
	tenantPub, _, err := pki.GetTenantX25519KeyPair()
	if err != nil {
		t.Fatalf("GetTenantX25519KeyPair: %v", err)
	}

	sealed := sealAsSprout(t, sprout, tenantPub, []byte(`{"a":"b"}`))
	var env EncryptedEnvelope
	if err := json.Unmarshal(sealed, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	env.Ciphertext[0] ^= 0xFF // flip a bit
	tampered, _ := json.Marshal(env)

	if err := DecryptEncryptedFrom(pki.CurrentTenantID(), "web-01", tampered, new(map[string]string)); err == nil {
		t.Fatal("expected tampered ciphertext to fail authentication")
	}
}

func TestOpenFromSprout_MalformedEnvelopeFails(t *testing.T) {
	setupCryptoTest(t)
	if err := DecryptEncryptedFrom(pki.CurrentTenantID(), "web-01", []byte("not json"), new(map[string]string)); err == nil {
		t.Fatal("expected malformed envelope JSON to fail")
	}
	if err := DecryptEncryptedFrom(pki.CurrentTenantID(), "web-01", []byte(`{"n":"aGk=","c":"aGk="}`), new(map[string]string)); err == nil {
		t.Fatal("expected a too-short nonce to fail")
	}
}

// TestOpenFromSprout_TwoTenantsSameSproutID_DecryptConcurrentlyWithoutCrossing
// exercises the box-key decrypt path (openFromSprout/ValidSproutBoxKeys)
// against two distinct tenants that both happen to have accepted a sprout
// under the exact same sprout ID ("web-01") with their own, different box
// keys — a real scenario, since sprout IDs are chosen per tenant
// independently. Both tenants' payloads are decrypted concurrently, not
// asserted one after the other, and each must only ever decrypt under its
// own tenant's key: this is the same tenant-scoping bug class PR #28 fixed
// once for a different call site (see
// docs/design/imas-tenant-context-threading.md) — asserting a single
// tenant twice would leave a regression back to the process-global
// tenantID() seam invisible here exactly as it was before that fix.
func TestOpenFromSprout_TwoTenantsSameSproutID_DecryptConcurrentlyWithoutCrossing(t *testing.T) {
	setupCryptoTest(t)
	const sproutID = "web-01"

	sproutA := newSproutKeypair(t)
	sproutB := newSproutKeypair(t)
	if err := pki.RotateSproutBoxKey("t_a", sproutID, sproutA.pubB64(), time.Hour); err != nil {
		t.Fatalf("seeding t_a's sprout box key: %v", err)
	}
	if err := pki.RotateSproutBoxKey("t_b", sproutID, sproutB.pubB64(), time.Hour); err != nil {
		t.Fatalf("seeding t_b's sprout box key: %v", err)
	}

	tenantPub, _, err := pki.GetTenantX25519KeyPair()
	if err != nil {
		t.Fatalf("GetTenantX25519KeyPair: %v", err)
	}

	sealedA := sealAsSprout(t, sproutA, tenantPub, []byte(`{"tenant":"a"}`))
	sealedB := sealAsSprout(t, sproutB, tenantPub, []byte(`{"tenant":"b"}`))

	type result struct {
		tenant string
		out    map[string]string
		err    error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		var out map[string]string
		err := DecryptEncryptedFrom("t_a", sproutID, sealedA, &out)
		results <- result{"t_a", out, err}
	}()
	go func() {
		defer wg.Done()
		var out map[string]string
		err := DecryptEncryptedFrom("t_b", sproutID, sealedB, &out)
		results <- result{"t_b", out, err}
	}()
	wg.Wait()
	close(results)

	for r := range results {
		if r.err != nil {
			t.Fatalf("DecryptEncryptedFrom(%s) failed: %v", r.tenant, r.err)
		}
		want := map[string]string{"tenant": r.tenant[len(r.tenant)-1:]}
		if r.out["tenant"] != want["tenant"] {
			t.Errorf("%s decrypted %v, want %v", r.tenant, r.out, want)
		}
	}

	// Cross-tenant decryption must fail: t_a's ciphertext under t_b's key
	// lookup, and vice versa.
	if err := DecryptEncryptedFrom("t_b", sproutID, sealedA, new(map[string]string)); err == nil {
		t.Error("expected t_a's payload to fail decryption under t_b's box key")
	}
	if err := DecryptEncryptedFrom("t_a", sproutID, sealedB, new(map[string]string)); err == nil {
		t.Error("expected t_b's payload to fail decryption under t_a's box key")
	}
}
