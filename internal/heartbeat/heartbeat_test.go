package heartbeat

// These tests cover this package's own logic (tenant/key scoping, and
// mapping a CONNECT/DISCONNECT event to a real tenant + sprout ID) against
// an in-memory PKI store. They deliberately don't exercise a real
// Set/Del/Exists round trip: valkey-go's command builder needs an
// unexported "no keyslot restriction" sentinel to build a valid command
// outside of an actual client connection, and its ValkeyMessage
// success-reply type has no exported constructor either — both are
// internal to that package, so a faithful fake isn't buildable from here
// without a live Valkey/Redis server (e.g. in a docker-compose-backed
// integration test), which this unit test suite doesn't have.
// IsOnline/handleConnect/handleDisconnect's nil-client short-circuit
// (exercised below) is what every code path actually goes through when no
// Valkey backend is configured, which is worth covering directly.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/pki"
)

// newTestPKIDB wires up an in-memory PKI store, plus the minimal config
// pki.ReloadNKeys/ReloadNKeysForTenant (called via defer by
// AcceptNKey/UnacceptNKey) needs to fail fast rather than fatally — a
// dummy farmer pub key file so it doesn't log.Fatalf, matching
// internal/pki's own test setup.
func newTestPKIDB(t *testing.T) {
	t.Helper()
	dsn := "file:" + t.Name() + "-pki?mode=memory&cache=shared"
	gdb, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("opening pki test db: %v", err)
	}
	if err := gdb.AutoMigrate(pki.Models()...); err != nil {
		t.Fatalf("migrating pki test db: %v", err)
	}
	pki.SetDB(gdb)
	t.Cleanup(func() { pki.SetDB(nil) })

	dir := t.TempDir()
	config.FarmerPKI = dir + "/"
	farmerPubFile := filepath.Join(dir, "farmer.pub")
	if err := os.WriteFile(farmerPubFile, []byte("UFAKE_FARMER_KEY_FOR_TESTING"), 0o600); err != nil {
		t.Fatal(err)
	}
	config.NKeyFarmerPubFile = farmerPubFile
	pki.NatsServer = nil
}

// connectEventJSON builds a $SYS.ACCOUNT.*.CONNECT/DISCONNECT event body
// carrying both the connecting Account's pubkey ("acc") and the
// authenticated user's pubkey ("user") — the two ClientInfo fields
// sproutIDFromEvent reads.
func connectEventJSON(t *testing.T, accountPub, userPub string) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"client": map[string]string{"acc": accountPub, "user": userPub},
	})
	if err != nil {
		t.Fatalf("marshaling event: %v", err)
	}
	return data
}

func TestKeyFor(t *testing.T) {
	got := keyFor("acme", "sprout-1")
	want := "imas:heartbeat:acme:sprout-1"
	if got != want {
		t.Errorf("keyFor() = %q, want %q", got, want)
	}
}

func TestIsOnline_NilClient(t *testing.T) {
	SetClient(nil)
	if IsOnline(context.Background(), "acme", "any-sprout") {
		t.Error("expected false with no client configured")
	}
}

func TestSproutIDFromEvent_MalformedJSON(t *testing.T) {
	newTestPKIDB(t)

	if _, _, ok := sproutIDFromEvent([]byte("{not json"), "CONNECT"); ok {
		t.Error("expected ok=false for malformed event JSON")
	}
}

func TestSproutIDFromEvent_UnknownAccount(t *testing.T) {
	newTestPKIDB(t)

	// "acc" doesn't match any provisioned tenant's Account pubkey (the
	// legacy current tenant's included, since ensureNatsAuth hasn't been
	// bootstrapped here at all) — TenantIDForAccountPub must fail closed.
	data := connectEventJSON(t, "UNKNOWN_ACCOUNT_PUBKEY", "UNKNOWN_USER_PUBKEY")
	if _, _, ok := sproutIDFromEvent(data, "CONNECT"); ok {
		t.Error("expected ok=false for an Account pubkey that isn't any provisioned tenant")
	}
}

func TestSproutIDFromEvent_AcceptedSprout(t *testing.T) {
	newTestPKIDB(t)

	accountPub, err := pki.GetTenantAccountPub(pki.CurrentTenantID())
	if err != nil {
		t.Fatalf("GetTenantAccountPub: %v", err)
	}

	if err := pki.UnacceptNKey(pki.CurrentTenantID(), "web-01", "UPUBKEY123"); err != nil {
		t.Fatalf("UnacceptNKey: %v", err)
	}
	if err := pki.AcceptNKey(pki.CurrentTenantID(), "web-01"); err != nil {
		t.Fatalf("AcceptNKey: %v", err)
	}

	data := connectEventJSON(t, accountPub, "UPUBKEY123")
	tenant, sproutID, ok := sproutIDFromEvent(data, "CONNECT")
	if !ok {
		t.Fatal("expected ok=true for an accepted sprout's pubkey")
	}
	if tenant != pki.CurrentTenantID() {
		t.Errorf("tenant = %q, want %q", tenant, pki.CurrentTenantID())
	}
	if sproutID != "web-01" {
		t.Errorf("sproutID = %q, want %q", sproutID, "web-01")
	}
}

func TestSproutIDFromEvent_UnacceptedSproutNotOnline(t *testing.T) {
	newTestPKIDB(t)

	accountPub, err := pki.GetTenantAccountPub(pki.CurrentTenantID())
	if err != nil {
		t.Fatalf("GetTenantAccountPub: %v", err)
	}

	if err := pki.UnacceptNKey(pki.CurrentTenantID(), "web-02", "UPUBKEY456"); err != nil {
		t.Fatalf("UnacceptNKey: %v", err)
	}

	data := connectEventJSON(t, accountPub, "UPUBKEY456")
	if _, _, ok := sproutIDFromEvent(data, "CONNECT"); ok {
		t.Error("expected ok=false for a sprout that isn't accepted yet")
	}
}

func TestHandleConnectDisconnect_NilClientDoesNotPanic(t *testing.T) {
	newTestPKIDB(t)
	SetClient(nil)

	accountPub, err := pki.GetTenantAccountPub(pki.CurrentTenantID())
	if err != nil {
		t.Fatalf("GetTenantAccountPub: %v", err)
	}

	if err := pki.UnacceptNKey(pki.CurrentTenantID(), "web-03", "UPUBKEY789"); err != nil {
		t.Fatalf("UnacceptNKey: %v", err)
	}
	if err := pki.AcceptNKey(pki.CurrentTenantID(), "web-03"); err != nil {
		t.Fatalf("AcceptNKey: %v", err)
	}

	data := connectEventJSON(t, accountPub, "UPUBKEY789")
	handleConnect(data)
	handleDisconnect(data)
}

// TestSproutIDFromEvent_TwoTenantsSameSproutIDAndPubkey_DoNotCrossResolve
// exercises two distinct, dynamically-provisioned tenants concurrently —
// not one tenant asserted twice — proving a CONNECT event's Account pubkey
// is what disambiguates them, even when both tenants happen to have
// accepted a sprout under the exact same sprout ID with the exact same
// NKey pubkey (a real scenario: sprout IDs and even NKeys are chosen by
// each tenant's own sprouts independently). This is the same tenant-
// isolation bug class PR #28 fixed once for a different call site (see
// docs/design/imas-tenant-context-threading.md); asserting only one
// tenant here would make a regression back to the old process-global
// tenantID() seam invisible to this test, exactly as it was before.
func TestSproutIDFromEvent_TwoTenantsSameSproutIDAndPubkey_DoNotCrossResolve(t *testing.T) {
	newTestPKIDB(t)

	// Accepting a sprout under a tenant ID that's never been seen before
	// lazily provisions that tenant's own Account (ReloadNKeysForTenant,
	// called via AcceptNKey/UnacceptNKey's defer) — the same lazy path
	// enroll.go's acceptEnrolledNKey relies on. The reload's own push to
	// the bus resolver is expected to fail in this unit test (no live bus
	// configured) and is logged, not returned by Accept/UnacceptNKey, so
	// it doesn't need to be asserted on here — only the Account material
	// it creates as a side effect does.
	const sharedSproutID = "web-01"
	const sharedNKey = "UPUBSHARED"
	if err := pki.UnacceptNKey("t_a", sharedSproutID, sharedNKey); err != nil {
		t.Fatalf("UnacceptNKey(t_a): %v", err)
	}
	if err := pki.AcceptNKey("t_a", sharedSproutID); err != nil {
		t.Fatalf("AcceptNKey(t_a): %v", err)
	}
	if err := pki.UnacceptNKey("t_b", sharedSproutID, sharedNKey); err != nil {
		t.Fatalf("UnacceptNKey(t_b): %v", err)
	}
	if err := pki.AcceptNKey("t_b", sharedSproutID); err != nil {
		t.Fatalf("AcceptNKey(t_b): %v", err)
	}

	accountPubA, err := pki.GetTenantAccountPub("t_a")
	if err != nil {
		t.Fatalf("GetTenantAccountPub(t_a): %v", err)
	}
	accountPubB, err := pki.GetTenantAccountPub("t_b")
	if err != nil {
		t.Fatalf("GetTenantAccountPub(t_b): %v", err)
	}
	if accountPubA == accountPubB {
		t.Fatal("expected distinct tenants to get distinct Account pubkeys")
	}

	dataA := connectEventJSON(t, accountPubA, sharedNKey)
	dataB := connectEventJSON(t, accountPubB, sharedNKey)

	type result struct {
		tenant, sproutID string
		ok               bool
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		tenant, sproutID, ok := sproutIDFromEvent(dataA, "CONNECT")
		results <- result{tenant, sproutID, ok}
	}()
	go func() {
		defer wg.Done()
		tenant, sproutID, ok := sproutIDFromEvent(dataB, "CONNECT")
		results <- result{tenant, sproutID, ok}
	}()
	wg.Wait()
	close(results)

	got := make(map[string]string, 2)
	for r := range results {
		if !r.ok {
			t.Fatalf("sproutIDFromEvent unexpectedly returned ok=false for tenant %q", r.tenant)
		}
		got[r.tenant] = r.sproutID
	}

	if got["t_a"] != sharedSproutID {
		t.Errorf("tenant t_a resolved sprout %q, want %q", got["t_a"], sharedSproutID)
	}
	if got["t_b"] != sharedSproutID {
		t.Errorf("tenant t_b resolved sprout %q, want %q", got["t_b"], sharedSproutID)
	}

	// Now prove the CONNECT/DISCONNECT key writes land under, and only
	// under, their own tenant's heartbeat key by checking keyFor's output
	// for each — the real Valkey write path (untestable here, see this
	// file's header comment) uses exactly this key.
	if keyFor("t_a", sharedSproutID) == keyFor("t_b", sharedSproutID) {
		t.Fatal("expected distinct tenants to produce distinct heartbeat keys for the same sprout ID")
	}
}
