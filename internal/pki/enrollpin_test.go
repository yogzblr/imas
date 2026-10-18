package pki

// The tenant key fingerprint in the join token (security review 2026-10,
// L24; docs/briefs/U-hardening.md, U2): the sprout refuses a first
// enrollment response whose tenant key isn't the one the token names,
// before it seals anything to it or pins it, and refuses a token with no
// fingerprint unless enrollpinrequired is false. Farmer refuses a token
// minted for a tenant key it has since rotated away from, before spending
// it.

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/jointoken"
)

// pinnedToken is credential ({key_id}.{secret}) with tenant t_1's current
// key fingerprint, as the SaaS API mints it. The tenant key is created if
// it doesn't exist yet, as farmer's internal.tenant.boxkey does.
func pinnedToken(t *testing.T, credential string) string {
	t.Helper()
	return pinnedTokenFor(t, credential, "t_1")
}

func pinnedTokenFor(t *testing.T, credential, tenantID string) string {
	t.Helper()
	pub, err := GetTenantX25519PublicKey(tenantID)
	if err != nil {
		t.Fatalf("tenant %s key: %v", tenantID, err)
	}
	fp, err := jointoken.FingerprintB64(pub)
	if err != nil {
		t.Fatal(err)
	}
	return credential + "." + fp
}

func setupPinTest(t *testing.T) (*fakeEnrollmentKeyStore, *enrollServer, string) {
	t.Helper()
	store, _ := setupEnrollTest(t)
	newJWSGatewayMinter(t)
	config.GatewayJWTTTL = time.Hour
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}
	setupSproutFiles(t)
	srv := startEnrollServer(t)
	sproutPub, err := EnsureSproutBoxKey()
	if err != nil {
		t.Fatal(err)
	}
	return store, srv, sproutPub
}

func requireNothingPinned(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(config.SproutTenantX25519PubFile); !os.IsNotExist(err) {
		t.Errorf("tenant key pin file exists (%v): nothing may be pinned", err)
	}
	if SproutEnrolled() {
		t.Error("the sprout is marked enrolled")
	}
}

// An Envoy that substitutes its own tenant key in the first response is
// caught: ErrTenantKeyFingerprintMismatch, no second request (no proof is
// sealed to the substituted key), nothing pinned, and EnsureEnrolled
// gives up at once instead of retrying.
func TestEnrollSprout_RefusesSubstitutedTenantKey(t *testing.T) {
	_, srv, sproutPub := setupPinTest(t)
	token := pinnedToken(t, "ek_1.s")
	srv.mu.Lock()
	srv.enrollTenantPubOverride = otherBoxPub(t)
	srv.mu.Unlock()

	start := time.Now()
	if _, err := EnsureEnrolled(t.Context(), token, "web-01", sproutPub, time.Hour); !errors.Is(err, ErrTenantKeyFingerprintMismatch) {
		t.Fatalf("EnsureEnrolled = %v, want ErrTenantKeyFingerprintMismatch without retrying", err)
	}
	if time.Since(start) > 30*time.Second {
		t.Error("EnsureEnrolled waited before giving up")
	}
	srv.mu.Lock()
	n := len(srv.requests)
	srv.mu.Unlock()
	if n != 1 {
		t.Errorf("sent %d requests, want 1: the box key proof must not be sealed to an unverified key", n)
	}
	requireNothingPinned(t)
}

// With the real key the same token enrolls, and the pin is the key the
// fingerprint names.
func TestEnrollSprout_FingerprintMatchEnrolls(t *testing.T) {
	_, _, sproutPub := setupPinTest(t)
	token := pinnedToken(t, "ek_1.s")
	id, err := EnsureEnrolled(t.Context(), token, "web-01", sproutPub, time.Millisecond)
	if err != nil || id != "web-01" {
		t.Fatalf("EnsureEnrolled = %q, %v", id, err)
	}
	pinned, err := os.ReadFile(config.SproutTenantX25519PubFile)
	if err != nil {
		t.Fatal(err)
	}
	fp, _ := jointoken.FingerprintB64(string(pinned))
	if !strings.HasSuffix(token, "."+fp) {
		t.Errorf("pinned key's fingerprint %s is not the token's", fp)
	}
}

// A token without a fingerprint is refused by default before anything is
// sent, and is not retried.
func TestEnrollSprout_RefusesTokenWithoutFingerprint(t *testing.T) {
	store, srv, sproutPub := setupPinTest(t)
	config.EnrollPinRequired = true

	if _, err := EnsureEnrolled(t.Context(), "ek_1.s", "web-01", sproutPub, time.Hour); !errors.Is(err, ErrJoinTokenNoFingerprint) {
		t.Fatalf("EnsureEnrolled = %v, want ErrJoinTokenNoFingerprint", err)
	}
	srv.mu.Lock()
	n := len(srv.requests)
	srv.mu.Unlock()
	if n != 0 || store.rows["ek_1"].UsedCount != 0 {
		t.Errorf("sent %d requests, used_count %d: nothing may reach farmer", n, store.rows["ek_1"].UsedCount)
	}
	requireNothingPinned(t)

	priv, err := readBoxPrivKeyFile(config.SproutBoxPrivFile, false)
	if err != nil {
		t.Fatal(err)
	}
	c := &EnrollClient{}
	if _, err := c.Enroll(t.Context(), "ek_1.s", "web-01", EnrollKeys{NKey: loadTestSproutNKey(t), BoxPriv: priv}); !errors.Is(err, ErrJoinTokenNoFingerprint) {
		t.Errorf("EnrollClient's zero value = %v, want ErrJoinTokenNoFingerprint", err)
	}
}

// enrollpinrequired: false enrolls with a token without a fingerprint,
// and logs a warning on every enrollment.
func TestEnrollSprout_TokenWithoutFingerprintWhenNotRequired(t *testing.T) {
	_, _, sproutPub := setupPinTest(t)
	config.EnrollPinRequired = false
	t.Cleanup(func() { config.EnrollPinRequired = true })
	logs := captureLog(t)

	if _, err := EnrollSprout(t.Context(), "ek_1.s", "web-01", sproutPub); err != nil {
		t.Fatalf("EnrollSprout: %v", err)
	}
	// A second enrollment of the same NKey (farmer's replay path) warns
	// again.
	if _, err := EnrollSprout(t.Context(), "ek_1.s", "web-01", sproutPub); err != nil {
		t.Fatalf("EnrollSprout again: %v", err)
	}
	if n := strings.Count(logs.String(), "carries no tenant key fingerprint and enrollpinrequired is false"); n != 2 {
		t.Errorf("warned %d times, want once per enrollment (2):\n%s", n, logs.String())
	}
}

// A token that carries a fingerprint is checked even with
// enrollpinrequired false.
func TestEnrollSprout_FingerprintCheckedWhenNotRequired(t *testing.T) {
	_, srv, sproutPub := setupPinTest(t)
	config.EnrollPinRequired = false
	t.Cleanup(func() { config.EnrollPinRequired = true })
	token := pinnedToken(t, "ek_1.s")
	srv.mu.Lock()
	srv.enrollTenantPubOverride = otherBoxPub(t)
	srv.mu.Unlock()
	if _, err := EnrollSprout(t.Context(), token, "web-01", sproutPub); !errors.Is(err, ErrTenantKeyFingerprintMismatch) {
		t.Fatalf("EnrollSprout = %v, want ErrTenantKeyFingerprintMismatch", err)
	}
	requireNothingPinned(t)
}

// Farmer refuses a token minted for a tenant key it has rotated away from,
// before redeeming it; the token's use is kept. The current key's token
// enrolls.
func TestEnroll_RefusesTokenForAnotherTenantKey(t *testing.T) {
	store, _ := setupEnrollTest(t)
	newJWSGatewayMinter(t)
	store.rows["ek_1"] = &enrollmentKeyRow{TenantID: "t_1", KeyHash: hashSecret("s"), Expiry: time.Now().Add(time.Hour), MaxUses: 1}
	stale, err := jointoken.FingerprintB64(otherBoxPub(t))
	if err != nil {
		t.Fatal(err)
	}
	kp := testEnrollNKey(t)
	if _, err := Enroll(t.Context(), signedEnroll(t, kp, "ek_1.s."+stale, "web-01", testEnrollBoxPub(t))); !errors.Is(err, ErrEnrollmentFailed) {
		t.Fatalf("Enroll with a stale fingerprint = %v, want ErrEnrollmentFailed", err)
	}
	if store.rows["ek_1"].UsedCount != 0 {
		t.Errorf("used_count = %d: a refused token must keep its use", store.rows["ek_1"].UsedCount)
	}
	if _, err := Enroll(t.Context(), signedEnroll(t, kp, pinnedToken(t, "ek_1.s"), "web-01", testEnrollBoxPub(t))); err != nil {
		t.Fatalf("Enroll with the current fingerprint: %v", err)
	}
	if store.rows["ek_1"].UsedCount != 1 {
		t.Errorf("used_count = %d, want 1", store.rows["ek_1"].UsedCount)
	}
}

// The key the SaaS API fingerprints into a new token is read from OpenBao
// afresh, not from a cache that may predate a rotation on another
// replica; an invalid or deprovisioned tenant gets none.
func TestTenantX25519PublicKeyForJoinToken(t *testing.T) {
	setupEnrollTest(t)
	stale, err := GetTenantX25519PublicKey("t_1")
	if err != nil {
		t.Fatal(err)
	}
	e := tenantBoxEntryFor("t_1")
	e.mu.Lock()
	cached := e.set
	e.mu.Unlock()
	rot, err := RotateTenantX25519Keypair("t_1", false)
	if err != nil {
		t.Fatal(err)
	}
	// This replica still holds the set it read before the rotation.
	e.mu.Lock()
	e.set = cached
	e.mu.Unlock()
	if got, _ := GetTenantX25519PublicKey("t_1"); got != stale {
		t.Fatalf("cache not in place: %s", got)
	}
	got, err := TenantX25519PublicKeyForJoinToken("t_1")
	if err != nil || got != rot.Pub || got == stale {
		t.Fatalf("TenantX25519PublicKeyForJoinToken = %s, %v; want the rotated key %s", got, err, rot.Pub)
	}

	if _, err := TenantX25519PublicKeyForJoinToken("not a tenant"); !errors.Is(err, ErrTenantIDInvalid) {
		t.Errorf("invalid tenant: %v", err)
	}
	if err := db.Create(&tenantRow{ID: "t_1", Name: "t1", Deleted: true, CreatedAt: time.Now().Unix()}).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := TenantX25519PublicKeyForJoinToken("t_1"); !errors.Is(err, ErrTenantDeprovisioned) {
		t.Errorf("deprovisioned tenant: %v, want ErrTenantDeprovisioned", err)
	}
}

// A join token's key read that fails (OpenBao down) leaves this replica's
// cached key set in place, so every other caller keeps its stale-copy
// fallback; a read that succeeds replaces it.
func TestTenantX25519PublicKeyForJoinToken_KeepsTheCacheOnFailure(t *testing.T) {
	setupEnrollTest(t)
	srv := setupTenantBoxOpenBao(t)
	pub, err := TenantX25519PublicKeyForJoinToken("t_1")
	if err != nil {
		t.Fatal(err)
	}
	reads := srv.Reads
	if got, err := GetTenantX25519PublicKey("t_1"); err != nil || got != pub || srv.Reads != reads {
		t.Fatalf("GetTenantX25519PublicKey = %s, %v (%d reads); want the set the token read cached", got, err, srv.Reads-reads)
	}

	srv.Close()
	origTTL := tenantBoxCacheTTL
	t.Cleanup(func() { tenantBoxCacheTTL = origTTL })
	tenantBoxCacheTTL = 0
	if _, err := TenantX25519PublicKeyForJoinToken("t_1"); err == nil {
		t.Fatal("minted a token's key with OpenBao down")
	}
	if got, err := GetTenantX25519PublicKey("t_1"); err != nil || got != pub {
		t.Fatalf("after a failed token read: %s, %v; want the cached key still served", got, err)
	}
}
