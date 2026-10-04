package pki

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
	"github.com/yogzblr/imas/internal/pki/tenantboxtest"
)

// setupTenantBoxOpenBao points the package at a mock OpenBao KV v2
// server for the duration of the test, and clears the in-process key
// cache both before and after (so cache state never leaks between tests).
func setupTenantBoxOpenBao(t *testing.T) *tenantboxtest.Server {
	t.Helper()
	srv := tenantboxtest.Start(t)
	resetTenantX25519KeypairCache()
	t.Cleanup(resetTenantX25519KeypairCache)
	return srv
}

// withTenantBoxGrace sets the config values tenantBoxGrace derives from.
func withTenantBoxGrace(t *testing.T, d time.Duration) {
	t.Helper()
	origBox, origTTL := config.BoxKeyGraceDuration, config.GatewayJWTTTL
	config.BoxKeyGraceDuration, config.GatewayJWTTTL = d, 0
	t.Cleanup(func() { config.BoxKeyGraceDuration, config.GatewayJWTTTL = origBox, origTTL })
}

func b64(k *[32]byte) string { return base64.StdEncoding.EncodeToString(k[:]) }

func TestGetTenantX25519PublicKey_NotConfigured(t *testing.T) {
	t.Setenv(EnvTenantBoxOpenBaoAddr, "")
	resetTenantX25519KeypairCache()
	t.Cleanup(resetTenantX25519KeypairCache)

	if _, err := GetTenantX25519PublicKey("t_1"); !errors.Is(err, ErrTenantBoxNotConfigured) {
		t.Fatalf("expected ErrTenantBoxNotConfigured, got %v", err)
	}
}

func TestGetTenantX25519PublicKey_RejectsInvalidTenantID(t *testing.T) {
	setupTenantBoxOpenBao(t)
	for _, id := range []string{"", "../other", "a/b", "t.1"} {
		if _, err := GetTenantX25519PublicKey(id); err == nil {
			t.Errorf("tenant id %q accepted", id)
		}
	}
}

func TestGetTenantX25519PublicKey_GeneratesAndPersistsPerTenant(t *testing.T) {
	srv := setupTenantBoxOpenBao(t)

	pubA, err := GetTenantX25519PublicKey("t_a")
	if err != nil {
		t.Fatalf("GetTenantX25519PublicKey(t_a): %v", err)
	}
	pubB, err := GetTenantX25519PublicKey("t_b")
	if err != nil {
		t.Fatalf("GetTenantX25519PublicKey(t_b): %v", err)
	}
	if pubA == pubB {
		t.Fatal("two tenants were given the same keypair")
	}
	for tenant, pub := range map[string]string{"t_a": pubA, "t_b": pubB} {
		vs := srv.Versions(tenantboxtest.TenantPath(tenant))
		if len(vs) != 1 || vs[0].Data["pub"] != pub || vs[0].Data["origin"] != tenantBoxOriginGenerated {
			t.Errorf("tenant %s stored %+v, want one generated version with pub %s", tenant, vs, pub)
		}
	}
	if len(srv.Versions(tenantboxtest.BasePath)) != 0 {
		t.Error("the legacy path was written")
	}

	// With the cache cleared, the same keypair is read back, not
	// regenerated.
	resetTenantX25519KeypairCache()
	again, err := GetTenantX25519PublicKey("t_a")
	if err != nil || again != pubA {
		t.Errorf("reload returned %q, %v; want %q", again, err, pubA)
	}
}

// No tenant ever gets a shared keypair (security review 2026-10, H3):
// even with a keypair sitting at the base path, where the deleted legacy
// one-per-deployment keypair lived, and with sprouts on record, every
// tenant's first key is freshly generated, and the base path is neither
// used nor written.
func TestGetTenantX25519PublicKey_NeverAdoptsASharedKeypair(t *testing.T) {
	setupTestPKI(t)
	srv := setupTenantBoxOpenBao(t)
	legacyPub, _ := srv.SeedKeypair(t, tenantboxtest.BasePath, nil)
	for _, tenant := range []string{"t_old", "t_other"} {
		if err := upsertSproutBoxKeyActive(tenant, "web-01", testEnrollBoxPub(t)); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]string{}
	for _, tenant := range []string{"t_old", "t_other", "t_new"} {
		pub, err := GetTenantX25519PublicKey(tenant)
		if err != nil {
			t.Fatal(err)
		}
		if pub == b64(legacyPub) {
			t.Errorf("tenant %s was given the keypair at the base path", tenant)
		}
		if other, dup := seen[pub]; dup {
			t.Errorf("tenants %s and %s share a keypair", other, tenant)
		}
		seen[pub] = tenant
		vs := srv.Versions(tenantboxtest.TenantPath(tenant))
		if len(vs) != 1 || vs[0].Data["origin"] != tenantBoxOriginGenerated {
			t.Errorf("tenant %s stored %+v, want one generated version", tenant, vs)
		}
	}
	if n := len(srv.Versions(tenantboxtest.BasePath)); n != 1 {
		t.Errorf("base path has %d versions, want the 1 seeded", n)
	}
}

func TestLoadTenantKeySet_CacheAndStaleLimit(t *testing.T) {
	srv := setupTenantBoxOpenBao(t)

	pub1, err := GetTenantX25519PublicKey("t_1")
	if err != nil {
		t.Fatal(err)
	}
	reads := srv.Reads
	if _, err := GetTenantX25519PublicKey("t_1"); err != nil {
		t.Fatal(err)
	}
	if srv.Reads != reads {
		t.Error("a cached call went back to OpenBao")
	}

	srv.Close()
	// Past the TTL but inside the stale limit, the cached set is served.
	origTTL, origStale := tenantBoxCacheTTL, tenantBoxStaleLimit
	t.Cleanup(func() { tenantBoxCacheTTL, tenantBoxStaleLimit = origTTL, origStale })
	tenantBoxCacheTTL = 0
	if pub2, err := GetTenantX25519PublicKey("t_1"); err != nil || pub2 != pub1 {
		t.Fatalf("stale-but-usable cache: %q, %v", pub2, err)
	}
	// Past the stale limit, OpenBao being down is an error.
	tenantBoxStaleLimit = 0
	if _, err := GetTenantX25519PublicKey("t_1"); err == nil {
		t.Fatal("expected an error once the cached set is past the stale limit")
	}
}

func TestGetTenantX25519PublicKey_ConcurrentBootstrapAgreesOnOneKey(t *testing.T) {
	setupTenantBoxOpenBao(t)

	const n = 8
	results := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			// Simulate n separate processes: no shared in-process cache,
			// so each goes through OpenBao's check-and-set create.
			client, err := newTenantBoxClientFromEnv()
			if err != nil {
				errs[i] = err
				return
			}
			set, err := client.ensureTenantKeySet(t.Context(), "t_1")
			if err != nil {
				errs[i] = err
				return
			}
			results[i] = b64(set.current.pub)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	for i := 1; i < n; i++ {
		if results[i] != results[0] {
			t.Errorf("concurrent bootstraps disagreed: %q and %q", results[0], results[i])
		}
	}
}

func TestGetTenantX25519PublicKey_CorruptStoredDataErrors(t *testing.T) {
	pub, priv, _ := box.GenerateKey(rand.Reader)
	otherPub, _, _ := box.GenerateKey(rand.Reader)
	for name, data := range map[string]map[string]string{
		"bad encoding":       {"pub": "not-valid-base64!!", "priv": "also-not-valid!!"},
		"missing priv":       {"pub": b64(pub)},
		"pub not priv's own": {"pub": b64(otherPub), "priv": b64(priv)},
	} {
		t.Run(name, func(t *testing.T) {
			srv := setupTenantBoxOpenBao(t)
			srv.Put(tenantboxtest.TenantPath("t_1"), data)
			if _, err := GetTenantX25519PublicKey("t_1"); !errors.Is(err, ErrTenantBoxReadFailed) {
				t.Fatalf("expected ErrTenantBoxReadFailed, got %v", err)
			}
		})
	}
}

func TestWriteKeypair_CASGuard(t *testing.T) {
	srv := setupTenantBoxOpenBao(t)
	client, err := newTenantBoxClientFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	path := client.tenantPath("t_1")
	pub1, priv1, _ := box.GenerateKey(rand.Reader)
	pub2, priv2, _ := box.GenerateKey(rand.Reader)

	if ok, err := client.writeKeypair(t.Context(), path, pub1, priv1, 0, nil); err != nil || !ok {
		t.Fatalf("first create: %v, %v", ok, err)
	}
	if ok, err := client.writeKeypair(t.Context(), path, pub2, priv2, 0, nil); err != nil || ok {
		t.Fatalf("second create: %v, %v; want rejected", ok, err)
	}
	// A rotation that read version 0 (stale) is rejected too.
	if ok, _ := client.writeKeypair(t.Context(), path, pub2, priv2, 0, nil); ok {
		t.Fatal("stale rotation written")
	}
	if srv.CASRejects != 2 {
		t.Errorf("CASRejects = %d, want 2", srv.CASRejects)
	}
	got, found, err := client.readKeypair(t.Context(), path, 0)
	if err != nil || !found || *got.pub != *pub1 || got.version != 1 {
		t.Errorf("read back %+v, %v, %v; want version 1 of the first write", got, found, err)
	}
}

// openContinuity opens a continuity proof the way a sprout pinned to
// pinnedTenantPub would, and returns the key it names.
func openContinuity(t *testing.T, proof []byte, pinnedTenantPub, sproutPriv *[32]byte, sproutID string) (string, error) {
	t.Helper()
	msg, err := payloadbox.Open(proof, []payloadbox.KeyPair{{PeerPub: pinnedTenantPub, Priv: sproutPriv}},
		payloadbox.Expect{Purpose: payloadbox.PurposeTenantKeyContinuity, SproutID: sproutID})
	if err != nil {
		return "", err
	}
	var body tenantKeyContinuityBody
	if err := json.Unmarshal(msg.Body, &body); err != nil {
		return "", err
	}
	return body.To, nil
}

func TestRotateTenantX25519Keypair_GraceAndContinuity(t *testing.T) {
	srv := setupTenantBoxOpenBao(t)
	withTenantBoxGrace(t, time.Hour)
	sproutPub, sproutPriv, _ := box.GenerateKey(rand.Reader)

	v1, err := GetTenantX25519PublicKey("t_1")
	if err != nil {
		t.Fatal(err)
	}
	if proof, err := TenantKeyContinuity("t_1", "web-01", b64(sproutPub)); err != nil || proof != nil {
		t.Fatalf("continuity before any rotation: %s, %v; want none", proof, err)
	}

	rot, err := RotateTenantX25519Keypair("t_1", false)
	if err != nil {
		t.Fatalf("RotateTenantX25519Keypair: %v", err)
	}
	if rot.PreviousVersion != 1 || rot.Version != 2 || rot.Pub == v1 || rot.Severed {
		t.Errorf("rotation result %+v", rot)
	}
	if cur, _ := GetTenantX25519PublicKey("t_1"); cur != rot.Pub {
		t.Errorf("current key after rotation is %s, want %s (cache not dropped?)", cur, rot.Pub)
	}

	// Inside the grace window, both keys seal and open.
	keys, err := TenantBoxKeys("t_1")
	if err != nil || len(keys) != 2 || b64(keys[0].Pub) != rot.Pub || b64(keys[1].Pub) != v1 {
		t.Fatalf("TenantBoxKeys in grace = %+v, %v; want [v2, v1]", keys, err)
	}

	// A sprout pinned to v1 opens the proof with v1 and learns v2; one
	// pinned to v2 (or anything else) can't open it.
	proof, err := TenantKeyContinuity("t_1", "web-01", b64(sproutPub))
	if err != nil || proof == nil {
		t.Fatalf("TenantKeyContinuity: %s, %v", proof, err)
	}
	v1Pub, _ := DecodeBoxPubKey(v1)
	if to, err := openContinuity(t, proof, v1Pub, sproutPriv, "web-01"); err != nil || to != rot.Pub {
		t.Errorf("proof opened under v1 says %q, %v; want %q", to, err, rot.Pub)
	}
	v2Pub, _ := DecodeBoxPubKey(rot.Pub)
	if _, err := openContinuity(t, proof, v2Pub, sproutPriv, "web-01"); err == nil {
		t.Error("proof opened under the new key it names")
	}
	if _, err := openContinuity(t, proof, v1Pub, sproutPriv, "web-02"); err == nil {
		t.Error("proof opened for another sprout id")
	}

	// Past the grace window, only the current key seals and opens, but
	// v1 still signs continuity (for sprouts that were offline).
	srv.SetCreated(tenantboxtest.TenantPath("t_1"), 2, time.Now().Add(-2*time.Hour))
	resetTenantX25519KeypairCache()
	keys, err = TenantBoxKeys("t_1")
	if err != nil || len(keys) != 1 || b64(keys[0].Pub) != rot.Pub {
		t.Fatalf("TenantBoxKeys after grace = %+v, %v; want [v2]", keys, err)
	}
	proof, _ = TenantKeyContinuity("t_1", "web-01", b64(sproutPub))
	if to, err := openContinuity(t, proof, v1Pub, sproutPriv, "web-01"); err != nil || to != rot.Pub {
		t.Errorf("continuity from v1 after grace: %q, %v", to, err)
	}
}

func TestRotateTenantX25519Keypair_SeverCutsGraceAndContinuity(t *testing.T) {
	srv := setupTenantBoxOpenBao(t)
	withTenantBoxGrace(t, time.Hour)
	sproutPub, sproutPriv, _ := box.GenerateKey(rand.Reader)

	v1, _ := GetTenantX25519PublicKey("t_1")
	severed, err := RotateTenantX25519Keypair("t_1", true)
	if err != nil {
		t.Fatal(err)
	}
	if srv.Versions(tenantboxtest.TenantPath("t_1"))[1].Data["severed"] != "true" {
		t.Error("severing rotation didn't mark its version")
	}
	keys, _ := TenantBoxKeys("t_1")
	if len(keys) != 1 || b64(keys[0].Pub) != severed.Pub {
		t.Errorf("TenantBoxKeys after sever = %+v, want only the new key", keys)
	}
	if proof, err := TenantKeyContinuity("t_1", "web-01", b64(sproutPub)); err != nil || proof != nil {
		t.Errorf("continuity after sever: %s, %v; want none", proof, err)
	}

	// A later ordinary rotation continues from the severed version, but
	// never from before it.
	v3, err := RotateTenantX25519Keypair("t_1", false)
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := TenantKeyContinuity("t_1", "web-01", b64(sproutPub))
	v2Pub, _ := DecodeBoxPubKey(severed.Pub)
	if to, err := openContinuity(t, proof, v2Pub, sproutPriv, "web-01"); err != nil || to != v3.Pub {
		t.Errorf("continuity from the severed version: %q, %v", to, err)
	}
	v1Pub, _ := DecodeBoxPubKey(v1)
	if _, err := openContinuity(t, proof, v1Pub, sproutPriv, "web-01"); err == nil {
		t.Error("continuity reached back past a severing rotation")
	}
}

// Deleting a version in OpenBao retires it: no continuity from it.
func TestTenantKeyContinuity_SkipsDeletedVersions(t *testing.T) {
	srv := setupTenantBoxOpenBao(t)
	sproutPub, sproutPriv, _ := box.GenerateKey(rand.Reader)

	v1, _ := GetTenantX25519PublicKey("t_1")
	v2, _ := RotateTenantX25519Keypair("t_1", false)
	v3, _ := RotateTenantX25519Keypair("t_1", false)
	srv.Delete(tenantboxtest.TenantPath("t_1"), 2)
	resetTenantX25519KeypairCache()

	proof, err := TenantKeyContinuity("t_1", "web-01", b64(sproutPub))
	if err != nil {
		t.Fatal(err)
	}
	v1Pub, _ := DecodeBoxPubKey(v1)
	if to, err := openContinuity(t, proof, v1Pub, sproutPriv, "web-01"); err != nil || to != v3.Pub {
		t.Errorf("continuity from v1 past a deleted v2: %q, %v", to, err)
	}
	v2Pub, _ := DecodeBoxPubKey(v2.Pub)
	if _, err := openContinuity(t, proof, v2Pub, sproutPriv, "web-01"); err == nil {
		t.Error("continuity from a deleted version")
	}
}

func TestRotateTenantX25519Keypair_Isolated(t *testing.T) {
	setupTenantBoxOpenBao(t)
	a1, _ := GetTenantX25519PublicKey("t_a")
	b1, _ := GetTenantX25519PublicKey("t_b")
	if _, err := RotateTenantX25519Keypair("t_a", false); err != nil {
		t.Fatal(err)
	}
	if b, _ := GetTenantX25519PublicKey("t_b"); b != b1 {
		t.Error("rotating one tenant changed another's key")
	}
	if a, _ := GetTenantX25519PublicKey("t_a"); a == a1 {
		t.Error("rotation didn't change the rotated tenant's key")
	}
}
