package saasapi

// §2.5: saasapi refuses to build a rollout from a catalog row whose
// signature is missing or doesn't verify against the imas-fleet-signing
// key (read-only). Farmer and the sprout verify again; this is the early
// refusal that keeps a bad row from ever becoming a batch.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/fleetsign"
)

var (
	testFleetKeyOnce sync.Once
	testFleetPriv    ed25519.PrivateKey
	testFleetKeySet  fleetsign.KeySet
)

// testFleetKey is the key the test catalog is signed with, standing in
// for cmd/fleetreleaser's Transit key.
func testFleetKey(t *testing.T) (ed25519.PrivateKey, fleetsign.KeySet) {
	t.Helper()
	testFleetKeyOnce.Do(func() {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		testFleetPriv = priv
		testFleetKeySet, _ = fleetsign.NewKeySet([]fleetsign.PublicKey{{Version: 1, Key: pub}})
	})
	return testFleetPriv, testFleetKeySet
}

type staticFleetKeys struct {
	ks  fleetsign.KeySet
	err error
}

func (s staticFleetKeys) KeySet(context.Context) (fleetsign.KeySet, error) { return s.ks, s.err }

// withTestFleetKeys installs the test key set as saasapi's fleet key
// source for the duration of the test.
func withTestFleetKeys(t *testing.T) {
	t.Helper()
	_, ks := testFleetKey(t)
	SetFleetKeySource(staticFleetKeys{ks: ks})
	t.Cleanup(func() { SetFleetKeySource(nil) })
}

// signTestRelease signs v's fields the way cmd/fleetreleaser does.
func signTestRelease(t *testing.T, v FleetVersion) string {
	t.Helper()
	priv, _ := testFleetKey(t)
	msg, err := fleetsign.Release{Version: v.Version, ArtifactURL: v.ArtifactURL, ChecksumSHA256: strings.ToLower(v.ChecksumSHA256)}.Message()
	if err != nil {
		t.Fatalf("signing test release %s: %v", v.Version, err)
	}
	return fleetsign.EncodeSignature(1, ed25519.Sign(priv, msg))
}

func TestCreateFleetUpdateBatch_RefusesUnverifiableCatalogRow(t *testing.T) {
	gdb := newUpdateTestDB(t)
	tid := mustCreateActiveTenant(t, gdb)
	good := mustPublishVersion(t, gdb, "v-good", time.Now())

	unsigned := FleetVersion{ID: "fv_unsigned", Version: "v-unsigned", ArtifactURL: "https://artifacts.internal.test/sprout/u",
		ChecksumSHA256: strings.Repeat("cd", 32), ReleasedAt: time.Now()} // an un-migrated row: signature ""
	tampered := FleetVersion{ID: "fv_tampered", Version: "v-tampered", ArtifactURL: "https://artifacts.internal.test/sprout/t",
		ChecksumSHA256: strings.Repeat("cd", 32), ReleasedAt: time.Now()}
	tampered.Signature = signTestRelease(t, tampered)
	tampered.ArtifactURL = "https://evil.test/sprout" // valid hash, signature now over different fields
	forged := FleetVersion{ID: "fv_forged", Version: "v-forged", ArtifactURL: "https://artifacts.internal.test/sprout/f",
		ChecksumSHA256: strings.Repeat("cd", 32), ReleasedAt: time.Now(), Signature: good.Signature} // another row's signature
	for _, v := range []FleetVersion{unsigned, tampered, forged} {
		if err := gdb.Create(&v).Error; err != nil {
			t.Fatal(err)
		}
		mustApprove(t, gdb, tid, v.Version)
		code, resp := postUpdates(t, tid, map[string]any{"asset_ids": []string{"a1"}, "target_version": v.Version})
		if code != 500 || resp["error"] != "internal_error" {
			t.Fatalf("%s: %d %v", v.Version, code, resp)
		}
	}
	var n int64
	gdb.Model(&AssetActionBatch{}).Count(&n)
	if n != 0 {
		t.Fatalf("%d batch(es) created from unverifiable rows", n)
	}
}

func TestSelfUpdateParams_KeySourceFailuresRefuse(t *testing.T) {
	_, ks := testFleetKey(t)
	v := FleetVersion{Version: "v1", ArtifactURL: "https://a.test/s", ChecksumSHA256: strings.Repeat("ab", 32)}
	v.Signature = signTestRelease(t, v)

	SetFleetKeySource(staticFleetKeys{ks: ks})
	defer SetFleetKeySource(nil)
	if _, err := selfUpdateParams(t.Context(), v); err != nil {
		t.Fatalf("valid row refused: %v", err)
	}
	SetFleetKeySource(nil)
	if _, err := selfUpdateParams(t.Context(), v); err == nil {
		t.Fatal("dispatched with no key source")
	}
	SetFleetKeySource(staticFleetKeys{err: errors.New("403 permission denied")})
	if _, err := selfUpdateParams(t.Context(), v); err == nil {
		t.Fatal("dispatched when the key couldn't be read")
	}
	// Uppercase checksum in the row: saasapi lowercases it before
	// verifying, matching what fleetreleaser signed.
	up := v
	up.ChecksumSHA256 = strings.ToUpper(v.ChecksumSHA256)
	SetFleetKeySource(staticFleetKeys{ks: ks})
	if _, err := selfUpdateParams(t.Context(), up); err != nil {
		t.Fatalf("uppercase checksum row refused: %v", err)
	}
}
