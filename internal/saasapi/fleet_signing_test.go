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
// source, and test values for the manifest columns saas.fleet_versions
// doesn't have yet, for the duration of the test.
func withTestFleetKeys(t *testing.T) {
	t.Helper()
	_, ks := testFleetKey(t)
	SetFleetKeySource(staticFleetKeys{ks: ks})
	t.Cleanup(func() { SetFleetKeySource(nil) })
	withTestManifestColumns(t)
}

// withTestManifestColumns stands in for the os, arch, file_name and
// min_sprout_version columns FU.3 adds to saas.fleet_versions.
func withTestManifestColumns(t *testing.T) {
	t.Helper()
	orig := fleetVersionManifestColumns
	fleetVersionManifestColumns = testManifestColumns
	t.Cleanup(func() { fleetVersionManifestColumns = orig })
}

func testManifestColumns(v FleetVersion) (osName, arch, fileName, minSproutVersion string) {
	return "linux", "amd64", "imas-sprout_" + strings.TrimPrefix(v.Version, "v") + "_amd64.deb", "v0.0.0"
}

// signTestRelease signs v's manifest the way cmd/fleetreleaser does.
func signTestRelease(t *testing.T, v FleetVersion) string {
	t.Helper()
	priv, _ := testFleetKey(t)
	osName, arch, fileName, minSproutVersion := testManifestColumns(v)
	msg, err := fleetsign.Manifest{Version: v.Version, OS: osName, Arch: arch, FileName: fileName,
		ChecksumSHA256: strings.ToLower(v.ChecksumSHA256), MinSproutVersion: minSproutVersion}.Message()
	if err != nil {
		t.Fatalf("signing test release %s: %v", v.Version, err)
	}
	return fleetsign.EncodeSignature(1, ed25519.Sign(priv, msg))
}

func TestCreateFleetUpdateBatch_RefusesUnverifiableCatalogRow(t *testing.T) {
	gdb := newUpdateTestDB(t)
	tid := mustCreateActiveTenant(t, gdb)
	good := mustPublishVersion(t, gdb, "v9.0.0", time.Now())

	unsigned := FleetVersion{ID: "fv_unsigned", Version: "v9.0.1", ArtifactURL: "https://artifacts.internal.test/sprout/u",
		ChecksumSHA256: strings.Repeat("cd", 32), ReleasedAt: time.Now()} // an un-migrated row: signature ""
	tampered := FleetVersion{ID: "fv_tampered", Version: "v9.0.2", ArtifactURL: "https://artifacts.internal.test/sprout/t",
		ChecksumSHA256: strings.Repeat("cd", 32), ReleasedAt: time.Now()}
	tampered.Signature = signTestRelease(t, tampered)
	tampered.ChecksumSHA256 = strings.Repeat("ef", 32) // valid hash, signature now over different fields
	forged := FleetVersion{ID: "fv_forged", Version: "v9.0.3", ArtifactURL: "https://artifacts.internal.test/sprout/f",
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
	v := FleetVersion{Version: "v1.0.0", ArtifactURL: "https://a.test/s", ChecksumSHA256: strings.Repeat("ab", 32)}
	v.Signature = signTestRelease(t, v)

	withTestManifestColumns(t)
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

// Until saas.fleet_versions has the manifest columns (FU.3), no row can
// be verified, so every self_update rollout is refused, including one
// whose signature would verify with the columns filled in.
func TestSelfUpdateParams_FailsClosedWithoutManifestColumns(t *testing.T) {
	_, ks := testFleetKey(t)
	v := FleetVersion{Version: "v1.0.0", ArtifactURL: "https://a.test/s", ChecksumSHA256: strings.Repeat("ab", 32)}
	v.Signature = signTestRelease(t, v)
	SetFleetKeySource(staticFleetKeys{ks: ks})
	defer SetFleetKeySource(nil)
	if _, err := selfUpdateParams(t.Context(), v); !errors.Is(err, fleetsign.ErrInvalidManifest) {
		t.Fatalf("selfUpdateParams = %v, want ErrInvalidManifest", err)
	}
}
