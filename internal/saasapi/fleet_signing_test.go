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

	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/fleetsign"
)

var (
	testFleetKeyOnce sync.Once
	testFleetPriv    ed25519.PrivateKey
	testFleetKeySet  fleetsign.KeySet
)

// testFleetKey is the key the test catalog is signed with, standing in
// for cmd/fleetreleaser's Transit key. t may be nil (for the fake signers,
// which have none).
func testFleetKey(t *testing.T) (ed25519.PrivateKey, fleetsign.KeySet) {
	if t != nil {
		t.Helper()
	}
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

// signTestRelease signs v's manifest the way cmd/fleetreleaser does.
func signTestRelease(t *testing.T, v FleetVersion) string {
	t.Helper()
	priv, _ := testFleetKey(t)
	msg, err := v.Manifest().Message()
	if err != nil {
		t.Fatalf("signing test release %s: %v", v.Version, err)
	}
	return fleetsign.EncodeSignature(1, ed25519.Sign(priv, msg))
}

func TestCreateFleetUpdateBatch_RefusesUnverifiableCatalogRow(t *testing.T) {
	gdb := newUpdateTestDB(t)
	tid := mustCreateActiveTenant(t, gdb)
	good := mustPublishVersion(t, gdb, "v9.0.0", time.Now())

	row := func(id, version string) FleetVersion {
		return FleetVersion{ID: id, Version: version, OS: "linux", Arch: "amd64", PackageType: "deb",
			FileName:       "imas-sprout_" + strings.TrimPrefix(version, "v") + "_amd64.deb",
			ChecksumSHA256: strings.Repeat("cd", 32), MinSproutVersion: "v0.0.0", ReleasedAt: time.Now()}
	}
	unsigned := row("fv_unsigned", "v9.0.1") // signature ""
	tampered := row("fv_tampered", "v9.0.2")
	tampered.Signature = signTestRelease(t, tampered)
	tampered.ChecksumSHA256 = strings.Repeat("ef", 32) // valid hash, signature now over different fields
	forged := row("fv_forged", "v9.0.3")
	forged.Signature = good.Signature // another row's signature
	floorLowered := row("fv_floor", "v9.0.4")
	floorLowered.MinSproutVersion = "v1.0.0"
	floorLowered.Signature = signTestRelease(t, floorLowered)
	floorLowered.MinSproutVersion = "v0.0.0" // the signed floor, lowered
	for _, v := range []FleetVersion{unsigned, tampered, forged, floorLowered} {
		if err := gdb.Create(&v).Error; err != nil {
			t.Fatal(err)
		}
		mustApprove(t, gdb, tid, v.Version)
		code, resp := postUpdates(t, tid, map[string]any{"asset_ids": []string{"a1"}, "target_version": v.Version})
		if code != 500 || resp["error"] != "internal_error" {
			t.Fatalf("%s: %d %v", v.Version, code, resp)
		}
	}

	// One bad OS/arch row refuses the whole version, even with a good one
	// beside it.
	mixed := mustPublishVersion(t, gdb, "v9.1.0", time.Now())
	bad := row("fv_mixed_bad", mixed.Version)
	bad.OS, bad.PackageType, bad.FileName = "windows", "msi", "imas-sprout_9.1.0_amd64.msi"
	if err := gdb.Create(&bad).Error; err != nil {
		t.Fatal(err)
	}
	mustApprove(t, gdb, tid, mixed.Version)
	if code, resp := postUpdates(t, tid, map[string]any{"asset_ids": []string{"a1"}, "target_version": mixed.Version}); code != 500 {
		t.Fatalf("mixed: %d %v", code, resp)
	}

	var n int64
	gdb.Model(&AssetActionBatch{}).Where("tenant_id = ?", tid).Count(&n)
	if n != 0 {
		t.Fatalf("%d batch(es) created from unverifiable rows", n)
	}
}

func TestSelfUpdateParams(t *testing.T) {
	_, ks := testFleetKey(t)
	v := FleetVersion{Version: "v1.0.0", OS: "linux", Arch: "amd64", PackageType: "deb", FileName: "imas-sprout_1.0.0_amd64.deb",
		ChecksumSHA256: strings.Repeat("ab", 32), MinSproutVersion: "v0.0.0"}
	v.Signature = signTestRelease(t, v)
	w := v
	w.OS, w.PackageType, w.FileName = "windows", "msi", "imas-sprout_1.0.0_amd64.msi"
	w.Signature = signTestRelease(t, w)

	SetFleetKeySource(staticFleetKeys{ks: ks})
	defer SetFleetKeySource(nil)
	params, err := selfUpdateParams(t.Context(), []FleetVersion{v, w})
	if err != nil {
		t.Fatalf("valid rows refused: %v", err)
	}
	// Only the version: no URL, file name, checksum or signature.
	if string(params) != `{"version":"v1.0.0"}` {
		t.Fatalf("params = %s", params)
	}
	// And it is exactly what farmer accepts.
	if p, err := controlplane.DecodeSelfUpdateParams(params); err != nil || p.Version != "v1.0.0" {
		t.Fatalf("farmer's decoder refuses saasapi's params %s: %v", params, err)
	}
	if _, err := selfUpdateParams(t.Context(), nil); err == nil {
		t.Fatal("params built from no rows")
	}
	other := w
	other.Version = "v1.0.1"
	if _, err := selfUpdateParams(t.Context(), []FleetVersion{v, other}); err == nil {
		t.Fatal("params built from rows of two versions")
	}
	// The stored checksum is used exactly as stored: an uppercase one (it
	// could only get there by bypassing registration) doesn't verify.
	up := v
	up.ChecksumSHA256 = strings.ToUpper(v.ChecksumSHA256)
	if _, err := selfUpdateParams(t.Context(), []FleetVersion{up}); !errors.Is(err, fleetsign.ErrInvalidManifest) {
		t.Fatalf("uppercase checksum row = %v, want ErrInvalidManifest", err)
	}

	SetFleetKeySource(nil)
	if _, err := selfUpdateParams(t.Context(), []FleetVersion{v}); err == nil {
		t.Fatal("dispatched with no key source")
	}
	SetFleetKeySource(staticFleetKeys{err: errors.New("403 permission denied")})
	if _, err := selfUpdateParams(t.Context(), []FleetVersion{v}); err == nil {
		t.Fatal("dispatched when the key couldn't be read")
	}
}
