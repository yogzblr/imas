package selfupdate

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/fleetsign"
	"github.com/yogzblr/imas/internal/ingredients"
	"github.com/yogzblr/imas/internal/pki"
)

var artifact = []byte("#!/bin/sh\necho sprout v2.4.1\n")

// fixture is an artifact host whose TLS cert chains to the sprout's
// SproutRootCA, a pinned fleet key set, and a signer for it.
type fixture struct {
	ts       *httptest.Server
	requests atomic.Int32
	priv     ed25519.PrivateKey
	installs []string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{}
	f.ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.requests.Add(1)
		w.Write(artifact)
	}))
	t.Cleanup(f.ts.Close)

	dir := t.TempDir()
	rootCA := filepath.Join(dir, "tls-rootca.pem")
	os.WriteFile(rootCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ts.Certificate().Raw}), 0o644)
	origCA, origCache, origPin := config.SproutRootCA, config.CacheDir, config.SproutFleetSigningJWKS
	config.SproutRootCA = rootCA
	config.CacheDir = filepath.Join(dir, "cache")
	config.SproutFleetSigningJWKS = filepath.Join(dir, "fleet-signing-jwks.json")
	t.Cleanup(func() {
		config.SproutRootCA, config.CacheDir, config.SproutFleetSigningJWKS = origCA, origCache, origPin
	})

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f.priv = priv
	ks, _ := fleetsign.NewKeySet([]fleetsign.PublicKey{{Version: 1, Key: pub}})
	jwks, _ := ks.MarshalJWKS()
	if err := pki.PinFleetSigningKeys(jwks); err != nil {
		t.Fatalf("pinning: %v", err)
	}

	origFields := manifestFields
	manifestFields = testManifestFields
	t.Cleanup(func() { manifestFields = origFields })

	origInstall := install
	install = func(_ context.Context, _ stepRelease, staged string) error {
		f.installs = append(f.installs, staged)
		return nil
	}
	t.Cleanup(func() { install = origInstall })

	// By default farmer is unreachable for keys and none has ever been
	// fetched, so these tests run on the enrollment-time bootstrap key;
	// keys_test.go covers the live path.
	resetLiveKeys()
	origFetch := fetchLiveKeys
	fetchLiveKeys = func(context.Context) (fleetsign.KeySet, error) { return nil, errors.New("no connection to farmer") }
	t.Cleanup(func() { fetchLiveKeys = origFetch; resetLiveKeys() })
	return f
}

// testManifestFields stands in for the signed manifest fields a step
// doesn't carry yet (manifestFields).
func testManifestFields() (osName, arch, fileName, minSproutVersion string) {
	return "linux", "amd64", "imas-sprout_2.4.1_amd64.deb", "v2.0.0"
}

func (f *fixture) release() stepRelease {
	sum := sha256.Sum256(artifact)
	return stepRelease{Version: "v2.4.1", ArtifactURL: f.ts.URL + "/sprout-v2.4.1", ChecksumSHA256: hex.EncodeToString(sum[:])}
}

func (f *fixture) sign(t *testing.T, rel stepRelease) string {
	t.Helper()
	msg, err := rel.manifest("").Message()
	if err != nil {
		t.Fatal(err)
	}
	return fleetsign.EncodeSignature(1, ed25519.Sign(f.priv, msg))
}

func step(t *testing.T, rel stepRelease, sig string) cook.RecipeCooker {
	t.Helper()
	props := map[string]interface{}{
		fleetsign.PropVersion:        rel.Version,
		propArtifactURL:              rel.ArtifactURL,
		fleetsign.PropChecksumSHA256: rel.ChecksumSHA256,
		fleetsign.PropSignature:      sig,
	}
	// Through the ingredient registry, as the sprout's cook engine does.
	rc, err := ingredients.NewRecipeCooker("selfupdate-v2.4.1", fleetsign.SelfUpdateIngredient, fleetsign.SelfUpdateMethod, props)
	if err != nil {
		t.Fatalf("NewRecipeCooker: %v", err)
	}
	return rc
}

func TestApply_VerifiedReleaseIsFetchedCheckedAndInstalled(t *testing.T) {
	f := newFixture(t)
	rel := f.release()
	res, err := step(t, rel, f.sign(t, rel)).Apply(context.Background())
	if err != nil || !res.Succeeded {
		t.Fatalf("Apply = %+v, %v", res, err)
	}
	if len(f.installs) != 1 {
		t.Fatalf("install called %d times", len(f.installs))
	}
	data, _ := os.ReadFile(f.installs[0])
	if string(data) != string(artifact) {
		t.Fatal("installed file isn't the artifact")
	}
}

// Tampered row: the checksum is a perfectly good SHA-256 (of the very
// artifact being served), but the signature was made over different
// fields. Refused, and the artifact host is never contacted.
func TestApply_TamperedRowValidHashInvalidSignature(t *testing.T) {
	f := newFixture(t)
	rel := f.release()
	signedFor := rel
	signedFor.Version = "v2.4.0"
	res, err := step(t, rel, f.sign(t, signedFor)).Apply(context.Background())
	if !errors.Is(err, fleetsign.ErrInvalidSignature) || res.Succeeded {
		t.Fatalf("Apply = %+v, %v; want ErrInvalidSignature", res, err)
	}
	if n := f.requests.Load(); n != 0 {
		t.Fatalf("artifact host got %d request(s) before the signature was checked", n)
	}
	if len(f.installs) != 0 {
		t.Fatal("installed a release with an invalid signature")
	}
}

// Un-migrated fleet_versions row: no signature at all. Never accepted on
// the strength of the checksum alone.
func TestApply_MissingSignatureRefused(t *testing.T) {
	f := newFixture(t)
	rel := f.release()
	for name, props := range map[string]map[string]interface{}{
		"empty signature": {fleetsign.PropVersion: rel.Version, propArtifactURL: rel.ArtifactURL, fleetsign.PropChecksumSHA256: rel.ChecksumSHA256, fleetsign.PropSignature: ""},
		"no signature":    {fleetsign.PropVersion: rel.Version, propArtifactURL: rel.ArtifactURL, fleetsign.PropChecksumSHA256: rel.ChecksumSHA256},
	} {
		rc, err := SelfUpdate{}.Parse("s", fleetsign.SelfUpdateMethod, props)
		if err != nil {
			t.Fatalf("%s: Parse: %v", name, err)
		}
		res, err := rc.Apply(context.Background())
		if !errors.Is(err, fleetsign.ErrMissingSignature) || res.Succeeded {
			t.Fatalf("%s: Apply = %+v, %v; want ErrMissingSignature", name, res, err)
		}
		if _, err := rc.Test(context.Background()); !errors.Is(err, fleetsign.ErrMissingSignature) {
			t.Fatalf("%s: Test = %v; want ErrMissingSignature", name, err)
		}
	}
	if n := f.requests.Load(); n != 0 || len(f.installs) != 0 {
		t.Fatalf("unsigned release reached the network (%d) or install (%d)", n, len(f.installs))
	}
}

func TestApply_NoPinnedKeyRefused(t *testing.T) {
	f := newFixture(t)
	os.Remove(config.SproutFleetSigningJWKS)
	rel := f.release()
	if _, err := step(t, rel, f.sign(t, rel)).Apply(context.Background()); !errors.Is(err, pki.ErrFleetKeyNotPinned) {
		t.Fatalf("Apply = %v, want ErrFleetKeyNotPinned", err)
	}
	if f.requests.Load() != 0 {
		t.Fatal("fetched without a pinned key")
	}
}

// Validly signed, but the artifact host's certificate doesn't chain to
// SproutRootCA: the TLS handshake is refused.
func TestApply_ArtifactHostNotChainingToSproutRootCARefused(t *testing.T) {
	f := newFixture(t)
	os.WriteFile(config.SproutRootCA, unrelatedCAPEM(t), 0o644)
	rel := f.release()
	_, err := step(t, rel, f.sign(t, rel)).Apply(context.Background())
	var unknownAuthority x509.UnknownAuthorityError
	if !errors.As(err, &unknownAuthority) {
		t.Fatalf("Apply = %v, want x509.UnknownAuthorityError", err)
	}
	if len(f.installs) != 0 {
		t.Fatal("installed after a refused TLS handshake")
	}
	if entries, _ := os.ReadDir(filepath.Join(config.CacheDir, "selfupdate")); len(entries) != 0 {
		t.Fatalf("staging dir not empty: %v", entries)
	}
}

// Validly signed row, but the served bytes aren't the signed checksum
// (e.g. the object in storage was swapped). The checksum check after
// download refuses it and removes the staged file.
func TestApply_ChecksumCheckedAfterDownload(t *testing.T) {
	f := newFixture(t)
	rel := f.release()
	rel.ChecksumSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // sha256 of ""
	_, err := step(t, rel, f.sign(t, rel)).Apply(context.Background())
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("Apply = %v, want ErrChecksumMismatch", err)
	}
	if f.requests.Load() != 1 || len(f.installs) != 0 {
		t.Fatalf("requests %d, installs %d", f.requests.Load(), len(f.installs))
	}
	if _, err := os.Stat(filepath.Join(config.CacheDir, "selfupdate", "sprout-"+rel.ChecksumSHA256)); !os.IsNotExist(err) {
		t.Fatal("mismatched artifact left staged")
	}
}

// Until §2.3's install step exists, a verified release ends failed —
// never a success a rollout gate would advance on.
func TestApply_DefaultInstallFailsClosed(t *testing.T) {
	f := newFixture(t)
	install = func(ctx context.Context, rel stepRelease, staged string) error {
		return ErrInstallNotImplemented
	}
	rel := f.release()
	res, err := step(t, rel, f.sign(t, rel)).Apply(context.Background())
	if !errors.Is(err, ErrInstallNotImplemented) || res.Succeeded || !res.Failed {
		t.Fatalf("Apply = %+v, %v", res, err)
	}
}

func TestTest_VerifiesWithoutFetching(t *testing.T) {
	f := newFixture(t)
	rel := f.release()
	res, err := step(t, rel, f.sign(t, rel)).Test(context.Background())
	if err != nil || !res.Succeeded || f.requests.Load() != 0 {
		t.Fatalf("Test = %+v, %v (requests %d)", res, err, f.requests.Load())
	}
	bad := rel
	bad.Version = "v6.6.6"
	if _, err := step(t, bad, f.sign(t, rel)).Test(context.Background()); !errors.Is(err, fleetsign.ErrInvalidSignature) {
		t.Fatalf("Test with bad signature = %v", err)
	}
}

// Until FU.2 a step can't supply the manifest's os, arch, file_name and
// min_sprout_version, so every release is refused — before any key read
// or download — even one whose signature would verify with them filled
// in.
func TestApply_FailsClosedWithoutManifestFields(t *testing.T) {
	f := newFixture(t)
	rel := f.release()
	sig := f.sign(t, rel)
	manifestFields = func() (string, string, string, string) { return "", "", "", "" }
	res, err := step(t, rel, sig).Apply(context.Background())
	if !errors.Is(err, fleetsign.ErrInvalidManifest) || res.Succeeded {
		t.Fatalf("Apply = %+v, %v; want ErrInvalidManifest", res, err)
	}
	if _, err := step(t, rel, sig).Test(context.Background()); !errors.Is(err, fleetsign.ErrInvalidManifest) {
		t.Fatalf("Test = %v; want ErrInvalidManifest", err)
	}
	if f.requests.Load() != 0 || len(f.installs) != 0 {
		t.Fatalf("requests %d, installs %d; want none", f.requests.Load(), len(f.installs))
	}
}

func TestApply_RefusesNonHTTPSArtifactURL(t *testing.T) {
	f := newFixture(t)
	rel := f.release()
	rel.ArtifactURL = "http" + rel.ArtifactURL[len("https"):]
	if _, err := step(t, rel, f.sign(t, rel)).Apply(context.Background()); !errors.Is(err, fleetsign.ErrInvalidManifest) {
		t.Fatalf("Apply = %v; want ErrInvalidManifest", err)
	}
	if f.requests.Load() != 0 {
		t.Fatal("artifact host contacted over a refused URL")
	}
}

func TestParse_RejectsMissingFieldsAndUnknownMethod(t *testing.T) {
	if _, err := (SelfUpdate{}).Parse("s", fleetsign.SelfUpdateMethod, map[string]interface{}{fleetsign.PropVersion: "v1"}); !errors.Is(err, ErrMissingProperty) {
		t.Errorf("missing fields: %v", err)
	}
	if _, err := (SelfUpdate{}).Parse("s", "install", nil); !errors.Is(err, ErrMethodUndefined) {
		t.Errorf("unknown method: %v", err)
	}
	name, methods := SelfUpdate{}.Methods()
	if name != "selfupdate" || len(methods) != 1 || methods[0] != "apply" {
		t.Errorf("Methods = %s %v", name, methods)
	}
}

func unrelatedCAPEM(t *testing.T) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "not the farmer root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
