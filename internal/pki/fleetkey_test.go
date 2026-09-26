package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/fleetsign"
)

func testFleetJWKS(t *testing.T) (fleetsign.KeySet, []byte) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ks, _ := fleetsign.NewKeySet([]fleetsign.PublicKey{{Version: 1, Key: pub}})
	data, err := ks.MarshalJWKS()
	if err != nil {
		t.Fatal(err)
	}
	return ks, data
}

func withFleetPinPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pki", "sprout", "fleet-signing-jwks.json")
	orig := config.SproutFleetSigningJWKS
	config.SproutFleetSigningJWKS = path
	t.Cleanup(func() { config.SproutFleetSigningJWKS = orig })
	return path
}

func TestPinFleetSigningKeys_WriteOnce(t *testing.T) {
	path := withFleetPinPath(t)
	if _, err := LoadPinnedFleetSigningKeys(); !errors.Is(err, ErrFleetKeyNotPinned) {
		t.Fatalf("Load before pin = %v, want ErrFleetKeyNotPinned", err)
	}

	ks, jwks := testFleetJWKS(t)
	if err := PinFleetSigningKeys(jwks); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	got, err := LoadPinnedFleetSigningKeys()
	if err != nil || len(got) != 1 || !got[0].Key.Equal(ks[0].Key) {
		t.Fatalf("Load = %+v, %v", got, err)
	}
	// Same document again: fine.
	if err := PinFleetSigningKeys(jwks); err != nil {
		t.Fatalf("re-pin same: %v", err)
	}
	// A different key set never replaces the pinned one.
	_, other := testFleetJWKS(t)
	if err := PinFleetSigningKeys(other); !errors.Is(err, ErrFleetKeyAlreadyPinned) {
		t.Fatalf("pin different = %v, want ErrFleetKeyAlreadyPinned", err)
	}
	onDisk, _ := os.ReadFile(path)
	if string(onDisk) != string(jwks) {
		t.Fatal("pinned file changed after a refused re-pin")
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o644 {
		t.Errorf("pinned file mode = %v, want 0644", fi.Mode().Perm())
	}
}

func TestPinFleetSigningKeys_RejectsInvalid(t *testing.T) {
	path := withFleetPinPath(t)
	for _, doc := range []string{``, `{}`, `{"keys":[]}`, `{"keys":[{"kty":"oct","k":"AAAA","kid":"1"}]}`} {
		if err := PinFleetSigningKeys([]byte(doc)); err == nil {
			t.Errorf("pinned invalid JWKS %q", doc)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("invalid JWKS left a pin file behind: %v", err)
	}
}

func TestLoadPinnedFleetSigningKeys_CorruptFile(t *testing.T) {
	path := withFleetPinPath(t)
	os.MkdirAll(filepath.Dir(path), 0o755)
	os.WriteFile(path, []byte("garbage"), 0o644)
	if _, err := LoadPinnedFleetSigningKeys(); err == nil {
		t.Fatal("loaded a corrupt pin file")
	}
}
