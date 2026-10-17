// Package packagingtest checks the sprout's update trust root as the
// packages ship it (security review 2026-10, L5): the keyring every
// imas-sprout package installs as /etc/imas/fleet-signing-keys.asc is
// built from the repo's gpg-public-key.asc (.goreleaser.yaml nfpms,
// packaging/windows/imas-sprout.wxs), and the sprout parses it with
// fleetsign.ParseArmoredKeyring and verifies every release's
// checksums.txt.sig against it with VerifyChecksums.
//
// The same tests are the release gate, run from .github/workflows/
// release.yml and publish-packages.yml with the sprout's own verify code
// (no other tool):
//
//	IMAS_RELEASE=1 go test ./packaging/test -run TestPackagedKeyring
//	IMAS_RELEASE_DIST=dist go test ./packaging/test -run TestReleaseChecksums
//
// (a relative IMAS_RELEASE_DIST is taken from the repo root).
//
// In the development tree the keyring may be empty ({}, or no key) until
// the release GPG public key is added (owner decision T1, 2026-10-17); a
// release may not ship it so.
package packagingtest

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/yogzblr/imas/internal/fleetsign"
)

// packagedKeyring is the file the packages install as the keyring.
var packagedKeyring = filepath.Join("..", "..", "gpg-public-key.asc")

// releaseMode reports whether this run is a release gate: then an empty
// keyring fails.
func releaseMode() bool {
	return os.Getenv("IMAS_RELEASE") != "" || os.Getenv("IMAS_RELEASE_DIST") != ""
}

// checkKeyring parses data as the sprout does. An empty keyring
// (fleetsign.ErrNoKeys: "{}", nothing, or no key that can sign) is
// allowed unless release is set; anything else that doesn't parse is
// always an error.
func checkKeyring(data []byte, release bool) (fleetsign.ArmoredKeyring, error) {
	k, err := fleetsign.ParseArmoredKeyring(data)
	switch {
	case errors.Is(err, fleetsign.ErrNoKeys) && !release:
		return k, nil
	case errors.Is(err, fleetsign.ErrNoKeys):
		return k, fmt.Errorf("the keyring holds no release key: a release may not ship it (add the release GPG public key, docs/RELEASING.md): %w", err)
	case err != nil:
		return k, fmt.Errorf("the keyring does not parse as the sprout parses it: %w", err)
	}
	return k, nil
}

// checkRelease is the release gate on one release's files: the keyring
// holds a key, checksums.txt.sig verifies over the exact checksums.txt
// bytes against it, and checksums.txt parses strictly, all as the sprout
// checks them.
func checkRelease(keyring, txt, sig []byte) error {
	k, err := checkKeyring(keyring, true)
	if err != nil {
		return err
	}
	if err := k.VerifyChecksums(txt, sig); err != nil {
		return fmt.Errorf("checksums.txt.sig does not verify against the packaged keyring as the sprout verifies it: %w", err)
	}
	if _, err := fleetsign.ParseChecksums(txt); err != nil {
		return fmt.Errorf("checksums.txt does not parse as the sprout parses it: %w", err)
	}
	return nil
}

// TestPackagedKeyring: the keyring the packages ship parses as the sprout
// parses it, so a malformed key change fails here and not on the fleet.
// With IMAS_RELEASE set it must also hold a key.
func TestPackagedKeyring(t *testing.T) {
	data, err := os.ReadFile(packagedKeyring)
	if err != nil {
		t.Fatal(err)
	}
	k, err := checkKeyring(data, releaseMode())
	if err != nil {
		t.Fatalf("%s: %v", packagedKeyring, err)
	}
	t.Logf("%s: %d release key(s)", packagedKeyring, k.Len())
}

// TestPackagingInstallsTheKeyring: every imas-sprout package installs
// gpg-public-key.asc as the keyring, mode 0600 (the sprout refuses a
// looser one, security review L3), and the MSI installs it too.
func TestPackagingInstallsTheKeyring(t *testing.T) {
	goreleaser, err := os.ReadFile(filepath.Join("..", "..", ".goreleaser.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	entry := regexp.MustCompile(`- src: \./gpg-public-key\.asc\n\s+dst: /etc/imas/fleet-signing-keys\.asc\n\s+file_info:\n\s+mode: (\d+)`)
	m := entry.FindAllSubmatch(goreleaser, -1)
	if len(m) != 3 {
		t.Fatalf(".goreleaser.yaml installs the keyring %d times, want 3 (apk, deb, rpm)", len(m))
	}
	for _, mode := range m {
		if string(mode[1]) != "0600" {
			t.Errorf(".goreleaser.yaml installs the keyring mode %s, want 0600", mode[1])
		}
	}
	wxs, err := os.ReadFile(filepath.Join("..", "windows", "imas-sprout.wxs"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(wxs, []byte("Name='fleet-signing-keys.asc'")) || !bytes.Contains(wxs, []byte("Source='gpg-public-key.asc'")) {
		t.Error("the MSI does not install gpg-public-key.asc as fleet-signing-keys.asc")
	}
}

// TestReleaseChecksums: the release gate (checkRelease) accepts a release
// signed by a key in the keyring and refuses an empty keyring, another
// key's signature, an altered checksums.txt and a text-mode signature.
// With IMAS_RELEASE_DIST set it also runs on that directory's
// checksums.txt and checksums.txt.sig against the packaged keyring.
func TestReleaseChecksums(t *testing.T) {
	key, other := newKey(t), newKey(t)
	ring := armoredPublic(t, key)
	txt := []byte(strings.Repeat("a", 64) + "  imas-sprout_2.4.1_linux_amd64.deb\n" +
		strings.Repeat("b", 64) + "  imas-sprout-2.4.1-windows-x64.msi\n")
	sig := detachSign(t, key, txt, false)

	if err := checkRelease(ring, txt, sig); err != nil {
		t.Errorf("a good release: %v", err)
	}
	for name, tc := range map[string]struct{ ring, txt, sig []byte }{
		"empty keyring {}":        {[]byte("{}"), txt, sig},
		"no keyring":              {nil, txt, sig},
		"another key's signature": {ring, txt, detachSign(t, other, txt, false)},
		"altered checksums.txt":   {ring, bytes.Replace(txt, []byte("aaaa"), []byte("cccc"), 1), sig},
		"text-mode signature":     {ring, txt, detachSign(t, key, txt, true)},
		"no signature":            {ring, txt, nil},
		"malformed checksums.txt": {ring, []byte("not a checksums file\n"), detachSign(t, key, []byte("not a checksums file\n"), false)},
		"private key in keyring":  {armoredPrivate(t, key), txt, sig},
	} {
		if err := checkRelease(tc.ring, tc.txt, tc.sig); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The development tree may carry {} (owner decision T1); a release
	// may not.
	if _, err := checkKeyring([]byte("{}"), false); err != nil {
		t.Errorf("{} in the development tree: %v", err)
	}
	if _, err := checkKeyring([]byte("{}"), true); !errors.Is(err, fleetsign.ErrNoKeys) {
		t.Errorf("{} in a release: %v, want ErrNoKeys", err)
	}

	dist := os.Getenv("IMAS_RELEASE_DIST")
	if dist == "" {
		return
	}
	if !filepath.IsAbs(dist) {
		// Relative to the repo root, where the workflows run; go test
		// runs in this package's directory.
		dist = filepath.Join("..", "..", dist)
	}
	read := func(path string) []byte {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if err := checkRelease(read(packagedKeyring), read(filepath.Join(dist, "checksums.txt")), read(filepath.Join(dist, "checksums.txt.sig"))); err != nil {
		t.Fatalf("release in %s: %v", dist, err)
	}
	t.Logf("release in %s: checksums.txt.sig verifies against %s", dist, packagedKeyring)
}

func newKey(t *testing.T) *openpgp.Entity {
	t.Helper()
	e, err := openpgp.NewEntity("imas release test", "", "release@example.invalid",
		&packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Time: func() time.Time { return time.Now().Add(-time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func armoredPublic(t *testing.T, es ...*openpgp.Entity) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range es {
		if err := e.Serialize(w); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	return buf.Bytes()
}

func armoredPrivate(t *testing.T, e *openpgp.Entity) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SerializePrivate(w, nil); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return buf.Bytes()
}

func detachSign(t *testing.T, e *openpgp.Entity, txt []byte, textMode bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	sign := openpgp.DetachSign
	if textMode {
		sign = openpgp.DetachSignText
	}
	if err := sign(&buf, e, bytes.NewReader(txt), nil); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
