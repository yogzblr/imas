package pkg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/gogrlx/snack"
	"github.com/yogzblr/imas/internal/cook"
)

// apt keys given as a URL are installed here, not by snack's apt.AddKey.
// snack saves such a key to /etc/apt/keyrings/<base>.gpg (the URL's last
// element without its extension), so two URLs with the same last element
// (https://a.example/linux/ubuntu/gpg, https://b.example/repo/gpg) share
// one file: the second was reported present and never installed.
//
// The first key keeps snack's name, so recipes and sources that name
// /etc/apt/keyrings/<base>.gpg still work. A different key whose snack name
// is taken goes to /etc/apt/keyrings/<base>-<hash>.gpg, <hash> being the
// first 12 hex digits of the URL's SHA-256. Which file holds a URL's key is
// decided by content: the key is fetched and dearmored on every run, and it
// is present when either file holds exactly those bytes.

// aptKeyringDir is where apt keyrings live; a variable for tests.
var aptKeyringDir = "/etc/apt/keyrings"

// maxKeySize bounds a fetched key. Real keyrings are a few KiB.
const maxKeySize = 1 << 20

var keyHTTPClient = &http.Client{Timeout: 2 * time.Minute}

// fetchURLKey downloads the key at url; a variable for tests.
var fetchURLKey = func(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := keyHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch key %s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxKeySize+1))
	if err != nil {
		return nil, fmt.Errorf("fetch key %s: %w", url, err)
	}
	if len(data) > maxKeySize {
		return nil, fmt.Errorf("fetch key %s: larger than %d bytes", url, maxKeySize)
	}
	return data, nil
}

// isAptURLKey reports whether key is a URL handed to apt.
func isAptURLKey(keyMgr snack.KeyManager, key string) bool {
	m, ok := keyMgr.(interface{ Name() string })
	if !ok || m.Name() != "apt" {
		return false
	}
	return strings.HasPrefix(key, "http://") || strings.HasPrefix(key, "https://")
}

// aptKeyringPaths returns the two files a URL's key may be kept in:
// snack's name, shared by every URL with the same last element, and the
// name only this URL maps to.
func aptKeyringPaths(url string) (legacy, unique string) {
	base := path.Base(url)
	base = strings.TrimSuffix(base, path.Ext(base))
	sum := sha256.Sum256([]byte(url))
	legacy = path.Join(aptKeyringDir, base+".gpg")
	unique = path.Join(aptKeyringDir, base+"-"+hex.EncodeToString(sum[:6])+".gpg")
	return legacy, unique
}

var errNotAKey = errors.New("not an OpenPGP public key")

// dearmorKey returns key as a binary keyring, as `gpg --dearmor` writes
// it: an ASCII-armored public key block is decoded (its checksum checked),
// a binary one is returned as is. Anything else, such as an HTML error
// page, is refused.
func dearmorKey(key []byte) ([]byte, error) {
	trimmed := bytes.TrimLeft(key, " \t\r\n")
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		block, err := armor.Decode(bytes.NewReader(trimmed))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errNotAKey, err)
		}
		if block.Type != "PGP PUBLIC KEY BLOCK" {
			return nil, fmt.Errorf("%w: armor block is %q", errNotAKey, block.Type)
		}
		bin, err := io.ReadAll(block.Body)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errNotAKey, err)
		}
		if !isPublicKeyPacket(bin) {
			return nil, errNotAKey
		}
		return bin, nil
	}
	if !isPublicKeyPacket(key) {
		return nil, errNotAKey
	}
	return key, nil
}

// isPublicKeyPacket reports whether data starts with an OpenPGP public key
// packet (tag 6), in the old or the new packet format.
func isPublicKeyPacket(data []byte) bool {
	if len(data) == 0 || data[0]&0x80 == 0 {
		return false
	}
	if data[0]&0x40 != 0 { // new format: tag in bits 5-0
		return data[0]&0x3f == 6
	}
	return (data[0]&0x3c)>>2 == 6 // old format: tag in bits 5-2
}

// fileHolds reports whether the file at name holds exactly want. A
// missing file holds nothing.
func fileHolds(name string, want []byte) (exists, same bool, err error) {
	got, err := os.ReadFile(name)
	if errors.Is(err, os.ErrNotExist) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	return true, bytes.Equal(got, want), nil
}

// writeKeyring writes data to name (mode 0644) through a temporary file
// in the same directory, so apt never reads a half-written keyring.
func writeKeyring(name string, data []byte) error {
	dir := filepath.Dir(name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".imas-key-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), name)
}

// aptURLKeyAdded installs the key at p.name for apt (see the top of this
// file for where it goes).
func (p Pkg) aptURLKeyAdded(ctx context.Context, test bool) (cook.Result, error) {
	raw, err := fetchURLKey(ctx, p.name)
	if err != nil {
		return failResult(err)
	}
	want, err := dearmorKey(raw)
	if err != nil {
		return failResult(fmt.Errorf("key %s: %w", p.name, err))
	}
	legacy, unique := aptKeyringPaths(p.name)
	legacyExists, legacySame, err := fileHolds(legacy, want)
	if err != nil {
		return failResult(err)
	}
	uniqueExists, uniqueSame, err := fileHolds(unique, want)
	if err != nil {
		return failResult(err)
	}
	for _, f := range []struct {
		name string
		same bool
	}{{legacy, legacySame}, {unique, uniqueSame}} {
		if f.same {
			return cook.Result{
				Succeeded: true,
				Changed:   false,
				Notes:     []fmt.Stringer{note("key already present: %s in %s", p.name, f.name)},
			}, nil
		}
	}
	// The URL's own name once it exists (only this URL maps to it, so it
	// holds an older copy of this key); else snack's name while it is free.
	// A taken snack name holds another URL's key, or an older copy of this
	// one: it is left alone either way.
	dest := legacy
	if uniqueExists || legacyExists {
		dest = unique
	}
	if test {
		return cook.Result{
			Succeeded: true,
			Changed:   true,
			Notes:     []fmt.Stringer{note("would add key: %s to %s", p.name, dest)},
		}, nil
	}
	if err := writeKeyring(dest, want); err != nil {
		return failResult(fmt.Errorf("add key %s: %w", p.name, err))
	}
	return cook.Result{
		Succeeded: true,
		Changed:   true,
		Notes:     []fmt.Stringer{note("added key: %s to %s", p.name, dest)},
	}, nil
}
