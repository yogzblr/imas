package fleetsign

// The sprout's verification of a release (P22, signing design D9, D12,
// D20, D21). The steps, in the order the sprout runs them, each failing
// closed with its own error:
//
//  1. LoadArmoredKeyring: the keyring file shipped in the sprout package
//     (config.SproutFleetSigningKeyring); no usable key is ErrNoKeys.
//  2. VerifyChecksums: size limits (ErrChecksumsTooLarge), then the
//     detached signature over the exact checksums.txt bytes against any
//     key in the ring (ErrBadSignature).
//  3. ParseChecksums: every line strictly well formed (ErrBadChecksums).
//  4. ExpectedFileName: the file name, derived by the sprout, never sent
//     by farmer.
//  5. Checksums.Sum: that name's line (ErrNotInChecksums if absent).

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Keyring file limits. The release keyring holds one key, two during a
// rotation; an armored RSA-4096 public key is about 3 KiB.
const (
	maxArmoredKeyring  = 256 << 10
	maxArmoredEntities = 32
)

// armoredPrefix marks an ASCII-armored signature; anything else is taken
// as binary OpenPGP packets.
const armoredPrefix = "-----BEGIN PGP"

// ArmoredKeyring is the set of release GPG public keys a sprout trusts
// for updates, read from the keyring file shipped in the sprout package
// (LoadArmoredKeyring). It is never fetched: no NATS subject, no HTTP
// endpoint can add a key to it, so neither farmer nor the bus is part of
// the sprout's trust chain.
//
// Rotation: a new key is added to the keyring in a sprout release signed
// by a key the running sprouts already hold; the old key is removed once
// no approved version depends on it (packaging/etc/fleet-signing-keys.md).
// During the overlap VerifyChecksums accepts a signature by either.
type ArmoredKeyring struct {
	entities openpgp.EntityList
}

// Len is the number of keys (OpenPGP entities) in the ring.
func (k ArmoredKeyring) Len() int { return len(k.entities) }

// LoadArmoredKeyring reads and parses the keyring file at path. Besides
// ParseArmoredKeyring's checks it refuses, with ErrUnsafePath, anything
// but a regular file owned by the effective user and no looser than 0600
// (on Windows: owned by SYSTEM or Administrators, with no write for anyone
// else), and a symlink (readTrustFile, CheckPrivateFile).
func LoadArmoredKeyring(path string) (ArmoredKeyring, error) {
	data, err := readTrustFile(path, maxArmoredKeyring)
	if err != nil {
		return ArmoredKeyring{}, err
	}
	return ParseArmoredKeyring(data)
}

// ParseArmoredKeyring parses one or more ASCII-armored OpenPGP public key
// blocks ("-----BEGIN PGP PUBLIC KEY BLOCK-----", as gpg --armor --export
// writes them; a block may hold several keys and blocks may be
// concatenated). Text outside the blocks is ignored. It refuses any other
// armor type, private key material, more than 32 keys, and a ring with no
// usable key (ErrNoKeys): a key is usable when its primary key or a
// subkey is certified for signing.
func ParseArmoredKeyring(data []byte) (ArmoredKeyring, error) {
	if len(data) > maxArmoredKeyring {
		return ArmoredKeyring{}, fmt.Errorf("fleetsign: keyring is larger than %d bytes", maxArmoredKeyring)
	}
	var usable openpgp.EntityList
	for _, segment := range armorSegments(data) {
		block, err := armor.Decode(bytes.NewReader(segment))
		if err != nil {
			return ArmoredKeyring{}, fmt.Errorf("fleetsign: decoding keyring armor: %w", err)
		}
		if block.Type != openpgp.PublicKeyType {
			return ArmoredKeyring{}, fmt.Errorf("fleetsign: keyring holds a %q block; only %q is allowed", block.Type, openpgp.PublicKeyType)
		}
		el, err := openpgp.ReadKeyRing(block.Body)
		if err != nil {
			return ArmoredKeyring{}, fmt.Errorf("fleetsign: reading keyring: %w", err)
		}
		for _, e := range el {
			if hasPrivateKey(e) {
				return ArmoredKeyring{}, errors.New("fleetsign: keyring holds private key material")
			}
			if canSign(e) {
				usable = append(usable, e)
			}
		}
		if len(usable) > maxArmoredEntities {
			return ArmoredKeyring{}, fmt.Errorf("fleetsign: keyring holds more than %d keys", maxArmoredEntities)
		}
	}
	if len(usable) == 0 {
		return ArmoredKeyring{}, ErrNoKeys
	}
	return ArmoredKeyring{entities: usable}, nil
}

// armorSegments splits data before every "-----BEGIN PGP" that starts an
// armor block, dropping text before the first one. armor.Decode reads
// ahead through a buffer, so each block is decoded from its own segment.
func armorSegments(data []byte) [][]byte {
	var starts []int
	for i := 0; ; {
		j := bytes.Index(data[i:], []byte(armoredPrefix))
		if j < 0 {
			break
		}
		starts = append(starts, i+j)
		i += j + len(armoredPrefix)
	}
	segments := make([][]byte, len(starts))
	for j, start := range starts {
		end := len(data)
		if j+1 < len(starts) {
			end = starts[j+1]
		}
		segments[j] = data[start:end]
	}
	return segments
}

func hasPrivateKey(e *openpgp.Entity) bool {
	if e.PrivateKey != nil {
		return true
	}
	for _, sk := range e.Subkeys {
		if sk.PrivateKey != nil {
			return true
		}
	}
	return false
}

// canSign reports whether e's primary key or one of its subkeys carries
// the signing key flag.
func canSign(e *openpgp.Entity) bool {
	if self, _ := e.PrimarySelfSignature(); self != nil && self.FlagsValid && self.FlagSign {
		return true
	}
	for _, sk := range e.Subkeys {
		if sk.Sig != nil && sk.Sig.FlagsValid && sk.Sig.FlagSign {
			return true
		}
	}
	return false
}

// VerifyChecksums checks that sig, the detached checksums.txt.sig (binary
// OpenPGP packets, or ASCII-armored if it starts with "-----BEGIN PGP"),
// is a valid binary-document signature over exactly the bytes txt by a
// key in k. In order:
//
//   - k holds no key: ErrNoKeys;
//   - txt is empty or sig is empty: ErrBadChecksums / ErrBadSignature;
//   - txt is over MaxChecksumsTxt or sig over MaxChecksumsSig:
//     ErrChecksumsTooLarge;
//   - anything else wrong with the signature: ErrBadSignature. That
//     includes an issuer not in the ring, a revoked key (whenever it was
//     revoked), a signature whose own lifetime has run out or whose
//     creation time is in the future, and a text-mode signature (which
//     would verify over line-ending-normalized bytes, not the exact ones).
//
// Key expiry is not enforced (D12.2): a release signed by a key that has
// since expired still verifies. go-crypto has no configuration switch for
// that and moving packet.Config.Time would also move the revocation
// check, so the config pins the clock to now and the one result accepted
// besides success is pgperrors.ErrKeyExpired, which go-crypto reports
// only after its revocation checks have passed.
func (k ArmoredKeyring) VerifyChecksums(txt, sig []byte) error {
	if len(k.entities) == 0 {
		return ErrNoKeys
	}
	switch {
	case len(txt) == 0:
		return fmt.Errorf("%w: checksums.txt is empty", ErrBadChecksums)
	case len(txt) > MaxChecksumsTxt:
		return fmt.Errorf("%w: checksums.txt is larger than %d bytes", ErrChecksumsTooLarge, MaxChecksumsTxt)
	case len(sig) == 0:
		return fmt.Errorf("%w: the signature is empty", ErrBadSignature)
	case len(sig) > MaxChecksumsSig:
		return fmt.Errorf("%w: the signature is larger than %d bytes", ErrChecksumsTooLarge, MaxChecksumsSig)
	}
	raw := sig
	if bytes.HasPrefix(sig, []byte(armoredPrefix)) {
		block, err := armor.Decode(bytes.NewReader(sig))
		if err != nil {
			return fmt.Errorf("%w: decoding the armored signature: %v", ErrBadSignature, err)
		}
		if block.Type != openpgp.SignatureType {
			return fmt.Errorf("%w: armored block is %q, not %q", ErrBadSignature, block.Type, openpgp.SignatureType)
		}
		if raw, err = io.ReadAll(io.LimitReader(block.Body, MaxChecksumsSig+1)); err != nil {
			return fmt.Errorf("%w: decoding the armored signature: %v", ErrBadSignature, err)
		}
	}
	now := time.Now()
	config := &packet.Config{Time: func() time.Time { return now }}
	s, _, err := openpgp.VerifyDetachedSignature(k.entities, bytes.NewReader(txt), bytes.NewReader(raw), config)
	switch {
	case err == nil:
	case errors.Is(err, pgperrors.ErrKeyExpired) && s != nil:
		// D12.2. go-crypto skipped its signature-lifetime check after
		// the key-expiry one; make it here.
		if s.SigExpired(now) {
			return fmt.Errorf("%w: the signature has expired or is dated in the future", ErrBadSignature)
		}
	default:
		return fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	if s.SigType != packet.SigTypeBinary {
		return fmt.Errorf("%w: signature type 0x%02x is not a binary document signature", ErrBadSignature, uint8(s.SigType))
	}
	return nil
}

// reChecksumLine is one checksums.txt line as goreleaser writes it
// (sha256sum format, binary mode not marked): 64 lowercase hex digits,
// two spaces, a plain file name (the same rule as reFileName).
var reChecksumLine = regexp.MustCompile(`^[0-9a-f]{64}  [A-Za-z0-9][A-Za-z0-9._+~-]*$`)

// Checksums is a parsed checksums.txt: file name to lowercase hex
// SHA-256.
type Checksums struct {
	sums map[string]string
}

// ParseChecksums parses checksums.txt strictly: every non-empty line
// must be "<64 lowercase hex>  <file name>" with a file name from
// [A-Za-z0-9._+~-] starting with a letter or digit, at most 255
// characters (so no path separator, no "." or "..", no '%', no space). A
// malformed line, an uppercase hash or a duplicate file name refuses the
// whole file (ErrBadChecksums), naming the line. Empty lines, including
// trailing ones, are skipped; a file with no entry is refused. Over
// MaxChecksumsTxt is ErrChecksumsTooLarge.
func ParseChecksums(txt []byte) (Checksums, error) {
	if len(txt) > MaxChecksumsTxt {
		return Checksums{}, fmt.Errorf("%w: checksums.txt is larger than %d bytes", ErrChecksumsTooLarge, MaxChecksumsTxt)
	}
	sums := map[string]string{}
	for i, line := range strings.Split(string(txt), "\n") {
		if line == "" {
			continue
		}
		if !reChecksumLine.MatchString(line) {
			return Checksums{}, fmt.Errorf("%w: line %d is not \"<64 lowercase hex>  <file name>\"", ErrBadChecksums, i+1)
		}
		sum, name := line[:64], line[66:]
		if len(name) > maxFileNameLen {
			return Checksums{}, fmt.Errorf("%w: line %d: file name is longer than %d characters", ErrBadChecksums, i+1, maxFileNameLen)
		}
		if _, dup := sums[name]; dup {
			return Checksums{}, fmt.Errorf("%w: line %d: duplicate file name %s", ErrBadChecksums, i+1, name)
		}
		sums[name] = sum
	}
	if len(sums) == 0 {
		return Checksums{}, fmt.Errorf("%w: no entries", ErrBadChecksums)
	}
	return Checksums{sums: sums}, nil
}

// Sum returns the SHA-256 (64 lowercase hex characters) on the line for
// exactly fileName.
func (c Checksums) Sum(fileName string) (string, bool) {
	s, ok := c.sums[fileName]
	return s, ok
}

// Len is the number of entries.
func (c Checksums) Len() int { return len(c.sums) }

// ExpectedFileName returns the release file name of the imas-sprout
// package for version (canonical semver with a leading 'v'), os, arch and
// packageType, as goreleaser and packaging/windows/build-msi.sh name it:
//
//	deb, rpm: imas-sprout_<version without v>_linux_<arch>.<deb|rpm>
//	msi:      imas-sprout-<version without v>-windows-<winarch>.msi
//
// where winarch is x64 for amd64, x86 for 386, and otherwise arch
// unchanged (the inverse of packaging/helm/stamp-sprout-release.sh). deb
// and rpm need os linux, msi needs os windows. Any other input is
// ErrInvalidManifest.
func ExpectedFileName(version, os, arch, packageType string) (string, error) {
	if err := checkVersion("version", version); err != nil {
		return "", err
	}
	if err := checkOSArch("os", os); err != nil {
		return "", err
	}
	if err := checkOSArch("arch", arch); err != nil {
		return "", err
	}
	v := strings.TrimPrefix(version, "v")
	var name string
	switch packageType {
	case PackageTypeDeb, PackageTypeRPM:
		if os != "linux" {
			return "", fmt.Errorf("%w: a .%s is for linux, not %s", ErrInvalidManifest, packageType, os)
		}
		name = "imas-sprout_" + v + "_linux_" + arch + "." + packageType
	case PackageTypeMSI:
		if os != "windows" {
			return "", fmt.Errorf("%w: an .msi is for windows, not %s", ErrInvalidManifest, os)
		}
		winArch := arch
		switch arch {
		case "amd64":
			winArch = "x64"
		case "386":
			winArch = "x86"
		}
		name = "imas-sprout-" + v + "-windows-" + winArch + ".msi"
	default:
		return "", fmt.Errorf("%w: package type %s", ErrInvalidManifest, strconv.Quote(packageType))
	}
	if len(name) > maxFileNameLen || !reFileName.MatchString(name) {
		return "", fmt.Errorf("%w: %q is not a plain file name", ErrInvalidManifest, name)
	}
	return name, nil
}
