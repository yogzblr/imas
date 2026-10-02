package fleetsign

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
)

// Keyring is the set of imas-fleet-signing public keys a sprout trusts
// for updates, keyed by key id: the Transit key version that the
// signature's "v<key version>:" prefix names. It is loaded from a file
// shipped in the sprout package (LoadKeyring), never fetched: no NATS
// subject, no HTTP endpoint and no JWKS can add a key to it, so
// neither farmer nor the bus is part of the sprout's trust chain (§2.5,
// "Key rotation").
//
// Rotation: a new key version is added to the keyring file in a sprout
// release signed by a key the running sprouts already hold, and the old
// one is removed only after no approved version depends on it. During
// the overlap the ring holds both, and Verify accepts a manifest signed
// by either.
type Keyring struct {
	keys KeySet
}

// Keyring file limits. A keyring holds one key per live Transit key
// version, so a handful at most.
const (
	maxKeyringFile = 16 << 10
	maxKeyringKeys = 32
)

// NewKeyring builds a Keyring from keys with NewKeySet's validation: at
// least one key, positive unique key ids, 32-byte keys, no weak keys.
func NewKeyring(keys []PublicKey) (Keyring, error) {
	ks, err := NewKeySet(keys)
	if err != nil {
		return Keyring{}, err
	}
	return Keyring{keys: ks}, nil
}

// ParseKeyring parses the keyring file format: one JSON object mapping
// each key id (a positive decimal Transit key version, "1", not "01" or
// "v1") to that key version's raw 32-byte Ed25519 public key in standard
// padded base64 — the same encoding Transit's keys/<key> read returns
// (ParseTransitEd25519PublicKey):
//
//	{"1": "<base64>", "2": "<base64>"}
//
// It is strict, since this file is the root of trust for every binary
// the sprout will ever install: duplicate key ids, any non-string value,
// trailing data, an empty ring and weak keys are all refused.
func ParseKeyring(data []byte) (Keyring, error) {
	if len(data) > maxKeyringFile {
		return Keyring{}, fmt.Errorf("fleetsign: keyring is larger than %d bytes", maxKeyringFile)
	}
	obj, err := parseFlatStringObject(data, maxKeyringKeys)
	if err != nil {
		return Keyring{}, fmt.Errorf("fleetsign: parsing keyring: %w", err)
	}
	keys := make([]PublicKey, 0, len(obj))
	for id, b64 := range obj {
		version, err := strconv.Atoi(id)
		if err != nil || version < 1 || id != strconv.Itoa(version) {
			return Keyring{}, fmt.Errorf("fleetsign: keyring key id %q is not a positive key version", id)
		}
		pub, err := ParseTransitEd25519PublicKey(b64)
		if err != nil {
			return Keyring{}, fmt.Errorf("fleetsign: keyring key %s: %w", id, err)
		}
		keys = append(keys, PublicKey{Version: version, Key: pub})
	}
	return NewKeyring(keys)
}

// LoadKeyring reads and parses the keyring file at path. Besides
// ParseKeyring's checks it refuses anything but a regular file, and on
// Unix-like systems a file that is group- or world-writable: whoever can
// write this file decides what the sprout installs as root.
func LoadKeyring(path string) (Keyring, error) {
	f, err := os.Open(path)
	if err != nil {
		return Keyring{}, fmt.Errorf("fleetsign: opening keyring: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return Keyring{}, fmt.Errorf("fleetsign: stat keyring: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return Keyring{}, fmt.Errorf("fleetsign: keyring %s is not a regular file", path)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o022 != 0 {
		return Keyring{}, fmt.Errorf("fleetsign: keyring %s is group- or world-writable (mode %v)", path, fi.Mode().Perm())
	}
	data, err := io.ReadAll(io.LimitReader(f, maxKeyringFile+1))
	if err != nil {
		return Keyring{}, fmt.Errorf("fleetsign: reading keyring: %w", err)
	}
	return ParseKeyring(data)
}

// Verify checks m's signature against the key the signature names, which
// may be any key in the ring. It is KeySet.Verify over the shipped keys:
// fields validated, signature required, no fallback.
func (k Keyring) Verify(m Manifest) error {
	return k.keys.Verify(m)
}

// KeyIDs returns the ring's key ids (Transit key versions), ascending.
func (k Keyring) KeyIDs() []int {
	ids := make([]int, len(k.keys))
	for i, pk := range k.keys {
		ids[i] = pk.Version
	}
	return ids
}

// ed25519FieldPrime is p = 2^255 - 19, little-endian, the bound for a
// canonical y coordinate.
var ed25519FieldPrime = [32]byte{
	0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
}

// smallOrderY are the y coordinates (little-endian, sign bit clear) of
// the eight points of order dividing 8 on edwards25519: the same list
// libsodium blocks. keyring_test.go rederives it with
// filippo.io/edwards25519.
var smallOrderY = [5][32]byte{
	{},     // y = 0: the two points of order 4
	{0x01}, // y = 1: the identity
	{ // order 8
		0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
		0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
	},
	{ // order 8
		0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
		0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
	},
	{ // y = p - 1: order 2
		0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
	},
}

var errWeakKey = errors.New("weak Ed25519 public key")

// checkPublicKey refuses public keys no real signer produces but for
// which crypto/ed25519.Verify can accept forged signatures: a
// small-order point (with the all-zero key, a placeholder someone might
// ship, signatures over any message can be forged in a few tries), and
// a non-canonical encoding of y (which only small-order keys need).
func checkPublicKey(key ed25519.PublicKey) error {
	if len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: %d bytes", errWeakKey, len(key))
	}
	var y [32]byte
	copy(y[:], key)
	y[31] &= 0x7f
	for i := 31; i >= 0; i-- {
		if y[i] < ed25519FieldPrime[i] {
			break
		}
		if y[i] > ed25519FieldPrime[i] || i == 0 {
			return fmt.Errorf("%w: non-canonical encoding", errWeakKey)
		}
	}
	for _, so := range smallOrderY {
		if bytes.Equal(y[:], so[:]) {
			return fmt.Errorf("%w: small-order point", errWeakKey)
		}
	}
	return nil
}
