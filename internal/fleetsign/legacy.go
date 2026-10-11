package fleetsign

// Deprecated: removed in P22 slice 2.
//
// This file holds the Ed25519 fleet trust that P22 replaces with the
// release's GPG-signed checksums.txt (gpg.go, signing design D9): the
// pre-P22 manifest (LegacyManifest), its canonical signed message, the
// signature encoding stored in saas.fleet_versions.signature, the
// Ed25519 KeySet and the JSON Keyring. The sprout no longer uses any of
// it. It is kept only so farmer, saasapi, natsapi, fleetcatalog and
// cmd/fleetreleaser keep compiling until P22 slice 2 moves them to the
// wire Manifest (manifest.go) and deletes this file, obtransit.go and
// their tests.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
)

// maxLegacyManifestJSON bounds LegacyParseManifest's input: every field
// at its limit plus the signature and JSON syntax is well under 1 KiB.
const maxLegacyManifestJSON = 4 << 10

// DefaultTransitKeyName is the OpenBao Transit key sprout releases are
// signed with: Ed25519, non-exportable, and distinct from
// internal/gatewayjwt's imas-gateway-jwt key.
const DefaultTransitKeyName = "imas-fleet-signing"

var (
	// ErrMissingSignature: the row has no signature (for example a
	// fleet_versions row written before the signature column existed).
	// Always a refusal, never a fallback to checksum-only trust.
	ErrMissingSignature = errors.New("fleetsign: manifest has no signature")
	// ErrMalformedSignature: the signature isn't "v<version>:<base64>".
	ErrMalformedSignature = errors.New("fleetsign: malformed signature")
	// ErrUnknownKeyVersion: the signature names a key version the key set
	// or keyring doesn't hold (not shipped, or retired).
	ErrUnknownKeyVersion = errors.New("fleetsign: signature key version not in key set")
	// ErrInvalidSignature: the signature doesn't verify.
	ErrInvalidSignature = errors.New("fleetsign: signature verification failed")
)

// MessageDomain is the domain-separation tag every manifest message
// starts with (Message).
const MessageDomain = "imas-fleet-manifest-v1"

// LegacyManifest is one saas.fleet_versions row as farmer serves it to a sprout
// (GET /v1/sprout/update-manifest, design doc §2.6): the sprout package
// for one version, OS and arch, and fleetreleaser's signature over it.
//
// There is deliberately no URL. The sprout builds the download URL from
// the repository configured in the sprout itself plus FileName
// (requirement 20, §1.8), so nothing a farmer, a saas.fleet_versions
// writer or the bus can change decides where code is fetched from; the
// signed checksum decides what may be installed.
type LegacyManifest struct {
	Version          string `json:"version"`
	OS               string `json:"os"`
	Arch             string `json:"arch"`
	FileName         string `json:"file_name"`
	ChecksumSHA256   string `json:"checksum_sha256"`
	MinSproutVersion string `json:"min_sprout_version"`
	// Signature is EncodeSignature's "v<key version>:<base64>" over
	// Message(). It is not part of the signed message.
	Signature string `json:"signature"`
}

// fields returns the signed fields in canonical order, with their JSON
// names. Message, Validate and ParseManifest all read this one list, so
// there is exactly one definition of what is signed.
func (m LegacyManifest) fields() [6]struct{ name, value string } {
	return [6]struct{ name, value string }{
		{"version", m.Version},
		{"os", m.OS},
		{"arch", m.Arch},
		{"file_name", m.FileName},
		{"checksum_sha256", m.ChecksumSHA256},
		{"min_sprout_version", m.MinSproutVersion},
	}
}

// Message returns the canonical bytes a manifest is signed over:
//
//	imas-fleet-manifest-v1|version|os|arch|file_name|checksum_sha256|min_sprout_version
//
// The leading MessageDomain is a fixed domain-separation tag: it binds
// the signature to this purpose and format version, so bytes signed with
// imas-fleet-signing for anything else (including the pre-FU.0
// version|artifact_url|checksum_sha256 message) can never verify as a
// manifest. A future format change gets a new tag, not a reinterpretation
// of this one.
//
// It is the one encoder shared by the signer (cmd/fleetreleaser) and
// every verifier (KeySet.Verify, Keyring.Verify). Fields are validated
// first (Validate) and never normalized: a value the signer would have to
// rewrite to accept, such as an uppercase checksum, is refused, so the
// bytes signed are exactly the bytes a verifier rebuilds. Because no
// field may contain '|', the encoding is unambiguous.
//
// min_sprout_version is signed along with the five fields §2.5 lists, so
// a manifest's floor can't be lowered (or raised) without breaking the
// signature.
func (m LegacyManifest) Message() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	f := m.fields()
	parts := make([]string, 0, len(f)+1)
	parts = append(parts, MessageDomain)
	for _, kv := range f {
		parts = append(parts, kv.value)
	}
	return []byte(strings.Join(parts, "|")), nil
}

// Validate checks every signed field (not Signature):
//
//   - no field is empty, contains '|' or a control character;
//   - version and min_sprout_version are canonical semver with a leading
//     'v' and no build metadata ("v2.4.1", "v2.5.0-rc.1"), at most 64
//     characters, and min_sprout_version <= version;
//   - os and arch are lowercase [a-z0-9_], at most 32 characters;
//   - file_name is a single file name from [A-Za-z0-9._+~-] that starts
//     with a letter or digit, at most 255 characters;
//   - checksum_sha256 is exactly 64 lowercase hex characters.
func (m LegacyManifest) Validate() error {
	for _, kv := range m.fields() {
		if kv.value == "" {
			return fmt.Errorf("%w: %s is empty", ErrInvalidManifest, kv.name)
		}
		if strings.ContainsRune(kv.value, '|') {
			return fmt.Errorf("%w: %s contains '|'", ErrInvalidManifest, kv.name)
		}
		for _, c := range kv.value {
			if c < 0x20 || c == 0x7f || (c >= 0x80 && c < 0xa0) {
				return fmt.Errorf("%w: %s contains a control character", ErrInvalidManifest, kv.name)
			}
		}
	}
	for _, kv := range []struct{ name, value string }{
		{"version", m.Version}, {"min_sprout_version", m.MinSproutVersion},
	} {
		if len(kv.value) > maxVersionLen {
			return fmt.Errorf("%w: %s is longer than %d characters", ErrInvalidManifest, kv.name, maxVersionLen)
		}
		if !semver.IsValid(kv.value) || semver.Canonical(kv.value) != kv.value {
			return fmt.Errorf("%w: %s %q is not a canonical semver version (vMAJOR.MINOR.PATCH[-PRERELEASE])", ErrInvalidManifest, kv.name, kv.value)
		}
	}
	if semver.Compare(m.MinSproutVersion, m.Version) > 0 {
		return fmt.Errorf("%w: min_sprout_version %s is above version %s", ErrInvalidManifest, m.MinSproutVersion, m.Version)
	}
	for _, kv := range []struct{ name, value string }{{"os", m.OS}, {"arch", m.Arch}} {
		if len(kv.value) > maxOSArchLen || !reOSArch.MatchString(kv.value) {
			return fmt.Errorf("%w: %s %q is not lowercase [a-z0-9_] of at most %d characters", ErrInvalidManifest, kv.name, kv.value, maxOSArchLen)
		}
	}
	if len(m.FileName) > maxFileNameLen || !reFileName.MatchString(m.FileName) {
		return fmt.Errorf("%w: file_name %q is not a plain file name", ErrInvalidManifest, m.FileName)
	}
	if !reSHA256.MatchString(m.ChecksumSHA256) {
		return fmt.Errorf("%w: checksum_sha256 is not 64 lowercase hex characters", ErrInvalidManifest)
	}
	return nil
}

// LegacyParseManifest decodes the JSON a sprout receives from farmer (§2.6)
// strictly: one JSON object, every value a string, the seven field names
// exactly as LegacyManifest's JSON tags spell them (no case folding, unlike
// encoding/json), no duplicate, missing or unknown key, nothing after
// the object, at most 4 KiB. The fields are then validated (Validate).
//
// ParseManifest does not verify the signature; call Keyring.Verify on
// the result. An unknown key is refused rather than ignored so that no
// field can ride along unsigned and later be trusted by a newer reader.
func LegacyParseManifest(data []byte) (LegacyManifest, error) {
	if len(data) > maxLegacyManifestJSON {
		return LegacyManifest{}, fmt.Errorf("%w: manifest is larger than %d bytes", ErrInvalidManifest, maxLegacyManifestJSON)
	}
	obj, err := parseFlatStringObject(data, 8)
	if err != nil {
		return LegacyManifest{}, fmt.Errorf("%w: %w", ErrInvalidManifest, err)
	}
	var m LegacyManifest
	dst := map[string]*string{
		"version": &m.Version, "os": &m.OS, "arch": &m.Arch, "file_name": &m.FileName,
		"checksum_sha256": &m.ChecksumSHA256, "min_sprout_version": &m.MinSproutVersion,
		"signature": &m.Signature,
	}
	for k, v := range obj {
		p, ok := dst[k]
		if !ok {
			return LegacyManifest{}, fmt.Errorf("%w: unknown field %q", ErrInvalidManifest, k)
		}
		*p = v
	}
	for k := range dst {
		if _, ok := obj[k]; !ok {
			return LegacyManifest{}, fmt.Errorf("%w: missing field %q", ErrInvalidManifest, k)
		}
	}
	if err := m.Validate(); err != nil {
		return LegacyManifest{}, err
	}
	return m, nil
}

// EncodeSignature renders a raw Ed25519 signature made by Transit key
// version keyVersion as stored in saas.fleet_versions.signature:
// "v<keyVersion>:<standard base64>". It's Transit's own
// "vault:v<N>:<base64>" format without the product prefix, so the key
// version a verifier must use travels with the signature.
func EncodeSignature(keyVersion int, sig []byte) string {
	return "v" + strconv.Itoa(keyVersion) + ":" + base64.StdEncoding.EncodeToString(sig)
}

// DecodeSignature parses EncodeSignature's format. An empty string is
// ErrMissingSignature, not ErrMalformedSignature, so callers can tell an
// un-migrated row from a corrupted one in their logs; both are refusals.
func DecodeSignature(s string) (keyVersion int, sig []byte, err error) {
	if s == "" {
		return 0, nil, ErrMissingSignature
	}
	ver, b64, ok := strings.Cut(s, ":")
	if !ok || !strings.HasPrefix(ver, "v") {
		return 0, nil, ErrMalformedSignature
	}
	keyVersion, err = strconv.Atoi(ver[1:])
	if err != nil || keyVersion < 1 || ver[1:] != strconv.Itoa(keyVersion) {
		return 0, nil, ErrMalformedSignature
	}
	sig, err = base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return 0, nil, ErrMalformedSignature
	}
	return keyVersion, sig, nil
}

// PublicKey is one version of the imas-fleet-signing Transit key.
type PublicKey struct {
	Version int
	Key     ed25519.PublicKey
}

// KeySet is every imas-fleet-signing key version a verifier trusts,
// sorted by ascending Version.
type KeySet []PublicKey

// NewKeySet validates keys and returns them as a sorted KeySet. It
// rejects an empty set, a non-positive or duplicate version, a key that
// isn't ed25519.PublicKeySize bytes, and a weak key (checkPublicKey).
func NewKeySet(keys []PublicKey) (KeySet, error) {
	if len(keys) == 0 {
		return nil, ErrNoKeys
	}
	seen := make(map[int]bool, len(keys))
	ks := make(KeySet, 0, len(keys))
	for _, k := range keys {
		if k.Version < 1 {
			return nil, fmt.Errorf("fleetsign: key version %d is not positive", k.Version)
		}
		if seen[k.Version] {
			return nil, fmt.Errorf("fleetsign: duplicate key version %d", k.Version)
		}
		if len(k.Key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("fleetsign: key version %d is %d bytes, want %d", k.Version, len(k.Key), ed25519.PublicKeySize)
		}
		if err := checkPublicKey(k.Key); err != nil {
			return nil, fmt.Errorf("fleetsign: key version %d: %w", k.Version, err)
		}
		seen[k.Version] = true
		ks = append(ks, PublicKey{Version: k.Version, Key: append(ed25519.PublicKey(nil), k.Key...)})
	}
	sort.Slice(ks, func(i, j int) bool { return ks[i].Version < ks[j].Version })
	return ks, nil
}

// Verify checks m.Signature (EncodeSignature's format) over m's
// canonical message (Manifest.Message) against the key version the
// signature names. Every failure is an error: there is no path on which a
// missing or bad signature, or an invalid field, is accepted.
func (ks KeySet) Verify(m LegacyManifest) error {
	if len(ks) == 0 {
		return ErrNoKeys
	}
	msg, err := m.Message()
	if err != nil {
		return err
	}
	return ks.verifyMessage(msg, m.Signature)
}

// verifyMessage is the one signature check behind KeySet.Verify and
// Keyring.Verify: decode the signature, pick the key it names, verify.
// Callers build msg with Manifest.Message; it is separate only so the
// captured real-OpenBao signatures (openbao_response_test.go) can be
// checked over the exact bytes they were made over.
func (ks KeySet) verifyMessage(msg []byte, signature string) error {
	keyVersion, sig, err := DecodeSignature(signature)
	if err != nil {
		return err
	}
	for _, k := range ks {
		if k.Version != keyVersion {
			continue
		}
		if len(k.Key) != ed25519.PublicKeySize || !ed25519.Verify(k.Key, msg, sig) {
			return ErrInvalidSignature
		}
		return nil
	}
	return fmt.Errorf("%w: v%d", ErrUnknownKeyVersion, keyVersion)
}

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
func (k Keyring) Verify(m LegacyManifest) error {
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
