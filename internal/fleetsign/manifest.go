package fleetsign

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"golang.org/x/mod/semver"
)

// Manifest is one saas.fleet_versions row as farmer serves it to a sprout
// (GET /v1/sprout/update-manifest, design doc §2.6): the sprout package
// for one version, OS and arch, and fleetreleaser's signature over it.
//
// There is deliberately no URL. The sprout builds the download URL from
// the repository configured in the sprout itself plus FileName
// (requirement 20, §1.8), so nothing a farmer, a saas.fleet_versions
// writer or the bus can change decides where code is fetched from; the
// signed checksum decides what may be installed.
type Manifest struct {
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

// Field limits. Version sizes match saas.fleet_versions.version.
const (
	maxVersionLen  = 64
	maxOSArchLen   = 32
	maxFileNameLen = 255
	// maxManifestJSON bounds ParseManifest's input: every field at its
	// limit plus the signature and JSON syntax is well under 1 KiB.
	maxManifestJSON = 4 << 10
)

// Per-field allowlists. They are stricter than "no separator, no control
// character" on purpose: every field is used by the sprout to build a
// URL, a local path or a version comparison, so anything outside these
// sets is refused at the signer rather than discovered on a fleet.
var (
	reOSArch = regexp.MustCompile(`^[a-z0-9][a-z0-9_]*$`)
	// A single path component: no '/', '\\', '%', '?', '#', ':' or
	// whitespace, and it can't start with '.', so it is never "." or "..".
	reFileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]*$`)
	reSHA256   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// fields returns the signed fields in canonical order, with their JSON
// names. Message, Validate and ParseManifest all read this one list, so
// there is exactly one definition of what is signed.
func (m Manifest) fields() [6]struct{ name, value string } {
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
//	version|os|arch|file_name|checksum_sha256|min_sprout_version
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
func (m Manifest) Message() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	f := m.fields()
	parts := make([]string, len(f))
	for i, kv := range f {
		parts[i] = kv.value
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
func (m Manifest) Validate() error {
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

// ParseManifest decodes the JSON a sprout receives from farmer (§2.6)
// strictly: one JSON object, every value a string, the seven field names
// exactly as Manifest's JSON tags spell them (no case folding, unlike
// encoding/json), no duplicate, missing or unknown key, nothing after
// the object, at most 4 KiB. The fields are then validated (Validate).
//
// ParseManifest does not verify the signature; call Keyring.Verify on
// the result. An unknown key is refused rather than ignored so that no
// field can ride along unsigned and later be trusted by a newer reader.
func ParseManifest(data []byte) (Manifest, error) {
	if len(data) > maxManifestJSON {
		return Manifest{}, fmt.Errorf("%w: manifest is larger than %d bytes", ErrInvalidManifest, maxManifestJSON)
	}
	obj, err := parseFlatStringObject(data, 8)
	if err != nil {
		return Manifest{}, fmt.Errorf("%w: %w", ErrInvalidManifest, err)
	}
	var m Manifest
	dst := map[string]*string{
		"version": &m.Version, "os": &m.OS, "arch": &m.Arch, "file_name": &m.FileName,
		"checksum_sha256": &m.ChecksumSHA256, "min_sprout_version": &m.MinSproutVersion,
		"signature": &m.Signature,
	}
	for k, v := range obj {
		p, ok := dst[k]
		if !ok {
			return Manifest{}, fmt.Errorf("%w: unknown field %q", ErrInvalidManifest, k)
		}
		*p = v
	}
	for k := range dst {
		if _, ok := obj[k]; !ok {
			return Manifest{}, fmt.Errorf("%w: missing field %q", ErrInvalidManifest, k)
		}
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// parseFlatStringObject decodes data as exactly one JSON object whose
// values are all strings, refusing duplicate keys (encoding/json keeps
// the last one silently), more than maxKeys keys, and trailing data.
// Keys are compared byte for byte.
func parseFlatStringObject(data []byte, maxKeys int) (map[string]string, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("decoding JSON: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not a JSON object")
	}
	out := make(map[string]string)
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("decoding JSON: %w", err)
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errors.New("decoding JSON: object key is not a string")
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("duplicate key %q", key)
		}
		if len(out) == maxKeys {
			return nil, fmt.Errorf("more than %d keys", maxKeys)
		}
		tok, err = dec.Token()
		if err != nil {
			return nil, fmt.Errorf("decoding JSON: %w", err)
		}
		val, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("value of %q is not a string", key)
		}
		out[key] = val
	}
	if _, err := dec.Token(); err != nil { // the closing '}'
		return nil, fmt.Errorf("decoding JSON: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after JSON object")
	}
	return out, nil
}
