package fleetsign

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"

	"golang.org/x/mod/semver"
)

// Manifest is farmer's 200 response to GET /v1/sprout/update-manifest
// (the P22 wire contract): one release for one OS, arch and package
// type, with the release's checksums.txt and its detached signature
// relayed verbatim. Every value is a JSON string and these seven keys are
// the only ones.
//
// There is deliberately no URL, file name or checksum field. The sprout
// derives the package file name itself (ExpectedFileName), takes its
// SHA-256 from the signed checksums.txt (ArmoredKeyring.VerifyChecksums,
// ParseChecksums), and downloads from the repository configured in the
// sprout (requirement 20, §1.8). MinSproutVersion is unsigned (D19): it
// is farmer policy, enforced by the sprout.
type Manifest struct {
	Version          string `json:"version"`
	OS               string `json:"os"`
	Arch             string `json:"arch"`
	PackageType      string `json:"package_type"`
	MinSproutVersion string `json:"min_sprout_version"`
	// ChecksumsTxt is the release's checksums.txt, byte for byte.
	ChecksumsTxt string `json:"checksums_txt"`
	// ChecksumsSig is checksums.txt.sig in standard padded base64.
	ChecksumsSig string `json:"checksums_sig"`

	// sig is ChecksumsSig decoded, set by ParseManifest.
	sig []byte
}

// Signature returns the decoded checksums.txt.sig bytes ParseManifest
// read from ChecksumsSig. It is nil on a Manifest ParseManifest didn't
// return.
func (m Manifest) Signature() []byte { return m.sig }

// Field limits. Version sizes match saas.fleet_versions.version.
const (
	maxVersionLen  = 64
	maxOSArchLen   = 32
	maxFileNameLen = 255
	// MaxChecksumsTxt and MaxChecksumsSig bound checksums.txt and its
	// decoded signature (the wire contract).
	MaxChecksumsTxt = 128 << 10
	MaxChecksumsSig = 8 << 10
	// maxManifestJSON bounds ParseManifest's input: checksums.txt at its
	// limit, JSON-escaped, plus the base64 signature and the short fields.
	maxManifestJSON = 256 << 10
)

// Package types a Manifest can name: the sprout's own (platform.go in
// internal/ingredients/selfupdate).
const (
	PackageTypeDeb = "deb"
	PackageTypeRPM = "rpm"
	PackageTypeMSI = "msi"
)

// Per-field allowlists. They are stricter than "no separator, no control
// character" on purpose: every field is used by the sprout to build a
// URL, a local path or a version comparison, so anything outside these
// sets is refused rather than discovered on a fleet.
var (
	reOSArch = regexp.MustCompile(`^[a-z0-9][a-z0-9_]*$`)
	// A single path component: no '/', '\\', '%', '?', '#', ':' or
	// whitespace, and it can't start with '.', so it is never "." or "..".
	reFileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]*$`)
	reSHA256   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// manifestKeys is the wire contract's key set.
func (m *Manifest) manifestKeys() map[string]*string {
	return map[string]*string{
		"version": &m.Version, "os": &m.OS, "arch": &m.Arch, "package_type": &m.PackageType,
		"min_sprout_version": &m.MinSproutVersion, "checksums_txt": &m.ChecksumsTxt,
		"checksums_sig": &m.ChecksumsSig,
	}
}

// ParseManifest decodes the JSON a sprout receives from farmer strictly:
// one JSON object, every value a string, the seven keys exactly as
// Manifest's JSON tags spell them (no case folding, unlike
// encoding/json), no duplicate, missing or unknown key, nothing after the
// object, at most 256 KiB. It then validates the fields (Validate) and
// decodes the signature (Signature).
//
// ParseManifest does not verify anything cryptographically; the caller
// runs ArmoredKeyring.VerifyChecksums on ChecksumsTxt and Signature(). An
// unknown key (a file_name, a URL, a checksum) is refused rather than
// ignored, so nothing unsigned can ride along and later be trusted by a
// newer reader.
func ParseManifest(data []byte) (Manifest, error) {
	if len(data) > maxManifestJSON {
		return Manifest{}, fmt.Errorf("%w: manifest is larger than %d bytes", ErrInvalidManifest, maxManifestJSON)
	}
	var m Manifest
	dst := m.manifestKeys()
	obj, err := parseFlatStringObject(data, len(dst)+1)
	if err != nil {
		return Manifest{}, fmt.Errorf("%w: %w", ErrInvalidManifest, err)
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
	m.sig, _ = base64.StdEncoding.Strict().DecodeString(m.ChecksumsSig) // Validate decoded it
	return m, nil
}

// Validate checks every field:
//
//   - version and min_sprout_version are canonical semver with a leading
//     'v' and no build metadata ("v2.4.1", "v2.5.0-rc.1"), at most 64
//     characters, and min_sprout_version <= version;
//   - os and arch are lowercase [a-z0-9_], at most 32 characters;
//   - package_type is deb, rpm or msi;
//   - checksums_txt is 1 byte to MaxChecksumsTxt (ErrChecksumsTooLarge
//     above it);
//   - checksums_sig is standard padded base64 of 1 byte to
//     MaxChecksumsSig (ErrChecksumsTooLarge above it).
//
// It doesn't parse checksums.txt: that is done after the signature over
// it verifies (ParseChecksums).
func (m Manifest) Validate() error {
	for _, kv := range []struct{ name, value string }{
		{"version", m.Version}, {"min_sprout_version", m.MinSproutVersion},
	} {
		if err := checkVersion(kv.name, kv.value); err != nil {
			return err
		}
	}
	if semver.Compare(m.MinSproutVersion, m.Version) > 0 {
		return fmt.Errorf("%w: min_sprout_version %s is above version %s", ErrInvalidManifest, m.MinSproutVersion, m.Version)
	}
	for _, kv := range []struct{ name, value string }{{"os", m.OS}, {"arch", m.Arch}} {
		if err := checkOSArch(kv.name, kv.value); err != nil {
			return err
		}
	}
	switch m.PackageType {
	case PackageTypeDeb, PackageTypeRPM, PackageTypeMSI:
	default:
		return fmt.Errorf("%w: package_type %q is not deb, rpm or msi", ErrInvalidManifest, m.PackageType)
	}
	switch {
	case m.ChecksumsTxt == "":
		return fmt.Errorf("%w: checksums_txt is empty", ErrInvalidManifest)
	case len(m.ChecksumsTxt) > MaxChecksumsTxt:
		return fmt.Errorf("%w: checksums_txt is larger than %d bytes", ErrChecksumsTooLarge, MaxChecksumsTxt)
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(m.ChecksumsSig)
	switch {
	case err != nil:
		return fmt.Errorf("%w: checksums_sig is not standard padded base64", ErrInvalidManifest)
	case len(sig) == 0:
		return fmt.Errorf("%w: checksums_sig is empty", ErrInvalidManifest)
	case len(sig) > MaxChecksumsSig:
		return fmt.Errorf("%w: checksums_sig decodes to more than %d bytes", ErrChecksumsTooLarge, MaxChecksumsSig)
	}
	return nil
}

// checkVersion requires a canonical semver release tag: leading 'v', no
// build metadata, at most maxVersionLen characters.
func checkVersion(name, v string) error {
	if v == "" {
		return fmt.Errorf("%w: %s is empty", ErrInvalidManifest, name)
	}
	if len(v) > maxVersionLen {
		return fmt.Errorf("%w: %s is longer than %d characters", ErrInvalidManifest, name, maxVersionLen)
	}
	if !semver.IsValid(v) || semver.Canonical(v) != v {
		return fmt.Errorf("%w: %s %q is not a canonical semver version (vMAJOR.MINOR.PATCH[-PRERELEASE])", ErrInvalidManifest, name, v)
	}
	return nil
}

// checkOSArch requires lowercase [a-z0-9_] of at most maxOSArchLen.
func checkOSArch(name, v string) error {
	if len(v) > maxOSArchLen || !reOSArch.MatchString(v) {
		return fmt.Errorf("%w: %s %q is not lowercase [a-z0-9_] of at most %d characters", ErrInvalidManifest, name, v, maxOSArchLen)
	}
	return nil
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
