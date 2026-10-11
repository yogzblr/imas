// Package fleetsign is the sprout release trust root (signing design D9,
// D12, D19, D20, D21; P22): the update manifest farmer serves a sprout
// (Manifest, GET /v1/sprout/update-manifest), and the sprout's
// verification of it against the release GPG keyring shipped in its
// package (gpg.go).
//
// A release publishes checksums.txt (one "<sha256>  <file name>" line per
// release file) and checksums.txt.sig, a detached OpenPGP signature over
// its exact bytes made with the release key. Farmer relays both verbatim;
// the sprout is the only verifier (D20). It checks the signature against
// the keys in its own keyring file (LoadArmoredKeyring), parses the file
// strictly (ParseChecksums), derives the package file name itself
// (ExpectedFileName) and takes the expected SHA-256 from that one line.
// Nothing farmer sends names a URL or a file name: the sprout downloads
// from the repository configured in the sprout itself (requirement 20).
//
// FLAG FOR SECURITY REVIEW. This package contains no signing code: the
// release key signs checksums.txt in the release workflow, never here.
// TestNoSigningCodeInPackage keeps the shape honest.
//
// legacy.go and obtransit.go hold the pre-P22 Ed25519 / OpenBao Transit
// manifest signature, kept only until P22 slice 2 moves farmer, saasapi
// and natsapi off it.
package fleetsign

import "errors"

// The one-step job farmer sends a sprout for a self_update action: the
// sprout's selfupdate ingredient (internal/ingredients/selfupdate), method
// apply, with the target version as its only property read. Shared here
// so farmer doesn't import the ingredient package to name it.
const (
	SelfUpdateIngredient   = "selfupdate"
	SelfUpdateMethod       = "apply"
	PropVersion            = "version"
	PropChecksumSHA256     = "checksum_sha256"
	PropSignature          = "signature"
	SelfUpdateStepIDPrefix = "selfupdate-"
)

var (
	// ErrInvalidManifest: the manifest isn't well formed (ParseManifest),
	// or a field can't name a release (ExpectedFileName).
	ErrInvalidManifest = errors.New("fleetsign: invalid manifest fields")
	// ErrNoKeys: the keyring holds no usable key.
	ErrNoKeys = errors.New("fleetsign: no fleet signing keys")
	// ErrBadSignature: checksums.txt.sig is empty, malformed, or doesn't
	// verify over the exact checksums.txt bytes against any key in the
	// keyring, or the signing key is revoked.
	ErrBadSignature = errors.New("fleetsign: checksums.txt signature does not verify against the fleet signing keyring")
	// ErrBadChecksums: checksums.txt is empty or has a malformed line, an
	// uppercase hash, a path in a file name, or a duplicate file name.
	ErrBadChecksums = errors.New("fleetsign: malformed checksums.txt")
	// ErrNotInChecksums: checksums.txt has no line for the file name the
	// sprout derived.
	ErrNotInChecksums = errors.New("fleetsign: package file is not listed in checksums.txt")
	// ErrChecksumsTooLarge: checksums.txt is over MaxChecksumsTxt, or its
	// signature over MaxChecksumsSig.
	ErrChecksumsTooLarge = errors.New("fleetsign: checksums.txt or its signature is too large")
)
