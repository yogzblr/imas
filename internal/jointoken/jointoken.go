// Package jointoken is the one definition of a sprout join token
// (enrollment key) and of the tenant key fingerprint it carries
// (security review 2026-10, L24; docs/briefs/U-hardening.md, U2).
//
// FLAG FOR SECURITY REVIEW. A join token is
//
//	{key_id}.{secret}.{tenant_key_fingerprint}
//
// key_id is the public lookup half and secret the bearer half
// (imas-machine-manager-api-design.md §3.1). tenant_key_fingerprint is the
// lowercase hex SHA-256 of the tenant's current NaCl box public key (the
// 32 raw bytes, not their base64), as farmer held it when the SaaS API
// minted the token. A sprout compares it with the tenant_x25519_pub its
// first enrollment response carries before it seals anything to that key
// or pins it, so a DMZ Envoy that substitutes its own key at enrollment
// is caught. A token minted before the fingerprint existed is
// {key_id}.{secret}, and still parses (Fingerprint empty); whether a
// sprout enrolls with one is its "enrollpinrequired" setting.
//
// The fingerprint is not a secret: it is a hash of a public key.
package jointoken

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// FingerprintLen is the length of a tenant key fingerprint: 64 lowercase
// hex characters, a SHA-256.
const FingerprintLen = 2 * sha256.Size

// ErrMalformed is a token that isn't {key_id}.{secret} or
// {key_id}.{secret}.{fingerprint}.
var ErrMalformed = errors.New("jointoken: not a {key_id}.{secret}[.{tenant_key_fingerprint}] join token")

// Token is a parsed join token.
type Token struct {
	KeyID  string
	Secret string
	// Fingerprint is the tenant key fingerprint, or "" for a token minted
	// without one.
	Fingerprint string
}

// Credential is the {key_id}.{secret} part farmer redeems.
func (t Token) Credential() string { return t.KeyID + "." + t.Secret }

// String is the token as the SaaS API hands it out.
func (t Token) String() string {
	if t.Fingerprint == "" {
		return t.Credential()
	}
	return t.Credential() + "." + t.Fingerprint
}

// Parse parses s. The key ID is everything before the first '.', and
// must be non-empty. When what follows has a further '.' and the last
// part is a well-formed fingerprint, that is the fingerprint and the rest
// is the secret; otherwise everything after the first '.' is the secret,
// exactly as tokens were split before fingerprints existed. The secret
// must be non-empty. A token never contains whitespace.
func Parse(s string) (Token, error) {
	if s == "" || strings.ContainsAny(s, " \t\r\n") {
		return Token{}, ErrMalformed
	}
	keyID, rest, ok := strings.Cut(s, ".")
	if !ok || keyID == "" || rest == "" {
		return Token{}, ErrMalformed
	}
	if i := strings.LastIndexByte(rest, '.'); i >= 0 && ValidFingerprint(rest[i+1:]) {
		if i == 0 {
			return Token{}, ErrMalformed
		}
		return Token{KeyID: keyID, Secret: rest[:i], Fingerprint: rest[i+1:]}, nil
	}
	return Token{KeyID: keyID, Secret: rest}, nil
}

// Format builds the token for keyID and secret carrying fingerprint,
// which must be a valid fingerprint: the SaaS API never mints a token
// without one.
func Format(keyID, secret, fingerprint string) (string, error) {
	if keyID == "" || secret == "" || strings.Contains(keyID, ".") || strings.Contains(secret, ".") {
		return "", ErrMalformed
	}
	if !ValidFingerprint(fingerprint) {
		return "", fmt.Errorf("jointoken: invalid tenant key fingerprint %q", fingerprint)
	}
	return Token{KeyID: keyID, Secret: secret, Fingerprint: fingerprint}.String(), nil
}

// ValidFingerprint reports whether s is FingerprintLen lowercase hex
// characters.
func ValidFingerprint(s string) bool {
	if len(s) != FingerprintLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Fingerprint is the fingerprint of a tenant box public key given as its
// 32 raw bytes.
func Fingerprint(pub *[32]byte) string {
	sum := sha256.Sum256(pub[:])
	return hex.EncodeToString(sum[:])
}

// FingerprintB64 is the fingerprint of a tenant box public key given in
// standard base64, as tenant_x25519_pub carries it. Anything that isn't
// 32 bytes of standard base64 is an error.
func FingerprintB64(pub string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pub))
	if err != nil || len(raw) != 32 {
		return "", errors.New("jointoken: tenant key is not a base64 32-byte X25519 public key")
	}
	return Fingerprint((*[32]byte)(raw)), nil
}
