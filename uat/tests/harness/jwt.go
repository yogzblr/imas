package harness

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DecodeSegment decodes a JWT's base64url payload segment into its
// claims. It verifies nothing.
func DecodeSegment(seg string) (map[string]any, error) {
	seg = strings.TrimSpace(seg)
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(seg, "="))
	if err != nil {
		return nil, fmt.Errorf("JWT segment is not base64url: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(b, &claims); err != nil {
		return nil, fmt.Errorf("JWT segment is not a JSON object: %w", err)
	}
	return claims, nil
}

// DecodeClaims returns a compact JWT's claims, unverified.
func DecodeClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a compact JWT")
	}
	return DecodeSegment(parts[1])
}

// ExpiresAt returns a JWT's exp claim.
func ExpiresAt(token string) (time.Time, error) {
	c, err := DecodeClaims(token)
	if err != nil {
		return time.Time{}, err
	}
	exp, ok := c["exp"].(float64)
	if !ok {
		return time.Time{}, errors.New("JWT has no numeric exp")
	}
	return time.Unix(int64(exp), 0), nil
}

// ClaimString returns a string claim, or "".
func ClaimString(c map[string]any, name string) string {
	s, _ := c[name].(string)
	return s
}

// TamperSignature returns token with its signature altered, so a
// verifier must refuse it while its header and claims stay valid.
func TamperSignature(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[2] == "" {
		return token + "x"
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) == 0 {
		return parts[0] + "." + parts[1] + ".AAAA"
	}
	sig[0] ^= 0xff
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	return strings.Join(parts, ".")
}

// ForgeEdDSA returns an EdDSA JWT with the given claims, signed by a key
// made up on the spot: well-formed, and trusted by nobody.
func ForgeEdDSA(claims map[string]any) (string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	h, err := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": "uat-forged"})
	if err != nil {
		return "", err
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	sig := ed25519.Sign(priv, []byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
