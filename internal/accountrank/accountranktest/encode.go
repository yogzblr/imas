// Package accountranktest signs Account JWTs with an issued-at of the
// caller's choosing, which jwt/v2's Encode never produces (it stamps the
// current time): the future-dated JWT a compromised bus node could plant
// (security review 2026-10, L16). Tests only.
package accountranktest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// Year3000 is 3000-01-01T00:00:00Z as a Unix time.
const Year3000 int64 = 32503680000

// EncodeAt is ac.Encode(signer) with the issued-at replaced by iat,
// signed again by signer, so the result decodes and verifies like any
// other Account JWT.
func EncodeAt(ac *jwt.AccountClaims, signer nkeys.KeyPair, iat int64) (string, error) {
	signed, err := ac.Encode(signer)
	if err != nil {
		return "", err
	}
	parts := strings.Split(signed, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("accountranktest: encoded JWT has %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return "", err
	}
	claims["iat"] = iat
	raw, err = json.Marshal(claims)
	if err != nil {
		return "", err
	}
	toSign := parts[0] + "." + base64.RawURLEncoding.EncodeToString(raw)
	sig, err := signer.Sign([]byte(toSign))
	if err != nil {
		return "", err
	}
	return toSign + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
