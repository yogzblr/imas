package fleetsign

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// MarshalJWKS renders ks as a standard JWKS document (RFC 7517), in the
// same shape internal/gatewayjwt/jwks.go serves the gateway key in: one
// OKP/Ed25519 JWK per key version, kid = the Transit key version,
// use = "sig", alg = "EdDSA". Nothing in production serves or pins it
// any more (see the package comment); a sprout trusts its Keyring.
func (ks KeySet) MarshalJWKS() ([]byte, error) {
	if len(ks) == 0 {
		return nil, ErrNoKeys
	}
	set := jwk.NewSet()
	for _, k := range ks {
		key, err := jwk.FromRaw(k.Key)
		if err != nil {
			return nil, fmt.Errorf("fleetsign: converting key version %d to JWK: %w", k.Version, err)
		}
		for name, value := range map[string]any{
			jwk.KeyIDKey:     strconv.Itoa(k.Version),
			jwk.KeyUsageKey:  "sig",
			jwk.AlgorithmKey: jwa.EdDSA.String(),
		} {
			if err := key.Set(name, value); err != nil {
				return nil, fmt.Errorf("fleetsign: setting %s on JWK version %d: %w", name, k.Version, err)
			}
		}
		if err := set.AddKey(key); err != nil {
			return nil, fmt.Errorf("fleetsign: adding JWK version %d to set: %w", k.Version, err)
		}
	}
	return json.Marshal(set)
}

// ParseJWKS parses MarshalJWKS's format back into a KeySet. It is strict,
// since its main caller is a sprout pinning the key it will trust for
// every future binary it runs: every key must be an OKP/Ed25519 *public*
// key (a JWK carrying a private "d" is rejected, not quietly reduced to
// its public half), kid must be a positive decimal key version, and use
// and alg, when present, must be "sig" and "EdDSA".
func ParseJWKS(data []byte) (KeySet, error) {
	set, err := jwk.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("fleetsign: parsing JWKS: %w", err)
	}
	keys := make([]PublicKey, 0, set.Len())
	for i := 0; i < set.Len(); i++ {
		key, _ := set.Key(i)
		if key.KeyType() != jwa.OKP {
			return nil, fmt.Errorf("fleetsign: JWK %d has kty %q, want OKP", i, key.KeyType())
		}
		if u := key.KeyUsage(); u != "" && u != "sig" {
			return nil, fmt.Errorf("fleetsign: JWK %d has use %q, want sig", i, u)
		}
		if a := key.Algorithm(); a != nil && a.String() != "" && a.String() != jwa.EdDSA.String() {
			return nil, fmt.Errorf("fleetsign: JWK %d has alg %q, want EdDSA", i, a)
		}
		var raw any
		if err := key.Raw(&raw); err != nil {
			return nil, fmt.Errorf("fleetsign: JWK %d: %w", i, err)
		}
		pub, ok := raw.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("fleetsign: JWK %d is %T, want an Ed25519 public key", i, raw)
		}
		version, err := strconv.Atoi(key.KeyID())
		if err != nil || version < 1 || key.KeyID() != strconv.Itoa(version) {
			return nil, fmt.Errorf("fleetsign: JWK %d has kid %q, want a positive key version", i, key.KeyID())
		}
		keys = append(keys, PublicKey{Version: version, Key: pub})
	}
	return NewKeySet(keys)
}
