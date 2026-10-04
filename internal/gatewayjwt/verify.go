package gatewayjwt

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// PublicKeySource supplies the gateway key versions a gateway JWT may be
// verified against. *GatewaySigner satisfies it (PublicKeys, cached per
// transitPublicKeyCacheTTL); tests supply a static in-memory set.
type PublicKeySource interface {
	PublicKeys(ctx context.Context) ([]TransitKeyVersion, error)
}

// ErrInvalidToken wraps every verification failure VerifyGatewayJWT
// reports for the token itself (bad signature, unknown kid, expired,
// wrong issuer, missing claims), as opposed to a failure fetching keys.
var ErrInvalidToken = errors.New("gatewayjwt: invalid gateway JWT")

// VerifyGatewayJWT is the server-side counterpart of MintGatewayJWT: the
// same checks Envoy's jwt_authn applies (signature against the served
// key versions, "iss" == GatewayIssuer, "exp"), plus requiring the
// sub/tenant_id/sprout_id claims MintGatewayJWT always sets. It exists
// so a farmer handler behind Envoy can re-verify the forwarded token
// itself rather than trusting headers Envoy derived from it (e.g.
// x-imas-sprout-nkey) — farmer's API port is also reachable without
// passing through Envoy.
//
// The key set is built the same way JWKSHandler builds the served JWKS:
// "kid" is the Transit version and "alg" is pinned to EdDSA on each key,
// so jwx picks the algorithm from the key, never from the token header,
// and a token without a matching kid is rejected.
//
// A token that passes here is genuine and unexpired, not current: this
// package holds no sprout state, so it cannot tell that the sprout named
// was deleted, or replaced by a host with another NKey, after the token
// was minted. Every caller that grants access on a gateway JWT must also
// check the returned Subject against the sprout's current NKey and the
// tenant's revoked list, failing closed (internal/api's
// verifySproutGatewayJWT does, via pki.VerifyGatewaySubject; SEC.7c,
// security review 2026-10-b B3).
func VerifyGatewayJWT(ctx context.Context, keys PublicKeySource, token string) (GatewayClaims, error) {
	if keys == nil {
		return GatewayClaims{}, fmt.Errorf("gatewayjwt: nil key source")
	}
	versions, err := keys.PublicKeys(ctx)
	if err != nil {
		return GatewayClaims{}, fmt.Errorf("gatewayjwt: fetching verification keys: %w", err)
	}
	set, err := verificationKeySet(versions)
	if err != nil {
		return GatewayClaims{}, err
	}

	tok, err := jwt.Parse([]byte(token),
		jwt.WithKeySet(set),
		jwt.WithValidate(true),
		jwt.WithIssuer(GatewayIssuer),
		jwt.WithRequiredClaim(jwt.ExpirationKey),
		jwt.WithRequiredClaim(jwt.SubjectKey),
	)
	if err != nil {
		return GatewayClaims{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	tenantID, err := stringClaim(tok, "tenant_id")
	if err != nil {
		return GatewayClaims{}, err
	}
	sproutID, err := stringClaim(tok, "sprout_id")
	if err != nil {
		return GatewayClaims{}, err
	}

	return GatewayClaims{
		Subject:  tok.Subject(),
		TenantID: tenantID,
		SproutID: sproutID,
		Expiry:   tok.Expiration(),
	}, nil
}

// VerifyGatewayJWT is the method form, verifying against s's own
// Transit key versions.
func (s *GatewaySigner) VerifyGatewayJWT(ctx context.Context, token string) (GatewayClaims, error) {
	return VerifyGatewayJWT(ctx, s, token)
}

func verificationKeySet(versions []TransitKeyVersion) (jwk.Set, error) {
	if len(versions) == 0 {
		return nil, fmt.Errorf("gatewayjwt: no verification key versions available")
	}
	set := jwk.NewSet()
	for _, v := range versions {
		key, err := jwk.FromRaw(v.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("gatewayjwt: converting key version %d to JWK: %w", v.Version, err)
		}
		if err := key.Set(jwk.KeyIDKey, strconv.Itoa(v.Version)); err != nil {
			return nil, fmt.Errorf("gatewayjwt: setting kid on key version %d: %w", v.Version, err)
		}
		if err := key.Set(jwk.AlgorithmKey, jwa.EdDSA); err != nil {
			return nil, fmt.Errorf("gatewayjwt: setting alg on key version %d: %w", v.Version, err)
		}
		if err := set.AddKey(key); err != nil {
			return nil, fmt.Errorf("gatewayjwt: adding key version %d to set: %w", v.Version, err)
		}
	}
	return set, nil
}

func stringClaim(tok jwt.Token, name string) (string, error) {
	v, ok := tok.Get(name)
	if !ok {
		return "", fmt.Errorf("%w: missing %q claim", ErrInvalidToken, name)
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("%w: %q claim is not a non-empty string", ErrInvalidToken, name)
	}
	return s, nil
}
