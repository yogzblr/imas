package gatewayjwt

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// GatewayIssuer is the "iss" claim every gateway JWT carries, and the
// value Envoy's jwt_authn provider config (deploy/envoy/envoy.yaml) must
// have as its issuer for that provider. Fixed and platform-wide — see
// the package doc's "Two corrections" on why this is never a tenant
// Account's own identifier.
const GatewayIssuer = "imas-gateway"

// GatewayClaims is the minimal claim set MintGatewayJWT signs. Subject is
// the sprout's NKey public key — the same identity the NATS User JWT
// names — so a caller holding both tokens can trivially confirm they
// describe the same sprout.
type GatewayClaims struct {
	Subject  string // nkey_pub
	TenantID string
	SproutID string
	Expiry   time.Time
}

// MintGatewayJWT builds and signs a standard alg:EdDSA JWS over claims,
// using signer's current Transit key version (stamped into the JWS "kid"
// header so JWKS rotation overlap — signer.PublicKeys serving both an
// outgoing and incoming version — resolves to the right key on verify).
// No ed25519.PrivateKey exists in this process at any point; the actual
// signature is produced by signer.Sign, which calls out to Transit.
func MintGatewayJWT(ctx context.Context, signer *GatewaySigner, claims GatewayClaims) (string, error) {
	if signer == nil {
		return "", fmt.Errorf("gatewayjwt: nil signer")
	}
	if claims.Subject == "" {
		return "", fmt.Errorf("gatewayjwt: empty subject")
	}

	current, err := signer.currentSigningKey(ctx)
	if err != nil {
		return "", fmt.Errorf("gatewayjwt: resolving current signing key: %w", err)
	}

	now := time.Now().UTC()
	tok, err := jwt.NewBuilder().
		Subject(claims.Subject).
		Issuer(GatewayIssuer).
		IssuedAt(now).
		Expiration(claims.Expiry).
		Claim("tenant_id", claims.TenantID).
		Claim("sprout_id", claims.SproutID).
		Build()
	if err != nil {
		return "", fmt.Errorf("gatewayjwt: building claims: %w", err)
	}

	hdrs := jws.NewHeaders()
	if err := hdrs.Set(jws.KeyIDKey, strconv.Itoa(current.Version)); err != nil {
		return "", fmt.Errorf("gatewayjwt: setting kid header: %w", err)
	}
	if err := hdrs.Set(jws.TypeKey, "JWT"); err != nil {
		return "", fmt.Errorf("gatewayjwt: setting typ header: %w", err)
	}

	adapter := &cryptoSignerAdapter{ctx: ctx, signer: signer, pub: current.PublicKey}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA, adapter, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return "", fmt.Errorf("gatewayjwt: signing: %w", err)
	}
	return string(signed), nil
}

// MintGatewayJWT is the method form internal/pki's minting call sites
// depend on (see enroll.go's gatewayJWTMinter interface) — a thin
// wrapper so callers hold just a *GatewaySigner, not a signer plus a
// free function.
func (s *GatewaySigner) MintGatewayJWT(ctx context.Context, claims GatewayClaims) (string, error) {
	return MintGatewayJWT(ctx, s, claims)
}
