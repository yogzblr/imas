package saasapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Organization is the confirmed shape of a Keycloak-issued end-user JWT's
// "organization" claim (see NewAuthConfig's doc comment). organization.id
// is the cloud platform's "customer_id" — the same concept as tenant_id everywhere
// else in this codebase (the {tenant_id} path parameter, internal/pki's
// and internal/props's tenantID variables). There is deliberately no
// separate CustomerID field: match the path's {tenant_id} directly
// against ID.
type Organization struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

type organizationContextKey struct{}

// OrganizationFromContext returns the caller's organization claim, as
// parsed by Auth from the request's bearer token, and whether one was
// present. Auth only populates this when the claim parsed successfully
// (see middleware.go) — a handler must still check ok before using it.
func OrganizationFromContext(ctx context.Context) (Organization, bool) {
	org, ok := ctx.Value(organizationContextKey{}).(Organization)
	return org, ok
}

func withOrganization(ctx context.Context, org Organization) context.Context {
	return context.WithValue(ctx, organizationContextKey{}, org)
}

// parseOrganizationClaim extracts and decodes tok's "organization"
// claim into the confirmed Organization shape. jwx decodes unknown
// claims as generic JSON values (typically map[string]any), so this
// round-trips through encoding/json rather than a direct type
// assertion. An absent claim, or one that doesn't decode into
// Organization (or decodes with an empty id), is an error — Auth treats
// that as a defensive 403, never a panic or a silent pass.
func parseOrganizationClaim(tok jwt.Token) (Organization, error) {
	raw, ok := tok.Get("organization")
	if !ok {
		return Organization{}, fmt.Errorf("organization claim absent")
	}
	buf, err := json.Marshal(raw)
	if err != nil {
		return Organization{}, fmt.Errorf("re-marshaling organization claim: %w", err)
	}
	var org Organization
	if err := json.Unmarshal(buf, &org); err != nil {
		return Organization{}, fmt.Errorf("decoding organization claim: %w", err)
	}
	if org.ID == "" {
		return Organization{}, fmt.Errorf("organization claim has empty id")
	}
	return org, nil
}

// InternalAuthHeader is the header the BFF sets its pre-shared service
// secret on (Auth's layer 1). Named distinctly from Authorization, which
// carries the end-user's own Keycloak JWT (layer 2) — the two are
// independent credentials checked independently.
const InternalAuthHeader = "X-Internal-Auth"

// AuthConfig holds Auth's runtime dependencies: the shared service
// secret(s) for layer 1, and the JWKS/issuer/audience needed to verify
// layer 2's Keycloak-issued end-user JWTs. Build one with NewAuthConfig
// and install it once at startup with SetAuthConfig — the same
// read-once-at-startup pattern as the rest of this package's config (see
// config.go), not polled or hot-reloaded in-process.
type AuthConfig struct {
	secretCurrent  []byte
	secretPrevious []byte
	hasPrevious    bool

	jwksURL  string
	jwkCache *jwk.Cache
	issuer   string
	audience string
}

// NewAuthConfig builds an AuthConfig. ctx bounds the lifetime of the
// JWKS cache's background refresh goroutine (see jwk.NewCache) — pass a
// context that lives for the process's lifetime, not a per-request one.
//
// secretCurrent is required. secretPrevious may be empty, meaning only
// secretCurrent is accepted; a non-empty value is accepted as an
// equally-valid alternative for the duration of a secret-rotation
// window (see middleware.go's Auth doc comment for why two values exist
// at all).
//
// jwksURL, issuer, and audience configure verification of the Keycloak-
// issued end-user JWT the BFF forwards on Authorization (layer 2).
func NewAuthConfig(ctx context.Context, secretCurrent, secretPrevious, jwksURL, issuer, audience string) (*AuthConfig, error) {
	if secretCurrent == "" {
		return nil, fmt.Errorf("saasapi: INTERNAL_AUTH_SECRET_CURRENT must not be empty")
	}
	if jwksURL == "" {
		return nil, fmt.Errorf("saasapi: Keycloak JWKS URL must not be empty")
	}
	if issuer == "" {
		return nil, fmt.Errorf("saasapi: JWT issuer must not be empty")
	}
	if audience == "" {
		return nil, fmt.Errorf("saasapi: JWT audience must not be empty")
	}

	cache := jwk.NewCache(ctx)
	if err := cache.Register(jwksURL); err != nil {
		return nil, fmt.Errorf("saasapi: registering JWKS URL %q: %w", jwksURL, err)
	}

	cfg := &AuthConfig{
		secretCurrent: []byte(secretCurrent),
		jwksURL:       jwksURL,
		jwkCache:      cache,
		issuer:        issuer,
		audience:      audience,
	}
	if secretPrevious != "" {
		cfg.secretPrevious = []byte(secretPrevious)
		cfg.hasPrevious = true
	}
	return cfg, nil
}

// validInternalSecret reports whether provided matches secretCurrent or
// (if configured) secretPrevious, using a constant-time comparison
// either way so a mismatch can't be timed to learn how many leading
// bytes were correct.
func (c *AuthConfig) validInternalSecret(provided string) bool {
	if provided == "" {
		return false
	}
	pb := []byte(provided)
	if constantTimeEqual(pb, c.secretCurrent) {
		return true
	}
	if c.hasPrevious && constantTimeEqual(pb, c.secretPrevious) {
		return true
	}
	return false
}

// constantTimeEqual compares a and b in constant time for equal-length
// inputs. Comparing lengths first (as crypto/hmac.Equal also does)
// leaks only the length of the secret, never its content — the length
// of a shared secret isn't itself sensitive.
func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// verifyBearerToken fetches the current JWKS (via the auto-refreshing
// cache) and parses+verifies raw against it, checking signature, issuer,
// audience, and expiry in one call.
func (c *AuthConfig) verifyBearerToken(ctx context.Context, raw string) (jwt.Token, error) {
	keySet, err := c.jwkCache.Get(ctx, c.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}

	tok, err := jwt.Parse([]byte(raw),
		jwt.WithKeySet(keySet),
		jwt.WithIssuer(c.issuer),
		jwt.WithAudience(c.audience),
	)
	if err != nil {
		return nil, fmt.Errorf("verifying JWT: %w", err)
	}
	return tok, nil
}

// authCfg is the package-level AuthConfig Auth uses, installed once at
// startup via SetAuthConfig — the same injection pattern as db.go's
// SetDB.
var authCfg *AuthConfig

// SetAuthConfig installs the AuthConfig Auth uses. Call once at startup,
// after NewAuthConfig.
func SetAuthConfig(c *AuthConfig) { authCfg = c }
