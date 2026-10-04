package saasapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	testInternalAuthSecretCurrent  = "test-internal-secret-current"
	testInternalAuthSecretPrevious = "test-internal-secret-previous"
	testJWTIssuer                  = "https://keycloak.test/realms/cloudxp"
	testJWTAudience                = "saasapi"
)

// testAuthEnv is an in-process stand-in for Keycloak: an httptest JWKS
// server backed by a freshly generated Ed25519 key, plus a helper to
// mint end-user JWTs against it. newTestAuthEnv installs the resulting
// AuthConfig as the package's active one (see auth_config.go) for the
// duration of the test, and tears it down in t.Cleanup.
type testAuthEnv struct {
	t    *testing.T
	priv ed25519.PrivateKey
	kid  string
}

// newTestAuthEnv sets up a full working two-layer auth environment: a
// local JWKS server and an AuthConfig pointed at it with known secret
// values (testInternalAuthSecretCurrent/Previous). Most tests only need
// this plus mintTokenForTenant.
func newTestAuthEnv(t *testing.T) *testAuthEnv {
	t.Helper()
	return newTestAuthEnvWithSecrets(t, testInternalAuthSecretCurrent, testInternalAuthSecretPrevious)
}

// newTestAuthEnvWithSecrets is newTestAuthEnv with explicit secret
// values, for tests exercising the rotation window itself — in
// particular, an empty previous value, which NewAuthConfig treats as
// "only current is accepted".
func newTestAuthEnvWithSecrets(t *testing.T, secretCurrent, secretPrevious string) *testAuthEnv {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating test signing key: %v", err)
	}

	const kid = "test-key-1"
	key, err := jwk.FromRaw(pub)
	if err != nil {
		t.Fatalf("building JWK from test public key: %v", err)
	}
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatalf("setting kid: %v", err)
	}
	if err := key.Set(jwk.KeyUsageKey, "sig"); err != nil {
		t.Fatalf("setting use: %v", err)
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.EdDSA.String()); err != nil {
		t.Fatalf("setting alg: %v", err)
	}

	set := jwk.NewSet()
	if err := set.AddKey(key); err != nil {
		t.Fatalf("adding key to test JWKS: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(set); err != nil {
			t.Errorf("writing test JWKS response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)

	authCfg, err := NewAuthConfig(context.Background(),
		secretCurrent, secretPrevious,
		srv.URL, testJWTIssuer, testJWTAudience)
	if err != nil {
		t.Fatalf("building test AuthConfig: %v", err)
	}
	SetAuthConfig(authCfg)
	t.Cleanup(func() { SetAuthConfig(nil) })

	return &testAuthEnv{t: t, priv: priv, kid: kid}
}

// tokenOpts customizes mintToken's output for the negative-path cases
// the combined-behavior test matrix needs. Zero values mean "use the
// otherwise-valid default".
type tokenOpts struct {
	issuer    string
	audience  string
	expiresAt time.Time
	org       *Organization // nil: omit the organization claim entirely
	badOrg    bool          // true: include an organization claim with no "id" field
	// realmRoles and clientRoles become realm_access.roles and
	// resource_access.<testJWTAudience>.roles; nil omits the claim.
	realmRoles  []string
	clientRoles []string
	subject     string // default "test-user"
}

func (e *testAuthEnv) mintToken(opts tokenOpts) string {
	e.t.Helper()

	issuer := opts.issuer
	if issuer == "" {
		issuer = testJWTIssuer
	}
	audience := opts.audience
	if audience == "" {
		audience = testJWTAudience
	}
	expiresAt := opts.expiresAt
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(time.Hour)
	}

	subject := opts.subject
	if subject == "" {
		subject = "test-user"
	}
	builder := jwt.NewBuilder().
		Issuer(issuer).
		Audience([]string{audience}).
		IssuedAt(time.Now()).
		Expiration(expiresAt).
		Subject(subject)
	if opts.realmRoles != nil {
		builder = builder.Claim("realm_access", map[string]any{"roles": opts.realmRoles})
	}
	if opts.clientRoles != nil {
		builder = builder.Claim("resource_access", map[string]any{testJWTAudience: map[string]any{"roles": opts.clientRoles}})
	}

	switch {
	case opts.org != nil:
		builder = builder.Claim("organization", opts.org)
	case opts.badOrg:
		builder = builder.Claim("organization", map[string]any{"name": "acme-corp"})
	}

	tok, err := builder.Build()
	if err != nil {
		e.t.Fatalf("building test token: %v", err)
	}

	hdrs := jws.NewHeaders()
	if err := hdrs.Set(jws.KeyIDKey, e.kid); err != nil {
		e.t.Fatalf("setting kid header: %v", err)
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA, e.priv, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		e.t.Fatalf("signing test token: %v", err)
	}
	return string(signed)
}

// mintTokenForTenant returns an otherwise-valid token whose
// organization.id equals tenantID — the common case used by every test
// that isn't specifically exercising a failure path.
func (e *testAuthEnv) mintTokenForTenant(tenantID string) string {
	return e.mintToken(tokenOpts{org: &Organization{ID: tenantID, Name: "acme-corp", Attributes: map[string]any{"tier": "enterprise"}}})
}

// setAuthHeaders sets both layers' headers on r: the current internal
// secret and a bearer token whose organization.id is tenantID.
func (e *testAuthEnv) setAuthHeaders(r *http.Request, tenantID string) {
	r.Header.Set(InternalAuthHeader, testInternalAuthSecretCurrent)
	r.Header.Set("Authorization", "Bearer "+e.mintTokenForTenant(tenantID))
}
