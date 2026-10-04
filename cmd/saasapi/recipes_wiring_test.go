package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
	"github.com/yogzblr/imas/internal/saasapi"
)

const (
	wiringSecret   = "wiring-test-internal-secret"
	wiringIssuer   = "https://keycloak.test/realms/cloudxp"
	wiringAudience = "saasapi"
	wiringTenant   = "t_acme"
)

// wiringAuth installs a working two-layer AuthConfig backed by an
// in-process JWKS server, and returns a function minting a token for
// wiringTenant with the given realm roles.
func wiringAuth(t *testing.T) func(roles ...string) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.FromRaw(pub)
	if err != nil {
		t.Fatal(err)
	}
	_ = key.Set(jwk.KeyIDKey, "k1")
	_ = key.Set(jwk.AlgorithmKey, jwa.EdDSA.String())
	set := jwk.NewSet()
	_ = set.AddKey(key)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(srv.Close)

	cfg, err := saasapi.NewAuthConfig(context.Background(), wiringSecret, "", srv.URL, wiringIssuer, wiringAudience)
	if err != nil {
		t.Fatal(err)
	}
	saasapi.SetAuthConfig(cfg)
	t.Cleanup(func() { saasapi.SetAuthConfig(nil) })

	return func(roles ...string) string {
		tok, err := jwt.NewBuilder().Issuer(wiringIssuer).Audience([]string{wiringAudience}).
			IssuedAt(time.Now()).Expiration(time.Now().Add(time.Hour)).Subject("wiring-user").
			Claim("organization", map[string]any{"id": wiringTenant, "name": "acme"}).
			Claim("realm_access", map[string]any{"roles": roles}).Build()
		if err != nil {
			t.Fatal(err)
		}
		hdrs := jws.NewHeaders()
		_ = hdrs.Set(jws.KeyIDKey, "k1")
		signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA, priv, jws.WithProtectedHeaders(hdrs)))
		if err != nil {
			t.Fatal(err)
		}
		return string(signed)
	}
}

// clearRecipeEnv empties every variable LoadConfig reads for recipes.
func clearRecipeEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"SAASAPI_RECIPES_S3_ENDPOINT", "SAASAPI_RECIPES_S3_BUCKET", "SAASAPI_RECIPES_S3_ACCESS_KEY_ID",
		"SAASAPI_RECIPES_S3_SECRET_ACCESS_KEY_FILE", "SAASAPI_RECIPES_S3_USE_SSL",
		"SAASAPI_RECIPES_READ_ROLE", "SAASAPI_RECIPES_WRITE_ROLE", "SAASAPI_RECIPES_MAX_COUNT",
		"SAASAPI_RECIPES_MAX_TOTAL_BYTES", "SAASAPI_RECIPES_WRITE_RATE_LIMIT", "SAASAPI_RECIPES_WRITE_RATE_BURST",
		"IMAS_RECIPE_MAX_SOURCE_BYTES", "IMAS_RECIPE_MAX_RENDERED_BYTES", "IMAS_RECIPE_MAX_VALUE_BYTES",
		"IMAS_RECIPE_RENDER_TIMEOUT", "IMAS_RECIPE_MAX_RANGE_ITERATIONS",
	} {
		t.Setenv(k, "")
	}
}

// setRecipeEnv points the recipe settings at a fresh fake S3 bucket, with
// the secret key in a file, as the Helm chart does.
func setRecipeEnv(t *testing.T) {
	t.Helper()
	s3 := objectstoretest.NewServer(t).Config()
	keyFile := filepath.Join(t.TempDir(), "secret-access-key")
	if err := os.WriteFile(keyFile, []byte(s3.SecretAccessKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAASAPI_RECIPES_S3_ENDPOINT", s3.Endpoint)
	t.Setenv("SAASAPI_RECIPES_S3_BUCKET", s3.Bucket)
	t.Setenv("SAASAPI_RECIPES_S3_ACCESS_KEY_ID", s3.AccessKeyID)
	t.Setenv("SAASAPI_RECIPES_S3_SECRET_ACCESS_KEY_FILE", keyFile)
	t.Setenv("SAASAPI_RECIPES_S3_USE_SSL", "false")
}

// resetRecipes puts saasapi's recipe settings back to "off" after a test.
func resetRecipes(t *testing.T) {
	t.Cleanup(func() { _ = saasapi.ConfigureRecipes(saasapi.DefaultRecipeSettings(), nil) })
}

// tenantHandler builds the tenant API handler the way main does: startup
// recipe configuration, then the router behind RejectUncleanPaths (the
// expression main hands to its http.Server).
func tenantHandler(t *testing.T) http.Handler {
	t.Helper()
	cfg, err := saasapi.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if err := saasapi.ConfigureRecipes(cfg.Recipes, nil); err != nil {
		t.Fatalf("ConfigureRecipes: %v", err)
	}
	return saasapi.RejectUncleanPaths(newRouter(cfg))
}

// TestRecipeRoutesWired: through main's startup path (LoadConfig →
// saasapi.ConfigureRecipes → RejectUncleanPaths(newRouter)), recipe config
// in the environment makes the recipe routes live, and without it they
// answer 503. A PUT without a precondition is the probe: a live route
// answers 428 before it needs the database, an unconfigured one 503. An
// unclean recipe path is refused by the guard, never redirected.
func TestRecipeRoutesWired(t *testing.T) {
	resetRecipes(t)
	mint := wiringAuth(t)

	put := func(h http.Handler, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPut, path, strings.NewReader("steps: {}\n"))
		r.Header.Set(saasapi.InternalAuthHeader, wiringSecret)
		r.Header.Set("Authorization", "Bearer "+mint("imas-recipes-write"))
		r.Header.Set("Content-Type", "application/yaml")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	probe := func(t *testing.T) *httptest.ResponseRecorder {
		t.Helper()
		return put(tenantHandler(t), "/v1/tenants/"+wiringTenant+"/recipes/web.hello")
	}
	code := func(w *httptest.ResponseRecorder) string {
		var body struct{ Error string }
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return body.Error
	}

	t.Run("configured", func(t *testing.T) {
		clearRecipeEnv(t)
		setRecipeEnv(t)
		w := probe(t)
		if w.Code != http.StatusPreconditionRequired || code(w) != "precondition_required" {
			t.Fatalf("PUT with recipes configured = %d %s, want 428 precondition_required (the route is live)", w.Code, w.Body.String())
		}
		// Behind RejectUncleanPaths: a dot-segment path is a 400, not a
		// 307 on to PUT /v1/tenants/{id}.
		w = put(tenantHandler(t), "/v1/tenants/"+wiringTenant+"/recipes/..")
		if w.Code != http.StatusBadRequest || code(w) != "invalid_request" || w.Header().Get("Location") != "" {
			t.Fatalf("PUT .../recipes/.. = %d %s (Location %q), want 400 invalid_request", w.Code, w.Body.String(), w.Header().Get("Location"))
		}
	})
	t.Run("unconfigured", func(t *testing.T) {
		clearRecipeEnv(t)
		w := probe(t)
		if w.Code != http.StatusServiceUnavailable || code(w) != "recipes_not_configured" {
			t.Fatalf("PUT without recipe config = %d %s, want 503 recipes_not_configured", w.Code, w.Body.String())
		}
	})
}

// TestRecipeConfigInvalidStopsStartup: recipe settings that LoadConfig
// accepts but that can't be used fail ConfigureRecipes, the step main
// treats as fatal, so saasapi refuses to start instead of serving 503.
func TestRecipeConfigInvalidStopsStartup(t *testing.T) {
	resetRecipes(t)
	for name, set := range map[string]func(t *testing.T){
		"missing secret key file": func(t *testing.T) {
			t.Setenv("SAASAPI_RECIPES_S3_SECRET_ACCESS_KEY_FILE", filepath.Join(t.TempDir(), "absent"))
		},
		"render limit out of range": func(t *testing.T) {
			t.Setenv("IMAS_RECIPE_MAX_SOURCE_BYTES", "1099511627776")
		},
	} {
		t.Run(name, func(t *testing.T) {
			clearRecipeEnv(t)
			setRecipeEnv(t)
			set(t)
			cfg, err := saasapi.LoadConfig()
			if err != nil {
				t.Fatalf("LoadConfig refused it first (%v); this test wants the case only ConfigureRecipes catches", err)
			}
			if err := saasapi.ConfigureRecipes(cfg.Recipes, nil); err == nil {
				t.Fatal("ConfigureRecipes accepted unusable recipe settings")
			}
		})
	}
}
