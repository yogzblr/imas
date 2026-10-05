package saasapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/yogzblr/imas/internal/cook"
)

func clearRecipeEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"SAASAPI_RECIPES_S3_ENDPOINT", "SAASAPI_RECIPES_S3_BUCKET", "SAASAPI_RECIPES_S3_ACCESS_KEY_ID",
		"SAASAPI_RECIPES_S3_SECRET_ACCESS_KEY_FILE", "SAASAPI_RECIPES_S3_USE_SSL", "SAASAPI_RECIPES_READ_ROLE",
		"SAASAPI_RECIPES_WRITE_ROLE", "SAASAPI_RECIPES_MAX_COUNT", "SAASAPI_RECIPES_MAX_TOTAL_BYTES",
		"SAASAPI_RECIPES_WRITE_RATE_LIMIT", "SAASAPI_RECIPES_WRITE_RATE_BURST", "SAASAPI_RECIPES_CREDENTIAL_CHECK",
		"SAASAPI_RECIPES_JOB_BUCKET", "SAASAPI_RECIPES_PLATFORM_RECIPE_DIR",
		"IMAS_RECIPE_MAX_SOURCE_BYTES", "IMAS_RECIPE_MAX_RENDERED_BYTES", "IMAS_RECIPE_MAX_VALUE_BYTES",
		"IMAS_RECIPE_RENDER_TIMEOUT", "IMAS_RECIPE_MAX_RANGE_ITERATIONS",
	} {
		t.Setenv(k, "")
	}
}

func TestLoadRecipeSettingsDefaults(t *testing.T) {
	clearRecipeEnv(t)
	s := DefaultRecipeSettings()
	if err := loadRecipeSettings(&s); err != nil {
		t.Fatal(err)
	}
	if s.Endpoint != "" || !s.UseSSL || s.ReadRole != "imas-recipes-read" || s.WriteRole != "imas-recipes-write" ||
		s.MaxCount != 500 || s.MaxTotalBytes != 20<<20 || s.WriteRateLimit != 1 || s.WriteRateBurst != 10 ||
		s.RenderLimits != (cook.RenderLimits{}) || !s.CredentialCheck || s.JobBucket != "" || s.PlatformRecipeDir != "/srv/imas/recipes/prod" {
		t.Fatalf("defaults %+v", s)
	}
}

func TestLoadRecipeSettingsFromEnv(t *testing.T) {
	clearRecipeEnv(t)
	for k, v := range map[string]string{
		"SAASAPI_RECIPES_S3_ENDPOINT":               "minio:9000",
		"SAASAPI_RECIPES_S3_BUCKET":                 "recipes",
		"SAASAPI_RECIPES_S3_ACCESS_KEY_ID":          "saasapi",
		"SAASAPI_RECIPES_S3_SECRET_ACCESS_KEY_FILE": "/var/run/secrets/key",
		"SAASAPI_RECIPES_S3_USE_SSL":                "false",
		"SAASAPI_RECIPES_CREDENTIAL_CHECK":          "false",
		"SAASAPI_RECIPES_JOB_BUCKET":                "jobs",
		"SAASAPI_RECIPES_PLATFORM_RECIPE_DIR":       "/srv/recipes",
		"SAASAPI_RECIPES_READ_ROLE":                 "r",
		"SAASAPI_RECIPES_WRITE_ROLE":                "w",
		"SAASAPI_RECIPES_MAX_COUNT":                 "10",
		"SAASAPI_RECIPES_MAX_TOTAL_BYTES":           "1000",
		"SAASAPI_RECIPES_WRITE_RATE_LIMIT":          "0.5",
		"SAASAPI_RECIPES_WRITE_RATE_BURST":          "3",
		"IMAS_RECIPE_MAX_SOURCE_BYTES":              "1024",
		"IMAS_RECIPE_RENDER_TIMEOUT":                "500ms",
	} {
		t.Setenv(k, v)
	}
	s := DefaultRecipeSettings()
	if err := loadRecipeSettings(&s); err != nil {
		t.Fatal(err)
	}
	want := RecipeSettings{Endpoint: "minio:9000", Bucket: "recipes", AccessKeyID: "saasapi", SecretAccessKeyFile: "/var/run/secrets/key",
		CredentialCheck: false, JobBucket: "jobs", PlatformRecipeDir: "/srv/recipes", ReadRole: "r", WriteRole: "w", MaxCount: 10, MaxTotalBytes: 1000, WriteRateLimit: 0.5, WriteRateBurst: 3,
		RenderLimits: cook.RenderLimits{MaxSourceBytes: 1024, RenderTimeout: 500 * time.Millisecond}}
	if s != want {
		t.Fatalf("got %+v\nwant %+v", s, want)
	}
}

func TestLoadRecipeSettingsRejects(t *testing.T) {
	for _, tc := range []struct{ env, val, want string }{
		{"SAASAPI_RECIPES_S3_USE_SSL", "maybe", "SAASAPI_RECIPES_S3_USE_SSL"},
		{"SAASAPI_RECIPES_CREDENTIAL_CHECK", "yes please", "SAASAPI_RECIPES_CREDENTIAL_CHECK"},
		{"SAASAPI_RECIPES_MAX_COUNT", "0", "SAASAPI_RECIPES_MAX_COUNT"},
		{"SAASAPI_RECIPES_MAX_COUNT", "100001", "SAASAPI_RECIPES_MAX_COUNT"},
		{"SAASAPI_RECIPES_MAX_TOTAL_BYTES", "-1", "SAASAPI_RECIPES_MAX_TOTAL_BYTES"},
		{"SAASAPI_RECIPES_WRITE_RATE_LIMIT", "0", "rate"},
		{"SAASAPI_RECIPES_WRITE_RATE_BURST", "0", "burst"},
		{"SAASAPI_RECIPES_WRITE_ROLE", "imas-recipes-read", "must differ"},
		{"SAASAPI_RECIPES_READ_ROLE", " r", "role name"},
		{"SAASAPI_RECIPES_S3_ENDPOINT", "minio:9000", "SAASAPI_RECIPES_S3_"},
		{"IMAS_RECIPE_MAX_SOURCE_BYTES", "-5", "IMAS_RECIPE_MAX_SOURCE_BYTES"},
		{"IMAS_RECIPE_RENDER_TIMEOUT", "soon", "IMAS_RECIPE_RENDER_TIMEOUT"},
	} {
		t.Run(tc.env+"="+tc.val, func(t *testing.T) {
			clearRecipeEnv(t)
			t.Setenv(tc.env, tc.val)
			s := DefaultRecipeSettings()
			err := loadRecipeSettings(&s)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error naming %q", err, tc.want)
			}
		})
	}
}

// FIX.5: with the credential check on (the default), the platform recipe
// prefix must be usable and the job bucket, when set, must not be the
// recipe bucket; with the check off neither is looked at.
func TestLoadRecipeSettingsCredentialCheckScope(t *testing.T) {
	store := map[string]string{
		"SAASAPI_RECIPES_S3_ENDPOINT":               "minio:9000",
		"SAASAPI_RECIPES_S3_BUCKET":                 "recipes",
		"SAASAPI_RECIPES_S3_ACCESS_KEY_ID":          "saasapi",
		"SAASAPI_RECIPES_S3_SECRET_ACCESS_KEY_FILE": "/var/run/secrets/key",
	}
	for _, tc := range []struct {
		name string
		env  map[string]string
		want string // "" accepts
	}{
		{"job bucket set", map[string]string{"SAASAPI_RECIPES_JOB_BUCKET": "jobs"}, ""},
		{"no job bucket (the check warns at startup)", nil, ""},
		{"job bucket is the recipe bucket", map[string]string{"SAASAPI_RECIPES_JOB_BUCKET": "recipes"}, "must differ"},
		{"platform dir under tenants/", map[string]string{"SAASAPI_RECIPES_JOB_BUCKET": "jobs", "SAASAPI_RECIPES_PLATFORM_RECIPE_DIR": "tenants/x"}, "SAASAPI_RECIPES_PLATFORM_RECIPE_DIR"},
		{"platform dir under sprouts/", map[string]string{"SAASAPI_RECIPES_JOB_BUCKET": "jobs", "SAASAPI_RECIPES_PLATFORM_RECIPE_DIR": "/sprouts"}, "SAASAPI_RECIPES_PLATFORM_RECIPE_DIR"},
		{"check off, no job bucket", map[string]string{"SAASAPI_RECIPES_CREDENTIAL_CHECK": "false"}, ""},
		{"check off, bad platform dir", map[string]string{"SAASAPI_RECIPES_CREDENTIAL_CHECK": "false", "SAASAPI_RECIPES_PLATFORM_RECIPE_DIR": "tenants/x"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearRecipeEnv(t)
			for k, v := range store {
				t.Setenv(k, v)
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			s := DefaultRecipeSettings()
			err := loadRecipeSettings(&s)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error naming %q", err, tc.want)
			}
		})
	}
}

func TestLoadConfigIncludesRecipes(t *testing.T) {
	clearRecipeEnv(t)
	t.Setenv("SAASAPI_RECIPES_MAX_COUNT", "7")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Recipes.MaxCount != 7 {
		t.Fatalf("Recipes %+v", cfg.Recipes)
	}
	t.Setenv("SAASAPI_RECIPES_MAX_COUNT", "x")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("bad recipe setting accepted by LoadConfig")
	}
}

func TestConfigureRecipes(t *testing.T) {
	prevSvc, prevLimits := recipeSvc, cook.CurrentRenderLimits()
	t.Cleanup(func() { recipeSvc = prevSvc; _ = cook.SetRenderLimits(prevLimits) })

	// Off: no store, routes answer 503.
	if err := ConfigureRecipes(DefaultRecipeSettings(), nil); err != nil {
		t.Fatal(err)
	}
	if recipeSvc.store != nil {
		t.Fatal("store configured with no endpoint")
	}

	// On: the secret comes from the file; limits reach cook.
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "secret")
	if err := os.WriteFile(keyFile, []byte("s3cr3t\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := DefaultRecipeSettings()
	s.Endpoint, s.Bucket, s.AccessKeyID, s.SecretAccessKeyFile = "minio:9000", "recipes", "saasapi", keyFile
	// No store answers at minio:9000: this test is about the key file and
	// the limits, so the scope check (on by default, covered in
	// recipes_credcheck_test.go) is off here.
	s.CredentialCheck = false
	s.RenderLimits = cook.RenderLimits{MaxSourceBytes: 4096}
	if err := ConfigureRecipes(s, nil); err != nil {
		t.Fatal(err)
	}
	if recipeSvc.store == nil || recipeSvc.audit == nil || cook.CurrentRenderLimits().MaxSourceBytes != 4096 {
		t.Fatalf("not configured: %+v", recipeSvc)
	}

	// Refused: a missing or empty key file, limits out of range.
	for name, mutate := range map[string]func(*RecipeSettings){
		"missing key file": func(s *RecipeSettings) { s.SecretAccessKeyFile = filepath.Join(dir, "nope") },
		"empty key file": func(s *RecipeSettings) {
			p := filepath.Join(dir, "empty")
			_ = os.WriteFile(p, []byte("  \n"), 0o600)
			s.SecretAccessKeyFile = p
		},
		"limit out of range": func(s *RecipeSettings) { s.RenderLimits = cook.RenderLimits{MaxSourceBytes: 1 << 40} },
		"same roles":         func(s *RecipeSettings) { s.WriteRole = s.ReadRole },
	} {
		bad := s
		mutate(&bad)
		err := ConfigureRecipes(bad, nil)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "s3cr3t") {
			t.Errorf("%s: error holds the secret: %v", name, err)
		}
	}
}

func TestCallerFromToken(t *testing.T) {
	tok := jwt.New()
	_ = tok.Set(jwt.SubjectKey, "u-1")
	_ = tok.Set("realm_access", map[string]any{"roles": []any{"b", "a", 7, ""}})
	_ = tok.Set("resource_access", map[string]any{
		"saasapi": map[string]any{"roles": []any{"c", "a"}},
		"other":   map[string]any{"roles": []any{"not-mine"}},
	})
	c := callerFromToken(tok, "saasapi")
	if c.Subject != "u-1" || strings.Join(c.Roles, ",") != "a,b,c" {
		t.Fatalf("caller %+v", c)
	}
	if !c.HasAnyRole("x", "c") || c.HasAnyRole("not-mine") || c.HasAnyRole("") {
		t.Fatal("HasAnyRole")
	}
	// Malformed claims grant nothing.
	bad := jwt.New()
	_ = bad.Set("realm_access", "admin")
	_ = bad.Set("resource_access", map[string]any{"saasapi": []any{"admin"}})
	if c := callerFromToken(bad, "saasapi"); len(c.Roles) != 0 {
		t.Fatalf("roles from malformed claims: %v", c.Roles)
	}
}
