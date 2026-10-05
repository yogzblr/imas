package saasapi

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/valkey-io/valkey-go"
	"golang.org/x/time/rate"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/cook"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/objectstore"
)

// Recipe upload settings (REC.1, recipes.go). FLAG FOR SECURITY REVIEW.
//
// saasapi writes tenants' recipes straight to the recipe bucket farmer
// reads, with an object-store credential of its own whose policy allows
// only tenants/*/recipes/* (and PutObject on tenants/*/recipe-audit/*):
// never sprouts/, the job bucket or the platform recipe prefix. See
// deploy/helm/farmer/files/objectstore-policies/ for MinIO and AWS
// examples. Environment variables, read once at startup; a value that is
// set but invalid is a startup error:
//
//   - SAASAPI_RECIPES_S3_ENDPOINT: host:port of the S3/MinIO endpoint (the
//     one farmer's IMAS_S3_ENDPOINT names). Empty turns recipe upload off:
//     the four routes stay registered and answer 503
//     recipes_not_configured. With it set, the next three are required.
//   - SAASAPI_RECIPES_S3_BUCKET: the recipe bucket (farmer's IMAS_S3_BUCKET).
//   - SAASAPI_RECIPES_S3_ACCESS_KEY_ID: saasapi's own access key id.
//   - SAASAPI_RECIPES_S3_SECRET_ACCESS_KEY_FILE: path to a file holding its
//     secret key (a mounted Secret), never the key itself.
//   - SAASAPI_RECIPES_S3_USE_SSL: default true.
//   - SAASAPI_RECIPES_CREDENTIAL_CHECK: default true (owner decision,
//     FIX.3), as in the Helm chart. ConfigureRecipes asks the object store
//     whether the credential can write outside tenants/ or write, read or
//     list sprouts/, and refuses to start if it can, or if the store gives
//     no answer it can classify (recipes_credcheck.go). Only an explicit
//     false turns it off. Ignored with no endpoint.
//   - SAASAPI_RECIPES_READ_ROLE / SAASAPI_RECIPES_WRITE_ROLE: the Keycloak
//     roles (caller.go) that may read (GET) and write (PUT, DELETE) a
//     tenant's recipes. Defaults imas-recipes-read and imas-recipes-write;
//     they must differ. A writer may also read.
//   - SAASAPI_RECIPES_MAX_COUNT: recipes per tenant, default 500, 1..100000.
//   - SAASAPI_RECIPES_MAX_TOTAL_BYTES: bytes of recipes per tenant, default
//     20 MiB, 1 to 1 GiB.
//   - SAASAPI_RECIPES_WRITE_RATE_LIMIT / _BURST: PUT and DELETE per second
//     per tenant (one budget for both), default 1 and burst 10; shared
//     across pods through Valkey when SAASAPI_VALKEY_ADDRS is set.
//   - IMAS_RECIPE_MAX_SOURCE_BYTES, IMAS_RECIPE_MAX_RENDERED_BYTES,
//     IMAS_RECIPE_MAX_VALUE_BYTES, IMAS_RECIPE_RENDER_TIMEOUT,
//     IMAS_RECIPE_MAX_RANGE_ITERATIONS: the template render limits, the
//     same variables (and Helm values, farmer.recipes.templateLimits)
//     farmer renders under, so an upload is validated exactly as farmer
//     will cook it. The source limit is also the upload body limit.
type RecipeSettings struct {
	Endpoint            string
	Bucket              string
	AccessKeyID         string
	SecretAccessKeyFile string
	UseSSL              bool
	// CredentialCheck runs the startup self-check of the credential's
	// scope (recipes_credcheck.go).
	CredentialCheck bool

	ReadRole  string
	WriteRole string

	MaxCount      int
	MaxTotalBytes int64

	WriteRateLimit float64
	WriteRateBurst int

	// RenderLimits are handed to cook.SetRenderLimits; zero fields keep
	// cook's defaults.
	RenderLimits cook.RenderLimits
}

// Recipe setting defaults and bounds.
const (
	defaultRecipeReadRole       = "imas-recipes-read"
	defaultRecipeWriteRole      = "imas-recipes-write"
	defaultRecipeMaxCount       = 500
	maxRecipeMaxCount           = 100000
	defaultRecipeMaxTotalBytes  = 20 << 20
	maxRecipeMaxTotalBytes      = 1 << 30
	defaultRecipeWriteRate      = 1.0
	defaultRecipeWriteBurst     = 10
	recipeWriteLimiterName      = "recipe-writes"
	maxRecipeSecretKeyFileBytes = 4096
)

// DefaultRecipeSettings returns the settings with recipe upload off and
// every other field at its default.
func DefaultRecipeSettings() RecipeSettings {
	return RecipeSettings{
		UseSSL:          true,
		CredentialCheck: true,
		ReadRole:        defaultRecipeReadRole,
		WriteRole:       defaultRecipeWriteRole,
		MaxCount:        defaultRecipeMaxCount,
		MaxTotalBytes:   defaultRecipeMaxTotalBytes,
		WriteRateLimit:  defaultRecipeWriteRate,
		WriteRateBurst:  defaultRecipeWriteBurst,
	}
}

// loadRecipeSettings overrides s's defaults with whichever SAASAPI_RECIPES_*
// and IMAS_RECIPE_* variables are set, refusing a value that doesn't parse
// or is out of range. It reads no file.
func loadRecipeSettings(s *RecipeSettings) error {
	s.Endpoint = os.Getenv("SAASAPI_RECIPES_S3_ENDPOINT")
	s.Bucket = os.Getenv("SAASAPI_RECIPES_S3_BUCKET")
	s.AccessKeyID = os.Getenv("SAASAPI_RECIPES_S3_ACCESS_KEY_ID")
	s.SecretAccessKeyFile = os.Getenv("SAASAPI_RECIPES_S3_SECRET_ACCESS_KEY_FILE")
	if v := os.Getenv("SAASAPI_RECIPES_S3_USE_SSL"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("saasapi: SAASAPI_RECIPES_S3_USE_SSL=%q: not a boolean", v)
		}
		s.UseSSL = b
	}
	if v := os.Getenv("SAASAPI_RECIPES_CREDENTIAL_CHECK"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("saasapi: SAASAPI_RECIPES_CREDENTIAL_CHECK=%q: not a boolean", v)
		}
		s.CredentialCheck = b
	}
	if v := os.Getenv("SAASAPI_RECIPES_READ_ROLE"); v != "" {
		s.ReadRole = v
	}
	if v := os.Getenv("SAASAPI_RECIPES_WRITE_ROLE"); v != "" {
		s.WriteRole = v
	}
	if v := os.Getenv("SAASAPI_RECIPES_MAX_COUNT"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxRecipeMaxCount {
			return fmt.Errorf("saasapi: SAASAPI_RECIPES_MAX_COUNT=%q: want an integer from 1 to %d", v, maxRecipeMaxCount)
		}
		s.MaxCount = n
	}
	if v := os.Getenv("SAASAPI_RECIPES_MAX_TOTAL_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 || n > maxRecipeMaxTotalBytes {
			return fmt.Errorf("saasapi: SAASAPI_RECIPES_MAX_TOTAL_BYTES=%q: want an integer from 1 to %d", v, maxRecipeMaxTotalBytes)
		}
		s.MaxTotalBytes = n
	}
	if v := os.Getenv("SAASAPI_RECIPES_WRITE_RATE_LIMIT"); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return fmt.Errorf("saasapi: SAASAPI_RECIPES_WRITE_RATE_LIMIT=%q: not a number", v)
		}
		s.WriteRateLimit = f
	}
	if v := os.Getenv("SAASAPI_RECIPES_WRITE_RATE_BURST"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("saasapi: SAASAPI_RECIPES_WRITE_RATE_BURST=%q: not an integer", v)
		}
		s.WriteRateBurst = n
	}
	limits, err := recipeRenderLimitsFromEnv()
	if err != nil {
		return err
	}
	s.RenderLimits = limits
	return s.validate()
}

// recipeRenderLimitsFromEnv reads the IMAS_RECIPE_* variables farmer reads
// (internal/config), with the same rules: unset keeps cook's default, a
// set one must be a positive whole number or a positive Go duration. Their
// ranges are checked by cook.SetRenderLimits in ConfigureRecipes.
func recipeRenderLimitsFromEnv() (cook.RenderLimits, error) {
	var l cook.RenderLimits
	for _, f := range []struct {
		env string
		dst *int
	}{
		{config.EnvRecipeMaxSourceBytes, &l.MaxSourceBytes},
		{config.EnvRecipeMaxRenderedBytes, &l.MaxRenderedBytes},
		{config.EnvRecipeMaxValueBytes, &l.MaxValueBytes},
		{config.EnvRecipeMaxRangeIterations, &l.MaxRangeIterations},
	} {
		v := os.Getenv(f.env)
		if v == "" {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return cook.RenderLimits{}, fmt.Errorf("saasapi: %s=%q: want a positive whole number", f.env, v)
		}
		*f.dst = n
	}
	if v := os.Getenv(config.EnvRecipeRenderTimeout); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return cook.RenderLimits{}, fmt.Errorf("saasapi: %s=%q: want a positive duration such as 2s", config.EnvRecipeRenderTimeout, v)
		}
		l.RenderTimeout = d
	}
	return l, nil
}

// validate checks the settings that don't need a file or a connection.
func (s RecipeSettings) validate() error {
	if s.Endpoint != "" {
		for name, v := range map[string]string{
			"SAASAPI_RECIPES_S3_BUCKET":                 s.Bucket,
			"SAASAPI_RECIPES_S3_ACCESS_KEY_ID":          s.AccessKeyID,
			"SAASAPI_RECIPES_S3_SECRET_ACCESS_KEY_FILE": s.SecretAccessKeyFile,
		} {
			if v == "" {
				return fmt.Errorf("saasapi: %s is required when SAASAPI_RECIPES_S3_ENDPOINT is set", name)
			}
		}
	}
	for name, v := range map[string]string{"SAASAPI_RECIPES_READ_ROLE": s.ReadRole, "SAASAPI_RECIPES_WRITE_ROLE": s.WriteRole} {
		if strings.TrimSpace(v) != v || v == "" {
			return fmt.Errorf("saasapi: %s=%q: want a non-empty role name without surrounding spaces", name, v)
		}
	}
	// Least privilege: one role for both would make every reader a writer.
	if s.ReadRole == s.WriteRole {
		return fmt.Errorf("saasapi: SAASAPI_RECIPES_READ_ROLE and SAASAPI_RECIPES_WRITE_ROLE must differ (both %q)", s.ReadRole)
	}
	if s.MaxCount < 1 || s.MaxCount > maxRecipeMaxCount {
		return fmt.Errorf("saasapi: recipe count cap %d out of range 1..%d", s.MaxCount, maxRecipeMaxCount)
	}
	if s.MaxTotalBytes < 1 || s.MaxTotalBytes > maxRecipeMaxTotalBytes {
		return fmt.Errorf("saasapi: recipe total size cap %d out of range 1..%d", s.MaxTotalBytes, maxRecipeMaxTotalBytes)
	}
	if err := validateRateLimit(s.WriteRateLimit, s.WriteRateBurst); err != nil {
		return fmt.Errorf("saasapi: recipe write rate limit (SAASAPI_RECIPES_WRITE_RATE_LIMIT/_BURST): %w", err)
	}
	return nil
}

// recipeSvc is the recipe routes' state, installed by ConfigureRecipes.
// Its zero store means recipe upload is off.
type recipeService struct {
	settings RecipeSettings
	store    *objectstore.Store
	audit    recipeAuditSink
	limiter  callerLimiter
}

var recipeSvc = newRecipeService(DefaultRecipeSettings(), nil, nil)

func newRecipeService(s RecipeSettings, store *objectstore.Store, vc valkey.Client) *recipeService {
	svc := &recipeService{settings: s, store: store}
	if store != nil {
		svc.audit = objectStoreAuditSink{store: store}
	}
	if vc != nil {
		svc.limiter = NewValkeyLimiter(vc, recipeWriteLimiterName, rate.Limit(s.WriteRateLimit), s.WriteRateBurst)
	} else {
		svc.limiter = NewPerCallerLimiter(rate.Limit(s.WriteRateLimit), s.WriteRateBurst)
	}
	return svc
}

// ConfigureRecipes installs the recipe upload settings: the render limits
// (cook.SetRenderLimits, range-checked), the object-store client built
// from saasapi's own credential (when an endpoint is set), the roles, the
// caps and the write rate limiter (Valkey-backed with a non-nil vc). Call
// it once at startup, before NewRouter, which wires the roles and limiter
// in effect at that moment. With s.CredentialCheck (the default) it first
// verifies the
// credential's scope against the store (recipes_credcheck.go), waiting
// for the store about half a minute, and returns an error, which stops
// saasapi, if the credential is too broad or the store didn't answer.
// Without it, it makes no network call: saasapi then starts without the
// object store, and recipe requests fail until it is reachable.
func ConfigureRecipes(s RecipeSettings, vc valkey.Client) error {
	if err := s.validate(); err != nil {
		return err
	}
	if err := cook.SetRenderLimits(s.RenderLimits); err != nil {
		return fmt.Errorf("saasapi: recipe template limits (IMAS_RECIPE_*): %w", err)
	}
	var store *objectstore.Store
	if s.Endpoint != "" {
		secret, err := readSecretFile(s.SecretAccessKeyFile, maxRecipeSecretKeyFileBytes)
		if err != nil {
			return fmt.Errorf("saasapi: SAASAPI_RECIPES_S3_SECRET_ACCESS_KEY_FILE: %w", err)
		}
		store, err = objectstore.Open(objectstore.Config{
			Endpoint: s.Endpoint, Bucket: s.Bucket, UseSSL: s.UseSSL,
			AccessKeyID: s.AccessKeyID, SecretAccessKey: secret,
		})
		if err != nil {
			return fmt.Errorf("saasapi: recipe store: %w", err)
		}
		if s.CredentialCheck {
			if err := checkRecipeCredentialScope(context.Background(), store, s.Bucket); err != nil {
				return err
			}
		} else {
			log.Warnf("saasapi: recipe credential check off (SAASAPI_RECIPES_CREDENTIAL_CHECK=false): nothing verifies that the credential is limited to tenants/*/recipes/*")
		}
		log.Infof("saasapi: recipe upload on: bucket %s at %s, caps %d recipes / %d bytes per tenant, read role %q, write role %q",
			s.Bucket, s.Endpoint, s.MaxCount, s.MaxTotalBytes, s.ReadRole, s.WriteRole)
	} else {
		log.Infof("saasapi: recipe upload off (SAASAPI_RECIPES_S3_ENDPOINT unset): the recipe routes answer 503")
	}
	recipeSvc = newRecipeService(s, store, vc)
	return nil
}

// readSecretFile reads a mounted secret, at most limit bytes, trimming
// surrounding whitespace. The content is never logged or wrapped into an
// error.
func readSecretFile(path string, limit int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()
	buf, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	if int64(len(buf)) > limit {
		return "", fmt.Errorf("%s is over %d bytes", path, limit)
	}
	v := strings.TrimSpace(string(buf))
	if v == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return v, nil
}
