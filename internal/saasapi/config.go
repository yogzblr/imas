// Package saasapi implements the external, customer/CloudXP-facing SaaS
// API service described in docs/design/cloudxp-machine-manager-api-design.md.
// It owns the `saas` schema in the shared PXC cluster and never writes to
// the `farmer` schema (see the design doc's §5.1 grants).
package saasapi

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds the saasapi service's runtime configuration. Unlike
// farmer/sprout/imas, this is a standalone service with its own env-based
// config rather than a new binary wired into internal/config's jety
// loader.
//
// Auth (see middleware.go's Auth and NewAuthConfig) is configured from
// this same env-var surface, read once at process startup:
//
//   - INTERNAL_AUTH_SECRET_CURRENT / INTERNAL_AUTH_SECRET_PREVIOUS: the
//     BFF's shared service secret (layer 1). Sourced from a Kubernetes
//     Secret kept in sync with Vault/OpenBao by External Secrets
//     Operator, with Reloader triggering a rolling restart on change.
//     Read once here, not polled or hot-reloaded — see middleware.go for
//     why two values exist.
//   - SAASAPI_KEYCLOAK_JWKS_URL / SAASAPI_JWT_ISSUER /
//     SAASAPI_JWT_AUDIENCE: the Keycloak realm whose end-user JWTs the
//     BFF forwards (layer 2).
//
// The NATS connection to farmer (see bus.go's ConnectBus, and
// docs/design/imas-internal-api-account.md) is configured the same way:
//
//   - SAASAPI_NATS_NKEY_SEED_FILE / SAASAPI_NATS_USER_JWT: this service's
//     own NATS identity — a narrowly-scoped User under the bus's SYS
//     Account, minted by farmer (pki.EnsureSaaSAPICredential). Same
//     operational model as INTERNAL_AUTH_SECRET_*: a Kubernetes Secret
//     kept in sync with OpenBao by External Secrets Operator, Reloader
//     rolling the Deployment on rotation, read once at startup. The seed
//     is the secret half, so it's taken only as a *path* to a file — the
//     Secret mounted as a volume — never as a raw env var: a mounted
//     Secret isn't inherited by child processes or captured in crash
//     dumps/`env` output the way an environment variable is (the same
//     preference internal/pki/jwtauth.go's IMAS_NATS_*_SEED_FILE states).
//     The JWT isn't secret, but must travel with the seed.
//   - SAASAPI_NATS_URL: the bus's client URL (e.g. "nats://farmerbus:4222";
//     TLS is always required, the scheme notwithstanding).
//   - SAASAPI_NATS_CA_FILE: path to the root CA PEM that signed the bus's
//     server certificate — the same config.RootCA farmer's own
//     connections trust.
//
// The per-tenant rate limit on POST .../enrollment-keys (see router.go's
// enrollmentKeyIssuanceRate for why the defaults are what they are) is
// tunable per deployment, e.g. from Helm values:
//
//   - SAASAPI_ENROLLMENT_KEY_RATE_LIMIT: sustained requests per second
//     per tenant, a decimal number > 0 (e.g. "0.5" is one every two
//     seconds). Default 1.
//   - SAASAPI_ENROLLMENT_KEY_RATE_BURST: requests a tenant may make back
//     to back before the sustained rate applies, an integer >= 1.
//     Default 5.
//
// An unparseable or out-of-range value is a startup error, not a silent
// fallback to the default: a typo in a Helm value shouldn't quietly
// leave the limit somewhere the operator didn't intend.
//
//   - SAASAPI_VALKEY_ADDRS: comma-separated Valkey node addresses (the
//     same format as farmer's IMAS_VALKEY_ADDRS). When set, the limit
//     above is enforced across all saasapi pods (see NewValkeyLimiter)
//     and saasapi refuses to start if it can't reach Valkey. When unset,
//     each pod enforces it on its own, so N pods allow up to N times as
//     much.
//
// The fleet update dispatch feature flag (see fleet_update_dispatch.go):
//
//   - SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED: "true" registers POST
//     .../sprouts/updates and its status endpoint (design doc §1.8).
//     Default false; turning it on is a deployment decision. Any value
//     strconv.ParseBool doesn't accept is a startup error. With it on, the
//     read-only fleet signing key client must also be configured
//     (IMAS_FLEETSIGN_OPENBAO_*, internal/fleetsign; design doc §2.5), or
//     saasapi refuses to start.
//   - SAASAPI_FLEET_UPDATE_CLOCK_SKEW: how far saasapi's clock and a
//     farmer node's may differ when the rollout's wave gate judges whether
//     a sprout's report postdates its update's dispatch (rolloutClockSkew),
//     as a Go duration ("45s", "2m"). Default 30s; must be above 0 and at
//     most 5m, since a wider margin lets older rows count as proof. An
//     invalid value is a startup error.
//
// The outbox sweeper (sweeper.go), which re-dispatches provisioning jobs
// and action items no live process is dispatching and resumes update
// rollouts whose process died. Safe to run on every replica: work is
// claimed with a row lease (outbox_lease.go). Durations are Go durations
// ("30s", "2m"); an invalid or out-of-range value is a startup error:
//
//   - SAASAPI_OUTBOX_SWEEPER_ENABLED: default true. Off, dispatchers still
//     take leases, so nothing else changes.
//   - SAASAPI_OUTBOX_SWEEP_INTERVAL: time between sweeps, default 30s,
//     1s..1h.
//   - SAASAPI_OUTBOX_PROVISIONING_STALE_AFTER: how long a tenant
//     provisioning job may stay pending after it was last published before
//     it is published again, doubling per attempt; default 2m, 10s..24h.
//   - SAASAPI_OUTBOX_ACTION_STALE_AFTER: the same for a queued action
//     item, from its last change; default 2m, 10s..24h.
//   - SAASAPI_OUTBOX_ACTION_MAX_AGE: how long after it was accepted a
//     queued action item may still be sent; past it the item fails with
//     expired_not_sent, never sent. Default 15m, 1m..1h. The only age
//     limit on the path: farmer and the sprout never reject a command on
//     its acceptance time.
//   - SAASAPI_OUTBOX_MAX_ATTEMPTS: dispatches of one job or item, the first
//     included, before it is failed; default 5, 1..50.
//   - SAASAPI_OUTBOX_LEASE_TTL: how long a lease lasts unrenewed, and so how
//     soon a dead process's batch or rollout is taken over; default 2m,
//     15s..1h.
//
// Dispatch concurrency (dispatch_limits.go; security review M5). Per
// process; an invalid or out-of-range value is a startup error:
//
//   - SAASAPI_ACTION_DISPATCH_CONCURRENCY: cmd.run and cook items in
//     flight to farmer at once, all tenants together. Default 64, 1..1024.
//   - SAASAPI_SELF_UPDATE_DISPATCH_CONCURRENCY: self_update items in
//     flight at once, a pool of its own so rollout waves are never
//     starved by cmd.run or cook. Default 16, 1..1024.
//   - SAASAPI_ACTION_DISPATCH_TENANT_CONCURRENCY: one tenant's cap in each
//     of those pools. Default 8, 1..1024, and at most half of
//     SAASAPI_ACTION_DISPATCH_CONCURRENCY.
//
// Keep them at or below farmer's IMAS_SPROUT_ACTION_CONCURRENCY,
// IMAS_SELF_UPDATE_CONCURRENCY and IMAS_SPROUT_ACTION_TENANT_CONCURRENCY
// times the farmer replicas: farmer refuses what doesn't fit
// (farmer_busy), and the item is sent again later.
//
// The operator plane (fleet_releases.go, design doc §2.5): release
// registration and revocation, served on its own HTTPS listener and never
// on the tenant API's. Off unless SAASAPI_OPERATOR_LISTEN_ADDR is set;
// with it set, every other setting below except the *_PREVIOUS_FILE and
// CA ones is required, and so is the read-only fleet signing key client
// (IMAS_FLEETSIGN_OPENBAO_*). Secrets are taken only as paths to mounted
// Secret files, read once at startup, like the NATS seed:
//
//   - SAASAPI_OPERATOR_LISTEN_ADDR: e.g. ":8443". Keep it off the
//     gateway's routes; only the farmer Helm release's hook Job calls it.
//   - SAASAPI_OPERATOR_TLS_CERT_FILE / SAASAPI_OPERATOR_TLS_KEY_FILE: the
//     operator listener's certificate and key (PEM). TLS only.
//   - SAASAPI_OPERATOR_TOKEN_FILE / SAASAPI_OPERATOR_TOKEN_PREVIOUS_FILE:
//     the operator bearer token, and the previous one during a rotation.
//     Must differ from the BFF's INTERNAL_AUTH_SECRET_* values.
//   - SAASAPI_FLEETRELEASER_URL: cmd/fleetreleaser's base URL, https only,
//     e.g. "https://fleetreleaser.imas.svc:8443".
//   - SAASAPI_FLEETRELEASER_TOKEN_FILE: the bearer token saasapi presents
//     to fleetreleaser.
//   - SAASAPI_FLEETRELEASER_CA_FILE: optional PEM bundle for
//     fleetreleaser's certificate; the system roots otherwise.
//
// Tenant recipe upload (recipes.go, REC.1): SAASAPI_RECIPES_* (the object
// store credential, roles, caps and write rate limit) and the
// IMAS_RECIPE_* template render limits farmer uses too. See
// RecipeSettings.
type Config struct {
	// ListenAddr is the address the HTTP server binds to, e.g. ":8081".
	ListenAddr string
	// DSN is the GORM MySQL DSN for the shared PXC cluster's `saas` schema,
	// e.g. "saas_svc:pass@tcp(pxc-cluster:3306)/saas?parseTime=true&loc=UTC".
	// parseTime=true is required: OpenDB refuses a DSN without it, since
	// every DATETIME column would otherwise fail to scan into time.Time.
	// loc should be UTC (the driver's default); OpenDB warns otherwise.
	DSN string

	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	// InternalAuthSecretCurrent is the required, currently-valid shared
	// service secret the BFF presents on X-Internal-Auth.
	InternalAuthSecretCurrent string
	// InternalAuthSecretPrevious is the previous secret value, still
	// accepted during a rotation window. Empty means only Current is
	// accepted.
	InternalAuthSecretPrevious string

	// KeycloakJWKSURL is the Keycloak realm's JWKS endpoint, e.g.
	// "https://keycloak.example.com/realms/cloudxp/protocol/openid-connect/certs".
	KeycloakJWKSURL string
	// JWTIssuer is the expected "iss" claim on end-user JWTs.
	JWTIssuer string
	// JWTAudience is the expected "aud" claim on end-user JWTs.
	JWTAudience string

	// NATSURL is the farmer bus's client URL.
	NATSURL string
	// NATSCAFile is the path to the root CA PEM used to verify the bus's
	// TLS certificate.
	NATSCAFile string
	// NATSNKeySeedFile is the path to a file holding this service's NATS
	// User NKey seed ("SU..."). The seed itself is read by ConnectBus and
	// never held in Config.
	NATSNKeySeedFile string
	// NATSUserJWT is this service's signed NATS User JWT.
	NATSUserJWT string

	// EnrollmentKeyRateLimit is the sustained per-tenant rate, in
	// requests per second, for POST .../enrollment-keys.
	EnrollmentKeyRateLimit float64
	// EnrollmentKeyRateBurst is the per-tenant burst size for POST
	// .../enrollment-keys.
	EnrollmentKeyRateBurst int

	// ValkeyAddrs are the Valkey nodes holding the shared rate-limit
	// state. Empty means per-pod limiting only.
	ValkeyAddrs []string

	// FleetUpdateDispatchEnabled is the fleet update dispatch feature
	// flag, passed to SetFleetUpdateDispatchEnabled before NewRouter.
	FleetUpdateDispatchEnabled bool
	// FleetUpdateClockSkew is the wave gate's clock-skew margin, passed to
	// SetFleetUpdateClockSkew before NewRouter.
	FleetUpdateClockSkew time.Duration

	// OutboxSweeper configures the outbox sweeper and the leases every
	// dispatcher takes, passed to SetOutboxSweeperSettings before NewRouter.
	OutboxSweeper OutboxSweeperSettings

	// OperatorListenAddr enables the operator plane (NewOperatorServer)
	// on this address. Empty means it is off.
	OperatorListenAddr        string
	OperatorTLSCertFile       string
	OperatorTLSKeyFile        string
	OperatorTokenFile         string
	OperatorTokenPreviousFile string
	FleetReleaserURL          string
	FleetReleaserTokenFile    string
	FleetReleaserCAFile       string

	// Recipes configures tenant recipe upload (recipes.go), passed to
	// ConfigureRecipes before NewRouter. See RecipeSettings for its
	// SAASAPI_RECIPES_* and IMAS_RECIPE_* variables.
	Recipes RecipeSettings
}

// LoadConfig reads the saasapi service's configuration from environment
// variables, applying sane defaults where possible. It returns an error
// only for a value that is set but invalid (the enrollment-key rate-limit
// settings, the fleet update dispatch flag and clock-skew margin, the
// outbox sweeper's settings, the recipe upload settings, and the operator
// plane's settings).
func LoadConfig() (Config, error) {
	cfg := Config{
		ListenAddr:   envOrDefault("SAASAPI_LISTEN_ADDR", ":8081"),
		DSN:          os.Getenv("SAASAPI_DSN"),
		ReadTimeout:  20 * time.Second,
		WriteTimeout: 20 * time.Second,
		IdleTimeout:  60 * time.Second,

		InternalAuthSecretCurrent:  os.Getenv("INTERNAL_AUTH_SECRET_CURRENT"),
		InternalAuthSecretPrevious: os.Getenv("INTERNAL_AUTH_SECRET_PREVIOUS"),

		KeycloakJWKSURL: os.Getenv("SAASAPI_KEYCLOAK_JWKS_URL"),
		JWTIssuer:       os.Getenv("SAASAPI_JWT_ISSUER"),
		JWTAudience:     os.Getenv("SAASAPI_JWT_AUDIENCE"),

		NATSURL:          os.Getenv("SAASAPI_NATS_URL"),
		NATSCAFile:       os.Getenv("SAASAPI_NATS_CA_FILE"),
		NATSNKeySeedFile: os.Getenv("SAASAPI_NATS_NKEY_SEED_FILE"),
		NATSUserJWT:      os.Getenv("SAASAPI_NATS_USER_JWT"),

		EnrollmentKeyRateLimit: float64(enrollmentKeyIssuanceRate),
		EnrollmentKeyRateBurst: enrollmentKeyIssuanceBurst,

		ValkeyAddrs: splitAddrs(os.Getenv("SAASAPI_VALKEY_ADDRS")),

		FleetUpdateClockSkew: defaultRolloutClockSkew,

		OutboxSweeper: DefaultOutboxSweeperSettings(),

		OperatorListenAddr:        os.Getenv("SAASAPI_OPERATOR_LISTEN_ADDR"),
		OperatorTLSCertFile:       os.Getenv("SAASAPI_OPERATOR_TLS_CERT_FILE"),
		OperatorTLSKeyFile:        os.Getenv("SAASAPI_OPERATOR_TLS_KEY_FILE"),
		OperatorTokenFile:         os.Getenv("SAASAPI_OPERATOR_TOKEN_FILE"),
		OperatorTokenPreviousFile: os.Getenv("SAASAPI_OPERATOR_TOKEN_PREVIOUS_FILE"),
		FleetReleaserURL:          os.Getenv("SAASAPI_FLEETRELEASER_URL"),
		FleetReleaserTokenFile:    os.Getenv("SAASAPI_FLEETRELEASER_TOKEN_FILE"),
		FleetReleaserCAFile:       os.Getenv("SAASAPI_FLEETRELEASER_CA_FILE"),

		Recipes: DefaultRecipeSettings(),
	}

	if v := os.Getenv("SAASAPI_ENROLLMENT_KEY_RATE_LIMIT"); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return Config{}, fmt.Errorf("saasapi: SAASAPI_ENROLLMENT_KEY_RATE_LIMIT=%q: not a number", v)
		}
		cfg.EnrollmentKeyRateLimit = f
	}
	if v := os.Getenv("SAASAPI_ENROLLMENT_KEY_RATE_BURST"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, fmt.Errorf("saasapi: SAASAPI_ENROLLMENT_KEY_RATE_BURST=%q: not an integer", v)
		}
		cfg.EnrollmentKeyRateBurst = n
	}
	if err := validateRateLimit(cfg.EnrollmentKeyRateLimit, cfg.EnrollmentKeyRateBurst); err != nil {
		return Config{}, fmt.Errorf("saasapi: enrollment-key rate limit (SAASAPI_ENROLLMENT_KEY_RATE_LIMIT/_BURST): %w", err)
	}
	if v := os.Getenv("SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("saasapi: SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED=%q: not a boolean", v)
		}
		cfg.FleetUpdateDispatchEnabled = b
	}
	if v := os.Getenv("SAASAPI_FLEET_UPDATE_CLOCK_SKEW"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 || d > maxRolloutClockSkew {
			return Config{}, fmt.Errorf("saasapi: SAASAPI_FLEET_UPDATE_CLOCK_SKEW=%q: want a duration above 0 and at most %s", v, maxRolloutClockSkew)
		}
		cfg.FleetUpdateClockSkew = d
	}
	if err := loadOutboxSweeperSettings(&cfg.OutboxSweeper); err != nil {
		return Config{}, err
	}
	if err := loadRecipeSettings(&cfg.Recipes); err != nil {
		return Config{}, err
	}
	if cfg.OperatorListenAddr != "" {
		if err := cfg.validateOperator(); err != nil {
			return Config{}, err
		}
	}
	return cfg, nil
}

// loadOutboxSweeperSettings overrides s's defaults with whichever
// SAASAPI_OUTBOX_* variables are set, refusing a value that doesn't parse
// or is out of range.
func loadOutboxSweeperSettings(s *OutboxSweeperSettings) error {
	if v := os.Getenv("SAASAPI_OUTBOX_SWEEPER_ENABLED"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("saasapi: SAASAPI_OUTBOX_SWEEPER_ENABLED=%q: not a boolean", v)
		}
		s.Enabled = b
	}
	for _, d := range []struct {
		name     string
		dst      *time.Duration
		min, max time.Duration
	}{
		{"SAASAPI_OUTBOX_SWEEP_INTERVAL", &s.Interval, minOutboxSweepInterval, maxOutboxSweepInterval},
		{"SAASAPI_OUTBOX_PROVISIONING_STALE_AFTER", &s.ProvisioningStaleAfter, minOutboxStaleAfter, maxOutboxStaleAfter},
		{"SAASAPI_OUTBOX_ACTION_STALE_AFTER", &s.ActionStaleAfter, minOutboxStaleAfter, maxOutboxStaleAfter},
		{"SAASAPI_OUTBOX_ACTION_MAX_AGE", &s.ActionMaxAge, minActionMaxAge, maxActionMaxAge},
		{"SAASAPI_OUTBOX_LEASE_TTL", &s.LeaseTTL, minOutboxLeaseTTL, maxOutboxLeaseTTL},
	} {
		v := os.Getenv(d.name)
		if v == "" {
			continue
		}
		parsed, err := time.ParseDuration(v)
		if err != nil || parsed < d.min || parsed > d.max {
			return fmt.Errorf("saasapi: %s=%q: want a duration from %s to %s", d.name, v, d.min, d.max)
		}
		*d.dst = parsed
	}
	if v := os.Getenv("SAASAPI_OUTBOX_MAX_ATTEMPTS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxOutboxMaxAttempts {
			return fmt.Errorf("saasapi: SAASAPI_OUTBOX_MAX_ATTEMPTS=%q: want an integer from 1 to %d", v, maxOutboxMaxAttempts)
		}
		s.MaxAttempts = n
	}
	for _, c := range []struct {
		name string
		dst  *int
	}{
		{"SAASAPI_ACTION_DISPATCH_CONCURRENCY", &s.DispatchConcurrency},
		{"SAASAPI_SELF_UPDATE_DISPATCH_CONCURRENCY", &s.SelfUpdateDispatchConcurrency},
		{"SAASAPI_ACTION_DISPATCH_TENANT_CONCURRENCY", &s.DispatchTenantConcurrency},
	} {
		v := os.Getenv(c.name)
		if v == "" {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxDispatchConcurrency {
			return fmt.Errorf("saasapi: %s=%q: want an integer from 1 to %d", c.name, v, maxDispatchConcurrency)
		}
		*c.dst = n
	}
	// "Well below the pool size" (security review M5): one tenant may
	// never hold more than half the cmd.run/cook pool.
	if s.DispatchTenantConcurrency*2 > s.DispatchConcurrency {
		return fmt.Errorf("saasapi: SAASAPI_ACTION_DISPATCH_TENANT_CONCURRENCY=%d must be at most half of SAASAPI_ACTION_DISPATCH_CONCURRENCY=%d",
			s.DispatchTenantConcurrency, s.DispatchConcurrency)
	}
	return nil
}

// validateOperator checks that every required operator-plane setting is
// present and the fleetreleaser URL is https. Files are read later, by
// NewOperatorServer.
func (c Config) validateOperator() error {
	for name, v := range map[string]string{
		"SAASAPI_OPERATOR_TLS_CERT_FILE":   c.OperatorTLSCertFile,
		"SAASAPI_OPERATOR_TLS_KEY_FILE":    c.OperatorTLSKeyFile,
		"SAASAPI_OPERATOR_TOKEN_FILE":      c.OperatorTokenFile,
		"SAASAPI_FLEETRELEASER_URL":        c.FleetReleaserURL,
		"SAASAPI_FLEETRELEASER_TOKEN_FILE": c.FleetReleaserTokenFile,
	} {
		if v == "" {
			return fmt.Errorf("saasapi: %s is required when SAASAPI_OPERATOR_LISTEN_ADDR is set", name)
		}
	}
	return validFleetReleaserURL(c.FleetReleaserURL)
}

// validateRateLimit rejects settings that would silently disable or
// break a token-bucket limiter: a non-positive, NaN, or infinite rate
// (rate.Limit(0) denies everything once the burst is spent, rate.Inf
// allows everything) and a burst below 1 (every request denied).
func validateRateLimit(perSecond float64, burst int) error {
	if math.IsNaN(perSecond) || math.IsInf(perSecond, 0) || perSecond <= 0 {
		return fmt.Errorf("rate must be a finite number of requests per second > 0, got %v", perSecond)
	}
	if burst < 1 {
		return fmt.Errorf("burst must be >= 1, got %d", burst)
	}
	return nil
}

// splitAddrs splits a comma-separated address list, dropping blanks and
// surrounding whitespace, so "" and " , " both mean no addresses.
func splitAddrs(v string) []string {
	var addrs []string
	for _, a := range strings.Split(v, ",") {
		if a = strings.TrimSpace(a); a != "" {
			addrs = append(addrs, a)
		}
	}
	return addrs
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
