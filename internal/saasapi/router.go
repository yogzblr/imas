package saasapi

import (
	"fmt"
	"net/http"

	"github.com/valkey-io/valkey-go"
	"golang.org/x/time/rate"

	log "github.com/yogzblr/imas/internal/log"
)

// enrollmentKeyIssuanceRate/Burst bound how often a single tenant (see
// RateLimit's key choice in middleware.go) may call POST
// .../enrollment-keys. This is a mutating, credential-issuing endpoint
// sitting behind Auth, not an unauthenticated guessing target — unlike
// NIST SP 800-63B's "cap failed attempts" figure, which bounds
// verification attempts against a secret at the not-yet-built §3.2/§3.3
// redemption endpoint, this number only needs to bound ordinary abuse of
// a leaked or over-eager bearer token (someone scripting key creation in
// a loop), not defend against brute-forcing a secret. The budget is
// shared by every user of a tenant. 1 request/second sustained with a
// burst of 5 is still ample for that: one key covers up to maxMaxUses
// machines, so even bulk onboarding needs few keys, and a spamming
// caller is capped at about 60 enrollment_keys rows/minute per tenant
// instead of an unbounded flood.
const (
	enrollmentKeyIssuanceRate  rate.Limit = 1
	enrollmentKeyIssuanceBurst int        = 5
)

// enrollmentKeyIssuanceLimiterName namespaces this limiter's Valkey keys.
const enrollmentKeyIssuanceLimiterName = "enrollment-keys"

// enrollmentKeyIssuanceLimiter starts as a per-pod limiter at the
// defaults. main replaces it via SetEnrollmentKeyRateLimit with the
// deployment's configured values (SAASAPI_ENROLLMENT_KEY_RATE_LIMIT/
// _BURST, see config.go and deploy/saasapi/), backed by Valkey when
// SAASAPI_VALKEY_ADDRS is set.
var enrollmentKeyIssuanceLimiter callerLimiter = NewPerCallerLimiter(enrollmentKeyIssuanceRate, enrollmentKeyIssuanceBurst)

// SetEnrollmentKeyRateLimit replaces the per-tenant limiter on POST
// .../enrollment-keys with one allowing perSecond requests/second
// sustained and bursts up to burst.
//
// With a non-nil vc, the limit is shared across every saasapi pod via
// Valkey (see NewValkeyLimiter, including how it degrades if Valkey is
// unreachable). With a nil vc, each pod enforces the limit on its own,
// so N pods allow a tenant up to N times as much.
//
// Like SetDB and SetAuthConfig, call it once at startup: it must run
// before NewRouter, which wires the limiter in effect at that moment
// into the route.
func SetEnrollmentKeyRateLimit(perSecond float64, burst int, vc valkey.Client) error {
	if err := validateRateLimit(perSecond, burst); err != nil {
		return fmt.Errorf("saasapi: enrollment-key rate limit: %w", err)
	}
	if vc != nil {
		enrollmentKeyIssuanceLimiter = NewValkeyLimiter(vc, enrollmentKeyIssuanceLimiterName, rate.Limit(perSecond), burst)
	} else {
		enrollmentKeyIssuanceLimiter = NewPerCallerLimiter(rate.Limit(perSecond), burst)
	}
	return nil
}

// sproutActionRate/Burst bound how often a single tenant may call POST
// .../sprouts/actions (§1.5). Each call can trigger up to
// maxAssetIDsPerLookup remote executions and writes as many
// asset_action_items rows, so it's limited like enrollment-key issuance:
// one batch per second sustained per tenant, bursts of 5. That's up to
// 100 machines a second per tenant — ample for operator-driven batches,
// while bounding a runaway script. Per pod only for now: there's no
// SAASAPI_* setting or Valkey wiring for it yet (that lives in
// cmd/saasapi and deploy/saasapi, outside this change).
const (
	sproutActionRate  rate.Limit = 1
	sproutActionBurst int        = 5
)

var sproutActionLimiter callerLimiter = NewPerCallerLimiter(sproutActionRate, sproutActionBurst)

// fleetUpdateRate/Burst bound how often a single tenant may call POST
// .../sprouts/updates (§1.8), when it's enabled. A rollout covers up to
// maxAssetIDsPerLookup machines and runs for a long time, so one every ten
// seconds sustained, bursts of 2, is ample and tighter than §1.5's
// limit. Per pod only, like sproutActionLimiter.
const (
	fleetUpdateRate  rate.Limit = 0.1
	fleetUpdateBurst int        = 2
)

var fleetUpdateLimiter callerLimiter = NewPerCallerLimiter(fleetUpdateRate, fleetUpdateBurst)

// NewRouter builds the SaaS API's HTTP router (design doc §1.1–§1.6 and
// §1.8, the last one's dispatch routes only with the feature flag on; see
// SetFleetUpdateDispatchEnabled). Call ConfigureRecipes first: the recipe
// routes use the roles and rate limiter it installed.
// Every route is wrapped in Auth — see middleware.go for the two-layer
// shared-secret + Keycloak-JWT check it performs, and SetAuthConfig,
// which must be called (from main, after NewAuthConfig) before this
// router serves any request.
//
// Serve it behind RejectUncleanPaths: on its own, http.ServeMux answers a
// path with "." or ".." segments with a method-preserving redirect to the
// cleaned path (see cleanpath.go).
func NewRouter() *http.ServeMux {
	mux := http.NewServeMux()

	route(mux, "POST /v1/tenants", CreateTenant, "CreateTenant")
	route(mux, "GET /v1/tenants/{tenant_id}", GetTenant, "GetTenant")
	route(mux, "PATCH /v1/tenants/{tenant_id}", PatchTenant, "PatchTenant")
	route(mux, "DELETE /v1/tenants/{tenant_id}", DeleteTenant, "DeleteTenant")
	route(mux, "GET /v1/tenants/{tenant_id}/status", GetTenantStatus, "GetTenantStatus")

	// POST .../enrollment-keys mints a new credential and is the one
	// enrollment-key route that lets a caller grow saas.enrollment_keys
	// without bound, so it's rate-limited (see enrollmentKeyIssuanceRate
	// above). GET (listing) and DELETE (revocation) are left to Auth's
	// gate alone: listing is read-only and returns no secret material
	// (§1.2's list response excludes key_hash), and revoking is bounded
	// by however many keys already exist — repeatedly revoking the same
	// key is a no-op, not a way to grow state or mint anything.
	routeRateLimited(mux, "POST /v1/tenants/{tenant_id}/enrollment-keys", CreateEnrollmentKey,
		"CreateEnrollmentKey", enrollmentKeyIssuanceLimiter)
	route(mux, "GET /v1/tenants/{tenant_id}/enrollment-keys", ListEnrollmentKeys, "ListEnrollmentKeys")
	route(mux, "DELETE /v1/tenants/{tenant_id}/enrollment-keys/{key_id}", DeleteEnrollmentKey, "DeleteEnrollmentKey")

	// Asset linking (§1.3) and lookup by asset id (§1.4). See
	// asset_links.go for why POST .../asset-link needs no rate limit.
	route(mux, "POST /v1/tenants/{tenant_id}/sprouts/{sprout_id}/asset-link", LinkAsset, "LinkAsset")
	route(mux, "DELETE /v1/tenants/{tenant_id}/sprouts/{sprout_id}/asset-link", UnlinkAsset, "UnlinkAsset")
	route(mux, "GET /v1/tenants/{tenant_id}/sprouts", ListSproutsByAssetIDs, "ListSproutsByAssetIDs")

	// Batch sprout actions (§1.5) — see sprout_actions.go. POST is the
	// SaaS API's remote-execution trigger, so it's rate-limited
	// (sproutActionRate above); GET is a local read and isn't.
	routeRateLimited(mux, "POST /v1/tenants/{tenant_id}/sprouts/actions", CreateSproutActionBatch,
		"CreateSproutActionBatch", sproutActionLimiter)
	route(mux, "GET /v1/tenants/{tenant_id}/sprouts/actions/{batch_id}", GetSproutActionBatch, "GetSproutActionBatch")

	// Fleet updates (§1.8): catalog and policy (fleet_updates.go). PATCH
	// .../update-policy only rewrites the tenant's single policy row, so
	// it can't grow state and needs no rate limit.
	route(mux, "GET /v1/versions", ListFleetVersions, "ListFleetVersions")
	route(mux, "GET /v1/tenants/{tenant_id}/update-policy", GetUpdatePolicy, "GetUpdatePolicy")
	route(mux, "PATCH /v1/tenants/{tenant_id}/update-policy", PatchUpdatePolicy, "PatchUpdatePolicy")

	// Fleet update dispatch (§1.8, fleet_update_dispatch.go) is only
	// registered with the feature flag on, which it is not by default:
	// turning it on is a deployment decision. With the flag off, neither
	// route exists.
	if fleetUpdateDispatchEnabled {
		log.Warnf("saasapi: fleet update dispatch is ENABLED (SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED): tenants with an approved version can roll sprout self-updates out")
		routeRateLimited(mux, "POST /v1/tenants/{tenant_id}/sprouts/updates", CreateFleetUpdateBatch,
			"CreateFleetUpdateBatch", fleetUpdateLimiter)
		route(mux, "GET /v1/tenants/{tenant_id}/sprouts/updates/{batch_id}", GetFleetUpdateBatch, "GetFleetUpdateBatch")
	}

	// Tenant recipes (§1.6, recipes.go; FLAG FOR SECURITY REVIEW). Reading
	// takes the read or the write role, writing the write role only
	// (SAASAPI_RECIPES_READ_ROLE / _WRITE_ROLE): a recipe runs as root on
	// every sprout of the tenant that cooks it, so writing it is granted
	// like the right to run code, not like a viewer. PUT and DELETE share
	// one per-tenant rate limit (SAASAPI_RECIPES_WRITE_RATE_LIMIT/_BURST).
	// Registered whether or not storage is configured; without it they
	// answer 503 recipes_not_configured. Uses the settings ConfigureRecipes
	// installed before this call.
	rs := recipeSvc
	readRoles := []string{rs.settings.ReadRole, rs.settings.WriteRole}
	writeRoles := []string{rs.settings.WriteRole}
	routeWithRole(mux, "GET /v1/tenants/{tenant_id}/recipes", rs.ListRecipes, "ListRecipes", readRoles, nil)
	routeWithRole(mux, "GET /v1/tenants/{tenant_id}/recipes/{name}", rs.GetRecipe, "GetRecipe", readRoles, nil)
	routeWithRole(mux, "PUT /v1/tenants/{tenant_id}/recipes/{name}", rs.PutRecipe, "PutRecipe", writeRoles, rs.limiter)
	routeWithRole(mux, "DELETE /v1/tenants/{tenant_id}/recipes/{name}", rs.DeleteRecipe, "DeleteRecipe", writeRoles, rs.limiter)

	// Fleet release registration (§2.5) is deliberately not on this mux:
	// it is the operator plane, with its own listener and credential
	// (NewOperatorServer, fleet_releases.go). The BFF's credentials never
	// reach it.

	return mux
}

func route(mux *http.ServeMux, pattern string, h http.HandlerFunc, name string) {
	mux.Handle(pattern, Logger(Auth(h, name), name))
}

// routeRateLimited is route plus a per-tenant RateLimit gate. RateLimit
// must sit inside Auth: it keys by the organization Auth puts on the
// request context, and an unauthenticated request (rejected by Auth
// first) never consumes rate-limit bookkeeping.
func routeRateLimited(mux *http.ServeMux, pattern string, h http.HandlerFunc, name string, limiter callerLimiter) {
	mux.Handle(pattern, Logger(Auth(RateLimit(h, limiter), name), name))
}

// routeWithRole is route plus a RequireRole gate (caller.go), and a
// per-tenant RateLimit after it when limiter isn't nil: the role is
// checked first, so a caller without it never spends the tenant's budget.
func routeWithRole(mux *http.ServeMux, pattern string, h http.HandlerFunc, name string, roles []string, limiter callerLimiter) {
	var inner http.Handler = h
	if limiter != nil {
		inner = RateLimit(inner, limiter)
	}
	mux.Handle(pattern, Logger(Auth(RequireRole(inner, name, roles...), name), name))
}
