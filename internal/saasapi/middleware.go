package saasapi

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	log "github.com/yogzblr/imas/internal/log"
)

// Logger wraps a handler with request logging, matching internal/api's
// farmer-side Logger middleware.
//
// Security note (part of the enrollment-key logging-safety review): this
// logs exactly four values — method, URI, route name, and duration. It
// never touches r.Body, so it cannot leak a request payload (an
// enrollment-key POST body, a tenant PATCH body, etc.) no matter what
// that payload contains. See TestLoggerNeverLogsRequestBody in
// middleware_test.go, which pins this by asserting a recognizable value
// from a request body never appears in Logger's output.
func Logger(inner http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		inner.ServeHTTP(w, r)
		log.Tracef("%s %s %s %s", r.Method, r.RequestURI, name, time.Since(start))
	})
}

// Auth implements the design doc's §1 auth boundary ("All endpoints
// require a bearer token whose claims include the caller's tenant_id")
// as two independent layers, checked in order, both required:
//
// Layer 1 — shared service secret (BFF identity). The BFF is the only
// intended caller of this service. It presents a pre-shared secret on
// the InternalAuthHeader ("X-Internal-Auth") header, compared with
// crypto/subtle.ConstantTimeCompare against AuthConfig's secretCurrent
// and (if configured) secretPrevious. The secret is sourced from a
// Kubernetes Secret that External Secrets Operator keeps in sync with
// Vault/OpenBao, with Reloader triggering a rolling restart on change;
// it's read once at startup (see NewAuthConfig/SetAuthConfig), not
// polled or hot-reloaded here. Because a rolling restart doesn't update
// every replica (of this service or the BFF) atomically, two secret
// values are accepted side by side during a rotation window —
// INTERNAL_AUTH_SECRET_CURRENT and the optional
// INTERNAL_AUTH_SECRET_PREVIOUS — so the window doesn't cause spurious
// 401s. This check runs before any JWKS fetch or JWT parsing, since it's
// the cheaper of the two.
//
// Layer 2 — Keycloak-issued end-user JWT. The BFF authenticates end
// users against Keycloak and forwards the user's own Keycloak-issued JWT
// (Authorization: Bearer ...) on every request. Verified via
// github.com/lestrrat-go/jwx/v2 against the realm's JWKS (fetched
// through an auto-refreshing jwk.Cache — see AuthConfig), checking
// signature, issuer, audience, and expiry.
//
// For any route with a {tenant_id} path parameter, the verified JWT's
// "organization" claim is parsed (see Organization) and organization.id
// — CloudXP's "customer_id", the same concept as tenant_id everywhere
// else in this codebase — is compared against the path's {tenant_id}.
// This claim is confirmed always present on a correctly-configured
// Keycloak realm, so an absent or unparseable claim here is treated as a
// defensive safety net for misconfiguration, not an expected path: it's
// logged as a warning (this should never happen) and rejected with 403,
// same as an outright mismatch, rather than trusted or allowed to panic.
// Routes without a {tenant_id} parameter (e.g. §1.8's fleet-catalog
// routes) skip this check entirely.
//
// Both layers fail the same way from the caller's point of view: missing
// or mismatched secret, missing/malformed bearer token, and signature/
// issuer/audience/expiry failures are all 401 "unauthorized" with no
// detail in the response body — the real reason is logged internally
// (Warnf), but never distinguishable from each other over the wire, same
// generic-failure discipline as the enrollment endpoint's single
// "enrollment_failed" response (design doc §3.4). A tenant_id mismatch
// or missing/malformed organization claim on an otherwise-valid,
// otherwise-verified token is 403 — a valid caller on both layers,
// asking for the wrong resource.
//
// On success, the full parsed Organization (id, name, attributes) is
// attached to the request context via OrganizationFromContext, not just
// the boolean match result, and so is the Caller (token subject and
// Keycloak roles, caller.go) that RequireRole checks.
func Auth(inner http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := authCfg
		if cfg == nil {
			log.Errorf("saasapi: %s: Auth called before SetAuthConfig; rejecting", name)
			writeError(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
			return
		}

		// Layer 1: shared service secret (BFF identity), checked first
		// and cheaply, before any JWKS fetch or JWT parsing.
		if !cfg.validInternalSecret(r.Header.Get(InternalAuthHeader)) {
			log.Warnf("saasapi: %s: missing or invalid %s header", name, InternalAuthHeader)
			writeError(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
			return
		}

		// Layer 2: Keycloak-issued end-user JWT.
		const bearerPrefix = "Bearer "
		authz := r.Header.Get("Authorization")
		if !strings.HasPrefix(authz, bearerPrefix) || authz == bearerPrefix {
			log.Warnf("saasapi: %s: missing or malformed Authorization header", name)
			writeError(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
			return
		}
		raw := strings.TrimPrefix(authz, bearerPrefix)

		tok, err := cfg.verifyBearerToken(r.Context(), raw)
		if err != nil {
			log.Warnf("saasapi: %s: JWT verification failed: %v", name, err)
			writeError(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
			return
		}

		org, orgErr := parseOrganizationClaim(tok)

		tenantID := r.PathValue("tenant_id")
		if tenantID != "" {
			if orgErr != nil {
				log.Warnf("saasapi: %s: organization claim missing or malformed on an otherwise-valid token (this should never happen if Keycloak is configured correctly): %v", name, orgErr)
				writeError(w, http.StatusForbidden, "forbidden", "forbidden")
				return
			}
			if org.ID != tenantID {
				log.Warnf("saasapi: %s: token organization.id %q does not match path tenant_id %q", name, org.ID, tenantID)
				writeError(w, http.StatusForbidden, "forbidden", "forbidden")
				return
			}
		}

		ctx := withCaller(r.Context(), callerFromToken(tok, cfg.audience))
		if orgErr == nil {
			ctx = withOrganization(ctx, org)
		}
		r = r.WithContext(ctx)

		inner.ServeHTTP(w, r)
	})
}

// callerBucketTTL bounds how long an idle per-caller bucket is kept
// around. RateLimit keys by tenant (see below), so the map is already
// bounded by the number of tenants actively calling; eviction just
// keeps it from holding a bucket for every tenant that ever called. A
// future caller of NewPerCallerLimiter keyed by something the caller
// controls (e.g. source IP at the /v1/enroll redemption endpoint) relies
// on this eviction far more.
const callerBucketTTL = 10 * time.Minute

// callerLimiter decides whether one more request from a caller key is
// allowed right now. RateLimit takes this rather than a concrete type so
// a route can use either the per-pod perCallerLimiter or the
// Valkey-backed valkeyLimiter (ratelimit_valkey.go), which enforces the
// limit across all pods.
type callerLimiter interface {
	allow(ctx context.Context, key string) bool
}

// callerBucket is one caller's token bucket plus bookkeeping for
// eviction.
type callerBucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// perCallerLimiter is a small, reusable per-caller token-bucket rate
// limiter, held in this pod's memory: with N pods, a caller spread
// across them gets up to N times the limit. NewValkeyLimiter builds the
// shared equivalent, and uses one of these as its fallback. It exists as its own named type (rather than inlined into the
// RateLimit middleware function) so the future /v1/enroll redemption
// endpoint (design doc §3.2/§3.3 — the caller-presents-a-key,
// server-validates-it flow; not implemented anywhere in this codebase
// yet) can construct its own instance here, with a much stricter,
// NIST-SP-800-63B-aligned rate for verification attempts specifically,
// without duplicating this bucketing/eviction logic.
type perCallerLimiter struct {
	mu      sync.Mutex
	limit   rate.Limit
	burst   int
	callers map[string]*callerBucket
}

// NewPerCallerLimiter builds a perCallerLimiter allowing r events/second
// sustained, with bursts up to burst, tracked independently per caller
// key.
func NewPerCallerLimiter(r rate.Limit, burst int) *perCallerLimiter {
	return &perCallerLimiter{
		limit:   r,
		burst:   burst,
		callers: make(map[string]*callerBucket),
	}
}

// allow reports whether a request from key is allowed right now.
func (l *perCallerLimiter) allow(_ context.Context, key string) bool {
	return l.allowAt(key, time.Now())
}

// allowAt is allow with an explicit clock, so tests can drive the
// limiter deterministically (advancing a fake "now") instead of
// sleeping in real time.
func (l *perCallerLimiter) allowAt(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.evictLocked(now)

	b, ok := l.callers[key]
	if !ok {
		b = &callerBucket{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.callers[key] = b
	}
	b.lastSeen = now
	return b.limiter.AllowN(now, 1)
}

// evictLocked drops buckets that have been idle longer than
// callerBucketTTL. Must be called with l.mu held.
func (l *perCallerLimiter) evictLocked(now time.Time) {
	cutoff := now.Add(-callerBucketTTL)
	for k, b := range l.callers {
		if b.lastSeen.Before(cutoff) {
			delete(l.callers, k)
		}
	}
}

// RateLimit wraps a handler with a per-tenant rate limit (design doc §3's
// security-review concerns, extended here to enrollment-key issuance —
// see router.go for which routes use this).
//
// Keying: buckets are keyed by the authenticated tenant — the verified
// JWT's organization.id (tenant_id, design doc §1.7/§6), which Auth puts
// on the request context. RateLimit must therefore run inside Auth (see
// routeRateLimited). Keying by tenant rather than by token means a
// caller can't dodge the limit by presenting a different, individually
// valid token per request; the trade-off is that every user of a tenant
// shares one bucket.
//
// If no organization is on the context, RateLimit fails closed with 403,
// the same response Auth gives for a missing organization claim. On a
// {tenant_id} route that can't happen (Auth already rejected the
// request); it means RateLimit was wired without Auth, or onto a route
// without {tenant_id} where Auth tolerates a missing claim. Either way,
// letting the request through with no bucket would silently disable the
// limit.
func RateLimit(inner http.Handler, limiter callerLimiter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		org, ok := OrganizationFromContext(r.Context())
		if !ok || org.ID == "" {
			log.Warnf("saasapi: RateLimit: no authenticated organization on request context; rejecting (is RateLimit wired inside Auth?)")
			writeError(w, http.StatusForbidden, "forbidden", "forbidden")
			return
		}
		if !limiter.allow(r.Context(), org.ID) {
			writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests, slow down and retry later")
			return
		}
		inner.ServeHTTP(w, r)
	})
}
