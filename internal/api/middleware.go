package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/yogzblr/imas/internal/api/handlers"
	"github.com/yogzblr/imas/internal/auth"
	"github.com/yogzblr/imas/internal/gatewayjwt"
	log "github.com/yogzblr/imas/internal/log"
)

func Logger(inner http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		inner.ServeHTTP(w, r)

		log.Tracef("%s %s %s %s",
			r.Method, r.RequestURI,
			name, time.Since(start),
		)
	})
}

// Auth wraps a handler with authentication and role-based access control.
// The name parameter must match a key from the Routes map so that
// role permissions can be checked against the route.
//
// Public routes (GetCertificate, PutNKey) are allowed without a token.
// If dangerously_allow_root is set in the farmer config, all requests
// are allowed without authentication.
//
// FileServer (GET /files/) additionally accepts a sprout's gateway JWT
// — see sproutFileAccess. Every other route, ListRecipes/GetRecipe
// included, accepts only the CLI's NKey-signed RBAC token.
func Auth(inner http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch name {
		case "GetCertificate", "PutNKey":
			inner.ServeHTTP(w, r)
			return
		}

		// Development bypass — no auth required.
		if auth.DangerouslyAllowRoot() {
			log.Warnf("dangerously_allow_root: bypassing auth for %s %s", r.Method, name)
			inner.ServeHTTP(w, r)
			return
		}

		authToken := r.Header.Get("Authorization")
		if authToken == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// A gateway JWT arrives as "Bearer <jws>" (Envoy's jwt_authn
		// default, forwarded as-is); the CLI token is bare base64 JSON
		// and never has that prefix. Once a request presents a bearer
		// token it is judged on that token alone — no fallback to the
		// CLI path.
		if name == "FileServer" {
			if jws, ok := strings.CutPrefix(authToken, "Bearer "); ok {
				if sproutFileAccess(r, jws) {
					inner.ServeHTTP(w, r)
				} else {
					w.WriteHeader(http.StatusForbidden)
				}
				return
			}
		}

		if auth.TokenHasRouteAccess(authToken, name) {
			inner.ServeHTTP(w, r)
		} else {
			w.WriteHeader(http.StatusForbidden)
		}
	})
}

// gatewayKeys is where sproutFileAccess gets gateway JWT verification
// keys. A variable so tests can install a static key set.
var gatewayKeys = handlers.GatewayKeySource

// sproutFileAccess reports whether token is a valid gateway JWT whose
// (tenant_id, sprout_id) owns the file r requests: the object key must
// sit under handlers.SproutFilePrefix for that pair. A valid gateway JWT
// grants nothing beyond its own sprout's subtree — not other sprouts'
// files, not the tenant's, not the shared recipe tree.
//
// The token is re-verified here rather than trusting Envoy: farmer's API
// port is reachable without passing through Envoy, and headers Envoy
// derives from the token (x-imas-sprout-nkey) can be spoofed on that
// path.
func sproutFileAccess(r *http.Request, token string) bool {
	keys := gatewayKeys()
	if keys == nil {
		log.Warnf("FileServer: gateway JWT presented but no gateway signer is configured")
		return false
	}
	claims, err := gatewayjwt.VerifyGatewayJWT(r.Context(), keys, token)
	if err != nil {
		log.Warnf("FileServer: rejecting gateway JWT: %v", err)
		return false
	}
	if !isKeySegment(claims.TenantID) || !isKeySegment(claims.SproutID) {
		log.Warnf("FileServer: gateway JWT tenant_id/sprout_id not usable as a key segment")
		return false
	}

	key := handlers.FileKey(r)
	prefix := handlers.SproutFilePrefix(claims.TenantID, claims.SproutID)
	rest, ok := strings.CutPrefix(key, prefix)
	if !ok || !isCleanRelKey(rest) {
		log.Warnf("FileServer: gateway JWT for tenant %q sprout %q denied key outside its own prefix", claims.TenantID, claims.SproutID)
		return false
	}
	return true
}

// isKeySegment reports whether s can stand as one "/"-delimited segment
// of an object key without changing which prefix the key falls under.
func isKeySegment(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\\\x00")
}

// isCleanRelKey reports whether rest (the key below a sprout's prefix)
// is a non-empty path of plain segments. Object stores treat keys
// literally, but ".." or empty segments are rejected anyway so a key
// can never be read as climbing out of the sprout's subtree by anything
// that normalizes paths along the way.
func isCleanRelKey(rest string) bool {
	if rest == "" {
		return false
	}
	for _, seg := range strings.Split(rest, "/") {
		if !isKeySegment(seg) {
			return false
		}
	}
	return true
}
