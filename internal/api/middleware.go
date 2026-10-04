package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/yogzblr/imas/internal/api/handlers"
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

// Auth wraps a handler with authentication.
// The name parameter must match a key from the Routes map.
//
// Public routes (GetCertificate, PutNKey) are allowed without a token.
// There is no development bypass: dangerously_allow_root was removed
// (owner decision 2026-10-04, PR #95: "remove the HTTP bypass too in PR
// 95"), and farmer ignores the key.
//
// FileServer (GET /files/) accepts a sprout's gateway JWT — see
// sproutFileAccess. SproutUpdateManifest (GET /v1/sprout/update-manifest)
// accepts only a gateway JWT — see sproutIdentityAuth. Nothing accepts a
// CLI credential any more: the CLI's bearer token, an NKey signature a
// compromised bus could mint from a CONNECT nonce, is gone (J.3,
// docs/design/imas-payload-encryption-design.md Decision A), and the CLI
// browses recipes over sealed imas.api.recipes.* instead; the HTTP recipe
// routes are gone (CL.4).
func Auth(inner http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch name {
		case "GetCertificate", "PutNKey":
			inner.ServeHTTP(w, r)
			return
		case "SproutUpdateManifest":
			// The handler's tenant is the JWT's, so there is nothing to
			// serve without one.
			sproutIdentityAuth(inner, w, r)
			return
		}

		authToken := r.Header.Get("Authorization")
		if authToken == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// A gateway JWT arrives as "Bearer <jws>" (Envoy's jwt_authn
		// default, forwarded as-is). It is the only credential any
		// route here accepts.
		if name == "FileServer" {
			if jws, ok := strings.CutPrefix(authToken, "Bearer "); ok && sproutFileAccess(r, jws) {
				inner.ServeHTTP(w, r)
				return
			}
		}
		w.WriteHeader(http.StatusForbidden)
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

// sproutIdentityAuth serves r through inner only if it carries a valid
// gateway JWT ("Authorization: Bearer <jws>"), with the token's verified
// (tenant_id, sprout_id) on the request context
// (handlers.WithSproutIdentity) — the only place the handler gets a
// tenant from. No CLI token, no development bypass, and no
// header Envoy derived from the token: farmer's API port is reachable
// without passing through Envoy, so the token is verified here.
//
// A missing or non-bearer Authorization header is 401; a bearer token
// that does not verify, or whose tenant_id/sprout_id is unusable, is 403.
func sproutIdentityAuth(inner http.Handler, w http.ResponseWriter, r *http.Request) {
	jws, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || jws == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	keys := gatewayKeys()
	if keys == nil {
		log.Warnf("SproutUpdateManifest: gateway JWT presented but no gateway signer is configured")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	claims, err := gatewayjwt.VerifyGatewayJWT(r.Context(), keys, jws)
	if err != nil {
		log.Warnf("SproutUpdateManifest: rejecting gateway JWT: %v", err)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if !isKeySegment(claims.TenantID) || !isKeySegment(claims.SproutID) {
		log.Warnf("SproutUpdateManifest: gateway JWT tenant_id/sprout_id unusable")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	ctx := handlers.WithSproutIdentity(r.Context(), handlers.SproutIdentity{
		TenantID: claims.TenantID,
		SproutID: claims.SproutID,
	})
	inner.ServeHTTP(w, r.WithContext(ctx))
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
