package saasapi

import (
	"context"
	"net/http"
	"slices"

	"github.com/lestrrat-go/jwx/v2/jwt"

	log "github.com/yogzblr/imas/internal/log"
)

// Caller is who made a request, as Auth read it from the verified
// Keycloak JWT: the token subject (Keycloak's stable user id, for audit
// records) and the roles the token grants.
//
// Roles are Keycloak roles, read from two claims and merged:
//
//   - realm_access.roles: realm roles.
//   - resource_access.<audience>.roles: client roles of the client named
//     by SAASAPI_JWT_AUDIENCE, the one the token was issued for.
//
// Roles, not OAuth scopes, gate routes (RequireRole): a role is assigned
// to a user or a group by an administrator of the organization, while a
// scope is something the client (the BFF) asks for, so it would grant the
// same thing to every user the BFF requests it for.
type Caller struct {
	Subject string
	Roles   []string
}

// HasAnyRole reports whether c holds at least one of roles.
func (c Caller) HasAnyRole(roles ...string) bool {
	for _, r := range roles {
		if r != "" && slices.Contains(c.Roles, r) {
			return true
		}
	}
	return false
}

type callerContextKey struct{}

// CallerFromContext returns the request's Caller, which Auth attaches to
// every request it lets through.
func CallerFromContext(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(callerContextKey{}).(Caller)
	return c, ok
}

func withCaller(ctx context.Context, c Caller) context.Context {
	return context.WithValue(ctx, callerContextKey{}, c)
}

// callerFromToken builds the Caller for a verified token. clientID is the
// client whose client roles count (the configured audience). Claims of an
// unexpected shape contribute no roles, never an error: a role check then
// fails closed.
func callerFromToken(tok jwt.Token, clientID string) Caller {
	c := Caller{Subject: tok.Subject()}
	if raw, ok := tok.Get("realm_access"); ok {
		c.Roles = append(c.Roles, rolesOf(raw)...)
	}
	if raw, ok := tok.Get("resource_access"); ok && clientID != "" {
		if m, ok := raw.(map[string]any); ok {
			c.Roles = append(c.Roles, rolesOf(m[clientID])...)
		}
	}
	slices.Sort(c.Roles)
	c.Roles = slices.Compact(c.Roles)
	return c
}

// rolesOf reads {"roles": ["a", "b"]}, ignoring anything else.
func rolesOf(v any) []string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	list, ok := m["roles"].([]any)
	if !ok {
		return nil
	}
	var roles []string
	for _, r := range list {
		if s, ok := r.(string); ok && s != "" {
			roles = append(roles, s)
		}
	}
	return roles
}

// RequireRole lets a request through only if its Caller holds at least
// one of roles; otherwise it answers 403 forbidden. It must run inside
// Auth, which attaches the Caller; with none on the context (RequireRole
// wired without Auth) it fails closed the same way. Put it before
// RateLimit, so a caller without the role doesn't spend the tenant's
// budget.
func RequireRole(inner http.Handler, name string, roles ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := CallerFromContext(r.Context())
		if !ok || !c.HasAnyRole(roles...) {
			log.Warnf("saasapi: %s: caller %q lacks every role of %v; rejecting", name, c.Subject, roles)
			writeError(w, http.StatusForbidden, "forbidden", "the caller lacks the role this route requires")
			return
		}
		inner.ServeHTTP(w, r)
	})
}
