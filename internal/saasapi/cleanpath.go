package saasapi

import (
	"net/http"
	"path"
	"strings"
)

// RejectUncleanPaths refuses, with 400 invalid_request, any request whose
// path is not already in canonical form: a "." or ".." segment (literal or
// percent-encoded), a doubled slash, or a missing leading slash.
//
// http.ServeMux would instead answer such a request with a 307 redirect to
// the cleaned path, which keeps the method and body. A client that follows
// redirects then sends, for example, DELETE /v1/tenants/t_a/recipes/.. on
// to DELETE /v1/tenants/t_a and starts offboarding the tenant. No route
// here has a reason to accept an unclean path, so it's an error, never a
// redirect. cmd/saasapi serves NewRouter behind it, and the operator
// listener serves its router behind it (operatorPlane.handler).
func RejectUncleanPaths(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isCleanRequestPath(r) {
			writeError(w, http.StatusBadRequest, "invalid_request", "request path is not in canonical form")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isCleanRequestPath reports whether r's path is canonical both decoded
// (r.URL.Path, which turns %2e%2e into "..") and as sent
// (r.URL.EscapedPath, which ServeMux matches against).
func isCleanRequestPath(r *http.Request) bool {
	p, escaped := r.URL.Path, r.URL.EscapedPath()
	return cleanPath(p) == p && cleanPath(escaped) == escaped
}

// cleanPath is net/http's ServeMux path canonicalization: path.Clean,
// rooted, keeping a trailing slash.
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	np := path.Clean(p)
	if p[len(p)-1] == '/' && np != "/" {
		if len(p) == len(np)+1 && strings.HasPrefix(p, np) {
			np = p
		} else {
			np += "/"
		}
	}
	return np
}
