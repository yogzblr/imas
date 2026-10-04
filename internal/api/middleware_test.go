package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/taigrr/jety"
)

func TestAuthPublicRoutesPassThrough(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for _, route := range []string{"GetCertificate", "PutNKey"} {
		t.Run(route, func(t *testing.T) {
			handler := Auth(inner, route)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("public route %s returned %d, want 200", route, rec.Code)
			}
		})
	}
}

func TestAuthNoTokenReturns401(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := Auth(inner, "Cook")
	req := httptest.NewRequest(http.MethodPost, "/cook", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no-token request returned %d, want 401", rec.Code)
	}
}

func TestAuthBadTokenReturns403(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := Auth(inner, "Cook")
	req := httptest.NewRequest(http.MethodPost, "/cook", nil)
	req.Header.Set("Authorization", "invalid-token-data")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	// Should be 403 (forbidden) since the token is invalid
	if rec.Code != http.StatusForbidden {
		t.Errorf("bad-token request returned %d, want 403", rec.Code)
	}
}

// dangerously_allow_root bypasses nothing on the HTTP API either (owner
// decision 2026-10-04, PR #95: "remove the HTTP bypass too in PR 95"):
// with it set, every route still takes its normal credential.
func TestAuthDangerouslyAllowRootBypassesNothing(t *testing.T) {
	jety.Set("dangerously_allow_root", true)
	t.Cleanup(func() { jety.Set("dangerously_allow_root", false) })

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("%s reached the handler", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	})
	for _, tc := range []struct {
		route, path, authz string
		want               int
	}{
		{"FileServer", "/files/sprouts/t_acme/web-01/nginx.conf", "", http.StatusUnauthorized},
		{"FileServer", "/files/sprouts/t_acme/web-01/nginx.conf", "Bearer not-a-jwt", http.StatusForbidden},
		{"ListRecipes", "/v1/recipes", "", http.StatusUnauthorized},
		{"ListRecipes", "/v1/recipes", "anything", http.StatusForbidden},
		{"GetRecipe", "/v1/recipes/base", "", http.StatusUnauthorized},
		{"SproutUpdateManifest", "/v1/sprout/update-manifest", "", http.StatusUnauthorized},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		if tc.authz != "" {
			req.Header.Set("Authorization", tc.authz)
		}
		rec := httptest.NewRecorder()
		Auth(inner, tc.route).ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s %q with the flag set: %d, want %d", tc.route, tc.authz, rec.Code, tc.want)
		}
	}
}

func TestLoggerWrapsHandler(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	handler := Logger(inner, "TestRoute")
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTeapot {
		t.Errorf("Logger wrapper changed status code: got %d, want 418", rec.Code)
	}
}
