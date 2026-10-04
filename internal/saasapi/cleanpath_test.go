package saasapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// uncleanPaths are request targets ServeMux would redirect (or, for the
// percent-encoded dot segments, route with a ".." wildcard value) rather
// than serve as sent.
var uncleanPaths = []string{
	"/v1/tenants/t_a/recipes/..",
	"/v1/tenants/t_a/enrollment-keys/..",
	"/v1/tenants/t_a/../other/status",
	"/v1/tenants/t_a/.",
	"/v1/tenants/t_a/./status",
	"/v1/tenants/t_a/recipes/../",
	"/v1/tenants//t_a",
	"//v1/tenants/t_a",
	"/v1/tenants/t_a//",
	"/v1/tenants/t_a/enrollment-keys/%2e%2e",
	"/v1/tenants/t_a/enrollment-keys/%2E%2E",
	"/v1/tenants/t_a/%2e/status",
	"/v1/tenants/t_a%2F..",
	"/v1/tenants/t_a/enrollment-keys/k%2F%2E%2E",
}

func TestRejectUncleanPathsNeverReachesHandler(t *testing.T) {
	reached := 0
	h := RejectUncleanPaths(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodDelete} {
		for _, p := range uncleanPaths {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(method, p, nil))
			if w.Code != http.StatusBadRequest {
				t.Errorf("%s %s = %d, want 400", method, p, w.Code)
				continue
			}
			var body errorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Error != "invalid_request" {
				t.Errorf("%s %s body = %q (%v), want error invalid_request", method, p, w.Body.String(), err)
			}
			if loc := w.Header().Get("Location"); loc != "" {
				t.Errorf("%s %s set Location %q", method, p, loc)
			}
		}
	}
	if reached != 0 {
		t.Fatalf("handler reached %d time(s) for unclean paths", reached)
	}

	// Canonical paths pass through, including a trailing slash and dots
	// that are part of a segment rather than the whole of one.
	for _, p := range []string{
		"/",
		"/v1/tenants/t_a",
		"/v1/tenants/t_a/",
		"/v1/tenants/t_a/status?x=../..",
		"/v1/operator/fleet-releases/v2.4.1/revoke",
		"/v1/tenants/t_a/enrollment-keys/k...",
		"/v1/tenants/t_a/enrollment-keys/..k",
		"/v1/tenants/t_a/enrollment-keys/%2e%2ek",
	} {
		before := reached
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		if w.Code != http.StatusNoContent || reached != before+1 {
			t.Errorf("GET %s = %d (reached %t), want it passed through", p, w.Code, reached == before+1)
		}
	}
}

// TestRejectUncleanPathsKeepsTenant is the case that motivated the guard:
// with valid credentials for the tenant, a DELETE on a dot-segment path
// below it must not end up offboarding it.
func TestRejectUncleanPathsKeepsTenant(t *testing.T) {
	gdb := newTestDB(t)
	auth := newTestAuthEnv(t)
	tid := mustCreateActiveTenant(t, gdb)

	do := func(h http.Handler, method, p string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, p, nil)
		auth.setAuthHeaders(r, tid)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	// Bare, the mux answers with a method-preserving redirect to the
	// tenant itself: what a redirect-following client would then DELETE.
	if w := do(NewRouter(), http.MethodDelete, "/v1/tenants/"+tid+"/recipes/.."); w.Code != http.StatusTemporaryRedirect ||
		w.Header().Get("Location") != "/v1/tenants/"+tid {
		t.Fatalf("bare router: %d Location %q, want 307 to the tenant", w.Code, w.Header().Get("Location"))
	}

	h := RejectUncleanPaths(NewRouter())
	for _, req := range []struct{ method, path string }{
		{http.MethodDelete, "/v1/tenants/" + tid + "/recipes/.."},
		{http.MethodDelete, "/v1/tenants/" + tid + "/enrollment-keys/.."},
		{http.MethodGet, "/v1/tenants/" + tid + "/../other/status"},
	} {
		if w := do(h, req.method, req.path); w.Code != http.StatusBadRequest {
			t.Errorf("%s %s = %d %s, want 400", req.method, req.path, w.Code, w.Body.String())
		}
	}

	var got Tenant
	if err := gdb.First(&got, "id = ?", tid).Error; err != nil {
		t.Fatalf("loading tenant: %v", err)
	}
	if got.Status != TenantStatusActive {
		t.Fatalf("tenant status = %q, want %q", got.Status, TenantStatusActive)
	}

	// A canonical request still reaches its route.
	if w := do(h, http.MethodGet, "/v1/tenants/"+tid); w.Code != http.StatusOK {
		t.Fatalf("GET tenant through the guard = %d %s, want 200", w.Code, w.Body.String())
	}
}

func TestOperatorHandlerRejectsUncleanPaths(t *testing.T) {
	gdb := newFleetTestDB(t)
	withTestFleetKeys(t)
	signer := &fakeSigner{}
	p := &operatorPlane{tokens: [][]byte{[]byte(testOperatorToken)}, signer: signer}
	h := p.handler()

	body := releaseBody("v2.4.1", "v2.0.0", debPkg("amd64", sumA))
	for _, path := range []string{
		"/v1/operator/fleet-releases/v2.4.1/revoke/../..",
		"/v1/operator/fleet-releases/x/../../fleet-releases",
		"/v1/operator//fleet-releases",
		"/v1/operator/fleet-releases/%2e%2e/revoke",
	} {
		if code, resp := operatorDo(t, h, testOperatorToken, http.MethodPost, path, body); code != http.StatusBadRequest ||
			resp["error"] != "invalid_request" {
			t.Errorf("POST %s = %d %v, want 400 invalid_request", path, code, resp)
		}
	}
	if signer.n() != 0 || countRows(t, gdb) != 0 {
		t.Fatalf("unclean paths: %d signing call(s), %d row(s)", signer.n(), countRows(t, gdb))
	}

	// The canonical route still works through the guard.
	if code, resp := register(t, h, body); code != http.StatusCreated {
		t.Fatalf("register through the guard = %d %v, want 201", code, resp)
	}
}
