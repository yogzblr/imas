package saasapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/objectstore"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
)

// REC.1 tests: tenant recipe upload through the SaaS API.

const (
	recipeReadRole  = defaultRecipeReadRole
	recipeWriteRole = defaultRecipeWriteRole
	// bodyMarker is in every recipe body these tests send, so a test can
	// check that no response, log line or audit record echoes the body.
	bodyMarker = "zz-recipe-body-marker-41"
)

func recipeBody(step string) string {
	return "steps:\n  " + step + ":\n    cmd.run:\n      - name: echo " + bodyMarker + "\n"
}

// memAuditSink records audit records in memory; fail makes record fail.
type memAuditSink struct {
	mu   sync.Mutex
	recs []RecipeAuditRecord
	fail bool
}

func (m *memAuditSink) record(_ context.Context, r RecipeAuditRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("audit store down")
	}
	m.recs = append(m.recs, r)
	return nil
}

func (m *memAuditSink) records() []RecipeAuditRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.recs)
}

type recipeEnv struct {
	t      *testing.T
	auth   *testAuthEnv
	srv    *objectstoretest.Server
	store  *objectstore.Store
	audit  *memAuditSink
	svc    *recipeService
	mux    *http.ServeMux
	tA, tB string
}

// newRecipeEnv wires the real router (Auth, roles, rate limit) to a fake
// S3 bucket, with two active tenants. mutate adjusts the settings; the
// write rate limit is high unless it changes it.
func newRecipeEnv(t *testing.T, mutate func(*RecipeSettings)) *recipeEnv {
	t.Helper()
	gdb := newTestDB(t)
	e := &recipeEnv{t: t, auth: newTestAuthEnv(t), srv: objectstoretest.NewServer(t), audit: &memAuditSink{}}
	e.tA, _ = newID("t_")
	e.tB, _ = newID("t_")
	for _, id := range []string{e.tA, e.tB} {
		if err := gdb.Create(&Tenant{ID: id, Name: id, Status: TenantStatusActive}).Error; err != nil {
			t.Fatal(err)
		}
	}
	var err error
	e.store, err = objectstore.Open(e.srv.Config())
	if err != nil {
		t.Fatal(err)
	}
	s := DefaultRecipeSettings()
	s.WriteRateLimit, s.WriteRateBurst = 1000, 1000
	if mutate != nil {
		mutate(&s)
	}
	e.svc = newRecipeService(s, e.store, nil)
	e.svc.audit = e.audit
	prev := recipeSvc
	recipeSvc = e.svc
	t.Cleanup(func() { recipeSvc = prev })
	e.mux = NewRouter()
	return e
}

// token mints a token for tenant with the given realm roles.
func (e *recipeEnv) token(tenant string, roles ...string) string {
	return e.auth.mintToken(tokenOpts{org: &Organization{ID: tenant, Name: tenant}, realmRoles: roles, subject: "user-of-" + tenant})
}

// do sends a request through the router. target is used verbatim (it may
// hold percent-encoding).
func (e *recipeEnv) do(method, target, token, body string, hdr map[string]string) *httptest.ResponseRecorder {
	e.t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, target, rdr)
	r.Header.Set(InternalAuthHeader, testInternalAuthSecretCurrent)
	r.Header.Set("Authorization", "Bearer "+token)
	if method == http.MethodPut {
		r.Header.Set("Content-Type", "application/yaml")
	}
	for k, v := range hdr {
		if v == "" {
			r.Header.Del(k)
		} else {
			r.Header.Set(k, v)
		}
	}
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, r)
	return w
}

func (e *recipeEnv) path(tenant, name string) string {
	p := "/v1/tenants/" + tenant + "/recipes"
	if name != "" {
		p += "/" + name
	}
	return p
}

// put creates (no sha) or replaces (sha) a recipe as tenant's writer.
func (e *recipeEnv) put(tenant, name, body, sha string) *httptest.ResponseRecorder {
	e.t.Helper()
	hdr := map[string]string{"If-None-Match": "*"}
	if sha != "" {
		hdr = map[string]string{"If-Match": `"` + sha + `"`}
	}
	return e.do(http.MethodPut, e.path(tenant, name), e.token(tenant, recipeWriteRole), body, hdr)
}

func decode[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("decoding %q: %v", w.Body.String(), err)
	}
	return v
}

func wantStatus(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, status, w.Body.String())
	}
	if code != "" {
		if got := decode[errorResponse](t, w).Error; got != code {
			t.Fatalf("error code = %q, want %q; body=%s", got, code, w.Body.String())
		}
	}
	if strings.Contains(w.Body.String(), bodyMarker) && !(status == http.StatusOK && w.Header().Get("ETag") != "" && strings.Contains(w.Body.String(), `"content"`)) {
		t.Fatalf("response echoes the recipe body: %s", w.Body.String())
	}
}

func TestRecipeCRUD(t *testing.T) {
	e := newRecipeEnv(t, nil)
	body := recipeBody("hello")

	w := e.put(e.tA, "web.nginx", body, "")
	wantStatus(t, w, http.StatusCreated, "")
	created := decode[recipeRecord](t, w)
	if created.SHA256 != sha256Hex([]byte(body)) || created.Size != int64(len(body)) || created.Name != "web.nginx" {
		t.Fatalf("create response %+v", created)
	}
	if w.Header().Get("ETag") != `"`+created.SHA256+`"` {
		t.Fatalf("ETag %q", w.Header().Get("ETag"))
	}
	// Stored at the SEC.4 key, nowhere else (apart from audit records).
	wantKey := "tenants/" + e.tA + "/recipes/web/nginx.imas"
	if got, ok := e.srv.Object(wantKey); !ok || got != body {
		t.Fatalf("object at %s: %q, %v (keys %v)", wantKey, got, ok, e.srv.Keys())
	}

	w = e.do(http.MethodGet, e.path(e.tA, "web.nginx"), e.token(e.tA, recipeReadRole), "", nil)
	wantStatus(t, w, http.StatusOK, "")
	got := decode[recipeRecord](t, w)
	if got.Content == nil || *got.Content != body || got.SHA256 != created.SHA256 || got.UpdatedAt.IsZero() {
		t.Fatalf("get %+v", got)
	}

	w = e.do(http.MethodGet, e.path(e.tA, ""), e.token(e.tA, recipeReadRole), "", nil)
	wantStatus(t, w, http.StatusOK, "")
	list := decode[recipeListResponse](t, w)
	if len(list.Recipes) != 1 || list.Recipes[0].Name != "web.nginx" || list.Recipes[0].Content != nil {
		t.Fatalf("list %+v", list)
	}

	body2 := recipeBody("hello again")
	w = e.put(e.tA, "web.nginx", body2, created.SHA256)
	wantStatus(t, w, http.StatusOK, "")
	replaced := decode[recipeRecord](t, w)
	if replaced.SHA256 != sha256Hex([]byte(body2)) {
		t.Fatalf("replace %+v", replaced)
	}

	w = e.do(http.MethodDelete, e.path(e.tA, "web.nginx"), e.token(e.tA, recipeWriteRole), "", map[string]string{"If-Match": replaced.SHA256})
	wantStatus(t, w, http.StatusNoContent, "")
	w = e.do(http.MethodGet, e.path(e.tA, "web.nginx"), e.token(e.tA, recipeReadRole), "", nil)
	wantStatus(t, w, http.StatusNotFound, "recipe_not_found")
	w = e.do(http.MethodDelete, e.path(e.tA, "web.nginx"), e.token(e.tA, recipeWriteRole), "", nil)
	wantStatus(t, w, http.StatusNotFound, "recipe_not_found")
}

func TestRecipeListPaging(t *testing.T) {
	e := newRecipeEnv(t, nil)
	var names []string
	for i := range 7 {
		n := fmt.Sprintf("app.r%d", i)
		names = append(names, n)
		wantStatus(t, e.put(e.tA, n, recipeBody(n), ""), http.StatusCreated, "")
	}
	// An object not written by the API under the prefix is skipped.
	objectstoretest.Seed(t, e.store, map[string]string{"tenants/" + e.tA + "/recipes/app/r3/init.imas": "steps: {}\n"})

	var seen []string
	token := ""
	for pages := 0; ; pages++ {
		if pages > 10 {
			t.Fatal("paging did not end")
		}
		target := e.path(e.tA, "") + "?limit=3"
		if token != "" {
			target += "&page_token=" + token
		}
		w := e.do(http.MethodGet, target, e.token(e.tA, recipeReadRole), "", nil)
		wantStatus(t, w, http.StatusOK, "")
		page := decode[recipeListResponse](t, w)
		for _, r := range page.Recipes {
			seen = append(seen, r.Name)
		}
		if page.NextPageToken == "" {
			break
		}
		token = page.NextPageToken
	}
	if !slices.Equal(seen, names) {
		t.Fatalf("listed %v, want %v", seen, names)
	}
	for _, bad := range []string{"?limit=0", "?limit=501", "?limit=x", "?page_token=%21%21", "?page_token=" + "Li4vLi4v%00"} {
		w := e.do(http.MethodGet, e.path(e.tA, "")+bad, e.token(e.tA, recipeReadRole), "", nil)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", bad, w.Code)
		}
	}
}

// TestRecipeTenantIsolation: a tenant cannot read, list, write or delete
// another tenant's recipes, under any name or encoded path.
func TestRecipeTenantIsolation(t *testing.T) {
	e := newRecipeEnv(t, nil)
	secret := "steps:\n  b secret:\n    cmd.run:\n      - name: echo tenant-b-secret\n"
	wantStatus(t, e.put(e.tB, "secret", secret, ""), http.StatusCreated, "")
	bKey := "tenants/" + e.tB + "/recipes/secret.imas"
	aAll := e.token(e.tA, recipeReadRole, recipeWriteRole)

	// 1. A's token on B's routes: 403 on every route, whatever the role.
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		for _, target := range []string{e.path(e.tB, "secret"), e.path(e.tB, "")} {
			if m != http.MethodGet && target == e.path(e.tB, "") {
				continue
			}
			w := e.do(m, target, aAll, recipeBody("x"), map[string]string{"If-None-Match": "*"})
			if w.Code != http.StatusForbidden {
				t.Errorf("%s %s with A's token: %d, want 403", m, target, w.Code)
			}
		}
	}

	// 2. A's own routes with names or paths that try to reach B's.
	crafted := []string{
		"/v1/tenants/" + e.tA + "/recipes/..%2F..%2F" + e.tB + "%2Frecipes%2Fsecret",
		"/v1/tenants/" + e.tA + "/recipes/%2e%2e",
		"/v1/tenants/" + e.tA + "/recipes/secret%2Eimas",
		"/v1/tenants/" + e.tA + "/recipes/tenants." + e.tB + ".recipes.secret",
		"/v1/tenants/" + e.tA + "/recipes/" + e.tB + "%2Frecipes%2Fsecret",
		"/v1/tenants/" + e.tA + "/recipes/..",
		"/v1/tenants/" + e.tA + "/recipes/../../" + e.tB + "/recipes/secret",
		"/v1/tenants/" + e.tA + "/../" + e.tB + "/recipes/secret",
		"/v1/tenants/" + e.tA + "/recipes/%2F" + e.tB,
		"/v1/tenants/" + e.tA + "/recipes/sprouts." + e.tB + ".web-01.recipe",
		"/v1/tenants/" + e.tA + "/recipes/secret.",
		"/v1/tenants/" + e.tA + "/recipes/.secret",
	}
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		for _, target := range crafted {
			w := e.do(m, target, aAll, recipeBody("x"), map[string]string{"If-Match": "*"})
			// ServeMux answers a path with dot segments with a redirect to
			// the cleaned path; a client that follows it lands on B's
			// route, where Auth refuses A's token.
			// (A redirect to A's own /v1/tenants/{id} is not followed here:
			// it leaves the recipe routes.)
			if loc := w.Header().Get("Location"); w.Code == http.StatusTemporaryRedirect || w.Code == http.StatusMovedPermanently {
				if !strings.Contains(loc, e.tB) {
					continue
				}
				w = e.do(m, loc, aAll, recipeBody("x"), map[string]string{"If-Match": "*"})
				if w.Code != http.StatusForbidden {
					t.Errorf("%s %s -> %s: %d, want 403", m, target, loc, w.Code)
				}
			}
			if w.Code < 300 || strings.Contains(w.Body.String(), "tenant-b-secret") {
				t.Errorf("%s %s: %d %s", m, target, w.Code, w.Body.String())
			}
		}
	}
	// "secret" under A is A's own (absent) recipe, never B's.
	w := e.do(http.MethodGet, e.path(e.tA, "secret"), aAll, "", nil)
	wantStatus(t, w, http.StatusNotFound, "recipe_not_found")

	// 3. Listing: A sees none of B's, even with a crafted page token.
	for _, tok := range []string{"", "Li4vLi4v", "Li4v" + "Li4v" + "dA"} {
		target := e.path(e.tA, "")
		if tok != "" {
			target += "?page_token=" + tok
		}
		w := e.do(http.MethodGet, target, aAll, "", nil)
		if w.Code == http.StatusOK && strings.Contains(w.Body.String(), "secret") {
			t.Errorf("A's listing (token %q) shows B's recipe: %s", tok, w.Body.String())
		}
	}

	// B's recipe is untouched, and A wrote nothing anywhere but its own
	// prefix (audit records included).
	if got, ok := e.srv.Object(bKey); !ok || got != secret {
		t.Fatalf("B's recipe changed: %q %v", got, ok)
	}
	for _, k := range e.srv.Keys() {
		if !strings.HasPrefix(k, "tenants/"+e.tB+"/") {
			t.Errorf("unexpected object %s", k)
		}
	}
}

func TestValidateUploadRecipeName(t *testing.T) {
	valid := []string{"web", "web.nginx", "a-b_c.d1", "0day", "x." + strings.Repeat("a", 64),
		strings.TrimSuffix(strings.Repeat("a.", 16), "."), "nginx.init-scripts", "imasx", "app.imas-tools"}
	for _, n := range valid {
		if err := validateUploadRecipeName(n); err != nil {
			t.Errorf("%q refused: %v", n, err)
		}
	}
	invalid := []string{"", "Web", "web..x", ".web", "web.", ".", "..", "web/x", "a.imas", "a.init", "imas", "init",
		"tenants", "tenants.x", "sprouts.a", "jobs", "-a", "a.-b", "_a", "a b", "ü", "a%2eb", "a\\b", "a\x00b",
		strings.Repeat("a", 201), strings.Repeat("a.", 17) + "a", "x." + strings.Repeat("a", 65), "a:b", "~a", "a*"}
	for _, n := range invalid {
		err := validateUploadRecipeName(n)
		if !errors.Is(err, errInvalidRecipeName) {
			t.Errorf("%q accepted (%v)", n, err)
		}
		// Short names can occur in the fixed rule text ("." or "jobs").
		if err != nil && len(n) > 8 && strings.Contains(err.Error(), n) {
			t.Errorf("%q: error echoes the name: %v", n, err)
		}
	}
	// One name, one key; the key round-trips and is what farmer resolves.
	key, err := recipeObjectKey("t_a", "web.nginx")
	if err != nil || key != "tenants/t_a/recipes/web/nginx.imas" {
		t.Fatalf("key %q %v", key, err)
	}
	if n, ok := recipeNameFromKey("t_a", "tenants/t_a/recipes/", key); !ok || n != "web.nginx" {
		t.Fatalf("name from key %q %v", n, ok)
	}
	for _, k := range []string{"tenants/t_a/recipes/web/init.imas", "tenants/t_a/recipes/web.x.imas", "tenants/t_b/recipes/web.imas", "tenants/t_a/recipes/web.yaml"} {
		if n, ok := recipeNameFromKey("t_a", "tenants/t_a/recipes/", k); ok {
			t.Errorf("%s mapped to %q", k, n)
		}
	}
	for _, tenant := range []string{"", ".", "..", "t/a", "t\\a"} {
		if _, err := recipeObjectKey(tenant, "web"); err == nil {
			t.Errorf("tenant %q accepted", tenant)
		}
	}
}

// TestRecipeInvalidNamesOverHTTP: invalid names are 400 on every route
// and nothing is stored.
func TestRecipeInvalidNamesOverHTTP(t *testing.T) {
	e := newRecipeEnv(t, nil)
	tok := e.token(e.tA, recipeWriteRole)
	for _, name := range []string{"Web", "a..b", "a.imas", "a.init", "tenants.x", "-x", strings.Repeat("a", 201), "a%2Fb", "a%2eb", "%61"} {
		for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			w := e.do(m, e.path(e.tA, name), tok, recipeBody("x"), map[string]string{"If-None-Match": "*"})
			wantStatus(t, w, http.StatusBadRequest, "invalid_recipe_name")
		}
	}
	if keys := e.srv.Keys(); len(keys) != 0 {
		t.Fatalf("stored %v", keys)
	}
}

// TestRecipePutValidation: every refused upload is a clear 4xx, stores
// nothing, and never echoes the body in the response or the log.
func TestRecipePutValidation(t *testing.T) {
	e := newRecipeEnv(t, nil)
	prev := cook.CurrentRenderLimits()
	if err := cook.SetRenderLimits(cook.RenderLimits{MaxSourceBytes: 2048}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cook.SetRenderLimits(prev) })

	m := bodyMarker
	cases := []struct {
		name   string
		body   string
		hdr    map[string]string
		status int
		code   string
	}{
		{"oversize", "steps: {}\n#" + strings.Repeat(m, 100), nil, http.StatusRequestEntityTooLarge, "recipe_too_large"},
		{"empty", "  \n", nil, http.StatusUnprocessableEntity, "recipe_empty"},
		{"not utf8", "steps: {}\n# " + m + "\xff\xfe", nil, http.StatusUnprocessableEntity, "recipe_not_utf8"},
		{"control char", "steps: {}\n# " + m + "\x07", nil, http.StatusUnprocessableEntity, "recipe_not_text"},
		{"bad yaml", "steps:\n  a: [" + m + "\n  b: }\n", nil, http.StatusUnprocessableEntity, "recipe_yaml_invalid"},
		{"yaml not a mapping", "- " + m + "\n", nil, http.StatusUnprocessableEntity, "recipe_yaml_invalid"},
		{"template does not parse", "steps: {}\n# {{ " + m + " }}\n", nil, http.StatusUnprocessableEntity, "recipe_template_invalid"},
		{"unknown function", "steps: {}\n# {{ nosuchfunc \"" + m + "\" }}\n", nil, http.StatusUnprocessableEntity, "recipe_template_invalid"},
		{"removed env", "steps: {}\n# {{ env \"IMAS_PXC_DSN\" }} " + m + "\n", nil, http.StatusUnprocessableEntity, "recipe_template_forbidden"},
		{"removed call", "steps: {}\n# {{ call . }} " + m + "\n", nil, http.StatusUnprocessableEntity, "recipe_template_forbidden"},
		{"removed js", "steps: {}\n# {{ js \"" + m + "\" }}\n", nil, http.StatusUnprocessableEntity, "recipe_template_forbidden"},
		{"define", "{{ define \"x\" }}" + m + "{{ end }}steps: {}\n", nil, http.StatusUnprocessableEntity, "recipe_template_forbidden"},
		{"template action", "steps: {}\n# {{ template \"" + m + "\" }}\n", nil, http.StatusUnprocessableEntity, "recipe_template_forbidden"},
		{"range over a number", "steps: {}\n# {{ range 100000000 }}" + m + "{{ end }}\n", nil, http.StatusUnprocessableEntity, "recipe_template_forbidden"},
		{"exec error", "steps: {}\n# {{ index .Missing \"" + m + "\" }}\n", nil, http.StatusUnprocessableEntity, "recipe_template_failed"},
		{"json content type", recipeBody("x"), map[string]string{"Content-Type": "application/json"}, http.StatusUnsupportedMediaType, "unsupported_media_type"},
		{"form content type", recipeBody("x"), map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, http.StatusUnsupportedMediaType, "unsupported_media_type"},
		{"latin1 charset", recipeBody("x"), map[string]string{"Content-Type": "text/plain; charset=iso-8859-1"}, http.StatusUnsupportedMediaType, "unsupported_media_type"},
		{"no precondition", recipeBody("x"), map[string]string{"If-None-Match": ""}, http.StatusPreconditionRequired, "precondition_required"},
		{"weak etag", recipeBody("x"), map[string]string{"If-None-Match": "", "If-Match": `W/"abc"`}, http.StatusBadRequest, "invalid_precondition"},
		{"bad etag", recipeBody("x"), map[string]string{"If-None-Match": "", "If-Match": `"abc"`}, http.StatusBadRequest, "invalid_precondition"},
		{"if-none-match not star", recipeBody("x"), map[string]string{"If-None-Match": `"abc"`}, http.StatusBadRequest, "invalid_precondition"},
	}
	out := captureStderr(t, func() {
		for _, tc := range cases {
			hdr := map[string]string{"If-None-Match": "*"}
			for k, v := range tc.hdr {
				hdr[k] = v
			}
			w := e.do(http.MethodPut, e.path(e.tA, "bad"), e.token(e.tA, recipeWriteRole), tc.body, hdr)
			if w.Code != tc.status {
				t.Errorf("%s: status %d, want %d; body=%s", tc.name, w.Code, tc.status, w.Body.String())
				continue
			}
			if tc.code != "" {
				if got := decode[errorResponse](t, w).Error; got != tc.code {
					t.Errorf("%s: code %q, want %q (%s)", tc.name, got, tc.code, w.Body.String())
				}
			}
			if strings.Contains(w.Body.String(), m) || strings.Contains(w.Body.String(), "IMAS_PXC_DSN") {
				t.Errorf("%s: response echoes the body: %s", tc.name, w.Body.String())
			}
		}
	})
	if strings.Contains(out, m) || strings.Contains(out, "IMAS_PXC_DSN") {
		t.Errorf("log echoes a recipe body:\n%s", out)
	}
	for _, k := range e.srv.Keys() {
		t.Errorf("a refused upload stored %s", k)
	}
	for _, r := range e.audit.records() {
		if r.Outcome != recipeOutcomeRejected {
			t.Errorf("audit record for a refused upload: %+v", r)
		}
	}
}

// TestRecipeRenderLimits: an upload that breaks a render limit is refused
// under the limits in force (the same ones farmer cooks under).
func TestRecipeRenderLimits(t *testing.T) {
	e := newRecipeEnv(t, nil)
	prev := cook.CurrentRenderLimits()
	if err := cook.SetRenderLimits(cook.RenderLimits{MaxRenderedBytes: 4096, MaxValueBytes: 1024, MaxRangeIterations: 10}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cook.SetRenderLimits(prev) })
	for name, body := range map[string]string{
		"rendered_bytes":   "steps: {}\n# {{ printf \"%0999d\" 1 }}{{ printf \"%0999d\" 1 }}{{ printf \"%0999d\" 1 }}{{ printf \"%0999d\" 1 }}{{ printf \"%0999d\" 1 }}\n",
		"range_iterations": "steps: {}\n# {{ range (split \"a,b,c,d,e,f,g,h,i,j,k,l\" \",\") }}x{{ end }}\n",
	} {
		w := e.put(e.tA, "lim", body, "")
		wantStatus(t, w, http.StatusUnprocessableEntity, "recipe_template_limit")
		if d := decode[errorResponse](t, w).Details["limit"]; d != name {
			t.Errorf("%s: details %v", name, d)
		}
	}
}

func TestRecipeQuota(t *testing.T) {
	e := newRecipeEnv(t, func(s *RecipeSettings) { s.MaxCount = 2 })
	wantStatus(t, e.put(e.tA, "a", recipeBody("a"), ""), http.StatusCreated, "")
	w := e.put(e.tA, "b", recipeBody("b"), "")
	wantStatus(t, w, http.StatusCreated, "")
	w = e.put(e.tA, "c", recipeBody("c"), "")
	wantStatus(t, w, http.StatusConflict, "recipe_quota_exceeded")
	if d := decode[errorResponse](t, w).Details["quota"]; d != "count" {
		t.Errorf("details %v", d)
	}
	// Replacing an existing one is still allowed at the cap, and another
	// tenant has its own cap.
	sha := sha256Hex([]byte(recipeBody("b")))
	wantStatus(t, e.put(e.tA, "b", recipeBody("b2"), sha), http.StatusOK, "")
	wantStatus(t, e.put(e.tB, "c", recipeBody("c"), ""), http.StatusCreated, "")

	e = newRecipeEnv(t, func(s *RecipeSettings) { s.MaxTotalBytes = int64(len(recipeBody("a")))*2 + 5 })
	wantStatus(t, e.put(e.tA, "a", recipeBody("a"), ""), http.StatusCreated, "")
	wantStatus(t, e.put(e.tA, "b", recipeBody("b"), ""), http.StatusCreated, "")
	w = e.put(e.tA, "c", recipeBody("c"), "")
	wantStatus(t, w, http.StatusConflict, "recipe_quota_exceeded")
	if d := decode[errorResponse](t, w).Details["quota"]; d != "total_bytes" {
		t.Errorf("details %v", d)
	}
	// Growing an existing recipe past the total is refused too.
	w = e.put(e.tA, "a", recipeBody("a much longer step name"), sha256Hex([]byte(recipeBody("a"))))
	wantStatus(t, w, http.StatusConflict, "recipe_quota_exceeded")
}

// TestRecipeConditionalWrite: two editors can't silently overwrite each
// other.
func TestRecipeConditionalWrite(t *testing.T) {
	e := newRecipeEnv(t, nil)
	v1 := recipeBody("v1")
	wantStatus(t, e.put(e.tA, "app", v1, ""), http.StatusCreated, "")
	sha1 := sha256Hex([]byte(v1))

	// Create-only on an existing name.
	w := e.put(e.tA, "app", recipeBody("other"), "")
	wantStatus(t, w, http.StatusPreconditionFailed, "precondition_failed")
	if d := decode[errorResponse](t, w).Details["current_sha256"]; d != sha1 {
		t.Errorf("current_sha256 %v", d)
	}
	// Editor 1 replaces; editor 2, still holding sha1, is refused.
	wantStatus(t, e.put(e.tA, "app", recipeBody("v2"), sha1), http.StatusOK, "")
	wantStatus(t, e.put(e.tA, "app", recipeBody("v3"), sha1), http.StatusPreconditionFailed, "precondition_failed")
	// If-Match on a missing recipe.
	wantStatus(t, e.put(e.tA, "nope", recipeBody("x"), sha1), http.StatusPreconditionFailed, "precondition_failed")
	w = e.do(http.MethodPut, e.path(e.tA, "nope"), e.token(e.tA, recipeWriteRole), recipeBody("x"), map[string]string{"If-None-Match": "", "If-Match": "*"})
	wantStatus(t, w, http.StatusPreconditionFailed, "precondition_failed")
	// A stale DELETE is refused too.
	w = e.do(http.MethodDelete, e.path(e.tA, "app"), e.token(e.tA, recipeWriteRole), "", map[string]string{"If-Match": sha1})
	wantStatus(t, w, http.StatusPreconditionFailed, "precondition_failed")

	// A writer that lands between saasapi's read and its write (another
	// replica, say) wins, and this request is 412, not a lost update.
	key := "tenants/" + e.tA + "/recipes/app.imas"
	cur, _ := e.srv.Object(key)
	racer := recipeBody("racer")
	e.srv.BeforePut(func(k string) {
		if k == key {
			e.srv.Set(k, racer)
		}
	})
	t.Cleanup(func() { e.srv.BeforePut(nil) })
	w = e.put(e.tA, "app", recipeBody("loser"), sha256Hex([]byte(cur)))
	wantStatus(t, w, http.StatusPreconditionFailed, "precondition_failed")
	if got, _ := e.srv.Object(key); got != racer {
		t.Fatalf("stored %q, want the concurrent writer's", got)
	}
	recs := e.audit.records()
	if last := recs[len(recs)-1]; last.Outcome != recipeOutcomeFailed || last.Code != "precondition_failed" {
		t.Errorf("last audit record %+v", last)
	}
}

func TestRecipeRoles(t *testing.T) {
	e := newRecipeEnv(t, nil)
	wantStatus(t, e.put(e.tA, "app", recipeBody("x"), ""), http.StatusCreated, "")
	sha := sha256Hex([]byte(recipeBody("x")))

	type call struct{ method, name string }
	reads := []call{{http.MethodGet, ""}, {http.MethodGet, "app"}}
	writes := []call{{http.MethodPut, "app"}, {http.MethodDelete, "app"}}
	try := func(tok string, c call) int {
		return e.do(c.method, e.path(e.tA, c.name), tok, recipeBody("y"), map[string]string{"If-Match": sha}).Code
	}
	none := e.token(e.tA)
	other := e.token(e.tA, "imas-viewer", "offline_access")
	reader := e.token(e.tA, recipeReadRole)
	for _, tok := range []string{none, other} {
		for _, c := range append(reads, writes...) {
			if code := try(tok, c); code != http.StatusForbidden {
				t.Errorf("%v without a recipe role: %d, want 403", c, code)
			}
		}
	}
	for _, c := range reads {
		if code := try(reader, c); code != http.StatusOK {
			t.Errorf("%v as reader: %d", c, code)
		}
	}
	for _, c := range writes {
		if code := try(reader, c); code != http.StatusForbidden {
			t.Errorf("%v as reader: %d, want 403", c, code)
		}
	}
	// Client roles of the token's audience count like realm roles.
	clientWriter := e.auth.mintToken(tokenOpts{org: &Organization{ID: e.tA}, clientRoles: []string{recipeWriteRole}})
	if code := try(clientWriter, call{http.MethodGet, "app"}); code != http.StatusOK {
		t.Errorf("client-role writer reading: %d", code)
	}
	if code := try(clientWriter, call{http.MethodPut, "app"}); code != http.StatusOK {
		t.Errorf("client-role writer writing: %d", code)
	}
}

// TestRecipeWriteRateLimit: PUT and DELETE share one per-tenant budget;
// GET doesn't spend it, and a caller without the role doesn't either.
func TestRecipeWriteRateLimit(t *testing.T) {
	e := newRecipeEnv(t, func(s *RecipeSettings) { s.WriteRateLimit, s.WriteRateBurst = 0.001, 2 })
	for range 3 {
		e.do(http.MethodPut, e.path(e.tA, "x"), e.token(e.tA, recipeReadRole), recipeBody("x"), map[string]string{"If-None-Match": "*"})
		e.do(http.MethodGet, e.path(e.tA, "x"), e.token(e.tA, recipeReadRole), "", nil)
	}
	wantStatus(t, e.put(e.tA, "a", recipeBody("a"), ""), http.StatusCreated, "")
	w := e.do(http.MethodDelete, e.path(e.tA, "a"), e.token(e.tA, recipeWriteRole), "", nil)
	wantStatus(t, w, http.StatusNoContent, "")
	wantStatus(t, e.put(e.tA, "b", recipeBody("b"), ""), http.StatusTooManyRequests, "rate_limited")
	wantStatus(t, e.put(e.tB, "b", recipeBody("b"), ""), http.StatusCreated, "")
}

// TestRecipeAudit: every write and delete leaves records with the tenant,
// caller, name, sha256 and size, never the content.
func TestRecipeAudit(t *testing.T) {
	e := newRecipeEnv(t, nil)
	v1, v2 := recipeBody("v1"), recipeBody("v2")
	wantStatus(t, e.put(e.tA, "app", v1, ""), http.StatusCreated, "")
	wantStatus(t, e.put(e.tA, "app", v2, sha256Hex([]byte(v1))), http.StatusOK, "")
	wantStatus(t, e.do(http.MethodDelete, e.path(e.tA, "app"), e.token(e.tA, recipeWriteRole), "", nil), http.StatusNoContent, "")

	recs := e.audit.records()
	type want struct{ action, outcome, before, after string }
	exp := []want{
		{recipeAuditPut, recipeOutcomeAttempted, "", sha256Hex([]byte(v1))},
		{recipeAuditPut, recipeOutcomeCreated, "", sha256Hex([]byte(v1))},
		{recipeAuditPut, recipeOutcomeAttempted, sha256Hex([]byte(v1)), sha256Hex([]byte(v2))},
		{recipeAuditPut, recipeOutcomeReplaced, sha256Hex([]byte(v1)), sha256Hex([]byte(v2))},
		{recipeAuditDelete, recipeOutcomeAttempted, sha256Hex([]byte(v2)), ""},
		{recipeAuditDelete, recipeOutcomeDeleted, sha256Hex([]byte(v2)), ""},
	}
	if len(recs) != len(exp) {
		t.Fatalf("%d records, want %d: %+v", len(recs), len(exp), recs)
	}
	for i, w := range exp {
		r := recs[i]
		if r.Action != w.action || r.Outcome != w.outcome || r.SHA256Before != w.before || r.SHA256After != w.after ||
			r.TenantID != e.tA || r.Caller != "user-of-"+e.tA || r.Name != "app" || r.Time.IsZero() {
			t.Errorf("record %d: %+v, want %+v", i, r, w)
		}
		if w.after != "" && r.SizeAfter != int64(len(v1)) {
			t.Errorf("record %d: size_after %d", i, r.SizeAfter)
		}
		b, _ := json.Marshal(r)
		if strings.Contains(string(b), bodyMarker) || strings.Contains(string(b), "cmd.run") {
			t.Errorf("record %d holds content: %s", i, b)
		}
	}
}

// TestRecipeAuditNeverHoldsContent pins the record's shape: no field that
// could carry recipe content.
func TestRecipeAuditNeverHoldsContent(t *testing.T) {
	b, _ := json.Marshal(RecipeAuditRecord{})
	var fields map[string]any
	_ = json.Unmarshal(b, &fields)
	for k := range fields {
		if strings.Contains(k, "content") || strings.Contains(k, "body") || strings.Contains(k, "source") {
			t.Errorf("audit record field %q", k)
		}
	}
}

// TestRecipeAuditFailsClosed: when the attempt can't be audited, nothing
// is stored or deleted.
func TestRecipeAuditFailsClosed(t *testing.T) {
	e := newRecipeEnv(t, nil)
	wantStatus(t, e.put(e.tA, "keep", recipeBody("k"), ""), http.StatusCreated, "")
	e.audit.mu.Lock()
	e.audit.fail = true
	e.audit.mu.Unlock()
	wantStatus(t, e.put(e.tA, "new", recipeBody("n"), ""), http.StatusServiceUnavailable, "audit_unavailable")
	w := e.do(http.MethodDelete, e.path(e.tA, "keep"), e.token(e.tA, recipeWriteRole), "", nil)
	wantStatus(t, w, http.StatusServiceUnavailable, "audit_unavailable")
	if _, ok := e.srv.Object("tenants/" + e.tA + "/recipes/new.imas"); ok {
		t.Error("stored without an audit record")
	}
	if _, ok := e.srv.Object("tenants/" + e.tA + "/recipes/keep.imas"); !ok {
		t.Error("deleted without an audit record")
	}
}

// TestRecipeObjectStoreAuditSink: the production sink writes one
// create-only JSON object per record under the tenant's audit prefix,
// without content.
func TestRecipeObjectStoreAuditSink(t *testing.T) {
	e := newRecipeEnv(t, nil)
	e.svc.audit = objectStoreAuditSink{store: e.store}
	wantStatus(t, e.put(e.tA, "app", recipeBody("x"), ""), http.StatusCreated, "")
	var audits []string
	for _, k := range e.srv.Keys() {
		if strings.HasPrefix(k, "tenants/"+e.tA+"/recipe-audit/") && strings.HasSuffix(k, ".json") {
			audits = append(audits, k)
		}
	}
	if len(audits) != 2 {
		t.Fatalf("audit objects %v (all keys %v)", audits, e.srv.Keys())
	}
	for _, k := range audits {
		content, _ := e.srv.Object(k)
		var rec RecipeAuditRecord
		if err := json.Unmarshal([]byte(content), &rec); err != nil || rec.TenantID != e.tA || rec.Name != "app" {
			t.Errorf("%s: %q %v", k, content, err)
		}
		if strings.Contains(content, bodyMarker) {
			t.Errorf("%s holds content", k)
		}
	}
	// The audit prefix is not a recipe: not listed, not resolvable.
	w := e.do(http.MethodGet, e.path(e.tA, ""), e.token(e.tA, recipeReadRole), "", nil)
	if list := decode[recipeListResponse](t, w); len(list.Recipes) != 1 {
		t.Errorf("listing %+v", list)
	}
}

func TestRecipesNotConfigured(t *testing.T) {
	e := newRecipeEnv(t, nil)
	e.svc.store = nil
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		w := e.do(m, e.path(e.tA, "app"), e.token(e.tA, recipeWriteRole), recipeBody("x"), map[string]string{"If-None-Match": "*"})
		wantStatus(t, w, http.StatusServiceUnavailable, "recipes_not_configured")
	}
	w := e.do(http.MethodGet, e.path(e.tA, ""), e.token(e.tA, recipeReadRole), "", nil)
	wantStatus(t, w, http.StatusServiceUnavailable, "recipes_not_configured")
}

func TestRecipeTenantState(t *testing.T) {
	e := newRecipeEnv(t, nil)
	pending, _ := newID("t_")
	db.Create(&Tenant{ID: pending, Name: "p", Status: TenantStatusPending})
	wantStatus(t, e.put(pending, "app", recipeBody("x"), ""), http.StatusConflict, "tenant_not_active")
	missing, _ := newID("t_")
	w := e.do(http.MethodGet, e.path(missing, ""), e.token(missing, recipeReadRole), "", nil)
	wantStatus(t, w, http.StatusNotFound, "tenant_not_found")
}

// TestRecipeInstallExample: the recipe in docs/INSTALL.md's "Upload a
// recipe" passes upload validation.
func TestRecipeInstallExample(t *testing.T) {
	doc, err := os.ReadFile("../../docs/INSTALL.md")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(doc), "cat > harden.imas <<'EOF'\n")
	body, _, ok2 := strings.Cut(rest, "\nEOF\n")
	if !ok || !ok2 {
		t.Fatal("docs/INSTALL.md has no harden.imas example")
	}
	if p := validateRecipeBody(context.Background(), []byte(body+"\n")); p != nil {
		t.Fatalf("the INSTALL.md example is refused: %s %s", p.code, p.message)
	}
	if err := validateUploadRecipeName("nginx.harden"); err != nil {
		t.Fatal(err)
	}
}
