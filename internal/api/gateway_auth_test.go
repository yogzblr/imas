package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/taigrr/jety"

	"github.com/yogzblr/imas/internal/api/handlers"
	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/gatewayjwt"
	"github.com/yogzblr/imas/internal/objectstore/objectstoretest"
)

// testGatewayKey is an in-memory stand-in for the gateway Transit key:
// installed as Auth's verification key source, and used to sign tokens
// in the same shape gatewayjwt.MintGatewayJWT produces.
type testGatewayKey struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func (k testGatewayKey) PublicKeys(context.Context) ([]gatewayjwt.TransitKeyVersion, error) {
	return []gatewayjwt.TransitKeyVersion{{Version: 1, PublicKey: k.pub}}, nil
}

// installGatewayKey also stands in for the revocation check
// (gatewaySubjectCheck) with one that passes every subject: these tests
// are about signature and scoping, and most run without a pki database.
// gateway_revocation_test.go puts the real check back
// (useRealGatewaySubjectCheck).
func installGatewayKey(t *testing.T) testGatewayKey {
	t.Helper()
	origCheck := gatewaySubjectCheck
	gatewaySubjectCheck = func(string, string, string) error { return nil }
	t.Cleanup(func() { gatewaySubjectCheck = origCheck })
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k := testGatewayKey{pub: pub, priv: priv}
	orig := gatewayKeys
	gatewayKeys = func() gatewayjwt.PublicKeySource { return k }
	t.Cleanup(func() { gatewayKeys = orig })
	return k
}

// mint signs a gateway JWT for (tenantID, sproutID) with priv.
func mint(t *testing.T, priv ed25519.PrivateKey, tenantID, sproutID string, exp time.Time) string {
	t.Helper()
	tok, err := jwt.NewBuilder().
		Subject("UTESTSPROUTNKEY").
		Issuer(gatewayjwt.GatewayIssuer).
		IssuedAt(time.Now()).
		Expiration(exp).
		Claim("tenant_id", tenantID).
		Claim("sprout_id", sproutID).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	hdrs := jws.NewHeaders()
	if err := hdrs.Set(jws.KeyIDKey, "1"); err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA, priv, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

const (
	ownFile          = "sprouts/t_acme/web-01/nginx.conf"
	ownFileContent   = "own sprout's file"
	otherSproutFile  = "sprouts/t_acme/web-02/nginx.conf"
	otherTenantFile  = "sprouts/t_other/web-01/nginx.conf" // same sprout_id, other tenant
	prefixTwinFile   = "sprouts/t_acme/web-010/nginx.conf"
	sharedRecipeFile = "recipes/webserver/nginx.imas"
)

// newGatewayTestServer serves NewRouter over an in-memory recipe store
// seeded with one file per scoping case.
func newGatewayTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	store := objectstoretest.NewStore(t)
	objectstoretest.Seed(t, store, map[string]string{
		ownFile:          ownFileContent,
		otherSproutFile:  "web-02's file",
		otherTenantFile:  "t_other's web-01 file",
		prefixTwinFile:   "web-010's file",
		sharedRecipeFile: "pkg.installed:\n  - name: nginx\n",
	})
	handlers.SetRecipeStore(store)
	t.Cleanup(func() { handlers.SetRecipeStore(nil) })

	origDir := config.RecipeDir
	config.RecipeDir = "recipes"
	t.Cleanup(func() { config.RecipeDir = origDir })

	srv := httptest.NewServer(NewRouter(""))
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, url, authz string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestFilesRoute_AcceptsCorrectlyScopedGatewayJWT(t *testing.T) {
	key := installGatewayKey(t)
	srv := newGatewayTestServer(t)

	token := mint(t, key.priv, "t_acme", "web-01", time.Now().Add(time.Hour))
	code, body := get(t, srv.URL+"/files/"+ownFile, "Bearer "+token)
	if code != http.StatusOK {
		t.Fatalf("GET own file with valid gateway JWT: got %d, want 200", code)
	}
	if body != ownFileContent {
		t.Errorf("body: got %q, want %q", body, ownFileContent)
	}
}

func TestFilesRoute_RejectsInvalidGatewayJWT(t *testing.T) {
	key := installGatewayKey(t)
	srv := newGatewayTestServer(t)

	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	valid := mint(t, key.priv, "t_acme", "web-01", time.Now().Add(time.Hour))

	cases := map[string]string{
		"signed by an untrusted key": mint(t, otherPriv, "t_acme", "web-01", time.Now().Add(time.Hour)),
		"expired":                    mint(t, key.priv, "t_acme", "web-01", time.Now().Add(-time.Minute)),
		"tampered signature":         valid[:len(valid)-4] + "AAAA",
		"not a JWT":                  "garbage",
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			if code, _ := get(t, srv.URL+"/files/"+ownFile, "Bearer "+token); code != http.StatusForbidden {
				t.Errorf("got %d, want 403", code)
			}
		})
	}
}

// TestFilesRoute_ValidGatewayJWTScopedToOwnSprout: a valid gateway JWT
// grants its own sprout's subtree and nothing else.
func TestFilesRoute_ValidGatewayJWTScopedToOwnSprout(t *testing.T) {
	key := installGatewayKey(t)
	srv := newGatewayTestServer(t)
	token := "Bearer " + mint(t, key.priv, "t_acme", "web-01", time.Now().Add(time.Hour))

	for name, file := range map[string]string{
		"another sprout, same tenant":        otherSproutFile,
		"same sprout_id, another tenant":     otherTenantFile,
		"sprout_id that shares a prefix":     prefixTwinFile,
		"shared recipe tree":                 sharedRecipeFile,
		"missing file in another sprout dir": "sprouts/t_acme/web-02/missing",
	} {
		t.Run(name, func(t *testing.T) {
			if code, _ := get(t, srv.URL+"/files/"+file, token); code != http.StatusForbidden {
				t.Errorf("GET %s: got %d, want 403", file, code)
			}
		})
	}
}

// TestFilesRoute_GatewayJWTRejectsUncleanKeys exercises Auth directly,
// since http.ServeMux would redirect some of these paths before Auth
// ever saw them.
func TestFilesRoute_GatewayJWTRejectsUncleanKeys(t *testing.T) {
	key := installGatewayKey(t)
	token := "Bearer " + mint(t, key.priv, "t_acme", "web-01", time.Now().Add(time.Hour))

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := Auth(inner, "FileServer")

	for _, path := range []string{
		"/files/sprouts/t_acme/web-01/../web-02/nginx.conf",
		"/files/sprouts/t_acme/web-01/./nginx.conf",
		"/files/sprouts/t_acme/web-01//nginx.conf",
		"/files/sprouts/t_acme/web-01/",
		"/files/sprouts/t_acme/web-01",
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.URL.Path = path
		req.Header.Set("Authorization", token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: got %d, want 403", path, rec.Code)
		}
	}
}

func TestFilesRoute_GatewayJWTWithSlashInClaimsRejected(t *testing.T) {
	key := installGatewayKey(t)
	srv := newGatewayTestServer(t)

	// tenant "t_acme/web-01" + sprout "x" would otherwise map onto
	// sprouts/t_acme/web-01/x/..., inside another sprout's subtree.
	token := mint(t, key.priv, "t_acme/web-01", "x", time.Now().Add(time.Hour))
	if code, _ := get(t, srv.URL+"/files/sprouts/t_acme/web-01/x/nginx.conf", "Bearer "+token); code != http.StatusForbidden {
		t.Errorf("got %d, want 403", code)
	}
}

func TestFilesRoute_GatewayJWTFailsClosedWithoutSigner(t *testing.T) {
	key := installGatewayKey(t)
	token := mint(t, key.priv, "t_acme", "web-01", time.Now().Add(time.Hour))
	gatewayKeys = func() gatewayjwt.PublicKeySource { return nil }
	srv := newGatewayTestServer(t)

	if code, _ := get(t, srv.URL+"/files/"+ownFile, "Bearer "+token); code != http.StatusForbidden {
		t.Errorf("got %d, want 403", code)
	}
}

// TestRecipesRoutes_GoneForGatewayJWT: the HTTP recipe routes were
// removed (CL.4). Neither an invalid nor a valid, correctly-scoped
// gateway JWT finds anything there.
func TestRecipesRoutes_GoneForGatewayJWT(t *testing.T) {
	key := installGatewayKey(t)
	srv := newGatewayTestServer(t)

	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tokens := map[string]string{
		"invalid gateway JWT": mint(t, otherPriv, "t_acme", "web-01", time.Now().Add(time.Hour)),
		"valid gateway JWT":   mint(t, key.priv, "t_acme", "web-01", time.Now().Add(time.Hour)),
	}
	for _, path := range []string{"/v1/recipes", "/v1/recipes/webserver.nginx"} {
		for name, token := range tokens {
			t.Run(path+"/"+name, func(t *testing.T) {
				if code, _ := get(t, srv.URL+path, "Bearer "+token); code != http.StatusNotFound {
					t.Errorf("got %d, want 404", code)
				}
			})
		}
	}
}

// With dangerously_allow_root set, GET /files/ still needs a gateway JWT,
// and a tenant's JWT still reads only its own sprout's files (owner
// decision 2026-10-04, PR #95: "remove the HTTP bypass too in PR 95").
func TestFilesRoute_DangerouslyAllowRootBypassesNothing(t *testing.T) {
	key := installGatewayKey(t)
	srv := newGatewayTestServer(t)
	jety.Set("dangerously_allow_root", true)
	t.Cleanup(func() { jety.Set("dangerously_allow_root", false) })

	if code, body := get(t, srv.URL+"/files/"+ownFile, ""); code != http.StatusUnauthorized || body == ownFileContent {
		t.Errorf("no JWT: %d %q, want 401", code, body)
	}
	tenantA := "Bearer " + mint(t, key.priv, "t_acme", "web-01", time.Now().Add(time.Hour))
	if code, body := get(t, srv.URL+"/files/"+otherTenantFile, tenantA); code != http.StatusForbidden {
		t.Errorf("tenant t_acme's JWT reading t_other's file: %d %q, want 403", code, body)
	}
	if code, _ := get(t, srv.URL+"/files/"+otherSproutFile, tenantA); code != http.StatusForbidden {
		t.Errorf("web-01's JWT reading web-02's file: %d, want 403", code)
	}
	if code, body := get(t, srv.URL+"/files/"+ownFile, tenantA); code != http.StatusOK || body != ownFileContent {
		t.Errorf("own file: %d %q", code, body)
	}
	for _, path := range []string{"/v1/recipes", "/v1/recipes/webserver.nginx"} {
		if code, _ := get(t, srv.URL+path, ""); code != http.StatusNotFound {
			t.Errorf("%s with the flag set: %d, want 404", path, code)
		}
	}
}
