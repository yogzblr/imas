package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/taigrr/jety"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/api/handlers"
	"github.com/yogzblr/imas/internal/fleetsign"
)

// GET /v1/sprout/update-manifest end to end: NewRouter, Auth's gateway
// JWT check, and the production SQL over farmer's handle
// (handlers.SetReadinessDB), with saas.* in an attached SQLite database.

type fleetKeys fleetsign.KeySet

func (k fleetKeys) KeySet(context.Context) (fleetsign.KeySet, error) { return fleetsign.KeySet(k), nil }

// manifestFixture is a saas schema with:
//
//	t_acme    approved v2.4.1  (rows linux/amd64, linux/arm64, windows/amd64)
//	t_other   approved v2.5.0  (row linux/amd64)
//	t_revoked approved v2.3.0  (row linux/amd64, revoked)
//	t_none    no policy row
//	t_null    policy row, approved_version NULL
//
// every row signed by the installed fleet key.
type manifestFixture struct {
	srv  *httptest.Server
	gw   testGatewayKey
	rows map[string]fleetsign.Manifest // "version os arch" -> served manifest
}

func newManifestFixture(t *testing.T) *manifestFixture {
	t.Helper()
	gw := installGatewayKey(t)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := fleetsign.NewKeySet([]fleetsign.PublicKey{{Version: 1, Key: pub}})
	if err != nil {
		t.Fatal(err)
	}
	handlers.SetFleetKeySource(fleetKeys(ks))
	t.Cleanup(func() { handlers.SetFleetKeySource(nil) })

	db := newSaasTestDB(t)
	f := &manifestFixture{gw: gw, rows: map[string]fleetsign.Manifest{}}
	insert := func(version, os, arch string, revoked bool) {
		m := fleetsign.Manifest{
			Version:          version,
			OS:               os,
			Arch:             arch,
			FileName:         fmt.Sprintf("imas-sprout_%s_%s_%s.pkg", strings.TrimPrefix(version, "v"), os, arch),
			ChecksumSHA256:   strings.Repeat("0123456789abcdef", 4),
			MinSproutVersion: "v1.0.0",
		}
		msg, err := m.Message()
		if err != nil {
			t.Fatal(err)
		}
		m.Signature = fleetsign.EncodeSignature(1, ed25519.Sign(priv, msg))
		exec(t, db, `INSERT INTO saas.fleet_versions
			(id, version, os, arch, package_type, file_name, checksum_sha256, min_sprout_version, signature, revoked, released_at)
			VALUES (?, ?, ?, ?, 'deb', ?, ?, ?, ?, ?, ?)`,
			version+os+arch, m.Version, m.OS, m.Arch, m.FileName, m.ChecksumSHA256, m.MinSproutVersion, m.Signature, revoked, time.Now())
		f.rows[version+" "+os+" "+arch] = m
	}
	insert("v2.4.1", "linux", "amd64", false)
	insert("v2.4.1", "linux", "arm64", false)
	insert("v2.4.1", "windows", "amd64", false)
	insert("v2.5.0", "linux", "amd64", false)
	insert("v2.3.0", "linux", "amd64", true)
	for tenant, version := range map[string]any{
		"t_acme": "v2.4.1", "t_other": "v2.5.0", "t_revoked": "v2.3.0", "t_null": nil,
	} {
		exec(t, db, `INSERT INTO saas.tenant_update_policy (tenant_id, approved_version, auto_update) VALUES (?, ?, 0)`, tenant, version)
	}

	handlers.SetReadinessDB(db)
	t.Cleanup(func() { handlers.SetReadinessDB(nil) })

	f.srv = httptest.NewServer(NewRouter(""))
	t.Cleanup(f.srv.Close)
	return f
}

// newSaasTestDB opens an in-memory SQLite database with an attached
// "saas" database holding fleet_versions and tenant_update_policy in the
// columns internal/migrations/saas gives them, so the production query's
// schema-qualified names resolve. One connection: ATTACH is
// per-connection.
func newSaasTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	name := strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	db, err := gorm.Open(sqlite.Open("file:"+name+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { sqlDB.Close() })
	exec(t, db, `ATTACH DATABASE 'file:`+name+`_saas?mode=memory&cache=shared' AS saas`)
	exec(t, db, `CREATE TABLE saas.fleet_versions (
		id varchar(32) PRIMARY KEY,
		version varchar(64) NOT NULL,
		os varchar(32) NOT NULL,
		arch varchar(32) NOT NULL,
		package_type varchar(16) NOT NULL,
		file_name varchar(255) NOT NULL,
		checksum_sha256 varchar(64) NOT NULL,
		min_sprout_version varchar(64) NOT NULL,
		signature varchar(128) NOT NULL DEFAULT '',
		revoked tinyint(1) NOT NULL DEFAULT 0,
		released_at datetime NOT NULL,
		notes text,
		UNIQUE (version, os, arch))`)
	exec(t, db, `CREATE TABLE saas.tenant_update_policy (
		tenant_id varchar(32) PRIMARY KEY,
		approved_version varchar(64) DEFAULT NULL,
		auto_update tinyint(1) NOT NULL DEFAULT 0,
		rollout_window_start datetime DEFAULT NULL,
		rollout_window_end datetime DEFAULT NULL,
		updated_at datetime DEFAULT NULL)`)
	return db
}

func exec(t *testing.T, db *gorm.DB, sql string, args ...any) {
	t.Helper()
	if err := db.Exec(sql, args...).Error; err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (f *manifestFixture) bearer(t *testing.T, tenantID, sproutID string) string {
	t.Helper()
	return "Bearer " + mint(t, f.gw.priv, tenantID, sproutID, time.Now().Add(time.Hour))
}

func (f *manifestFixture) get(t *testing.T, authz, os, arch, version string) (int, string) {
	t.Helper()
	q := url.Values{}
	if os != "" {
		q.Set("os", os)
	}
	if arch != "" {
		q.Set("arch", arch)
	}
	if version != "" {
		q.Set("version", version)
	}
	return get(t, f.srv.URL+"/v1/sprout/update-manifest?"+q.Encode(), authz)
}

const genericNotFound = "{\"error\":\"not_found\"}\n"

func TestUpdateManifestRoute_ServesOwnTenantsApprovedRow(t *testing.T) {
	f := newManifestFixture(t)
	authz := f.bearer(t, "t_acme", "web-01")

	for _, c := range []struct{ os, arch string }{
		{"linux", "amd64"}, {"linux", "arm64"}, {"windows", "amd64"},
	} {
		code, body := f.get(t, authz, c.os, c.arch, "v2.4.1")
		if code != http.StatusOK {
			t.Fatalf("%s/%s: got %d %s, want 200", c.os, c.arch, code, body)
		}
		got, err := fleetsign.ParseManifest([]byte(body))
		if err != nil {
			t.Fatalf("%s/%s: not a strict manifest: %v", c.os, c.arch, err)
		}
		if want := f.rows["v2.4.1 "+c.os+" "+c.arch]; got != want {
			t.Errorf("%s/%s: got %+v, want %+v", c.os, c.arch, got, want)
		}
	}
}

// TestUpdateManifestRoute_NoURLInResponse: the body is exactly the seven
// manifest fields; nothing URL-shaped, whatever was asked.
func TestUpdateManifestRoute_NoURLInResponse(t *testing.T) {
	f := newManifestFixture(t)
	code, body := f.get(t, f.bearer(t, "t_acme", "web-01"), "linux", "amd64", "v2.4.1")
	if code != http.StatusOK {
		t.Fatalf("got %d", code)
	}
	if _, err := fleetsign.ParseManifest([]byte(body)); err != nil {
		t.Fatalf("response has fields beyond the signed manifest: %v\n%s", err, body)
	}
	lower := strings.ToLower(body)
	for _, s := range []string{"url", "http", "://", "artifact", "repo"} {
		if strings.Contains(lower, s) {
			t.Errorf("response contains %q: %s", s, body)
		}
	}
}

// TestUpdateManifestRoute_CrossTenantIsolation: a tenant gets only the
// version it approved, never another tenant's — including when its
// sprout shares a sprout_id with the other tenant's, and when it names
// the other tenant in the query.
func TestUpdateManifestRoute_CrossTenantIsolation(t *testing.T) {
	f := newManifestFixture(t)

	// t_other approved v2.5.0; t_acme did not.
	if code, body := f.get(t, f.bearer(t, "t_acme", "web-01"), "linux", "amd64", "v2.5.0"); code != http.StatusNotFound || body != genericNotFound {
		t.Errorf("t_acme asking for t_other's version: got %d %s, want generic 404", code, body)
	}
	// And the other way round, from a sprout named like t_acme's.
	if code, body := f.get(t, f.bearer(t, "t_other", "web-01"), "linux", "amd64", "v2.4.1"); code != http.StatusNotFound || body != genericNotFound {
		t.Errorf("t_other asking for t_acme's version: got %d %s, want generic 404", code, body)
	}
	// t_other's own version still works, so the 404s above are isolation,
	// not a broken fixture.
	if code, _ := f.get(t, f.bearer(t, "t_other", "web-01"), "linux", "amd64", "v2.5.0"); code != http.StatusOK {
		t.Errorf("t_other's own version: got %d, want 200", code)
	}

	// The tenant is the JWT's: query parameters naming another tenant are
	// ignored.
	for _, param := range []string{"tenant_id", "tenant", "tenantId"} {
		u := f.srv.URL + "/v1/sprout/update-manifest?os=linux&arch=amd64&version=v2.5.0&" + param + "=t_other"
		if code, body := get(t, u, f.bearer(t, "t_acme", "web-02")); code != http.StatusNotFound || body != genericNotFound {
			t.Errorf("t_acme with %s=t_other: got %d %s, want generic 404", param, code, body)
		}
	}
}

// TestUpdateManifestRoute_NotServedIsOneGeneric404: unapproved, revoked,
// unknown, no row for the arch, no policy, and a NULL approval all give
// byte-identical responses.
func TestUpdateManifestRoute_NotServedIsOneGeneric404(t *testing.T) {
	f := newManifestFixture(t)
	cases := []struct {
		name, tenant, os, arch, version string
	}{
		{"registered but not approved by this tenant", "t_acme", "linux", "amd64", "v2.5.0"},
		{"approved but revoked", "t_revoked", "linux", "amd64", "v2.3.0"},
		{"revoked and not approved", "t_acme", "linux", "amd64", "v2.3.0"},
		{"unknown version", "t_acme", "linux", "amd64", "v9.9.9"},
		{"approved version, no row for this arch", "t_acme", "linux", "riscv64", "v2.4.1"},
		{"approved version, no row for this os", "t_acme", "darwin", "amd64", "v2.4.1"},
		{"approved version, arch registered only for another os", "t_other", "linux", "arm64", "v2.5.0"},
		{"tenant without a policy row", "t_none", "linux", "amd64", "v2.4.1"},
		{"tenant with no approved version", "t_null", "linux", "amd64", "v2.4.1"},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// A sprout per case, clear of the per-sprout limit.
			code, body := f.get(t, f.bearer(t, c.tenant, fmt.Sprintf("s-%d", i)), c.os, c.arch, c.version)
			if code != http.StatusNotFound || body != genericNotFound {
				t.Errorf("got %d %q, want 404 %q", code, body, genericNotFound)
			}
		})
	}
}

func TestUpdateManifestRoute_MissingParameter(t *testing.T) {
	f := newManifestFixture(t)
	for i, c := range []struct{ name, os, arch, version string }{
		{"missing arch", "linux", "", "v2.4.1"},
		{"missing os", "", "amd64", "v2.4.1"},
		{"missing version", "linux", "amd64", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, _ := f.get(t, f.bearer(t, "t_acme", fmt.Sprintf("p-%d", i)), c.os, c.arch, c.version)
			if code != http.StatusBadRequest {
				t.Errorf("got %d, want 400", code)
			}
		})
	}
}

func TestUpdateManifestRoute_BadJWT(t *testing.T) {
	f := newManifestFixture(t)
	_, untrusted, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	valid := mint(t, f.gw.priv, "t_acme", "web-01", time.Now().Add(time.Hour))

	cases := map[string]struct {
		authz string
		want  int
	}{
		"no Authorization":            {"", http.StatusUnauthorized},
		"empty bearer":                {"Bearer ", http.StatusUnauthorized},
		"CLI-style bare token":        {"eyJ0b2tlbiI6ImFiYyJ9", http.StatusUnauthorized},
		"raw JWT without Bearer":      {valid, http.StatusUnauthorized},
		"signed by an untrusted key":  {"Bearer " + mint(t, untrusted, "t_acme", "web-01", time.Now().Add(time.Hour)), http.StatusForbidden},
		"expired":                     {"Bearer " + mint(t, f.gw.priv, "t_acme", "web-01", time.Now().Add(-time.Minute)), http.StatusForbidden},
		"tampered signature":          {"Bearer " + valid[:len(valid)-4] + "AAAA", http.StatusForbidden},
		"not a JWT":                   {"Bearer garbage", http.StatusForbidden},
		"tenant_id not a key segment": {"Bearer " + mint(t, f.gw.priv, "t_acme/..", "web-01", time.Now().Add(time.Hour)), http.StatusForbidden},
		"empty sprout_id":             {"Bearer " + mint(t, f.gw.priv, "t_acme", "", time.Now().Add(time.Hour)), http.StatusForbidden},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			code, body := f.get(t, c.authz, "linux", "amd64", "v2.4.1")
			if code != c.want {
				t.Errorf("got %d, want %d", code, c.want)
			}
			if strings.Contains(body, "file_name") || strings.Contains(body, "checksum") {
				t.Errorf("manifest leaked to an unauthenticated caller: %s", body)
			}
		})
	}
}

// TestUpdateManifestRoute_NoGatewaySigner: with no gateway key source
// configured, a bearer token is refused rather than trusted unverified.
func TestUpdateManifestRoute_NoGatewaySigner(t *testing.T) {
	f := newManifestFixture(t)
	authz := f.bearer(t, "t_acme", "web-01")
	orig := gatewayKeys
	gatewayKeys = handlers.GatewayKeySource // no signer installed: nil
	t.Cleanup(func() { gatewayKeys = orig })
	if code, _ := f.get(t, authz, "linux", "amd64", "v2.4.1"); code != http.StatusForbidden {
		t.Errorf("got %d, want 403", code)
	}
}

// TestUpdateManifestRoute_DangerouslyAllowRootDoesNotBypass: the dev
// bypass opens CLI routes, but this route has no tenant without a JWT.
func TestUpdateManifestRoute_DangerouslyAllowRootDoesNotBypass(t *testing.T) {
	f := newManifestFixture(t)
	jety.Set("dangerously_allow_root", true)
	t.Cleanup(func() { jety.Set("dangerously_allow_root", false) })
	if code, _ := f.get(t, "", "linux", "amd64", "v2.4.1"); code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", code)
	}
}

func TestUpdateManifestRoute_RateLimitedPerSprout(t *testing.T) {
	f := newManifestFixture(t)
	web01 := f.bearer(t, "t_acme", "web-01")
	var last int
	for i := 0; i < 20; i++ {
		if last, _ = f.get(t, web01, "linux", "amd64", "v2.4.1"); last == http.StatusTooManyRequests {
			break
		}
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("20 requests from one sprout never limited (last %d)", last)
	}
	// Same sprout_id, another tenant: its own budget.
	if code, _ := f.get(t, f.bearer(t, "t_other", "web-01"), "linux", "amd64", "v2.5.0"); code != http.StatusOK {
		t.Errorf("t_other/web-01 limited by t_acme/web-01: got %d", code)
	}
	// Another sprout of the same tenant: its own budget too.
	if code, _ := f.get(t, f.bearer(t, "t_acme", "web-02"), "linux", "amd64", "v2.4.1"); code != http.StatusOK {
		t.Errorf("t_acme/web-02 limited by t_acme/web-01: got %d", code)
	}
}
