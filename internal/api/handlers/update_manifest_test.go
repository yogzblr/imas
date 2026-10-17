package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/fleetsign"
)

// --- fixtures ---

// wireManifest is a well-formed manifest for version on os/arch as a
// .deb, as fleetcatalog.SQL would return it: the release's checksums.txt
// and a base64 signature. Farmer never verifies the signature, so any
// bytes do.
func wireManifest(t *testing.T, version, os, arch string) fleetsign.Manifest {
	t.Helper()
	name, err := fleetsign.ExpectedFileName(version, os, arch, "deb")
	if err != nil {
		t.Fatal(err)
	}
	return fleetsign.Manifest{
		Version:          version,
		OS:               os,
		Arch:             arch,
		PackageType:      "deb",
		MinSproutVersion: "v1.0.0",
		ChecksumsTxt:     strings.Repeat("ab", 32) + "  " + name + "\n",
		ChecksumsSig:     base64.StdEncoding.EncodeToString([]byte("detached signature bytes")),
	}
}

// fakeManifestStore answers from rows keyed the same way the SQL does:
// tenant approval first, then (version, os, arch, package_type).
type fakeManifestStore struct {
	approved map[string]string // tenant_id -> approved_version
	rows     map[[4]string]fleetsign.Manifest
	err      error
	calls    int
}

func (f *fakeManifestStore) ApprovedManifest(_ context.Context, tenantID, os, arch, packageType, version string) (fleetsign.Manifest, bool, error) {
	f.calls++
	if f.err != nil {
		return fleetsign.Manifest{}, false, f.err
	}
	if f.approved[tenantID] != version {
		return fleetsign.Manifest{}, false, nil
	}
	m, ok := f.rows[[4]string{version, os, arch, packageType}]
	return m, ok, nil
}

func installStore(t *testing.T, s UpdateManifestStore) {
	t.Helper()
	SetUpdateManifestStore(s)
	t.Cleanup(func() { SetUpdateManifestStore(nil) })
}

func manifestRequest(t *testing.T, id *SproutIdentity, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/sprout/update-manifest?"+query, nil)
	if id != nil {
		req = req.WithContext(WithSproutIdentity(req.Context(), *id))
	}
	rec := httptest.NewRecorder()
	GetSproutUpdateManifest(rec, req)
	return rec
}

var acmeWeb01 = SproutIdentity{TenantID: "t_acme", SproutID: "web-01"}

const acmeQuery = "os=linux&arch=amd64&package_type=deb&version=v2.4.1"

// --- handler ---

func TestUpdateManifest_ServesApprovedRelease(t *testing.T) {
	want := wireManifest(t, "v2.4.1", "linux", "amd64")
	installStore(t, &fakeManifestStore{
		approved: map[string]string{"t_acme": "v2.4.1"},
		rows:     map[[4]string]fleetsign.Manifest{{"v2.4.1", "linux", "amd64", "deb"}: want},
	})

	rec := manifestRequest(t, &acmeWeb01, acmeQuery)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d %s, want 200", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type %q", ct)
	}
	// fleetsign.ParseManifest refuses any key beyond the wire contract's
	// seven, so this is also the "no URL, no file name" check.
	got, err := fleetsign.ParseManifest(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("response is not a strict manifest: %v\n%s", err, rec.Body)
	}
	if got.Version != want.Version || got.OS != want.OS || got.Arch != want.Arch || got.PackageType != want.PackageType ||
		got.MinSproutVersion != want.MinSproutVersion || got.ChecksumsTxt != want.ChecksumsTxt || got.ChecksumsSig != want.ChecksumsSig {
		t.Errorf("got %+v, want %+v", got, want)
	}
	var keys map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &keys); err != nil {
		t.Fatal(err)
	}
	wantKeys := []string{"version", "os", "arch", "package_type", "min_sprout_version", "checksums_txt", "checksums_sig"}
	if len(keys) != len(wantKeys) {
		t.Errorf("response has %d keys, want exactly %v: %s", len(keys), wantKeys, rec.Body)
	}
	for _, k := range wantKeys {
		if _, ok := keys[k]; !ok {
			t.Errorf("response lacks %q: %s", k, rec.Body)
		}
	}
	assertNoURL(t, rec.Body.Bytes())
}

// assertNoURL fails if a manifest response carries a URL (requirements
// item 20, API design §1.8). It checks the JSON keys and the string values
// except checksums_sig: it is random base64, which can spell "url" or
// "http" by chance. "://" can never appear in base64, so the whole body is
// also checked for it.
func assertNoURL(t *testing.T, body []byte) {
	t.Helper()
	if strings.Contains(string(body), "://") {
		t.Errorf("response mentions a URL: %s", body)
	}
	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatalf("response is not a JSON object: %v\n%s", err, body)
	}
	mentionsURL := func(s string) bool {
		s = strings.ToLower(s)
		return strings.Contains(s, "url") || strings.Contains(s, "http")
	}
	for k, v := range fields {
		if mentionsURL(k) {
			t.Errorf("response has a URL-like key %q: %s", k, body)
		}
		if k == "checksums_sig" {
			continue
		}
		if s, ok := v.(string); ok && mentionsURL(s) {
			t.Errorf("response field %q mentions a URL: %q", k, s)
		}
	}
}

// TestUpdateManifest_RefusesRowsThatFailChecks: a manifest the store
// returns is still not served unless it matches the request and is well
// formed. Each refusal is the generic 404. Farmer verifies no signature
// (D20), so a manifest with a bad one is the sprout's to refuse.
func TestUpdateManifest_RefusesRowsThatFailChecks(t *testing.T) {
	good := wireManifest(t, "v2.4.1", "linux", "amd64")
	with := func(f func(*fleetsign.Manifest)) fleetsign.Manifest { m := good; f(&m); return m }
	for name, row := range map[string]fleetsign.Manifest{
		"row for another arch":        wireManifest(t, "v2.4.1", "linux", "arm64"),
		"row for another version":     wireManifest(t, "v2.4.2", "linux", "amd64"),
		"row of another package type": with(func(m *fleetsign.Manifest) { m.PackageType = "rpm" }),
		"no checksums":                with(func(m *fleetsign.Manifest) { m.ChecksumsTxt = "" }),
		"no signature":                with(func(m *fleetsign.Manifest) { m.ChecksumsSig = "" }),
		"signature not base64":        with(func(m *fleetsign.Manifest) { m.ChecksumsSig = "not base64!" }),
		"min_sprout_version above":    with(func(m *fleetsign.Manifest) { m.MinSproutVersion = "v9.0.0" }),
		"oversize checksums":          with(func(m *fleetsign.Manifest) { m.ChecksumsTxt = strings.Repeat("a", fleetsign.MaxChecksumsTxt+1) }),
		"invalid min_sprout_version":  with(func(m *fleetsign.Manifest) { m.MinSproutVersion = "1.0" }),
	} {
		t.Run(name, func(t *testing.T) {
			installStore(t, &fakeManifestStore{
				approved: map[string]string{"t_acme": "v2.4.1"},
				rows:     map[[4]string]fleetsign.Manifest{{"v2.4.1", "linux", "amd64", "deb"}: row},
			})
			rec := manifestRequest(t, &acmeWeb01, acmeQuery)
			assertGenericNotFound(t, rec)
		})
	}
}

// TestUpdateManifest_CatalogMissIsNotFound: no row (another tenant's
// approval, an unknown version, a version without checksums) is the
// generic 404.
func TestUpdateManifest_CatalogMissIsNotFound(t *testing.T) {
	installStore(t, &fakeManifestStore{approved: map[string]string{"t_acme": "v2.4.1"}})
	assertGenericNotFound(t, manifestRequest(t, &acmeWeb01, acmeQuery))
}

func assertGenericNotFound(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d %s, want 404", rec.Code, rec.Body)
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"error":"not_found"}` {
		t.Errorf("404 body %q, want the generic one", got)
	}
}

func TestUpdateManifest_UnavailableIsNotCached(t *testing.T) {
	store := &fakeManifestStore{
		approved: map[string]string{"t_acme": "v2.4.1"},
		rows:     map[[4]string]fleetsign.Manifest{{"v2.4.1", "linux", "amd64", "deb"}: wireManifest(t, "v2.4.1", "linux", "amd64")},
		err:      errors.New("pxc down"),
	}
	installStore(t, store)

	if rec := manifestRequest(t, &acmeWeb01, acmeQuery); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("store error: got %d, want 503", rec.Code)
	}
	store.err = nil
	if rec := manifestRequest(t, &acmeWeb01, acmeQuery); rec.Code != http.StatusOK {
		t.Fatalf("after recovery: got %d, want 200 (the error must not be cached)", rec.Code)
	}
}

func TestUpdateManifest_FailsClosedWithoutStore(t *testing.T) {
	installStore(t, nil)
	if rec := manifestRequest(t, &acmeWeb01, acmeQuery); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("got %d, want 503", rec.Code)
	}
}

func TestUpdateManifest_RequiresIdentity(t *testing.T) {
	installStore(t, &fakeManifestStore{})
	for name, id := range map[string]*SproutIdentity{
		"none":           nil,
		"empty tenant":   {SproutID: "web-01"},
		"empty sprout":   {TenantID: "t_acme"},
		"empty identity": {},
	} {
		t.Run(name, func(t *testing.T) {
			if rec := manifestRequest(t, id, acmeQuery); rec.Code != http.StatusUnauthorized {
				t.Errorf("got %d, want 401", rec.Code)
			}
		})
	}
}

func TestUpdateManifest_BadQuery(t *testing.T) {
	store := &fakeManifestStore{}
	installStore(t, store)
	for _, q := range []string{
		"os=linux&package_type=deb&version=v2.4.1",                       // missing arch
		"arch=amd64&version=v2.4.1",                                      // missing os
		"os=linux&arch=amd64&package_type=deb",                           // missing version
		"os=linux&arch=&package_type=deb&version=v2.4.1",                 // empty arch
		"os=linux&arch=amd64&arch=arm64&package_type=deb&version=v2.4.1", // repeated
		"os=Linux&arch=amd64&package_type=deb&version=v2.4.1",            // not lowercase
		"os=linux&arch=amd64%2F..&package_type=deb&version=v2.4.1",       // separator
		"os=linux&arch=amd64&package_type=deb&version=2.4.1",             // no leading v
		"os=linux&arch=amd64&package_type=deb&version=v2.4",              // not canonical
		"os=linux&arch=amd64&package_type=deb&version=v2.4.1%2Bbuild",    // build metadata
		"os=linux&arch=amd64&package_type=deb&version=v2.4.1%7Cx",        // separator
		"os=linux&arch=" + strings.Repeat("a", 33) + "&package_type=deb&version=v2.4.1",
		"os=linux&arch=amd64&version=v2.4.1",                                   // missing package_type
		"os=linux&arch=amd64&package_type=apk&version=v2.4.1",                  // unknown package_type
		"os=linux&arch=amd64&package_type=DEB&version=v2.4.1",                  // not lowercase
		"os=linux&arch=amd64&package_type=deb&package_type=rpm&version=v2.4.1", // repeated
	} {
		t.Run(q, func(t *testing.T) {
			// One sprout per case, so the per-sprout limit doesn't answer
			// before the query check does.
			id := SproutIdentity{TenantID: "t_acme", SproutID: "bad-" + t.Name()}
			rec := manifestRequest(t, &id, q)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("got %d, want 400", rec.Code)
			}
		})
	}
	if store.calls != 0 {
		t.Errorf("store read %d times for malformed queries, want 0", store.calls)
	}
}

func TestUpdateManifest_CachesPerTenant(t *testing.T) {
	row := wireManifest(t, "v2.4.1", "linux", "amd64")
	store := &fakeManifestStore{
		approved: map[string]string{"t_acme": "v2.4.1"},
		rows:     map[[4]string]fleetsign.Manifest{{"v2.4.1", "linux", "amd64", "deb"}: row},
	}
	installStore(t, store)

	// Many sprouts of one tenant: one read.
	for _, sprout := range []string{"web-01", "web-02", "web-03"} {
		id := SproutIdentity{TenantID: "t_acme", SproutID: sprout}
		if rec := manifestRequest(t, &id, acmeQuery); rec.Code != http.StatusOK {
			t.Fatalf("%s: got %d", sprout, rec.Code)
		}
	}
	if store.calls != 1 {
		t.Errorf("store read %d times, want 1", store.calls)
	}
	// Another tenant asking for the same (version, os, arch) — even
	// from a sprout with the same sprout_id — must not get t_acme's
	// cached answer.
	other := SproutIdentity{TenantID: "t_other", SproutID: "web-01"}
	assertGenericNotFound(t, manifestRequest(t, &other, acmeQuery))
	if store.calls != 2 {
		t.Errorf("store read %d times, want 2 (separate cache entry per tenant)", store.calls)
	}
}

func TestManifestCache_Expiry(t *testing.T) {
	c := &manifestCache{}
	now := time.Now()
	k := manifestCacheKey{tenantID: "t_acme", os: "linux", arch: "amd64", version: "v2.4.1"}
	m := fleetsign.Manifest{Version: "v2.4.1"}

	c.put(k, m, now)
	if _, found, ok := c.get(k, now.Add(manifestCacheTTL-time.Second)); !ok || !found {
		t.Error("entry should be served before its TTL")
	}
	if _, _, ok := c.get(k, now.Add(manifestCacheTTL)); ok {
		t.Error("entry served at its TTL")
	}
	c.put(k, m, now)
	if total, own := c.size("t_acme"); total != 1 || own != 1 {
		t.Errorf("replacing an entry: %d total, %d for the tenant; want 1, 1", total, own)
	}
}

func cacheKey(tenant string, i int) manifestCacheKey {
	return manifestCacheKey{tenantID: tenant, os: "linux", arch: "amd64", packageType: "deb", version: fmt.Sprintf("v1.0.%d", i)}
}

func setCacheBounds(t *testing.T, perTenant, total int) {
	t.Helper()
	origPer, origTotal := manifestCacheMaxPerTenant, manifestCacheMaxEntries
	manifestCacheMaxPerTenant, manifestCacheMaxEntries = perTenant, total
	t.Cleanup(func() { manifestCacheMaxPerTenant, manifestCacheMaxEntries = origPer, origTotal })
}

// TestManifestCache_PerTenantShare (security review L6): one tenant
// filling its share, again and again, evicts only its own entries; the
// other tenant's are all still served.
func TestManifestCache_PerTenantShare(t *testing.T) {
	if manifestCacheMaxPerTenant != 256 || manifestCacheMaxEntries != 4096 {
		t.Fatalf("bounds = %d per tenant, %d in total; want 256, 4096", manifestCacheMaxPerTenant, manifestCacheMaxEntries)
	}
	c := &manifestCache{}
	now := time.Now()
	m := fleetsign.Manifest{Version: "v1"}
	for i := 0; i < 10; i++ {
		c.put(cacheKey("t_quiet", i), m, now)
	}
	for i := 0; i < 50*manifestCacheMaxPerTenant; i++ {
		c.put(cacheKey("t_noisy", i), m, now.Add(time.Duration(i)*time.Millisecond))
		if total, own := c.size("t_noisy"); own > manifestCacheMaxPerTenant || total > manifestCacheMaxEntries {
			t.Fatalf("after %d puts: %d for t_noisy, %d in total", i+1, own, total)
		}
	}
	for i := 0; i < 10; i++ {
		if _, found, ok := c.get(cacheKey("t_quiet", i), now.Add(time.Second)); !ok || !found {
			t.Fatalf("t_quiet's entry %d was evicted by t_noisy", i)
		}
	}
	if total, own := c.size("t_noisy"); own != manifestCacheMaxPerTenant || total != manifestCacheMaxPerTenant+10 {
		t.Errorf("t_noisy holds %d, total %d; want %d and %d", own, total, manifestCacheMaxPerTenant, manifestCacheMaxPerTenant+10)
	}
	// t_noisy's newest entry is kept; the one closest to expiry went.
	last := 50*manifestCacheMaxPerTenant - 1
	if _, found, _ := c.get(cacheKey("t_noisy", last), now.Add(time.Second)); !found {
		t.Error("t_noisy's newest entry was evicted")
	}
	if _, found, _ := c.get(cacheKey("t_noisy", 0), now.Add(time.Second)); found {
		t.Error("t_noisy's oldest entry survived its tenant's eviction")
	}
}

// TestManifestCache_TotalBound: with the total cap reached by other
// tenants' live entries, a new tenant's entry is not cached rather than
// evicting theirs; expired entries make room.
func TestManifestCache_TotalBound(t *testing.T) {
	setCacheBounds(t, 3, 6)
	c := &manifestCache{}
	now := time.Now()
	m := fleetsign.Manifest{Version: "v1"}
	for _, tenant := range []string{"t_a", "t_b"} {
		for i := 0; i < 5; i++ {
			c.put(cacheKey(tenant, i), m, now)
		}
	}
	if total, own := c.size("t_a"); total != 6 || own != 3 {
		t.Fatalf("%d total, %d for t_a; want 6, 3", total, own)
	}
	c.put(cacheKey("t_c", 0), m, now)
	if _, found, _ := c.get(cacheKey("t_c", 0), now); found {
		t.Error("cached over the total bound")
	}
	if total, _ := c.size("t_c"); total != 6 {
		t.Errorf("total %d, want 6: nobody else's entry evicted", total)
	}
	later := now.Add(manifestCacheTTL)
	c.put(cacheKey("t_c", 0), m, later)
	if _, found, _ := c.get(cacheKey("t_c", 0), later); !found {
		t.Error("not cached once the other entries expired")
	}
	if total, own := c.size("t_c"); total != 1 || own != 1 {
		t.Errorf("%d total, %d for t_c; want 1, 1 (expired entries dropped)", total, own)
	}
}

// TestUpdateManifest_NotFoundNotCached (security review L6): a 404 is
// read from the store every time, so a new approval is served at once,
// and a tenant's misses take no cache space.
func TestUpdateManifest_NotFoundNotCached(t *testing.T) {
	row := wireManifest(t, "v2.4.1", "linux", "amd64")
	store := &fakeManifestStore{
		approved: map[string]string{},
		rows:     map[[4]string]fleetsign.Manifest{{"v2.4.1", "linux", "amd64", "deb"}: row},
	}
	installStore(t, store)
	for i, sprout := range []string{"web-01", "web-02"} {
		id := SproutIdentity{TenantID: "t_acme", SproutID: sprout}
		assertGenericNotFound(t, manifestRequest(t, &id, acmeQuery))
		if store.calls != i+1 {
			t.Fatalf("store read %d times after %d misses", store.calls, i+1)
		}
	}
	if total, own := updateManifests.size("t_acme"); total != 0 || own != 0 {
		t.Errorf("misses cached: %d entries", total)
	}
	store.approved["t_acme"] = "v2.4.1"
	id := SproutIdentity{TenantID: "t_acme", SproutID: "web-03"}
	if rec := manifestRequest(t, &id, acmeQuery); rec.Code != http.StatusOK {
		t.Fatalf("after approval: got %d, want 200 at once", rec.Code)
	}
}

// --- rate limit ---

func TestSproutLimiter_KeyedOnTenantAndSprout(t *testing.T) {
	l := &sproutLimiter{}
	now := time.Now()
	acme := SproutIdentity{TenantID: "t_acme", SproutID: "web-01"}
	for i := 0; i < manifestRateBurst; i++ {
		if ok, _ := l.allow(acme, now); !ok {
			t.Fatalf("request %d within the burst refused", i+1)
		}
	}
	ok, retry := l.allow(acme, now)
	if ok {
		t.Fatal("request beyond the burst allowed")
	}
	if retry <= 0 || retry > manifestRateEvery {
		t.Errorf("retry after %s, want (0, %s]", retry, manifestRateEvery)
	}

	// The same sprout_id in another tenant, and another sprout in the
	// same tenant, have their own budgets.
	for _, id := range []SproutIdentity{
		{TenantID: "t_other", SproutID: "web-01"},
		{TenantID: "t_acme", SproutID: "web-02"},
	} {
		if ok, _ := l.allow(id, now); !ok {
			t.Errorf("%+v refused: shares t_acme/web-01's bucket", id)
		}
	}

	// A refused request doesn't spend tokens: it refills on schedule.
	if ok, _ := l.allow(acme, now.Add(manifestRateEvery)); !ok {
		t.Error("not refilled after one interval")
	}
}

func TestSproutLimiter_EvictsIdleBuckets(t *testing.T) {
	l := &sproutLimiter{}
	now := time.Now()
	l.allow(SproutIdentity{TenantID: "t_acme", SproutID: "web-01"}, now)
	l.allow(SproutIdentity{TenantID: "t_acme", SproutID: "web-02"}, now.Add(manifestLimiterIdle))
	if n := len(l.buckets); n != 1 {
		t.Errorf("%d buckets after the idle one should have been swept, want 1", n)
	}
}

func TestUpdateManifest_RateLimited(t *testing.T) {
	store := &fakeManifestStore{
		approved: map[string]string{"t_acme": "v2.4.1"},
		rows:     map[[4]string]fleetsign.Manifest{{"v2.4.1", "linux", "amd64", "deb"}: wireManifest(t, "v2.4.1", "linux", "amd64")},
	}
	installStore(t, store)

	for i := 0; i < manifestRateBurst; i++ {
		if rec := manifestRequest(t, &acmeWeb01, acmeQuery); rec.Code != http.StatusOK {
			t.Fatalf("request %d: got %d", i+1, rec.Code)
		}
	}
	rec := manifestRequest(t, &acmeWeb01, acmeQuery)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 without Retry-After")
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] != "rate_limited" {
		t.Errorf("429 body %q", rec.Body)
	}
	// Malformed requests count too: the limit is per sprout, not per
	// successful lookup.
	if rec := manifestRequest(t, &acmeWeb01, "os=linux"); rec.Code != http.StatusTooManyRequests {
		t.Errorf("malformed request while limited: got %d, want 429", rec.Code)
	}
}
