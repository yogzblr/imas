package handlers

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/fleetsign"
)

// --- fixtures ---

// staticFleetKeys is a fleetsign.KeySetSource over a fixed key set,
// standing in for farmer's read-only Transit client (internal/fleetsign's
// own tests cover that client).
type staticFleetKeys struct {
	ks  fleetsign.KeySet
	err error
}

func (s staticFleetKeys) KeySet(context.Context) (fleetsign.KeySet, error) { return s.ks, s.err }

// installFleetKey installs a fresh imas-fleet-signing stand-in as the
// fleet key source (staticFleetKeys) and returns its private half.
func installFleetKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := fleetsign.NewKeySet([]fleetsign.PublicKey{{Version: 1, Key: pub}})
	if err != nil {
		t.Fatal(err)
	}
	orig := fleetKeySource
	SetFleetKeySource(staticFleetKeys{ks: ks})
	t.Cleanup(func() { SetFleetKeySource(orig) })
	return priv
}

func signedManifest(t *testing.T, priv ed25519.PrivateKey, version, os, arch string) fleetsign.Manifest {
	t.Helper()
	m := fleetsign.Manifest{
		Version:          version,
		OS:               os,
		Arch:             arch,
		FileName:         "imas-sprout_" + strings.TrimPrefix(version, "v") + "_" + os + "_" + arch + ".deb",
		ChecksumSHA256:   strings.Repeat("ab", 32),
		MinSproutVersion: "v1.0.0",
	}
	msg, err := m.Message()
	if err != nil {
		t.Fatal(err)
	}
	m.Signature = fleetsign.EncodeSignature(1, ed25519.Sign(priv, msg))
	return m
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

func TestUpdateManifest_ServesApprovedSignedRow(t *testing.T) {
	priv := installFleetKey(t)
	want := signedManifest(t, priv, "v2.4.1", "linux", "amd64")
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
	// fleetsign.ParseManifest refuses any field beyond the seven signed
	// ones, so this is also the "no URL, nothing unsigned" check.
	got, err := fleetsign.ParseManifest(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("response is not a strict manifest: %v\n%s", err, rec.Body)
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if lower := strings.ToLower(rec.Body.String()); strings.Contains(lower, "url") || strings.Contains(lower, "http") {
		t.Errorf("response mentions a URL: %s", rec.Body)
	}
}

// TestUpdateManifest_RefusesRowsThatFailChecks: a row the store returns
// is still not served unless it is well-formed, matches the request and
// carries a signature that verifies. Each refusal is the generic 404.
func TestUpdateManifest_RefusesRowsThatFailChecks(t *testing.T) {
	priv := installFleetKey(t)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)

	good := signedManifest(t, priv, "v2.4.1", "linux", "amd64")
	unsigned := good
	unsigned.Signature = ""
	tampered := good
	tampered.ChecksumSHA256 = strings.Repeat("cd", 32)
	wrongKey := signedManifest(t, otherPriv, "v2.4.1", "linux", "amd64")
	wrongArch := signedManifest(t, priv, "v2.4.1", "linux", "arm64")
	invalid := good
	invalid.FileName = "../evil"
	// Signed and otherwise valid, but an .rpm stored under package_type
	// deb: package_type isn't signed, so the file name must agree with it.
	rpmAsDeb := good
	rpmAsDeb.FileName = "imas-sprout_2.4.1_linux_amd64.rpm"
	if msg, err := rpmAsDeb.Message(); err == nil {
		rpmAsDeb.Signature = fleetsign.EncodeSignature(1, ed25519.Sign(priv, msg))
	}

	for name, row := range map[string]fleetsign.Manifest{
		"unsigned":                     unsigned,
		"tampered checksum":            tampered,
		"signed by another key":        wrongKey,
		"row for another arch":         wrongArch,
		"invalid field":                invalid,
		"file of another package type": rpmAsDeb,
		"malformed signature form":     func() fleetsign.Manifest { m := good; m.Signature = "garbage"; return m }(),
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
	priv := installFleetKey(t)
	store := &fakeManifestStore{
		approved: map[string]string{"t_acme": "v2.4.1"},
		rows:     map[[4]string]fleetsign.Manifest{{"v2.4.1", "linux", "amd64", "deb"}: signedManifest(t, priv, "v2.4.1", "linux", "amd64")},
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

func TestUpdateManifest_FailsClosedWithoutStoreOrKeys(t *testing.T) {
	t.Run("no store", func(t *testing.T) {
		installFleetKey(t)
		installStore(t, nil)
		if rec := manifestRequest(t, &acmeWeb01, acmeQuery); rec.Code != http.StatusServiceUnavailable {
			t.Errorf("got %d, want 503", rec.Code)
		}
	})
	t.Run("no fleet key source", func(t *testing.T) {
		priv := installFleetKey(t)
		installStore(t, &fakeManifestStore{
			approved: map[string]string{"t_acme": "v2.4.1"},
			rows:     map[[4]string]fleetsign.Manifest{{"v2.4.1", "linux", "amd64", "deb"}: signedManifest(t, priv, "v2.4.1", "linux", "amd64")},
		})
		SetFleetKeySource(nil)
		if rec := manifestRequest(t, &acmeWeb01, acmeQuery); rec.Code != http.StatusServiceUnavailable {
			t.Errorf("got %d, want 503 (never served unverified)", rec.Code)
		}
	})
	t.Run("key set unavailable", func(t *testing.T) {
		priv := installFleetKey(t)
		installStore(t, &fakeManifestStore{
			approved: map[string]string{"t_acme": "v2.4.1"},
			rows:     map[[4]string]fleetsign.Manifest{{"v2.4.1", "linux", "amd64", "deb"}: signedManifest(t, priv, "v2.4.1", "linux", "amd64")},
		})
		SetFleetKeySource(staticFleetKeys{err: errors.New("transit down")})
		if rec := manifestRequest(t, &acmeWeb01, acmeQuery); rec.Code != http.StatusServiceUnavailable {
			t.Errorf("got %d, want 503", rec.Code)
		}
	})
}

func TestUpdateManifest_RequiresIdentity(t *testing.T) {
	installFleetKey(t)
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
	installFleetKey(t)
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
	priv := installFleetKey(t)
	row := signedManifest(t, priv, "v2.4.1", "linux", "amd64")
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

func TestManifestCache_ExpiryAndBound(t *testing.T) {
	c := &manifestCache{}
	now := time.Now()
	k := manifestCacheKey{tenantID: "t_acme", os: "linux", arch: "amd64", version: "v2.4.1"}
	m := fleetsign.Manifest{Version: "v2.4.1"}

	c.put(k, m, true, now)
	if _, found, ok := c.get(k, now.Add(manifestCacheTTL-time.Second)); !ok || !found {
		t.Error("positive entry should be served before its TTL")
	}
	if _, _, ok := c.get(k, now.Add(manifestCacheTTL)); ok {
		t.Error("positive entry served at its TTL")
	}
	c.put(k, fleetsign.Manifest{}, false, now)
	if _, _, ok := c.get(k, now.Add(manifestNegativeCacheTTL)); ok {
		t.Error("negative entry served at its TTL")
	}

	orig := manifestCacheMaxEntries
	manifestCacheMaxEntries = 3
	t.Cleanup(func() { manifestCacheMaxEntries = orig })
	c.reset()
	for i := 0; i < 10; i++ {
		c.put(manifestCacheKey{tenantID: "t", os: "linux", arch: "amd64", version: "v1.0." + string(rune('0'+i))}, m, true, now)
		if n := len(c.entries); n > manifestCacheMaxEntries {
			t.Fatalf("cache grew to %d entries, bound %d", n, manifestCacheMaxEntries)
		}
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
	priv := installFleetKey(t)
	store := &fakeManifestStore{
		approved: map[string]string{"t_acme": "v2.4.1"},
		rows:     map[[4]string]fleetsign.Manifest{{"v2.4.1", "linux", "amd64", "deb"}: signedManifest(t, priv, "v2.4.1", "linux", "amd64")},
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
