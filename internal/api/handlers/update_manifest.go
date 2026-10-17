package handlers

// GET /v1/sprout/update-manifest?os=&arch=&package_type=&version= —
// design doc §2.6. Serves a sprout the fleetsign.Manifest (the P22 wire
// contract) for its own tenant's approved sprout version, for one OS,
// arch and package type
// (deb, rpm or msi: one linux/amd64 binary ships as both a .deb and an
// .rpm). Authenticated with the sprout's gateway JWT by Auth
// (internal/api/middleware.go), which puts the verified (tenant_id,
// sprout_id) on the request context
// (WithSproutIdentity); the tenant is never read from the request.
//
// The manifest has no URL and no file name (fleetsign.Manifest,
// requirement 20): it carries the release's checksums.txt and its
// detached GPG signature verbatim. The sprout verifies the signature
// against the keyring shipped in its package, derives its package's file
// name itself, and downloads it from the repository configured in the
// sprout. Farmer verifies nothing (signing design D20); it only selects
// which release a tenant's sprouts may see.
//
// Every reason a manifest is not served — the tenant has approved
// another version or none, the version is revoked, unknown, has no row
// for this OS/arch/package type or no checksums, or the stored row fails
// validation — is the same 404 with the same body, so the endpoint is
// no oracle for which versions exist or what other tenants approved
// (design doc §3.4's reasoning, §4 "Tenant safety"). The reason is
// logged, never returned.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"

	"golang.org/x/mod/semver"
	"golang.org/x/time/rate"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/fleetcatalog"
	"github.com/yogzblr/imas/internal/fleetsign"
	log "github.com/yogzblr/imas/internal/log"
)

// SproutIdentity is the verified identity of the sprout making a request:
// the tenant_id and sprout_id claims of its gateway JWT. sprout_id is
// unique per tenant only, so the pair is the identity; never key
// anything on SproutID alone.
type SproutIdentity struct {
	TenantID string
	SproutID string
}

type sproutIdentityKey struct{}

// WithSproutIdentity returns ctx carrying id. Only Auth calls it, after
// verifying the gateway JWT the identity comes from.
func WithSproutIdentity(ctx context.Context, id SproutIdentity) context.Context {
	return context.WithValue(ctx, sproutIdentityKey{}, id)
}

// sproutIdentityFrom returns the identity Auth put on ctx, if any.
func sproutIdentityFrom(ctx context.Context) (SproutIdentity, bool) {
	id, ok := ctx.Value(sproutIdentityKey{}).(SproutIdentity)
	return id, ok && id.TenantID != "" && id.SproutID != ""
}

// UpdateManifestStore reads the manifest a tenant may be served.
type UpdateManifestStore interface {
	// ApprovedManifest returns the manifest for (version, os, arch,
	// packageType) — the saas.fleet_versions row with its version's
	// checksums.txt and signature — only if the row is not revoked and
	// version is the approved_version in tenantID's
	// saas.tenant_update_policy row. found is false for every other
	// case; err is only for a failed read.
	ApprovedManifest(ctx context.Context, tenantID, os, arch, packageType, version string) (m fleetsign.Manifest, found bool, err error)
}

// The PXC-backed store is fleetcatalog.SQL: the catalog read shared with
// farmer's self_update dispatch (internal/natsapi).

var (
	manifestStoreMu sync.RWMutex
	manifestStore   UpdateManifestStore
)

// SetUpdateManifestStore installs the store GetSproutUpdateManifest reads
// through (nil uninstalls it), and resets the endpoint's in-memory state:
// the manifest cache and the per-sprout rate limits. SetReadinessDB
// installs the production one at startup; tests install fakes.
func SetUpdateManifestStore(s UpdateManifestStore) {
	manifestStoreMu.Lock()
	manifestStore = s
	manifestStoreMu.Unlock()
	updateManifests.reset()
	updateManifestLimiter.reset()
}

// setUpdateManifestDB installs the PXC-backed catalog over db, or none for
// a nil db: as this endpoint's store, and as fleetcatalog's installed
// catalog, which farmer's self_update dispatch checks against.
func setUpdateManifestDB(db *gorm.DB) {
	if db == nil {
		fleetcatalog.Install(nil)
		SetUpdateManifestStore(nil)
		return
	}
	cat := fleetcatalog.New(db)
	fleetcatalog.Install(cat)
	SetUpdateManifestStore(cat)
}

func currentManifestStore() UpdateManifestStore {
	manifestStoreMu.RLock()
	defer manifestStoreMu.RUnlock()
	return manifestStore
}

// Query parameter shapes. They match fleetsign.Manifest.Validate, so a
// value that could never name a row is a 400 rather than a lookup.
var reManifestOSArch = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{0,31}$`)

const maxManifestVersionLen = 64

// GetSproutUpdateManifest handles GET /v1/sprout/update-manifest. It must
// run inside Auth, which rejects the request unless a valid gateway JWT
// put a SproutIdentity on the context.
func GetSproutUpdateManifest(w http.ResponseWriter, r *http.Request) {
	id, ok := sproutIdentityFrom(r.Context())
	if !ok {
		// Auth wasn't wired in front of this handler. Fail closed.
		log.Errorf("update-manifest: request without a verified sprout identity")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if ok, retry := updateManifestLimiter.allow(id, time.Now()); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int((retry+time.Second-1)/time.Second)))
		writeManifestError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}

	osName, arch, pkgType, version, ok := manifestQuery(r)
	if !ok {
		writeManifestError(w, http.StatusBadRequest, "bad_request")
		return
	}

	key := manifestCacheKey{tenantID: id.TenantID, os: osName, arch: arch, packageType: pkgType, version: version}
	m, found, ok := updateManifests.get(key, time.Now())
	if !ok {
		var err error
		m, found, err = lookupApprovedManifest(r.Context(), key)
		if err != nil {
			log.Errorf("update-manifest: tenant %q sprout %q %s/%s %s: %v", id.TenantID, id.SproutID, osName, arch, version, err)
			writeManifestError(w, http.StatusServiceUnavailable, "manifest_unavailable")
			return
		}
		if found {
			// "Not found" is never cached (security review L6): a 404
			// costs a read, which the per-sprout limit bounds, and can't
			// take cache space from anyone.
			updateManifests.put(key, m, time.Now())
		}
	}
	if !found {
		writeManifestError(w, http.StatusNotFound, "not_found")
		return
	}

	body, err := json.Marshal(m)
	if err != nil {
		log.Errorf("update-manifest: encoding manifest: %v", err)
		writeManifestError(w, http.StatusInternalServerError, "manifest_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body); err != nil {
		log.Errorf("update-manifest: writing response: %v", err)
	}
}

// manifestPackageTypes are the package_type values a sprout may ask for:
// the installer it uses (saasapi's packageTypeOS).
var manifestPackageTypes = map[string]bool{"deb": true, "rpm": true, "msi": true}

// manifestQuery returns the os, arch, package_type and version
// parameters, each present exactly once and well-formed. Other parameters
// are ignored — in particular there is no tenant parameter; the tenant is
// the JWT's.
func manifestQuery(r *http.Request) (osName, arch, pkgType, version string, ok bool) {
	q := r.URL.Query()
	one := func(name string) (string, bool) {
		v := q[name]
		if len(v) != 1 {
			return "", false
		}
		return v[0], true
	}
	if osName, ok = one("os"); !ok || !reManifestOSArch.MatchString(osName) {
		return "", "", "", "", false
	}
	if arch, ok = one("arch"); !ok || !reManifestOSArch.MatchString(arch) {
		return "", "", "", "", false
	}
	if pkgType, ok = one("package_type"); !ok || !manifestPackageTypes[pkgType] {
		return "", "", "", "", false
	}
	if version, ok = one("version"); !ok || len(version) > maxManifestVersionLen ||
		!semver.IsValid(version) || semver.Canonical(version) != version {
		return "", "", "", "", false
	}
	return osName, arch, pkgType, version, true
}

// lookupApprovedManifest reads key's manifest and checks it before it
// may be served: for exactly the os/arch/package type/version asked, and
// well-formed (fleetsign.Manifest.Validate: the field shapes and the
// checksums.txt and signature size limits). A manifest that fails either
// check is logged and reported as not found. The signature is not
// verified here: the sprout is the only verifier (D20). err is returned
// only when the answer is unknown (store unavailable), and is not cached.
func lookupApprovedManifest(ctx context.Context, key manifestCacheKey) (fleetsign.Manifest, bool, error) {
	store := currentManifestStore()
	if store == nil {
		return fleetsign.Manifest{}, false, errors.New("update manifest store not configured")
	}
	m, found, err := store.ApprovedManifest(ctx, key.tenantID, key.os, key.arch, key.packageType, key.version)
	if err != nil || !found {
		return fleetsign.Manifest{}, false, err
	}
	if m.Version != key.version || m.OS != key.os || m.Arch != key.arch || m.PackageType != key.packageType {
		log.Errorf("update-manifest: store returned %s %s/%s %s for %s %s/%s %s; refusing",
			m.Version, m.OS, m.Arch, m.PackageType, key.version, key.os, key.arch, key.packageType)
		return fleetsign.Manifest{}, false, nil
	}
	if err := m.Validate(); err != nil {
		log.Errorf("update-manifest: release %s %s/%s %s is invalid; refusing: %v", m.Version, m.OS, m.Arch, m.PackageType, err)
		return fleetsign.Manifest{}, false, nil
	}
	return m, true, nil
}

func writeManifestError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

// --- cache ---

// Cache lifetime and bounds. A served manifest can lag an approval change
// or a revoke by at most manifestCacheTTL on each farmer replica. The
// cache is what keeps a fleet-wide rollout wave from turning into one PXC
// read per sprout. Only served manifests are cached: a "not found" is
// read again every time, so a new approval is seen at once and a sprout
// asking for versions that don't exist can't fill the cache (security
// review 2026-10, L6).
//
// Keys are chosen by authenticated sprouts, so memory is bounded per
// tenant and in total. A tenant at its share evicts only its own entries
// (expired first, then the one closest to expiry); with the whole cache
// full of other tenants' live entries, a new entry is not cached at all
// rather than evicting someone else's. No tenant can empty or take over
// another tenant's share.
var (
	manifestCacheTTL = 30 * time.Second
	// manifestCacheMaxPerTenant bounds one tenant's entries.
	manifestCacheMaxPerTenant = 256
	// manifestCacheMaxEntries bounds all tenants' entries together.
	manifestCacheMaxEntries = 4096
)

// manifestCacheKey is per tenant: two tenants asking for the same
// version, os, arch and package type never share an entry, since whether
// a row is served depends on each tenant's own approval.
type manifestCacheKey struct {
	tenantID, os, arch, packageType, version string
}

type manifestCacheEntry struct {
	m       fleetsign.Manifest
	expires time.Time
}

// manifestCache holds served manifests, one map per tenant (keyed on
// tenant_id; the entry key repeats it).
type manifestCache struct {
	mu      sync.Mutex
	tenants map[string]map[manifestCacheKey]manifestCacheEntry
	total   int
}

var updateManifests = &manifestCache{}

// get returns key's cached manifest; found is false on a miss or expiry,
// and the caller reads the store.
func (c *manifestCache) get(key manifestCacheKey, now time.Time) (m fleetsign.Manifest, found, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, hit := c.tenants[key.tenantID][key]
	if !hit || !now.Before(e.expires) {
		return fleetsign.Manifest{}, false, false
	}
	return e.m, true, true
}

// put caches m, a served manifest, for key: within the key's tenant's
// share and the total, evicting only that tenant's entries.
func (c *manifestCache) put(key manifestCacheKey, m fleetsign.Manifest, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tenants == nil {
		c.tenants = make(map[string]map[manifestCacheKey]manifestCacheEntry)
	}
	if _, replace := c.tenants[key.tenantID][key]; !replace {
		if len(c.tenants[key.tenantID]) >= manifestCacheMaxPerTenant {
			c.dropExpired(key.tenantID, now)
			if len(c.tenants[key.tenantID]) >= manifestCacheMaxPerTenant {
				c.evictSoonest(key.tenantID)
			}
		}
		if c.total >= manifestCacheMaxEntries {
			for tenant := range c.tenants {
				c.dropExpired(tenant, now)
			}
		}
		if c.total >= manifestCacheMaxEntries {
			return
		}
		c.total++
	}
	own := c.tenants[key.tenantID]
	if own == nil {
		own = make(map[manifestCacheKey]manifestCacheEntry)
		c.tenants[key.tenantID] = own
	}
	own[key] = manifestCacheEntry{m: m, expires: now.Add(manifestCacheTTL)}
}

// dropExpired removes tenant's expired entries. c.mu is held.
func (c *manifestCache) dropExpired(tenant string, now time.Time) {
	own := c.tenants[tenant]
	for k, e := range own {
		if !now.Before(e.expires) {
			delete(own, k)
			c.total--
		}
	}
	if len(own) == 0 {
		delete(c.tenants, tenant)
	}
}

// evictSoonest removes tenant's entry closest to expiry. c.mu is held.
func (c *manifestCache) evictSoonest(tenant string) {
	own := c.tenants[tenant]
	var victim manifestCacheKey
	var soonest time.Time
	first := true
	for k, e := range own {
		if first || e.expires.Before(soonest) {
			victim, soonest, first = k, e.expires, false
		}
	}
	if !first {
		delete(own, victim)
		c.total--
	}
}

// size is the number of entries, in total and for tenant.
func (c *manifestCache) size(tenant string) (total, own int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total, len(c.tenants[tenant])
}

func (c *manifestCache) reset() {
	c.mu.Lock()
	c.tenants = nil
	c.total = 0
	c.mu.Unlock()
}

// --- per-sprout rate limit ---

// Per-sprout limit: a sprout fetches its manifest once per self_update
// plus retries, so a burst of manifestRateBurst then one request per
// manifestRateEvery is generous for a well-behaved sprout and caps what
// one stolen or misbehaving identity can cost. Per farmer replica.
var (
	manifestRateEvery = 12 * time.Second
	manifestRateBurst = 5
	// manifestLimiterIdle is how long a sprout's bucket is kept after its
	// last request; by then it has refilled, so dropping it changes
	// nothing.
	manifestLimiterIdle = 10 * time.Minute
)

type sproutLimiterBucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// sproutLimiter is keyed on the full (tenant_id, sprout_id) identity:
// keyed on sprout_id alone, web-01 in one tenant would spend web-01's
// budget in every other tenant.
type sproutLimiter struct {
	mu        sync.Mutex
	buckets   map[SproutIdentity]*sproutLimiterBucket
	lastSweep time.Time
}

var updateManifestLimiter = &sproutLimiter{}

// allow reports whether id may make a request at now, and if not, how
// long until it may.
func (l *sproutLimiter) allow(id SproutIdentity, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buckets == nil {
		l.buckets = make(map[SproutIdentity]*sproutLimiterBucket)
	}
	if now.Sub(l.lastSweep) >= manifestLimiterIdle {
		for k, b := range l.buckets {
			if now.Sub(b.lastSeen) >= manifestLimiterIdle {
				delete(l.buckets, k)
			}
		}
		l.lastSweep = now
	}
	b, ok := l.buckets[id]
	if !ok {
		b = &sproutLimiterBucket{limiter: rate.NewLimiter(rate.Every(manifestRateEvery), manifestRateBurst)}
		l.buckets[id] = b
	}
	b.lastSeen = now
	res := b.limiter.ReserveN(now, 1)
	if delay := res.DelayFrom(now); delay > 0 {
		res.CancelAt(now)
		return false, delay
	}
	return true, 0
}

func (l *sproutLimiter) reset() {
	l.mu.Lock()
	l.buckets = nil
	l.lastSweep = time.Time{}
	l.mu.Unlock()
}
