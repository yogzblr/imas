package handlers

// GET /v1/sprout/update-manifest?os=&arch=&package_type=&version= —
// design doc §2.6. Serves a sprout the signed fleetsign.Manifest for its
// own tenant's approved sprout version, for one OS, arch and package type
// (deb, rpm or msi: one linux/amd64 binary ships as both a .deb and an
// .rpm). Authenticated with the sprout's gateway JWT by Auth
// (internal/api/middleware.go), which puts the verified (tenant_id,
// sprout_id) on the request context
// (WithSproutIdentity); the tenant is never read from the request.
//
// The manifest has no URL (fleetsign.Manifest, requirement 20): the
// sprout builds the download URL from the repository configured in the
// sprout itself plus file_name, and verifies the signature against the
// keyring shipped in its package. Farmer only selects which signed row
// a tenant's sprouts may see.
//
// Every reason a manifest is not served — the tenant has approved
// another version or none, the version is revoked, unknown, or has no
// row for this OS/arch, or the stored row fails validation or signature
// verification — is the same 404 with the same body, so the endpoint is
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
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/semver"
	"golang.org/x/time/rate"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/fleetcatalog"
	"github.com/yogzblr/imas/internal/fleetsign"
	log "github.com/yogzblr/imas/internal/log"
)

// fleetKeySource is farmer's read-only view of the imas-fleet-signing
// Transit key, set once at startup via SetFleetKeySource
// (cmd/farmer/main.go), mirroring SetGatewaySigner. A stored row is
// re-verified against it before it is served.
var fleetKeySource fleetsign.KeySetSource

// SetFleetKeySource installs the read-only fleet signing key source the
// update manifest handler verifies rows against.
func SetFleetKeySource(s fleetsign.KeySetSource) { fleetKeySource = s }

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
	// ApprovedManifest returns the saas.fleet_versions row for (version,
	// os, arch, packageType), signature included, only if it is not
	// revoked and
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
// catalog, which farmer's self_update dispatch re-verifies against.
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
		updateManifests.put(key, m, found, time.Now())
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

// lookupApprovedManifest reads key's row and checks it before it may be
// served: well-formed, for exactly the os/arch/version asked, a file_name
// of the package type asked (package_type itself isn't signed), carrying a
// signature, and verifying against farmer's read-only view of the
// imas-fleet-signing key. A row that fails any check is logged and
// reported as not found; an unsigned row is never served. err is
// returned only when the answer is unknown (store or key set
// unavailable), and is not cached.
func lookupApprovedManifest(ctx context.Context, key manifestCacheKey) (fleetsign.Manifest, bool, error) {
	store := currentManifestStore()
	if store == nil {
		return fleetsign.Manifest{}, false, errors.New("update manifest store not configured")
	}
	m, found, err := store.ApprovedManifest(ctx, key.tenantID, key.os, key.arch, key.packageType, key.version)
	if err != nil || !found {
		return fleetsign.Manifest{}, false, err
	}
	if m.Version != key.version || m.OS != key.os || m.Arch != key.arch ||
		!strings.HasSuffix(m.FileName, "."+key.packageType) {
		log.Errorf("update-manifest: store returned %s %s/%s %s for %s %s/%s %s; refusing",
			m.Version, m.OS, m.Arch, m.FileName, key.version, key.os, key.arch, key.packageType)
		return fleetsign.Manifest{}, false, nil
	}
	if err := m.Validate(); err != nil {
		log.Errorf("update-manifest: fleet_versions row %s %s/%s is invalid; refusing: %v", m.Version, m.OS, m.Arch, err)
		return fleetsign.Manifest{}, false, nil
	}
	if m.Signature == "" {
		log.Errorf("update-manifest: fleet_versions row %s %s/%s has no signature; refusing", m.Version, m.OS, m.Arch)
		return fleetsign.Manifest{}, false, nil
	}
	if fleetKeySource == nil {
		return fleetsign.Manifest{}, false, errors.New("fleet signing key source not configured")
	}
	ks, err := fleetKeySource.KeySet(ctx)
	if err != nil {
		return fleetsign.Manifest{}, false, err
	}
	if err := ks.Verify(m); err != nil {
		log.Errorf("update-manifest: fleet_versions row %s %s/%s fails signature verification; refusing: %v", m.Version, m.OS, m.Arch, err)
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

// Cache lifetimes. A served manifest can lag an approval change or a
// revoke by at most manifestCacheTTL on each farmer replica; a 404 can
// lag a new approval by at most manifestNegativeCacheTTL. The cache is
// what keeps a fleet-wide rollout wave from turning into one PXC read per
// sprout.
var (
	manifestCacheTTL         = 30 * time.Second
	manifestNegativeCacheTTL = 10 * time.Second
	// manifestCacheMaxEntries bounds memory. Keys are chosen by
	// authenticated sprouts (any well-formed os/arch/version), so the
	// cache is emptied rather than allowed to grow without bound.
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
	found   bool
	expires time.Time
}

type manifestCache struct {
	mu      sync.Mutex
	entries map[manifestCacheKey]manifestCacheEntry
}

var updateManifests = &manifestCache{}

// get returns key's cached answer; ok is false on a miss or expiry.
func (c *manifestCache) get(key manifestCacheKey, now time.Time) (m fleetsign.Manifest, found, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, hit := c.entries[key]
	if !hit || !now.Before(e.expires) {
		return fleetsign.Manifest{}, false, false
	}
	return e.m, e.found, true
}

func (c *manifestCache) put(key manifestCacheKey, m fleetsign.Manifest, found bool, now time.Time) {
	ttl := manifestNegativeCacheTTL
	if found {
		ttl = manifestCacheTTL
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[manifestCacheKey]manifestCacheEntry)
	}
	if len(c.entries) >= manifestCacheMaxEntries {
		for k, e := range c.entries {
			if !now.Before(e.expires) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= manifestCacheMaxEntries {
			clear(c.entries)
		}
	}
	c.entries[key] = manifestCacheEntry{m: m, found: found, expires: now.Add(ttl)}
}

func (c *manifestCache) reset() {
	c.mu.Lock()
	c.entries = nil
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
