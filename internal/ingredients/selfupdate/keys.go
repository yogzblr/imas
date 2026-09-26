package selfupdate

// Which imas-fleet-signing key versions a sprout verifies a release
// against (design doc §2.5, "Key rotation").
//
// FLAG FOR SECURITY REVIEW. The root of trust is the sprout's existing
// connection to farmer — TLS pinned to SproutRootCA and authenticated
// with the sprout's own NATS User JWT — not a key handed over once at
// enrollment. So:
//
//  1. Live set (authoritative). The key set is fetched from farmer over
//     that connection (internal/fleetkeys, imas.sprouts.<id>.fleetsigningkeys):
//     every Transit version at or above min_decryption_version, i.e.
//     every version Transit's own /verify still accepts, including those
//     below min_encryption_version during a rotation grace period
//     (fleetsign's readKeySet). It's cached for
//     liveKeyTTL. A signature naming a version the cached set doesn't
//     hold triggers one immediate refetch before the release is refused,
//     so a release signed right after a rotation verifies without waiting
//     out the TTL. Any version in the set is accepted, not only the newest.
//
//  2. Enrollment-time key (bootstrap only, ADVISORY). The key set a sprout
//     pinned from POST /v1/enroll (pki.LoadPinnedFleetSigningKeys) is used
//     only while no live fetch has EVER succeeded on this sprout: its very
//     first update, before it has once reached farmer's key subject. The
//     first successful live fetch supersedes it permanently — recorded on
//     disk next to the pin (bootstrapSupersededPath), so a restart doesn't
//     bring it back — and from then on a failed live fetch is a refusal,
//     never a fall-back to the enrollment key. That matters because a
//     rotation is usually a response to a key being retired; letting a
//     sprout that can't reach farmer fall back to the old set would keep
//     the retired version trusted.
//
// Why a live fetch is not "trust on first fetch, i.e. no pinning at all":
// the channel itself is pinned (SproutRootCA + the sprout's JWT + a
// Publish grant on its own subject only), and whoever can answer on it —
// farmer, or another User in the tenant Account with the imas.> template —
// can already run arbitrary commands on the sprout via
// imas.sprouts.<id>.cmd.run, so a forged key set gives them nothing new.
// What signing still guards against is everyone who is NOT on that
// channel: saasapi and anything else that can write saas.fleet_versions,
// and the artifact host. See internal/fleetkeys' package doc.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/fleetkeys"
	"github.com/yogzblr/imas/internal/fleetsign"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/pki"
)

// ErrLiveKeysUnavailable: the live key fetch failed after one had already
// succeeded on this sprout, so the enrollment-time key is no longer an
// acceptable fall-back.
var ErrLiveKeysUnavailable = errors.New("selfupdate: fleet signing keys unavailable from farmer, and the enrollment-time key has been superseded")

const (
	// liveKeyTTL is how long a live key set is reused before refetching.
	// Short: a rotation or retirement reaches every sprout within it, and
	// a verification miss refetches immediately anyway.
	liveKeyTTL = 5 * time.Minute
	// liveFetchTimeout bounds one request to farmer.
	liveFetchTimeout = 15 * time.Second
)

var (
	connMu sync.RWMutex
	conn   *nats.Conn
)

// RegisterNatsConn installs the sprout's connection to farmer, the one
// the live key set is fetched over. cmd/sprout calls it alongside the
// other ingredients' RegisterNatsConn.
func RegisterNatsConn(nc *nats.Conn) {
	connMu.Lock()
	defer connMu.Unlock()
	conn = nc
}

// Seams for tests. Production code always uses these values.
var (
	// fetchLiveKeys asks farmer for the current key set.
	fetchLiveKeys = func(ctx context.Context) (fleetsign.KeySet, error) {
		connMu.RLock()
		nc := conn
		connMu.RUnlock()
		return fleetkeys.Fetch(ctx, nc, pki.GetSproutID())
	}
	// loadPinnedKeys reads the enrollment-time key set (bootstrap only).
	loadPinnedKeys = pki.LoadPinnedFleetSigningKeys
	now            = time.Now
)

// keySource says where a key set came from, for the refetch decision
// and the job's notes.
type keySource string

const (
	sourceLive      keySource = "live key set, just fetched from farmer"
	sourceCache     keySource = "live key set, cached"
	sourceBootstrap keySource = "enrollment-time key (bootstrap; no live fetch has succeeded on this sprout yet)"
)

var liveKeys struct {
	mu        sync.Mutex
	set       fleetsign.KeySet
	fetchedAt time.Time
	// superseded mirrors bootstrapSupersededPath's existence in memory.
	superseded bool
}

// bootstrapSupersededPath marks, next to the pinned enrollment-time key,
// that a live fetch has succeeded at least once, so the pin must never be
// used again. Same directory and lifecycle as SproutRootCA.
func bootstrapSupersededPath() string {
	return config.SproutFleetSigningJWKS + ".superseded"
}

func bootstrapSuperseded() bool {
	if liveKeys.superseded {
		return true
	}
	if _, err := os.Stat(bootstrapSupersededPath()); err == nil {
		liveKeys.superseded = true
	}
	return liveKeys.superseded
}

func markBootstrapSuperseded() {
	if liveKeys.superseded {
		return
	}
	liveKeys.superseded = true
	path := bootstrapSupersededPath()
	if err := os.WriteFile(path, []byte(now().UTC().Format(time.RFC3339)+"\n"), 0o644); err != nil {
		// In memory it's still superseded for this process's life; only a
		// restart before the next successful fetch could bring the pin
		// back, and only for as long as live fetches keep failing.
		log.Errorf("selfupdate: recording that the enrollment-time fleet key is superseded (%s): %v", path, err)
	}
}

// keysForVerify returns the key set to verify against. With refresh set
// it skips the cache and refetches.
func keysForVerify(ctx context.Context, refresh bool) (fleetsign.KeySet, keySource, error) {
	liveKeys.mu.Lock()
	defer liveKeys.mu.Unlock()

	if !refresh && liveKeys.set != nil && now().Sub(liveKeys.fetchedAt) < liveKeyTTL {
		return liveKeys.set, sourceCache, nil
	}
	fctx, cancel := context.WithTimeout(ctx, liveFetchTimeout)
	ks, err := fetchLiveKeys(fctx)
	cancel()
	if err == nil {
		liveKeys.set, liveKeys.fetchedAt = ks, now()
		markBootstrapSuperseded()
		return ks, sourceLive, nil
	}

	// The live fetch failed. A stale live set is not reused either: past
	// its TTL it may still hold a version that has since been retired.
	liveKeys.set = nil
	if bootstrapSuperseded() {
		return nil, "", fmt.Errorf("%w: %w", ErrLiveKeysUnavailable, err)
	}
	log.Warnf("selfupdate: live fleet signing key fetch failed (%v); using the enrollment-time key as a bootstrap fallback", err)
	pinned, perr := loadPinnedKeys()
	if perr != nil {
		return nil, "", errors.Join(err, perr)
	}
	return pinned, sourceBootstrap, nil
}

// verifyRelease checks sig over rel against the trusted key set, with one
// forced refetch if a cached live set doesn't hold the signature's key
// version (a release signed after a rotation the cache predates).
func verifyRelease(ctx context.Context, rel fleetsign.Release, sig string) (keySource, error) {
	ks, src, err := keysForVerify(ctx, false)
	if err != nil {
		return "", err
	}
	err = ks.Verify(rel, sig)
	if errors.Is(err, fleetsign.ErrUnknownKeyVersion) && src == sourceCache {
		if ks, src, err = keysForVerify(ctx, true); err != nil {
			return "", err
		}
		err = ks.Verify(rel, sig)
	}
	return src, err
}

// resetLiveKeys clears the in-process cache (tests).
func resetLiveKeys() {
	liveKeys.mu.Lock()
	defer liveKeys.mu.Unlock()
	liveKeys.set, liveKeys.fetchedAt, liveKeys.superseded = nil, time.Time{}, false
}
