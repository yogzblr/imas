package selfupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/fleetsign"
)

// transitKeys stands in for imas-fleet-signing's versions in Transit.
type transitKeys struct {
	priv map[int]ed25519.PrivateKey
	pub  map[int]ed25519.PublicKey
}

func newTransitKeys(t *testing.T, versions ...int) *transitKeys {
	t.Helper()
	tk := &transitKeys{priv: map[int]ed25519.PrivateKey{}, pub: map[int]ed25519.PublicKey{}}
	for _, v := range versions {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tk.priv[v], tk.pub[v] = priv, pub
	}
	return tk
}

// set is what farmer would serve with these versions live.
func (tk *transitKeys) set(t *testing.T, versions ...int) fleetsign.KeySet {
	t.Helper()
	var keys []fleetsign.PublicKey
	for _, v := range versions {
		keys = append(keys, fleetsign.PublicKey{Version: v, Key: tk.pub[v]})
	}
	ks, err := fleetsign.NewKeySet(keys)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func (tk *transitKeys) sign(t *testing.T, version int, rel fleetsign.Release) string {
	t.Helper()
	msg, err := rel.Message()
	if err != nil {
		t.Fatal(err)
	}
	return fleetsign.EncodeSignature(version, ed25519.Sign(tk.priv[version], msg))
}

// farmerKeys is a controllable live key endpoint that counts fetches.
type farmerKeys struct {
	mu    sync.Mutex
	set   fleetsign.KeySet
	err   error
	calls int
}

func (fk *farmerKeys) serve(ks fleetsign.KeySet, err error) {
	fk.mu.Lock()
	defer fk.mu.Unlock()
	fk.set, fk.err = ks, err
}

func (fk *farmerKeys) fetches() int {
	fk.mu.Lock()
	defer fk.mu.Unlock()
	return fk.calls
}

func installFarmerKeys(t *testing.T) *farmerKeys {
	t.Helper()
	fk := &farmerKeys{}
	fetchLiveKeys = func(context.Context) (fleetsign.KeySet, error) {
		fk.mu.Lock()
		defer fk.mu.Unlock()
		fk.calls++
		return fk.set, fk.err
	}
	return fk
}

// fakeClock replaces now for the duration of the test.
func fakeClock(t *testing.T) *time.Time {
	t.Helper()
	clock := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	orig := now
	now = func() time.Time { return clock }
	t.Cleanup(func() { now = orig })
	return &clock
}

// After a rotation, farmer serves v1..v3. A release signed by v2 — valid,
// just not the newest — verifies, is fetched, and installs.
func TestLiveKeys_NonNewestValidVersionVerifies(t *testing.T) {
	f := newFixture(t)
	tk := newTransitKeys(t, 1, 2, 3)
	fk := installFarmerKeys(t)
	fk.serve(tk.set(t, 1, 2, 3), nil)

	rel := f.release()
	res, err := step(t, rel, tk.sign(t, 2, rel)).Apply(context.Background())
	if err != nil || !res.Succeeded || len(f.installs) != 1 {
		t.Fatalf("Apply = %+v, %v (installs %d)", res, err, len(f.installs))
	}
	// v1 too, while it's still at or above min_decryption_version.
	res, err = step(t, rel, tk.sign(t, 1, rel)).Apply(context.Background())
	if err != nil || !res.Succeeded {
		t.Fatalf("Apply with v1 = %+v, %v", res, err)
	}
	// Once farmer stops serving v1 (min_decryption_version raised to 2),
	// a v1 signature is refused even after the forced refetch.
	fk.serve(tk.set(t, 2, 3), nil)
	resetLiveKeys()
	if _, err := step(t, rel, tk.sign(t, 1, rel)).Apply(context.Background()); !errors.Is(err, fleetsign.ErrUnknownKeyVersion) {
		t.Fatalf("Apply with retired v1 = %v, want ErrUnknownKeyVersion", err)
	}
}

// A cached set that predates a rotation: the first signature by the new
// version misses the cache, which triggers exactly one immediate refetch
// (not a wait for the TTL), and then verifies.
func TestLiveKeys_VerificationMissRefetchesImmediately(t *testing.T) {
	f := newFixture(t)
	fakeClock(t)
	tk := newTransitKeys(t, 1, 2, 7) // v7 exists only to sign with; farmer never serves it
	fk := installFarmerKeys(t)
	rel := f.release()

	fk.serve(tk.set(t, 1), nil)
	if _, err := step(t, rel, tk.sign(t, 1, rel)).Test(context.Background()); err != nil {
		t.Fatalf("v1 before rotation: %v", err)
	}
	if n := fk.fetches(); n != 1 {
		t.Fatalf("fetches after first verify = %d, want 1", n)
	}
	// A hit within the TTL uses the cache.
	if _, err := step(t, rel, tk.sign(t, 1, rel)).Test(context.Background()); err != nil || fk.fetches() != 1 {
		t.Fatalf("cached hit: err %v, fetches %d, want 1", err, fk.fetches())
	}

	// Transit rotates; farmer now serves v1 and v2. Still inside the TTL.
	fk.serve(tk.set(t, 1, 2), nil)
	if _, err := step(t, rel, tk.sign(t, 2, rel)).Test(context.Background()); err != nil {
		t.Fatalf("v2 right after rotation: %v", err)
	}
	if n := fk.fetches(); n != 2 {
		t.Fatalf("fetches after the miss = %d, want 2 (one refetch)", n)
	}

	// A version farmer doesn't have either: one refetch, then refused —
	// no loop.
	if _, err := step(t, rel, tk.sign(t, 7, rel)).Test(context.Background()); !errors.Is(err, fleetsign.ErrUnknownKeyVersion) {
		t.Fatalf("unknown v7 = %v, want ErrUnknownKeyVersion", err)
	}
	if n := fk.fetches(); n != 3 {
		t.Fatalf("fetches after an unresolvable miss = %d, want 3", n)
	}
	// An invalid signature under a version the cache holds doesn't
	// refetch: a Transit version's key never changes.
	bad := rel
	bad.Version = "v9.9.9"
	if _, err := step(t, bad, tk.sign(t, 1, rel)).Test(context.Background()); !errors.Is(err, fleetsign.ErrInvalidSignature) {
		t.Fatalf("bad signature = %v", err)
	}
	if n := fk.fetches(); n != 3 {
		t.Fatalf("an invalid signature triggered a refetch (fetches %d)", n)
	}
}

func TestLiveKeys_CacheExpiresAfterTTL(t *testing.T) {
	f := newFixture(t)
	clock := fakeClock(t)
	tk := newTransitKeys(t, 1)
	fk := installFarmerKeys(t)
	fk.serve(tk.set(t, 1), nil)
	rel := f.release()
	sig := tk.sign(t, 1, rel)

	step(t, rel, sig).Test(context.Background())
	*clock = clock.Add(liveKeyTTL - time.Second)
	step(t, rel, sig).Test(context.Background())
	if n := fk.fetches(); n != 1 {
		t.Fatalf("fetches within TTL = %d, want 1", n)
	}
	*clock = clock.Add(2 * time.Second)
	step(t, rel, sig).Test(context.Background())
	if n := fk.fetches(); n != 2 {
		t.Fatalf("fetches after TTL = %d, want 2", n)
	}
	// Farmer unreachable after the TTL: the stale set is not reused.
	fk.serve(nil, errors.New("timeout"))
	*clock = clock.Add(liveKeyTTL + time.Second)
	if _, err := step(t, rel, sig).Test(context.Background()); !errors.Is(err, ErrLiveKeysUnavailable) {
		t.Fatalf("stale cache with farmer down = %v, want ErrLiveKeysUnavailable", err)
	}
}

// The enrollment-time key is a bootstrap only. It's honored while no live
// fetch has ever succeeded — and ignored forever after the first one,
// even when a later live fetch fails, and even across a restart.
func TestLiveKeys_BootstrapKeyIgnoredOnceLiveFetchSucceeded(t *testing.T) {
	f := newFixture(t) // pins the fixture's key as enrollment-time v1
	rel := f.release()
	bootstrapSigned := f.sign(t, rel)
	fk := installFarmerKeys(t)

	// 1. Never reached farmer: the bootstrap key is used.
	fk.serve(nil, errors.New("not connected yet"))
	if _, err := step(t, rel, bootstrapSigned).Test(context.Background()); err != nil {
		t.Fatalf("first update, bootstrap only: %v", err)
	}
	if _, err := os.Stat(bootstrapSupersededPath()); !os.IsNotExist(err) {
		t.Fatal("bootstrap marked superseded before any live fetch succeeded")
	}

	// 2. A live fetch succeeds (Transit's real key, which isn't the
	// enrollment-time one): the live set is used, not the pin.
	tk := newTransitKeys(t, 1)
	fk.serve(tk.set(t, 1), nil)
	if _, err := step(t, rel, bootstrapSigned).Test(context.Background()); !errors.Is(err, fleetsign.ErrInvalidSignature) {
		t.Fatalf("bootstrap-signed release with a live set = %v, want ErrInvalidSignature", err)
	}
	if _, err := step(t, rel, tk.sign(t, 1, rel)).Test(context.Background()); err != nil {
		t.Fatalf("live-signed release: %v", err)
	}
	if _, err := os.Stat(bootstrapSupersededPath()); err != nil {
		t.Fatalf("supersession not recorded on disk: %v", err)
	}

	// 3. Farmer's key subject goes away. The bootstrap key would verify
	// bootstrapSigned — it must not be used.
	fk.serve(nil, errors.New("farmer unreachable"))
	resetLiveKeys() // cache gone; the on-disk marker remains
	for _, when := range []string{"same process", "after restart"} {
		if when == "after restart" {
			resetLiveKeys() // a new process: nothing in memory, only the marker on disk
		}
		_, err := step(t, rel, bootstrapSigned).Apply(context.Background())
		if !errors.Is(err, ErrLiveKeysUnavailable) {
			t.Fatalf("%s: Apply = %v, want ErrLiveKeysUnavailable", when, err)
		}
	}
	if f.requests.Load() != 0 || len(f.installs) != 0 {
		t.Fatalf("artifact requests %d, installs %d; want none", f.requests.Load(), len(f.installs))
	}
}
