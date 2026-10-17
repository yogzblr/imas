package pki

// L11 (security review 2026-10; docs/briefs/T-pre-azure.md T4): a failed
// re-check after a live push no longer leaves a deprovisioned tenant
// live. FLAG FOR SECURITY REVIEW. The re-check is retried, a redelivered
// provision that finds the tenant deleted pushes a fresh lock-out, and the
// periodic relock pushes one for every deleted tenant still live on the
// bus, batched and rate limited.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// failRecheck makes every re-check after a live push fail, with no wait
// between attempts, until the returned function is called.
func failRecheck(t *testing.T) (restore func()) {
	t.Helper()
	origCheck, origSleep := relockIfDeleted, recheckSleep
	relockIfDeleted = func(*natsAuthMaterial, string) (string, bool, error) {
		return "", false, errors.New("database unavailable")
	}
	recheckSleep = func(time.Duration) {}
	restore = func() { relockIfDeleted, recheckSleep = origCheck, origSleep }
	t.Cleanup(restore)
	return restore
}

// raceToLiveBus drives the L11 scenario on a running test bus: a provision
// copy pushes its live JWT after a deprovision completed, and every
// re-check after that push fails. It returns with the bus holding the
// live JWT for the deleted tenant, and the re-check working again.
func raceToLiveBus(t *testing.T, rt raceTenant) {
	t.Helper()
	addDeniedSprout(t, rt.id, "web-02")
	hook, reached, release := pauseAt(rt.id)
	testHookBeforeLivePush = hook
	provErr := make(chan error, 1)
	go func() { provErr <- ProvisionTenant(rt.id, "Race Co") }()
	await(t, reached, "the paused push")
	if err := DeprovisionTenant(rt.id); err != nil {
		t.Fatalf("DeprovisionTenant: %v", err)
	}
	restore := failRecheck(t)
	close(release)
	if err := <-provErr; !errors.Is(err, errTenantRecheckFailed) {
		t.Fatalf("ProvisionTenant = %v, want errTenantRecheckFailed", err)
	}
	restore()
	testHookBeforeLivePush = nil
	if ac := busAccountClaims(t, rt.id); isLockedOut(ac) {
		t.Fatal("precondition: the bus should hold the live JWT the failed re-check left behind")
	}
}

// The re-check after a live push is retried: two failed reads and a
// third that works, so the push succeeds, after two jittered, doubling
// waits.
func TestPushLiveTenantAccount_RecheckRetried(t *testing.T) {
	startRaceBus(t)
	rt := setupRaceTenant(t, "t_recheck_retry")
	attempts := 0
	var waits []time.Duration
	origCheck, origSleep := relockIfDeleted, recheckSleep
	relockIfDeleted = func(mat *natsAuthMaterial, id string) (string, bool, error) {
		attempts++
		if attempts < recheckAttempts {
			return "", false, errors.New("database unavailable")
		}
		return origCheck(mat, id)
	}
	recheckSleep = func(d time.Duration) { waits = append(waits, d) }
	t.Cleanup(func() { relockIfDeleted, recheckSleep = origCheck, origSleep })

	if err := ProvisionTenant(rt.id, "Race Co"); err != nil {
		t.Fatalf("ProvisionTenant with two failed re-checks: %v", err)
	}
	if attempts != recheckAttempts || len(waits) != recheckAttempts-1 {
		t.Fatalf("%d re-checks and waits %v, want %d and %d", attempts, waits, recheckAttempts, recheckAttempts-1)
	}
	for i, w := range waits {
		full := recheckBackoff << i
		if w < full/2 || w > full {
			t.Errorf("wait %d = %s, want within [%s, %s]", i+1, w, full/2, full)
		}
	}
}

// A provision copy redelivered after an earlier copy's re-check failed
// (the bus left live for a deleted tenant) is refused and pushes a fresh
// lock-out: the bus ends locked out.
func TestProvisionTenant_RedeliveredAfterFailedRecheckLocksOut(t *testing.T) {
	startRaceBus(t)
	rt := setupRaceTenant(t, "t_redeliver")
	raceToLiveBus(t, rt)

	if err := ProvisionTenant(rt.id, "Race Co"); !errors.Is(err, ErrTenantDeprovisioned) {
		t.Fatalf("redelivered ProvisionTenant = %v, want ErrTenantDeprovisioned", err)
	}
	assertBusLockedOut(t, rt)
}

// The periodic relock finds the deleted tenant the failed re-check left
// live on the bus, pushes a lock-out, and pushes nothing on its next run,
// nor for a deleted tenant already locked out.
func TestRelockDeprovisionedTenants_LocksOutLiveBus(t *testing.T) {
	startRaceBus(t)
	locked := setupRaceTenant(t, "t_relock_done")
	if err := DeprovisionTenant(locked.id); err != nil {
		t.Fatal(err)
	}
	rt := setupRaceTenant(t, "t_relock_live")
	raceToLiveBus(t, rt)

	n, err := RelockDeprovisionedTenants(t.Context())
	if err != nil || n != 1 {
		t.Fatalf("RelockDeprovisionedTenants = %d, %v; want 1 lock-out pushed", n, err)
	}
	assertBusLockedOut(t, rt)
	assertBusLockedOut(t, locked)
	if n, err := RelockDeprovisionedTenants(t.Context()); err != nil || n != 0 {
		t.Fatalf("second run = %d, %v; want nothing pushed", n, err)
	}
}

// fakeBusView answers lookups from a map; a pub it doesn't know is
// absent on every node.
type fakeBusView struct {
	mu      sync.Mutex
	jwts    map[string]string
	lookups int
	closed  bool
}

func (v *fakeBusView) lookup(pub string) ([]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.lookups++
	if j, ok := v.jwts[pub]; ok {
		return []string{j}, nil
	}
	return nil, nil
}

func (v *fakeBusView) close() { v.closed = true }

// withRelockFakes installs view as the bus, counts relockPush calls in
// order, and records relockSleep waits without waiting.
func withRelockFakes(t *testing.T, view *fakeBusView) (pushed func() []string, waits func() []time.Duration) {
	t.Helper()
	var mu sync.Mutex
	var ids []string
	var slept []time.Duration
	origView, origPush, origSleep := openBusAccountView, relockPush, relockSleep
	openBusAccountView = func() (busAccountView, error) { return view, nil }
	relockPush = func(id string) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		ids = append(ids, id)
		return true, nil
	}
	relockSleep = func(_ context.Context, d time.Duration) error {
		mu.Lock()
		defer mu.Unlock()
		slept = append(slept, d)
		return nil
	}
	t.Cleanup(func() { openBusAccountView, relockPush, relockSleep = origView, origPush, origSleep })
	return func() []string {
			mu.Lock()
			defer mu.Unlock()
			return slices.Clone(ids)
		}, func() []time.Duration {
			mu.Lock()
			defer mu.Unlock()
			return slices.Clone(slept)
		}
}

// No push storm: with 1000 deleted tenants, a sweep pushes only those
// still live on the bus, each once, in ID order across batches of
// relockBatchSize, relockPushGap apart; when every one is locked out it
// pushes nothing at all.
func TestRelockDeprovisionedTenants_NoPushStorm(t *testing.T) {
	setupTestPKI(t)
	op, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatal(err)
	}
	const tenants = 1000
	live, lockedOut := map[string]string{}, map[string]string{}
	var ids []string
	for i := range tenants {
		kp, _ := nkeys.CreateAccount()
		pub, _ := kp.PublicKey()
		id := fmt.Sprintf("t_storm_%04d", i)
		ids = append(ids, id)
		if err := db.Create(&tenantRow{ID: id, Name: id, Deleted: true, CreatedAt: 1, AccountPub: pub}).Error; err != nil {
			t.Fatal(err)
		}
		ac := jwt.NewAccountClaims(pub)
		liveJWT, err := ac.Encode(op)
		if err != nil {
			t.Fatal(err)
		}
		lockOutAccount(ac, time.Now())
		lockedJWT, err := ac.Encode(op)
		if err != nil {
			t.Fatal(err)
		}
		live[pub], lockedOut[pub] = liveJWT, lockedJWT
	}
	// A live tenant and a tombstone (no Account) are never pushed.
	if err := db.Create(&tenantRow{ID: "t_storm_live", Name: "live", CreatedAt: 1, AccountPub: "AXLIVE"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&tenantRow{ID: "t_storm_tomb", Name: "tomb", Deleted: true, CreatedAt: 1}).Error; err != nil {
		t.Fatal(err)
	}

	view := &fakeBusView{jwts: lockedOut}
	pushed, waits := withRelockFakes(t, view)
	if n, err := RelockDeprovisionedTenants(t.Context()); err != nil || n != 0 {
		t.Fatalf("all locked out: %d pushed, %v; want none", n, err)
	}
	if len(pushed()) != 0 || len(waits()) != 0 {
		t.Fatalf("all locked out: pushes %d, waits %d; want none", len(pushed()), len(waits()))
	}
	if view.lookups != tenants || !view.closed {
		t.Fatalf("%d lookups (closed %v), want %d and the view closed", view.lookups, view.closed, tenants)
	}

	view = &fakeBusView{jwts: live}
	pushed, waits = withRelockFakes(t, view)
	n, err := RelockDeprovisionedTenants(t.Context())
	if err != nil || n != tenants {
		t.Fatalf("all live: %d pushed, %v; want %d", n, err, tenants)
	}
	if got := pushed(); !slices.Equal(got, ids) {
		t.Fatalf("pushed %d tenants (first %v), want each of the %d once, in ID order", len(got), got[:min(3, len(got))], tenants)
	}
	got := waits()
	if len(got) != tenants-1 {
		t.Fatalf("%d waits between %d pushes, want %d", len(got), tenants, tenants-1)
	}
	for _, w := range got {
		if w != relockPushGap {
			t.Fatalf("wait %s between pushes, want %s", w, relockPushGap)
		}
	}
}

// A tenant whose bus state can't be read is pushed (fail closed); a
// cancelled sweep stops.
func TestRelockDeprovisionedTenants_FailsClosed(t *testing.T) {
	setupTestPKI(t)
	if err := db.Create(&tenantRow{ID: "t_unknown", Name: "u", Deleted: true, CreatedAt: 1, AccountPub: "AXUNKNOWN"}).Error; err != nil {
		t.Fatal(err)
	}
	view := &fakeBusView{jwts: map[string]string{"AXUNKNOWN": "not a JWT"}}
	pushed, _ := withRelockFakes(t, view)
	if n, err := RelockDeprovisionedTenants(t.Context()); err != nil || n != 1 || !slices.Equal(pushed(), []string{"t_unknown"}) {
		t.Fatalf("unreadable bus state: %d pushed (%v), %v; want t_unknown pushed", n, pushed(), err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := RelockDeprovisionedTenants(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled sweep = %v, want context.Canceled", err)
	}
}

// The relocker's tick runs under the tenant_relock lease: two ticks
// within the interval sweep once; one after it sweeps again.
func TestRelockSweepLeased_OncePerInterval(t *testing.T) {
	setupTestPKI(t)
	if err := db.Create(&tenantRow{ID: "t_tick", Name: "t", Deleted: true, CreatedAt: 1, AccountPub: "AXTICK"}).Error; err != nil {
		t.Fatal(err)
	}
	op, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatal(err)
	}
	acct, _ := nkeys.CreateAccount()
	pub, _ := acct.PublicKey()
	if err := db.Model(&tenantRow{}).Where("id = ?", "t_tick").Update("account_pub", pub).Error; err != nil {
		t.Fatal(err)
	}
	liveJWT, err := jwt.NewAccountClaims(pub).Encode(op)
	if err != nil {
		t.Fatal(err)
	}
	pushed, _ := withRelockFakes(t, &fakeBusView{jwts: map[string]string{pub: liveJWT}})
	now := time.Now()
	clock := func() time.Time { return now }
	relockSweepLeased(t.Context(), 10*time.Minute, clock)
	now = now.Add(time.Minute)
	relockSweepLeased(t.Context(), 10*time.Minute, clock)
	if got := len(pushed()); got != 1 {
		t.Fatalf("two ticks a minute apart pushed %d times, want 1", got)
	}
	now = now.Add(10 * time.Minute)
	relockSweepLeased(t.Context(), 10*time.Minute, clock)
	if got := len(pushed()); got != 2 {
		t.Fatalf("a tick after the interval: %d pushes in all, want 2", got)
	}
}

// A path that sees a deleted tenant pushes a lock-out, but at most once
// per tenant per seenRelockMinInterval, and never two at once or closer
// than relockPushGap, however many requests see it.
func TestSeenRelocker_Limits(t *testing.T) {
	pushes := 0
	origPush := relockPush
	relockPush = func(string) (bool, error) { pushes++; return true, nil }
	t.Cleanup(func() { relockPush = origPush })
	r := newSeenRelocker()
	now := time.Now()
	r.now = func() time.Time { return now }

	for range 1000 {
		r.note("t_a")
	}
	if pushes != 1 {
		t.Fatalf("1000 sightings of one tenant pushed %d times, want 1", pushes)
	}
	r.note("t_b") // within relockPushGap of t_a's push
	if pushes != 1 {
		t.Fatalf("a push went out less than %s after the last one", relockPushGap)
	}
	now = now.Add(relockPushGap)
	r.note("t_b")
	if pushes != 2 {
		t.Fatalf("t_b after the gap: %d pushes, want 2", pushes)
	}
	r.busy = true
	now = now.Add(seenRelockMinInterval)
	r.note("t_a")
	if pushes != 2 {
		t.Fatal("a push started while another was running")
	}
	r.busy = false
	r.note("t_a")
	if pushes != 3 {
		t.Fatalf("t_a after %s: %d pushes, want 3", seenRelockMinInterval, pushes)
	}

	// A failed push is retried on the next sighting, past the gap.
	relockPush = func(string) (bool, error) { pushes++; return false, errors.New("bus down") }
	now = now.Add(relockPushGap)
	r.note("t_c")
	now = now.Add(relockPushGap)
	r.note("t_c")
	if pushes != 5 {
		t.Fatalf("a failed push: %d pushes in all, want it retried (5)", pushes)
	}
}

// IMAS_TENANT_RELOCK_INTERVAL: 10m unset, 1m to 24h accepted, anything
// else refused.
func TestTenantRelockInterval(t *testing.T) {
	for v, want := range map[string]time.Duration{"": DefaultTenantRelockInterval, " ": DefaultTenantRelockInterval,
		"1m": time.Minute, "30m": 30 * time.Minute, "24h": 24 * time.Hour} {
		t.Setenv(TenantRelockIntervalEnv, v)
		if got, err := TenantRelockInterval(); err != nil || got != want {
			t.Errorf("%q: %s, %v; want %s", v, got, err, want)
		}
	}
	for _, v := range []string{"59s", "24h1s", "0", "-5m", "ten minutes", "600"} {
		t.Setenv(TenantRelockIntervalEnv, v)
		if got, err := TenantRelockInterval(); err == nil {
			t.Errorf("%q accepted as %s", v, got)
		}
	}
}

// StartTenantRelocker stops when its context ends.
func TestStartTenantRelocker_Stops(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	done := StartTenantRelocker(ctx, time.Hour)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the relocker did not stop")
	}
}

// A claims lookup that fewer bus nodes answer than the bus has is an
// error, which the sweep takes as live and pushes (fail closed): a node
// that stayed silent may hold a live copy.
func TestBusAccountView_IncompleteLookupIsAnError(t *testing.T) {
	startRaceBus(t)
	rt := setupRaceTenant(t, "t_lookup")
	row, err := getTenantRow(rt.id)
	if err != nil {
		t.Fatal(err)
	}
	view, err := dialBusAccountView()
	if err != nil {
		t.Fatal(err)
	}
	defer view.close()
	got, err := view.lookup(row.AccountPub)
	if err != nil || len(got) != 1 {
		t.Fatalf("one-node bus, one expected: %d answers, %v", len(got), err)
	}
	view.(*natsBusAccountView).want = 2
	if _, err := view.lookup(row.AccountPub); err == nil {
		t.Fatal("a lookup one of two nodes answered returned no error")
	}
}
