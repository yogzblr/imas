package heartbeat

// Tests for the Valkey acceptance marker (imas:accepted:{<tenant>:<sprout>}):
// farmer keeps no state of its own for the accepted-sprout check.

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"

	"github.com/yogzblr/imas/internal/pki"
)

// countingVerify wraps the live check and counts calls.
func countingVerify(n *atomic.Int64) {
	verifySprout = func(tenant, id string) error {
		n.Add(1)
		return pki.VerifySproutInTenant(tenant, id)
	}
}

func TestAcceptedKeyFor(t *testing.T) {
	if got, want := acceptedKeyFor("acme", "web-01"), "imas:accepted:{acme:web-01}"; got != want {
		t.Errorf("acceptedKeyFor = %q, want %q", got, want)
	}
	if keyFor("acme", "web-01") != "imas:heartbeat:{acme:web-01}" {
		t.Error("unexpected presence key name")
	}
	if AcceptedTTL <= TTL {
		t.Errorf("AcceptedTTL %s must be longer than the presence TTL %s", AcceptedTTL, TTL)
	}
	if AcceptedTTL != 4*time.Hour {
		t.Errorf("AcceptedTTL = %s, want 4h", AcceptedTTL)
	}
}

func TestMarkerLifetime_JitterWithinTenPercent(t *testing.T) {
	newTestPKIDB(t)
	_ = newTestValkey(t)
	seen := map[time.Duration]bool{}
	for i := 0; i < 300; i++ {
		d := markerLifetime()
		if d < AcceptedTTL || d > AcceptedTTL+AcceptedTTL/10 {
			t.Fatalf("markerLifetime = %s, outside [4h, 4h24m]", d)
		}
		seen[d] = true
	}
	if len(seen) < 10 {
		t.Fatalf("only %d distinct lifetimes in 300 draws; jitter is not random", len(seen))
	}
}

// Marker absent: one DB check, then both keys. Marker present: no DB check,
// and the presence key is refreshed even after it had lapsed.
func TestHandleHeartbeat_MarkerHitSkipsDatabaseAndRefreshes(t *testing.T) {
	newTestPKIDB(t)
	mr := newTestValkey(t)
	acceptedJitter = 0
	var calls atomic.Int64
	countingVerify(&calls)
	tenant := pki.CurrentTenantID()
	acceptSprout(t, tenant, "web-01", "UHBWEB01")
	subj := pki.SproutHeartbeatSubject("web-01")
	pk, mk := keyFor(tenant, "web-01"), acceptedKeyFor(tenant, "web-01")

	handleHeartbeat(tenant, subj)
	if calls.Load() != 1 {
		t.Fatalf("DB calls after the first heartbeat = %d, want 1", calls.Load())
	}
	if !mr.Exists(pk) || !mr.Exists(mk) {
		t.Fatalf("keys after a miss: %v; want both", mr.Keys())
	}
	if got := mr.TTL(pk); got != testTTL {
		t.Errorf("presence TTL = %s, want %s", got, testTTL)
	}
	if got := mr.TTL(mk); got != AcceptedTTL {
		t.Errorf("marker TTL = %s, want %s", got, AcceptedTTL)
	}

	// The presence key lapses (heartbeats paused); the marker is far from it.
	mr.FastForward(testTTL + time.Second)
	if mr.Exists(pk) {
		t.Fatal("presence key should have lapsed")
	}
	handleHeartbeat(tenant, subj)
	if calls.Load() != 1 {
		t.Fatalf("DB calls = %d after a marker hit, want still 1", calls.Load())
	}
	if !mr.Exists(pk) || mr.TTL(pk) != testTTL {
		t.Fatalf("presence key not refreshed past its old expiry: exists=%v ttl=%s", mr.Exists(pk), mr.TTL(pk))
	}
}

// The marker is a fixed lifetime: heartbeats never extend it, and once it
// lapses the next heartbeat goes back to the database.
func TestHandleHeartbeat_MarkerIsNotSliding(t *testing.T) {
	newTestPKIDB(t)
	mr := newTestValkey(t)
	acceptedJitter = 0
	var calls atomic.Int64
	countingVerify(&calls)
	tenant := pki.CurrentTenantID()
	acceptSprout(t, tenant, "web-01", "UHBWEB01")
	subj := pki.SproutHeartbeatSubject("web-01")
	mk := acceptedKeyFor(tenant, "web-01")

	handleHeartbeat(tenant, subj)
	for i := 0; i < 10; i++ { // ten heartbeats an hour apart
		mr.FastForward(time.Hour)
		if i < 3 {
			handleHeartbeat(tenant, subj)
			want := AcceptedTTL - time.Duration(i+1)*time.Hour
			if got := mr.TTL(mk); got != want {
				t.Fatalf("after %d hours the marker TTL is %s, want %s (a heartbeat extended it)", i+1, got, want)
			}
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("DB calls = %d while the marker was live, want 1", calls.Load())
	}
	if mr.Exists(mk) {
		t.Fatal("marker outlived AcceptedTTL")
	}
	handleHeartbeat(tenant, subj)
	if calls.Load() != 2 || !mr.Exists(mk) {
		t.Fatalf("after the marker lapsed: DB calls=%d marker=%v; want a re-check and a new marker", calls.Load(), mr.Exists(mk))
	}
}

// A failed or not-accepted check sets nothing, and is retried each time so a
// newly accepted sprout works at once.
func TestHandleHeartbeat_FailedCheckSetsNothing(t *testing.T) {
	newTestPKIDB(t)
	mr := newTestValkey(t)
	var calls atomic.Int64
	countingVerify(&calls)
	tenant := pki.CurrentTenantID()
	if err := pki.UnacceptNKey(tenant, "web-02", "UHBWEB02"); err != nil {
		t.Fatal(err)
	}
	subj := pki.SproutHeartbeatSubject("web-02")
	for i := 0; i < 3; i++ {
		handleHeartbeat(tenant, subj)
	}
	if len(mr.Keys()) != 0 || calls.Load() != 3 {
		t.Fatalf("keys=%v calls=%d; want no keys and 3 checks", mr.Keys(), calls.Load())
	}
	if err := pki.AcceptNKey(tenant, "web-02"); err != nil {
		t.Fatal(err)
	}
	handleHeartbeat(tenant, subj)
	if !IsOnline(context.Background(), tenant, "web-02") {
		t.Fatal("a newly accepted sprout was not picked up at once")
	}
	// A database error is a failed check too.
	verifySprout = func(string, string) error { return errors.New("db down") }
	mr.FlushAll()
	handleHeartbeat(tenant, subj)
	if len(mr.Keys()) != 0 {
		t.Fatalf("keys after a DB error: %v", mr.Keys())
	}
}

// A Valkey error from the refresh script behaves like a miss.
func TestHandleHeartbeat_ValkeyErrorFallsBackToDatabase(t *testing.T) {
	newTestPKIDB(t)
	mr := newTestValkey(t)
	var calls atomic.Int64
	countingVerify(&calls)
	prev := refreshScript
	refreshScript = valkey.NewLuaScript(`return redis.error_reply('simulated failure')`)
	t.Cleanup(func() { refreshScript = prev })
	tenant := pki.CurrentTenantID()
	acceptSprout(t, tenant, "web-01", "UHBWEB01")

	handleHeartbeat(tenant, pki.SproutHeartbeatSubject("web-01"))
	if calls.Load() != 1 {
		t.Fatalf("DB calls = %d, want 1 (fallback)", calls.Load())
	}
	if !mr.Exists(keyFor(tenant, "web-01")) || !mr.Exists(acceptedKeyFor(tenant, "web-01")) {
		t.Fatalf("keys = %v; want both set after the fallback", mr.Keys())
	}
}

// Deny, reject, unaccept and delete delete both keys through the hook, and
// the sprout is then refused.
func TestInvalidate_OnLeavingAccepted(t *testing.T) {
	for _, op := range []struct {
		name string
		do   func(tenant, id string) error
	}{
		{"deny", pki.DenyNKey},
		{"reject", func(tn, id string) error { return pki.RejectNKey(tn, id, "") }},
		{"unaccept", func(tn, id string) error { return pki.UnacceptNKey(tn, id, "") }},
		{"delete", pki.DeleteNKey},
	} {
		t.Run(op.name, func(t *testing.T) {
			newTestPKIDB(t)
			mr := newTestValkey(t)
			pki.OnSproutLeftAccepted(Invalidate)
			t.Cleanup(func() { pki.OnSproutLeftAccepted(nil) })
			tenant := pki.CurrentTenantID()
			acceptSprout(t, tenant, "web-01", "UHBWEB01")
			handleHeartbeat(tenant, pki.SproutHeartbeatSubject("web-01"))
			if len(mr.Keys()) != 2 {
				t.Fatalf("keys before = %v", mr.Keys())
			}
			if err := op.do(tenant, "web-01"); err != nil {
				t.Fatalf("%s: %v", op.name, err)
			}
			if len(mr.Keys()) != 0 {
				t.Fatalf("keys after %s = %v; want none", op.name, mr.Keys())
			}
			handleHeartbeat(tenant, pki.SproutHeartbeatSubject("web-01"))
			if len(mr.Keys()) != 0 {
				t.Fatalf("a heartbeat after %s re-created keys: %v", op.name, mr.Keys())
			}
		})
	}
}

// The same sprout ID in two tenants has separate keys, and invalidating one
// leaves the other.
func TestAcceptedMarkers_SameSproutIDInTwoTenantsIndependent(t *testing.T) {
	newTestPKIDB(t)
	mr := newTestValkey(t)
	tenantA, tenantB := pki.CurrentTenantID(), "t_b"
	acceptSprout(t, tenantA, "web-01", "UHBWEB01")
	// Tenant B has no tenant row in the test PKI database (and "t_b" is not
	// a real tenant ID), so its database check is faked; A's is the real one.
	var acceptedInB atomic.Bool
	verifySprout = func(tenant, id string) error {
		if tenant == tenantB {
			if acceptedInB.Load() {
				return nil
			}
			return pki.ErrSproutIDNotFound
		}
		return pki.VerifySproutInTenant(tenant, id)
	}
	subj := pki.SproutHeartbeatSubject("web-01")

	// Not accepted in B yet: A's marker must not vouch for it.
	handleHeartbeat(tenantA, subj)
	handleHeartbeat(tenantB, subj)
	if !mr.Exists(acceptedKeyFor(tenantA, "web-01")) || mr.Exists(acceptedKeyFor(tenantB, "web-01")) || mr.Exists(keyFor(tenantB, "web-01")) {
		t.Fatalf("keys = %v; want only tenant A's", mr.Keys())
	}
	acceptedInB.Store(true)
	handleHeartbeat(tenantB, subj)
	if len(mr.Keys()) != 4 {
		t.Fatalf("keys = %v; want presence and marker for both tenants", mr.Keys())
	}
	// Dropping B's keys (what the left-accepted hook does) leaves A's.
	Invalidate(tenantB, "web-01")
	want := fmt.Sprint([]string{acceptedKeyFor(tenantA, "web-01"), keyFor(tenantA, "web-01")})
	got := mr.Keys()
	if len(got) != 2 || !(mr.Exists(acceptedKeyFor(tenantA, "web-01")) && mr.Exists(keyFor(tenantA, "web-01"))) {
		t.Fatalf("keys after invalidating tenant B's sprout = %v; want tenant A's %s", got, want)
	}
}
