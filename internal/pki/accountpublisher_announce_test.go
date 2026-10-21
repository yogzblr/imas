package pki

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yogzblr/imas/internal/accountloader"
)

// flakyBus is a fakeBus whose publish fails while fail is set.
type flakyBus struct {
	fakeBus
	fail *atomic.Bool
}

func (b flakyBus) publish(subject string, payload []byte) error {
	if b.fail.Load() {
		return errors.New("nats: no responders")
	}
	return b.fakeBus.publish(subject, payload)
}

// waitEvents waits until e has recorded want events.
func waitEvents(t *testing.T, e *pubEnv, want int) []map[string]int64 {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		evs := e.eventAccounts(t)
		if len(evs) >= want {
			return evs
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d events after 10s, want %d", len(evs), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

const fastAnnounce = 10 * time.Millisecond

// P30: farmer starts before the bus. ReconcileAll writes the Accounts but
// cannot announce them; once the bus is reachable the queued event is
// published, without another ReconcileAll (which would find the bucket
// current and announce nothing).
func TestReconcileAllAnnounceRetriedUntilBusReachable(t *testing.T) {
	e := newPubEnv(t)
	var down atomic.Bool
	down.Store(true)
	e.p.openBus = func() (accountBus, error) {
		if down.Load() {
			return nil, errors.New("nats: no servers available for connection")
		}
		return fakeBus{seq: e.seq, events: &e.events, mu: &e.mu}, nil
	}
	e.p.announceBackoff = accountloader.Backoff{Min: fastAnnounce, Max: fastAnnounce}
	a, b := newAccount(t), newAccount(t)
	local := []string{e.tr.signAt(t, a, 100, false), e.tr.signAt(t, b, 200, false)}
	e.p.local = func() ([]string, error) { return local, nil }

	if err := e.p.ReconcileAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * fastAnnounce)
	if evs := e.eventAccounts(t); len(evs) != 0 {
		t.Fatalf("events with the bus down: %v", evs)
	}
	if err := e.p.ReconcileAll(context.Background()); err != nil {
		t.Fatal(err)
	}

	down.Store(false)
	evs := waitEvents(t, e, 1)
	if len(evs[0]) != 2 || evs[0][a] != 100 || evs[0][b] != 200 {
		t.Fatalf("event %v, want both reconciled Accounts", evs[0])
	}
	// Announced once: the retry stops after it succeeds.
	time.Sleep(10 * fastAnnounce)
	if n := len(e.eventAccounts(t)); n != 1 {
		t.Fatalf("%d events, want 1", n)
	}
}

// A Publish whose event fails is retried too, and a newer issued-at queued
// for the same account while the retry waits is the one announced.
func TestPublishAnnounceRetriedAfterEventFails(t *testing.T) {
	e := newPubEnv(t)
	var fail atomic.Bool
	fail.Store(true)
	e.p.openBus = func() (accountBus, error) {
		return flakyBus{fakeBus: fakeBus{seq: e.seq, events: &e.events, mu: &e.mu}, fail: &fail}, nil
	}
	e.p.announceBackoff = accountloader.Backoff{Min: fastAnnounce, Max: fastAnnounce}
	pub := newAccount(t)
	if err := e.p.Publish(context.Background(), pub, e.tr.signAt(t, pub, 100, false)); err != nil {
		t.Fatal(err)
	}
	if err := e.p.Publish(context.Background(), pub, e.tr.signAt(t, pub, 101, false)); err != nil {
		t.Fatal(err)
	}
	if e.seq.count("push ") != 2 {
		t.Fatalf("pushes %v, want two (a failed event is no push failure)", e.seq.all())
	}
	fail.Store(false)
	evs := waitEvents(t, e, 1)
	if len(evs[0]) != 1 || evs[0][pub] != 101 {
		t.Fatalf("event %v, want %s at 101", evs[0], pub)
	}
}

// The retry ends with the publisher's stop context.
func TestAnnounceRetryStops(t *testing.T) {
	e := newPubEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	e.p.announceStop = ctx
	var opens atomic.Int64
	e.p.openBus = func() (accountBus, error) {
		opens.Add(1)
		return nil, errors.New("bus down")
	}
	e.p.announceBackoff = accountloader.Backoff{Min: time.Millisecond, Max: time.Millisecond}
	e.p.queueAnnounce(map[string]int64{newAccount(t): 1})
	time.Sleep(20 * time.Millisecond)
	cancel()
	deadline := time.Now().Add(5 * time.Second)
	for {
		e.p.mu.Lock()
		running := e.p.announcing
		e.p.mu.Unlock()
		if !running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the announce retry did not stop")
		}
		time.Sleep(time.Millisecond)
	}
	if opens.Load() == 0 {
		t.Fatal("the retry never tried the bus")
	}
}
