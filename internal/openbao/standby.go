package openbao

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

// HA OpenBao (raft) behind a Service that spreads clients over every
// node: a standby answers requests itself and forwards writes to the
// active node (seen on OpenBao 2.6.3, UAT HA run 42448281672). That
// leaves two windows a client meets on a standby, both reproduced
// against a three-node cluster:
//
//   - A KV v2 mount enabled moments ago answers every request on a
//     standby with 400 "Waiting for the primary to upgrade from
//     non-versioned to versioned data" (on the active node "Upgrading
//     from non-versioned to versioned data") until it sees the active
//     node's upgrade marker, about 1.5 s. The request was refused before
//     it was handled, so sending it again is safe: request retries it
//     (KVUpgradeWait), the one retry this package makes.
//   - A read straight after the client's own write (a Transit key it
//     just created, a KV version it just put) reaches the standby before
//     the standby has applied the write and answers 404, every time;
//     0.2 s later it answers 200. A blanket retry on 404 would also delay
//     every genuine miss, so callers that read back what they just wrote
//     wrap that read in AwaitReadBack.

// kvUpgradeMarker is in both of KV v2's upgrade answers (the standby's
// "Waiting for the primary to upgrade from non-versioned to versioned
// data" and the active node's "Upgrading from non-versioned to versioned
// data").
const kvUpgradeMarker = "non-versioned to versioned data"

// Tunables, variables so tests can shorten them.
var (
	// KVUpgradeWait bounds request's retries of a KV upgrade answer.
	// Exported so other packages' tests can shorten it.
	KVUpgradeWait = 60 * time.Second
	// kvUpgradeBackoff is the first pause between them; it doubles up to
	// one second.
	kvUpgradeBackoff = 100 * time.Millisecond

	// ReadBackWindow bounds AwaitReadBack: how long a write may take to
	// reach the standby a read lands on. Exported so other packages'
	// tests can shorten it.
	ReadBackWindow = 5 * time.Second
	// readBackBackoff is AwaitReadBack's first pause; it doubles up to
	// half a second.
	readBackBackoff = 50 * time.Millisecond
)

// IsKVUpgrading reports whether err is a KV v2 mount answering that it is
// still upgrading from non-versioned data: a mount enabled moments ago,
// on a standby until it sees the active node finish. Nothing was written.
func IsKVUpgrading(err error) bool {
	var se *StatusError
	if !errors.As(err, &se) || se.StatusCode != http.StatusBadRequest {
		return false
	}
	for _, e := range se.Errors {
		if strings.Contains(e, kvUpgradeMarker) {
			return true
		}
	}
	return false
}

// retryKVUpgrade calls send until it returns anything but a KV upgrade
// answer, KVUpgradeWait has passed, or ctx ends. It returns send's last
// result.
func retryKVUpgrade[T any](ctx context.Context, send func() (T, error)) (T, error) {
	deadline := time.Now().Add(KVUpgradeWait)
	pause := kvUpgradeBackoff
	for {
		v, err := send()
		if !IsKVUpgrading(err) || !time.Now().Add(pause).Before(deadline) {
			return v, err
		}
		if !sleep(ctx, pause) {
			return v, err
		}
		pause = min(2*pause, time.Second)
	}
}

// AwaitReadBack runs read, which reads back something this client has
// just written, until it reports found, returns an error, or
// ReadBackWindow has passed: a standby can answer 404 for a write it has
// not applied yet (see the top of this file). read reports a not-found
// answer as (false, nil). AwaitReadBack returns read's last answer; a
// cancelled ctx ends the wait with ctx's error.
func AwaitReadBack(ctx context.Context, read func(context.Context) (found bool, err error)) (bool, error) {
	deadline := time.Now().Add(ReadBackWindow)
	pause := readBackBackoff
	for {
		found, err := read(ctx)
		if err != nil || found || !time.Now().Add(pause).Before(deadline) {
			return found, err
		}
		if !sleep(ctx, pause) {
			return false, ctx.Err()
		}
		pause = min(2*pause, 500*time.Millisecond)
	}
}

// sleep waits d, or until ctx ends (then false).
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
