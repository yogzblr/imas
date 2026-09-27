package payloadbox

import (
	"errors"
	"sync"
	"time"
)

// DefaultMaxSkew is how far a Message's IssuedAt may be from the
// receiver's clock, either way, and so how long ReplayGuard must remember
// an ID. Five minutes matches the tolerance NATS and gateway JWT expiry
// already demand of a sprout's clock.
const DefaultMaxSkew = 5 * time.Minute

// DefaultMaxEntries bounds a ReplayGuard's memory. Far above any real
// command rate for one sprout inside DefaultMaxSkew.
const DefaultMaxEntries = 1 << 16

var (
	// ErrStale: IssuedAt is outside the skew window.
	ErrStale = errors.New("payloadbox: message is outside the freshness window")
	// ErrReplayed: a message with this ID was already accepted.
	ErrReplayed = errors.New("payloadbox: message was already accepted")
	// ErrReplayGuardFull: the guard is at capacity with unexpired IDs,
	// so it can't record another and refuses rather than forget one.
	ErrReplayGuardFull = errors.New("payloadbox: replay guard is full")
)

// ReplayGuard accepts each message ID once while its IssuedAt is inside
// MaxSkew of the local clock. In-process only: a sprout is one process,
// and after a restart everything issued before it is either stale or
// was already answered, so a replay inside the window re-runs at most
// what the restart interrupted. (Farmer doesn't need one: it only accepts
// replies whose ReplyTo names a request it just sent.)
type ReplayGuard struct {
	MaxSkew    time.Duration
	MaxEntries int

	mu   sync.Mutex
	seen map[string]time.Time // id -> when it may be forgotten
}

// NewReplayGuard returns a guard with DefaultMaxSkew and DefaultMaxEntries.
func NewReplayGuard() *ReplayGuard {
	return &ReplayGuard{MaxSkew: DefaultMaxSkew, MaxEntries: DefaultMaxEntries}
}

// Accept records msg's ID and returns nil if msg is fresh and not seen
// before; otherwise ErrStale, ErrReplayed or ErrReplayGuardFull.
func (g *ReplayGuard) Accept(msg *Message) error {
	t := now()
	issued := time.Unix(msg.IssuedAt, 0)
	if issued.Before(t.Add(-g.MaxSkew)) || issued.After(t.Add(g.MaxSkew)) {
		return ErrStale
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen == nil {
		g.seen = map[string]time.Time{}
	}
	if _, ok := g.seen[msg.ID]; ok {
		return ErrReplayed
	}
	if len(g.seen) >= g.MaxEntries {
		for id, forget := range g.seen {
			if !t.Before(forget) {
				delete(g.seen, id)
			}
		}
		if len(g.seen) >= g.MaxEntries {
			return ErrReplayGuardFull
		}
	}
	// Once issued+MaxSkew has passed the message is stale anyway.
	g.seen[msg.ID] = issued.Add(g.MaxSkew)
	return nil
}
