package payloadbox

import (
	"encoding/binary"
	"errors"
	"hash/maphash"
	"maps"
	"strings"
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
	// ErrStale: IssuedAt is outside the skew window, or at or before the
	// guard's floor (ReplayState.Floor).
	ErrStale = errors.New("payloadbox: message is outside the freshness window")
	// ErrReplayed: a message with this ID was already accepted.
	ErrReplayed = errors.New("payloadbox: message was already accepted")
	// ErrReplayGuardFull: the guard is at capacity with unexpired IDs,
	// so it can't record another and refuses rather than forget one.
	ErrReplayGuardFull = errors.New("payloadbox: replay guard is full")
)

// ReplayStateVersion is the only ReplayState version Restore accepts.
const ReplayStateVersion = 1

// ReplayState is everything a ReplayGuard remembers, in a form its owner
// can persist (Commit) and load back after a restart (Restore). It holds
// message IDs and timestamps only, never a message's content.
type ReplayState struct {
	V int `json:"v"`
	// Floor is the latest IssuedAt (Unix seconds) of any ID the guard has
	// forgotten. A message issued at or before it is refused as stale:
	// once an ID is forgotten its message is already outside the window,
	// so the floor never refuses a message an honest clock would accept,
	// but it does stop a clock stepped backwards from making forgotten
	// messages fresh again.
	Floor int64 `json:"floor"`
	// Seen maps each accepted message ID still inside the window to its
	// IssuedAt (Unix seconds).
	Seen map[string]int64 `json:"seen"`
}

// ReplayGuard accepts each message ID once while its IssuedAt is inside
// MaxSkew of the local clock.
//
// On its own it is in memory only, and a restart forgets every ID: any
// message answered within the last MaxSkew could then be replayed once
// (security review 2026-10, M2). A receiver that must survive a restart
// sets Commit to persist each new state before the message is acted on,
// and Restores the persisted state at startup. internal/pki's sproutbox.go
// does both for the sprout. Farmer needs no guard for a sprout's replies
// (it accepts only one whose ReplyTo names a request it just sent), but
// does for sealed control-plane calls: internal/natsapi's sealedapi.go
// keeps one per replica, in memory only, since a cluster-wide claim in
// Valkey backs it for every call that changes state.
type ReplayGuard struct {
	MaxSkew    time.Duration
	MaxEntries int
	// Commit, if set, is called with the guard's whole state each time
	// Accept records a message, before Accept returns. If it fails, the
	// message is forgotten again and Accept returns its error, so a
	// message is never acted on unless its ID was persisted first.
	Commit func(ReplayState) error

	mu    sync.Mutex
	floor int64
	seen  map[string]int64 // id -> IssuedAt, Unix seconds
}

// NewReplayGuard returns a guard with DefaultMaxSkew and DefaultMaxEntries.
func NewReplayGuard() *ReplayGuard {
	return &ReplayGuard{MaxSkew: DefaultMaxSkew, MaxEntries: DefaultMaxEntries}
}

// Restore replaces the guard's state with s (a state Commit was given
// earlier, typically by a previous process). A state of another version
// is an error and leaves the guard unchanged.
func (g *ReplayGuard) Restore(s ReplayState) error {
	if s.V != ReplayStateVersion {
		return errors.New("payloadbox: unknown replay state version")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.floor = s.Floor
	g.seen = maps.Clone(s.Seen)
	if g.seen == nil {
		g.seen = map[string]int64{}
	}
	return nil
}

// State returns a copy of the guard's state.
func (g *ReplayGuard) State() ReplayState {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.stateLocked()
}

func (g *ReplayGuard) stateLocked() ReplayState {
	seen := maps.Clone(g.seen)
	if seen == nil {
		seen = map[string]int64{}
	}
	return ReplayState{V: ReplayStateVersion, Floor: g.floor, Seen: seen}
}

// Accept records msg's ID and returns nil if msg is fresh and not seen
// before; otherwise ErrStale, ErrReplayed, ErrReplayGuardFull or Commit's
// error.
func (g *ReplayGuard) Accept(msg *Message) error {
	t := now()
	skew := int64(g.MaxSkew / time.Second)
	issued := msg.IssuedAt
	if issued < t.Unix()-skew || issued > t.Unix()+skew {
		return ErrStale
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen == nil {
		g.seen = map[string]int64{}
	}
	// Forget every ID whose message is now stale anyway, raising the
	// floor past it.
	for id, at := range g.seen {
		if at+skew <= t.Unix() {
			delete(g.seen, id)
			g.floor = max(g.floor, at)
		}
	}
	if issued <= g.floor {
		return ErrStale
	}
	if _, ok := g.seen[msg.ID]; ok {
		return ErrReplayed
	}
	if len(g.seen) >= g.MaxEntries {
		return ErrReplayGuardFull
	}
	g.seen[msg.ID] = issued
	if g.Commit != nil {
		if err := g.Commit(g.stateLocked()); err != nil {
			delete(g.seen, msg.ID)
			return err
		}
	}
	return nil
}

// KeyedReplayGuardShards and KeyedReplayGuardShardEntries size a
// KeyedReplayGuard: 64 x 16384 = 1M messages inside one 5-minute window
// per replica, about 3500 a second.
const (
	KeyedReplayGuardShards       = 64
	KeyedReplayGuardShardEntries = 1 << 14
)

// KeyedReplayGuard is a ReplayGuard for a receiver that accepts messages
// from many senders: each message is keyed on its scope (tenant ID and
// principal, for instance) as well as its ID, and the keys are spread over
// KeyedReplayGuardShards independent guards. ReplayGuard sweeps its whole
// map on every accept and holds one lock; sharding bounds both. In memory
// only, one per replica: a receiver whose messages change shared state
// backs it with a cluster-wide claim (internal/pki's ClaimSealedMessage).
type KeyedReplayGuard struct {
	seed   maphash.Seed
	shards [KeyedReplayGuardShards]*ReplayGuard
}

// NewKeyedReplayGuard returns a guard with DefaultMaxSkew.
func NewKeyedReplayGuard() *KeyedReplayGuard {
	g := &KeyedReplayGuard{seed: maphash.MakeSeed()}
	for i := range g.shards {
		g.shards[i] = &ReplayGuard{MaxSkew: DefaultMaxSkew, MaxEntries: KeyedReplayGuardShardEntries}
	}
	return g
}

// Accept records msg once for scope; ErrStale, ErrReplayed or
// ErrReplayGuardFull otherwise. msg itself is not changed.
func (g *KeyedReplayGuard) Accept(msg *Message, scope ...string) error {
	// Length-prefixed, so no two (scope..., id) tuples share a key.
	var b strings.Builder
	part := func(s string) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(s)))
		b.Write(n[:])
		b.WriteString(s)
	}
	for _, s := range scope {
		part(s)
	}
	part(msg.ID)
	key := b.String()
	keyed := *msg
	keyed.ID = key
	return g.shards[maphash.String(g.seed, key)%KeyedReplayGuardShards].Accept(&keyed)
}

// CheckFresh returns ErrStale unless msg's IssuedAt is within
// DefaultMaxSkew of the local clock: ReplayGuard's freshness check alone,
// for a reader that relays a message rather than acting on it, and
// leaves replay to the receiver it relays to.
func CheckFresh(msg *Message) error {
	t := now().Unix()
	skew := int64(DefaultMaxSkew / time.Second)
	if msg.IssuedAt < t-skew || msg.IssuedAt > t+skew {
		return ErrStale
	}
	return nil
}
