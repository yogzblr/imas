package payloadbox

import (
	"errors"
	"testing"
	"time"
)

// KeyedReplayGuard keys on (scope..., id): the same ID in another scope is
// another message, the same one twice is a replay, and a stale one is
// refused before anything is recorded.
func TestKeyedReplayGuard(t *testing.T) {
	g := NewKeyedReplayGuard()
	id, _ := NewID()
	msg := &Message{ID: id, IssuedAt: time.Now().Unix()}
	for _, scope := range [][]string{{"t_1", "a"}, {"t_1", "b"}, {"t_2", "a"}, {"t_1a", ""}, {"t_1"}} {
		if err := g.Accept(msg, scope...); err != nil {
			t.Fatalf("%v: %v", scope, err)
		}
	}
	if err := g.Accept(msg, "t_1", "a"); !errors.Is(err, ErrReplayed) {
		t.Fatalf("replay: %v", err)
	}
	if msg.ID != id {
		t.Fatal("the guard changed the caller's message")
	}
	old := &Message{ID: "x", IssuedAt: time.Now().Add(-DefaultMaxSkew - time.Minute).Unix()}
	if err := g.Accept(old, "t_1", "a"); !errors.Is(err, ErrStale) {
		t.Fatalf("stale: %v", err)
	}
	future := &Message{ID: "y", IssuedAt: time.Now().Add(DefaultMaxSkew + time.Minute).Unix()}
	if err := g.Accept(future, "t_1", "a"); !errors.Is(err, ErrStale) {
		t.Fatalf("future: %v", err)
	}
}
