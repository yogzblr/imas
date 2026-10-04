package shell

import (
	"sync"
	"time"
)

// SessionInfo is farmer's record of one shell session it relays.
type SessionInfo struct {
	TenantID  string    `json:"tenant_id"`
	SessionID string    `json:"session_id"`
	SproutID  string    `json:"sprout_id"`
	Pubkey    string    `json:"pubkey"`
	Username  string    `json:"username,omitempty"`
	RoleName  string    `json:"role"`
	Shell     string    `json:"shell,omitempty"`
	StartedAt time.Time `json:"started_at"`
}

// SessionKey identifies a session. A session ID is random and farmer's
// own, but every farmer-side table is keyed on the tenant too (CLAUDE.md,
// "Tenant safety").
type SessionKey struct {
	TenantID  string
	SessionID string
}

// Limits caps concurrent sessions; 0 means no cap.
type Limits struct {
	PerUser, PerTenant, PerReplica int
}

// Tracker is farmer's set of sessions on this replica, keyed
// (tenant_id, session_id). Sessions don't migrate between replicas, and
// v1 keeps no cross-replica list.
type Tracker struct {
	mu       sync.Mutex
	sessions map[SessionKey]*SessionInfo
}

// NewTracker returns an empty tracker.
func NewTracker() *Tracker {
	return &Tracker{sessions: make(map[SessionKey]*SessionInfo)}
}

// TryAdd records info unless that would exceed limits, or a session with
// its key exists; it reports whether it did.
func (t *Tracker) TryAdd(info *SessionInfo, limits Limits) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := SessionKey{info.TenantID, info.SessionID}
	if _, exists := t.sessions[key]; exists {
		return false
	}
	if limits.PerReplica > 0 && len(t.sessions) >= limits.PerReplica {
		return false
	}
	var tenant, user int
	for k, s := range t.sessions {
		if k.TenantID != info.TenantID {
			continue
		}
		tenant++
		if s.Pubkey == info.Pubkey {
			user++
		}
	}
	if limits.PerTenant > 0 && tenant >= limits.PerTenant || limits.PerUser > 0 && user >= limits.PerUser {
		return false
	}
	t.sessions[key] = info
	return true
}

// Remove removes a session and returns its info, or nil if not found.
func (t *Tracker) Remove(key SessionKey) *SessionInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	info, ok := t.sessions[key]
	if !ok {
		return nil
	}
	delete(t.sessions, key)
	return info
}

// Get returns a session's info, or nil.
func (t *Tracker) Get(key SessionKey) *SessionInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sessions[key]
}

// Active is how many sessions this replica relays.
func (t *Tracker) Active() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.sessions)
}

// List returns every session's info.
func (t *Tracker) List() []*SessionInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]*SessionInfo, 0, len(t.sessions))
	for _, info := range t.sessions {
		out = append(out, info)
	}
	return out
}
