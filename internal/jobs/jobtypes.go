package jobs

import (
	"time"

	"github.com/yogzblr/imas/internal/cook"
)

type (
	Job struct {
		JID     string        `json:"jid"`
		ID      string        `json:"id"`
		Results []cook.Result `json:"results"`
		Sprout  string        `json:"sprout"`
		Summary cook.Summary  `json:"summary"`
	}
	Executor struct {
		PubKey string
	}
	// JobMeta stores metadata about a job, including who invoked it.
	// Written as jobs/<tenant>/<sprout>/<jid>/meta.json in the job store
	// (see the key layout in store.go).
	JobMeta struct {
		JID       string    `json:"jid"`
		InvokedBy string    `json:"invoked_by,omitempty"`
		CreatedAt time.Time `json:"created_at"`
	}

	// ExpiredMarker is jobs/<tenant>/<sprout>/<jid>/expired.json: written
	// once when farmer finds the job started later than its reconcile
	// window allows, and dropped its events (see reconcile.go).
	ExpiredMarker struct {
		JID          string        `json:"jid"`
		DispatchedAt time.Time     `json:"dispatched_at"`
		ExpiredAt    time.Time     `json:"expired_at"`
		Window       time.Duration `json:"window_ns"`
	}
)
