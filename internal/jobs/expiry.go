package jobs

import (
	"context"
	"time"

	"github.com/yogzblr/imas/internal/lease"
	log "github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/objectstore"
)

// reapInterval is how often each replica's reaper ticks.
const reapInterval = time.Hour

// reapMinInterval is how long after one replica's run no replica runs the
// reaper again: a little under reapInterval, so the replica that ran last
// still runs on its next tick however its ticker drifts.
const reapMinInterval = reapInterval - reapInterval/10

// reapJobName is the reaper's farmer.job_leases row.
const reapJobName = "jobs_expiry"

// reapBody is the reaper's work; tests replace it to count runs.
var reapBody = (*Store).reap

// StartReaper launches a background goroutine that periodically removes jobs
// with no activity for longer than the given TTL. It checks once per hour. A
// TTL of 0 disables expiration entirely; farmer never passes one
// (config.JobLogTTL is IMAS_JOB_LOG_TTL or joblogttl, where 0 means the
// 720h default; docs/retention.md). The reaper runs until the process
// exits; use StartReaperCtx to bind its lifetime to a context.
//
// Every farmer replica ticks its own reaper, but a tick only reaps under
// the jobs_expiry row lease (internal/lease), and only if no replica has
// reaped within reapMinInterval, so the shared job bucket is listed once
// per hour, not once per replica. The delete stays idempotent all the
// same: a replica that stalls past its lease can overlap the next one,
// and deleting an already-deleted object succeeds.
func (s *Store) StartReaper(ttl time.Duration) {
	s.StartReaperCtx(context.Background(), ttl)
}

// StartReaperCtx is like StartReaper but stops the background goroutine when
// ctx is cancelled, allowing a clean shutdown.
func (s *Store) StartReaperCtx(ctx context.Context, ttl time.Duration) {
	if ttl <= 0 {
		log.Notice("job log expiration disabled (ttl <= 0)")
		return
	}
	log.Noticef("job log reaper started: ttl=%s", ttl)
	go func() {
		// Run once immediately on startup, then hourly.
		s.reapLeased(ctx, ttl, time.Now)
		ticker := time.NewTicker(reapInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				log.Notice("job log reaper stopped")
				return
			case <-ticker.C:
				s.reapLeased(ctx, ttl, time.Now)
			}
		}
	}()
}

// reapLeased is one reaper tick: reap under the jobs_expiry lease on the
// farmer database, with now as the lease clock. With no database
// installed (SetDB never called) it reaps unconditionally.
func (s *Store) reapLeased(ctx context.Context, ttl time.Duration, now func() time.Time) {
	body := func(context.Context) error { reapBody(s, ttl); return nil }
	d := db
	if d == nil {
		_ = body(ctx)
		return
	}
	if _, err := lease.New(d, now).Run(ctx, reapJobName, lease.JobTTL(), reapMinInterval, body); err != nil {
		log.Errorf("reaper: job lease: %v", err)
	}
}

// reap deletes every job whose last activity is older than the TTL. Object
// storage has no modification time to go by the way the local-disk reaper
// used file mtimes, so a job's last activity is the receive time of its
// newest event (encoded in the event key), or its meta.json CreatedAt if
// no events have arrived. recordJobCreation always writes meta.json, so every
// job can be dated. A job with neither is left alone.
func (s *Store) reap(ttl time.Duration) {
	// The job-status index expires by its own clock (status_index.go),
	// whether or not the object store is reachable.
	reapJobStatusIndex(time.Now().Add(-ttl))

	obj, err := s.backend()
	if err != nil {
		log.Errorf("reaper: %v", err)
		return
	}
	ctx, cancel := opContext()
	defer cancel()

	cutoff := time.Now().Add(-ttl)
	keys, err := obj.List(ctx, jobKeyPrefix)
	if err != nil {
		log.Errorf("reaper: listing jobs: %v", err)
		return
	}

	removed := 0
	// Deliberately indexJobs, not listJobs: a meta.json with no log
	// objects (its job's created.jsonl Put failed) should expire too.
	//
	// This is the job store's one platform-wide scan (every tenant's
	// jobs/<tenant>/ prefix at once). indexJobs parses each key's tenant
	// into its jobRef, so each job is dated from, and deleted by, its own
	// (tenant, sprout, jid) keys only: two tenants' jobs with the same
	// sprout and job IDs are two refs, and one expiring never touches the
	// other. The TTL is farmer's one joblogttl; there is no per-tenant TTL
	// to apply. Keys in the pre-tenant layout don't parse, so they are
	// neither read nor deleted.
	for ref, objs := range indexJobs(keys, "") {
		last := lastActivity(ctx, obj, ref, objs)
		if last.IsZero() || !last.Before(cutoff) {
			continue
		}
		if err := deleteJobObjects(ctx, obj, ref, objs); err != nil {
			log.Errorf("reaper: removing job %s for sprout %s (tenant %s): %v", ref.jid, ref.sproutID, ref.tenantID, err)
			continue
		}
		removed++
	}

	if removed > 0 {
		log.Noticef("reaper: removed %d expired job log(s)", removed)
	}
}

// lastActivity returns when a job was last written to, or the zero time if
// that can't be determined.
func lastActivity(ctx context.Context, obj *objectstore.Store, ref jobRef, objs *jobObjects) time.Time {
	var last time.Time
	for _, key := range objs.events {
		if t, ok := eventTime(key); ok && t.After(last) {
			last = t
		}
	}
	if last.IsZero() && objs.meta {
		if meta, err := readJobMeta(ctx, obj, ref); err == nil {
			last = meta.CreatedAt
		}
	}
	return last
}
