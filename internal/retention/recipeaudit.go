package retention

import (
	"context"
	"time"

	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/lease"
	log "github.com/yogzblr/imas/internal/log"
)

// recipeAuditInterval is how often each farmer replica's sweeper ticks.
const recipeAuditInterval = time.Hour

// recipeAuditMinInterval is how long after one replica's sweep no replica
// sweeps again: the recipe audit days are whole days, so one sweep a day
// is enough, and the bucket is listed once a day, not once per replica
// per hour.
const recipeAuditMinInterval = 23 * time.Hour

// RecipeAuditJobName is the sweep's farmer.job_leases row.
const RecipeAuditJobName = "recipe_audit_expiry"

// sweepTimeout bounds one sweep's object store calls.
const sweepTimeout = 30 * time.Minute

// StartRecipeAuditSweeper deletes recipe audit records older than days
// from s, the recipe bucket, once at start and then about daily, until ctx
// is done. days 0 keeps them for ever (nothing runs). Every farmer replica
// ticks, but a tick sweeps only under the recipe_audit_expiry row lease on
// db (internal/lease), and only if no replica has swept within
// recipeAuditMinInterval. A nil db sweeps unconditionally (one process).
func StartRecipeAuditSweeper(ctx context.Context, db *gorm.DB, s Store, days int) {
	if days <= 0 {
		log.Notice("recipe audit records are kept for ever (IMAS_RECIPE_AUDIT_RETENTION_DAYS=0)")
		return
	}
	if s == nil {
		log.Warn("recipe audit sweep not started: no recipe object store")
		return
	}
	log.Noticef("recipe audit sweep started: records older than %d days are deleted", days)
	go func() {
		sweepRecipeAuditLeased(ctx, db, s, days, time.Now)
		t := time.NewTicker(recipeAuditInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				sweepRecipeAuditLeased(ctx, db, s, days, time.Now)
			}
		}
	}()
}

// sweepRecipeAuditLeased is one tick: SweepRecipeAudit under the lease.
func sweepRecipeAuditLeased(ctx context.Context, db *gorm.DB, s Store, days int, now func() time.Time) {
	body := func(ctx context.Context) error {
		_, err := SweepRecipeAudit(ctx, s, days, now())
		return err
	}
	if db == nil {
		if err := body(ctx); err != nil {
			log.Errorf("recipe audit sweep: %v", err)
		}
		return
	}
	if _, err := lease.New(db, now).Run(ctx, RecipeAuditJobName, lease.JobTTL(), recipeAuditMinInterval, body); err != nil {
		log.Errorf("recipe audit sweep: %v", err)
	}
}

// SweepRecipeAudit deletes every tenant's recipe audit records of a day
// before Cutoff(now, days) from s, and nothing else (RecipeAuditDate).
func SweepRecipeAudit(ctx context.Context, s Store, days int, now time.Time) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, sweepTimeout)
	defer cancel()
	r, err := SweepDated(ctx, s, RecipeAuditPrefix, RecipeAuditDate, Cutoff(now, days))
	if r.Deleted > 0 {
		log.Noticef("recipe audit sweep: deleted %d records older than %d days, kept %d", r.Deleted, days, r.Kept)
	}
	return r, err
}
