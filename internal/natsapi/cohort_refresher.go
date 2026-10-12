package natsapi

import (
	"context"
	"sort"
	"time"

	"github.com/yogzblr/imas/internal/lease"
	"github.com/yogzblr/imas/internal/log"
	"github.com/yogzblr/imas/internal/pki"
)

// cohortRefreshJobName is the refresher's farmer.job_leases row.
const cohortRefreshJobName = "cohort_refresher"

// cohortRefreshBody is the refresher's work; tests replace it to count
// runs.
var cohortRefreshBody = refreshAllCohorts

// StartCohortRefresher launches a background goroutine that periodically
// refreshes all dynamic cohort memberships. It recalculates membership
// by evaluating property matches against currently known sprouts.
//
// The refresher ticks every interval. Pass a zero or negative interval to
// disable scheduled refresh. Cancel the context to stop the goroutine.
// The returned channel is closed when the goroutine exits.
//
// Every farmer replica ticks, but a tick refreshes only under the
// cohort_refresher row lease (internal/lease), and only if no replica has
// refreshed within nine tenths of interval (refreshCohortsLeased), so the
// work runs once per interval across replicas. The membership cache it
// fills is per replica and nothing in farmer reads it outside tests, so a
// replica that doesn't refresh serves nothing stale.
func StartCohortRefresher(ctx context.Context, interval time.Duration) <-chan struct{} {
	done := make(chan struct{})
	if interval <= 0 {
		log.Info("Cohort scheduled refresh disabled (interval <= 0)")
		close(done)
		return done
	}

	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		log.Infof("Cohort scheduled refresh started (every %s)", interval)

		for {
			select {
			case <-ctx.Done():
				log.Info("Cohort scheduled refresh stopped")
				return
			case <-ticker.C:
				refreshCohortsLeased(ctx, interval, time.Now)
			}
		}
	}()

	return done
}

// refreshCohortsLeased is one refresher tick: refresh under the
// cohort_refresher lease on the farmer database, with now as the lease
// clock. With no database installed it refreshes unconditionally.
func refreshCohortsLeased(ctx context.Context, interval time.Duration, now func() time.Time) {
	l := pki.JobLeases(now)
	if l == nil {
		cohortRefreshBody()
		return
	}
	_, err := l.Run(ctx, cohortRefreshJobName, lease.JobTTL(), interval-interval/10,
		func(context.Context) error { cohortRefreshBody(); return nil })
	if err != nil {
		log.Errorf("Scheduled cohort refresh: job lease: %v", err)
	}
}

// refreshAllCohorts gathers current sprout IDs from the PKI store and
// refreshes every registered cohort's cached membership.
func refreshAllCohorts() {
	if cohortRegistry == nil {
		return
	}

	names := cohortRegistry.List()
	if len(names) == 0 {
		return
	}

	allKeys := pki.ListNKeysByType(pki.CurrentTenantID())
	allSproutIDs := make([]string, 0, len(allKeys.Accepted.Sprouts))
	for _, km := range allKeys.Accepted.Sprouts {
		allSproutIDs = append(allSproutIDs, km.SproutID)
	}
	sort.Strings(allSproutIDs)

	results, err := cohortRegistry.RefreshAll(allSproutIDs)
	if err != nil {
		log.Errorf("Scheduled cohort refresh error: %v", err)
		return
	}

	log.Debugf("Scheduled cohort refresh completed: %d cohort(s) refreshed", len(results))
}
