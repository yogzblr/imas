package natsapi

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/config"
	"github.com/yogzblr/imas/internal/lease"
	"github.com/yogzblr/imas/internal/pki"
	"github.com/yogzblr/imas/internal/rbac"
)

func TestStartCohortRefresher_DisabledOnZeroInterval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Should not panic or block with zero interval.
	done := StartCohortRefresher(ctx, 0)
	<-done
	done = StartCohortRefresher(ctx, -1*time.Second)
	<-done
}

// useJobLeaseDB installs, for this test only, a pki database holding
// job_leases, so the refresher's lease never touches TestMain's shared
// store. That matters: cancelling the refresher's context mid-statement
// makes database/sql drop the connection, and a shared-cache in-memory
// database vanishes with its last connection, taking every later test's
// tables with it.
func useJobLeaseDB(t *testing.T) *gorm.DB {
	t.Helper()
	gdb, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := gdb.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := gdb.AutoMigrate(&lease.JobLease{}); err != nil {
		t.Fatal(err)
	}
	pki.SetDB(gdb)
	t.Cleanup(func() { pki.SetDB(sharedPKIDB); sqlDB.Close() })
	return gdb
}

func TestStartCohortRefresher_StopsOnCancel(t *testing.T) {
	useJobLeaseDB(t)
	oldReg, oldOrg := cohortRegistry, config.FarmerOrganization
	config.FarmerOrganization = t.Name()
	defer func() { config.FarmerOrganization = oldOrg }()
	cohortRegistry = rbac.NewRegistry()

	ctx, cancel := context.WithCancel(context.Background())
	done := StartCohortRefresher(ctx, 50*time.Millisecond)

	// Let it tick a couple of times.
	time.Sleep(150 * time.Millisecond)

	// Cancel and wait for the goroutine to fully exit before restoring.
	cancel()
	<-done
	cohortRegistry = oldReg
}

func TestRefreshAllCohorts_NilRegistry(t *testing.T) {
	old := cohortRegistry
	defer func() { cohortRegistry = old }()
	cohortRegistry = nil

	// Should not panic.
	refreshAllCohorts()
}

func TestRefreshAllCohorts_EmptyRegistry(t *testing.T) {
	oldReg, oldOrg := cohortRegistry, config.FarmerOrganization
	config.FarmerOrganization = t.Name()
	defer func() {
		cohortRegistry = oldReg
		config.FarmerOrganization = oldOrg
	}()
	cohortRegistry = rbac.NewRegistry()

	// Should not panic with an empty registry.
	refreshAllCohorts()
}

func TestRefreshAllCohorts_WithStaticCohort(t *testing.T) {
	oldReg, oldOrg := cohortRegistry, config.FarmerOrganization
	config.FarmerOrganization = t.Name()
	defer func() {
		cohortRegistry = oldReg
		config.FarmerOrganization = oldOrg
	}()

	reg := rbac.NewRegistry()
	err := reg.Register(&rbac.Cohort{
		Name:    "test-static",
		Type:    rbac.CohortTypeStatic,
		Members: []string{"sprout-1", "sprout-2"},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	cohortRegistry = reg

	// Should refresh without error (PKI will return empty sprout list in test).
	refreshAllCohorts()

	// Verify cache was populated.
	cached, ok := reg.GetCachedMembership("test-static")
	if !ok {
		t.Fatal("expected cached membership after refresh")
	}
	if len(cached.Members) != 2 {
		t.Fatalf("expected 2 cached members, got %d", len(cached.Members))
	}
	if cached.LastRefreshed.IsZero() {
		t.Fatal("expected non-zero LastRefreshed timestamp")
	}
}

// TestCohortRefresherRunsOnce: four replicas tick the cohort refresher at
// the same instant; it refreshes once per interval across them.
func TestCohortRefresherRunsOnce(t *testing.T) {
	gdb := useJobLeaseDB(t)

	var runs atomic.Int32
	orig := cohortRefreshBody
	cohortRefreshBody = func() { runs.Add(1) }
	t.Cleanup(func() { cohortRefreshBody = orig })

	var mu sync.Mutex
	clock := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	advance := func(d time.Duration) { mu.Lock(); clock = clock.Add(d); mu.Unlock() }
	const interval = 10 * time.Minute
	tick := func() {
		var wg sync.WaitGroup
		for range 4 {
			wg.Add(1)
			go func() { defer wg.Done(); refreshCohortsLeased(context.Background(), interval, now) }()
		}
		wg.Wait()
	}

	tick()
	if got := runs.Load(); got != 1 {
		t.Fatalf("first tick refreshed %d times, want 1", got)
	}
	advance(interval / 2)
	tick()
	if got := runs.Load(); got != 1 {
		t.Fatalf("within the interval: %d refreshes in all, want 1", got)
	}
	advance(interval / 2)
	tick()
	if got := runs.Load(); got != 2 {
		t.Fatalf("after the interval: %d refreshes in all, want 2", got)
	}
	var row lease.JobLease
	if err := gdb.Where("name = ?", cohortRefreshJobName).Take(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.LastRunAt == nil || !row.LastRunAt.Equal(now()) {
		t.Fatalf("last_run_at = %v, want %v", row.LastRunAt, now())
	}
}
