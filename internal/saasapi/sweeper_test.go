package saasapi

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"gorm.io/gorm"

	"github.com/yogzblr/imas/internal/controlplane"
)

// clearOutbox empties the outbox tables. The sqlite test database is
// shared by the package's tests, and the sweeper, unlike the handlers,
// looks at every tenant's rows.
func clearOutbox(t *testing.T, gdb *gorm.DB) {
	t.Helper()
	for _, m := range []any{&ProvisioningJob{}, &AssetActionItem{}, &AssetActionBatch{}} {
		if err := gdb.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(m).Error; err != nil {
			t.Fatalf("clearing %T: %v", m, err)
		}
	}
}

// testClock replaces outboxNow (and rolloutNow, so dispatch times agree)
// with a clock the test moves by hand.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func useTestClock(t *testing.T) *testClock {
	t.Helper()
	c := &testClock{now: time.Now().UTC().Truncate(time.Millisecond)}
	prevOutbox, prevRollout := outboxNow, rolloutNow
	outboxNow, rolloutNow = c.Now, c.Now
	t.Cleanup(func() { outboxNow, rolloutNow = prevOutbox, prevRollout })
	return c
}

// useOutboxClock is useTestClock for outboxNow alone: leases move with the
// test's clock, while rollouts keep the real one, which farmer.props'
// write times (reportFact) are on.
func useOutboxClock(t *testing.T) *testClock {
	t.Helper()
	c := &testClock{now: time.Now().UTC().Truncate(time.Millisecond)}
	prev := outboxNow
	outboxNow = c.Now
	t.Cleanup(func() { outboxNow = prev })
	return c
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// testSweeper is a sweeper over gdb and nc with the default settings and
// the installed readers.
func testSweeper(gdb *gorm.DB, nc *nats.Conn) *sweeper {
	return &sweeper{d: gdb, nc: nc, readers: rolloutReaders{jobs: jobStatusReader, facts: sproutFactsReader}, s: DefaultOutboxSweeperSettings()}
}

// sweepConcurrently runs every sweeper's sweep at once and waits for them
// and for any dispatch they started.
func sweepConcurrently(sws ...*sweeper) {
	var wg sync.WaitGroup
	for _, sw := range sws {
		wg.Add(1)
		go func() { defer wg.Done(); sw.sweep() }()
	}
	wg.Wait()
	actionDispatches.Wait()
}

func TestBackoff(t *testing.T) {
	for attempts, want := range map[int]time.Duration{
		0: time.Minute, 1: time.Minute, 2: 2 * time.Minute, 3: 4 * time.Minute,
		7: 64 * time.Minute, 50: 64 * time.Minute,
	} {
		if got := backoff(time.Minute, attempts); got != want {
			t.Errorf("backoff(1m, %d) = %s, want %s", attempts, got, want)
		}
	}
}

func TestLoadConfigOutboxSweeper(t *testing.T) {
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OutboxSweeper != DefaultOutboxSweeperSettings() || !cfg.OutboxSweeper.Enabled {
		t.Fatalf("defaults = %+v", cfg.OutboxSweeper)
	}

	t.Setenv("SAASAPI_OUTBOX_SWEEPER_ENABLED", "false")
	t.Setenv("SAASAPI_OUTBOX_SWEEP_INTERVAL", "10s")
	t.Setenv("SAASAPI_OUTBOX_PROVISIONING_STALE_AFTER", "5m")
	t.Setenv("SAASAPI_OUTBOX_ACTION_STALE_AFTER", "90s")
	t.Setenv("SAASAPI_OUTBOX_ACTION_MAX_AGE", "10m")
	t.Setenv("SAASAPI_OUTBOX_MAX_ATTEMPTS", "3")
	t.Setenv("SAASAPI_OUTBOX_LEASE_TTL", "1m")
	cfg, err = LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	want := OutboxSweeperSettings{Enabled: false, Interval: 10 * time.Second, ProvisioningStaleAfter: 5 * time.Minute,
		ActionStaleAfter: 90 * time.Second, ActionMaxAge: 10 * time.Minute, MaxAttempts: 3, LeaseTTL: time.Minute,
		DispatchConcurrency: 64, SelfUpdateDispatchConcurrency: 16, DispatchTenantConcurrency: 8}
	if cfg.OutboxSweeper != want {
		t.Fatalf("overrides = %+v, want %+v", cfg.OutboxSweeper, want)
	}

	for name, bad := range map[string]string{
		"SAASAPI_OUTBOX_SWEEPER_ENABLED":          "sometimes",
		"SAASAPI_OUTBOX_SWEEP_INTERVAL":           "0s",
		"SAASAPI_OUTBOX_PROVISIONING_STALE_AFTER": "1s",
		"SAASAPI_OUTBOX_ACTION_STALE_AFTER":       "48h",
		"SAASAPI_OUTBOX_ACTION_MAX_AGE":           "2h",
		"SAASAPI_OUTBOX_MAX_ATTEMPTS":             "0",
		"SAASAPI_OUTBOX_LEASE_TTL":                "5s",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, bad)
			if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("%s=%q: %v", name, bad, err)
			}
		})
	}
}

// A live lease is not taken over; an expired one is, and its old holder
// finds out on its next renewal and stops.
func TestRowLeaseTakeover(t *testing.T) {
	gdb := newTestDB(t)
	clearOutbox(t, gdb)
	clock := useTestClock(t)
	tid := mustCreateActiveTenant(t, gdb)
	batch := AssetActionBatch{ID: "b_lease_" + tid, TenantID: tid, ActionType: controlplane.ActionCmdRun, ActionParams: "{}", RequestedAssetIDs: "[]"}
	if err := gdb.Create(&batch).Error; err != nil {
		t.Fatal(err)
	}
	table, key := AssetActionBatch{}.TableName(), []any{batch.ID, tid}
	claim := func() *rowLease {
		t.Helper()
		l, err := claimRowLease(gdb, table, batchLeaseKey, key, "", nil, nil, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		return l
	}

	first := claim()
	if first == nil || !first.held() {
		t.Fatal("a never-leased row was not claimed")
	}
	if claim() != nil {
		t.Fatal("a live lease was taken over")
	}
	clock.Advance(30 * time.Second)
	if !first.renew() || !first.held() {
		t.Fatal("the holder could not renew its own lease")
	}
	clock.Advance(59 * time.Second)
	if claim() != nil {
		t.Fatal("a renewed lease was taken over before it expired")
	}

	clock.Advance(2 * time.Second)
	if first.held() {
		t.Fatal("a lease past its expiry still reads as held")
	}
	second := claim()
	if second == nil || !second.held() {
		t.Fatal("an expired lease was not taken over")
	}
	if first.renew() || first.held() {
		t.Fatal("the old holder renewed a lease another holder took")
	}
	var stored AssetActionBatch
	gdb.First(&stored, "id = ?", batch.ID)
	if stored.LeaseOwner != second.token || !strings.HasPrefix(stored.LeaseOwner, replicaName+"/") || len(stored.LeaseOwner) > 64 {
		t.Fatalf("lease_owner = %q", stored.LeaseOwner)
	}
}

// provisioningFarmer counts the provisioning requests farmer receives,
// per job, and answers none of them.
type provisioningFarmer struct {
	mu    sync.Mutex
	byJob map[string]int
	names map[string]string
}

func startProvisioningFarmer(t *testing.T, nc *nats.Conn) *provisioningFarmer {
	t.Helper()
	f := &provisioningFarmer{byJob: map[string]int{}, names: map[string]string{}}
	for _, subject := range []string{controlplane.SubjectTenantProvision, controlplane.SubjectTenantDeprovision} {
		if _, err := nc.Subscribe(subject, func(msg *nats.Msg) {
			var req controlplane.TenantProvisionRequest
			if err := json.Unmarshal(msg.Data, &req); err != nil {
				t.Errorf("bad request: %v", err)
				return
			}
			f.mu.Lock()
			f.byJob[req.JobID]++
			f.names[req.JobID] = req.Name
			f.mu.Unlock()
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	return f
}

// received waits briefly for farmer to have seen want requests in all,
// and returns the per-job counts.
func (f *provisioningFarmer) received(t *testing.T, want int) map[string]int {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.mu.Lock()
		n := 0
		out := map[string]int{}
		for k, v := range f.byJob {
			out[k] = v
			n += v
		}
		f.mu.Unlock()
		if n >= want || time.Now().After(deadline) {
			// Give a would-be extra request a moment to show up.
			time.Sleep(50 * time.Millisecond)
			f.mu.Lock()
			out = map[string]int{}
			for k, v := range f.byJob {
				out[k] = v
			}
			f.mu.Unlock()
			return out
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The crash case for provisioning: a tenant is created while saasapi has
// no bus (as if its pod died before the publish). Two sweepers on one
// database then publish the job exactly once, again only after the
// backoff, and finally fail the job and the tenant once every attempt is
// used. A result that arrives in time stops the re-publishing.
func TestSweepProvisioningJobs_CrashThenTwoSweepers(t *testing.T) {
	gdb := newTestDB(t)
	clearOutbox(t, gdb)
	clock := useTestClock(t)
	SetBus(nil)
	tenantID := mustCreateTenant(t, "Swept Ltd")
	job := latestJob(t, gdb, tenantID)
	if job.Attempts != 0 || job.LastDispatchedAt != nil {
		t.Fatalf("job dispatched without a bus: %+v", job)
	}

	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	farmer := startProvisioningFarmer(t, nc)
	a, b := testSweeper(gdb, nc), testSweeper(gdb, nc)

	// Not stale yet: nothing.
	sweepConcurrently(a, b)
	if got := farmer.received(t, 0); len(got) != 0 {
		t.Fatalf("published before the job was stale: %v", got)
	}

	clock.Advance(defaultProvisioningStaleAfter + time.Second)
	sweepConcurrently(a, b)
	if got := farmer.received(t, 1); got[job.ID] != 1 || len(got) != 1 {
		t.Fatalf("after the first sweep farmer got %v, want one request for %s", got, job.ID)
	}
	if farmer.names[job.ID] != "Swept Ltd" {
		t.Fatalf("re-published request names tenant %q", farmer.names[job.ID])
	}
	job = latestJob(t, gdb, tenantID)
	if job.Attempts != 1 || job.LastDispatchedAt == nil || !job.LastDispatchedAt.Equal(dbTime(clock.Now())) {
		t.Fatalf("after the re-publish: %+v", job)
	}

	// Every further attempt waits twice as long as the one before, and
	// nothing goes out within the backoff.
	for attempt := 2; attempt <= defaultOutboxMaxAttempts; attempt++ {
		clock.Advance(backoff(defaultProvisioningStaleAfter, attempt-1) - time.Second)
		sweepConcurrently(a, b)
		if got := farmer.received(t, attempt-1); got[job.ID] != attempt-1 {
			t.Fatalf("attempt %d went out before its backoff: %v", attempt, got)
		}
		clock.Advance(2 * time.Second)
		sweepConcurrently(a, b)
		if got := farmer.received(t, attempt); got[job.ID] != attempt {
			t.Fatalf("attempt %d: farmer got %v", attempt, got)
		}
	}

	// Out of attempts: failed after the last backoff, with a fixed message.
	clock.Advance(backoff(defaultProvisioningStaleAfter, defaultOutboxMaxAttempts) + time.Second)
	sweepConcurrently(a, b)
	if got := farmer.received(t, defaultOutboxMaxAttempts); got[job.ID] != defaultOutboxMaxAttempts {
		t.Fatalf("published past the attempt limit: %v", got)
	}
	tenant, job := reload(t, gdb, tenantID, job.ID)
	if job.Status != ProvisioningJobFailed || tenant.Status != TenantStatusFailed ||
		job.LastError != provisioningNoResultMessage+" (reference "+job.ID+")" {
		t.Fatalf("after the last attempt: tenant %s, job %+v", tenant.Status, job)
	}
	// A late result changes nothing.
	if err := applyProvisioningResult(ProvisioningJobProvision, controlplane.TenantResult{JobID: job.ID, TenantID: tenantID, Status: controlplane.StatusActive}); err != nil {
		t.Fatal(err)
	}
	if tenant, _ := reload(t, gdb, tenantID, job.ID); tenant.Status != TenantStatusFailed {
		t.Fatalf("late result moved the tenant to %s", tenant.Status)
	}
}

func TestSweepProvisioningJobs_ResultStopsRepublishing(t *testing.T) {
	gdb := newTestDB(t)
	clearOutbox(t, gdb)
	clock := useTestClock(t)
	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	farmer := startProvisioningFarmer(t, nc)
	tenant, job := seedTenantAndJob(t, gdb, TenantStatusOffboarding, ProvisioningJobDeprovision)
	sw := testSweeper(gdb, nc)

	clock.Advance(defaultProvisioningStaleAfter + time.Second)
	sw.sweep()
	if got := farmer.received(t, 1); got[job.ID] != 1 {
		t.Fatalf("deprovision job not re-published: %v", got)
	}
	if err := applyProvisioningResult(ProvisioningJobDeprovision, controlplane.TenantResult{JobID: job.ID, TenantID: tenant.ID, Status: controlplane.StatusOffboarded}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(time.Hour)
	sw.sweep()
	if got := farmer.received(t, 1); got[job.ID] != 1 {
		t.Fatalf("a finished job was re-published: %v", got)
	}
	if tenant, _ := reload(t, gdb, tenant.ID, job.ID); tenant.Status != TenantStatusOffboarded {
		t.Fatalf("tenant = %s", tenant.Status)
	}
}

// No bus connection, or a closed one: the sweep claims and sends nothing.
func TestSweep_SkipsWithoutBus(t *testing.T) {
	gdb := newTestDB(t)
	clearOutbox(t, gdb)
	clock := useTestClock(t)
	_, job := seedTenantAndJob(t, gdb, TenantStatusPending, ProvisioningJobProvision)
	clock.Advance(time.Hour)

	testSweeper(gdb, nil).sweep()
	ns := startTestBus(t)
	nc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	nc.Close()
	testSweeper(gdb, nc).sweep()

	var stored ProvisioningJob
	gdb.First(&stored, "id = ?", job.ID)
	if stored.Attempts != 0 || stored.LeaseUntil != nil || stored.LastDispatchedAt != nil {
		t.Fatalf("a sweep without a bus touched the job: %+v", stored)
	}
}

// DELETE doesn't wait out a provision job the sweeper re-published: a
// copy still running on farmer can no longer leave the tenant live on the
// bus (internal/pki's TestProvisionDeprovisionRace_* tests), so offboarding
// goes ahead at once, however recently the job was last published.
func TestDeleteTenant_DoesNotWaitOutRepublishedProvisionJob(t *testing.T) {
	gdb := newTestDB(t)
	clearOutbox(t, gdb)
	clock := useTestClock(t)
	SetBus(nil)
	tenant, job := seedTenantAndJob(t, gdb, TenantStatusActive, ProvisioningJobProvision)
	if err := gdb.Model(&ProvisioningJob{}).Where("id = ?", job.ID).Updates(map[string]any{
		"status": ProvisioningJobSucceeded, "attempts": 3, "last_dispatched_at": dbTime(clock.Now())}).Error; err != nil {
		t.Fatal(err)
	}
	if code := doRequest(t, DeleteTenant, "DELETE", "/v1/tenants/"+tenant.ID, map[string]string{"tenant_id": tenant.ID}, nil).Code; code != 202 {
		t.Fatalf("DELETE right after a re-publish: %d, want 202", code)
	}
}

func latestJob(t *testing.T, gdb *gorm.DB, tenantID string) ProvisioningJob {
	t.Helper()
	var job ProvisioningJob
	if err := gdb.Where("tenant_id = ?", tenantID).Order("created_at DESC").First(&job).Error; err != nil {
		t.Fatal(err)
	}
	return job
}
