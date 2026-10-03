package saasapi

// The outbox sweeper against MySQL, where the lease's guarantees actually
// come from: InnoDB row locks, rows affected counting changed rows, and
// datetime(3) comparisons. Skipped unless IMAS_TEST_MYSQL_ROOT_DSN names a
// MySQL-compatible server by its root account, as in internal/migrations'
// MySQL tests:
//
//	IMAS_TEST_MYSQL_ROOT_DSN='root:pw@tcp(127.0.0.1:3306)/' go test ./internal/saasapi/ -run MySQL

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/yogzblr/imas/internal/controlplane"
	"github.com/yogzblr/imas/internal/migrations"
)

// newMySQLSaasSchema creates a fresh schema migrated by the saas set and
// returns two independent GORM handles on it, standing in for two
// saasapi replicas. The schema is dropped when the test ends.
func newMySQLSaasSchema(t *testing.T) (*gorm.DB, *gorm.DB) {
	t.Helper()
	dsn := os.Getenv("IMAS_TEST_MYSQL_ROOT_DSN")
	if dsn == "" {
		t.Skip("IMAS_TEST_MYSQL_ROOT_DSN not set; skipping the MySQL tests")
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal("IMAS_TEST_MYSQL_ROOT_DSN: not a valid DSN")
	}
	sfx := make([]byte, 4)
	if _, err := rand.Read(sfx); err != nil {
		t.Fatal(err)
	}
	schema := "t_saasapi_sweep_" + hex.EncodeToString(sfx)
	cfg.DBName = ""
	root, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	if _, err := root.Exec("CREATE DATABASE `" + schema + "`"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Exec("DROP DATABASE IF EXISTS `" + schema + "`") })

	cfg = cfg.Clone()
	cfg.DBName, cfg.ParseTime, cfg.Loc = schema, true, time.UTC
	sdb, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sdb.Close() })
	if _, err := migrations.Up(context.Background(), sdb, migrations.Saas, t.Logf); err != nil {
		t.Fatal(err)
	}
	open := func() *gorm.DB {
		g, err := gorm.Open(gormmysql.Open(cfg.FormatDSN()), &gorm.Config{Logger: gormlogger.Default.LogMode(gormlogger.Silent)})
		if err != nil {
			t.Fatal(err)
		}
		if s, err := g.DB(); err == nil {
			t.Cleanup(func() { s.Close() })
		}
		return g
	}
	return open(), open()
}

// Lease claims on MySQL: of many concurrent claims on one row exactly one
// wins; a live lease isn't taken over and an expired one is; a renewal is
// never a no-op MySQL reports as zero rows, even within one millisecond.
func TestMySQLRowLease(t *testing.T) {
	g1, g2 := newMySQLSaasSchema(t)
	clock := useTestClock(t)
	batch := AssetActionBatch{ID: "b_mysql_lease", TenantID: "t_mysql", ActionType: "cmd.run", ActionParams: "{}", RequestedAssetIDs: "[]"}
	if err := g1.Create(&batch).Error; err != nil {
		t.Fatal(err)
	}
	table, key := AssetActionBatch{}.TableName(), []any{batch.ID, batch.TenantID}

	var (
		mu   sync.Mutex
		won  []*rowLease
		wg   sync.WaitGroup
		errs []error
	)
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g := g1
			if i%2 == 1 {
				g = g2
			}
			l, err := claimRowLease(g, table, batchLeaseKey, key, "", nil, nil, time.Minute)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
			}
			if l != nil {
				won = append(won, l)
			}
		}()
	}
	wg.Wait()
	if len(won) != 1 || len(errs) != 0 {
		t.Fatalf("%d of 16 concurrent claims won (errors %v), want exactly 1", len(won), errs)
	}
	holder := won[0]

	// Two renewals in the same millisecond still each change the row.
	for i := range 2 {
		if !holder.renew() {
			t.Fatalf("renewal %d within one millisecond was reported as a lost lease", i+1)
		}
	}
	clock.Advance(30 * time.Second)
	if l, err := claimRowLease(g2, table, batchLeaseKey, key, "", nil, nil, time.Minute); l != nil || err != nil {
		t.Fatalf("a live lease was taken over (%v)", err)
	}
	clock.Advance(2 * time.Minute)
	taker, err := claimRowLease(g2, table, batchLeaseKey, key, "", nil, nil, time.Minute)
	if err != nil || taker == nil {
		t.Fatalf("an expired lease was not taken over (%v)", err)
	}
	if holder.renew() || holder.held() {
		t.Fatal("the old holder kept a lease that was taken over")
	}
	if !taker.renew() {
		t.Fatal("the new holder could not renew")
	}
}

// The provisioning crash case on MySQL, with two replicas' sweepers on
// separate connection pools: the job is published once per due attempt.
func TestMySQLSweepProvisioningJobs_TwoReplicas(t *testing.T) {
	g1, g2 := newMySQLSaasSchema(t)
	clock := useTestClock(t)
	SetDB(g1)
	t.Cleanup(func() { SetDB(nil) })
	tenant := Tenant{ID: "t_mysql_prov", Name: "Acme", Status: TenantStatusPending}
	if err := g1.Create(&tenant).Error; err != nil {
		t.Fatal(err)
	}
	job, err := enqueueProvisioningJob(g1, tenant.ID, ProvisioningJobProvision)
	if err != nil {
		t.Fatal(err)
	}
	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	farmer := startProvisioningFarmer(t, nc)
	a, b := testSweeper(g1, nc), testSweeper(g2, nc)

	for attempt := 1; attempt <= 3; attempt++ {
		clock.Advance(backoff(defaultProvisioningStaleAfter, attempt-1) + time.Second)
		sweepConcurrently(a, b, a, b)
		if got := farmer.received(t, attempt); got[job.ID] != attempt {
			t.Fatalf("attempt %d: farmer got %v", attempt, got)
		}
	}
	var stored ProvisioningJob
	if err := g2.First(&stored, "id = ?", job.ID).Error; err != nil || stored.Attempts != 3 || stored.LastDispatchedAt == nil {
		t.Fatalf("stored job %+v, %v", stored, err)
	}
}

// The action batch crash case on MySQL, with two replicas' sweepers on
// separate connection pools sweeping repeatedly: every queued item is
// sent exactly once, and a dispatching item a dead process left an hour
// ago is never sent, only failed with dispatch_outcome_unknown.
func TestMySQLSweepActionBatches_TwoReplicas(t *testing.T) {
	g1, g2 := newMySQLSaasSchema(t)
	clock := useTestClock(t)
	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	farmer := startFakeFarmer(t, ns, completingFarmer)

	if err := g1.Create(&Tenant{ID: "t_mysql", Name: "Acme", Status: TenantStatusActive}).Error; err != nil {
		t.Fatal(err)
	}
	params, _ := json.Marshal(farmerCmdRun{Command: "uptime", Timeout: time.Minute})
	expired := dbTime(clock.Now().Add(-time.Minute))
	batch := AssetActionBatch{ID: "b_mysql_sweep", TenantID: "t_mysql", ActionType: controlplane.ActionCmdRun,
		ActionParams: string(params), RequestedAssetIDs: "[]", LeaseOwner: "dead-pod/x", LeaseUntil: &expired}
	if err := g1.Create(&batch).Error; err != nil {
		t.Fatal(err)
	}
	sent := dbTime(clock.Now().Add(-time.Hour))
	items := []AssetActionItem{{BatchID: batch.ID, AssetID: "stuck", TenantID: batch.TenantID, SproutID: "web-stuck",
		Status: ActionItemDispatching, Attempts: 1, DispatchedAt: &sent}}
	for i := range 8 {
		items = append(items, AssetActionItem{BatchID: batch.ID, AssetID: fmt.Sprintf("q%d", i), TenantID: batch.TenantID,
			Position: i + 1, SproutID: fmt.Sprintf("web-%d", i), Status: ActionItemQueued})
	}
	if err := g1.Create(&items).Error; err != nil {
		t.Fatal(err)
	}

	clock.Advance(defaultActionStaleAfter + time.Second)
	a, b := testSweeper(g1, nc), testSweeper(g2, nc)
	sweepConcurrently(a, b, a, b, a, b)
	sends := sendsPerSprout(farmer)
	if len(sends) != 8 || sends[SproutRef{TenantID: batch.TenantID, SproutID: "web-stuck"}] != 0 {
		t.Fatalf("sends = %v", sends)
	}
	for ref, n := range sends {
		if n != 1 {
			t.Fatalf("%v sent %d times", ref, n)
		}
	}
	var stuck AssetActionItem
	if err := g2.First(&stuck, "batch_id = ? AND asset_id = ?", batch.ID, "stuck").Error; err != nil ||
		stuck.Status != ActionItemFailed || stuck.ErrorCode != errCodeDispatchOutcomeUnknown {
		t.Fatalf("dispatching item = %+v, %v", stuck, err)
	}
}

// Taking over a rollout on MySQL: of many concurrent takeovers from two
// replicas exactly one wins, and it rewrites the tenant's rollout claim in
// the same transaction.
func TestMySQLClaimRolloutTakeover(t *testing.T) {
	g1, g2 := newMySQLSaasSchema(t)
	useTestClock(t)
	version := "v2.4.1"
	prev := dbTime(time.Now().Add(-time.Hour))
	if err := g1.Create(&TenantUpdatePolicy{TenantID: "t_mysql", ApprovedVersion: &version, RolloutClaimedAt: &prev}).Error; err != nil {
		t.Fatal(err)
	}
	expired := dbTime(outboxNow().Add(-time.Second))
	batch := AssetActionBatch{ID: "b_mysql_roll", TenantID: "t_mysql", ActionType: controlplane.ActionSelfUpdate,
		ActionParams: `{"version":"v2.4.1"}`, RequestedAssetIDs: "[]", RolloutBatchSize: 1, RolloutGate: gateJobStatus,
		LeaseOwner: "dead-pod/x", LeaseUntil: &expired}
	if err := g1.Create(&batch).Error; err != nil {
		t.Fatal(err)
	}
	var (
		mu  sync.Mutex
		won int
		wg  sync.WaitGroup
	)
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g := g1
			if i%2 == 1 {
				g = g2
			}
			l, err := claimRolloutTakeover(g, batch, time.Minute)
			if err != nil {
				t.Logf("takeover %d: %v (counts as not claimed)", i, err)
			}
			if l != nil {
				mu.Lock()
				won++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if won != 1 {
		t.Fatalf("%d of 12 concurrent takeovers won, want 1", won)
	}
	var p TenantUpdatePolicy
	if err := g2.First(&p, "tenant_id = ?", "t_mysql").Error; err != nil || p.RolloutClaimedAt == nil || !p.RolloutClaimedAt.After(prev) {
		t.Fatalf("rollout claim after the takeover: %+v, %v", p.RolloutClaimedAt, err)
	}
}

// The DELETE wait after a re-published provision job comes from the
// database (provisioning_jobs.attempts and last_dispatched_at), not from
// any replica's memory: replica A's sweeper re-publishes the job, and a
// DELETE served by replica B, on its own connection pool, still waits it
// out, then goes ahead once the window has passed.
func TestMySQLDeleteWaitIsSharedAcrossReplicas(t *testing.T) {
	g1, g2 := newMySQLSaasSchema(t)
	clock := useTestClock(t)
	tenant := Tenant{ID: "t_mysql_del", Name: "Acme", Status: TenantStatusPending}
	if err := g1.Create(&tenant).Error; err != nil {
		t.Fatal(err)
	}
	job, err := enqueueProvisioningJob(g1, tenant.ID, ProvisioningJobProvision)
	if err != nil {
		t.Fatal(err)
	}
	ns := startTestBus(t)
	nc := connectSaaSBus(t, ns)
	farmer := startProvisioningFarmer(t, nc)

	// Replica A publishes it twice (the original and one re-publish).
	SetDB(g1)
	dispatchProvisioning(context.Background(), job, tenant.Name)
	clock.Advance(defaultProvisioningStaleAfter + time.Second)
	testSweeper(g1, nc).sweep()
	if got := farmer.received(t, 2); got[job.ID] != 2 {
		t.Fatalf("farmer got %v", got)
	}
	// One copy's result comes back: the tenant is active.
	if err := applyProvisioningResult(ProvisioningJobProvision, controlplane.TenantResult{JobID: job.ID, TenantID: tenant.ID, Status: controlplane.StatusActive}); err != nil {
		t.Fatal(err)
	}

	// Replica B serves the DELETE.
	SetDB(g2)
	t.Cleanup(func() { SetDB(nil) })
	SetBus(nil)
	del := func() int {
		return doRequest(t, DeleteTenant, "DELETE", "/v1/tenants/"+tenant.ID, map[string]string{"tenant_id": tenant.ID}, nil).Code
	}
	if code := del(); code != 409 {
		t.Fatalf("DELETE on the other replica right after the re-publish: %d, want 409", code)
	}
	clock.Advance(defaultProvisioningStaleAfter + time.Second)
	if code := del(); code != 202 {
		t.Fatalf("DELETE after the window: %d, want 202", code)
	}
}
