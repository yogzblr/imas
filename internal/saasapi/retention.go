package saasapi

// Removing terminal rows (U4, docs/retention.md). The outbox sweeper also
// deletes the SaaS database's rows that nothing will change again, once
// they are older than SAASAPI_TERMINAL_ROW_RETENTION (default 2160h, 90
// days):
//
//   - §1.5 action batches and update rollouts whose every item is
//     terminal (AssetActionItemStatus.terminal) and was last changed
//     before the cutoff, created before it, and not leased: the items,
//     then the batch;
//   - provisioning jobs (provision, deprovision) that succeeded or failed
//     before the cutoff, of a tenant that is pending, active or failed.
//     An offboarding, offboarded or purged tenant's jobs stay: they are
//     the tombstone's record (S6 decision 1, internal/tenantpurge
//     KeepTables), purge jobs among them;
//   - enrollment keys (join tokens) whose expiry is before the cutoff.
//     A key is used up, revoked or expired by then (its expiry is at most
//     720h after it was minted), so no token still redeems against it.
//
// Batched and rate limited, so it cannot lock a table: each statement
// selects at most pruneBatchRows primary keys with a plain read (no
// locking read) and deletes exactly those, by primary key and tenant,
// with the terminal condition repeated; it pauses pruneBatchPause between
// statements and stops after pruneMaxBatches statements of each kind per
// run, leaving the rest for the next run (pruneInterval later). Several
// replicas may prune at once: a row two of them delete is deleted once.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"gorm.io/gorm"

	log "github.com/yogzblr/imas/internal/log"
)

// RetentionSettings configures how long the SaaS database keeps terminal
// rows (Config.Retention; SAASAPI_TERMINAL_ROW_RETENTION).
type RetentionSettings struct {
	// TerminalRows is how long a terminal row is kept
	// (SAASAPI_TERMINAL_ROW_RETENTION, default 2160h, 24h to 87600h;
	// empty or 0 is the default).
	TerminalRows time.Duration
}

// Defaults and bounds for RetentionSettings.
const (
	defaultTerminalRowRetention = 2160 * time.Hour
	minTerminalRowRetention     = 24 * time.Hour
	maxTerminalRowRetention     = 87600 * time.Hour
)

// The prune's pacing; variables so tests can shorten them.
var (
	// pruneInterval is the time between one replica's prune runs.
	pruneInterval = time.Hour
	// pruneBatchRows bounds the rows one DELETE removes.
	pruneBatchRows = 500
	// pruneBatchPause is the pause after each DELETE.
	pruneBatchPause = 100 * time.Millisecond
	// pruneMaxBatches bounds the DELETEs of each kind in one run.
	pruneMaxBatches = 50
)

// DefaultRetentionSettings is what LoadConfig starts from.
func DefaultRetentionSettings() RetentionSettings {
	return RetentionSettings{TerminalRows: defaultTerminalRowRetention}
}

// retentionSettings is the configuration in use.
var retentionSettings = DefaultRetentionSettings()

// SetRetentionSettings installs s. Call it once at startup, before
// StartOutboxSweeper. LoadConfig has already validated s.
func SetRetentionSettings(s RetentionSettings) {
	if s.TerminalRows <= 0 {
		s.TerminalRows = defaultTerminalRowRetention
	}
	retentionSettings = s
}

// CurrentRetentionSettings returns the settings in use.
func CurrentRetentionSettings() RetentionSettings { return retentionSettings }

// loadRetentionSettings overrides s's default with
// SAASAPI_TERMINAL_ROW_RETENTION if it is set, refusing a value that
// doesn't parse or is out of range. Empty or 0 keeps the default.
func loadRetentionSettings(s *RetentionSettings) error {
	v := strings.TrimSpace(os.Getenv("SAASAPI_TERMINAL_ROW_RETENTION"))
	if v == "" || v == "0" {
		return nil
	}
	d, err := time.ParseDuration(v)
	if err == nil && d == 0 {
		return nil
	}
	if err != nil || d < minTerminalRowRetention || d > maxTerminalRowRetention {
		return fmt.Errorf("saasapi: SAASAPI_TERMINAL_ROW_RETENTION=%q: want a duration from %s to %s (empty or 0 for the default, %s)",
			v, minTerminalRowRetention, maxTerminalRowRetention, defaultTerminalRowRetention)
	}
	s.TerminalRows = d
	return nil
}

// pruneResult counts one prune run's deleted rows.
type pruneResult struct {
	Items, Batches, ProvisioningJobs, EnrollmentKeys int64
}

// runPruneLoop prunes once now and then every pruneInterval until ctx is
// done.
func (sw *sweeper) runPruneLoop(ctx context.Context) {
	sw.pruneOnce(ctx)
	t := time.NewTicker(pruneInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sw.pruneOnce(ctx)
		}
	}
}

// pruneOnce is one logged prune run.
func (sw *sweeper) pruneOnce(ctx context.Context) {
	if sw.d == nil {
		return
	}
	r, err := pruneTerminalRows(ctx, sw.d, retentionSettings.TerminalRows, outboxNow())
	if err != nil {
		log.Errorf("saasapi: removing terminal rows: %v", err)
	}
	if r != (pruneResult{}) {
		log.Noticef("saasapi: removed terminal rows older than %s: %d action items, %d batches, %d provisioning jobs, %d enrollment keys",
			retentionSettings.TerminalRows, r.Items, r.Batches, r.ProvisioningJobs, r.EnrollmentKeys)
	}
}

// pruneTerminalRows deletes the terminal rows older than retention at
// now (the file comment), at most pruneMaxBatches DELETEs of
// pruneBatchRows rows of each kind.
func pruneTerminalRows(ctx context.Context, d *gorm.DB, retention time.Duration, now time.Time) (pruneResult, error) {
	var r pruneResult
	now = dbTime(now)
	cutoff := now.Add(-retention)
	d = d.WithContext(ctx)
	if err := pruneActionBatches(ctx, d, cutoff, now, &r); err != nil {
		return r, err
	}
	if err := pruneProvisioningJobs(ctx, d, cutoff, &r); err != nil {
		return r, err
	}
	err := pruneEnrollmentKeys(ctx, d, cutoff, &r)
	return r, err
}

// terminalItemStatuses is every terminal AssetActionItemStatus.
var terminalItemStatuses = []AssetActionItemStatus{
	ActionItemUnresolved, ActionItemSucceeded, ActionItemFailed, ActionItemUnresponsiveAfterUpdate,
}

// pause waits pruneBatchPause, or less if ctx is done first.
func pause(ctx context.Context) error {
	t := time.NewTimer(pruneBatchPause)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// openOrYoungItem is the condition of an item that keeps its batch: not
// terminal, or changed at or after cutoff. Its two placeholders are the
// terminal statuses and the cutoff.
const openOrYoungItem = "i.batch_id = b.id AND i.tenant_id = b.tenant_id AND (i.status NOT IN ? OR i.updated_at >= ?)"

// pruneActionBatches deletes the items, then the row, of each batch that
// is done before cutoff and not leased at now.
func pruneActionBatches(ctx context.Context, d *gorm.DB, cutoff, now time.Time, r *pruneResult) error {
	items, batches := AssetActionItem{}.TableName(), AssetActionBatch{}.TableName()
	statements := 0
	for statements < pruneMaxBatches {
		type ref struct{ ID, TenantID string }
		var refs []ref
		if err := d.Table(batches+" AS b").Select("b.id, b.tenant_id").
			Where("b.created_at < ? AND (b.lease_until IS NULL OR b.lease_until < ?)", cutoff, now).
			Where("NOT EXISTS (SELECT 1 FROM "+items+" AS i WHERE "+openOrYoungItem+")", terminalItemStatuses, cutoff).
			Limit(pruneBatchRows).Scan(&refs).Error; err != nil {
			return fmt.Errorf("finding finished action batches: %w", err)
		}
		if len(refs) == 0 {
			return nil
		}
		for _, b := range refs {
			// The batch's items, at most pruneBatchRows per statement.
			for {
				if statements >= pruneMaxBatches {
					return nil
				}
				var assets []string
				if err := d.Model(&AssetActionItem{}).Where("batch_id = ? AND tenant_id = ?", b.ID, b.TenantID).
					Limit(pruneBatchRows).Pluck("asset_id", &assets).Error; err != nil {
					return fmt.Errorf("reading items of batch %s (tenant %s): %w", b.ID, b.TenantID, err)
				}
				if len(assets) == 0 {
					break
				}
				res := d.Where("batch_id = ? AND tenant_id = ? AND asset_id IN ? AND status IN ? AND updated_at < ?",
					b.ID, b.TenantID, assets, terminalItemStatuses, cutoff).Delete(&AssetActionItem{})
				statements++
				if res.Error != nil {
					return fmt.Errorf("deleting items of batch %s (tenant %s): %w", b.ID, b.TenantID, res.Error)
				}
				r.Items += res.RowsAffected
				if err := pause(ctx); err != nil {
					return err
				}
				if res.RowsAffected < int64(len(assets)) {
					break // an item changed since the batch was picked: it stays, and so does the batch
				}
			}
			// The batch, only if no item is left and it is still unleased.
			// No alias on the DELETE's table: sqlite has none.
			res := d.Where("id = ? AND tenant_id = ? AND (lease_until IS NULL OR lease_until < ?)", b.ID, b.TenantID, now).
				Where("NOT EXISTS (SELECT 1 FROM " + items + " WHERE " + items + ".batch_id = " + batches + ".id AND " + items + ".tenant_id = " + batches + ".tenant_id)").
				Delete(&AssetActionBatch{})
			statements++
			if res.Error != nil {
				return fmt.Errorf("deleting batch %s (tenant %s): %w", b.ID, b.TenantID, res.Error)
			}
			r.Batches += res.RowsAffected
			if err := pause(ctx); err != nil {
				return err
			}
			if statements >= pruneMaxBatches {
				return nil
			}
		}
	}
	return nil
}

// prunableTenantStatuses are the tenant statuses whose finished
// provisioning jobs may go: never an offboarding, offboarded or purged
// tenant's, which are its tombstone's record.
var prunableTenantStatuses = []TenantStatus{TenantStatusPending, TenantStatusActive, TenantStatusFailed}

// pruneProvisioningJobs deletes provisioning jobs that ended before
// cutoff, of a tenant whose status is in prunableTenantStatuses.
func pruneProvisioningJobs(ctx context.Context, d *gorm.DB, cutoff time.Time, r *pruneResult) error {
	jobs, tenants := ProvisioningJob{}.TableName(), Tenant{}.TableName()
	finished := []ProvisioningJobStatus{ProvisioningJobSucceeded, ProvisioningJobFailed}
	tenantOK := "tenant_id IN (SELECT id FROM " + tenants + " WHERE status IN ?)"
	for range pruneMaxBatches {
		type ref struct{ ID, TenantID string }
		var refs []ref
		if err := d.Table(jobs).Select("id, tenant_id").
			Where("status IN ? AND updated_at < ? AND type <> ?", finished, cutoff, ProvisioningJobPurge).
			Where(tenantOK, prunableTenantStatuses).
			Limit(pruneBatchRows).Scan(&refs).Error; err != nil {
			return fmt.Errorf("finding finished provisioning jobs: %w", err)
		}
		if len(refs) == 0 {
			return nil
		}
		// One tenant's and another's jobs never share an ID (pj_ plus
		// random), but the delete still carries tenant_id with each.
		var deleted int64
		for tenant, tids := range groupByTenant(refs, func(x ref) (string, string) { return x.TenantID, x.ID }) {
			res := d.Where("id IN ? AND tenant_id = ? AND status IN ? AND updated_at < ? AND type <> ?", tids, tenant, finished, cutoff, ProvisioningJobPurge).
				Where(tenantOK, prunableTenantStatuses).Delete(&ProvisioningJob{})
			if res.Error != nil {
				return fmt.Errorf("deleting finished provisioning jobs: %w", res.Error)
			}
			deleted += res.RowsAffected
		}
		r.ProvisioningJobs += deleted
		if err := pause(ctx); err != nil {
			return err
		}
		if len(refs) < pruneBatchRows {
			return nil
		}
	}
	return nil
}

// pruneEnrollmentKeys deletes enrollment keys whose expiry is before
// cutoff.
func pruneEnrollmentKeys(ctx context.Context, d *gorm.DB, cutoff time.Time, r *pruneResult) error {
	for range pruneMaxBatches {
		type ref struct{ KeyID, TenantID string }
		var refs []ref
		if err := d.Model(&EnrollmentKey{}).Select("key_id, tenant_id").Where("expiry < ?", cutoff).
			Limit(pruneBatchRows).Scan(&refs).Error; err != nil {
			return fmt.Errorf("finding expired enrollment keys: %w", err)
		}
		if len(refs) == 0 {
			return nil
		}
		for tenant, ids := range groupByTenant(refs, func(x ref) (string, string) { return x.TenantID, x.KeyID }) {
			res := d.Where("key_id IN ? AND tenant_id = ? AND expiry < ?", ids, tenant, cutoff).Delete(&EnrollmentKey{})
			if res.Error != nil {
				return fmt.Errorf("deleting expired enrollment keys: %w", res.Error)
			}
			r.EnrollmentKeys += res.RowsAffected
		}
		if err := pause(ctx); err != nil {
			return err
		}
		if len(refs) < pruneBatchRows {
			return nil
		}
	}
	return nil
}

// groupByTenant groups rows' IDs by tenant (key returns tenant and ID).
func groupByTenant[T any](rows []T, key func(T) (string, string)) map[string][]string {
	m := map[string][]string{}
	for _, x := range rows {
		t, id := key(x)
		m[t] = append(m[t], id)
	}
	return m
}
