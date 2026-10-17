package saasapi

// A cap on one tenant's action backlog (P3 walkthrough 3.4 item 5, unit S3;
// FLAG FOR SECURITY REVIEW). POST .../sprouts/actions accepts a batch into
// the outbox and returns 202; its items are then sent at most
// SAASAPI_ACTION_DISPATCH_TENANT_CONCURRENCY at a time per process
// (dispatch_limits.go), and an item still queued
// SAASAPI_OUTBOX_ACTION_MAX_AGE after the POST fails as expired_not_sent.
// Without a cap a tenant could keep submitting and only learn later that
// most items never ran. With it, a request that would take the tenant's
// pending items (queued or dispatching; a running item is a cook farmer
// already started, so it is no longer waiting to be sent and is not
// counted) past SAASAPI_ACTION_MAX_PENDING_PER_TENANT is
// refused as a whole, at submit time, with 429 backlog_full.
//
// Only §1.5 action batches are checked. An update rollout (§1.8) is never
// refused by it, so a rollout wave is never blocked by the tenant's own
// backlog; its queued items do count towards the next §1.5 request.
//
// The count is a soft limit. It runs inside the batch's own transaction,
// before the batch row is written, but it takes no lock: two requests on
// different replicas (or two in flight on one) at the same moment may both
// see room and both pass, so the backlog can exceed the setting by at most
// the items of the requests in flight, each at most maxAssetIDsPerLookup
// (100), and the per-tenant rate limit allows one request a second per
// tenant per process.

import (
	"fmt"
	"net/http"

	"gorm.io/gorm"
)

// Default and bound of SAASAPI_ACTION_MAX_PENDING_PER_TENANT.
const (
	defaultMaxPendingPerTenant = 2000
	maxMaxPendingPerTenant     = 100000
)

// backlogRetryAfterSeconds is the Retry-After a backlog_full refusal
// carries.
const backlogRetryAfterSeconds = "60"

// errBacklogFull is returned by backlogClaim when a request would take a
// tenant's pending items past the limit. Nothing has been written.
type errBacklogFull struct {
	pending, limit, requested int
}

func (e *errBacklogFull) Error() string {
	return fmt.Sprintf("tenant backlog full: %d pending + %d requested > limit %d", e.pending, e.requested, e.limit)
}

// available is how many more items the tenant could submit now, never
// negative.
func (e *errBacklogFull) available() int {
	return max(e.limit-e.pending, 0)
}

// countPendingItems counts tenantID's items in status queued or
// dispatching (idx_asset_action_items_tenant_status).
func countPendingItems(tx *gorm.DB, tenantID string) (int, error) {
	var n int64
	err := tx.Model(&AssetActionItem{}).
		Where("tenant_id = ? AND status IN ?", tenantID, []AssetActionItemStatus{ActionItemQueued, ActionItemDispatching}).
		Count(&n).Error
	return int(n), err
}

// backlogClaim is createBatch's claim hook for a §1.5 batch of requested
// deduplicated asset_ids: it refuses with *errBacklogFull when the
// tenant's pending items plus requested exceed limit.
func backlogClaim(tenantID string, requested, limit int) func(tx *gorm.DB) error {
	return func(tx *gorm.DB) error {
		pending, err := countPendingItems(tx, tenantID)
		if err != nil {
			return err
		}
		if pending+requested > limit {
			return &errBacklogFull{pending: pending, limit: limit, requested: requested}
		}
		return nil
	}
}

// writeBacklogFull writes the 429 backlog_full refusal for e.
func writeBacklogFull(w http.ResponseWriter, e *errBacklogFull) {
	w.Header().Set("Retry-After", backlogRetryAfterSeconds)
	writeErrorDetails(w, http.StatusTooManyRequests, "backlog_full",
		"this tenant has too many actions waiting to be sent; wait for some to finish and send again",
		map[string]any{
			"pending":   e.pending,
			"limit":     e.limit,
			"requested": e.requested,
			"available": e.available(),
		})
}
