-- +goose Up
-- +goose NO TRANSACTION
--
-- S3 (docs/briefs/S-hardening.md): a cap on one tenant's action backlog.
--
--   asset_action_items index idx_asset_action_items_tenant_status (tenant_id, status)
--
-- POST /tenants/{tenant_id}/sprouts/actions counts the tenant's items in
-- status queued or dispatching, inside the batch's transaction, and
-- refuses the request with 429 backlog_full when that count plus the
-- request's asset_ids exceeds SAASAPI_ACTION_MAX_PENDING_PER_TENANT
-- (internal/saasapi/backlog.go). The primary key is (batch_id, asset_id)
-- and idx_asset_action_items_status covers status alone, so without this
-- index the count reads every queued item of every tenant.
--
-- Expand only: an index changes no column, so a saasapi built for an
-- older schema runs on it unchanged and saasCompatibleFrom stays 1.
-- Migrations are forward-only (no Down section): rolling saasapi back
-- leaves the index in place, where the older release ignores it.
--
-- MySQL has no ADD INDEX IF NOT EXISTS: the step is prepared only when the
-- index is missing ('DO 0' otherwise), as in 00006. Idempotent.

SET @imas_ddl = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `asset_action_items` ADD INDEX `idx_asset_action_items_tenant_status` (`tenant_id`, `status`)', 'DO 0')
  FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'asset_action_items' AND INDEX_NAME = 'idx_asset_action_items_tenant_status');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;
