-- +goose Up
-- +goose NO TRANSACTION
--
-- Drops two indexes asset_links' first GORM model created and the
-- current one doesn't (this was saasapi's migrateSchema until cmd/migrate
-- took over):
--   - idx_asset_links_sprout_id, a single-column UNIQUE on sprout_id.
--     sprout_id is unique per tenant only, so it stopped a second tenant
--     linking its own same-named sprout. idx_asset_links_tenant_sprout
--     (tenant_id, sprout_id) replaces it.
--   - idx_asset_links_tenant_id, redundant now that
--     idx_asset_links_tenant_sprout leads with tenant_id.
--
-- MySQL has no DROP INDEX IF EXISTS, so each drop is prepared only when
-- the index is there ('DO 0' otherwise). goose runs a migration's
-- statements on one connection, so @imas_ddl carries between them.
-- Idempotent; drops nothing on an install created from the baseline.

SET @imas_ddl = (SELECT IF(COUNT(*) > 0,
    'ALTER TABLE `asset_links` DROP INDEX `idx_asset_links_sprout_id`', 'DO 0')
  FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'asset_links'
    AND INDEX_NAME = 'idx_asset_links_sprout_id');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;

SET @imas_ddl = (SELECT IF(COUNT(*) > 0,
    'ALTER TABLE `asset_links` DROP INDEX `idx_asset_links_tenant_id`', 'DO 0')
  FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'asset_links'
    AND INDEX_NAME = 'idx_asset_links_tenant_id');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;
