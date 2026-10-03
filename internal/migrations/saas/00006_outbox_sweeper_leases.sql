-- +goose Up
-- +goose NO TRANSACTION
--
-- CL.3: the columns saasapi's outbox sweeper (internal/saasapi/sweeper.go)
-- needs to re-dispatch work whose dispatching process died, safely with
-- several saasapi replicas.
--
--   provisioning_jobs.last_dispatched_at  datetime(3) NULL
--   provisioning_jobs.lease_owner         varchar(64) NOT NULL DEFAULT ''
--   provisioning_jobs.lease_until         datetime(3) NULL
--   asset_action_batches.lease_owner      varchar(64) NOT NULL DEFAULT ''
--   asset_action_batches.lease_until      datetime(3) NULL
--   asset_action_items.dispatched_at      datetime(3) NULL
--   asset_action_items.planned_at_target  tinyint(1) NOT NULL DEFAULT '0'
--   asset_action_items index idx_asset_action_items_status (status)
--
-- The lease is a row lease, not GET_LOCK, which is node-local on Galera:
-- a replica claims a row with one conditional UPDATE (lease expired or
-- never set) and owns it only if that UPDATE affected the row. On PXC two
-- claims committed on different nodes write the same row, so
-- certification refuses one of them.
--
-- last_dispatched_at is when a provisioning job was last published (its
-- backoff is measured from it). dispatched_at is when an action item was
-- claimed for sending, cleared if the bus proved it was never delivered;
-- a resumed update rollout measures its wave deadline and judges the
-- freshness of a sprout's report from it. planned_at_target records that
-- the sprout already reported the target version when the rollout was
-- planned, which the rollout's gate needs and couldn't otherwise rebuild.
-- The status index serves the sweeper's search for queued and unfinished
-- items across batches.
--
-- Expand only. The previous release's saasapi doesn't know the columns:
-- GORM skips columns its model lacks when it reads (SELECT *), and its
-- inserts name their columns, so the new ones take their defaults. A
-- batch it created has no lease (lease_until NULL); the sweeper treats such
-- a rollout as live until its items have been quiet for longer than a wave
-- can take. Nothing is dropped, so compatibleFrom stays.
--
-- MySQL has no ADD COLUMN IF NOT EXISTS or ADD INDEX IF NOT EXISTS: each
-- step is prepared only when the column or index is missing ('DO 0'
-- otherwise), as in 00003. The index is added after its table's columns,
-- so a re-run after a failure halfway resumes where it stopped. Idempotent.

SET @imas_ddl = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `provisioning_jobs` ADD COLUMN `last_dispatched_at` datetime(3) DEFAULT NULL', 'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'provisioning_jobs' AND COLUMN_NAME = 'last_dispatched_at');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;

SET @imas_ddl = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `provisioning_jobs` ADD COLUMN `lease_owner` varchar(64) NOT NULL DEFAULT ''''', 'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'provisioning_jobs' AND COLUMN_NAME = 'lease_owner');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;

SET @imas_ddl = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `provisioning_jobs` ADD COLUMN `lease_until` datetime(3) DEFAULT NULL', 'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'provisioning_jobs' AND COLUMN_NAME = 'lease_until');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;

SET @imas_ddl = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `asset_action_batches` ADD COLUMN `lease_owner` varchar(64) NOT NULL DEFAULT ''''', 'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'asset_action_batches' AND COLUMN_NAME = 'lease_owner');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;

SET @imas_ddl = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `asset_action_batches` ADD COLUMN `lease_until` datetime(3) DEFAULT NULL', 'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'asset_action_batches' AND COLUMN_NAME = 'lease_until');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;

SET @imas_ddl = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `asset_action_items` ADD COLUMN `dispatched_at` datetime(3) DEFAULT NULL', 'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'asset_action_items' AND COLUMN_NAME = 'dispatched_at');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;

SET @imas_ddl = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `asset_action_items` ADD COLUMN `planned_at_target` tinyint(1) NOT NULL DEFAULT ''0''', 'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'asset_action_items' AND COLUMN_NAME = 'planned_at_target');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;

SET @imas_ddl = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `asset_action_items` ADD INDEX `idx_asset_action_items_status` (`status`)', 'DO 0')
  FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'asset_action_items' AND INDEX_NAME = 'idx_asset_action_items_status');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;
