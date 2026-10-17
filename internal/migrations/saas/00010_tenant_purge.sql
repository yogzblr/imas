-- +goose Up
-- +goose NO TRANSACTION
--
-- S6 (docs/briefs/S6-tenant-erasure.md): erasing an offboarded tenant's
-- data after a retention delay. FLAG FOR SECURITY REVIEW.
--
--   tenants.offboarded_at              datetime(3) NULL
--   tenants.purge_claimed_at           datetime(3) NULL
--   provisioning_jobs.purge_trigger    varchar(16) NOT NULL DEFAULT ''
--   tenants rows: offboarded_at backfilled from updated_at, for
--                 offboarded tenants only
--
-- offboarded_at is when saasapi applied the tenant's deprovision result:
-- the outbox sweeper starts a purge job for a tenant offboarded for at
-- least SAASAPI_TENANT_PURGE_AFTER (internal/saasapi sweeper.go), and GET
-- /tenants/{tenant_id}/status shows when (purge_after). A tenant already
-- offboarded gets updated_at, which applying that result last moved;
-- every other tenant keeps NULL.
--
-- purge_claimed_at is written when a purge job is started for the tenant,
-- conditional on the value read, so two saasapi replicas never both start
-- one (two such writes on different PXC nodes conflict and certification
-- refuses one), and the sweeper retries a failed purge at most daily.
--
-- purge_trigger records what started a purge job (retention or
-- operator); saasapi sends it with every publish of the job.
--
-- Expand only. The previous release's saasapi doesn't know the columns:
-- GORM skips columns its model lacks when it reads, and its inserts name
-- their columns, so the new ones take their defaults; a tenant it
-- offboards keeps offboarded_at NULL, and the sweeper reads
-- COALESCE(offboarded_at, updated_at). Nothing is dropped, so
-- saasCompatibleFrom stays 1. Migrations are forward-only (no Down
-- section): rolling saasapi back leaves the columns in place.
--
-- MySQL has no ADD COLUMN IF NOT EXISTS: each step is prepared only when
-- the column is missing ('DO 0' otherwise), as in 00006. The backfill
-- touches only rows still NULL. Idempotent.

SET @imas_ddl = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `tenants` ADD COLUMN `offboarded_at` datetime(3) DEFAULT NULL', 'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tenants' AND COLUMN_NAME = 'offboarded_at');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;

SET @imas_ddl = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `tenants` ADD COLUMN `purge_claimed_at` datetime(3) DEFAULT NULL', 'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tenants' AND COLUMN_NAME = 'purge_claimed_at');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;

SET @imas_ddl = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `provisioning_jobs` ADD COLUMN `purge_trigger` varchar(16) NOT NULL DEFAULT ''''', 'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'provisioning_jobs' AND COLUMN_NAME = 'purge_trigger');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;

UPDATE `tenants` SET `offboarded_at` = `updated_at`
  WHERE `status` = 'offboarded' AND `offboarded_at` IS NULL;
