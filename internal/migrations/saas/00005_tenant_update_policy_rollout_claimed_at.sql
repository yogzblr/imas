-- +goose Up
-- +goose NO TRANSACTION
--
-- FU.6b: saas.tenant_update_policy.rollout_claimed_at, datetime(3) NULL.
--
-- saasapi's claimRollout (internal/saasapi/fleet_update_dispatch.go) has
-- to write the tenant's policy row when it starts an update rollout, so
-- that Galera certification refuses one of two claims committed on
-- different PXC nodes. It wrote updated_at, so GET update-policy reported
-- a policy change whenever a rollout started. It now writes this column
-- instead, and updated_at moves only when the policy does. The column is
-- never returned by the API.
--
-- Expand only. The previous release's saasapi doesn't know the column:
-- GORM skips columns its model lacks when it reads (SELECT *), and its
-- inserts name their columns, so the new one is NULL. Its claims still
-- write updated_at; the two releases' claims still write the same row, so
-- certification holds while both run. Nothing is dropped, so
-- compatibleFrom stays.
--
-- MySQL has no ADD COLUMN IF NOT EXISTS: prepared only when the column is
-- missing ('DO 0' otherwise), as in 00003. Idempotent.

SET @imas_ddl = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `tenant_update_policy` ADD COLUMN `rollout_claimed_at` datetime(3) DEFAULT NULL', 'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'tenant_update_policy'
    AND COLUMN_NAME = 'rollout_claimed_at');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;
