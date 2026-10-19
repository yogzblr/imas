-- +goose Up
-- +goose NO TRANSACTION
--
-- P29: farmer.job_status.dispatch_refused, tinyint(1) NOT NULL DEFAULT 0.
--
-- Farmer answers the SaaS API's cook with a jid and dispatches it in the
-- background (internal/natsapi cook.go). A cook it refused there before
-- any copy could reach the sprout (its recipe didn't resolve: a missing
-- include, the per-cook render budget; staging failed; the stage guard
-- refused it) wrote no job_status row, so saasapi followed the job as
-- running for ever. internal/jobs now records such a job here
-- (recordJobRefusal), and the status it computes is 'refused'.
--
-- Expand only. The previous release's farmer doesn't know the column: its
-- inserts name their columns, so the new one is 0, and it recomputes a
-- row's status only when an event of that job arrives, which a refused
-- job never gets. Nothing is dropped, so compatibleFrom stays at 2.
--
-- MySQL has no ADD COLUMN IF NOT EXISTS: prepared only when the column is
-- missing ('DO 0' otherwise), as in 00002. Idempotent.

SET @imas_ddl = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `job_status` ADD COLUMN `dispatch_refused` tinyint(1) NOT NULL DEFAULT ''0''', 'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'job_status'
    AND COLUMN_NAME = 'dispatch_refused');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;
