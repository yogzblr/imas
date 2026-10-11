-- +goose Up
-- +goose NO TRANSACTION
--
-- P21 slice 3 (docs/briefs/P21-slice3-farmer-saasapi-state.md §2, §4.4).
--
--   job_leases                                    new table
--   job_leases rows jobs_expiry, cohort_refresher seed rows
--
-- job_leases holds one row lease per farmer background job, so that with
-- several farmer replicas a job runs on one of them at a time. A replica
-- takes a lease with one conditional UPDATE (lease never set, expired, or
-- already its own) and holds it only if that UPDATE affected the row, as
-- saasapi's outbox sweeper does (saas/00006). A row, not GET_LOCK: GET_LOCK
-- is local to the node it ran on.
--
-- last_run_at is when the job last ran, for jobs with a minimum interval
-- (pushall:<tenant_id>). The jobs_expiry and cohort_refresher rows are
-- seeded here; pushall:<tenant_id> rows are inserted on demand with
-- INSERT IGNORE. A tenant ID is at most 32 characters (the saas tenants
-- table), so every name fits.
--
-- Expand only: a farmer built for schema 3 never touches this table, so
-- farmerCompatibleFrom stays 2. No Down section.
--
-- Idempotent: CREATE TABLE IF NOT EXISTS, and INSERT IGNORE leaves a seed
-- row that exists (and any lease on it) alone.

CREATE TABLE IF NOT EXISTS `job_leases` (
  `name` varchar(128) NOT NULL,
  `lease_owner` varchar(128) DEFAULT NULL,
  `lease_until` datetime(3) DEFAULT NULL,
  `last_run_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`name`)
) ENGINE=InnoDB;

INSERT IGNORE INTO `job_leases` (`name`) VALUES ('jobs_expiry'), ('cohort_refresher');
