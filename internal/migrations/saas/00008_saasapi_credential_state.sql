-- +goose Up
-- +goose NO TRANSACTION
--
-- P21 slice 3 (docs/briefs/P21-slice3-farmer-saasapi-state.md §2, §4.3).
-- Version 00008: P22 slice 2 owns saas 00007 (docs/briefs/ORCHESTRATOR.md).
--
--   saasapi_credential_state                      new table
--
-- saasapi_credential_state is saasapi's NATS user credential rotation
-- state, which replaces the user JWT file saasapi kept on local disk and
-- read its previous public key from. One row, id 1: the current and the
-- previous user public key, when it last rotated, and a version that a
-- rotation's conditional UPDATE checks (WHERE version = ?), so that of two
-- saasapi replicas rotating at once only one wins. lease_owner and
-- lease_until are the row lease a rotation holds while it computes the new
-- key.
--
-- farmer reads prev_pub (it has SELECT on saas.*) to build the SYS
-- account's revocation list. Only saasapi writes this table.
--
-- No row is seeded: current_pub and rotated_at have no value until
-- saasapi's first credential exists, and saasapi inserts the row then.
--
-- Expand only: a saasapi built for an older schema never touches this
-- table, so saasCompatibleFrom stays 1. No Down section.
--
-- Idempotent: CREATE TABLE IF NOT EXISTS.

CREATE TABLE IF NOT EXISTS `saasapi_credential_state` (
  `id` tinyint NOT NULL,
  `current_pub` varchar(64) NOT NULL,
  `prev_pub` varchar(64) DEFAULT NULL,
  `rotated_at` datetime(3) NOT NULL,
  `version` bigint NOT NULL,
  `lease_owner` varchar(128) DEFAULT NULL,
  `lease_until` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `chk_saasapi_credential_state_one_row` CHECK (`id` = 1)
) ENGINE=InnoDB;
