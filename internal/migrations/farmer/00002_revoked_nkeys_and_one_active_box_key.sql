-- +goose Up
-- +goose NO TRANSACTION
--
-- SEC.3a (docs/security-review-2026-10.md, H1). FLAG FOR SECURITY REVIEW.
--
--   pki_revoked_nkeys                              new table
--   pki_sprout_box_keys.active_slot                tinyint NULL
--   pki_sprout_box_keys chk_pki_sprout_box_keys_active_slot  CHECK
--   pki_sprout_box_keys idx_pki_sprout_box_keys_one_active   UNIQUE
--                                                  (tenant_id, sprout_id, active_slot)
--
-- pki_revoked_nkeys remembers every sprout NKey revoked by deleting or
-- replacing its sprout (internal/pki retireSproutTx). A deleted pki_nkeys
-- row can't carry its own revocation, so its User JWT, which has no exp,
-- used to stay valid. Keyed on (tenant_id, nkey), with sprout_id indexed
-- together with tenant_id, never alone.
--
-- At most one box key per (tenant_id, sprout_id) is active: active_slot
-- is 1 on the active row and NULL on every other one (the CHECK ties it to
-- state, NULL-safely: a CHECK whose expression is NULL passes), and
-- (tenant_id, sprout_id, active_slot) is unique. NULLs never collide in a
-- MySQL unique index, so grace and revoked rows are unconstrained.
--
-- Existing rows: every active row gets its slot, except that a sprout
-- holding more than one active row (the defect H1 describes: which one
-- farmer sealed to depended on row order) has all of them revoked first.
-- No one can tell which key is the real sprout's, so it fails closed and
-- has to re-enrol. Owner decision 2026-10-04: nothing is deployed, so
-- this is expected to touch no rows.
--
-- Contract, not expand: a farmer built for schema 1 writes active rows
-- without active_slot, which the CHECK refuses, so farmerCompatibleFrom
-- rises to 2 and `migrate check` refuses such a binary against this
-- schema (a helm rollback past it needs a database restore). There is no
-- Down section, as for every migration here.
--
-- Idempotent: the table is CREATE TABLE IF NOT EXISTS; each ALTER is
-- prepared only when information_schema lacks what it adds ('DO 0'
-- otherwise), as in saas/00003; the UPDATEs are no-ops on a re-run.

CREATE TABLE IF NOT EXISTS `pki_revoked_nkeys` (
  `tenant_id` varchar(191) NOT NULL,
  `nkey` varchar(191) NOT NULL,
  `sprout_id` varchar(253) NOT NULL,
  `revoked_at` bigint NOT NULL,
  PRIMARY KEY (`tenant_id`,`nkey`),
  KEY `idx_pki_revoked_nkeys_sprout` (`tenant_id`,`sprout_id`)
) ENGINE=InnoDB;

SET @imas_ddl = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `pki_sprout_box_keys` ADD COLUMN `active_slot` tinyint DEFAULT NULL', 'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'pki_sprout_box_keys' AND COLUMN_NAME = 'active_slot');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;

UPDATE `pki_sprout_box_keys` k
  JOIN (SELECT `tenant_id`, `sprout_id` FROM `pki_sprout_box_keys`
        WHERE `state` = 'active'
        GROUP BY `tenant_id`, `sprout_id` HAVING COUNT(*) > 1) d
    ON d.`tenant_id` = k.`tenant_id` AND d.`sprout_id` = k.`sprout_id`
  SET k.`state` = 'revoked', k.`grace_until` = NULL, k.`active_slot` = NULL
  WHERE k.`state` = 'active';

UPDATE `pki_sprout_box_keys` SET `active_slot` = 1
  WHERE `state` = 'active' AND `active_slot` IS NULL;

UPDATE `pki_sprout_box_keys` SET `active_slot` = NULL
  WHERE `state` <> 'active' AND `active_slot` IS NOT NULL;

SET @imas_ddl = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `pki_sprout_box_keys` ADD CONSTRAINT `chk_pki_sprout_box_keys_active_slot` CHECK ((state = ''active'' AND active_slot IS NOT NULL AND active_slot = 1) OR (state <> ''active'' AND active_slot IS NULL))', 'DO 0')
  FROM information_schema.TABLE_CONSTRAINTS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'pki_sprout_box_keys'
    AND CONSTRAINT_NAME = 'chk_pki_sprout_box_keys_active_slot' AND CONSTRAINT_TYPE = 'CHECK');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;

SET @imas_ddl = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `pki_sprout_box_keys` ADD UNIQUE INDEX `idx_pki_sprout_box_keys_one_active` (`tenant_id`, `sprout_id`, `active_slot`)', 'DO 0')
  FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'pki_sprout_box_keys' AND INDEX_NAME = 'idx_pki_sprout_box_keys_one_active');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;
