-- +goose Up
-- +goose NO TRANSACTION
--
-- J.1 (docs/design/imas-payload-encryption-design.md, "Sealing the
-- control plane"). FLAG FOR SECURITY REVIEW.
--
--   auth_users                                    new table
--   auth_cli_box_keys                             new table
--   pki_sprout_box_keys idx_pki_sprout_box_keys_pub  (pub)
--
-- auth_users is the users store for users registered through the API
-- (auth.users.add), shared by every farmer replica. It replaces the write
-- to farmer's local config file, which was inconsistent across replicas
-- (docs/BUILD-STATUS.md, Open item 11). Keyed on (tenant_id, user_id);
-- user_id is the user's NKey public key.
--
-- auth_cli_box_keys holds each user's CLI box public keys, keyed on
-- (tenant_id, user_id): the active key, a rotated-away key in its grace
-- window, and retired ones, with when each was registered (created_at)
-- and stopped being active (rotated_at). At most one active key per
-- (tenant_id, user_id): active_slot is 1 on the active row and NULL on
-- every other, the CHECK ties it to status, and (tenant_id, user_id,
-- active_slot) is unique, as for pki_sprout_box_keys (00002). pub is
-- unique across the table on purpose: a box key registered to one
-- principal, ever, is never registered to another.
--
-- idx_pki_sprout_box_keys_pub lets registration check a CLI key against
-- every sprout box key without a scan (a key two principals share would
-- give them the same secret with farmer).
--
-- Expand only: a farmer built for schema 2 never touches these tables or
-- the index, so farmerCompatibleFrom stays 2. No Down section.
--
-- Idempotent: the tables are CREATE TABLE IF NOT EXISTS; the index is
-- prepared only when information_schema lacks it ('DO 0' otherwise).

CREATE TABLE IF NOT EXISTS `auth_users` (
  `tenant_id` varchar(191) NOT NULL,
  `user_id` varchar(191) NOT NULL,
  `role_name` varchar(191) NOT NULL,
  `username` varchar(191) DEFAULT NULL,
  `created_at` datetime(3) NOT NULL,
  PRIMARY KEY (`tenant_id`,`user_id`)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS `auth_cli_box_keys` (
  `tenant_id` varchar(191) NOT NULL,
  `user_id` varchar(191) NOT NULL,
  `pub` varchar(64) NOT NULL,
  `status` varchar(16) NOT NULL,
  `active_slot` tinyint DEFAULT NULL,
  `created_at` datetime(3) NOT NULL,
  `rotated_at` datetime(3) DEFAULT NULL,
  `grace_until` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`tenant_id`,`user_id`,`pub`),
  UNIQUE KEY `idx_auth_cli_box_keys_pub` (`pub`),
  UNIQUE KEY `idx_auth_cli_box_keys_one_active` (`tenant_id`,`user_id`,`active_slot`),
  CONSTRAINT `chk_auth_cli_box_keys_active_slot` CHECK ((status = 'active' AND active_slot IS NOT NULL AND active_slot = 1) OR (status <> 'active' AND active_slot IS NULL))
) ENGINE=InnoDB;

SET @imas_ddl = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `pki_sprout_box_keys` ADD INDEX `idx_pki_sprout_box_keys_pub` (`pub`)', 'DO 0')
  FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'pki_sprout_box_keys' AND INDEX_NAME = 'idx_pki_sprout_box_keys_pub');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;
