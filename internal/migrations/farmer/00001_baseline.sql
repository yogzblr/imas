-- +goose Up
-- +goose NO TRANSACTION
--
-- Baseline of the farmer schema: every table exactly as GORM AutoMigrate
-- created it from the models in internal/props, internal/pki,
-- internal/rbac and internal/jobs, before cmd/migrate took over (design
-- doc §4.1a). IF NOT EXISTS makes this a no-op on an install that
-- AutoMigrate already brought up to date. No table options beyond the
-- engine, so each table takes the schema's default character set and
-- collation, as AutoMigrate's did.
--
-- Forward-only: there is no Down section, and there never will be.

CREATE TABLE IF NOT EXISTS `props` (
  `tenant_id` varchar(191) NOT NULL,
  `sprout_id` varchar(253) NOT NULL,
  `name` varchar(191) NOT NULL,
  `value` text,
  `static` tinyint(1) NOT NULL DEFAULT '0',
  `expiry` datetime(3) NOT NULL,
  PRIMARY KEY (`tenant_id`,`sprout_id`,`name`),
  KEY `idx_props_expiry` (`expiry`)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS `pki_nkeys` (
  `tenant_id` varchar(191) NOT NULL,
  `sprout_id` varchar(253) NOT NULL,
  `nkey` varchar(191) NOT NULL,
  `state` varchar(32) NOT NULL,
  PRIMARY KEY (`tenant_id`,`sprout_id`),
  KEY `idx_pki_nkeys_n_key` (`nkey`),
  KEY `idx_pki_nkeys_state` (`state`)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS `pki_tenants` (
  `id` varchar(191) NOT NULL,
  `name` varchar(255) NOT NULL,
  `deleted` tinyint(1) NOT NULL DEFAULT '0',
  `created_at` bigint NOT NULL,
  `account_pub` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_pki_tenants_deleted` (`deleted`),
  KEY `idx_pki_tenants_account_pub` (`account_pub`)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS `pki_sprout_box_keys` (
  `tenant_id` varchar(191) NOT NULL,
  `sprout_id` varchar(253) NOT NULL,
  `pub` varchar(64) NOT NULL,
  `state` varchar(16) NOT NULL,
  `grace_until` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`tenant_id`,`sprout_id`,`pub`),
  KEY `idx_pki_sprout_box_keys_state` (`state`)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS `rbac_roles` (
  `tenant_id` varchar(191) NOT NULL,
  `name` varchar(191) NOT NULL,
  `rules` text,
  PRIMARY KEY (`tenant_id`,`name`)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS `rbac_user_roles` (
  `tenant_id` varchar(191) NOT NULL,
  `pubkey` varchar(191) NOT NULL,
  `role_name` varchar(191) NOT NULL,
  `username` varchar(191) DEFAULT NULL,
  PRIMARY KEY (`tenant_id`,`pubkey`)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS `rbac_cohorts` (
  `tenant_id` varchar(191) NOT NULL,
  `name` varchar(191) NOT NULL,
  `type` varchar(32) NOT NULL,
  `members` text,
  `match_rule` text,
  `compound` text,
  PRIMARY KEY (`tenant_id`,`name`)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS `job_status` (
  `tenant_id` varchar(191) NOT NULL,
  `sprout_id` varchar(253) NOT NULL,
  `jid` varchar(64) NOT NULL,
  `status` varchar(16) NOT NULL,
  `steps_total` bigint DEFAULT NULL,
  `steps_reported` bigint NOT NULL DEFAULT '0',
  `step_failed` tinyint(1) NOT NULL DEFAULT '0',
  `started` tinyint(1) NOT NULL DEFAULT '0',
  `finished` tinyint(1) NOT NULL DEFAULT '0',
  `timed_out` tinyint(1) NOT NULL DEFAULT '0',
  `updated_at` datetime(3) NOT NULL,
  `expired` tinyint(1) NOT NULL DEFAULT '0',
  `dispatched_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`tenant_id`,`sprout_id`,`jid`),
  KEY `idx_job_status_updated_at` (`updated_at`)
) ENGINE=InnoDB;
