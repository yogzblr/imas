-- +goose Up
-- +goose NO TRANSACTION
--
-- Baseline of the saas schema: every table exactly as GORM AutoMigrate
-- created it from internal/saasapi's models (saasapi.Models()), before
-- cmd/migrate took over (design doc §4.1a). IF NOT EXISTS makes this a no-op on an install that
-- AutoMigrate already brought up to date. No table options beyond the
-- engine, so each table takes the schema's default character set and
-- collation, as AutoMigrate's did.
--
-- Forward-only: there is no Down section, and there never will be.

CREATE TABLE IF NOT EXISTS `tenants` (
  `id` varchar(32) NOT NULL,
  `name` varchar(255) NOT NULL,
  `status` varchar(32) NOT NULL,
  `plan_id` varchar(64) DEFAULT NULL,
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_tenants_status` (`status`)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS `provisioning_jobs` (
  `id` varchar(36) NOT NULL,
  `tenant_id` varchar(32) NOT NULL,
  `type` varchar(32) NOT NULL,
  `status` varchar(32) NOT NULL,
  `attempts` bigint NOT NULL DEFAULT '0',
  `last_error` text,
  `warning` text,
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_provisioning_jobs_tenant_id` (`tenant_id`)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS `enrollment_keys` (
  `key_id` varchar(32) NOT NULL,
  `tenant_id` varchar(32) NOT NULL,
  `key_hash` varchar(64) NOT NULL,
  `expiry` datetime(3) NOT NULL,
  `max_uses` bigint NOT NULL,
  `used_count` bigint NOT NULL DEFAULT '0',
  `revoked` tinyint(1) NOT NULL DEFAULT '0',
  `created_at` datetime(3) DEFAULT NULL,
  `last_used_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`key_id`),
  KEY `idx_enrollment_keys_tenant_id` (`tenant_id`)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS `asset_links` (
  `id` varchar(32) NOT NULL,
  `tenant_id` varchar(32) NOT NULL,
  `sprout_id` varchar(253) NOT NULL,
  `asset_id` varchar(191) NOT NULL,
  `linked_at` datetime(3) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_asset_links_tenant_sprout` (`tenant_id`,`sprout_id`),
  UNIQUE KEY `idx_asset_links_asset_id` (`asset_id`)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS `asset_action_batches` (
  `id` varchar(32) NOT NULL,
  `tenant_id` varchar(32) NOT NULL,
  `action_type` varchar(32) NOT NULL,
  `action_params` text NOT NULL,
  `requested_asset_ids` text NOT NULL,
  `rollout_batch_size` bigint NOT NULL DEFAULT '0',
  `rollout_gate` varchar(32) NOT NULL DEFAULT '',
  `created_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_asset_action_batches_tenant_id` (`tenant_id`)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS `asset_action_items` (
  `batch_id` varchar(32) NOT NULL,
  `asset_id` varchar(191) NOT NULL,
  `tenant_id` varchar(32) NOT NULL,
  `position` bigint NOT NULL,
  `sprout_id` varchar(253) NOT NULL DEFAULT '',
  `jid` varchar(64) NOT NULL DEFAULT '',
  `status` varchar(32) NOT NULL,
  `error_code` varchar(64) NOT NULL DEFAULT '',
  `exit_code` bigint DEFAULT NULL,
  `attempts` bigint NOT NULL DEFAULT '0',
  `created_at` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`batch_id`,`asset_id`)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS `fleet_versions` (
  `id` varchar(32) NOT NULL,
  `version` varchar(64) NOT NULL,
  `artifact_url` varchar(2048) NOT NULL,
  `checksum_sha256` varchar(64) NOT NULL,
  `released_at` datetime(3) NOT NULL,
  `notes` text,
  `signature` varchar(128) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_fleet_versions_version` (`version`),
  KEY `idx_fleet_versions_released_at` (`released_at`)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS `tenant_update_policy` (
  `tenant_id` varchar(32) NOT NULL,
  `approved_version` varchar(64) DEFAULT NULL,
  `auto_update` tinyint(1) NOT NULL DEFAULT '0',
  `rollout_window_start` datetime(3) DEFAULT NULL,
  `rollout_window_end` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) DEFAULT NULL,
  PRIMARY KEY (`tenant_id`)
) ENGINE=InnoDB;
