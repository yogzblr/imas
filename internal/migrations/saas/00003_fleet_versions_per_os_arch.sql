-- +goose Up
-- +goose NO TRANSACTION
--
-- FU.3 (design doc §2.5, §4.3): one saas.fleet_versions row per version,
-- OS and arch, holding every field of the signed manifest, registered by
-- saasapi's operator plane and signed by cmd/fleetreleaser.
--
--   1. Deletes every row written in the pre-FU.3 shape (it still has
--      artifact_url). Such a row was signed over a message no verifier
--      accepts any more (FU.0), and has no os, arch or file_name, so it
--      can be neither verified nor served. Done only while artifact_url
--      exists, so a re-run after step 5 never deletes a registered row.
--   2. Adds os, arch, package_type, file_name, min_sprout_version and
--      revoked.
--   3. Drops idx_fleet_versions_version, the UNIQUE(version) index: a
--      version now has a row per OS/arch.
--   4. Adds idx_fleet_versions_version_os_arch, UNIQUE(version, os, arch).
--   5. Drops artifact_url. The sprout builds the download URL from its own
--      configured repository and file_name (requirement 20).
--
-- The previous release's saasapi reads this table with SELECT *, so it
-- keeps running against the new shape (its fleet update dispatch already
-- refused every row); nothing in it writes the table. The previous
-- release's fleetreleaser CLI can no longer insert, which is intended.
--
-- MySQL has no ADD COLUMN IF NOT EXISTS, DROP COLUMN IF EXISTS or DROP
-- INDEX IF EXISTS, so each step is prepared only when needed ('DO 0'
-- otherwise), as in 00002. goose runs a migration's statements on one
-- connection, so @imas_ddl carries between them. Idempotent.

SET @imas_ddl = (SELECT IF(COUNT(*) > 0, 'DELETE FROM `fleet_versions`', 'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'fleet_versions' AND COLUMN_NAME = 'artifact_url');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;

SET @imas_ddl = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `fleet_versions` ADD COLUMN `os` varchar(32) NOT NULL', 'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'fleet_versions' AND COLUMN_NAME = 'os');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;

SET @imas_ddl = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `fleet_versions` ADD COLUMN `arch` varchar(32) NOT NULL', 'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'fleet_versions' AND COLUMN_NAME = 'arch');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;

SET @imas_ddl = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `fleet_versions` ADD COLUMN `package_type` varchar(16) NOT NULL', 'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'fleet_versions' AND COLUMN_NAME = 'package_type');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;

SET @imas_ddl = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `fleet_versions` ADD COLUMN `file_name` varchar(255) NOT NULL', 'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'fleet_versions' AND COLUMN_NAME = 'file_name');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;

SET @imas_ddl = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `fleet_versions` ADD COLUMN `min_sprout_version` varchar(64) NOT NULL', 'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'fleet_versions' AND COLUMN_NAME = 'min_sprout_version');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;

SET @imas_ddl = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `fleet_versions` ADD COLUMN `revoked` tinyint(1) NOT NULL DEFAULT ''0''', 'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'fleet_versions' AND COLUMN_NAME = 'revoked');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;

SET @imas_ddl = (SELECT IF(COUNT(*) > 0,
    'ALTER TABLE `fleet_versions` DROP INDEX `idx_fleet_versions_version`', 'DO 0')
  FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'fleet_versions'
    AND INDEX_NAME = 'idx_fleet_versions_version');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;

SET @imas_ddl = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `fleet_versions` ADD UNIQUE INDEX `idx_fleet_versions_version_os_arch` (`version`, `os`, `arch`)', 'DO 0')
  FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'fleet_versions'
    AND INDEX_NAME = 'idx_fleet_versions_version_os_arch');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;

SET @imas_ddl = (SELECT IF(COUNT(*) > 0,
    'ALTER TABLE `fleet_versions` DROP COLUMN `artifact_url`', 'DO 0')
  FROM information_schema.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'fleet_versions' AND COLUMN_NAME = 'artifact_url');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;
