-- +goose Up
-- +goose NO TRANSACTION
--
-- FU.2: a release has one saas.fleet_versions row per version, OS, arch
-- and package type. The same linux/amd64 binary ships as both a .deb
-- (Debian family) and an .rpm (RHEL family, SUSE), each with its own file
-- name and SHA-256, so (version, os, arch) can't be the key: a release
-- could register only one of them. package_type is not signed; what a
-- sprout installs is decided by the signed file_name and checksum, and
-- the sprout refuses a file_name that isn't its own package type.
--
--   1. Adds idx_fleet_versions_version_os_arch_type,
--      UNIQUE(version, os, arch, package_type).
--   2. Drops idx_fleet_versions_version_os_arch, UNIQUE(version, os, arch).
--
-- Every existing row stays valid under the new key (it is unique on a
-- subset of it). The previous release's saasapi refuses a second package
-- for an OS/arch itself, and its farmer selects by (version, os, arch),
-- which stays unambiguous until a release registers a second package
-- type, which only this release's saasapi does.
--
-- Prepared only when needed ('DO 0' otherwise), as in 00003. Idempotent.

SET @imas_ddl = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `fleet_versions` ADD UNIQUE INDEX `idx_fleet_versions_version_os_arch_type` (`version`, `os`, `arch`, `package_type`)', 'DO 0')
  FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'fleet_versions'
    AND INDEX_NAME = 'idx_fleet_versions_version_os_arch_type');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;

SET @imas_ddl = (SELECT IF(COUNT(*) > 0,
    'ALTER TABLE `fleet_versions` DROP INDEX `idx_fleet_versions_version_os_arch`', 'DO 0')
  FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'fleet_versions'
    AND INDEX_NAME = 'idx_fleet_versions_version_os_arch');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;
