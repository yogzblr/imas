-- +goose Up
-- +goose NO TRANSACTION
--
-- P22 slice 2 (docs/briefs/P22-gpg-fleet-trust.md; signing design D9,
-- D20): the release's GPG-signed checksums.txt, which replaces the
-- per-row Ed25519 signature as the sprout update trust root.
--
--   fleet_release_checksums                       new table
--
-- One row per release version: checksums.txt byte for byte
-- (checksums_txt) and checksums.txt.sig in standard padded base64
-- (checksums_sig), as the release's farmer chart registers them. saasapi
-- stores them without verifying the signature (D20: the sprout is the only
-- verifier) and farmer serves them with the version's
-- saas.fleet_versions row in GET /v1/sprout/update-manifest.
--
-- saas.fleet_versions.signature stays: saasapi now writes '' to it, and a
-- later migration drops it.
--
-- Expand only: a saasapi or farmer built for an older schema never touches
-- this table, so saasCompatibleFrom stays 1. No Down section.
--
-- Idempotent: CREATE TABLE IF NOT EXISTS.

CREATE TABLE IF NOT EXISTS `fleet_release_checksums` (
  `version` varchar(64) NOT NULL,
  `checksums_txt` mediumtext NOT NULL,
  `checksums_sig` text NOT NULL,
  `created_at` datetime(3) NOT NULL,
  PRIMARY KEY (`version`)
) ENGINE=InnoDB;
