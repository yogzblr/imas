-- +goose Up
-- +goose NO TRANSACTION
--
-- U1 (docs/briefs/U-hardening.md; security review 2026-10, I6). FLAG FOR
-- SECURITY REVIEW.
--
--   pki_cli_admin_keys                            new table
--
-- pki_cli_admin_keys remembers every CLI admin NKey (farmer config
-- users.admin and pubkeys.admin) the Account rebuild granted on a tenant's
-- Account
-- (internal/pki syncNatsAuth), so that once one leaves the config the
-- rebuild knows it was there: it puts the NKey on the tenant's revoked
-- list (pki_revoked_nkeys, sprout_id empty), retires its CLI box keys,
-- deletes its row here and re-signs the Account with the revocation.
-- Before this, a removed admin key kept every grant it had. Keyed on
-- (tenant_id, nkey); granted_at (Unix seconds) is when it was first
-- granted.
--
-- Expand only: a farmer built for schema 6 never touches this table, so
-- farmerCompatibleFrom stays 2. No Down section.
--
-- Idempotent: CREATE TABLE IF NOT EXISTS.

CREATE TABLE IF NOT EXISTS `pki_cli_admin_keys` (
  `tenant_id` varchar(191) NOT NULL,
  `nkey` varchar(191) NOT NULL,
  `granted_at` bigint NOT NULL,
  PRIMARY KEY (`tenant_id`,`nkey`)
) ENGINE=InnoDB;
