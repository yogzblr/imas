-- +goose Up
-- +goose NO TRANSACTION
--
-- T4 (docs/briefs/T-pre-azure.md; security review 2026-10, I7). FLAG FOR
-- SECURITY REVIEW.
--
--   pki_nkeys idx_pki_nkeys_tenant_nkey   UNIQUE (tenant_id, nkey)
--
-- An NKey is held by at most one sprout ID per tenant, so a lookup by
-- NKey within a tenant (internal/pki findNKeyRowByNKeyInTenant) has one
-- answer, and the enrollment path gives an NKey the tenant already holds
-- the sprout ID it holds it under (resolveEnrollSproutID). The index is
-- keyed on tenant_id with nkey, never on nkey alone: the same public key
-- in two tenants is two tenants' business (CLAUDE.md, tenant safety); the
-- one cross-tenant lookup (SproutIDAndTenantForNKey) refuses more than
-- one accepted match instead.
--
-- Existing rows: `migrate up` refuses to run this migration while
-- pki_nkeys holds two rows with the same (tenant_id, nkey), and names
-- every such NKey with its sprout IDs (internal/migrations preflight.go),
-- so an operator decides which sprout keeps it. Nothing is deleted here.
-- Should the ALTER run regardless, MySQL refuses it with a duplicate-key
-- error and changes nothing.
--
-- Expand only: a farmer built for schema 5 reads pki_nkeys exactly as
-- before, and the one write it could make that the index refuses (an
-- enrollment of an NKey the tenant already holds under another sprout
-- ID) fails that enrollment, the fail-closed outcome; so
-- farmerCompatibleFrom stays 2. No Down section.
--
-- Idempotent: the ALTER is prepared only when information_schema lacks
-- the index ('DO 0' otherwise), as in 00002.

SET @imas_ddl = (SELECT IF(COUNT(*) = 0,
    'ALTER TABLE `pki_nkeys` ADD UNIQUE INDEX `idx_pki_nkeys_tenant_nkey` (`tenant_id`, `nkey`)', 'DO 0')
  FROM information_schema.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'pki_nkeys' AND INDEX_NAME = 'idx_pki_nkeys_tenant_nkey');
PREPARE imas_ddl FROM @imas_ddl;
EXECUTE imas_ddl;
DEALLOCATE PREPARE imas_ddl;
