-- +goose Up
-- +goose NO TRANSACTION
--
-- P21 slice 3 (docs/briefs/P21-slice3-farmer-saasapi-state.md §2, §4.2).
--
--   sprout_user_jwt                               new table
--
-- sprout_user_jwt indexes the per-sprout NATS user JWTs, which live in the
-- private sprout JWT bucket (IMAS_S3_SPROUT_JWT_BUCKET) instead of farmer's
-- local disk. One row per sprout, keyed on (tenant_id, sprout_id): a sprout
-- ID is unique per tenant only (CLAUDE.md). object_key is the JWT's key in
-- the bucket, <tenant_id>/<sprout_id>/<jwt_sha256>.jwt; jwt_sha256 lets a
-- reader check the object it fetched; user_pubkey is the source of truth
-- for which key the sprout's JWT was minted for.
--
-- lease_owner and lease_until are the row lease that serialises minting
-- across farmer replicas: a replica inserts the row if missing and takes
-- the lease with one conditional UPDATE, as for job_leases (00004). So a
-- sprout's first row is inserted before its JWT exists, with only
-- (tenant_id, sprout_id): object_key, user_pubkey and jwt_sha256 are NULL
-- until the first mint, and updated_at defaults to the insert time. A NULL
-- user_pubkey matches no key, so a pending row is never reused as a JWT.
--
-- sprout_id is varchar(253), as in pki_nkeys (00001): that is the longest
-- sprout ID farmer accepts (internal/pki maxSproutIDLen). object_key is
-- varchar(512) so the longest such key fits (32 + 1 + 253 + 1 + 64 + 4).
--
-- Expand only: a farmer built for schema 4 never touches this table, so
-- farmerCompatibleFrom stays 2. No Down section.
--
-- Idempotent: CREATE TABLE IF NOT EXISTS.

CREATE TABLE IF NOT EXISTS `sprout_user_jwt` (
  `tenant_id` varchar(64) NOT NULL,
  `sprout_id` varchar(253) NOT NULL,
  `object_key` varchar(512) DEFAULT NULL,
  `user_pubkey` varchar(64) DEFAULT NULL,
  `jwt_sha256` char(64) DEFAULT NULL,
  `expires_at` datetime(3) DEFAULT NULL,
  `lease_owner` varchar(128) DEFAULT NULL,
  `lease_until` datetime(3) DEFAULT NULL,
  `updated_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`tenant_id`,`sprout_id`)
) ENGINE=InnoDB;
