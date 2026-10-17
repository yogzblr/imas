# S6: erase a tenant's data after offboarding

Read `docs/briefs/ORCHESTRATOR.md` first: its session prompt (zero open items,
repo-wide search, brief errors decided by a fixed order) applies. Source: P3
walkthrough 3.6 item 3 (`docs/security-review-pack.md`), owner decision
2026-10-17. Needs: S5 (S3 to S6 all edit the saasapi sweeper and config, the
saas migrations and the farmer chart values, README and `chart_test.go`; they
run one after another).

Owner decisions (2026-10-17), final:

- Offboarding a tenant locks it out at once (today's behaviour, unchanged). Its
  data is then erased automatically after a retention delay, default 30 days,
  and can be erased earlier by an operator.
- What is erased: everything the tenant owns except a small tombstone that
  keeps its ID from ever being reused and keeps it locked out (see
  "Keep" below).
- Erasure is idempotent, resumable and audited. It never touches another
  tenant's data, including a sprout with the same `sprout_id`.

## Why

`DeprovisionTenant` (`internal/pki/tenant.go`) closes the tenant's bus
connections, pushes a locked-out Account JWT and retires its two Transit keys.
Its own comment says it "does not delete sprout state or stored JWTs", and
`docs/design/imas-machine-manager-api-design.md` says deleting
`tenants/<tenant_id>/recipes/` is done by nothing yet. A departed tenant's data
(recipes, staged recipes, job output, sprout and property rows, stored sprout
JWTs, box keys) therefore stays indefinitely. For tenants under data-protection
rules that is a gap. It is not an access hole: the tenant cannot connect or
sign, and tenant IDs are random, so another tenant cannot collide with it.

Scope: `internal/saasapi` (model, sweeper, provisioning, tenants, config,
operator plane router, `fleet_releases.go`'s operator server for the new route),
`internal/controlplane` (new subject and result), `internal/natsapi`
(`tenant_provision.go`), `internal/pki`, `internal/props`, `internal/auth`,
`internal/rbac`, `internal/jobs`, `internal/heartbeat`, `internal/cook`,
`internal/migrations/saas`, `deploy/helm/farmer` (values, README, chart tests),
`docs/` (API, OpenAPI, design docs, `docs/INSTALL.md`, the OpenBao runbook).

Facts on main (2026-10-17), verify first:

- Tenant statuses: `pending`, `active`, `failed`, `offboarding`, `offboarded`
  (`internal/saasapi/model.go`). `DeleteTenant` sets `offboarding` and enqueues a
  `deprovision` outbox job (`provisioning_jobs`); farmer's
  `handleTenantDeprovision` (`internal/natsapi/tenant_provision.go`) runs
  `pki.DeprovisionTenant` and publishes a sealed result that saasapi applies.
- The outbox sweeper re-sends pending provisioning jobs under row leases
  (`internal/saasapi/sweeper.go`); the operator plane is a separate listener
  with its own bearer token (`NewOperatorServer`).
- Where tenant data lives (known today; the session completes the inventory):
  - Object store: `tenants/<t>/recipes/`, `tenants/<t>/recipe-audit/`,
    `sprouts/<t>/<sprout>/` (staged recipe), `jobs/<t>/` (job output), the
    private sprout JWT bucket (`IMAS_S3_SPROUT_JWT_BUCKET`, keys
    `<t>/<sprout>/<hash>.jwt`), the accounts bucket (`accounts/` prefix,
    `internal/accountloader`), and any tenant key-set objects under
    `tenants/<t>/`.
  - Farmer schema tables with a `tenant_id` column: `props`, `pki_nkeys`,
    `pki_revoked_nkeys`, `pki_sprout_box_keys`, `pki_tenants`, `auth_users`,
    `auth_cli_box_keys`, `rbac_roles`, `rbac_user_roles`, `rbac_cohorts`,
    `job_status`, the sprout User JWT lease table, and any other found.
  - Saas schema: `tenants`, `provisioning_jobs`, `enrollment_keys`,
    `asset_links`, `asset_action_batches`, `asset_action_items`,
    `tenant_update_policy`.
  - OpenBao Transit: the tenant's signing and account keys (retired, i.e.
    soft-deleted, at deprovision); any tenant KV material.
  - Valkey: heartbeat and accepted-sprout keys (`{tenant:sprout}` slots);
    replay claims expire by themselves.

## Decisions

1. **Keep (the tombstone), erase everything else.** Kept forever: the `tenants`
   row (status becomes `purged`), the `pki_tenants` row (deleted marker), the
   tenant's locked-out Account JWT object in the accounts bucket, and the
   `provisioning_jobs` rows. Together they keep the ID reserved and the tenant
   locked out. Everything else listed above is deleted, including
   `recipe-audit/` (platform audit logs are separate and follow their own
   30-day retention) and the Transit keys, which are destroyed permanently
   (the session reads the OpenBao Transit API and the repo's `RetireKey` to do
   this correctly, e.g. allowing deletion on the key first, and records the
   exact calls in the runbook).
2. **Completing the inventory.** The session searches for every table, bucket
   prefix, Valkey key shape and OpenBao path that holds a tenant's data and
   handles each one. A test fails if a model or table with a `tenant_id`
   column, or a store prefix keyed on a tenant, exists that is in neither the
   purge list nor an explicit keep list in code: add a table and the test says
   to decide.
3. **Retention and switches.** Settings (saasapi, Helm key under
   `saasapi.tenantPurge`, null emits no variable):
   - `SAASAPI_TENANT_PURGE_ENABLED`, default `true`.
   - `SAASAPI_TENANT_PURGE_AFTER`, default `720h`, bounds `1h` to `8760h`.
   The sweeper starts a purge for a tenant that has been `offboarded` for at
   least that long. The time is a new column `offboarded_at` on `tenants`
   (new goose migration after the latest, next number read from the directory;
   set when the deprovision result is applied; backfill existing offboarded
   rows from `updated_at`).
4. **How it runs.** A new outbox job type `purge` in `provisioning_jobs`, at most
   one pending per tenant, published to a new sealed subject
   (`controlplane.SubjectTenantPurge`) with the same sealing, lease, retry and
   result path as `deprovision`. Farmer's handler runs the erasure and publishes
   a sealed result carrying counts per category (numbers only, no names, keys or
   content). saasapi sets the tenant `purged` on success. A failed job leaves the
   tenant `offboarded` and visible in `GET .../status` (`last_error`); the
   sweeper starts a new purge job for it no more than once a day, and an
   operator can start one at once.
5. **Guards, checked by farmer before it deletes anything.** The tenant ID is
   valid; it is not the legacy current tenant (`FarmerOrganization`); and
   `pki_tenants` shows it deleted. If any check fails, delete nothing and return
   a refusal result. saasapi starts a purge only for `offboarded` tenants.
6. **Operator route.** `POST /v1/operator/tenants/{tenant_id}/purge` on the
   operator plane (its own bearer token): 202 and the job ID for an `offboarded`
   tenant, 404 for an unknown one, 409 `not_offboarded` otherwise, 409
   `purge_in_progress` if a purge job is pending. Rate-limited like the other
   operator routes. Documented in `docs/api/saasapi-operator-openapi.yaml`.
7. **Order of erasure** (so a crash leaves the tenant locked out and the rest
   re-runnable): live caches first (Valkey), then DB rows, then object store
   prefixes, then OpenBao KV, then the Transit keys last. Every step lists and
   deletes by exact tenant prefix or `tenant_id` equality, in bounded batches
   with a per-step timeout; a step that fails stops the run and reports which.
   Re-running after a partial run finishes it.
8. **Audit.** Farmer writes one platform audit entry per purge with the tenant ID,
   the job ID, the trigger (retention or operator) and the category counts, using
   the existing tenant-action audit path (`auditTenantAction`), and applying S2's
   redaction rules.
9. **API and docs.** `GET /tenants/{tenant_id}/status` shows `offboarded` or
   `purged`, and for an offboarded tenant a `purge_after` timestamp
   (RFC 3339). Update `docs/api/saasapi.md` and `saasapi-openapi.yaml`, the API
   design doc (replace the "Nothing does yet" line on tenant deletion with what
   exists), `docs/INSTALL.md`, `docs/OPENBAO-RUNBOOK.md` (Transit key
   destruction, what stays after a purge, how to purge early), the farmer chart
   README, and `docs/security-review-pack.md` item 3.6.3.

## Tests

- Table and prefix coverage test from decision 2.
- With two tenants holding a sprout of the same `sprout_id` and the same
  property, job and recipe names, purging tenant A leaves every row, object and
  key of tenant B untouched, and removes all of A's except the tombstone.
- Each category on fakes: DB rows (both schemas), object prefixes (including
  the sprout JWT bucket and staged recipes), Valkey slots, OpenBao KV, Transit
  keys destroyed; the tombstone (tenants row as `purged`, `pki_tenants` row,
  locked-out Account JWT, provisioning jobs) stays.
- Guards: a non-offboarded tenant, the legacy current tenant, an invalid ID and a
  tenant `pki_tenants` does not show deleted each delete nothing.
- Idempotence and resume: stop after each step in turn, re-run, end state equal;
  a second purge of a purged tenant is a no-op success.
- Retention: a fake clock before and after `SAASAPI_TENANT_PURGE_AFTER`;
  disabled switch starts nothing; bounds of both settings refuse startup.
- Operator route: auth, each status code, rate limit, only one pending job.
- The sealed subject is registered and refuses plaintext, forged and replayed
  requests like the deprovision subject; the result is applied once.
- Migration applies and rolls back; backfill sets `offboarded_at` from
  `updated_at` for offboarded rows only.
- Audit entry has counts and no names, keys or content.
- Helm: `saasapi.tenantPurge` renders with and without overrides.

Search gate: `TenantStatusOffboarded`, `ProvisioningJobDeprovision`,
`SubjectTenantDeprovision`, `handleTenantDeprovision`, `DeprovisionTenant`,
`retireTenantKeys`, `RetireKey`, `Nothing does yet`, `does not delete sprout
state`, `tenant_id` in `internal/migrations`, `jobKeyPrefix`,
`tenantRecipeRoot`, `stagedRecipeRoot`, `AccountsPrefix`,
`IMAS_S3_SPROUT_JWT_BUCKET` across `internal/`, `cmd/`, `deploy/`, `uat/`,
`docs/`.
