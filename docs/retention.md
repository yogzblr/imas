# Data retention

Every place imas keeps data for a time or for ever, how long, and the
setting that decides it (owner decision U4, 2026-10-18,
`docs/briefs/U-hardening.md`). A time-based setting is a chart value that
reaches its pod as the variable in the table. An empty value, or `0` unless
the row says otherwise, is the documented default, never "delete at once".
A value the binary refuses (not a duration, out of range) stops it at
startup with a message naming the variable. The tenant purge delay is the
model for the others.

Erasing a tenant: everything listed here that belongs to a tenant is also
erased when the tenant is purged, `saasapi.tenantPurge.after` after it was
offboarded (`internal/tenantpurge`, farmer README "Erasing an offboarded
tenant's data"). The rows below say how long data is kept while the tenant
exists. The shipped logs are the platform's, not a tenant's: the purge
leaves them, and they go after their own 30 days (S6 decision 1;
`internal/tenantpurge` `KeepRoots`).

## Time-based retention

| What | Where | Default | Setting |
|---|---|---|---|
| Offboarded tenant's data (everything below of that tenant, its Transit keys and its tenant box key in OpenBao KV) | every store; tombstone kept | 720h (30 days) after offboarding | `saasapi.tenantPurge.after`, `SAASAPI_TENANT_PURGE_AFTER` (Go duration, 1h to 8760h); `saasapi.tenantPurge.enabled` |
| Job records and cook step events | job bucket (`objectStore.jobBucket`) `jobs/<tenant>/<sprout>/<jid>/` (`meta.json`, `created.jsonl`, `events/`, `expired.json`), and the `farmer.job_status` row | 720h (30 days) after the job's last activity; the hourly reaper (`internal/jobs` `expiry.go`) under the `jobs_expiry` lease | `farmer.retention.jobLogTTL`, `IMAS_JOB_LOG_TTL` (Go duration, 1h to 87600h); config key `joblogttl` |
| Recipe audit records | recipe bucket (`objectStore.bucket`) `tenants/<tenant>/recipe-audit/<YYYY-MM-DD>/` | 365 days, by the day in the key; farmer's daily sweep (`internal/retention`) under the `recipe_audit_expiry` lease | `farmer.retention.recipeAuditDays`, `IMAS_RECIPE_AUDIT_RETENTION_DAYS` (days, 1 to 3650; `0` keeps them for ever); config key `recipeauditretentiondays` |
| Service and audit logs (every container log of the release's namespace: farmer's audit log, saasapi's and the other services' JSON on stdout) | log bucket (`logShipping.bucket`) `<prefix><YYYY>/<MM>/<DD>/`, written by Fluent Bit (`logShipping`) | 30 days, by the day in the key; the log retention CronJob (`farmer log-retention`), daily | `logShipping.retention.days` (days, 1 to 3650; `0` or null is 30), `logShipping.retention.schedule`. With `logShipping.existingConfigMap` the destination's own |
| Finished action batches and their items (§1.5 actions and fleet update rollouts: every item `succeeded`, `failed`, `unresolved` or `unresponsive_after_update`) | saas `asset_action_batches`, `asset_action_items` | 2160h (90 days) after the batch was created and its last item changed; the outbox sweeper, hourly, 500 rows per statement | `saasapi.retention.terminalRows`, `SAASAPI_TERMINAL_ROW_RETENTION` (Go duration, 24h to 87600h) |
| Finished provisioning jobs (provision, deprovision) of a pending, active or failed tenant | saas `provisioning_jobs` | 2160h (90 days) after they finished; the outbox sweeper | `saasapi.retention.terminalRows`, `SAASAPI_TERMINAL_ROW_RETENTION` |
| Expired, revoked and used-up enrollment keys (join tokens) | saas `enrollment_keys` | 2160h (90 days) after the key's expiry. A key expires at most 720h after it is minted, so a revoked or used-up key goes at most 120 days after it was minted | `saasapi.retention.terminalRows`, `SAASAPI_TERMINAL_ROW_RETENTION` |
| A sprout's previous box public key after a rotation | farmer `pki_sprout_box_keys`, state `grace`, then `revoked` | 24h | `farmer.retention.boxKeyGrace`, `IMAS_BOX_KEY_GRACE_DURATION` (Go duration, 10m to 720h); config key `boxkeygraceduration` |
| A tenant's previous box key after a rotation (still opens sealed messages) | OpenBao KV v2 `<kvMount>/data/<kvPath>/tenants/<tenant>`, earlier versions | the longer of `farmer.retention.boxKeyGrace` and `farmer.gatewayJWTTTL` (24h each by default); the versions themselves stay with the secret (at most 8 are read) | `farmer.retention.boxKeyGrace`, `farmer.gatewayJWTTTL` |
| Sprout job logs on the host | sprout `joblogdir` (`/var/cache/imas/sprout/jobs`, `%ProgramData%\imas\...` on Windows) `<jid>.jsonl` | 30 days by file time; the sprout's hourly reaper | sprout config key `joblogttl` (`packaging/etc/imas-sprout.conf`); not a chart: the sprout is installed by its package or the Ansible role |
| The sprout's previous box private key after a rotation | sprout `<sproutboxprivfile>.prev` | 15m, never under 10m | sprout config key `sproutboxkeyprevgrace`, Ansible `imas_sprout_boxkey_prev_grace` |
| Staged recipe copies, too old to cook | recipe bucket `sprouts/<tenant>/<sprout>/recipe.json` | refused by the sprout 1h after staging; the object is overwritten by the next cook and deleted with the sprout | sprout config key `stagedrecipemaxage` (how old a copy may be cooked) |

## Short-lived keys (protocol windows, not retention)

These keys expire by their own TTL. The TTL is part of what the key
proves, so it is a fixed constant, not a setting: a shorter one would
open the replay guard or end a live sprout's presence, a longer one would
keep a dead sprout online or hold a claim past its window. None of them
holds a record anyone reads later.

| What | Where | TTL | Why fixed |
|---|---|---|---|
| Sprout presence | Valkey `imas:heartbeat:{<tenant>:<sprout>}` | 5m, refreshed every 1m (`internal/heartbeat` `TTL`) | sprouts send a heartbeat every TTL/5, compiled in; offline detection is the TTL |
| Acceptance marker | Valkey `imas:accepted:{<tenant>:<sprout>}` | 4h plus up to 10% jitter | how often presence is re-checked against the database |
| "Sprout needs an upgrade" marker | Valkey `imas:upgrade:{<tenant>:<sprout>}` | 5m (`UpgradeMarkerTTL`), renewed while the sprout keeps sending plaintext | the state lasts while the cause does |
| Enrolment and refresh replay claims | Valkey `imas:replay:<hash>` | the signed timestamp plus the ±5 minute window plus 1m | must cover the window it guards, no more |
| Sealed-message claims | Valkey `imas:replay:sealed:<tenant>:<principal>:<id>` | 10m (`SealedClaimTTL`) | twice the ±5 minute window |
| Rate-limit buckets | Valkey `imas:saasapi:ratelimit:<name>:<key>` | until the bucket is full again | the bucket's state; the rate and burst are settings (`saasapi.enrollmentKeys.rateLimit`, `saasapi.recipes.writeRateLimit`) |
| In-memory caches and nonces | farmer and saasapi memory | minutes | lost with the process |

## Kept while the thing they describe exists

Not history: one current record per object, overwritten when it changes
and deleted with the object (and with the tenant).

| What | Where | Kept until |
|---|---|---|
| Tenant recipes | recipe bucket `tenants/<tenant>/recipes/` | deleted through the API, or the tenant is purged |
| Staged recipe copy | recipe bucket `sprouts/<tenant>/<sprout>/recipe.json` | the next cook overwrites it; the sprout is deleted or replaced |
| Sprout User JWT | sprout JWT bucket `<tenant>/<sprout>/<sha256>.jwt`, row `farmer.sprout_user_jwt` | replaced by a re-mint, which deletes the object it superseded; the tenant is purged |
| Account JWTs | accounts bucket `accounts/` | replaced by a newer JWT; a purged tenant's locked-out JWT stays (tombstone) |
| Sprout properties | farmer `props` | overwritten by the next report; rows are read only while unexpired |
| Sprout identity, links, update policy, users, roles, cohorts | farmer `pki_nkeys`, `auth_users`, `rbac_*`; saas `asset_links`, `tenant_update_policy` | deleted through the API or CLI, or the tenant is purged |
| Fleet release catalog | saas `fleet_versions`, `fleet_release_checksums` | for ever: a revoked release is marked, not deleted, so a sprout can never be offered it again |

## Kept on purpose for ever

| What | Where | Why |
|---|---|---|
| Revoked NKeys | farmer `pki_revoked_nkeys` | the Account JWT's revocation list is built from them; deleting one would un-revoke the key |
| Revoked sprout box keys and retired CLI box keys | farmer `pki_sprout_box_keys` (state `revoked`), `auth_cli_box_keys` (state `retired`) | so a revoked key is never accepted again |
| The tenant tombstone | saas `tenants` (status `purged`), `provisioning_jobs` of an offboarding, offboarded or purged tenant, farmer `pki_tenants`, the locked-out Account JWT | S6 decision 1: the ID is never reused and the tenant stays locked out |
| Job leases | farmer `job_leases` | one row per background job name; no tenant data |

## Not kept

The bus keeps no data: its Account resolver directory is an `emptyDir`
rebuilt from the accounts bucket (design D10, D11), and it logs to stdout.
There is no JetStream. farmer and saasapi keep nothing on disk and log to
stdout (D16); the log shipper above is what keeps logs.
