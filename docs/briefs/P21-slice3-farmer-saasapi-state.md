# Slice 3 build spec: stateless farmer and saasapi

Repo: /home/claude/yogzblr/imas (module github.com/yogzblr/imas). Spec only; nothing in the repo was changed.
Source design: docs/design/imas-openbao-signing-design.md (D1-D21, section 9.2 state inventory, 9.1 loader, 11 tests) and docs/design/imas-nats-jwt-auth-design.md.
Note: the brief calls the docs "grlx-*"; the real files are "imas-*".
Items marked CONFIRM could not be verified from the sources available (Go module cache and nats-io/jwt source are absent in this sandbox).

## 0. Binding decisions and dependencies

Binding (from the owner):
- No PVC. No state that cannot be rebuilt from PXC, Valkey, OpenBao or S3.
- Per-sprout User JWTs live in a private object-store bucket. Mint-or-reuse is guarded by a PXC row lease (pattern: internal/saasapi/outbox_lease.go). GET_LOCK is not used (node-local on PXC).
- Account/signing keys are OpenBao Transit keys (slice 1/2).
- Farmer NKey is a shared Kubernetes Secret (via ESO, like natsSeeds).
- SaaS API credential rotation state goes to PXC.
- Audit goes to stdout as JSON; Fluent Bit ships it; default retention 30 days.
- `localCooks` becomes a PXC row with TTL (D13) - see owner decision 2 for a simpler alternative.
- Per-replica background jobs get a row lease or are made idempotent.
- `recipeTenantLocks` becomes a row lease or optimistic version check.
- Farmer per-tenant bus connections reconnect after the 30-attempt limit, connect lazily, close when idle.
- Remove chart `farmer.replicaCount==1` validation and the RWO PVC.
- No migration or compat shims. Tests do not test PXC/Valkey/OpenBao/S3 (D7); they test our code with fakes.

Interfaces required from other slices (narrowest form I need):

```go
// package pki (slice 1 supplies the Transit implementation; tests use an in-memory ed25519 fake)
type Signer interface {
    PublicKey() (string, error)          // account/operator public nkey ("A...", "O...")
    Sign(payload []byte) ([]byte, error) // raw Ed25519 signature
}
// slice 2 (loader) supplies:
type AccountStore interface {
    AccountSigner(ctx context.Context, tenantID string) (Signer, error)
    OperatorSigner(ctx context.Context) (Signer, error)
    SystemAccountSigner(ctx context.Context) (Signer, error)
}
```
Slice 3 calls jwt encoding through a Signer->nkeys.KeyPair adapter (needs PublicKey and Sign only; whether jwt.Encode needs Seed()/PrivateKey() is CONFIRM against the pinned nats-io/jwt version; if it does, the adapter must be built on `nkeys.KeyPair` with those methods returning an error, and the call site must use a signing function that does not need them).

## 1. Inventory of file writes and process-local state

Class: (a) must move to a shared store, (b) already rebuilt from shared stores / safe per replica, (c) per-replica memory that is wrong or wasteful across replicas and needs a lease, idempotency or shared store.
Line numbers are from the current tree.

### 1.1 Files under config.FarmerPKI and /var/lib/imas/farmer

| Path (config key) | Written at | Class | Target |
|---|---|---|---|
| FarmerPKI/ operator and account seeds/JWTs, tenant account JWT and signing key files (internal/pki/tenant.go, jwtauth.go) | pki/tenant.go, pki/jwtauth.go (functions that call os.WriteFile for account material; see 1.4) | (a) | Transit keys (slice 1/2); account JWT recomputed from PXC, not stored |
| Per-sprout user JWT files (internal/pki/jwtusers.go) | jwtusers.go | (a) | private S3 bucket `IMAS_S3_SPROUT_JWT_BUCKET`, PXC index + lease |
| saasapi user JWT file and the `prevPub` read from it (internal/pki/saasapi_user.go, saasapi_publish.go) | saasapi_user.go, saasapi_publish.go | (a) | PXC `saas.saasapi_credential_state` |
| SYS account JWT with revocations (internal/pki/pushall.go, nats.go) | pushall.go, nats.go | (a) | recomputed from PXC `farmer.account_lockouts` (see 1.4) and signed with Transit; not persisted |
| `sys-user.nk` seed (generated locally; absent from chart's six seeds, values.yaml:73-92) | pki (nats.go / busauth.go) | (a) | new Secret key `SYS_USER` in natsSeeds, env `IMAS_NATS_SYS_USER_SEED_FILE` |
| Farmer NKey files (`GenNKey`, internal/certs/nkey.go:24-57), configmap path farmer-configmap.yaml:12-17 | nkey.go:24-57 | (a) | Secret mounted read-only; `IMAS_FARMER_NKEY_SEED_FILE`; GenNKey removed from the farmer start path |
| Farmer TLS certs written to tls dir (internal/certs/tls.go; chart tls volume farmer-deployment.yaml:258-275, `_helpers.tpl:232`) | certs/tls.go | (b) | memory emptyDir already (or Secret); the in-memory lease id at tls.go:271 is per-process and fine |
| Audit file (internal/audit/audit.go, configmap audit path) | audit.go | (a) | stdout JSON (section 4.6) |
| Job log files (configmap joblog path) | internal/jobs | (b) | S3 job bucket already (config S3JobBucket); remove local path from configmap |
| props path (configmap) | farmer-configmap | (b) | read only |
| `/etc/imas/farmer` config file: LoadConfig creates and rewrites it (config.go: create at 495-505 for farmer; `jety.WriteConfig()` at config.go:772 runs for every binary) | config.go:495-505, 772 | (a) | farmer/saasapi must never write config: guard WriteConfig behind `binary != farmer`; the read-only ConfigMap would otherwise fail (error is ignored today, so this is silent; make it explicit) |
| `createConfigRoot` (cmd/farmer/main.go:611-626) | main.go:611-626 | (a) | mkdir of config root removed; fail fast if absent |
| `data`, `cache` volumes (farmer-deployment.yaml:208-218) | chart | (a) | removed; only `tmp` emptyDir stays |
| `SetSproutID`/`ClearJoinToken` (config.go:1022) | sprout side only | n/a | not used by farmer; CONFIRM by grep in step 1 |

### 1.2 Process-local state

| State | Location | Class | Change |
|---|---|---|---|
| `localCooks` | internal/natsapi/cook.go:131-166, read at 176-207 (`awaitCookTrigger`); prepare at sprout_action.go:586, trigger at 601 in same handler | (c) | see owner decision 2; default: collapse prepare+trigger so no map is needed; fallback: PXC row `farmer.prepared_cooks` with TTL |
| `recipeTenantLocks` | internal/saasapi/recipes.go:599-605, 741-746 (`PutConditional` already used) | (c) | optimistic: rely on `PutConditional` ETag and retry; remove in-process mutex map |
| Cohort membership cache | internal/rbac/cohort.go:149-169, 324-353 | (c) | acceptable per replica only if bounded TTL; add TTL (default 30s) and invalidation by PXC `updated_at` version check |
| `cohort_refresher` | internal/natsapi/cohort_refresher.go | (c) | row lease `cohort_refresher` |
| Job expiry reaper | internal/jobs/expiry.go:20-47, 55-102 (every replica) | (c) | row lease `jobs_expiry`, plus idempotent delete |
| jobs status index | internal/jobs/status_index.go:286 | (b) | CONFIRM idempotent; wrap in same lease if it is periodic |
| sprout reaper, CLI store | internal/jobs/sproutreaper.go, clistore.go | (b) | sprout/CLI only |
| Heartbeat $SYS subscriptions (non-queue) | internal/heartbeat/heartbeat.go:155-198 | (c) | every replica processes every event; writes to PXC must be idempotent upserts (CONFIRM they are); queue sub at 234-239 is fine |
| Tenant connection registry (tenantconn.Registry, natsConns, farmerConns) | internal/tenantconn/registry.go; cmd/farmer/main.go:720-989 | (c) | lazy connect, reconnect forever, idle close (section 4.5) |
| Valkey replay/claim caches (pki/tenantbox.go, platformbox.go, store.go:248, sealedclaim.go, payloadbox/replay.go) | pki | (b) | already Valkey |
| update manifest cache and limiter | internal/api/handlers/update_manifest.go | (c) | per-replica cache is safe; limiter becomes N x limit; document, no change (see owner decisions: none needed) |
| saasapi rate limiter | internal/saasapi/middleware.go:183, router.go:40,80,92 | (c) | same: per-replica, document effective limit = N x configured |
| dispatch limits | internal/saasapi/dispatch_limits.go, sprout_actions.go:722-729, fleet_update_dispatch.go:752,780 | (c) | CONFIRM whether state is in memory; if so move counter to Valkey INCR with TTL |
| natsapi limiter | sprout_action.go:243-300 | (c) | same treatment as dispatch limits |
| Outbox workers | internal/saasapi/outbox_lease.go | (b) | already leased; reuse as the model |
| cook helpers cache | internal/cook/helpers.go:40-41, farmercook.go:889 | (b) | CONFIRM read-only |
| PKI JWT caches | pki/jwtauth.go | (c) | `ReloadNKeysForTenant` re-syncs all sprouts per enrolment (O(N)); replace with single-sprout push (section 4.2) |
| `PushAllAccounts` at every reconnect on every replica | pki/pushall.go | (c) | wrap in lease `pushall:<tenant>` with 60s min interval |

### 1.3 Logging
internal/log/log.go:31-37 writes charm text to stderr. Add JSON mode (env `IMAS_LOG_FORMAT=json`, default `json` in chart). This is the "audit to stdout JSON" channel.

### 1.4 Open items I could not verify
- Exact os.WriteFile call sites inside internal/pki/*.go (the list above is by file; step 1 of the build starts with `grep -rn "WriteFile\|os.Create\|OpenFile\|MkdirAll" cmd/farmer cmd/saasapi internal/pki internal/certs internal/audit internal/jobs internal/natsapi internal/saasapi` and the test `TestNoFileWritesOutsideTmp` enforces the result).
- Whether jwt.Encode needs the private key accessors (see section 0).

## 2. Schema (goose, internal/migrations)

Ownership rules: farmer_svc has ALL on farmer.*, SELECT on saas.*; saas_svc the reverse. Forward-only, idempotent, PREPARE-guard idiom, expand-only, bump `compatibleFrom` in migrations.go. Next numbers: farmer 00004+, saas 00007+ (existing: farmer 00001-00003, saas 00001-00006).

farmer schema (written by farmer):
```sql
-- farmer/00004_state_leases.sql
CREATE TABLE IF NOT EXISTS farmer.job_leases (
  name        VARCHAR(128) NOT NULL PRIMARY KEY,
  lease_owner VARCHAR(128) NULL,
  lease_until DATETIME(3)  NULL,
  last_run_at DATETIME(3)  NULL
);
-- seed rows: jobs_expiry, cohort_refresher, (pushall:<tenant> inserted on demand with INSERT IGNORE)

-- farmer/00005_sprout_jwt_index.sql
CREATE TABLE IF NOT EXISTS farmer.sprout_user_jwt (
  tenant_id    VARCHAR(64)  NOT NULL,
  sprout_id    VARCHAR(128) NOT NULL,
  object_key   VARCHAR(255) NOT NULL,
  user_pubkey  VARCHAR(64)  NOT NULL,
  jwt_sha256   CHAR(64)     NOT NULL,
  expires_at   DATETIME(3)  NULL,
  lease_owner  VARCHAR(128) NULL,
  lease_until  DATETIME(3)  NULL,
  updated_at   DATETIME(3)  NOT NULL,
  PRIMARY KEY (tenant_id, sprout_id)
);

-- farmer/00006_prepared_cooks.sql   (only if owner decision 2 picks the PXC row)
CREATE TABLE IF NOT EXISTS farmer.prepared_cooks (
  tenant_id VARCHAR(64) NOT NULL, jid VARCHAR(64) NOT NULL,
  payload   MEDIUMBLOB NOT NULL, expires_at DATETIME(3) NOT NULL,
  PRIMARY KEY (tenant_id, jid), KEY ix_expires (expires_at)
);
```
Keys follow the (tenant_id, sprout_id) rule from CLAUDE.md.

saas schema (written by saasapi):
```sql
-- saas/00007_saasapi_credential_state.sql
CREATE TABLE IF NOT EXISTS saas.saasapi_credential_state (
  id            TINYINT      NOT NULL PRIMARY KEY,   -- single row, id=1
  current_pub   VARCHAR(64)  NOT NULL,
  prev_pub      VARCHAR(64)  NULL,
  rotated_at    DATETIME(3)  NOT NULL,
  version       BIGINT       NOT NULL,
  lease_owner   VARCHAR(128) NULL,
  lease_until   DATETIME(3)  NULL
);
```
Cross-schema rule: farmer needs saasapi `prev_pub` for SYS account revocations; farmer reads it with SELECT on saas.* (allowed). saasapi must not write farmer.*.

Lease SQL (model: outbox_lease.go, full pattern read): acquire = `UPDATE t SET lease_owner=?, lease_until=? WHERE name=? AND (lease_owner IS NULL OR lease_until < NOW(3) OR lease_owner=?)`, success iff RowsAffected==1. Extract the helper into `internal/lease` (new package, one function set `Acquire/Renew/Release`) with table/columns parameters validated against an allow-list (never interpolate caller strings).

## 3. Config and env

New or changed:
- `IMAS_FARMER_NKEY_SEED_FILE`: path to mounted Secret key (replaces generated NKey files).
- `IMAS_NATS_SYS_USER_SEED_FILE`: Secret key `SYS_USER`.
- `IMAS_S3_SPROUT_JWT_BUCKET`: private bucket for user JWTs (distinct from recipe and job buckets, same reasoning as config.S3JobBucket comment).
- `IMAS_LOG_FORMAT=json|text`.
- `IMAS_JOB_LEASE_TTL` (default 120s), `IMAS_TENANT_CONN_IDLE_TTL` (default 10m), `IMAS_PREPARED_COOK_TTL` (default 60s, only with PXC row).
- `IMAS_FARMER_PKI_DIR`, data dir env: removed. Farmer refuses to start if it detects a writable `/var/lib/imas/farmer` is required.
Chart: add `natsSeeds.SYS_USER` to values.yaml:73-92 and the ESO mapping; add `farmer.nkeySecret`.

## 4. Function-level changes

### 4.1 Account and signing keys (pki/tenant.go, jwtauth.go, nats.go)
Replace every direct `nkeys.KeyPair` file load with `AccountStore.AccountSigner(ctx, tenant)`. Account JWTs are encoded with the signer and never written to disk. Failure: if the signer is unavailable (OpenBao down), enrolment returns 503 and sprouts retry; existing connections are unaffected.

### 4.2 Sprout user JWT mint-or-reuse (pki/jwtusers.go, enroll.go)
`MintOrReuseUserJWT(ctx, tenant, sprout, pubkey)`:
1. SELECT row; if exists and `user_pubkey` matches and not within renew window: GET object, verify sha256, return.
2. Else acquire row lease (INSERT IGNORE the row, then conditional UPDATE).
3. Re-read after acquiring (another replica may have minted); if present, release and return it.
4. Sign with the tenant account signer, PUT object (idempotent key `<tenant>/<sprout>/<jwt_sha256>.jwt`), UPDATE row, release.
5. Lease not acquired: poll row up to 5s, then return 503 retry-after.
Replica killed mid-enrolment: lease expires at `lease_until`; object may exist without a row update, harmless because key includes the hash and the next minter overwrites or reuses. No duplicate keys: the lease serialises, and the row `user_pubkey` is the source of truth.
`ReloadNKeysForTenant` (O(N) re-sync) is replaced by pushing only the changed sprout's claims.

### 4.3 SaaS API credential rotation (pki/saasapi_user.go, saasapi_publish.go)
Read `prev_pub`/`current_pub` from `saas.saasapi_credential_state`. Rotation: lease, compute new key (Transit), conditional UPDATE `WHERE version=?`. Farmer builds SYS account revocation list from `prev_pub`.

### 4.4 Background jobs
`jobs/expiry.go:55-102`: wrap loop body in `lease.Run(ctx, "jobs_expiry", ttl, fn)`; skip silently when not leader. `natsapi/cohort_refresher.go`: same. `pki/pushall.go`: lease per tenant plus min interval via `last_run_at`.

### 4.5 Tenant bus connections (cmd/farmer/main.go:720-989)
- `dialTenantBus` (720-795): set `MaxReconnects(-1)` (replaces 30 at line 723/767); keep `maxFarmerReconnect` only as a log threshold; add `ClosedHandler` that removes the entry from the registry so the next use reconnects. Seed read at 743 uses the account signer/loader (slice 2), not a file.
- `ConnectFarmer` (906-989) and `connectTenantWithRetry` (844-875): no longer connect all tenants at start or only on the provisioning replica; `tenantconn.Registry.Get(ctx, tenant)` connects lazily (singleflight per tenant) the first time a handler or sub needs it.
- Queue subscriptions for a tenant (`imas-core`) are created on first connect on every replica, so work spreads. `registerTenantHandlers` (803-828) is idempotent.
- Idle close: registry tracks last-use; a sweeper closes connections idle > `IMAS_TENANT_CONN_IDLE_TTL` and unsubscribes. Caveat: a tenant with no live connection receives no queue-group messages on that replica; with N replicas at least one must remain subscribed while sprouts are online. Resolution: tenant discovery from PXC (tenants with sprouts heartbeating in last X) keeps those connections open; idle close applies only to tenants without recent sprout heartbeat. Needs owner decision 3.
- `disconnectTenant` (884-895) unchanged semantics, called by sweeper and ClosedHandler.

### 4.6 Audit (internal/audit/audit.go, query.go, natsapi/audit.go; callers sealedrouter.go:174-193, shell.go:814-818, tenant_provision.go:207)
`audit.Record` writes one JSON line to stdout (`{"ts","kind":"audit",...}`). `initAuditLogger` (main.go:567-581) is reduced to configuring that writer. Query API (`audit.query`, `audit.dates`) cannot work; see owner decision 1.

### 4.7 Config and root FS
`config.LoadConfig`: skip file creation and `jety.WriteConfig()` for farmer (config.go:495-505, 772). `createConfigRoot` removed. Run farmer with `readOnlyRootFilesystem: true`.

### 4.8 recipeTenantLocks (saasapi/recipes.go:599-605, 741-746)
Remove the in-process lock; on `PutConditional` precondition failure retry up to 3 times re-reading; after that return 409. Failure: concurrent writers get 409 instead of silent serialisation.

## 5. Chart changes

- farmer-deployment.yaml:15-20: `replicas: {{ .Values.farmer.replicaCount }}`, strategy RollingUpdate (maxUnavailable 0, maxSurge 1) instead of Recreate. Remove `data`, `cache` volumes and mounts (208-218, 231-257 as applicable); keep `tmp` emptyDir (size limit) and tls volume (258-275). Add nkey and SYS_USER secret mounts (read-only). Add `readOnlyRootFilesystem: true`.
- farmer-pvc.yaml: delete file. values.yaml:346-355 `farmer.persistence` block deleted.
- `_helpers.tpl:699-700`: delete the `replicaCount==1` fail.
- farmer-configmap.yaml:3,12-17: delete pki/nkey-generation/audit/joblog paths; add the env above.
- values.yaml: `farmer.replicaCount` (235) default 2; add `farmer.pdb` (new farmer-pdb.yaml, minAvailable 1); add `farmer.topologySpreadConstraints` and default preferred anti-affinity mirroring saasapi-deployment.yaml:56-68 (farmer `affinity` at 391 currently empty/default - CONFIRM); saasapi `replicaCount` (414) default 2; saasapi has `pdb` and `topologySpreadConstraints` at 628-641, already present; add explicit `strategy: RollingUpdate` (maxUnavailable 0) to saasapi-deployment.yaml (no strategy field today, default RollingUpdate with 25%).
- NOTES.txt:1 "farmer (1 replica)": reword.
- README "Why one farmer replica" (~line 900): replace with "Farmer is stateless" section describing leases and bucket.
- Chart render Go tests: update expectations (see tests).

## 6. Tests (names and assertions; fakes only)

Location: package-level tests alongside code, using sqlite GORM AutoMigrate, miniredis, objectstoretest, openbaotest (Transit fake) per existing patterns. MySQL-specific lease SQL gets an additional test gated on `IMAS_TEST_MYSQL_ROOT_DSN`.

1. `TestEnrollConcurrentReplicas`: N=8 goroutines, each with its own `pki` instance sharing one sqlite DB + objectstoretest + fake signer, enrol the same (tenant, sprout) at once. Assert: exactly one object per sprout, one PXC row, identical returned JWT for all, signer.Sign call count for that sprout == 1. Variant with 8 distinct sprouts: 8 rows, distinct pubkeys, no duplicate.
2. `TestEnrollReplicaKilledMidMint`: replica A acquires lease then its context is cancelled after the PUT but before the row UPDATE (test hook). Replica B (clock advanced past lease_until by injected clock) completes; assert final row consistent, JWT valid, no orphan row without object.
3. `TestEnrollLeaseNotAcquiredReturnsRetry`: lease held, not expired: caller gets retryable error within 5s, no signing.
4. `TestHourlyJobsRunOnce`: 4 replicas' `jobs.Expiry` loops against one sqlite; same tick via fake clock; assert reaper body executed once per interval, `job_leases.last_run_at` updated, second tick after TTL elapses allows another run; same for cohort_refresher and pushall.
5. `TestPreparedCookTriggerOnOtherReplica` (applies to whichever design owner picks): prepare on replica A's handler, trigger on replica B; assert cook starts exactly once; second trigger returns not-found; TTL expiry test. If collapsed design: `TestRunSproutCookSingleCall` asserts no shared map is touched and trigger is called after prepare in one handler.
6. `TestRecipePutConcurrentWriters`: 8 concurrent PutConditional on same key; assert exactly the sequence of ETag-validated writes succeed, losers get 409 after retries, no lost update.
7. `TestTenantBusReconnectsAfterMax`: fake dialer that closes the connection; after ClosedHandler fires, next `Registry.Get` redials; assert it does not give up after 30 attempts (MaxReconnects == -1 check on options).
8. `TestTenantBusLazyAndIdleClose`: no dial at startup; first Get dials once under 16 concurrent callers (singleflight); idle sweeper closes after TTL with fake clock; busy tenant stays open.
9. `TestNoFileWrittenOutsideTmp`: run farmer and saasapi startup plus enrolment, cook prepare, audit record, and rotation flows with working dir and `HOME` set to a temp dir and the config root a read-only dir (chmod 0555 or test seam); assert no file created anywhere except under os.TempDir()/the test's tmp. Add a static test that greps source for `os.WriteFile|os.Create|OpenFile|MkdirAll` in cmd/farmer, cmd/saasapi, internal/pki, internal/certs and fails on any call not on an allow-list (tmp dir use only).
10. `TestAuditWritesJSONToStdout`: capture stdout, assert one valid JSON line per event with required fields, nothing written to a file.
11. `TestSaasapiCredentialRotationConcurrent`: two replicas rotate; version check ensures one wins; `prev_pub` set; farmer revocation list includes it.
12. Chart render tests: `TestFarmerRendersWithTwoReplicas` (no fail), `TestFarmerHasNoPVC`, `TestFarmerRootFSReadOnly`, `TestFarmerPDBRendered`, `TestSaasapiStrategyRollingUpdate`, `TestFarmerNoDataVolume`.
13. Migration tests per existing pattern in internal/migrations (idempotent second run, ownership grants).

## 7. Implementation order (one PR each)

1. Inventory guard: add `TestNoFileWrittenOutsideTmp` static allow-list in report-only mode, plus `internal/lease` package with fake-clock tests. Green: `go test ./...`.
2. Migrations (farmer 00004-00005 [+00006], saas 00007) and migration tests. Green: migrations tests, MySQL gated run in CI.
3. Config/logging: JSON log format, audit to stdout, LoadConfig no-write, createConfigRoot removal, owner decision 1 applied. Green: audit and config tests.
4. Seeds: SYS_USER and farmer NKey from Secret (chart and code). Green: chart render tests, farmer start test with read-only root.
5. Sprout JWT store + lease (needs slice 1/2 interfaces merged). Green: tests 1-3.
6. SaaS API credential state. Green: test 11.
7. Background jobs leases + recipe optimistic writes + prepared cook change. Green: tests 4-6.
8. Tenant bus lazy/reconnect/idle. Green: tests 7-8.
9. Chart: remove PVC and validation, replicas 2, RollingUpdate, PDB, spread, README, NOTES; switch the static test from report-only to enforcing. Green: chart tests, test 9 enforcing.

## 8. OWNER DECISIONS NEEDED

1. Replacement for `audit.query`/`audit.dates` and the `imas audit` CLI once audit goes to stdout. Options: (A) drop the API and CLI, query via the log platform; (B) keep it, backed by a PXC audit table (violates "audit to stdout" intent, adds write load); (C) read back from shipper output in S3. Recommendation: A.
2. `localCooks`: D13 says PXC row with TTL. The prepare (sprout_action.go:586) and trigger (601) run in the same handler, so the map is only needed across the `awaitCookTrigger` path (cook.go:176-207). Options: (A) collapse into one call, no shared state; (B) PXC row `prepared_cooks` as D13 says. Recommendation: A if the separate trigger API is internal only; otherwise B.
3. Idle close vs queue-group delivery: a replica that closes an idle tenant connection stops receiving that tenant's queue messages. Options: (A) keep open every tenant that has had a sprout heartbeat in the last N minutes (default 15), close only truly idle ones; (B) never idle-close, only lazy connect; (C) idle close everywhere and rely on sprouts reconnecting. Recommendation: A.

## Owner decisions (2026-10-11) - these settle "OWNER DECISIONS NEEDED" above; do not ask again
1. (A) Drop the audit.query and audit.dates API and the imas audit CLI; audit goes to stdout and is queried in the log platform. Remove the routes, handlers, client and CLI command, and state the removal in the PR.
2. (A) Merge prepare and trigger into one call; localCooks and any prepared_cooks table are not built.
3. (A) Keep open every tenant connection that has a sprout heartbeat in the last 15 minutes; close only idle ones. The 15 minutes is a chart value.
