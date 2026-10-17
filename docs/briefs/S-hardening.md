# Hardening units from the P3 review walkthrough (S1, S2, S3)

Read `docs/briefs/ORCHESTRATOR.md` first: its session prompt (zero open items,
repo-wide search, brief errors decided by a fixed order) applies to all
units. S1 and S2 come from the owner's walkthrough of `docs/security-review-pack.md`
sections 3.3 (items 1 and 6) on 2026-10-14. Decisions below are final.

Owner decisions (2026-10-14; S3: 2026-10-17):

- **S1.** The bus loader never mounts the bus's TLS volume or the bus key,
  in either TLS mode. In `openbao` mode it gets the CA certificate from a
  ConfigMap (public data; a ConfigMap is configuration, not pod state, so the
  loader and the bus stay stateless), and the bus keeps issuing its own key
  in memory. In `secret` mode nothing changes: the loader already mounts only
  the `ca.crt` item of the customer's TLS Secret, never `tls.key`, and a
  second ConfigMap there would be one more thing for the customer to supply
  with no gain in isolation.
- **S2.** Secrets and passwords must not reach the audit log (stdout, then
  Fluent Bit, kept 30 days). Use the `masq` library where it fits (Apache-2.0,
  allowed by `CLAUDE.md`), and a small in-repo walker where it does not.
  Free-form content (command text, recipes, property values) is not logged;
  its hash is.

- **S3.** A tenant may always submit, until its backlog is full; then it gets
  a clear refusal at submit time, not failed items later. The dispatch caps
  stay (they are the fairness control from review finding M5), with higher
  defaults. Decided numbers are in the S3 section.

## S1: the loader mounts the CA from a ConfigMap, never the bus TLS volume

Scope: `deploy/helm/nats` (templates, values, README, `chart_test.go`),
`deploy/helm/farmer` (the OpenBao bootstrap Job, trust RBAC, values, README),
`uat/hub` scripts that copy the NATS trust, docs.

Facts on main (2026-10-14), verify first:

- `deploy/helm/nats/templates/bus-statefulset.yaml`: in `bus.tls.mode` `secret`
  the loader mounts volume `loader-ca`, a Secret projection of `ca.crt` alone
  (`IMAS_LOADER_CA_FILE=/var/run/imas/loader-ca/ca.crt`). In `openbao` mode it
  mounts the whole in-memory `tls` volume (`$tlsDir`) read-only, which holds the
  bus key, and reads `$tlsDir/tls-rootca.pem`.
- In `openbao` mode the bus writes the issuing CA of the certificate OpenBao
  issued (`internal/certs/tls.go`, `issuing_ca`) to `tls-rootca.pem`.
- The core bootstrap Job writes the public trust ConfigMap
  (`natsTrust.configMapName`, default `imas-nats-trust`); its RBAC
  (`deploy/helm/farmer/templates/nats-trust-rbac.yaml`) allows `create` on
  ConfigMaps and `get, update, patch` on that one name. The ConfigMap is copied
  into the bus namespace (and to the DMZ hub) by hand or pipeline
  (`uat/hub/dmz/lib.sh`, `DMZ_TRUST_CONFIGMAP`).

Build:

1. **New value** `bus.loader.caConfigMap` (nats chart), default `imas-bus-ca`:
   the ConfigMap, in the bus's namespace, with key `ca.crt`. Used only in
   `openbao` mode. In `secret` mode nothing changes: the loader already
   mounts only `ca.crt` of the TLS Secret.
2. **nats chart, `openbao` mode:** the loader's `loader-ca` volume is a
   `configMap` volume of `bus.loader.caConfigMap`, projecting only `ca.crt`,
   mounted read-only as a directory (never `subPath`, which would not receive
   a CA rotation) at `/var/run/imas/loader-ca`; `IMAS_LOADER_CA_FILE` is
   `/var/run/imas/loader-ca/ca.crt` in both modes. The loader container no
   longer mounts `tls`. The bus pod waits for the ConfigMap the way it waits
   for `nats-trust` (same init pattern; the message names the ConfigMap).
3. **farmer chart, bootstrap Job:** when OpenBao PKI is in use
   (`openbao.enabled` and the PKI mount the bus role issues from), the Job
   writes the ConfigMap named by a new value `natsTrust.busCAConfigMapName`
   (default `imas-bus-ca`) in the core namespace, with `ca.crt` set to the PEM
   OpenBao returns as `issuing_ca` for the bus role's issuer (read the
   issuer certificate from `pki/cert/ca`, or `pki/cert/ca_chain` when the
   mount's issuer is an intermediate; the test below pins which bytes equal
   what an issued certificate's `issuing_ca` carries; if they differ, use the
   one that equals it). The Job creates it when absent and updates it when
   the PEM changed. Add `resourceNames` for the new name to the trust RBAC
   (`get`, `update`, `patch`); `create` is already allowed. Nothing else
   changes in the Job's token handling.
4. **Copy step:** wherever the NATS trust ConfigMap is copied to the bus
   namespace or the DMZ hub (`uat/hub` scripts, `deploy/helm/nats/README.md`,
   `deploy/helm/farmer/README.md` "NATS trust"), copy the CA ConfigMap as well
   when the bus runs in `openbao` mode, with the same wording ("public data
   only"). The two names are two values that default to the same string
   (`natsTrust.busCAConfigMapName` in the farmer chart, the source;
   `bus.loader.caConfigMap` in the nats chart, the destination). The copy
   reads the **source** name from the farmer release's value and writes
   under the **destination** name from the nats release's value, so an
   override of either is delivered (a different destination name is a
   rename). The UAT script takes both names as variables
   (`DMZ_BUS_CA_SRC_CONFIGMAP`, `DMZ_BUS_CA_CONFIGMAP`, next to
   `DMZ_TRUST_CONFIGMAP`), both defaulting to `imas-bus-ca`, and its script
   test covers an override. The UAT uses `secret` mode today, so only the
   copy code and its script tests change there; do not switch the UAT's mode.
5. **Docs:** the nats README describes the loader's mounts exactly (CA
   ConfigMap, SYS user seed, accounts-reader credential, trust ConfigMap; no
   bus key in either mode) and says a CA rotation is a ConfigMap update with
   the new PEM (the loader re-reads it on restart; the runbook,
   `docs/OPENBAO-RUNBOOK.md` section 6, lists it).

Tests (the repo's chart test pattern):

- `deploy/helm/nats/chart_test.go`: for both modes, the loader container
  mounts none of `tls`, `data`, `nats-seeds`; in `openbao` mode `loader-ca`
  is a `configMap` volume named `imas-bus-ca`, projecting only `ca.crt`, no
  `subPath`, and `farmerbus` does not mount it; `IMAS_LOADER_CA_FILE` is
  `/var/run/imas/loader-ca/ca.crt` in both. Extend the existing test that
  covers `secret` mode so that `openbao` mode is no longer untested.
- farmer chart: the bootstrap Job renders the ConfigMap step and the RBAC rule
  with the new name; with OpenBao PKI off the step is absent.
- A Job-script test (the repo's script-test pattern, fake `bao` and `kubectl`)
  that the step writes the PEM, updates on change, and does nothing on no
  change.
- A Go test that the PEM the step reads equals the `issuing_ca` a certificate
  issued from the same mount carries (use `internal/certs`'s test server or
  `openbaotest`; if neither can answer both calls, extend the fake).

Search gate: `loader-ca`, `tls-rootca.pem`, `IMAS_LOADER_CA_FILE`,
`imas-nats-trust`, `DMZ_TRUST_CONFIGMAP`, `busCAConfigMapName`,
`DMZ_BUS_CA_SRC_CONFIGMAP`, `DMZ_BUS_CA_CONFIGMAP`,
`caConfigMap` across `deploy/`, `uat/`, `docs/`, `.github/`.

## S2: no secrets or passwords in the audit log

Scope: `internal/audit`, the two audit write sites in `internal/natsapi`
(`sealedrouter.go` `auditCall`, `shell.go` around line 812), the tenant
provisioning call (`LogAction`), `DEPENDENCIES.md`, `go.mod`, docs.

Facts on main (2026-10-14), verify first:

- `internal/natsapi/sealedrouter.go` `auditCall` sets `entry.Parameters = params`
  for every method that is not in `audit.readOnlyActions`, with no redaction.
  `audit.LogAction` calls `redactToken`, which removes only a top-level
  `token` key. `internal/natsapi/shell.go` writes its own entry.
- Write methods that carry user content include `cmd.run`, `cook`,
  `props.set`, `shell.open`, `deploy.app`, `deploy.recipe`, `multi.recipe`,
  `test.recipe`, `test.sls`, `nginx.harden`, `webserver.nginx`, and
  `auth.users.add`/`resetkey` (public keys). Confirm the list from the router
  and add every other method whose params are free-form.
- `audit.Entry` has `Error`, which can quote a value. `Logger.Log` is the one
  function every audit line goes through.

Build:

1. **One choke point.** Redaction runs inside `Logger.Log`, on a copy of the
   entry, so every writer is covered, now and later: `auditCall`, `shell.go`,
   `LogAction`, and any other `audit.Entry{` writer you find (search; route
   it through `Log`). Callers do not redact.
2. **Free-form methods: log shape, not content.** A fixed set
   `freeFormMethods` (the list above plus every method you add after the
   router check) never logs its parameters. Its `params` becomes
   `{"redacted":"free-form","bytes":N,"sha256":"<hex of the original bytes>","keys":[the sorted top-level key names]}`.
   Targets stay as the entry already carries them. A method not in the set
   and not read-only gets rule 3.
3. **Every other logged parameter object.** Decode to `any` (numbers kept as
   `json.Number`), walk objects and arrays to any depth, and:
   - replace the value of any object key whose lower-cased name matches
     `pass(word|wd|phrase)?`, `secret`, `token`, `api[_-]?key`, `private`,
     `seed`, `credential`, `authorization`, `bearer`, `cookie`, `otp`,
     `sdb` or `key_material` (a substring match on those words) with the
     string `[REDACTED]`;
   - on every string leaf, replace what matches these patterns with
     `[REDACTED]`: a JWT (three base64url parts, the first starting `eyJ`),
     a PEM private key block (`-----BEGIN [A-Z ]*PRIVATE KEY-----` to its END
     line), an NATS seed (`S[UAON][A-Z2-7]{55}`), `AKIA[0-9A-Z]{16}`,
     `Bearer\s+\S+`, URL userinfo (`://user:pass@`), and `name=value` or
     `name: value` where name is one of the key words above.
   - Use **`github.com/m-mizutani/masq`** for the string-leaf patterns:
     build one `masq.New(masq.WithRegex(...))` per pattern and apply it to
     each string leaf as a `slog.Attr`. Its documentation covers `slog`
     attributes and struct fields only, so the key-name rule and the
     free-form rule are the in-repo walker, not masq. First write the test
     that applies masq to a string leaf holding each pattern. If it does
     not replace all of them, use `regexp` for the string leaves instead
     and say so in the PR; do not leave both in.
   - Parameters that do not parse as JSON, or that exceed 1 MiB, are not
     logged: `{"redacted":"unparseable","bytes":N,"sha256":"..."}`.
4. **`Entry.Error`.** Apply rule 3's string patterns to it (an error that
   quotes a secret is redacted). Do not change the other fields.
5. **Dependency.** If masq is kept: `go get` the latest release, record it in
   `DEPENDENCIES.md` with its licence (Apache-2.0), confirm
   `CGO_ENABLED=0 go build ./...` still passes. A license other than
   Apache-2.0 or MIT in the module's own tree is flagged and the dependency
   not added (use `regexp`).
6. **Docs.** `docs/design/imas-payload-encryption-design.md` (the router step
   that audits "a write's params") and the audit paragraph in
   `internal/audit/audit.go` say what is logged: parameters of ordinary
   write methods with secrets masked, the shape and hash of free-form
   methods. Add a short "What the audit log never contains" list to
   `docs/INSTALL.md` or the saasapi/farmer README where audit is described.

Tests:

- Table test per rule: each key word (any case, at depth 3, inside an array);
  each string pattern; a JWT in a command-looking string; a PEM block; an NATS
  seed; invalid JSON; a 2 MiB body.
- Per free-form method: the logged line has the shape in rule 2 and the
  original text appears nowhere in the line (assert on the raw bytes written).
- A test through `auditCall` and through the shell writer and `LogAction`
  that a fixture containing `password`, `X-Api-Key`, an NATS seed and a JWT
  never appears in the bytes written to the writer.
- The existing audit tests still pass; a read-only method is unchanged.

Search gate: `audit.Entry{`, `Parameters`, `redactToken`, `LogAction`,
`readOnlyActions` across `internal/`, `cmd/`, `docs/`.

## S3: action backlog: higher dispatch defaults and a refusal when a tenant's backlog is full

Source: P3 walkthrough 3.4 item 5, owner decision 2026-10-17. Today a tenant
can submit batches (100 `asset_ids` per request, 1 request a second, burst 5)
and every one is accepted with a 202, but items are sent at most
`tenantConcurrency` (8) at a time per process, and an item still queued
`SAASAPI_OUTBOX_ACTION_MAX_AGE` (15m) after acceptance fails as
`expired_not_sent`. A tenant sending a batch for 1,000 sprouts with minute-long
commands sees most items expire, with no error at submit time. The backlog is
durable (`asset_action_items` in the saas schema) and survives a pod restart;
that does not change.

Scope: `internal/saasapi` (`sprout_actions.go`, `config.go`, `sweeper.go`,
`dispatch_limits.go`, `errors.go`), `internal/natsapi/sprout_action.go`,
`internal/migrations/saas` (one new migration), `deploy/helm/farmer`
(templates, values, README, `chart_test.go`), `docs/api/saasapi.md`,
`docs/api/saasapi-openapi.yaml`, `uat/` values if they set these keys, docs.

Facts on main (2026-10-17), verify first:

- `CreateSproutActionBatch` (`sprout_actions.go`) validates, resolves the
  `asset_ids`, calls `createActionBatch`, which calls `createBatch` with a
  `claim func(tx *gorm.DB) error` hook that runs first inside the transaction
  and rolls everything back on error. Update rollouts also call `createBatch`.
- Defaults: `defaultActionDispatchConcurrency` 64,
  `defaultSelfUpdateDispatchConcurrency` 16,
  `defaultActionDispatchTenantConcurrency` 8 (`dispatch_limits.go`);
  `defaultActionMaxAge` 15m, bounds 1m to 1h (`sweeper.go`); farmer has the
  same pool defaults (`IMAS_SPROUT_ACTION_CONCURRENCY`,
  `IMAS_SELF_UPDATE_CONCURRENCY`, `IMAS_SPROUT_ACTION_TENANT_CONCURRENCY` in
  `internal/natsapi/sprout_action.go`).
- `LoadConfig` requires the tenant cap times 2 to be at most the cmd.run/cook
  pool.
- `asset_action_items` has primary key `(batch_id, asset_id)` and no index on
  `tenant_id` and `status`.
- Error responses use `writeErrorDetails` (`errors.go`); the per-tenant rate
  limit answers 429 `rate_limited`.

Decisions (final):

1. **New defaults**, in code, in `deploy/helm/farmer/values.yaml` for both
   `farmer.sproutActions` and `saasapi.actionDispatch`, and in the READMEs:
   cmd.run/cook pool 256 (was 64); tenant cap 32 (was 8); self_update pool
   stays 16. Farmer and saasapi change together, because saasapi's values must
   stay at or below farmer's value times its replicas (existing README rule).
   The half-of-the-pool rule stays and is satisfied (32 times 2 is at most
   256). `SAASAPI_OUTBOX_ACTION_MAX_AGE` default becomes 30m; its bounds stay
   1m to 1h. Update every test that asserts an old default.
2. **A cap on a tenant's pending items.** New setting
   `SAASAPI_ACTION_MAX_PENDING_PER_TENANT`: default 2000, an integer from 1 to
   100000, refused at startup outside that range, same style as the other
   dispatch settings. Helm key `saasapi.actionDispatch.maxPendingPerTenant`
   (null emits no env var). "Pending" is a tenant's items in status `queued`
   or `dispatching`; `running` items hold a dispatch slot and are not counted.
3. **Where it is checked.** Only in `CreateSproutActionBatch`, never for update
   rollouts (a rollout wave must not be blocked by a tenant's own backlog).
   Use the `claim` hook of `createBatch`: inside the transaction, before the
   batch row is written, count the tenant's pending items; if the count plus
   the number of deduplicated `asset_ids` in this request exceeds the setting,
   return a typed error that the handler turns into the refusal below. Nothing
   is written on refusal and the request is refused as a whole, never
   partially accepted. The count is a soft limit: two requests on different
   replicas at the same moment may both pass, so the backlog can exceed the
   setting by at most the items of the requests in flight (each at most 100,
   and one request a second per tenant per pod). Say this in the code comment
   and the docs.
4. **The refusal.** HTTP 429, code `backlog_full`, message "this tenant has too
   many actions waiting to be sent; wait for some to finish and send again",
   `details` with integers `pending`, `limit`, `requested` and `available`
   (`limit - pending`, never negative), and a `Retry-After: 60` header. A
   `rate_limited` response is unchanged. Add `backlog_full` to the error list in
   `docs/api/saasapi.md` and to `docs/api/saasapi-openapi.yaml` for the
   endpoint, with a 429 response schema that carries `details`.
5. **Index.** One new goose migration after the latest in
   `internal/migrations/saas` (use the next number; read the directory, do not
   guess) adds `idx_asset_action_items_tenant_status` on
   `asset_action_items (tenant_id, status)`. Follow the style of the existing
   migrations including the Down section, and add the migration test that the
   neighbouring migrations have. Keep the gorm model tags consistent with it.
6. **Docs.** In `docs/api/saasapi.md`, under the actions endpoint, say in
   plain words: items are stored durably and sent in the background; at most
   the tenant cap run at once per process; an item not sent within the max age
   fails as `expired_not_sent` and never ran; the pending cap and the
   `backlog_full` response; the throughput rule of thumb (cap divided by the
   command's duration, per process). State the defaults.

Tests:

- Boundary: pending plus requested equal to the limit is accepted, one more
  is refused; the refusal writes no batch or item rows; the details numbers are
  right; `Retry-After` is set.
- Another tenant with the same number of pending items is not affected.
- `running`, `succeeded` and `failed` items are not counted; `queued` and
  `dispatching` are.
- An update rollout batch is accepted when the tenant is over the cap.
- Config: the new setting's default, range, and a bad value refuses startup;
  new defaults of the pools, tenant cap and max age; the half-of-the-pool rule
  still enforced.
- Farmer's new defaults (`internal/natsapi`) and the Helm render of both values
  blocks, with and without `maxPendingPerTenant`, in `chart_test.go`.
- The migration applies, and rolls back, on the test database used by the
  neighbouring migration tests.

Search gate: `defaultActionDispatchConcurrency`,
`defaultActionDispatchTenantConcurrency`, `defaultActionMaxAge`,
`ACTION_DISPATCH_TENANT_CONCURRENCY`, `SPROUT_ACTION_TENANT_CONCURRENCY`,
`ACTION_MAX_AGE`, `tenantConcurrency`, `actionMaxAge`, `rate_limited`,
`sproutActionRate` across `internal/`, `cmd/`, `deploy/`, `uat/`, `docs/`.
