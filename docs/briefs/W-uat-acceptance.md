# UAT acceptance cases for the S, T and U fixes (W1)

Read `docs/briefs/ORCHESTRATOR.md` first: its session prompt (zero open items,
repo-wide search, brief errors decided by a fixed order) applies to this unit.
The fix units S1 to S6, T1 to T6 and U1 to U4 are merged and unit tested, but
the UAT acceptance suite (`uat/tests`) has no case that exercises them on a
deployed stack. This unit adds those cases and refreshes `uat/lite/README.md`,
so the local rig run (WSL2) and the Azure runs prove them.

Owner decisions (2026-10-19, final):

- Add the six cases below to the catalogue and the suite. They run in the
  `core` tier unless stated, and are written to run unchanged on the local
  rig (`uat/lite`) and on Azure.
- A case that cannot run on the rig (needs Windows, network separation, a
  node reboot) gets a written `SKIP` with a reason, never a silent pass.
- Retention periods and the purge delay are configurable in the charts. The
  cases do not wait for the defaults: they set short values through the
  chart/env settings in the UAT values files (`uat/hub/core/values/`), and the
  defaults stay as shipped.
- Nothing here changes product code. If a case finds a product bug, the
  session stops, files it under "Brief corrections" with the failing test
  kept behind `t.Skip("known bug: <issue>")` only if the owner agrees, and
  otherwise leaves the case failing with the reason in the PR.

Found by the first rig run (rc.14, 2026-10-19; core 58 pass, 0 fail, 3
skip): scenario S6's clean re-enrolment after a purge is skipped because
saasapi has no route to delete or revoke a sprout. That is a product gap, not
a test gap. **Open owner decision:** add `DELETE /v1/tenants/{tenant_id}/sprouts/{sprout_id}`
(write role, rate limited, revokes the sprout's NKey and removes its row)
before W1, or accept the skip. Until decided, W1 does not add the route; E1
covers erasure through the tenant purge, which removes the tenant's sprouts
with it, and the S6 skip stays.

## W1: acceptance cases and the lite README

Scope: `uat/tests/*_test.go`, `uat/tests/catalogue.tsv`,
`uat/tests/harness/` (helpers, and `fakestack` so the in-memory run stays
green), `docs/claude-code-parallel-build-plan.md` section 4h's scenario table
(`TestCatalogueMatchesPlan` keeps it equal to the catalogue), `uat/tests/README.md`,
`uat/hub/core/values/*-uat.yaml` and `uat/lite` (values only, for the short
retention settings), `uat/lite/README.md`, `uat/RUNBOOK.md`, docs.

New scenario IDs (check the catalogue for clashes and take the next free
ones if these are used):

| ID | Tier | Scenario | Covers |
|---|---|---|---|
| B1 | core | A tenant whose action backlog is full gets `429 backlog_full` with `details` (pending, limit, requested, available) and `Retry-After: 60`; after the backlog drains, the same request is accepted | S3 |
| E1 | core | Offboard a tenant, purge it (operator route, and the automatic one with a short `SAASAPI_TENANT_PURGE_AFTER`): status `purged`, the tombstone still answers, `PATCH` gives `409 tenant_purged`, its data (keys, sprouts, recipes, bus account, OpenBao key) is gone, and a second tenant is untouched | S6 |
| D1 | core | Retention: with short settings, the recipe-audit sweep removes day-prefixes older than the limit and keeps newer ones; finished action batches and provisioning jobs past `SAASAPI_TERMINAL_ROW_RETENTION` are pruned, pending ones kept; the log retention CronJob/Fluent Bit config is present with the configured period | U4 |
| U1 | core | Sealed payloads: facts and cook step events arrive sealed (`s2f.facts`, step events) and `jobs.follow` shows the steps; a forged plaintext facts or step message is refused; after a forged plaintext message a sprout shows "needs upgrade" until its next sealed report | U3 |
| N1 | core, standalone only | `PUT /pki/putnkey` without a proof of possession is refused and does not revoke an NKey; with a valid proof it is accepted. The hosted stack does not serve the route: the case SKIPs there with that reason | T6 (L12) |
| RB1 | core | The per-cook render budget on the real stack: a recipe whose templates exceed the budget fails with the budget error and leaves the sprout unchanged; one inside it applies. Not only against `fakestack` | S4 |

Rules for every case:

- Use the existing harness (`harness.Settings`, `Fleet`, tenant helpers, the
  no-silent-green rule in `uatreport`). Each ID is a test function with the
  tier prefix, so `uatreport` selects it.
- Each case cleans up what it made (tenants, recipes, keys) and tolerates a
  re-run on a rig that already ran it.
- Each case passes against `harness/fakestack`, which gets the minimum new
  behaviour to do so. The fake proves plumbing only; the README says so.
- Windows: cases that run on a Linux sprout also run on Windows when a
  Windows sprout exists; otherwise the rig's existing SKIP lines apply.
- Updating the plan table: add the six rows to section 4h of
  `docs/claude-code-parallel-build-plan.md`; `go test ./uat/tests/...` must
  pass `TestCatalogueMatchesPlan`.

`uat/lite/README.md` refresh (same PR):

- Replace "Status: the rig has never been run" with a status that is true on
  the day of the PR: what was validated by script review and the stubbed
  tests (counts from `bash uat/lite/tests/test_lite.sh`), and that the first
  real run is the owner's on WSL2, with the open points that remain
  unverified (kind node image digest, systemd containers on Docker Desktop
  and WSL2, published ports).
- Examples use the latest release candidate tag, written as `<latest rc>`
  with one worked example, not a tag that is already stale.
- State what the rig now proves: the S to U items by case ID (B1, E1, D1,
  U1, N1 (standalone only), RB1), and what it still cannot (Windows,
  network separation, HA, reboot of a kernel).
- Prerequisites: owner steps for a release the rig can install (chart
  packages public and linked, signed release, see `docs/RELEASE-SOP.md`),
  and the WSL2 notes already in the file kept.
- Update the test count line (`293 checks`) from the real output.

Done when:

- `go test ./...` and `go vet -tags uat ./uat/...` pass; `uat/tests/run.sh`
  against `fakestack` runs all six new cases green; `bash uat/lite/tests/test_lite.sh`
  passes; `scripts/status/rollup.py --check` passes.
- Every new case names the finding or unit it covers in its doc comment and
  in `catalogue.tsv`.
- Status fragment added; `docs/security-findings-status.md` evidence columns
  gain the UAT case ID for L12 and the S/U items where they apply.

Needs: none.

## Brief corrections (W1, 2026-10-19)

Decided by the order of `docs/briefs/ORCHESTRATOR.md` rule 6 (the Owner
decisions above, then the code on main, then the smallest change), and
built that way:

- **IDs.** B1, E1, D1, U1, N1 and RB1 were free in the catalogue and in
  section 4h, and are used as proposed. N1's tier is `core` (the catalogue
  takes tier names only); "standalone only" is in its title and is a
  written SKIP on the hosted stack.
- **Scope.** The cases need to look inside the core hub, which the harness
  could not: `uat/hub/core/acceptance.sh` (with its container-backed test)
  does it, next to `bind-tenant.sh` and with the same arguments. D1's log
  retention needs log shipping, which the UAT core hub had off: turning it
  on took the log bucket, two users with the chart's own policies and their
  Secrets (`rustfs-setup.sh`, `install.sh` for Versity Gateway and external
  S3, `lib/common.sh`) and a RustFS ingress rule for the shipper's pods
  (`chart/`), beyond the values files. `uat/lite` has no values of its own:
  the rig installs with `uat/hub/core`'s.
- **Short settings have floors.** saasapi accepts no
  `SAASAPI_TENANT_PURGE_AFTER` under 1h and no
  `SAASAPI_TERMINAL_ROW_RETENTION` under 24h; its prune runs at start and
  then hourly; farmer's recipe audit sweep runs at start and then at most
  once in 23 hours. So the UAT values set those floors (and a backlog cap
  of 20, and one day of recipe audit and log retention), and the cases move
  their own rows' times back past them (`acceptance.sh backdate`), restart
  saasapi, clear the sweep's last run, and plant dated audit records and
  log objects, instead of waiting hours or days. `values/values-ha.yaml`
  puts the backlog cap back to 2000: the ha tier's traffic loops would
  otherwise hit it.
- **D1, "pending ones kept".** A provisioning job can't be held pending
  from outside (farmer answers within seconds). D1 checks the prune keeps a
  batch with a pending item and an offboarded tenant's finished jobs (the
  tombstone's record, the documented keep rule), and removes a finished
  batch, a live tenant's finished jobs and an expired key.
- **E1, "bus account".** A purge keeps the tenant's locked-out Account JWT
  in the accounts bucket by design (`internal/tenantpurge` KeepRoots: a bus
  node started empty must load the tenant locked out). E1 checks that every
  sprout identity is gone (`pki_nkeys`, `sprout_user_jwt`, the sprout JWT
  objects, box keys) with the KV keypair and both Transit keys, and that the
  tombstone's rows stay.
- **U1, "jobs.follow shows the steps".** `jobs.follow` is the CLI's leg,
  whose users belong to farmer's own organization and may view only its
  sprouts; the run's sprouts are in SaaS tenants. U1 checks the steps where
  farmer records them from the sealed events (`farmer.job_status` and the
  job's objects); the forged messages come from a sprout U1 enrols and
  connects through Envoy, the way a sprout does.
- **RB1, the product bug.** On a deployed stack a cook farmer refuses for
  its render budget never fails its batch item: `internal/natsapi/cook.go`
  answers `dispatched` with a jid and only logs the refusal, so saasapi
  keeps the item `running` for ever. RB1 asserts the budget error (farmer's
  log) and the untouched sprout, then fails on the item, with that reason.
  Recorded as P29 (status fragment `zz-W1.md`); product code is not changed
  here. P29 has since been fixed (status fragment `zzz-P29.md`): the item
  fails with `job_refused`, and RB1 asserts that.
- **The lite README.** The rig had already run once (the owner, WSL2 and
  Docker Desktop, `v0.1.0-rc.14`, `docs/status/days/2026-10-19/rig-rc14.md`),
  so its status says that rather than "the first real run is the owner's":
  the systemd containers on Docker Desktop and the published ports worked
  there. The kind node image is pinned to the digest kind v0.30.0 lists.
  `test_lite.sh` has 304 checks.

## W2: the two failures of the rc.15 rig run

The owner's rig run on `v0.1.0-rc.15` (2026-10-20, core 65 pass, 2 fail,
4 skip) was the first of the W1 cases on a deployed stack. Both failures
were bugs in the cases; W2 fixes them in the tests, the harness, the fake
stack and `acceptance.sh`, and changes no product code.

- **E1.** `acceptance.sh inventory` counted every table `WHERE tenant_id =`,
  but `saas.tenants` and `farmer.pki_tenants` are keyed by `id` (the
  migrations; the tombstone's tables come from `internal/tenantpurge`
  KeepTables). It now counts each table by its key column from one explicit
  map (`tenant_key`), refuses a table not in it (`farmer.job_leases` is
  keyed by name, `pushall:<tenant_id>`) and keeps the
  `^(farmer|saas)\.[a-z_]+$` check. `harness.InventoryKeyColumns` is the
  same map; its test checks it against the migrations, the script and the
  fake stack.
- **RB1.** The parts used `printf "%09000d" 0`, over farmer's printf width
  cap of 1000 (`internal/cook` maxFormatWidth), so the upload was refused
  (`recipe_template_failed`). Each part now ranges nine times over
  `split (printf "%01000d" 0) ""` (`harness.RB1PartRecipe`), and
  `TestRB1RecipesAgainstCook` renders the exact recipes with the cook
  package's limits, without a cluster.
- `uat/lite/run.sh` takes every tier `uat/tests/run.sh` takes, so
  `uat/lite/run.sh resilience` runs L1 to L3.

### Brief corrections (W2, 2026-10-20)

- **RB1's arithmetic.** The task said "about 9009 iterations per render".
  The range guard charges each range the length of its list
  (`internal/cook` farmercook.go), so a part is exactly 9 x 1000 = 9000
  iterations a render: under the 10000 per render
  (`DefaultMaxRangeIterations`); a cook renders each recipe twice, so seven
  parts cost 126000, over the per-cook 100000
  (`DefaultCookMaxRangeIterations`), and two cost 36000, inside it. The
  unit test checks each number with the real limits, including that a
  per-render cap of 8999 refuses a part.
- **The unit table.** `docs/briefs/ORCHESTRATOR.md` had no W2 row; one is
  added (needs W1).

## W3: the null object_store output (Run 2, rc.15)

Run 2 of the Azure UAT gate (`hub_nodes` 1, `v0.1.0-rc.15`) applied
`uat/tofu` (53 resources added) and then failed with `Error: Output
"object_store" not found`. `uat/tofu/outputs.tf` gives `object_store` the
value `null` when the core hub has one node, and OpenTofu 1.11 does not
store a null output in state, so `tofu output -json object_store` fails.
Only `hub_nodes` 1 is affected. W3 changes the workflow and its scripts, no
product code.

- The workflow's two output steps are `uat/scripts/tofu-outputs.sh outputs
  STATE` and `tofu-outputs.sh credentials STATE SECRETS`. `object_store` is
  read from the full `tofu output -json` (piped into jq, never written; it
  holds the sensitive outputs too) as `.object_store.value // null`, so a
  missing or null output writes `null` and the HA run's writes the object;
  anything else fails the step.
- The other outputs cannot be null: `uat` and `ha_node_names` are objects
  for every node count, `ssh_private_key` and `windows_admin_password` are
  generated strings, and `object_store_account_key` is `""` in the
  single-node run (stored). They keep the direct call, which fails loudly if
  one is missing. The account key is read only when `object_store.json` is
  an object, and an empty key there fails the step.
- `uat/scripts/tests/scripts_test.sh` runs the script against a stub
  `tofu` (`tests/stubs/tofu`) whose state has no `object_store`, a null one
  and the HA run's object.

### Brief corrections (W3, 2026-10-20)

- **The unit table.** `docs/briefs/ORCHESTRATOR.md` had no W3 row and this
  file no W3 section; both are added (needs none).
- **Where the test reads the steps.** The task asked for the fake `tofu` to
  drive the workflow's steps. The steps' shell moved into
  `uat/scripts/tofu-outputs.sh` so the test runs exactly the code the
  workflow runs, rather than a copy of the YAML's `run:` blocks.
