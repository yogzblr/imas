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
