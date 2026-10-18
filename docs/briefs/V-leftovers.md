# Leftovers before the Azure run (V1 to V3)

Read `docs/briefs/ORCHESTRATOR.md` first: its session prompt (zero open items,
repo-wide search, brief errors decided by a fixed order) applies to every unit.
These units close the Low and Info items that no earlier batch covered:
`docs/security-review-2026-10.md` (L16, I1, I8, I9, I12), BUILD-STATUS P10, P11
and P14, and the stale findings table. Line numbers in the reviews have drifted:
find each place by name and check on main that the finding still holds. A
finding that no longer holds gets a test that pins the good behaviour and a
line under "Brief corrections" (and counts as closed).

The three units touch different files and run at the same time.

Owner decisions (2026-10-18, final):

- **V1.** Fix L16, I8, I9, I12 and I1 as below.
- **V2.** Fix the release and chart publishing leftovers (P10) in the
  workflows and docs. Package visibility on GHCR cannot be set by the
  workflow's token, so the workflow checks it and the release notes say how to
  set it (owner step).
- **V3.** Triage P11 and close what is code-only and bounded. The web UI
  submodule items are out of scope (the submodule is empty on main). The
  findings table moves out of `docs/BUILD-STATUS.md` into its own document.
- Not in this batch, by decision: the RustFS pod-restart soak, UAT.7 and the
  Windows lines (they need the Azure run), the Keycloak JWKS harness (needs
  Docker), the tenant key rotation scheduler and the CERT-In/DPDP review
  (P16, unowned; separate features).

## V1: Account JWT integrity, enrol limits, clock (L16, I8, I9, I12, I1)

Scope: `cmd/farmerbus` (fence), `internal/accountrank`, `internal/pki`
(`tenant.go`, `jwtauth.go`, `pushall.go`), `internal/api/handlers/enroll.go`,
`internal/pki/enrollclient.go`, `internal/saasapi` and `cmd/saasapi` (clock),
`internal/config`, charts and docs as needed.

- **L16.** Wherever Accounts are ranked or merged (the fence, the loader, the
  accounts bucket reader, `accountrank.Rank`), a JWT whose `iat` is more than
  the skew window (5 minutes) ahead of now is rejected and logged, and never
  wins over a later push. Test: an `iat` in the year 3000 does not beat a
  current JWT, in the fence and in the loader. Check whether the bus still
  holds any signing seed after P21; if it does, say so in the PR and in
  `docs/design/imas-openbao-signing-design.md` as an accepted residual. Do not
  build pre-signed bus JWTs.
- **I8.** If an Account or SYS JWT file is missing or undecodable, minting does
  not proceed with an empty revocation list: it rebuilds the revocations from the
  database first (the same logic as `syncTenantSprouts`), and on a database error
  it fails closed with an error that names the tenant. Cover
  `ensureTenantAccountMaterial` and `ensureNatsAuth` (or whatever P21 left of
  them). Test: delete the file, mint, and check a revoked sprout stays revoked.
- **I9.** `PushAllAccounts` runs `syncTenantSprouts` for each tenant before it
  pushes, so a restore from an older backup does not re-admit revoked sprouts.
  Test with a stale JWT and a revoked sprout.
- **I12.** `/v1/enroll` limits the body (64 KiB, a documented constant, 413 on
  excess, same style as `maxRefreshRequestBytes`); `writeFileAtomic` fsyncs the
  directory after the rename; the stale comment in `pushall.go` is corrected.
- **I1.** The rollout lease is compared in one clock: the database's. Where that
  is not possible, farmer and saasapi refuse to start when the MySQL DSN `loc`
  is not UTC, with a message naming the setting (today they only warn). Update the
  chart default and docs. Test both.

## V2: release and chart publishing (P10)

Scope: `.github/workflows` (`release.yml`, `publish-packages.yml`,
`snapshot.yml`), `.goreleaser.yaml`, `uat/README.md`,
`ansible/roles/imas_sprout/defaults/main.yml`, release docs.

- **GHCR packages.** After the chart push, the workflow verifies anonymously that
  each chart can be pulled (an unauthenticated `helm pull` or `oras manifest
  fetch`) and that its package is linked to the repository, and fails with a
  message that says what the owner must do (set the package public, link it to
  the repo) if not. The release docs list that owner step.
- **Chart signatures.** Chart signatures are verified with a certificate identity
  pinned to this repository's release workflow at a `refs/tags/v*` ref (not a
  loose regex); the verification command in the docs and in any script (`uat/`,
  Ansible) uses the pinned identity. Test the identity string with a script test.
- **Tag moves.** A second push of an existing tag cannot move a published
  release: `release.yml` fails when a release for that tag already exists and the
  tag points at another commit, with a message. Document how to cut a new rc
  instead of moving a tag.
- **Buildkite.** `uat/README.md` item 8 and the `imas_sprout` role defaults point
  charts and packages at GHCR/GitHub, like the rest. Repo-wide search for
  "buildkite" and fix every live reference (history in `docs/status/` stays).
- **`snapshot.yml`.** Repair it so it runs on `workflow_dispatch` and passes
  against what `release.yml` now does (REL.1/REL.2), checked with `actionlint`
  and a local `goreleaser release --snapshot --clean` in the session; it does
  not publish anything.

## V3: triage, issues and the findings table (P11, P14)

Scope: `docs/`, small code moves named below, GitHub issues.

- **P11.** Find the carry-over list (the archive's "Open item 10" in
  `docs/` history, `docs/claude-code-parallel-build-plan.md` and the BUILD-STATUS
  archive). For each follow-up decide, on main: done already (say where), or do
  it now (code-only and bounded: for example moving `self_update_disabled` and
  the two other codes into `internal/controlplane`, and REC.1's audit and
  deprovision follow-ups if S6 and T4 did not cover them), or out of scope by the
  owner decision above (web UI items). Do the "do it now" ones. Write the result
  as a table in the findings document.
- **P14.** Verify and close issues #138, #139 and #142 with a comment naming
  the PR that fixed each (`gh api repos/yogzblr/imas/issues/<n>` with
  `state=closed`), after checking the fix is on main with its test.
- **Findings table.** Create `docs/security-findings-status.md`: one row per
  finding of `docs/security-review-2026-10.md` and `-b.md` (every L, I, B, M, H
  that is not Info-only noise) with the state on main today (fixed in unit or PR,
  accepted with the reason, or open) and the test that pins it. Verify each row by
  reading the code on main, not from earlier notes. The old "Review findings
  re-checked" section of `docs/BUILD-STATUS.md` is replaced by a one-line pointer
  to the new document (this PR is allowed that one edit to BUILD-STATUS; the P4
  and P17 items also change through the status fragment).
- **P17 leftovers.** After the batches S, T and U, list in the findings document
  which of the "tests that pin current behaviour" are now changed, and which gaps
  remain; fix any remaining gap that is a missing test.
