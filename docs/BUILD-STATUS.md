# Build Status

The live tracker. It records what is **pending**, not what is done. Everything
built before 2026-10-09 is accepted as done (see "Baseline"), and its full
history is in [`archive/BUILD-STATUS-2026-10-09.md`](archive/BUILD-STATUS-2026-10-09.md):
Waves 0 to 7, the Azure UAT gate briefs UAT.1 to UAT.13 and the ledger of PRs
#36 to #165. Documents that cite a BUILD-STATUS section or "Open item N" from
before this date mean that archive.

Set up 2026-10-09 against `main` at `5336942` (PR #165). Nothing was re-run for
this file; its facts come from the archived file, the PR descriptions and the
owner's local-rig runs on `v0.1.0-rc.9`.

**How to keep it.** One row per pending item, with a next step. Add a row when
new work starts or a gap is found; delete the row when the work has merged and
(where it matters) been verified. Do not copy a PR ledger here: `git log` and
the PR list are the ledger. Date every change in the change log at the end.

## Baseline (accepted as done)

Accepted by the owner on 2026-10-09 as built, merged and green in CI:

| Area | Contents |
|---|---|
| Waves 0 to 2, the ongoing batch, post-rebrand work | Core platform: bus, farmer, sprout, Envoy, SaaS API scaffold, JWT auth, ingredients (Linux and Windows), Helm charts, M.1 to M.4 |
| Waves 4 and 5 | Fleet updates, DB migrations, clean-ups, GoReleaser release flow |
| Wave 7 and the open-item briefs | Security fixes and payload sealing (J.1 to J.5), SEC.0 to SEC.7d, REC.1, SH.1, SCALE.1 to SCALE.3, PKI.1, PKI.2, LIC.1, REL.2, FIX.1 to FIX.6 |
| Azure UAT gate, built | UAT.1 to UAT.13: OpenTofu infrastructure, k0s hubs, tenants and enrolment, the acceptance suite, ingredient conformance cases, the local rig (`uat/lite`), GHCR charts, rig findings; RustFS as the UAT object store with a configurable S3 endpoint; the core install split into `install.sh` and `finish.sh` (PR #163) |

**What "accepted" does not mean.**
- "Merged" is reviewed and green in CI, not proven on real hosts. The local
  rig (kind plus systemd containers) has passed smoke (10 of 10) and core
  (58 passed, 0 failed, 3 skipped) on `v0.1.0-rc.9`; nothing has run in Azure
  or on Windows.
- Work whose brief carried "FLAG FOR SECURITY REVIEW" is **ready for review,
  not done or safe to merge** (`CLAUDE.md`) until the human review in P3 is
  recorded. Accepting it as built does not change that.

## Requirements still not Green

Of the 21 requirements in `docs/design/requirements.md`, 12 were Green and 9
Amber at the last full assessment (2026-10-05); none was Red. Only the Amber
ones are listed. The assessment has not been redone since the UAT work.

| # | Requirement | What turns it Green | Pending item |
|---|---|---|---|
| 1 | 1M endpoints | Load runs at 10k and 100k on a real cluster; PXC and Valkey failure tests | P5 |
| 3 | Windows and Unix | A Windows Server run (Server 2016 is the stated floor); nothing has installed the MSI | P9 |
| 7 | Horizontally scalable farmer | A load test; the 3-node bus has never run on a real cluster | P5 |
| 10 | NATS response under 300 ms | A latency measurement; only a 200-sprout smoke run exists | P5 |
| 13 | Backend on Kubernetes | The charts installed on a real cluster (the rig is kind, not production-shaped) | P1 |
| 14 | Payload encryption | The human security review, then the plaintext residuals | P3, P6 |
| 18 | Installers: yum, apt, zypper, MSI | apk, zypper and MSI installs on hosts (deb and rpm have installed on the rig's Ubuntu and AlmaLinux sprouts) | P9 |
| 20 | Fleet updates from the sprout's repo | The human review, the self-update cycle on published packages, B4 and B8 | P3, P4, P9 |
| 21 | Licensing | Decide on BSD-2-Clause, BSD-3-Clause, ISC and 0BSD and record them under item 21 | P8 |

## Pending items

Ordered by severity. **Severity is my assessment** from the reviews' own
ratings and from what each item blocks; the owner should re-rank it. IDs are
stable, so they do not run in order. RAG: **Red** = not started or a known gap
that defeats the purpose; **Amber** = built but unverified, or a gap that does
not defeat it.

### S1 Blocking

Two kinds. **S1a** stops the first Azure run. **S1b** is needed only before
fleet-update dispatch or self-update is turned on anywhere, which includes an
Azure run that sets `dispatch_flags` (the L4 and L5 self-update tests); a first
run with `dispatch_flags` off does not need it.

**S1a, before the first Azure run**

| ID | Item | RAG | Next step |
|---|---|---|---|
| P2 | **Prove PR #163 on a rig started from scratch** | Amber | `up.sh` now installs core, then the DMZ, then `finish.sh` (farmer and saasapi need the DMZ bus; the release-registration hook runs from `finish.sh` as a second `helm upgrade --reuse-values`). Unit tests pass (298) but `go test ./uat/...` could not run in the sandbox (Go 1.26), and no fresh-rig run exists. Run `down.sh`, then `up.sh --release-tag <tag>`, then smoke and core. Check that the second helm upgrade re-runs the other hooks cleanly. Do this before P1. |
| P1 | **Azure UAT gate: the run** | **Red** | Built and validated on the local rig only. Owner prerequisites in plan §4h: OIDC identity, the `uat` and `uat-janitor` environments, quota, image terms. Then dispatch `uat.yml`. Only Azure can run X3 (network separation), the Windows lines and the janitor's teardown. Validation order in `uat/README.md`: local rig, a kept smoke run, `v0.1.0-rc.3` failing, a good tag passing. |

**S1b, before dispatch or self-update is enabled**

| ID | Item | RAG | Next step |
|---|---|---|---|
| P18 | **Fleet signing keyring is a placeholder** (L5) | Amber | `packaging/etc/fleet-signing-keys.json` is `{}` and is packaged (`.goreleaser.yaml`). A sprout with an empty keyring fails closed, so self-update cannot work on a released package until the real keyring is installed; nothing in the release hooks, CI or `packaging/test` (`check-package-contents.sh` checks that the path exists, `test-windows-packaging.sh` that the MSI holds the repo's bytes) checks the content with `ParseKeyring`. Add that check to the release, and install the real keyring before the Azure self-update cycle (L4, L5 tests). Related and open: L3 (the staging directory and keyring are checked by mode, not owner or symlink), L6, L7, I4, I5. |
| P3 | **Human security review of the flagged work** | Amber | Nothing records one. Scope: the sealing work (J.1 to J.5), SEC.* fixes, SCALE.2, PKI.1 and PKI.2, SH.1, REC.1, FIX.1 to FIX.5, UAT.1 and UAT.6 (Azure credentials), UAT.12 and UAT.13 (a sprout publish permission and its startup path). Record who, when, scope and what was accepted. **Owed before `SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED` or `IMAS_SELF_UPDATE_ENABLED` is turned on anywhere.** |

**Pre-flight for the first Azure run** (it costs money, so do the free checks first):
1. P2, a from-scratch rig run of PR #163.
2. Checked 2026-10-09: `actionlint` and `yamllint -s` pass on `uat.yml` and `uat-janitor.yml`; the `uat/lite` (298) and `uat/k0s` (221) shell tests pass. **Not run in the sandbox** (no Go 1.26.9, no OpenTofu): `go test ./uat/...`, `tofu validate` and `tofu test`, and the `uat/enroll` suite. Run them where the toolchains exist.
3. Cheap fixes worth landing first because a confusing failure inside a paid run is expensive: #138 (P14) and the `TestItemErrorCodesDocumented` blind spot (P17).
4. Run order in `uat/README.md`: a kept smoke run first, then `v0.1.0-rc.3` failing, then a good tag passing, with `dispatch_flags` off and `keep_hours` 0 unless debugging.
5. Cost controls in place before dispatching: the subscription budget in the bootstrap stack, the `uat-janitor` environment, quota for the Windows VM size, image terms, the OIDC identity.
6. Expect the first run to find something the rig cannot: Bastion tunnels, k0s over the tunnels, private DNS and NSG rules, WinRM and the Windows MSI have never run anywhere.

### S2 High

A gap that defeats a requirement, or that a review rated High. Does not block the Azure run.

| ID | Item | RAG | Next step |
|---|---|---|---|
| P5 | **Scale and latency** | **Red** | SCALE.1 to SCALE.3 are built, the harness has only made its 200-sprout smoke run (`docs/loadtest.md`). Run 10k and 100k on a real cluster; add the PXC and Valkey failure tests the scale plan's Phase 3 asks for; core still pushes Accounts to one bus node without waiting for all; farmer's per-tenant bus connection gives up after 30 failed attempts (`cmd/farmer/main.go`, `maxFarmerReconnect`) and has no `ClosedHandler`, so that tenant stays unreachable from the replica until restart (confirmed in code 2026-10-09); a sprout whose User JWT is refused twice stays offline until restarted; decide the resolver mode. |
| P6 | **Plaintext inside TLS** | Amber | Facts (ranked High by review 2026-10), cook step events, `test.ping`, the rotate trigger, log shipping and the join event are not sealed. Facts feed the rollout gate and recipe templates. Decide what to seal and when. |

### S3 Medium

Real defects, risks or untested paths. Schedule them; some should land before the Azure run if cheap (#138, the P17 doc-test gap).

| ID | Item | RAG | Next step |
|---|---|---|---|
| P14 | **Open issues** | Amber | #138: **a real bug, still in the code**: `imas auth privkey --output json` calls `os.Exit(1)` after printing the status even on success (`cmd/imas/cmd/auth.go`). #139: mostly handled: `restrictConfig` (`cmd/imas/cmd/configperm.go`, UAT.9) tightens the file to 0600 and the default directory to 0700 after load and after every write, and before the private key is put in; left: the loader still creates the file 0644 first, for a moment, and the issue is open. #142: the test exists (`internal/natsapi/shell_test.go:505`); the flake is unfixed and not reproduced. Likely causes from reading it: the spy capture is read right after `run.wait` with no `waitFor` (`:513`); `env.sp.Active() != 0` is an immediate read (`:541`), where the sibling test uses `waitFor`; `fastShellTimings` allows only 1 s of peer silence, which a loaded CI runner can exceed; it relies on global state (`ShellTracker`, sprout policy, replay guard) and so on there being no `t.Parallel`. #138 has no test. |
| P4 | **Review findings still open** | Amber | Re-checked against `main` on 2026-10-09 (code read, no tests run). Medium and the named Lows: **B4** open (the recipe include count is capped, `maxRecipeIncludes`, and rendered bytes are capped, `MaxRenderedRecipeBytes` 1 MiB, but no per-cook render budget; decide if wanted); **B5/M6** partly handled (a tenant lock-out waits for a strictly newer `iat`, `waitPastIssuedAt`, `internal/pki/tenant.go`; other Account re-signs do not, not checked); **B6** accepted (owner, PR #97); **B8** open. The deferred Lows and Infos are listed below under "Review findings re-checked": 23 of 31 are still open or partly fixed. |
| P12 | **Heartbeat leftovers (UAT.12, UAT.13)** | Amber | **No test covers the CONNECT/DISCONNECT race** (`handleConnect` is a plain `SET`, `handleDisconnect` a plain `DEL`, on different subscriptions). A DISCONNECT from an old connection processed after the new CONNECT still deletes the presence key until the next heartbeat; the two-key refresh script assumes standalone Valkey and is tested only on miniredis (no hash-slot, real-Valkey or cluster test); `tools/loadtest/fixture.go` keeps its own copy of the sprout permissions, so load-test sprouts send no heartbeats; UAT.13 checks only the heartbeat grant, and a sprout needs a restart to use a JWT a later refresh changes. |
| P17 | **Test gaps found while re-checking** | Amber | Tests that would pass while the problem exists: `TestItemErrorCodesDocumented` (`internal/saasapi/sweeper_actions_test.go:386`) iterates only `actionErrorMessages`, so it cannot see that `self_update_disabled` is missing from `docs/api/saasapi.md` and the OpenAPI enum (P11). Nothing tests `maxRecipeIncludes` (`internal/cook/helpers.go`), and the include cost is excepted from the whole-render bound (B4; up to 256 includes times 1 MiB). CI and packaging pass `-tags no_self_update`, which no Go file reads (I5), and `packaging/test` checks that the keyring file is present and identical, not that it is not `{}` (L5). No test for farmer's redial after the NATS client gives up (P5), for the heartbeat race or a Valkey Cluster (P12), for `imas auth privkey --output json` (P14), or for the other re-signs that can tie on `iat` (P4). Tests that pin the current behaviour and must change with any fix: L9 (`internal/natsapi/sprout_action_test.go:365`, `internal/saasapi/sprout_actions_test.go:296`), L12 (`internal/api/handlers/pki_test.go:267`), L20 (`internal/ingredients/sdb/openbao/rotation_test.go:175`), L22 (`internal/pki/tenantbox_test.go:362`), I1, I2. |
| P9 | **Untried installs and platforms** | Amber | The Windows MSI on a host (Server 2016 floor), apk and zypper installs on hosts, enrolment through Envoy against a real backend with the DMZ/core network separated, the self-update cycle per OS on published packages, FU.2's index reader against a real registry, zypper's downgrade skip. All fall to the Azure run (P1) except where a package manager is cheap to try on its own (apk, zypper). deb and rpm installs are exercised by the rig. |
| P8 | **Licence record** | Amber | Record BSD-2-Clause, BSD-3-Clause, ISC and 0BSD under `requirements.md` item 21, or drop the modules (every such module and its binaries are in `DEPENDENCIES.md`; questions in PR #73). |

### S4 Low

Leftovers, documentation and tidying.

| ID | Item | RAG | Next step |
|---|---|---|---|
| P13 | **UAT harness and rig leftovers** | Amber | `check.sh`'s "must refuse" checks cannot tell a wrong-reason 401 from the right one; `dispatch_flags` does not turn on fleet-update dispatch or self-update, so L5 fails ("not registered") unless they are enabled by hand; RustFS: `minio` names remain in manifests and values, no pod-restart soak, `external` S3 mode never run against a gateway (for example Versity), digests not pinned for Keycloak and Envoy; `validate-rustfs.sh` is not in the repo; UAT.7 conformance cases and the Windows lines have not run on the rig. |
| P10 | **Release and chart publishing leftovers** | Amber | Set the GHCR chart packages public after the first push and check they are linked to the repo; chart signatures are not pinned to tag runs; a second push of an existing tag moves it (PR #149). `uat/README.md` item 8 and `ansible/roles/imas_sprout/defaults/main.yml` still point charts at Buildkite. `snapshot.yml` last ran 2026-09-26 and failed before REL.1/REL.2 rewrote it. |
| P11 | **Carry-over follow-ups from PRs #62 to #113** | Amber | Not triaged. The archive's Open item 10 lists them. The larger ones: add `self_update_disabled` to `docs/api/saasapi.md` and the OpenAPI item enum (saasapi still records it as `internal_error`; confirmed in `internal/saasapi/sprout_actions.go`, 2026-10-09), move that code and two others into `internal/controlplane`, the web UI's `boxpub`, and REC.1's audit and deprovision follow-ups. |
| P15 | **User documentation** | Amber | Refresh `docs/INSTALL.md`, `docs-site/` and `docs/api/saasapi.md` **after the Azure run**, once install order and Windows and network behaviour are proven. Not yet reviewed for any of the UAT changes; a grep found no stale mention of `PrivateTmp` or MinIO in them. |
| P16 | **Nice-to-haves** | Amber | Unowned: run the Keycloak JWKS harness somewhere with Docker, a key-rotation scheduler, a CERT-In and DPDP review. |

### Planned work (not a defect)

| ID | Item | RAG | Next step |
|---|---|---|---|
| P7 | **SaaS API §1.7** (caller API keys, teams, webhooks, billing and metering) | **Red** | Never designed. Needs a design pass before any build. |

## Review findings re-checked (2026-10-09)

The deferred Lows and Infos of `docs/security-review-2026-10.md` (and Info
I1, I2, I6 of `-b`) were re-read against the code on `main` by a read-only
pass: code only, no builds, no tests (tests may cover some of these). 31 were
checked. **Fixed or accepted, no longer tracked:** L25 (plaintext never
accepted for `cmd.run` and `cook`), I11 (route mTLS on the general CA, accepted
in the review), -b I6 (URL redaction), -b I1 (by design), -b I2 (holds).
**Still open or partly fixed (the rest), by theme.** Suggested order within the Lows: P18 first, then deprovision and identity (L10, L11), the OpenBao client (L17 to L19, L21), the bus (L12 to L14), sealing (L22 to L24), the rest.

| Theme | Findings (review rating) | State |
|---|---|---|
| **Before dispatch is enabled** | **L5** (Low) is now P18 (S1). L3 (Low): the staging directory and keyring are checked by mode, not owner or symlink (`internal/fleetsign/keyring.go`, `selfupdate.go`). L6 (Low): one tenant can clear the shared manifest cache. L7 (Low, docs): the signer/saasapi split is still described as a barrier. I4, I5 (Info): loose bounds on a hostile repository; stale `artifact_url` and `no_self_update` text. | Open |
| **Deprovision and identity** | L10 (Low), **partly fixed** (the `/files/` middleware refuses a deleted tenant, SEC.7c; `SproutIDAndTenantForNKey`, `reissueExistingIdentity` and the sealed refresh path do not). L11 (Low): a failed re-check leaves a deprovisioned tenant live, no retry or periodic relock. I6 (Info): removed CLI admin keys are never revoked. I7 (Info): NKey lookup over a non-unique index, and a database error spends a join-token use. I8, I9 (Info): an Account JWT file that is missing or undecodable is re-minted without its revocations; `PushAllAccounts` after a PVC restore pushes without re-syncing them. I10 (Info), mitigated: `JobRef` has no tenant, callers pass it. | Open |
| **OpenBao client** | L17 (Low): redirects carry the token and body to any host. L18 (Low): the login client can pick up an ambient `BAO_NAMESPACE`. L19 (Low), **partly fixed** (the sprout rejects non-2xx; farmer's `send` does not, so a 3xx can report `written=true`). L20 (Low): a cached token survives certificate rotation. L21 (Low): an `sdb://openbao` ref can reach any path (no `..` check). I2 (Info): `http://` addresses accepted. I3 (Info, docs). | Open |
| **Bus and cluster** | L12 (Low): unauthenticated `PUT /pki/putnkey` can reject legacy sprouts. L13 (Low): the bus logs at Trace and Debug (`internal/pki/nats.go`, `cmd/farmerbus/main.go`); whether that logs payloads was not confirmed. L14 (Low): a single-node bus serves before its SYS JWT; the SaaS API user JWT has no `exp`. L15 (Low): the fence counts any routed peer; cluster size comes from local config (a partial-mesh check exists; whether it covers a 3-to-5 scale-up was not decided). L16 (Low): a future-dated Account `iat` survives cleanup. | Open |
| **Sealing** | L22 (Low): deleting a severing tenant-key version rejoins the chain. L23 (Low): the continuity proof has no freshness check. L24 (Low, design): the tenant pin is trust-on-first-use against the DMZ Envoy. | Open |
| **Other** | L9 (Low): `cmd.run` stdout and stderr are still sent on the unsealed `internal.*` bus, and saasapi reads only the exit code. I1 (Info): the rollout lease is compared in the application clock; a non-UTC `loc` only warns. I12 (Info): no body limit on `/v1/enroll`, and the directory is not fsynced after the atomic write. | Open |

**Test coverage of the open findings (tests read 2026-10-09; none run).**
No open finding has a test proving it fixed. The rest by state:
- **Partly covered:** L3 (mode bits only, not owner or symlink), L5 (a sprout with an empty keyring fails closed, but the package is not checked), L6 (the size bound, not that other tenants' entries survive a `clear`), L10 (the `/files/` middleware, not the enroll-replay, `reissueExistingIdentity` or sealed-refresh paths), L11 (many provision/deprovision interleavings, not a failed re-check or a redelivered provision), L15 (partial mesh, not a 3-to-5 scale-up), L18 (the static-token path, not the Kubernetes login client), L24 (a mismatch after the pin, not a substituted first response), I4 (the zstd window, not the index and package caps), I9 (a fresh bus, not a restore from older JWTs).
- **Tests pin the current behaviour:** L9, L12, L20, L22, I1, I2 (see P17).
- **No test at all:** L7, L13 (the test turns Trace and Debug off itself), L14, L16, L17, L19, L21, L23, I3, I5, I6, I7, I8, I10, I12.
- **Fixed, with tests:** L25 (`internal/ingredients/cmd/sealed_test.go`; no matching test was found for `internal/cook/sealed.go`), -b I6 (`internal/ingredients/selfupdate/pkgmeta_test.go`).

## In flight

No pull requests are open (checked 2026-10-09).

## Decisions in force

- **PrivateTmp stays off** on the sprout units (owner, 2026-10-09, option A). A
  UAT-only drop-in or restoring it with test changes are not planned.
- **UAT object store is RustFS** (Apache-2.0), pinned by digest; MinIO (AGPL-3.0)
  is not used and its licence exception is withdrawn (`requirements.md` item 21).
  The S3 endpoint is the `object_store` setting in the endpoints file.
- **Sealed only, no downgrade:** a sprout with no box key is refused, not
  downgraded (owner, 2026-10-04).
- **B6 accepted:** forged "no responders" on `internal.sprout.action` (owner, PR #97).
- **Azure, OpenTofu, two single-node k0s hubs and six tenant VMs, Bastion-only
  management** for the UAT gate (owner, 2026-10-06).

## Releases

Pre-releases `v0.1.0-rc.1` to `-rc.9` exist; `rc.4` was the first good one and
`rc.9` (2026-10-09) is the current one on the rig. No stable release has been cut.

## Change log

- 2026-10-09: reset. The old BUILD-STATUS (Waves 0 to 7, UAT briefs, PR ledger
  #36 to #165) moved to `archive/BUILD-STATUS-2026-10-09.md`; this file now
  tracks pending items only.
- 2026-10-09: pending items re-checked against the code. P4, P5, P11 and P14 updated with what the code shows; "Review findings re-checked" added (31 Lows and Infos).
- 2026-10-09: tests read for the open findings; P12 and P14 updated, P17 (test gaps) added.
- 2026-10-09: pending items re-ordered by severity (S1 to S4); P18 split out of the review findings (L5).
- 2026-10-09: S1 split into S1a (before the first Azure run) and S1b (before dispatch or self-update); pre-flight list for the first Azure run added.
