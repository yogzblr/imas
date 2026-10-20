# Runbook: the next Azure runs (Run 2 and Run 3)

The owner's checklist for the two Azure runs of
`docs/briefs/H-azure-next-runs.md` (owner decisions of 2026-10-13), in this
order:

- **Run 2**, the single-node gate run again on current main, with the fleet
  update path on (unit R1; P20, P13, P1).
- **Run 3**, the HA run on 3 core and 3 DMZ k0s nodes with Versity Gateway
  over Azure Blob (units H1 to H5; P24, P23, the first half of P25).

`uat/README.md` is the reference for the gate itself (every input, every
step, the artifacts, keeping and cleaning up an environment); this page only
says what to do for these two runs and what each one proves. The one-time
prerequisites of `uat/README.md` ("Prerequisites (once)": resource
providers, the OIDC identity, the AlmaLinux terms, the bootstrap stack, the
`uat` and `uat-janitor` environments) were done for run 38107290465
(2026-10-11) and stay done.

## 1. Before the first dispatch (owner)

Do these in order; each is a setting or an action only the owner can take.

1. **GPG secrets on the `goreleaser` environment only.** `GPG_PRIVATE_KEY`
   and `GPG_PASSPHRASE` exist as secrets of the GitHub environment
   `goreleaser` and **not** at repository level (Settings, Secrets and
   variables, Actions: the Repository secrets list must not have them;
   delete any copy there). Policy of 2026-10-11, `docs/RELEASING.md`
   "Settings": a repository secret is readable by any workflow pushed on a
   branch and skips the reviewer gate, and every sprout trusts this key for
   updates (P22). The `goreleaser` environment keeps its required reviewer
   and its deployment rules for `v*` tags and `main`.
2. **A ruleset for `v*` tags.** Settings, Rules, Rulesets, New tag ruleset:
   target `refs/tags/v*`, enforcement Active, rules **Restrict updates**
   and **Restrict deletions** (a tag never moves, `docs/RELEASING.md`
   "Tags"), and **Restrict creations** with the owner as the only bypass
   actor, so that only the owner can create a release tag. Release tags are
   what `release.yml` signs with the GPG key and what `publish-packages.yml`
   and the cosign identities accept (`refs/tags/v*`).
3. **Two signed release candidates cut from main after this runbook's PR.**
   The latest published release, `v0.1.0-rc.13` (2026-10-11), was tagged
   before P22 (GPG-signed `checksums.txt`, #203 and #205) and before the
   stateless build, so it can be neither the release under test nor L5's
   starting point: L5's earlier sprout must already verify the GPG
   signature. Cut, with the [First release checklist](../docs/RELEASING.md#first-release-checklist):
   - `v0.1.0-rc.14` on main (the earlier release for L4 and L5);
   - `v0.1.0-rc.15` on a **later** commit of main (any later merge, such as
     the day's status roll-up), so that each tag is the only one on its
     commit.

   For each: approve the Release run (`goreleaser` environment), check
   that the draft release has `checksums.txt`, `checksums.txt.sig` and
   `checksums.txt.sigstore.json`, publish it, and run **Publish packages**
   by hand for the tag (a pre-release is not published automatically; the
   Windows sprouts and L4/L5's package installs read Buildkite, and the
   farmer chart that carries the stamped `files/sprout-release.json` goes
   to GHCR). The gate's first step refuses a `release_tag` (or
   `upgrade_from_tag`) without a published release and refuses a
   `release_tag` without `checksums.txt.sig`; the core install refuses a
   chart without the stamped release for the tag.
4. **Quota in the region** (default `centralindia`; `uat/README.md`
   "Prerequisites", step 4). Request, before Run 3:

   | Quota | Run 2 (`hub_nodes` 1) | Run 3 (`hub_nodes` 3) | Request |
   |---|---|---|---|
   | Standard DSv5 Family vCPUs | 10 (D8s_v5 + D2s_v5) | 18 (3 × D4s_v5 + 3 × D2s_v5) | **18** |
   | The B2ls_v2 family (`az vm list-skus --location <region> --size Standard_B2ls_v2 --query [0].family`) | 12 (6 sprouts) | 12 | **12** |
   | Total Regional vCPUs | 22 | 30 | **30** |

   Check with `az vm list-usage --location <region> -o table`. One run at a
   time (the workflow's concurrency group), so the two runs never add up.
   The apply step checks the quota first (`uat/tofu/quota-check.sh`) and
   fails, naming the family and the limit to request, before anything is
   created. Standard_D4s_v5 must be offered to the subscription in the
   region's zones (the same check fails when it is not).
5. **The security review stays owed.** `dispatch_flags` turns
   `SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED` and `IMAS_SELF_UPDATE_ENABLED` on
   **in the UAT only**. They stay off everywhere else until the human
   security review (P3) has covered the flagged work, the GPG fleet update
   path (P22) and R1 included. A green Run 2 is evidence for that review,
   not a substitute for it.

## 2. Run 2: the single-node gate with the fleet update path on

Actions, **UAT gate**, Run workflow on `main`, with:

| Input | Value |
|---|---|
| `release_tag` | `v0.1.0-rc.15` |
| `region` | `centralindia` (or the region with the quota) |
| `keep_hours` | `0` |
| `tier` | `all` |
| `upgrade_from_tag` | `v0.1.0-rc.14` |
| `scenarios` | empty |
| `hub_nodes` | `1` |
| `dispatch_flags` | `true` |
| `ingress_cidrs` | empty (Bastion 443, core 443 and Envoy open to the Internet, W5) |

```sh
gh workflow run uat.yml --ref main -f release_tag=v0.1.0-rc.15 -f region=centralindia \
  -f keep_hours=0 -f tier=all -f upgrade_from_tag=v0.1.0-rc.14 -f hub_nodes=1 -f dispatch_flags=true
```

Approve the `uat` deployment when GitHub asks. Expect about an hour before
the first test and up to a few hours in all; the job stops at 350 minutes
(the test step at 180). If a failure needs a look, dispatch again with
`keep_hours` 2 and the same inputs (`uat/README.md`, "Keeping an
environment for debugging").

**What Run 2 proves** when green, on the build after P21 and P22 (the
earlier green run, 38107290465, was before both):

- The release's published charts, images and packages install and run on
  single-node k0s, with the stateless farmer (2 replicas, OpenBao-held
  signing keys on raft, the sprout JWT bucket, the bus loader reading the
  accounts bucket on RustFS from the DMZ); every scoped object store
  credential reaches exactly its buckets (`validate-object-store.sh`).
- The sprout release of `v0.1.0-rc.15` registers through saasapi's operator
  plane with its GPG-signed `checksums.txt` and signature (`finish.sh` fails
  otherwise; P20 option C).
- `dispatch_flags` turns the two fleet update flags on through the chart
  values, and the core check sees them on the Deployments (`check.sh`).
- L5: a Linux sprout on `v0.1.0-rc.14` updates itself to `v0.1.0-rc.15`,
  verifying the signature against `/etc/imas/fleet-signing-keys.asc` (the
  repository's `gpg-public-key.asc`), and refuses a scratch release whose
  `checksums.txt` was altered, with nothing downloaded and the release under
  test still running. L4: the package upgrade from `v0.1.0-rc.14` keeps the
  sprout's identity and configuration.
- Every other scenario of the catalogue on Ubuntu 24.04, AlmaLinux 9 and
  Windows Server 2022 in two tenants: tenants, keys, enrolment through
  Envoy, commands, recipes, ingredients, resilience, auth and isolation,
  with `check.sh`'s refusals asserting saasapi's error code (P13).
- The S, T and U fixes on the deployed stack (brief W1, tier core, with the
  core hub's short settings of `uat/hub/core/values/farmer-uat.yaml` and log
  shipping on): the action backlog cap (B1), tenant erasure by the operator
  route and by the retention sweeper (E1), retention of recipe audit days,
  log days and terminal rows (D1), sealed facts and step events and the
  "needs upgrade" mark (U1), the per-cook render budget (RB1). N1 skips,
  saying so: the hosted stack serves no `PUT /pki/putnkey`. RB1's
  over-budget cook fails with `job_refused` (P29).

It does **not** prove high availability (one node per hub, one pod of each
stateful service): that is Run 3. The `ha` scenarios HA1 to HA6 are in tier
`all` and skip on this run, each saying it needs `hub_nodes` 3.

## 3. Run 3: the HA run

After Run 2 is green (it is the plumbing pass; owner, 2026-10-11) and the
quota of section 1 is granted:

| Input | Value |
|---|---|
| `release_tag` | `v0.1.0-rc.15` (the release Run 2 passed) |
| `region` | the region with the 18 DSv5 vCPU |
| `keep_hours` | `0` |
| `tier` | `ha` |
| `upgrade_from_tag` | empty |
| `scenarios` | empty |
| `hub_nodes` | `3` |
| `dispatch_flags` | `false` |

```sh
gh workflow run uat.yml --ref main -f release_tag=v0.1.0-rc.15 -f region=centralindia \
  -f keep_hours=0 -f tier=ha -f hub_nodes=3 -f dispatch_flags=false
```

`hub_nodes` 3 makes `uat/tofu` build `uat-core-1` to `uat-core-3`
(Standard_D4s_v5) and `uat-dmz-1` to `uat-dmz-3` (Standard_D2s_v5) over the
region's zones, each hub behind an internal and a public Standard load
balancer, and the run's Azure Blob account for Versity Gateway; both hubs
install with their `values-ha.yaml` overlay (`uat/README.md`, "HA run").
`check-inputs.sh` refuses `tier=ha` with `hub_nodes` 1. After the tests,
whatever their result, the workflow starts every HA hub VM again before the
destroy.

**What Run 3 proves** when green, against the owner's error windows (brief,
Owner decisions):

- **Pod kill** (HA1): with farmer, saasapi, Envoy and each bus pod deleted
  in turn under load (an API call every second, an enrolment every 10 s, a
  `cmd.run` every 5 s), no call fails after 3 client retries (1 s, 2 s,
  4 s), every sprout is connected again within 30 s, no two enrolments share
  a sprout JWT or box key, and a restarted bus pod's loader is ready only
  holding every account.
- **Node stop** (HA2): with a core node and then a DMZ node stopped, the
  API, a new enrolment and a `cmd.run` are served by other pods within
  60 s and every sprout of the stopped node's bus node is back within
  60 s; PXC, OpenBao and Valkey serve on two replicas; the node and all its
  pods are Ready within 10 minutes of its start, with nothing created during
  the stop lost.
- **Rolling restart** (HA3), **empty bus node** (HA4), **lost account
  event** (HA5) and **parallel enrolment at Envoy's admitted rate across
  the farmer replicas** (HA6), which together with the core tier cover the
  design tests T1 to T8 (`uat/tests/README.md`, "The ha tier").
- Versity Gateway over Azure Blob serves farmer, saasapi and the bus loader
  with the scoped users of design D22 (`validate-object-store.sh` in the core
  install), the first half of P25 on a real backend.

Known single points, not stopped by HA2 by design: Valkey's primary (the
pinned chart has no Sentinel) and Keycloak (UAT only). A stateful pod on a
stopped node stays down until the node returns while its replicas serve
(local volumes; owner, 2026-10-11).

## 4. Reading the report

Each run uploads `uat-report-<run_id>` and `uat-outputs-<run_id>`; the job
summary prints `summary.txt` (`uat/README.md`, "Artifacts" and "Reading a
failure").

1. **Which step failed.** A step before **Tests** failing means there is no
   report: it is an environment, chart, package or script problem, and the
   step names the directory that owns it (`uat/README.md`, "The pieces").
   For these runs the new failure points are: `Check inputs and variables`
   (a tag without a published release or `checksums.txt.sig`), `tofu
   apply` (quota, with the numbers), `Core hub` (a chart without the
   stamped sprout release; `validate-object-store.sh`; on Run 3 the Versity
   bucket Job or OpenBao's three voters) and `Core hub, second half` (the
   registration Job failed, or the operator API does not hold the release
   with its signature).
2. **`summary.txt`**: one line per scenario, OS and tenant, `PASS`, `FAIL`
   or `SKIP`, with seconds and the first failure message, which starts with
   `[<id> os=<os> tenant=<n> vm=<vm> step=<step>]`. Read failures across
   lines with the pattern table in `uat/README.md` ("Reading a failure").
3. **Skips** are never silent: each has its reason, and `run.sh` fails the
   run if a scenario of the tier neither ran nor skipped with a reason.
   Expected on Run 2: HA1 to HA6 (single node), L4 and L5 on the Windows
   sprouts, X5 and the by-design skips listed in `uat/tests/README.md`
   ("What can't be asserted from outside"). Expected on Run 3: none of HA1
   to HA6. **An L5 skip on Run 2 is a failed run**: it means `dispatch_flags`
   or `upgrade_from_tag` was not set.
4. **The HA scenarios' timings.** Each HA scenario logs, in `events.json`
   (the `go test -json` stream; `junit.xml` has the same per test), the
   moments it acted (pod deleted, VM stopped and started), each loop's
   calls, retries, failures and longest outage, and each sprout's longest
   outage. A window failure names the loop or sprout and its outage against
   the window (30 s or 60 s).
5. **Outputs.** `uat-outputs-<run_id>` has `run.json` (the inputs),
   `uat.json`, `ha_node_names.json` and `object_store.json` (Run 3), the
   endpoints file, `core.json` (with Run 3's `topology`) and the enrolment
   files; no credential is ever uploaded.

## 5. After the runs

Record each run in a status fragment (`docs/status/README.md`): the run id,
the commit and tag, the result, and what it closes. A green Run 2 moves P20
and P13 towards closing and is the re-run P1 waits for; a green Run 3 is
the validation P24 and P23 wait for, and the Azure check of the Versity
half of P25. A failed run is fixed forward, as tags never move: cut the next
release candidate (`v0.1.0-rc.16`, and so on) from main with the fix,
publish it as in section 1, and dispatch again with `release_tag` set to
that new candidate and the other inputs unchanged. Run 2 keeps
`v0.1.0-rc.14` as `upgrade_from_tag` (any published release cut after P22
will do, as long as it is older than `release_tag`); Run 3 uses the
candidate Run 2 passed.
