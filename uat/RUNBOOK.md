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
   bucket Job or OpenBao's three voters) and `Core hub, second half` (farmer
   or saasapi not Ready within 1200 s: "The first core install takes up to
   about 10 minutes" below; or the
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

### The first core install takes up to about 10 minutes until P30 lands

**Symptom.** `Core hub, second half` fails with `deployment
"imas-core-farmer" exceeded its progress deadline` (0 of 2 available), or
with `deployment/imas-core-farmer in imas-core did not become ready within
1200s`, on a clean first install; the farmer pods may turn Ready seconds
later.

**Evidence (UAT Run 2 #5, 2026-10-21, rc.15).** The farmer Deployment had
the API's default progress deadline (600 s) and the chart's startup probe
(`/health` every 5 s, 60 failures: 300 s). The first farmer container
(started about 05:14:28Z) wrote the two Account JWTs at 05:14:30, could not
announce them (`nats: no servers available`: the DMZ bus turns Ready only
once its loader holds every Account), logged nothing more until 05:16:39
(the SYS listener connected; the bus loader's `initial load complete, 2
accounts` was at 05:16:29), and still answered 503 on `/health` until
kubelet killed it at 05:19:28. The second container was Ready 5 s after it
started (05:19:34), seconds after the workflow gave up. The DMZ side was
healthy; Envoy's JWKS fetch from farmer failed until farmer's API was up,
then recovered. The bus's `TLS handshake error: EOF` every 20 s from
10.244.0.1 is a TCP probe on the TLS port: noise.

**What the UAT does now (W7).** Only UAT files, no product code (P30 is the
product fix: farmer ready within seconds of reaching the bus, and the bus
loader polling fast during its initial load). `values/farmer-uat.yaml`
gives farmer's startup probe 120 failures (10 minutes);
`uat/hub/core/install.sh` raises farmer's and saasapi's
`progressDeadlineSeconds` to 3600 as soon as helm creates them (the chart
has no value for it; the deadline runs from then, through the DMZ install,
before farmer can reach the bus); `finish.sh` and `acceptance.sh restart`
wait 1200 s for each rollout, and `uat/hub/dmz/install.sh` waits up to 20 minutes
(`--timeout`, default `20m`). Worst case expected: the first container
killed after 10 minutes and its successor Ready in seconds, inside
`finish.sh`'s 20.

**Reading the next run.** On a timeout `finish.sh` prints, before failing,
in this order: `kubectl get pods -o wide` of `imas-core`; `kubectl describe`
of both Deployments and their pods (the events are at the end of each:
startup probe failures, restarts, image pulls); the last 40 lines of each
farmer and saasapi container, and of its run before a restart; the DMZ pods and the
last 40 lines of each bus pod's `farmerbus` and `loader` containers.

- Farmer logs stop after `announcing ... reconciled Accounts: ... no servers
  available`, the loader shows `initial load complete` a few minutes later,
  and the startup probe events count to 120: the slow first start this
  entry is about; with P30 not yet in the release, re-run.
- A restarted farmer whose second run is Ready in seconds, but the rollout
  still failed: the progress deadline was not raised (`install.sh` logs
  `deployment/imas-core-farmer: progressDeadlineSeconds 3600 (W7)`; check
  `kubectl -n imas-core get deploy imas-core-farmer -o
  jsonpath='{.spec.progressDeadlineSeconds}'`).
- The loader never reports its initial load, or farmer never connects:
  not this entry. Read the loader's lines (accounts bucket credential,
  object store reach) and the DMZ check.

### All tunnels hang or go UNREACHABLE after about an hour

**Symptom.** Everything over the tunnels works for a long while, then every
host fails at once: Windows tasks hit WinRM read timeouts (300 s), Linux
tasks go UNREACHABLE, `kubectl` hangs. Most likely cause: **a stale Azure
login and the tunnels opened on it** (W6). The runner's az session is a
GitHub OIDC login, which cannot renew itself once its access token expires
(about an hour); an `az network bastion tunnel` started earlier then stops
opening new connections (a hang, not a refusal), while connections already
open keep working.

**Evidence (UAT Run 2, 2026-10-20).** Azure login (OIDC) 17:23:54Z; tofu
apply 17:24:02 for 20 minutes; tunnels opened 17:44:24; k0s 17:44:46;
"Tenants and enrolment" 18:13:58. The Linux hosts had completed 26 tasks
over the tunnels when, at about 18:19 (login about 55 minutes old, tunnels
about 35), both Windows hosts read-timed-out after 300 s on "Download the
imas-sprout installer" and all four Linux hosts went UNREACHABLE on the
next SSH task (`imas_verify`'s config file read, behind `no_log`). The
earlier failed run broke the same way, at the same age of its login. The
workflow logged in again before the tests and the destroy, but not before
enrolment. Ruled out on the live environment: the VMs (idle, WinRM and
imas-sprout running), the network (github.com and the exact MSI fetched in
about a second from the VM), the feed, the module and the Terraform (no
difference), and the allowlist of W5. The cause is inferred from the
timing; the mechanism is not proven.

**What the workflow does now (W6).** Every phase from the tunnels on starts
with `uat/access/session.sh phase`: it logs in again (`az-relogin.sh`, the
same OIDC exchange as `azure/login`) and reopens every tunnel, on its old port when free (a moved kube port is
rewritten in the kubeconfigs; `enroll.sh` writes its inventory again)
when the login or the tunnels are 10 minutes old
(`UAT_SESSION_REFRESH_AFTER_MIN`, default `UAT_REFRESH_AFTER_MIN`; 15
before W10), then checks the ages that result: it
refuses to start a phase if either is still older than 40
(`UAT_SESSION_MAX_AGE_MIN`), which can only happen when no refresh was
made (a 41-minute-old login is refreshed first and the phase starts), and
logs `<phase>: azure login age Xm, tunnels age Ym`. Enrolment and the tests always start on a fresh login and fresh
tunnels, each probed end to end, and refresh again between their own
Ansible runs (`enroll.sh`) and top-level tests (`run.sh`), never during one.
`imas_verify` checks the connection before its `no_log` read, so an
unreachable host is named with its error. On a failure the step "Azure
login and tunnel ages (on failure)" prints both ages, whether each
tunnel's process still runs, and the end of each tunnel's log.

**Maximum safe phase length.** About 40 minutes for one uninterrupted
unit of work (a workflow step between two boundaries, one Ansible run, one
top-level test): the observed failure came 55 to 60 minutes after the
login, and a unit can start on a login up to 15 minutes old. **During the
tests this no longer holds on its own** (W10, "The test channel after Run 2
#6" below): Run 2 #6's tunnels went stale about 20 minutes after they
opened, inside one top-level test, so a supervisor now renews them during
the tests. For scale: in
Run 2, k0s, both hubs, core's second half and the DMZ check took 29 minutes
together. A single unit that runs longer and opens tunnel connections late
is not covered; the per-test times in `events.json` and the step times show
whether one does.

**Reading the next run.**

- The failing step's log has `azure login age Xm, tunnels age Ym` at its
  start and, from the probe, `probe FAILED: <vm> <kind> tunnel
  (127.0.0.1:<port>) is stale or dead ... tunnel age Ym`. A failure with
  both ages well under 40 minutes refutes the stale-login cause; look at
  the tunnel logs the failure step printed (an az error there names the
  real one).
- `refusing to start: azure login age ...` means a phase began on an old
  login without a refresh: a bug in the wiring
  (`uat/scripts/workflow_test.go` checks it).
- `refresh: the Azure login failed` or `reopening the tunnels failed`:
  the OIDC exchange or the Bastion refused; the step's log has az's error.

**Checking by hand on a live (kept) environment.** From a laptop with a
normal `az login` (it renews itself), open a fresh tunnel and test it the
way the probe does:

```sh
uat/access/tunnels.sh open /tmp/uat-$RUN.json /tmp/uat-$RUN-access
jq . /tmp/uat-$RUN-access/access.json
ssh-keyscan -T 15 -p <ssh_port of a Linux sprout> 127.0.0.1           # a host key line: alive
curl -sk -m 20 -o /dev/null -w '%{http_code}\n' https://127.0.0.1:<winrm_port>/wsman   # 401 or 405: alive
```

Both answering on a fresh tunnel while the runner's tunnels hung points at
the runner's login and tunnels, not the VMs (in Run 2 a fresh laptop tunnel
ran the same `win_get_url` in 6 s).

### The test channel: what Run 2 (rc.16) taught, and what to read now (W8)

**Run 2 (run 39709416839, rc.16)** was the first run to reach the tests:
207 pass, 101 fail, 60 skip, with every core acceptance scenario (T, K, S,
C, R, U1, B1, E1, RB1, X3) passing on AlmaLinux, Ubuntu and Windows. About
85 of the failures were the test channel, not the product: `vmctl.sh run`
was `az vm run-command invoke`, 30 to 60 s a call and one execution at a
time per VM, so a Linux ingredient case took 100 to 175 s; the tests'
fixed 165-minute budget ran out with about 70 cases unrun ("the run ended
before the case ran on this sprout"), a Windows run-command that hung for
15 minutes left the extension busy for the calls after it ("(Conflict) Run
command extension execution is in progress"), and both Windows L1 reboots
failed with the VM running because the run-command probe never answered.
L5 was not hung: it was the last test and got the 2m19s left of the budget
(`panic: test timed out after 2m19s`). D1's log retention Job could not
reach RustFS (`connection refused` to its Service for over 10 minutes), and
nothing in the artifacts said why.

**What the gate does now (W8).**

- `vmctl.sh` runs commands over the Bastion tunnels (SSH on Linux, WinRM on
  Windows), one call per VM at a time, each call with its own 120 s
  timeout, retrying only what never started, and fails a VM fast after 3
  channel failures in a row (`uat/access/README.md`, "The channel"). A
  reboot waits for the power state and then SSH or WinRM, never a
  run-command. (W10 changed the last two: a strike only after a probe and
  a reopen, a re-probe instead of the 30-minute hold, and a reboot wait
  that recreates the tunnel; next section.)
- The tests' budget is what the job has left, less 60 minutes for the
  diagnostics, the report and the destroy (at most 280 minutes); the Tests
  step prints it (`tests budget: ...`), and `run.sh` prints the budget left
  before each top-level test.
- `TestIngredients` times one trivial host call per VM first and logs an
  estimate per VM (`ingredients estimate: <vm>: <n> cases, <n> host calls
  x <measured time> + <n> cooks = <total>`), then the longest against the time
  left, with a WARNING when it cannot fit. The cook time is an estimate
  (`IMAS_UAT_COOK_ESTIMATE`, 15 s).
- After a failed top-level test, `run.sh` collects both hubs' state
  (`uat/scripts/diagnostics.sh kube`) into
  `report/diagnostics/<Test>/`; after a failed Tests step, the workflow's
  "Diagnostics (on a test failure)" step collects it again with the
  sprouts' service logs and Azure's run-command state
  (`report/diagnostics/after-the-tests/`). Both are redacted and uploaded
  with the report.

**Reading the next run.**

1. `build.log` in `uat-report-<run_id>` is now the whole test log: compile
   errors, everything the tests printed, `run.sh`'s messages (budgets,
   diagnostics), the session refreshes and the summary. (In Run 2 it held
   only compile errors, so it was empty.)
2. `junit.xml`: a failed case's body has everything its test printed
   (steps, `cook ...: job <jid>, item <status>`, each step's status and
   changes), and its time is the case's own (`case time on this sprout`),
   so an ingredient line no longer shows 0.0 s on any OS. The summary's
   SECONDS column uses the same time.
3. Channel lines in the test output: `<vm>: ran over ssh (127.0.0.1:N) in
   Ns` (the per-call time), `run-command is busy ... (Conflict); retry`,
   `<vm> is now marked dead: 3 channel failures in a row (last: ...)` and,
   on the cases after it, `<vm> is marked dead after ...`. A dead VM's
   cases all fail with that line: read the first failure it names, then
   `diagnostics/after-the-tests/sprouts/<vm>.txt` and `azure/<vm>.json`.
4. `diagnostics/<Test>/<hub>/`: `pods.txt`, `jobs.txt`, `events.txt`,
   `top.txt`, `endpoints.txt` (the RustFS Service's endpoints in full) and
   `pods/<ns>.<pod>.txt` (describe, logs, logs `--previous`) for RustFS,
   failed Jobs and unhealthy pods. For a D1 like Run 2's: an empty RustFS
   endpoint list with the pod restarting (`--previous`, `OOMKilled` in
   describe, the node's memory in `top.txt`) is a restart or OOM; a pod
   Running but not Ready is a readiness problem; endpoints that name
   another pod or port are a wrong Service.
5. `diagnostics/<Test>/core/keycloak/<ns>.<pod>.txt`: the Keycloak log's
   login errors and brute-force lines from the whole log, then its last
   lines. A token refused with `invalid_grant Invalid user credentials`
   for a tenant user whose password worked earlier is a temporary lockout
   when the log shows `user_temporarily_disabled`. The harness waits that
   out (up to 150 s, and logs `uat harness: Keycloak refused ...`). The
   `LOGIN_ERROR` lines name the user and error of each failed login; the
   brute-force protector's debug lines (`new num failures`, `quick login,
   set min wait seconds`) carry no user, only the failure count and
   timing, so match them to those lines by time.

### The test channel after Run 2 #6 (rc.20): tunnels that go stale inside a test (W10)

**Run 2 #6 (run 40106684046, `v0.1.0-rc.20`, tier `ingredients`, single
node)**: 193 pass, 114 fail, 60 skip, nothing missing. The local rig passes
the same code (smoke 10/0, core 68/0/4, ingredients 126/0/111), so the
failures were the Azure channel, the harness and one Windows ingredient.
What the job log (from 16:59:43Z; GitHub keeps only its last 5000 lines)
and the summary show:

- **The tunnels went stale inside one test.** `TestIngredients` ran
  17:04:22Z to 17:19:32Z as one top-level test; the login and tunnels were
  last refreshed at about 16:52. The first channel failures were t1-win's
  (`winrm_exec.py: could not open a WinRM shell on 127.0.0.1:20106 ...
  Read timed out. (read timeout=30)`), then t1-alma's and t1-ubuntu's
  (`Connection timed out during banner exchange`), at tunnel ages of about
  22 to 25 minutes. The next refresh, at 17:21:33, found `azure login age
  29m, tunnels age 28m`. A stale tunnel keeps accepting on its local port
  and hangs every new connection. **No tenant 2 VM failed** although its
  tunnels were just as old: the tenant 1 tunnels had carried far more
  connections (every case runs on tenant 1; only tenant-2 cases on tenant 2),
  so the use one `az network bastion tunnel` process has carried is as
  likely a factor as its age. Both are met by the same remedy below.
- **The dead mark never recovered.** t1-win, t1-alma and t1-ubuntu were
  marked dead at 17:18:51 (3 failures in a row) for a fixed 1800 s; about
  100 cases then failed on the mark in under a second, among them L4
  (ubuntu, alma) and L5 (ubuntu) **after** the 17:21:33 refresh had reopened
  every tunnel (`not trying again for 1521s`).
- **The Windows L1 reboots** both failed after 659.5 s and 661.2 s. The
  summary shows only `vmctl.sh restart t1-win exited 255: vmctl.sh:
  restarting t1-win` because a summary line keeps only the first line of a
  multi-line message (the rest was in `build.log`, which was lost, below).
  The time is `az vm restart` (about a minute) plus the guest wait's 600 s
  over the WinRM tunnel opened before the reboot, which never answered,
  while the Linux reboots were back in 50 to 74 s. Ten minutes later, on
  tunnels the 16:52 refresh had reopened, both Windows sprouts served
  ingredient cases. The tunnel, not the VM, was what did not come back.
- **I.win_firewall.rule_present** failed in test mode on t1-win:
  `netsh.exe: exit status 1; stdout: No rules match the specified
  criteria.`, netsh's normal "no such rule". The ingredient took the exit
  code as a failure (fixed: exit 1 of `show rule` is "absent"). The report
  said only `job_failed`: the harness read the job record over the channel,
  t1-win was already marked dead, and the read failed silently.
- **No `build.log`.** "Collect the report and outputs" removed it:
  `matches: (^|[^A-Za-z0-9_-])eyJ...` (a JWT). `az-relogin.sh` printed
  `::add-mask::<OIDC token>`, which GitHub masks in the job log, and
  `run.sh` copied the session refresh's output into `build.log`, where the
  token stayed in clear. The scanner did its job; the file was the leak.
- The farmer logged `failed to connect to NATS bus ... closed before it
  connected` at ERROR, retrying forever, for tenants the tests had
  offboarded.

**What the gate does now (W10).**

| Where | What |
|---|---|
| `session.sh supervise` | One supervisor per run, started by the Tests step, stopped before the tunnels close. Every `UAT_SUPERVISE_INTERVAL` (60 s): renews the login when `REFRESH_AFTER` (`UAT_REFRESH_AFTER_MIN`, 10 minutes) old; takes the tunnels one at a time, oldest first, and reopens one that is `REFRESH_AFTER` old or fails its protocol probe, **on the same port**, then probes it; never under a running command (it holds every `vmctl.sh` slot of the VM, or for a kube tunnel waits until no connection is open on its port); re-probes every dead VM every `VMCTL_REPROBE_SECONDS` (120) and clears its mark when the tunnel answers. Its log: `diagnostics/channel/supervisor.log` |
| `vmctl.sh`, before a command | Renews a login or the VM's tunnel past `REFRESH_AFTER` first |
| `vmctl.sh`, on a channel failure | One `CHANNEL ERROR` line stamped at the moment (epoch, UTC time, VM, kind, port, login age, tunnel age, the probe's verdict, the failure); the channel's state captured into `diagnostics/channel/`; the tunnel probed by its protocol and reopened when it does not answer; a call that certainly never started tried once more; only then a strike |
| `vmctl.sh`, dead VMs | After 3 strikes a call fails at once with `CHANNEL UNAVAILABLE`; no fixed hold: a call 120 s after the last failure or re-probe re-probes (and reopens) the tunnel and runs when it answers; every full refresh clears every mark |
| `vmctl.sh restart` | `az vm restart` (a run-command reboot when that fails), then up to `VMCTL_RESTART_WAIT_SECONDS` (600) for the power state, the protocol probe and a command, **recreating the tunnel on every failed probe**; a failure names its reason and the last probe's error |
| `vmctl.sh`, hardening | A counting semaphore per VM (`VMCTL_SLOTS_LINUX` 4, `VMCTL_SLOTS_WINDOWS` 2); one persistent SSH master per Linux VM (`ControlPersist` 300 s, `ServerAlive` 15 s x 4) and one pooled WinRM session per Windows VM (`winrm_exec.py --pool`, idle 300 s), so a call opens no new connection through the tunnel; setup and revert scripts get a 5-minute call timeout; the harness's backstop per call is 25 minutes |
| The harness | Checks the login's and the kube tunnels' ages before kubectl (`session.sh ensure kube` when due); a case the channel blocked is **`CHAN`**, apart from `FAIL`; a failed cook's failure line carries its failed steps' errors, read over the channel and, when the channel is down, through `az vm run-command`; the VM's side of a failure goes to `diagnostics/<vm>/` |
| The report | `CHAN` lines in `summary.txt` (with their count and a pointer to the diagnostics) and as `<error type="channel-unavailable">` in `junit.xml`; they fail the run like `FAIL` |
| `build.log` | Everything that goes into it is redacted (`uat/scripts/redact.sh`); `az-relogin.sh` prints its `::add-mask::` line only for the workflow's own steps (`AZ_RELOGIN_ADD_MASK=1`), never into a file; `collect-artifacts.sh` redacts the text logs on the way and always writes a `build.log` (one that says why, when the run wrote none) |
| The sprout | A failed step's error is logged at ERROR in its log, redacted like the job record (`Step <id> of job <jid> failed: ...`) |

**The knobs** (environment of the Tests step; the workflow sets
`UAT_REFRESH_AFTER_MIN`, `VMCTL_DIAG_DIR` and `AZ_RELOGIN_ADD_MASK`):

| Knob | Default | What |
|---|---|---|
| `UAT_REFRESH_AFTER_MIN` | 10 | REFRESH_AFTER: the supervisor's, `vmctl.sh`'s and the harness's age limit for the login and each tunnel; also the phase boundaries' default |
| `UAT_SUPERVISE_INTERVAL` | 60 s | Between the supervisor's rounds |
| `UAT_SUPERVISE_WAIT_SECONDS` | 30 s | How long a round waits for a VM's slots or a kube port's connections before leaving that tunnel for the next round |
| `UAT_SUPERVISE_PROBE` | 1 | 0: the supervisor reopens by age only, no probe each round |
| `UAT_PROBE_SSH_SECONDS`, `UAT_PROBE_HTTPS_SECONDS` | 5 s, 10 s | The protocol probe: the SSH banner; the WinRM (401 or 405 on `/wsman`) or Kubernetes (`/version`) HTTPS answer |
| `VMCTL_SLOTS_LINUX`, `VMCTL_SLOTS_WINDOWS` | 4, 2 | Calls at once per VM |
| `VMCTL_CONNECT_RETRIES` | 1 | Tries again of a call that never started, after the probe and any reopen |
| `VMCTL_DEAD_AFTER`, `VMCTL_REPROBE_SECONDS` | 3, 120 s | Strikes that mark a VM dead; how often it is re-probed |
| `VMCTL_RESTART_WAIT_SECONDS` | 600 s | The whole wait after a restart or start-vm |
| `VMCTL_SSH_PERSIST` | 300 s | An idle SSH master's life |
| `VMCTL_WINRM_POOL`, `VMCTL_WINRM_POOL_IDLE` | 1, 300 s | The pooled WinRM session per Windows VM (0: one per call), and an idle one's life |
| `VMCTL_CALL_TIMEOUT` | 120 s (setup and revert scripts 300 s) | One channel call |
| `IMAS_UAT_VMCTL_TIMEOUT` | 25 m | The harness's backstop on one `vmctl.sh` call |
| `IMAS_UAT_VM_DIAG_MAX` | 4 | `diagnostics/<vm>/` collections per VM (each a few run-command calls) |
| `VMCTL_DIAG_DIR` | `<report>/diagnostics` | Where a channel failure's capture goes |

**Reading the next run.**

1. `summary.txt`: `FAIL` lines are the product (or a test); `CHAN` lines
   did not test the product: the channel to their VM was down. A run with
   `CHAN` lines and no `FAIL` failed on the gate, not on the release.
2. `build.log`: search `CHANNEL ERROR` for each failure as it happened,
   with both ages and the probe's verdict, and the lines after it for the
   recovery (`reopening it on 127.0.0.1:<port>`, `after the reopen: ok
   ...`). `marked dead` and `the dead mark is cleared` bracket a dead
   period. A `CHANNEL ERROR` with `probe=ok` and young ages is not a stale
   tunnel: read the VM side (4).
3. `diagnostics/channel/<epoch>-<vm>-<kind>.txt` (the channel at that
   moment, before recovery): the tunnel's process (a `bastion tunnel` pid
   missing or a zombie), the listening ports (its port gone), the
   connections on its port by state (many `ESTAB` or `CLOSE-WAIT` on one
   tunnel: it carried too much; none: it hangs before the VM), and the end
   of its own log (an az error there names the cause).
   `diagnostics/channel/tunnels/<vm>-<kind>.log` is each tunnel's whole log
   with a line per reopen, `supervisor.log` every round's decisions.
4. `diagnostics/channel/<epoch>-<vm>-vm-side.txt` (through run-command):
   sshd's `MaxStartups` and `MaxSessions`, or WinRM's `MaxShellsPerUser`,
   `MaxConcurrentUsers` and `MaxConnections`, and the connections the VM
   sees on 22 or 5986: limits reached on the VM rather than in the tunnel.
5. `diagnostics/<vm>/<epoch>.txt` (through run-command, after a failed
   cook or a channel failure on that VM): the sprout service, the last 300
   lines of its log (fewer when they do not fit) and the failed jobs'
   records (`<joblogdir>/<jid>.jsonl`). The JUnit message and `build.log`
   carry the failed steps' errors too (`the job's failed steps: step "...":
   ...`).

**Re-dispatch** (after `v0.1.0-rc.21` is cut and published as in
section 1; the tests run from the checkout, so the channel fixes need no
release, but the win_firewall, win_certutil, sprout logging and farmer
fixes do):

| Input | Value |
|---|---|
| `release_tag` | `v0.1.0-rc.21` |
| `region` | `centralindia` |
| `keep_hours` | `0` |
| `tier` | `ingredients` |
| `upgrade_from_tag` | `v0.1.0-rc.20` (L4 and L5's earlier release) |
| `scenarios` | empty |
| `hub_nodes` | `1` |
| `dispatch_flags` | `true` (L5 runs; an L5 skip is a failed run) |
| `ingress_cidrs` | empty |

```sh
gh workflow run uat.yml --ref main -f release_tag=v0.1.0-rc.21 -f region=centralindia \
  -f keep_hours=0 -f tier=ingredients -f upgrade_from_tag=v0.1.0-rc.20 -f hub_nodes=1 -f dispatch_flags=true
```

Not verified anywhere but on Azure: that a reopened Bastion tunnel serves
again (the stubs model it), the WinRM and sshd limits' output, and the
Windows reboot's wait on a real WinRM listener. If `CHANNEL ERROR` lines
still appear with tunnels under 10 minutes old and `probe=fail`, the cause
is the tunnel's use, not its age: lower `UAT_REFRESH_AFTER_MIN` and read the
per-port connection counts.


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
