# UAT acceptance tests (UAT.5)

The Go acceptance suite of the Azure UAT gate
([plan section 4h](../../docs/claude-code-parallel-build-plan.md#4h-azure-uat-gate-uat1-to-uat8)).
It runs against a deployed stack from the runner, through the product's own
endpoints (saasapi, Keycloak, Envoy) and, for anything outside the platform,
through `uat/access/vmctl.sh`. It never calls Azure itself.

**Status: it has run once on Azure** (UAT run 38107290465, 2026-10-11, the
single-node run, before the stateless build), and its core tier on the local
rig (`uat/lite`, rc.14, 2026-10-19: 58 passed, 0 failed, 3 skipped). The `ha`
tier and L5 with the dispatch flags have not run on a real deployment yet:
Run 3 and Run 2 of `uat/RUNBOOK.md` are their first runs; the W1 cases (B1,
E1, D1, U1, N1, RB1, [below](#the-w1-cases-b1-e1-d1-u1-n1-rb1)) first run on
the owner's next rig run. It builds and vets with the `uat` tag, its helpers
have unit tests against fake servers, and the whole catalogue runs green
against the in-memory fake in `harness/fakestack`, which proves the plumbing
and nothing about the product.

## Layout

| Path | What |
|---|---|
| `*_test.go` (build tag `uat`) | the scenarios T1 to T6, K1 to K4, S1 to S6, C1 to C8, R1 to R6, X1 to X5 (tier core, the smoke ones named `TestSmoke`), B1, E1, D1, U1, N1 and RB1 (tier core, `hardening_test.go`, brief W1), L1 to L3 (tier resilience) and HA1 to HA6 (tier ha, `ha_test.go`) |
| `harness/` | the reusable helpers (no build tag; unit tested in `go test ./...`); the package comment is the interface |
| `harness/fakestack/`, `fakestack/` | an in-memory fake of the stack and a command that serves it with a material directory and a `vmctl.sh` |
| `uatreport/` | turns a tier and ids into a `-run` pattern, and test2json events into the summary, JUnit and the exit status |
| `catalogue.tsv` | the scenario catalogue (id, tiers, scenario, owning brief); a unit test keeps it equal to the plan's table |
| `run.sh` | the entry point |
| `ingredients/` | UAT.7's ingredient conformance runner (not this brief) |

## Running

```sh
IMAS_UAT_DIR=/path/to/material uat/tests/run.sh smoke
IMAS_UAT_DIR=/path/to/material uat/tests/run.sh core C2 X4      # two scenarios
IMAS_UAT_DIR=/path/to/material uat/tests/run.sh ingredients I.file.managed
```

Tiers: `smoke`, `core` (includes the smoke scenarios), `resilience`,
`ingredients`, `lifecycle`, `ha`, `all`. Ids must belong to the tier; ingredient ids
(`I.name.method`) go in a run of their own. Test functions are named
`Test<Tier><Id>_<What>` (`TestSmokeC1_CmdRunEverySprout`,
`TestCoreX4_CrossTenantDenied`, `TestResilienceL2_FarmerRestart`,
`TestHAHA1_PodKill`), so
`go test -tags uat -run '^TestCoreX4_' ./uat/tests` works too.

| Variable | Meaning |
|---|---|
| `IMAS_UAT_DIR` | required: the material directory below |
| `IMAS_UAT_VMCTL` | the `vmctl.sh` to use; else harness.json's `vmctl`; else `uat/access/vmctl.sh` |
| `IMAS_UAT_REPORT_DIR` | where the report goes (default `$IMAS_UAT_DIR/report`) |
| `IMAS_UAT_TIMEOUT` | `go test -timeout` (default: smoke 45m, core 4h, resilience and ha 3h, others 8h) |
| `IMAS_UAT_DMZ_KUBECONFIG` | the ha tier: the DMZ cluster's kubeconfig (the core one is `IMAS_UAT_CORE_KUBECONFIG`, below) |
| `IMAS_UAT_DMZ_CHART`, `IMAS_UAT_CORE_CHART` | the ha tier (HA3's `helm upgrade`): the nats chart uat/hub/dmz installed, and the farmer chart uat/hub/core installed (default `<state>/core/chart/farmer-<version>.tgz`) |
| `IMAS_UAT_CORE_CHECK` | the ha tier: `uat/hub/core/check.sh`, which HA3 runs after the upgrade (run.sh's default) |
| `IMAS_UAT_RELEASE_TAG` | optional: S1 then checks the installed package is this release |

`run.sh` builds the report tool and one test binary per package under
`uat/tests` with the `uat` tag, runs them, prints the tests' output as it
comes, then one summary line per scenario id, OS and tenant:

```
STATUS ID                     OS       TENANT  SECONDS  DETAIL
PASS   C1                     ubuntu   1           4.2
FAIL   C2                     windows  2          31.0  [C2 os=windows tenant=2 vm=t2-win step=check the item] FAIL: want failed command_failed exit_code 7, got ...
SKIP   X5                     -        -           0.0  a plaintext cmd.run or cook can only reach a sprout through the bus ...
```

The report directory gets `events.json` (go test -json), `summary.txt` and
`junit.xml`. **No silent green:** the run fails when no test of the tier
ran, when a catalogue scenario of the tier neither ran nor was skipped with
a written reason, when any skip has no reason, or when a package failed
outside a test (a build error, `TestMain`, a timeout). Every skip is listed
with its reason. A tier whose tests don't exist yet (lifecycle, until UAT.7)
fails.

## The material directory (`$IMAS_UAT_DIR`)

Written by the workflow (UAT.6) or the local rig (UAT.8) from what UAT.1,
UAT.3b and UAT.4 produce. Keep it out of git and out of uploaded artifacts:
it holds credentials. The harness never prints a password, secret, token or
join token.

**Owner decisions (2026-10-06):** "#132 writes keycloak.json (with
tenant_attribute), core.json, credentials.json; the harness calls
bind-tenant.sh once per tenant; #131 and #134 read that shape", then "UAT.4
binds tenants 1 and 2; harness binds only run-created tenants not in
core.json" and "bind-tenant.sh gains a create-user-and-bind mode for scratch
users (via kubectl exec); #134 uses it for T1, T4, T5; no admin API on the
edge." So the directory is normally uat/hub/core's state root, or a copy of
its outputs:

| File | Required | Content |
|---|---|---|
| `uat.json` | yes | `tofu output -json uat` (the Shared contract's shape; a `{"value": ...}` wrapper is accepted). `sprouts.<vm>.tenant` may be a number or a string. |
| `core.json`, or `core/out/core.json` | yes, unless `keycloak.json` says it all | uat/hub/core's (UAT.3b) non-secret outputs: `saasapi_url`, `ca_file`, `keycloak` (issuer, client_id, read_role, write_role), `users` (each with its tenant and roles), `tenants` (what `bind-tenant.sh` bound) and `sensitive_dir` |
| `credentials.json`, or `core/sensitive/credentials.json`, or `<sensitive_dir>/credentials.json` | with core.json | uat/hub/core's SENSITIVE file: `internal_auth_secret` (saasapi's `X-Internal-Auth`), `keycloak.client_secret` and `keycloak.passwords` per user |
| `keycloak.json`, or `core/sensitive/keycloak.json`, or `<sensitive_dir>/keycloak.json` | no (yes without core.json) | laid over what core.json gives, field by field; see below. uat/hub/core writes it in `core/sensitive` |
| `internal-auth-secret` | no | wins over credentials.json's `internal_auth_secret` |
| `uat-ca.pem` | no | the run's CA; else harness.json's `ca_file`; else core.json's `ca_file`; else the system roots |
| `harness.json` | no | overrides, below |
| `tenants.json` | no | `{"1": "t_...", "2": "t_..."}` (or `{"1": {"tenant_id": ...}}`): the tenants UAT.4 created, when keycloak.json doesn't carry them; core.json's `tenants` is the last fallback |
| `sprouts.json` | no | `{"t1-ubuntu": {"sprout_id": "ubuntu-01", "asset_id": "..."}}`; without it the sprout ID is read on the host from the sprout's gateway JWT (its `sprout_id` claim, never the token itself) and the asset ID is `uat-<run_id>-<vm>` |

From core.json, a user holding the write role is its tenant's admin
(`t1-admin`, `t2-admin`) and one holding only the read role its read only
user (`t1-reader`, `t2-reader`); the tenant attribute is `organization_id`,
which UAT.3b's realm maps to the `organization.id` claim.

**Binding the tenants.** UAT.4 binds tenants 1 and 2 with
`uat/hub/core/bind-tenant.sh`; the harness doesn't. Before any test it
checks that each tenant's admin token carries the tenant's ID as
`organization.id`, and stops the run, naming the tenant, if not.

**Users for tenants a test creates (T1, T4, T5).** The harness runs
bind-tenant.sh's scratch mode (PR #132):

```
bind-tenant.sh <kubeconfig> <endpoints.json> <state-dir> --scratch-user scratch-<random> admin <tenant_id>
```

It reads the JSON line the script prints (`username`, `tenant_id`, `role`,
`password_file`) and the password from that file, then gets the user's
tokens like any other user's. It needs the core kubeconfig
(`$IMAS_UAT_CORE_KUBECONFIG`) and the endpoints file (`$IMAS_UAT_ENDPOINTS`),
or harness.json's `bind_tenant`; the state directory defaults to the state
root core.json was found under, and the script to
`uat/hub/core/bind-tenant.sh` (`$IMAS_UAT_BIND_TENANT` overrides it). Without
them, and without a keycloak.json `admin` for the admin REST API, those
tests skip that part with the reason. uat/hub/core has no way to delete a
scratch user, so they stay in the realm (and in core.json's
`scratch_users`) until the run is torn down; the owner accepted that
(2026-10-06: "no scratch-user delete; accept").

`keycloak.json`:

```json
{
  "issuer": "https://uat<run_id>-core.<region>.cloudapp.azure.com/realms/imas-uat",
  "client_id": "imas-uat-tests",
  "client_secret": "optional, for a confidential client",
  "tenant_attribute": "organization_id",
  "admin": {"realm": "master", "client_id": "admin-cli", "username": "...", "password": "..."},
  "other_audience_client": {"client_id": "...", "client_secret": "optional"},
  "tenants": {
    "1": {"tenant_id": "t_...", "admin": {"username": "...", "password": "..."}, "readonly": {"username": "...", "password": "..."}},
    "2": {"tenant_id": "t_...", "admin": {"username": "...", "password": "..."}, "readonly": {"username": "...", "password": "..."}}
  }
}
```

Every field is optional when core.json is there; a field that is set wins
over core.json's. uat/hub/core's keycloak.json (PR #132, head 9ace6c7) has
this shape without `admin`, with `other_audience_client`
`imas-uat-other-audience`, and `tenants.<n>.tenant_id` once bind-tenant.sh
has bound the tenant.

What the suite assumes of the realm (UAT.3b):

- `client_id` allows the password grant ("direct access grants") and its
  tokens carry saasapi's audience (`SAASAPI_JWT_AUDIENCE`) and the
  `organization` claim with `id` equal to the user's tenant ID (saasapi reads
  `organization.id`, docs/api/saasapi.md).
- Each tenant's `admin` user holds `imas-recipes-read` and
  `imas-recipes-write`; its `readonly` user holds only the read role.
  Without a `readonly` user, R2 and part of X1 skip with that reason.
- `admin` (optional) can create and delete users in the test realm through
  the admin REST API, either the bootstrap admin (password grant in
  `master`) or a service account (`client_secret`, client credentials).
  UAT.3b's edge doesn't route the admin API (Keycloak is administered only
  through `kubectl exec`), so its keycloak.json has no `admin` and the
  harness never takes credentials.json's master admin for this; it uses
  bind-tenant.sh's scratch mode instead (above).
  `tenant_attribute` is the user attribute the realm maps to
  `organization.id` (for example a user attribute mapper with the claim name
  `organization.id`; on Keycloak 24 and later the attribute has to be in the
  realm's user profile, or unmanaged attributes enabled). T1, T4 and T5
  create tenants during the run, and saasapi only answers for a tenant to a
  token whose `organization.id` is its new ID, so they make a scratch user
  for it. Without `admin`, they skip with that reason.
- `other_audience_client` (optional) issues tokens without saasapi's
  audience, for X1's wrong-audience case; without it that case skips.
- An expired token for X1 is the tenant 1 admin token minted when the run
  starts; X1 waits for it to expire if it hasn't (up to 7 minutes, so keep
  the realm's access token lifespan at its default 5 minutes or less).

`harness.json` (all optional):

```json
{
  "saasapi_url": "https://uat<run_id>-core.<region>.cloudapp.azure.com",
  "envoy_url": "https://uat<run_id>-dmz.<region>.cloudapp.azure.com",
  "sprout_envoy_address": "uat<run_id>-dmz.<region>.cloudapp.azure.com:443",
  "ca_file": "uat-ca.pem",
  "internal_auth_secret_file": "internal-auth-secret",
  "vmctl": "/path/to/vmctl.sh",
  "core_probe_ports": [22, 443, 3306, 5405, 6443, 8081, 8200],
  "bind_tenant": {"script": "uat/hub/core/bind-tenant.sh", "kubeconfig": "...", "endpoints": "...", "state_dir": "..."},
  "restart": {
    "farmer":    {"vm": "uat-core", "command": "..."},
    "farmerbus": {"vm": "uat-dmz",  "command": "..."},
    "envoy":     {"vm": "uat-dmz",  "command": "..."}
  }
}
```

The defaults are the ones shown, derived from `uat.json` where they name a
host. `saasapi_url` has no `/v1`. The `restart` commands run on a hub through
`vmctl.sh run` (L2, L3); the defaults use `k0s kubectl` (or `kubectl`) to
`rollout restart` every workload labelled `app.kubernetes.io/component` =
`farmer`, `bus` or `envoy`, then wait for the rollout. The local rig overrides
them if its hubs are named or reached otherwise.

## vmctl.sh, as the harness uses it

The Access interface of the Shared contract:
`vmctl.sh <uat.json> restart|stop-sprout|start-sprout|stop-vm|start-vm|run <vm> [command]`
(`stop-vm` and `start-vm`, a hub node's VM, for the ha tier's node stop).
The harness passes `$IMAS_UAT_DIR/uat.json` and the VM name from uat.json
(the hubs by their `dmz.name` and `core.name`). For `run` it passes one
argument, a script it wraps so that the script's own exit status comes back
as a line `__IMAS_UAT_RC=<n>`, and reads its results from lines
`__IMAS_UAT_<KEY>=<value>`; everything else vmctl.sh prints is ignored, so
Azure's run-command headers don't matter. Linux scripts are POSIX sh (one
probe uses bash) and expect root; Windows scripts are PowerShell and expect
SYSTEM, which is what `az vm run-command` gives. Calls to one VM are
serialized. A `run` whose output has no `__IMAS_UAT_RC` line is an error that
quotes vmctl.sh's output.

## For UAT.7 (the harness interface)

`harness/doc.go` lists the interface. In short: `harness.Load()` and
`harness.NewFleet(env)`; `Fleet.Prepare` resolves sprout IDs and links asset
IDs; `Fleet.Sprouts(filters...)`; `Fleet.Do` and `Fleet.Cook` post a batch
(waiting out 429s) and wait for it; `Fleet.OnHost` with a `HostScript` runs a
check on a sprout's host; `Fleet.VM.Restart` and friends; `Client` has every
tenant route; `Tokens` gives tokens by tenant and role and scratch users;
`Begin(t, id)` and `Scenario.Fatalf/Errorf/Skipf` give the failure format;
`Fleet.EachSprout` names subtests `t<tenant>-<os>` so the summary can place
them. For the summary, an ingredient test is placed by the `I.name.method`
in its subtest path and by `t<n>`, `ubuntu`, `alma`, `windows` (or `win`) in
any subtest name; a selection of `I.` ids runs `-run
'^TestIngredients$/<id>'`, so the runner's top-level test should be
`TestIngredients` with the case id as the first subtest level. Extend the
harness only by adding.

## What can't be asserted from outside

Each is a written skip, listed in every report, or a comment in the test:

- **T3**: a provisioning `last_error` or `warning` can't be caused from the
  runner (it needs farmer unreachable for the sweeper's whole backoff). The
  field shape is checked, then the test skips.
- **T4**: the `409 provisioning_in_progress` window is checked when
  provisioning is still pending at the DELETE; when it already finished, that
  subtest skips.
- **T5**: the tenant's NATS Account on the bus (the runner can't reach the
  bus; synthetic sprouts never connect).
- **T6**: job logs (no saasapi route; farmer's job store is read over the
  bus).
- **S5**: "nothing is sent in plaintext" rests on the error code farmer
  returns before sealing or sending (FIX.1); the wire isn't observable.
- **S6**: on Windows (the MSI source is the Ansible role's), and a clean
  re-enrolment after a purge (needs the old sprout deleted; no API).
- **R5**: "pending changes" aren't in the batch API (items carry status,
  jid and error code only); asserted by effect on the host instead.
- **X5**: a plaintext `cmd.run` or `cook` can only reach a sprout over the
  bus with farmer's credential.
- **N1**: the hosted stack (enrolment on) serves neither `GET /pki/nkeynonce`
  nor `PUT /pki/putnkey`, and its Envoy routes no `/pki/` path; N1 checks the
  unproven `PUT` is refused, then skips with that reason. Its proof checks
  run against a standalone farmer (and the fake, which serves both routes).

K2, K3, S5 and T5 use synthetic sprouts: made-up NKey and box keys that do
step 1 of `POST /v1/enroll` through Envoy and never step 2, so they are
accepted sprouts with no box key. They stay in the tenant (an API gap the
owner recorded: no saasapi route to delete or revoke a sprout); a run's
tenants are thrown away with the run.
Tests leave small marker files under `/var/tmp` and `C:\Windows\Temp`
(`imas-uat-*`) and scratch tenants that T1, T4 and T5 offboard.

## The W1 cases (B1, E1, D1, U1, N1, RB1)

Brief `docs/briefs/W-uat-acceptance.md`: the S, T and U fixes on a deployed
stack, tier core, in `hardening_test.go`. They run on the rig and on Azure
unchanged. Besides saasapi, Keycloak, Envoy and `vmctl.sh` they look inside
the core hub through `uat/hub/core/acceptance.sh` (`Fleet.CoreProbe`,
`harness/acceptance.go`), which `kubectl exec`s into PXC, Valkey, RustFS and
OpenBao and port-forwards to saasapi's operator plane. It needs what
`bind-tenant.sh` needs (`$IMAS_UAT_CORE_KUBECONFIG`, `$IMAS_UAT_ENDPOINTS`,
the state directory; the workflow and the rig pass them); without them those
cases skip, saying so. E1 and D1 also make scratch users, like T1. They
rely on the core hub's short settings in `uat/hub/core/values/farmer-uat.yaml`
(the chart's defaults stay as shipped): a backlog cap of 20, a purge one hour
after offboarding, one day of recipe audit and log retention, and 24 hours
for terminal rows. Where a limit is hours or days, the case moves its own
rows' or objects' dates back past it (`acceptance.sh backdate`, planted
objects) instead of waiting.

| Id | What it does |
|---|---|
| B1 | Keeps tenant 1's sprouts busy (a 40 s `cmd.run` each, pending until they answer), then posts 100 unknown asset IDs: `429 backlog_full`, `Retry-After: 60`, `details` with `pending` (at least the busy items), `limit`, `requested` and `available` = `limit - pending`. Posts the smallest request that doesn't fit (also refused), waits for the sleeps, and the same request is accepted. |
| E1 | Two scratch tenants with data in every store (a key, a sprout enrolled through Envoy, an asset link, a recipe, a batch). Offboards each (`purge_after` an hour out), purges one through `POST /v1/operator/tenants/{tenant_id}/purge` (202, then 409 `purge_in_progress`) and the other through the sweeper (its `offboarded_at` moved two hours back). Each ends `purged`: `GET` answers with no name, `PATCH` is 409 `tenant_purged`, `DELETE` 409 `offboarding_in_progress`, the keys, recipes, update policy and asset link routes 404 `tenant_not_found`; every table, object prefix and Valkey prefix of `internal/tenantpurge`'s inventory counts 0, and the KV keypair and both Transit keys are gone, while the tombstone's rows stay and a purge job succeeded. Tenant 2 is untouched. |
| D1 | Checks the workloads run with the values file's settings and the log shipper and retention CronJob are there. Plants recipe audit records and log objects two days past the limit and on its edge, runs farmer's sweep and the CronJob: the old ones go, the edge and today's stay. Moves a finished batch, a batch with a pending item, an expired key and two scratch tenants' finished provisioning jobs back past `SAASAPI_TERMINAL_ROW_RETENTION` and restarts saasapi (its prune runs at start): the finished batch, the key and the live tenant's jobs go, the pending batch and the offboarded tenant's jobs (its tombstone's record) stay. |
| U1 | Every sprout's facts are fresh in `farmer.props` and none is marked as needing an upgrade; a cook on each of tenant 1's sprouts is recorded in `farmer.job_status` and the job bucket. A sprout the case enrols, connected to the bus through Envoy, sends a sealed facts report (stored), a plaintext one (refused, marked `facts`), a sealed one (stored, mark cleared), one sealed under another key (refused), a plaintext step event (refused, marked `cook step`, no job recorded) and a sealed report again (mark cleared). |
| N1 | Standalone only (above): no signature, a nonce farmer never issued, a spent nonce, and another sprout's public NKey signed by the attacker are 403; a proper proof is 200. |
| RB1 | Uploads seven recipes of 9000 range iterations each and two recipes including seven or two of them. The cook of seven (126000 iterations over two renders each) runs out of farmer's per-cook budget (100000): farmer logs the budget error for the sprout, the sprout's file isn't written, and its item fails with `job_refused` (farmer records the refused job in `farmer.job_status`, P29). The cook of two (36000) applies. |

The fake (`harness/fakestack`) has what these need: the backlog cap, a
pending `cmd.run` while its sleep lasts, the purge and the tombstone, the
sweeper and the prune, an in-process NATS server behind its Envoy for the
sprout's bus connection, sealed facts opened with the tenant's key, the
standalone NKey routes with farmer's own proof checks, and the per-cook
budget; its `acceptance.sh` (written next to its `bind-tenant.sh`) answers
from its memory. It proves the plumbing, never the product.

## The ha tier (HA1 to HA6)

Brief H5 of `docs/briefs/H-azure-next-runs.md` (P24 item 6, P23). It runs
only on the HA run (`hub_nodes` 3: three core and three DMZ k0s nodes,
`uat/README.md` "HA run"); on one node per hub every scenario skips, saying
so. Besides saasapi, Envoy and `vmctl.sh` it uses, from the runner: kubectl
on both clusters (`IMAS_UAT_CORE_KUBECONFIG`, `IMAS_UAT_DMZ_KUBECONFIG`;
`kubectl port-forward` to reach a bus node's client port and its loader's
`/status`, which no NetworkPolicy opens to anything else), helm on the charts
the hubs were installed from (HA3), and `uat/hub/core/check.sh` (HA3).
`harness.json` may set the same in `"ha": {"core_kubeconfig",
"dmz_kubeconfig", "core_chart", "dmz_chart", "core_check"}`.

**The loops.** While a scenario takes something away, loops make an API call
every second (an asset lookup, the tenants in turn), enrol a new sprout every
10 s (both requests of `/v1/enroll` through Envoy, with the sprout's own
client, so farmer records its box key and issues its JWTs), run `cmd.run`
every 5 s on every sprout of the run (each run appending a fresh word to a
marker file), and, in HA2, create a recipe every 15 s. Each call gets 3
client retries after 1 s, 2 s and 4 s. Every scenario logs its timings: the
moments (pod deleted, VM stopped), each loop's calls, retries, failures and
longest outage, and each sprout's longest outage.

**The owner's windows** (the brief's Owner decisions):

| Window | Holds when |
|---|---|
| pod kill (HA1) | no call fails after its 3 retries, and every sprout seen down (not connected, or a `cmd.run` failing on it) is seen up again within 30 s |
| node stop (HA2) | after any failed call, a call of the same kind (API, enrolment, `cmd.run`, recipe) succeeds within 60 s, and every sprout seen down is up again within 60 s |
| rolling restart (HA3) | no call fails after its 3 retries |

After the loops, every scenario that enrolled checks that no two enrolments
share a sprout, NKey, box key, User JWT or gateway JWT, and enrols each
again with its own keys: farmer must answer with the same sprout and the
same User JWT (one JWT per sprout across the farmer replicas; its box key
proof accepted, so the box key on record is the one it proved). The marker
files must hold each `cmd.run`'s word once (once for a succeeded item, never
twice for any).

| Id | What it does |
|---|---|
| HA1 | For farmer, saasapi, Envoy and each bus pod in turn: delete one pod under the loops, wait for its replacement, run 45 s more. The pod kill window. For a bus pod, its loader's `/status` is read every half second from the moment the new pod runs: whenever the loader (or its container) is ready it must hold every account it targets, and it ends holding as many as the other loaders. |
| HA2 | Stop the VM of a core node (`vmctl.sh stop-vm`): one hosting a farmer pod and a PXC, OpenBao and Valkey pod, never Valkey's primary or Keycloak; then a DMZ node hosting a bus pod and an Envoy. The node stop window, with the node stopped for 150 s. With the core node stopped, PXC (Galera Primary, ready, cluster size 2), OpenBao (two unsealed, one active) and Valkey (both answer, the primary has one replica) serve. Then `start-vm`: the node Ready, every pod on it Ready and nothing of the hub Pending within 10 minutes of the start; the stateful services back at three; the recipes and sprouts created during the stop all there (read back, enrolled again). |
| HA3 | `helm upgrade --reuse-values` of the core release (farmer and saasapi pod annotation) and the DMZ release (the bus's), with `--wait`, under the loops. The rolling restart window; every farmer, saasapi and bus pod replaced; every sprout still resolving to its sprout, accepted, and running a job; then `uat/hub/core/check.sh` passes (design T4: the bootstrap Job stayed idempotent through the upgrade). |
| HA4 | Enrol a sprout, scale farmer to 0, delete one bus pod (its `emptyDir` goes with it): it must come back Ready, its loader holding every account, from the object store alone, and accept the sprout. Farmer is scaled back and every sprout runs a job. |
| HA5 | A sprout in a scratch tenant connects to every bus node. One bus pod's loader is kept from the object store by a NetworkPolicy (the chart's bus policy excludes that pod; a policy of its own carries every rule but the egress to the account store's port), and the core edge proxy is restarted so the loader's open connections are cut; the loader must then report object store errors. A new account is created (a scratch tenant, with a sprout) and the first sprout revoked (its tenant offboarded: farmer's locked-out Account JWT revokes every user). The other loaders take it; the blocked one must not. The block is lifted: within the reconcile period (the loader's `IMAS_LOADER_RECONCILE_INTERVAL`, ±20%, plus 30 s for a request) its timer must apply both (same index, every account, two more pushes). Then every bus node refuses the revoked sprout and accepts the new tenant's. |
| HA6 | Create three tenants at once, then for a minute enrol a sprout every 60 s / (10 × Envoys) (Envoy admits 20 `/v1/enroll` requests per 60 s each; an enrolment is two), the tenants and tenant 1 in turn, all in flight together across the farmer replicas. Every enrolment succeeds, no identity is duplicated, each enrols again to the same JWT, and every new tenant's account is on every bus node (its sprout connects to each). |

**Design tests T1 to T8** (`docs/design/imas-openbao-signing-design.md`,
section 11), one to one onto the scenarios that cover them:

| T | Proves | Covered by |
|---|---|---|
| T1 | a JWT signed through the Transit-backed signer is accepted by nats-server | S1 and C1 (every sprout connects with its farmer-issued JWT and runs a job); HA5 and HA6 (sprouts enrolled during the run connect to each bus node directly) |
| T2 | farmer's enrolment path at the planned rate with N farmer replicas | HA6 (enrolment at Envoy's admitted rate across the three farmer replicas) |
| T3 | N farmer replicas provision tenants and enrol without divergence (no duplicate keys, Account JWT on every bus node) | HA6 (three tenants at once, parallel enrolments, every account on every bus node); HA1 (no duplicate JWT or box key while farmer pods are killed) |
| T4 | the bootstrap Job is idempotent; root and bootstrap tokens revoked; operator-identity sign permission removed | HA3 (`uat/hub/core/check.sh`'s T4 checks after a `helm upgrade` that re-runs the hooks); the same checks run at every install (`finish.sh`) |
| T5 | bus nodes start and authenticate from the published operator JWT alone, no private keys | HA4 (a bus node started empty with farmer at 0 loads every account and authenticates a sprout); HA1 (each bus pod restarted) |
| T6 | the sprout User JWT mint-or-reuse is safe across replicas | HA1, HA2, HA3 and HA6 (each enrolment, repeated, gets the same JWT; no JWT shared) |
| T7 | bus node add and remove with sprouts reconnecting through jitter, no storm | HA1 (each bus pod removed and re-added) and HA2 (a DMZ node and its bus node removed and re-added): every sprout back within the window, no call failing |
| T8 | SaaS API replicas: batch actions and provisioning with the outbox, no duplicate work | HA1 (a saasapi pod killed under the `cmd.run` loop: every batch's command ran once, by the marker files), HA3 (saasapi rolled), HA6 (tenants provisioned at once) |

Every T is covered by a scenario above, so none was added beyond HA1 to HA6
(HA6 is the one the brief's list did not have: T2 and T3 need a burst, which
the loops' one enrolment every 10 s is not).
