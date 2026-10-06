# UAT acceptance tests (UAT.5)

The Go acceptance suite of the Azure UAT gate
([plan section 4h](../../docs/claude-code-parallel-build-plan.md#4h-azure-uat-gate-uat1-to-uat8)).
It runs against a deployed stack from the runner, through the product's own
endpoints (saasapi, Keycloak, Envoy) and, for anything outside the platform,
through `uat/access/vmctl.sh`. It never calls Azure itself.

**Status: it has never run against a real deployment.** It builds and vets
with the `uat` tag, its helpers have unit tests against fake servers, and the
whole catalogue runs green against the in-memory fake in
`harness/fakestack`, which proves the plumbing and nothing about the product.
Expect fix rounds after the first real runs (local rig, then Azure).

## Layout

| Path | What |
|---|---|
| `*_test.go` (build tag `uat`) | the scenarios T1 to T6, K1 to K4, S1 to S6, C1 to C8, R1 to R6, X1 to X5 (tier core, the smoke ones named `TestSmoke`) and L1 to L3 (tier resilience) |
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
`ingredients`, `lifecycle`, `all`. Ids must belong to the tier; ingredient ids
(`I.name.method`) go in a run of their own. Test functions are named
`Test<Tier><Id>_<What>` (`TestSmokeC1_CmdRunEverySprout`,
`TestCoreX4_CrossTenantDenied`, `TestResilienceL2_FarmerRestart`), so
`go test -tags uat -run '^TestCoreX4_' ./uat/tests` works too.

| Variable | Meaning |
|---|---|
| `IMAS_UAT_DIR` | required: the material directory below |
| `IMAS_UAT_VMCTL` | the `vmctl.sh` to use; else harness.json's `vmctl`; else `uat/access/vmctl.sh` |
| `IMAS_UAT_REPORT_DIR` | where the report goes (default `$IMAS_UAT_DIR/report`) |
| `IMAS_UAT_TIMEOUT` | `go test -timeout` (default: smoke 45m, core 4h, resilience 3h, others 8h) |
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
`organization.id`, and stops the run, naming the tenant, if not. Tenants a
test creates itself (T1, T4, T5) need a user bound to them: the harness is
to use bind-tenant.sh's create-user-and-bind mode for that (owner decision),
which PR #132 had not documented when this was written, so it isn't wired in
yet (`Fleet.ScratchUser` is the one place it goes; `harness.json`'s
`bind_tenant` and `$IMAS_UAT_CORE_KUBECONFIG`, `$IMAS_UAT_ENDPOINTS` and
`$IMAS_UAT_BIND_TENANT` already give the arguments every uat/hub/core script
takes). Until then those tests skip that part with the reason.

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
  harness never takes credentials.json's master admin for this. On UAT.3b's
  deployment T1 (after its 202), T4 and T5 skip until bind-tenant.sh's
  create-user-and-bind mode is wired in (above).
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
`vmctl.sh <uat.json> restart|stop-sprout|start-sprout|run <vm> [command]`.
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

K2, K3, S5 and T5 use synthetic sprouts: made-up NKey and box keys that do
step 1 of `POST /v1/enroll` through Envoy and never step 2, so they are
accepted sprouts with no box key. They stay in the tenant (saasapi has no
route to delete a sprout); a run's tenants are thrown away with the run.
Tests leave small marker files under `/var/tmp` and `C:\Windows\Temp`
(`imas-uat-*`) and scratch tenants that T1, T4 and T5 offboard.
