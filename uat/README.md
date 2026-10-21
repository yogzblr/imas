# The Azure UAT gate (`uat/`)

The release acceptance gate of imas: one GitHub Actions run builds a small,
production-shaped environment in Azure from a **published release**, enrols
real sprouts in two tenants, runs the acceptance tests against it, uploads the
report and tears everything down. The design is section 4h of
`docs/claude-code-parallel-build-plan.md` (the Shared contract, the scenario
catalogue, the owner prerequisites); this page is the owner's guide to it.

> [!IMPORTANT]
> **The gate has run once on Azure:** run 38107290465 (2026-10-11, on main
> at `2fe395c8`) passed, before the stateless build (P21) and the GPG fleet
> update trust (P22). The next two runs, the single-node gate again with the
> fleet update path on (Run 2) and the HA run on 3 + 3 nodes (Run 3), have
> their exact inputs, owner prerequisites and what each proves in
> [`RUNBOOK.md`](RUNBOOK.md). The workflow and the janitor are **flagged for
> security review** (they hold Azure credentials): treat them as ready for
> review, not as done.

## What the gate proves, and what it does not

| Proves (when green) | Does not prove |
|---|---|
| The published Helm charts of the release install and run on Kubernetes (k0s): `deploy/helm/farmer` on core (farmer, saasapi, PXC, Valkey, OpenBao) and `deploy/helm/nats` on the DMZ (farmerbus, Envoy), with the release's own images and never `latest` | High availability on the single-node run (`hub_nodes` 1): every hub is one node, each stateful service one pod. The HA run (`hub_nodes` 3, [HA run](#ha-run)) is the one that proves it |
| The published OS packages install from the Buildkite repositories with the Ansible role, on Ubuntu 24.04, AlmaLinux 9 and Windows Server 2022 Core | On the single-node run: PXC clustering (one PXC node), the clustered bus, failover (the HA run covers them) |
| Enrolment through Envoy, with a pinned UAT CA, one-time keys, and sprouts reaching the bus only through Envoy | Real RHEL: AlmaLinux 9 stands in for it (same dnf and rpm path; no subscription, RHUI or FIPS; see `uat/enroll/README.md`) |
| Tenant isolation: two tenants with the same sprout IDs (`ubuntu-01`, `alma-01`, `win-01`) resolve to different machines, and nothing crosses (T6, S2, S4, R3, X4) | SUSE and zypper: out of scope for this gate (add one more tenant VM later) |
| Auth: Keycloak tokens checked by saasapi (issuer, audience, roles, `organization.id`), the BFF shared secret, Envoy's `jwt_authn` gate, sealing (X1 to X5) | The internet path: sprouts reach Envoy on the DMZ's private address, and Envoy sits behind no application gateway or public load balancer |
| The S, T and U fixes on the deployed stack (brief W1): the action backlog cap (B1), tenant erasure after offboarding by the operator route and the retention sweeper (E1), retention of recipe audit days, log days and terminal rows with Fluent Bit shipping (D1), sealed facts and step events and the "needs upgrade" mark (U1), the per-cook render budget (RB1); N1 (the proof of possession on `PUT /pki/putnkey`) is for standalone installs and skips on this hosted stack, saying so | The proof of possession on `PUT /pki/putnkey` on a standalone install (N1 skips here: the hosted stack serves neither route) |
| Commands, recipes and cooks on every OS (C1 to C8, R1 to R6), resilience to reboots and restarts (L1 to L3), and with UAT.7 every ingredient method and the package upgrade (I.*, L4) | Scale and load, the web UI, key expiry (the minimum is an hour; unit tests cover it), the self update cycle (L5) unless `dispatch_flags` is ticked, a Windows host with Desktop Experience |
| The sprout release of `release_tag` registers through saasapi's operator plane with its GPG-signed `checksums.txt` and signature (`finish.sh` fails otherwise); with `dispatch_flags`, a sprout on an earlier release self-updates to it, verifying the signature against its packaged keyring, and refuses a release whose `checksums.txt` was altered (L5) | That the flags are safe outside UAT: they stay off until the security review |

What runs where (section 4h, "The shape"): one resource group per run,
`imas-uat-<run_id>`, with a VNet of four subnets, an Azure Bastion (Standard,
native tunnelling), `uat-dmz` (single-node k0s, the nats chart), `uat-core`
(single-node k0s, the farmer chart plus RustFS and Keycloak, both UAT only) and
six sprouts: `t1-ubuntu`, `t1-alma`, `t1-win`, `t2-ubuntu`, `t2-alma`,
`t2-win`. SSH, WinRM and the Kubernetes API are reached only through Bastion
tunnels; only Envoy (8443 on the DMZ), 443 on core and the Bastion's 443 are
open from outside the VNet. By default they are open to the Internet, so they
follow whatever egress address the caller uses (owner, 2026-10-20, W5: one
/32 from the runner's address check need not be the address the Bastion
sees; W5 took that for Run 2's cause, which W6 found matches the age of the
Azure login instead, `RUNBOOK.md`); the `ingress_cidrs` input narrows all
three to named ranges. The HA run (`hub_nodes` 3, P24) makes each hub three k0s
nodes over the region's zones, `uat-dmz-1` to `uat-dmz-3` and `uat-core-1` to
`uat-core-3`, behind an internal and a public Standard load balancer
(`uat/tofu/README.md`, "HA topology"), each node a k0s controller+worker on
etcd (`uat/k0s/README.md`, "HA hubs").

## The pieces

| Directory | Brief | What |
|---|---|---|
| `uat/tofu` | UAT.1 | The OpenTofu module of one run, the bootstrap stack (state storage, budget), `destroy.sh` |
| `uat/access` | UAT.1 | `tunnels.sh` (Bastion tunnels) and `vmctl.sh` (reboot, stop and start a sprout, run a command): every Azure call of the gate; `session.sh` (W6) keeps the run's Azure login and tunnels fresh at each phase and prints their ages |
| `uat/k0s` | UAT.2 | k0s on both hubs, local-path storage, cert-manager, the per-run UAT CA, the endpoints file |
| `uat/hub/core` | UAT.3b | The core hub: farmer chart, OpenBao bootstrap, RustFS, Keycloak, the edge |
| `uat/hub/dmz` | UAT.3a | The DMZ hub: nats chart (farmerbus, Envoy), its exposure and `check.sh` |
| `uat/enroll` | UAT.4 | Tenants 1 and 2, one-time keys, the Ansible inventory, enrolment, waiting for farmer to see every sprout |
| `uat/tests` | UAT.5 | The acceptance suite (`run.sh`, the harness, the report) |
| `uat/cases`, `uat/tests/ingredients` | UAT.7 | Ingredient conformance and L4/L5 |
| `uat/lite` | UAT.8 | The local rig |
| `uat/scripts` | UAT.6 | The workflow's helpers: input checks, run id, test material, artifact allowlist, teardown check, janitor |
| `.github/workflows/uat.yml`, `uat-janitor.yml` | UAT.6 | The gate and the janitor |

## Prerequisites (once)

From section 4h, "Owner prerequisites", plus what the janitor needs. Run the
`az` commands in Azure Cloud Shell as the subscription Owner. Keep this
subscription for UAT only: the GitHub identity is Contributor on all of it.

Steps 1 to 3 and the federated credentials of steps 2 and 7 (the Azure side of the OIDC identity) can be done by
`uat/scripts/azure-owner-setup.sh`: it runs `az login` if needed, shows the subscription, asks before it
changes anything, does each step only if it is not already done, and prints the three GitHub variables
(`--help` lists the options, including `--accept-image-terms`). It works in WSL. It looks up the owner and
repository ids with the GitHub CLI (`gh auth login` first), or takes `--owner-id` and `--repo-id`, and it deletes
a credential with the old plain subject `repo:OWNER/REPO:environment:...`, which never matches.

> **The OIDC subject carries ids.** This repository's token subject is
> `repo:yogzblr@16265408/imas@1388858987:environment:uat`, not
> `repo:yogzblr/imas:environment:uat`; with the plain form the Azure login
> fails (found on the first Azure run). Find the ids with
> `gh api repos/yogzblr/imas --jq '.owner.id, .id'`. Use this form for every
> credential below, the janitor's too.

1. **Resource providers**: `Microsoft.Compute`, `Microsoft.Network`,
   `Microsoft.Storage`, `Microsoft.Authorization`, `Microsoft.Consumption`
   (`az provider register --namespace ...`).
2. **The GitHub OIDC identity** `imas-uat-github`: an app registration and its
   service principal, Contributor on the subscription, and a federated
   credential for `repo:yogzblr@16265408/imas@1388858987:environment:uat` (the commands are in
   section 4h). No client secret exists anywhere.
3. **AlmaLinux marketplace terms**, once per subscription:
   `az vm image terms accept --publisher almalinux --offer almalinux-x86_64 --plan 9-gen2`.
   Confirm the three image URNs first with `az vm image list --all ...`
   (`uat/tofu/README.md`, Inputs).
4. **Quota and sizes** in the region (default `centralindia`):
   Standard_D2s_v5, Standard_D8s_v5 and Standard_B2ls_v2 available;
   22 vCPUs in all, 10 in the Dsv5 family and 12 in the family of
   Standard_B2ls_v2 (find its name with `az vm list-skus --location <region>
   --size Standard_B2ls_v2 --query [0].family`; `az vm list-usage` shows the
   quota), so Total Regional vCPUs must be at least 22. The HA run
   (`hub_nodes` 3) needs Standard_D4s_v5 too and 18 Dsv5 vCPU plus the 12
   B2ls_v2 (owner, 2026-10-13), 30 in all. The workflow checks this before
   it creates anything (`uat/tofu/quota-check.sh`). One run at a time (the
   workflow's concurrency group).
5. **The bootstrap stack**, by hand, once: `uat/tofu/bootstrap` (state storage
   account with Entra-only access, a `CanNotDelete` lock, the monthly budget
   alert). Give the GitHub identity `Storage Blob Data Contributor` on the
   state account through its `state_blob_contributors` variable
   (`uat/tofu/README.md`, "Bootstrap, once"). Optionally put the account's
   name in the `uat` environment variable `UAT_TFSTATE_STORAGE_ACCOUNT`;
   otherwise the workflow finds it by its tag in `imas-uat-state`.
6. **The GitHub environment `uat`**: a required reviewer (you), a deployment
   branch rule for `main`, and the variables `AZURE_CLIENT_ID`,
   `AZURE_TENANT_ID` and `AZURE_SUBSCRIPTION_ID`.
7. **The GitHub environment `uat-janitor`** for the hourly janitor: the same
   three variables, a deployment branch rule for `main`, and **no** required
   reviewer (an hourly run cannot wait for one). Its federated credential:

   ```sh
   az ad app federated-credential create --id "$APP" --parameters '{
     "name": "imas-uat-janitor-env",
     "issuer": "https://token.actions.githubusercontent.com",
     "subject": "repo:yogzblr@16265408/imas@1388858987:environment:uat-janitor",
     "audiences": ["api://AzureADTokenExchange"]}'
   ```

   This reuses `imas-uat-github`, so the janitor holds Contributor without a
   reviewer; only a change merged to `main` can change what it runs. A
   narrower alternative is a second application with a custom role that can
   read and delete resource groups and what is in them (open question in the
   UAT.6 PR).
8. **The release under test** must have a published GitHub release, its OS
   packages must be in the Buildkite package registries (`imasdeb`,
   `imasrpm`, `imasnget`), and its Helm charts on GHCR
   (`oci://ghcr.io/yogzblr/charts/farmer` and `.../nats`), public and linked
   to this repository: `publish-packages.yml` ran to the end, its last step,
   *Check the charts are public and linked to the repository*, included
   (`docs/RELEASING.md`, "Helm charts on GHCR"). A pre-release is not
   published automatically: run Publish packages by hand for it, from the
   tag (*Use workflow from*: the tag), or the Windows sprouts cannot find
   the NuGet package (`uat/enroll/README.md`, "Windows with a pre-release
   tag").

## Running it

Actions, **UAT gate**, Run workflow on `main`, or:

```sh
gh workflow run uat.yml --ref main -f release_tag=v0.1.0-rc.4 -f tier=smoke -f keep_hours=2
```

Then approve the `uat` deployment when GitHub asks (the required reviewer).

The inputs of the next two runs (Run 2, Run 3) are in [`RUNBOOK.md`](RUNBOOK.md).

| Input | Default | Meaning |
|---|---|---|
| `release_tag` | required | `vX.Y.Z` or `vX.Y.Z-rc.N`. It must be a tag with a published (not draft), GPG-signed release (assets `checksums.txt` and `checksums.txt.sig`); the chart, the images, the packages and the CLI all come from it. It is the chart reference too: the core hub installs the farmer chart published with it, which carries the stamped sprout release `finish.sh` registers |
| `region` | `centralindia` | Azure region |
| `keep_hours` | `0` | `0` destroys at the end. Above 0 (at most 168) skips the destroy and keeps the environment for debugging; the janitor deletes it later |
| `tier` | `all` | `smoke` (about 10 minutes of tests), `core` (includes smoke), `resilience`, `ingredients`, `lifecycle`, `ha` (the HA tests HA1 to HA6; needs `hub_nodes` 3, see [HA run](#ha-run)) or `all` |
| `upgrade_from_tag` | empty | An earlier release for L4 (the package upgrade, UAT.7). Empty: L4 skips with that reason. Passed to the tests as `IMAS_UAT_UPGRADE_FROM_TAG` |
| `scenarios` | empty | Scenario ids of the tier, separated by spaces or commas (`C1 X4`), passed to `uat/tests/run.sh`. Ingredient ids (`I.file.managed`) go in an `ingredients` run of their own |
| `hub_nodes` | `1` | k0s nodes per hub. `1` is the single-node run. `3` is the HA run (P24): `uat/tofu` gets `core_node_count=3`, `dmz_node_count=3` and `core_node_size=Standard_D4s_v5` (3 core nodes of D4s_v5, 3 DMZ nodes of D2s_v5, each hub behind load balancers; `uat/tofu/README.md`, "HA topology"), which needs 18 Dsv5 vCPU of quota |
| `dispatch_flags` | `false` | `true` turns the fleet update flags on in the core hub (saasapi `SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED`, farmer `IMAS_SELF_UPDATE_ENABLED`, through the chart values `saasapi.fleetUpdateDispatch.enabled` and `farmer.selfUpdate.enabled`) and runs L5; `false` leaves both off and L5 skips. Passed as `IMAS_UAT_DISPATCH_FLAGS=on\|off` to the core install and the tests. UAT only |
| `ingress_cidrs` | empty | Who may reach the three ports open from outside the VNet (Bastion 443, core 443, Envoy on the DMZ). Empty: the Internet (`uat/tofu` `public_ingress=internet`), the UAT gate's default (owner, 2026-10-20, W5). Public IPv4 ranges, separated by spaces or commas (`a.b.c.d/N`, N from 8 to 32, no host bits, at most 50): the hardened mode (`public_ingress=cidrs`), only those ranges. They must cover every egress address of the caller: a GitHub hosted runner's address is not fixed, so the hardened mode suits a runner with known egress ranges. UAT only; recorded in the P3 security review |

What the run does, in order (each step is a step of the job, so the failed one
names the piece):

1. **Check inputs and variables** (`uat/scripts/check-inputs.sh`): the three
   Azure variables are set and are GUIDs; `release_tag` (and
   `upgrade_from_tag`) is a release tag that exists and has a published
   release, and `release_tag`'s release is GPG signed (`checksums.txt.sig`);
   region, `keep_hours`, tier, `hub_nodes`, `dispatch_flags`, `ingress_cidrs`
   and scenario ids are well formed. Every
   problem is reported at once, by name, and nothing is created.
2. Tools: Go, Python, OpenTofu 1.11.5, Helm v4.3.0, k0sctl and kubectl at
   `uat/k0s` pins, Ansible with pywinrm.
3. **Azure login** by OIDC (`azure/login`; its time is recorded for the
   ages below), then a fresh **run_id**
   (`run-id.sh`: 8 characters, a letter first). The run no longer looks up
   the runner's public address (W5): one lookup did not match the address
   the Bastion saw later in the run.
4. **tofu apply** (`uat/tofu`), state in the bootstrap account at
   `imas-uat/<run_id>.tfstate`. A plan and `uat/tofu/quota-check.sh` come
   first: the step fails before anything is created, naming the quota family
   and the vCPUs needed, in use and the limit to request, when the region's
   quota cannot hold the run; the apply applies exactly that checked plan
   (a retry plans and checks again). The per-run SSH key and Windows password go to
   0600 files on the runner, masked in the log; `uat.json`,
   `ha_node_names.json` (the VMs the HA tests stop) and `object_store.json`
   (the HA run's Azure Blob account, `null` otherwise, also when tofu did
   not store the null output) go to the run's state directory
   (`uat/scripts/tofu-outputs.sh`). On the HA run the account's name and key (masked) go to
   `<state>/hub/core/sensitive/azure-blob/`, which the core install turns into
   Versity Gateway's credential Secret.
5. **Bastion tunnels** (`uat/access/tunnels.sh open`, after `az extension add`
   for `bastion` and `ssh`, on a login made just before, not the one from
   before the 20-minute apply): SSH and the Kubernetes API on every hub node,
   and on an HA run also each hub's API address (`dmz-api`, `core-api`).

   **From here on every phase starts with `uat/access/session.sh phase`**
   (W6). The run's az session is an OIDC login, which stops working about an
   hour after it is made, and tunnels opened on it then hang (Run 2 failed
   that way, 55 to 60 minutes after its login: `RUNBOOK.md`). So a phase
   logs in again and reopens the tunnels (on the same local ports) when
   either is 15 minutes old, refuses to start past 40, and prints `azure
   login age Xm, tunnels age Ym`. A tunnel is never reopened while something
   uses it.
6. **k0s** on both hubs (`uat/k0s/bootstrap.sh --nodes <hub_nodes>`): one
   single-node cluster per hub, or on the HA run three controller+worker nodes
   per hub on etcd, waiting for every node Ready and every etcd member joined.
7. **Core hub** (`uat/hub/core/install.sh`: the release's published chart,
   checked to carry the stamped sprout release; the operator plane on; the
   dispatch flags as asked; `validate-object-store.sh` proves each scoped
   credential on RustFS; on the HA run the overlay `values/values-ha.yaml`
   and Versity Gateway instead, see [HA run](#ha-run)),
   then the **DMZ hub** (`uat/hub/dmz/install.sh`: core's public NATS trust
   copied from its ConfigMap; the bus loader's seed and the read-only
   accounts credential from core's state directory, `--loader-seed` and
   `--accounts-reader-dir`; on the HA run also the fence user's seed,
   `--fence-seed`, and its own `values-ha.yaml`), then **core's second half** (`uat/hub/core/finish.sh`: farmer and
   saasapi need the DMZ bus, so it waits for them, registers the sprout
   release (the hook Job must complete, and saasapi's operator API must then
   hold `release_tag` with its GPG-signed `checksums.txt` and signature, or
   the step fails) and runs core's `check.sh`) and the **DMZ check** (`check.sh`, before enrolment because it
   empties and then waits out Envoy's enrolment rate limit). Core comes first
   because the bus needs core's trust (with the loader's JWT), the loader's
   seed and the accounts bucket (on core's object store, which the DMZ reads
   on port 9000) when it starts.
8. A fresh Azure login and fresh tunnels, each tunnel probed end to end
   (`ssh-keyscan`, WinRM's `/wsman`, the API's `/version`), then **Tenants
   and enrolment** (`uat/enroll/enroll.sh`), which refreshes again between
   its Ansible runs when 15 minutes old.
9. **Test material** (`uat/scripts/material.sh`), a fresh Azure login and
   fresh, probed tunnels again, then **the tests** (`uat/tests/run.sh <tier>
   [ids]`), each top-level test in its own process with a refresh between
   them when 15 minutes old.
10. Always: on an HA run, **start every hub VM** (`vmctl.sh start-vm` on each
    name of `ha_node_names.json`, so a node stop that failed half way leaves no
    VM stopped); on a failure, **the login's and the tunnels' ages**, each
    tunnel's process and the end of its log; then **close the tunnels**, **collect and upload** the report and the
    outputs, then, unless `keep_hours` is above 0, a third Azure login,
    **destroy** (`uat/tofu/destroy.sh`) and **verify teardown**
    (`verify-teardown.sh`), each of which fails the job when something is
    left. The job summary shows the test summary and, for a kept run, its
    expiry.

Durations are guesses: about 60 minutes before the first test (the Bastion
alone takes about ten), 10 minutes of smoke tests, 15 to 20 minutes of
teardown. A GitHub-hosted job stops at 6 hours: the job's timeout is 350
minutes and the test step's 180 (`go test -timeout` 165m), so a tier `all`
run that needs longer than that has to be split into tier runs.

### Artifacts

| Artifact | Contents |
|---|---|
| `uat-report-<run_id>` | `summary.txt` (one line per scenario, OS and tenant), `junit.xml`, `events.json` (`go test -json`), `build.log` |
| `uat-outputs-<run_id>` | `run.json` (this run's inputs), `uat.json` (tofu output, no credentials), `ha_node_names.json` and `object_store.json` (tofu outputs, no key), `k0s/endpoints.json`, the UAT CA certificate, the rendered k0sctl files, `hub/core/out/core.json` and `admin.json` (public keys), `hub/harness.json`, `dmz/dmz.json`, `enroll/{run,tenants,keys,sprouts,sprouts-detail}.json` |

Never uploaded: the SSH key, the WinRM password, the kubeconfigs, OpenBao's
unseal keys and root token, the NKey seeds, the bootstrap admin's private
keys, the Keycloak and RustFS credentials, the BFF secret and the enrolment
keys. `collect-artifacts.sh` copies by an allowlist and then scans every copied
file for private keys, kubeconfig credentials, JWTs, NKey seeds and JSON
passwords, secrets, tokens or unseal keys; a match is removed and fails the
step. (`uat/hub/core/README.md` mentions keeping `openbao-init.json` as a
sensitive artifact; the gate does not upload it at all. A kept environment
keeps its unseal keys in the cluster Secret `imas-uat-openbao-unseal`.)

## HA run

`hub_nodes` 3 (Run 3; brief `docs/briefs/H-azure-next-runs.md`, H1 to H5)
builds three controller+worker k0s nodes per hub (`uat/tofu`, `uat/k0s`)
and installs both hubs with an HA overlay on top of their UAT values,
chosen by the node count in the endpoints file (no input of its own):

| Hub | Overlay | What changes |
|---|---|---|
| core | `uat/hub/core/values/values-ha.yaml` | farmer, saasapi and Versity Gateway 3 replicas each, spread one per node (`topologySpreadConstraints` over `kubernetes.io/hostname`, maxSkew 1, `DoNotSchedule`) with PodDisruptionBudgets; PXC 3 nodes and 3 HAProxy (no `unsafeFlags`); OpenBao 3-node raft (`retry_join` between the pods, the static seal below); Valkey a primary and 2 replicas (the chart's replicated mode); the object store Versity Gateway over the run's Azure Blob account instead of RustFS. The UAT-only chart runs one edge proxy per node. |
| DMZ | `uat/hub/dmz/values-ha.yaml` | the bus a 3-node NATS cluster (fence user, route password, every pod on the bus certificate) and Envoy 3 replicas, spread one per node with PodDisruptionBudgets. |

Neither farmer, saasapi, Versity Gateway, the bus nor Envoy carries a
volume: the bus's resolver directory is an `emptyDir`, rebuilt by its loader
from the accounts bucket at every start.

**Local volumes.** The stateful services (PXC, OpenBao, Valkey) keep their
data on the nodes' local volumes (StorageClass `local-path`, `uat/k0s`):
each replica's volume lives on its own node (owner, 2026-10-11) and they
replicate among themselves. So **a stateful pod on a stopped node stays
unavailable until that node returns**: its volume cannot follow it to
another node, and Kubernetes does not reschedule it. Meanwhile the
replicas on the other nodes serve: PXC and OpenBao keep a quorum with two
of three, and the HA tests (`ha` tier) assume exactly that. When the node
returns its pods start on their own volumes and rejoin (OpenBao unseals
itself, below; a PXC node resyncs from the others). Two single points are
known and are not stopped by the node-stop test, which stops a node hosting
a farmer pod, a bus pod and a *replica* of each stateful service:

- **Valkey's primary** is pod 0 (`core.json` `topology.valkey_primary`): the
  valkey-io chart 0.12.0 has no Sentinel or cluster mode, so the replicas
  serve reads while the primary's node is down but nothing takes its
  writes until it returns.
- **Keycloak** (UAT only, `uat/hub/core/chart`) is one pod on an H2 file
  volume: tokens for the tests come from it.

**OpenBao's seal.** The single-node run unseals OpenBao with Shamir keys,
by script (`openbao-bootstrap.sh`), which a pod restarted by a test would
not get. The HA run uses OpenBao's static seal instead: a 32-byte key
`install.sh` generates once (`<state>/core/sensitive/openbao-seal.key`) in
Secret `imas-uat-openbao-seal`, which every OpenBao pod mounts, so each pod
unseals itself on every start and rejoins raft. `openbao-bootstrap.sh`
initialises pod 0 once with recovery keys (kept like the unseal keys of the
single-node run) and waits for three unsealed voters. **UAT only:** anyone
who reads the seal Secret and a raft volume reads OpenBao
(`docs/design/imas-openbao-signing-design.md`, "Static seal (test)").

**Object store.** `uat/tofu` creates the run's storage account
(`imasuat<run_id>`, `object_store` output) when core has several nodes; the
workflow writes its name and key (masked) to
`<state>/hub/core/sensitive/azure-blob/`, and `install.sh` makes Versity
Gateway's Secrets from them, its root credential and the six users' pairs
(the accounts reader's goes to the DMZ as before; the two log users' are
for Fluent Bit and the log retention CronJob). The chart's
`createBuckets` Job makes the buckets (containers) and their policies;
`validate-object-store.sh` then proves each user's reach through the
gateway. The DMZ's bus loader reads the accounts bucket on core's private
address, port 9000, where the core edge proxy passes it to the gateway.

**The `ha` tier** (`tier=ha`, or `all`; `uat/tests/README.md`, "The ha
tier") runs HA1 to HA6 against these hubs, from the runner, with kubectl on
both clusters (through the API tunnels), `vmctl.sh stop-vm` and `start-vm`
for the node stop, and helm on the charts the hubs were installed from: pod
kills, a core node and a DMZ node stopped, a rolling restart, an empty bus
node, a lost account event and parallel enrolment, each checked against the
owner's error windows (brief H-azure-next-runs.md, Owner decisions). Its
node stop picks a node by the rule above. `check-inputs.sh` refuses
`tier=ha` with `hub_nodes` 1, and on the single-node run every HA scenario
skips, saying so.

**Load balancers.** Each HA hub's private address is its internal load
balancer (`api_address`), so the other hub and the sprouts keep one address
while a node is stopped. The NetworkPolicies admit the other hub's traffic
from its nodes' addresses and the Azure health probe's source
(168.63.129.16) on the load-balanced ports, or a node would drop out of the
balancer's rule. `uat/hub/dmz/check.sh`'s enrolment burst scales with the
Envoys (each has its own bucket of 20 per 60 s).

## Keeping an environment for debugging

Run with `keep_hours` above 0. Everything up to and including the tests runs as
usual, the tunnels are closed and the report is uploaded, but the destroy and
its check are skipped. The resource group's `expires_at` tag is the time of the
first apply + `run_budget_hours` (3 for smoke, 7 otherwise, so a live run is
never collected) + `keep_hours`; the job summary prints it.

The runner and everything on it are gone when the job ends, including the
SSH key, the kubeconfigs and the core hub's credential files. To get in:

```sh
az login && az account set --subscription <uat subscription>
RUN=<run_id>
cd uat/tofu
export ARM_SUBSCRIPTION_ID=$(az account show --query id -o tsv)
ACCOUNT=$(az storage account list -g imas-uat-state --query "[?tags.purpose=='imas-uat-state'].name | [0]" -o tsv)
tofu init -reconfigure -backend-config=resource_group_name=imas-uat-state \
  -backend-config=storage_account_name=$ACCOUNT -backend-config=container_name=tfstate \
  -backend-config=key=imas-uat/$RUN.tfstate
tofu output -json uat >/tmp/uat-$RUN.json
(umask 077; tofu output -raw ssh_private_key >/tmp/uat-$RUN.key)
# A run with the default ingress (public_ingress internet in run.json) already
# admits you; skip this apply. A run with ingress_cidrs admits only those
# ranges: add yours (this moves the Envoy, core 443 and Bastion 443 rules
# together). Keep the run's release_tag, region, keep_hours, run_budget_hours
# and hub_nodes (all in the outputs artifact's run.json). For an HA run
# (hub_nodes 3) also pass -var core_node_count=3 -var dmz_node_count=3
# -var core_node_size=Standard_D4s_v5, or the apply removes the extra nodes.
tofu apply -var run_id=$RUN -var release_tag=<tag> -var region=<region> -var keep_hours=<hours> \
  -var run_budget_hours=<3 or 7> -var public_ingress=cidrs \
  -var 'public_ingress_cidrs=["<each of the run ranges>","<your address>/32"]'
cd ../..
uat/access/tunnels.sh open /tmp/uat-$RUN.json /tmp/uat-$RUN-access
jq . /tmp/uat-$RUN-access/access.json      # local ports per VM
ssh -i /tmp/uat-$RUN.key -p <ssh_port of uat-core> imasuat@127.0.0.1 sudo k0s kubectl get pods -A
```

On an HA run the VMs are `uat-core-1` to `uat-core-3` and `uat-dmz-1` to
`uat-dmz-3`. The Kubernetes API is on each hub node's `kube_port`, and on an
HA run on the `core-api` and `dmz-api` entries' `kube_port` too (the hub's
internal load balancer, which keeps answering while a node is stopped);
`sudo k0s kubeconfig admin` on a hub node prints an admin kubeconfig (point
its server at `https://127.0.0.1:<kube_port>`). The generated passwords (Keycloak users,
RustFS, the BFF secret) are in Kubernetes Secrets on core (`uat/hub/core/README.md`);
OpenBao's unseal keys and root token are in `imas-uat-openbao-unseal` and
`imas-uat-openbao-root`. `uat/access/vmctl.sh` works from your machine with an
`az login`. A tunnel opened on your own `az login` keeps working (an
interactive login renews itself; the runner's OIDC login cannot). If one
hangs, `uat/access/tunnels.sh reopen /tmp/uat-$RUN.json /tmp/uat-$RUN-access`
reopens them all on the same ports. Close your tunnels with `uat/access/tunnels.sh close /tmp/uat-$RUN-access`
and delete the key file when done.

Changing the expiry: re-apply with another `keep_hours`, or set the group's tag
directly (the janitor reads only the group's tag):
`az group update -n imas-uat-$RUN --set tags.expires_at=2026-10-08T12:00:00Z`.

## Cleanup

Three things remove a run, in this order:

1. **The run's own destroy** (`keep_hours` 0): `uat/tofu/destroy.sh` runs
   `tofu destroy`, falls back to `az group delete` for a group tagged
   `purpose=imas-uat` and this `run_id` (never another), and checks that
   nothing tagged `run_id=<run_id>` remains. Then **Verify teardown**
   (`uat/scripts/verify-teardown.sh`) checks again, independently: the group
   `imas-uat-<run_id>` is gone, no group and no resource anywhere in the
   subscription is tagged with the run_id; an `az` error counts as a leftover.
   The job fails if either finds anything. Both run after a failure or a
   cancellation too (`if: always()`).
2. **The janitor** (`uat-janitor.yml`, every hour at :17, and by hand with an
   optional dry run): deletes every resource group tagged exactly
   `purpose=imas-uat` whose `expires_at` has passed, and lists in the job
   summary what it deleted, what it kept and why. It never looks at a group
   without that tag (the bootstrap group is tagged `imas-uat-state`). A
   tagged group whose name is not `imas-uat-<run_id>`, whose `run_id` tag
   differs from its name, or whose `expires_at` is missing or not an RFC 3339
   time is left alone and reported as a warning. Each group is read again
   just before it is deleted. A failed deletion fails the janitor run.
3. **The budget alert** (bootstrap): mails at 50 % and 90 % of the monthly
   budget and at 100 % forecast. It stops nothing.

Not removed by any of these: the run's state blob (the bootstrap's lifecycle
rule deletes it 30 days after its last change), the bootstrap group itself,
and `NetworkWatcherRG` if Azure created it (free, shared, untagged).

### Cleaning up by hand

```sh
az group list --tag purpose=imas-uat -o table                 # every UAT group and its tags
az group show -n imas-uat-<run_id> --query tags                # check purpose=imas-uat first
uat/tofu/destroy.sh <run_id>                                   # destroy and check
uat/scripts/verify-teardown.sh <run_id>                        # check again
az resource list --tag run_id=<run_id> -o table                # must be empty
```

## Reading a failure

Start with the job: the failed step names the piece (the table under "The
pieces" says which directory owns it). Steps before **Tests** are setup: a
failure there is an environment, chart, package or script problem, not a test
result, and there is no report.

When the tests ran, the job summary and `summary.txt` have one line per
scenario, OS and tenant:

```
STATUS ID                     OS       TENANT  SECONDS  DETAIL
PASS   C1                     ubuntu   1           4.2
FAIL   C2                     windows  2          31.0  [C2 os=windows tenant=2 vm=t2-win step=check the item] FAIL: want ...
SKIP   X5                     -        -           0.0  a plaintext cmd.run or cook can only reach a sprout through the bus ...
```

Every failure message starts with `[<id> os=<os> tenant=<n> vm=<vm>
step=<step>]`. Read the pattern across the lines:

| Pattern | Likely cause |
|---|---|
| One OS fails in both tenants (say `windows` in 1 and 2) | The package, the Ansible role or the sprout on that OS |
| One tenant fails on every OS | Tenant setup or scoping: its Keycloak binding, its keys, its bus account |
| One VM only | That host: look at its enrolment in the job log, then `vmctl.sh run <vm> ...` on a kept environment |
| Everything fails, or `TestMain` fails | The stack or the material: saasapi, Keycloak, the CA, a tenant not bound (`uat/tests/README.md`) |
| X or T scenarios fail across the board | Auth and isolation: these are the gate's point; treat as a product finding first |

`junit.xml` loads in any JUnit viewer; `events.json` is the full `go test
-json` stream with every test's output. Skips are always listed with their
reason (some are by design: T3, part of T4 to T6, S6 on Windows, X5; see
`uat/tests/README.md`, "What can't be asserted from outside").

**No silent green**: `run.sh` fails when no test of the tier ran, when a
catalogue scenario of the tier neither ran nor was skipped with a written
reason, when a skip has no reason, or when a package failed outside a test. A
green run therefore always ran or explained every scenario of its tier.

## How the suite itself is validated

The gate is only worth something if it fails when the product is broken.
It earns trust in layers, in this order:

1. **Static checks and unit tests** in each directory (shellcheck, yamllint,
   actionlint, helm template and lint, tofu validate and test with mocked
   providers, stubbed `az`, fake saasapi and Keycloak, an in-memory fake stack
   the whole catalogue runs green against). They prove plumbing, not the
   product. `go test ./...` runs most of them.
2. **The local rig** (`uat/lite`, UAT.8): the hub scripts and the smoke and
   core tiers on one machine with Docker, Linux sprouts only, for free and in
   minutes. Debug the tests there before spending on Azure. Windows scenarios
   appear there as skipped with the reason, never as passed.
3. **A smoke run in Azure with `keep_hours` set** (say 2): the first Azure
   runs are `tier=smoke`, kept, so a failure can be looked at; widen to
   `core`, then `resilience`, then `all` as each goes green.
4. **A known bad release must fail.** Run against `v0.1.0-rc.3`, whose Linux
   packages are broken (a versioned binary name and none of the config,
   signing keys or state directories). The run must **fail at the install**
   (the enrolment step) **or at S1**. If it passes, the gate is broken: stop
   and find out why before trusting any green run.
5. **The first good release must pass.** Then run against `v0.1.0-rc.4`, which
   must pass the same tier.
6. **No silent green** (above) holds on every run.

Only after 4 and 5 should the gate be wired to a trigger (on a published
release, or on a schedule); the workflow deliberately has neither today.

## Cost

**Guesses, not checked against Azure's price list for the region; confirm with
the pricing calculator and watch the budget alert.** From section 4h:

| Item | Rough cost |
|---|---|
| The two hubs (D8s_v5 core, D2s_v5 DMZ) | about $1 an hour together |
| The HA hubs instead (3 x D4s_v5 core, 3 x D2s_v5 DMZ, 4 Standard load balancers) | about $2 an hour together (18 vCPU against 10) |
| The six sprouts (all Standard_B2ls_v2) | a few cents an hour |
| Azure Bastion, Standard SKU | about $0.25 to $0.30 an hour |
| Nine Standard public IPs, disks, DNS zone | cents an hour |
| A smoke or core run (60 to 90 minutes) | a few dollars |
| A tier `all` run (up to 6 hours) | up to about $10 |
| A kept environment | about $1.50 an hour until the janitor deletes it |

The janitor costs about a minute of GitHub-hosted runner time an hour (about
12 hours a month), which counts against Actions minutes on a private
repository.

## Licences

The gate adds no dependency to any released artifact. Tools it runs:
OpenTofu and the azurerm, random and tls providers (MPL-2.0), the Azure CLI
and its extensions (MIT), k0s, k0sctl, kubectl, cert-manager,
local-path-provisioner, Helm and Keycloak (Apache-2.0), Ansible (GPL-3.0,
controller tooling), pywinrm (MIT), and in the environment PXC (GPLv2) and
OpenBao (MPL-2.0) (recorded exceptions), RustFS (Apache-2.0, the single-node
run's object store), Versity Gateway (Apache-2.0, the HA run's, design D18) and
busybox (GPL-2.0, UAT only, pending owner confirmation). The workflows use the
GitHub actions `actions/*`, `azure/login`, `azure/setup-helm` and
`opentofu/setup-opentofu`, which run on the runner only (their licences were
not checked here; none is shipped). actionlint (MIT) and yamllint (GPL-3.0)
are test tools only.
