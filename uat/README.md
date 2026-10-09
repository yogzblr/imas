# The Azure UAT gate (`uat/`)

The release acceptance gate of imas: one GitHub Actions run builds a small,
production-shaped environment in Azure from a **published release**, enrols
real sprouts in two tenants, runs the acceptance tests against it, uploads the
report and tears everything down. The design is section 4h of
`docs/claude-code-parallel-build-plan.md` (the Shared contract, the scenario
catalogue, the owner prerequisites); this page is the owner's guide to it.

> [!IMPORTANT]
> **The gate has never run.** Every piece was written by agents that could not
> reach Azure, the registries or a cluster. Static checks, unit tests and
> tests against stubs and fakes ran (each directory's README says which);
> nothing ran end to end. Expect fix rounds after the first real runs. The
> workflow and the janitor are **flagged for security review** (they hold
> Azure credentials): treat them as ready for review, not as done.

## What the gate proves, and what it does not

| Proves (when green) | Does not prove |
|---|---|
| The published Helm charts of the release install and run on Kubernetes (k0s): `deploy/helm/farmer` on core (farmer, saasapi, PXC, Valkey, OpenBao) and `deploy/helm/nats` on the DMZ (farmerbus, Envoy), with the release's own images and never `latest` | High availability: every hub is one node, every workload one replica |
| The published OS packages install from the Buildkite repositories with the Ansible role, on Ubuntu 24.04, AlmaLinux 9 and Windows Server 2022 Core | PXC clustering (one PXC node), the clustered bus, failover |
| Enrolment through Envoy, with a pinned UAT CA, one-time keys, and sprouts reaching the bus only through Envoy | Real RHEL: AlmaLinux 9 stands in for it (same dnf and rpm path; no subscription, RHUI or FIPS; see `uat/enroll/README.md`) |
| Tenant isolation: two tenants with the same sprout IDs (`ubuntu-01`, `alma-01`, `win-01`) resolve to different machines, and nothing crosses (T6, S2, S4, R3, X4) | SUSE and zypper: out of scope for this gate (add one more tenant VM later) |
| Auth: Keycloak tokens checked by saasapi (issuer, audience, roles, `organization.id`), the BFF shared secret, Envoy's `jwt_authn` gate, sealing (X1 to X5) | The internet path: sprouts reach Envoy on the DMZ's private address, and Envoy sits behind no application gateway or public load balancer |
| Commands, recipes and cooks on every OS (C1 to C8, R1 to R6), resilience to reboots and restarts (L1 to L3), and with UAT.7 every ingredient method and the package upgrade (I.*, L4) | Scale and load, the web UI, key expiry (the minimum is an hour; unit tests cover it), the self update cycle (L5) unless its dispatch flags are on, a Windows host with Desktop Experience |

What runs where (section 4h, "The shape"): one resource group per run,
`imas-uat-<run_id>`, with a VNet of four subnets, an Azure Bastion (Standard,
native tunnelling), `uat-dmz` (single-node k0s, the nats chart), `uat-core`
(single-node k0s, the farmer chart plus MinIO and Keycloak, both UAT only) and
six sprouts: `t1-ubuntu`, `t1-alma`, `t1-win`, `t2-ubuntu`, `t2-alma`,
`t2-win`. SSH, WinRM and the Kubernetes API are reached only through Bastion
tunnels; only Envoy (8443 on the DMZ) and 443 on core are open, and only to
the runner's own address.

## The pieces

| Directory | Brief | What |
|---|---|---|
| `uat/tofu` | UAT.1 | The OpenTofu module of one run, the bootstrap stack (state storage, budget), `destroy.sh` |
| `uat/access` | UAT.1 | `tunnels.sh` (Bastion tunnels) and `vmctl.sh` (reboot, stop and start a sprout, run a command): every Azure call of the gate |
| `uat/k0s` | UAT.2 | k0s on both hubs, local-path storage, cert-manager, the per-run UAT CA, the endpoints file |
| `uat/hub/core` | UAT.3b | The core hub: farmer chart, OpenBao bootstrap, MinIO, Keycloak, the edge |
| `uat/hub/dmz` | UAT.3a | The DMZ hub: nats chart (farmerbus, Envoy), its exposure and `check.sh` |
| `uat/enroll` | UAT.4 | Tenants 1 and 2, one-time keys, the Ansible inventory, enrolment, waiting for farmer to see every sprout |
| `uat/tests` | UAT.5 | The acceptance suite (`run.sh`, the harness, the report) |
| `uat/cases`, `uat/tests/ingredients` | UAT.7 | Ingredient conformance and L4/L5 (not merged at the time of writing) |
| `uat/lite` | UAT.8 | The local rig (not merged at the time of writing) |
| `uat/scripts` | UAT.6 | The workflow's helpers: input checks, run id, runner address, test material, artifact allowlist, teardown check, janitor |
| `.github/workflows/uat.yml`, `uat-janitor.yml` | UAT.6 | The gate and the janitor |

## Prerequisites (once)

From section 4h, "Owner prerequisites", plus what the janitor needs. Run the
`az` commands in Azure Cloud Shell as the subscription Owner. Keep this
subscription for UAT only: the GitHub identity is Contributor on all of it.

1. **Resource providers**: `Microsoft.Compute`, `Microsoft.Network`,
   `Microsoft.Storage`, `Microsoft.Authorization`, `Microsoft.Consumption`
   (`az provider register --namespace ...`).
2. **The GitHub OIDC identity** `imas-uat-github`: an app registration and its
   service principal, Contributor on the subscription, and a federated
   credential for `repo:yogzblr/imas:environment:uat` (the commands are in
   section 4h). No client secret exists anywhere.
3. **AlmaLinux marketplace terms**, once per subscription:
   `az vm image terms accept --publisher almalinux --offer almalinux-x86_64 --plan 9-gen2`.
   Confirm the three image URNs first with `az vm image list --all ...`
   (`uat/tofu/README.md`, Inputs).
4. **Quota and sizes** in the region (default `centralindia`):
   Standard_D2s_v5, Standard_D8s_v5, Standard_B1ms and Standard_B2s available;
   18 vCPUs in all, 10 in the Dsv5 family and 8 in the B family. Two runs at
   once (two different releases) need twice that.
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
     "subject": "repo:yogzblr/imas:environment:uat-janitor",
     "audiences": ["api://AzureADTokenExchange"]}'
   ```

   This reuses `imas-uat-github`, so the janitor holds Contributor without a
   reviewer; only a change merged to `main` can change what it runs. A
   narrower alternative is a second application with a custom role that can
   read and delete resource groups and what is in them (open question in the
   UAT.6 PR).
8. **The release under test** must have a published GitHub release, and its
   packages and charts must be in Buildkite (`publish-packages.yml` ran to the
   end). A pre-release is not published automatically: run Publish packages
   by hand for it, or the Windows sprouts cannot find the NuGet package
   (`uat/enroll/README.md`, "Windows with a pre-release tag").

## Running it

Actions, **UAT gate**, Run workflow on `main`, or:

```sh
gh workflow run uat.yml --ref main -f release_tag=v0.1.0-rc.4 -f tier=smoke -f keep_hours=2
```

Then approve the `uat` deployment when GitHub asks (the required reviewer).

| Input | Default | Meaning |
|---|---|---|
| `release_tag` | required | `vX.Y.Z` or `vX.Y.Z-rc.N`. It must be a tag with a published (not draft) release; the chart, the images, the packages and the CLI all come from it |
| `region` | `centralindia` | Azure region |
| `keep_hours` | `0` | `0` destroys at the end. Above 0 (at most 168) skips the destroy and keeps the environment for debugging; the janitor deletes it later |
| `tier` | `all` | `smoke` (about 10 minutes of tests), `core` (includes smoke), `resilience`, `ingredients`, `lifecycle` or `all` |
| `upgrade_from_tag` | empty | An earlier release for L4 (the package upgrade, UAT.7). Empty: L4 skips with that reason. Passed to the tests as `IMAS_UAT_UPGRADE_FROM_TAG` |
| `scenarios` | empty | Scenario ids of the tier, separated by spaces or commas (`C1 X4`), passed to `uat/tests/run.sh`. Ingredient ids (`I.file.managed`) go in an `ingredients` run of their own |

What the run does, in order (each step is a step of the job, so the failed one
names the piece):

1. **Check inputs and variables** (`uat/scripts/check-inputs.sh`): the three
   Azure variables are set and are GUIDs; `release_tag` (and
   `upgrade_from_tag`) is a release tag that exists and has a published
   release; region, `keep_hours`, tier and scenario ids are well formed. Every
   problem is reported at once, by name, and nothing is created.
2. Tools: Go, Python, OpenTofu 1.11.5, Helm v4.3.0, k0sctl and kubectl at
   `uat/k0s` pins, Ansible with pywinrm.
3. **Azure login** by OIDC (`azure/login`), then the **runner's public
   address** (`runner-cidr.sh`: three services asked over IPv4, at least two
   must answer and all must agree, and the address must be public), and a
   fresh **run_id** (`run-id.sh`: 8 characters, a letter first).
4. **tofu apply** (`uat/tofu`), state in the bootstrap account at
   `imas-uat/<run_id>.tfstate`. The per-run SSH key and Windows password go to
   0600 files on the runner, masked in the log.
5. **Bastion tunnels** (`uat/access/tunnels.sh open`, after `az extension add`
   for `bastion` and `ssh`).
6. **k0s** on both hubs (`uat/k0s/bootstrap.sh`).
7. **Core hub** (`uat/hub/core/install.sh`),
   then the **DMZ hub** (`uat/hub/dmz/install.sh`, seeds copied from core's
   Secret), then **core's second half** (`uat/hub/core/finish.sh`: farmer and
   saasapi need the DMZ bus, so it waits for them, registers the sprout
   release and runs core's `check.sh`) and the **DMZ check** (`check.sh`, before enrolment because it
   empties and then waits out Envoy's enrolment rate limit). Core comes first
   because the bus needs core's seeds when it starts.
8. **Tenants and enrolment** (`uat/enroll/enroll.sh`).
9. **Test material** (`uat/scripts/material.sh`) and a second Azure login,
   then **the tests** (`uat/tests/run.sh <tier> [ids]`).
10. Always: **close the tunnels**, **collect and upload** the report and the
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

**Until UAT.7 merges, the tiers `ingredients`, `lifecycle` and `all` fail by
design**: `run.sh` fails a tier whose catalogue scenarios have no test (the
no silent green rule). Use `smoke`, `core` or `resilience` until then.

### Artifacts

| Artifact | Contents |
|---|---|
| `uat-report-<run_id>` | `summary.txt` (one line per scenario, OS and tenant), `junit.xml`, `events.json` (`go test -json`), `build.log` |
| `uat-outputs-<run_id>` | `run.json` (this run's inputs), `uat.json` (tofu output, no credentials), `k0s/endpoints.json`, the UAT CA certificate, the rendered k0sctl files, `hub/core/out/core.json` and `admin.json` (public keys), `hub/harness.json`, `dmz/dmz.json`, `enroll/{run,tenants,keys,sprouts,sprouts-detail}.json` |

Never uploaded: the SSH key, the WinRM password, the kubeconfigs, OpenBao's
unseal keys and root token, the NKey seeds, the bootstrap admin's private
keys, the Keycloak and MinIO credentials, the BFF secret and the enrolment
keys. `collect-artifacts.sh` copies by an allowlist and then scans every copied
file for private keys, kubeconfig credentials, JWTs, NKey seeds and JSON
passwords, secrets, tokens or unseal keys; a match is removed and fails the
step. (`uat/hub/core/README.md` mentions keeping `openbao-init.json` as a
sensitive artifact; the gate does not upload it at all. A kept environment
keeps its unseal keys in the cluster Secret `imas-uat-openbao-unseal`.)

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
# The NSGs admit only the runner's old address. Let yours in (this also moves
# the Envoy and core 443 rules to you); keep the run's release_tag, region,
# keep_hours and run_budget_hours (all in the outputs artifact's run.json).
tofu apply -var run_id=$RUN -var release_tag=<tag> -var region=<region> -var keep_hours=<hours> \
  -var run_budget_hours=<3 or 7> -var runner_cidr=$(curl -4 -s https://api.ipify.org)/32
cd ../..
uat/access/tunnels.sh open /tmp/uat-$RUN.json /tmp/uat-$RUN-access
jq . /tmp/uat-$RUN-access/access.json      # local ports per VM
ssh -i /tmp/uat-$RUN.key -p <ssh_port of uat-core> imasuat@127.0.0.1 sudo k0s kubectl get pods -A
```

The Kubernetes API is on each hub's `kube_port`; `sudo k0s kubeconfig admin`
on a hub prints an admin kubeconfig (point its server at
`https://127.0.0.1:<kube_port>`). The generated passwords (Keycloak users,
MinIO, the BFF secret) are in Kubernetes Secrets on core (`uat/hub/core/README.md`);
OpenBao's unseal keys and root token are in `imas-uat-openbao-unseal` and
`imas-uat-openbao-root`. `uat/access/vmctl.sh` works from your machine with an
`az login`. Close your tunnels with `uat/access/tunnels.sh close /tmp/uat-$RUN-access`
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
| The six sprouts (four B1ms, two B2s) | a few cents an hour |
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
OpenBao (MPL-2.0) (recorded exceptions), RustFS (Apache-2.0, the UAT object store) and
busybox (GPL-2.0, UAT only, pending owner confirmation). The workflows use the
GitHub actions `actions/*`, `azure/login`, `azure/setup-helm` and
`opentofu/setup-opentofu`, which run on the runner only (their licences were
not checked here; none is shipped). actionlint (MIT) and yamllint (GPL-3.0)
are test tools only.
