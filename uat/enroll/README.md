# uat/enroll: tenants and sprout enrolment for the UAT gate (UAT.4)

This directory creates the two UAT tenants through saasapi, mints one
one-time enrolment key per sprout in that sprout's own tenant, and enrols the
six sprouts (or the local rig's four) with the published packages, using the
existing `ansible/site.yml` and its roles. It then waits until farmer reports
every sprout connected. It follows the Shared contract in plan section 4h
(`docs/claude-code-parallel-build-plan.md`). The infrastructure (UAT.1) and
the hubs (UAT.2, UAT.3a, UAT.3b) were written in parallel, so this code
follows the contract rather than their files. **None of it has run against
a real stack**: the agent sandbox can't reach Azure or the registries.

| File | What it does |
|---|---|
| `enroll.sh` | The wrapper: runs the steps below in order. Each step is safe to repeat |
| `create-tenants.sh` | Step 1: tenants 1 and 2 (`POST /v1/tenants`, polled until `active`), and one key per sprout (`max_uses: 1`) |
| `gen-inventory.py` | Step 2: the Ansible inventory for `ansible/site.yml` |
| `playbooks/seed-sproutid.yml` | Step 3: gives the sprouts of each OS the same sprout ID in both tenants |
| `ansible/site.yml` (not here) | Step 4: installs the pinned package, enrols, and runs `imas_verify` (the role includes it) |
| `playbooks/collect.yml` | Step 5: runs `imas_verify` again, then records each sprout's enrolled ID |
| `wait-connected.sh` | Step 6: farmer's view through saasapi, until every sprout is connected |
| `core-token.sh` | The token hook for the core hub: binds each new tenant with `uat/hub/core/bind-tenant.sh`, then prints a token (see "Tokens and the tenant id") |
| `lib.sh` | Shared helpers: saasapi calls that keep credentials off command lines |
| `requirements.yml` | Ansible collections for the controller |

## Running it

```sh
pip install 'ansible-core>=2.15' pywinrm        # pywinrm: Windows sprouts only
ansible-galaxy collection install -r uat/enroll/requirements.yml

uat/enroll/enroll.sh \
  --uat uat.json --access state/access.json --state state/enroll \
  --release-tag v0.1.0-rc.4 \
  --ssh-key state/id_uat --winrm-password-file state/winrm-password \
  --core-state state --core-kubeconfig state/core.kubeconfig \
  --endpoints state/endpoints.json               # see "Tokens and the tenant id"
```

| Input | From | Notes |
|---|---|---|
| `--uat` | `tofu output -json uat` (UAT.1), or the local rig (UAT.8) | The contract's object: `run_id`, `dmz.fqdn`, `core.fqdn`, and `sprouts` keyed by VM name with `tenant`, `os`, `connection`, `admin_user` |
| `--access` | `uat/access/tunnels.sh open` (UAT.1), or the local rig (UAT.8) | Required. For each VM name, `host` (127.0.0.1 through a tunnel) and `ssh_port` or `winrm_port`. A top-level map or one under `vms` is accepted |
| `--release-tag` | the workflow input | `vX.Y.Z` or `vX.Y.Z-rc.N`. Anything else, including `latest`, is refused |
| `--ca-file` | the UAT CA (UAT.2); default `core.json`'s `ca_file` with `--core-state` | Sprouts pin it (`sproutrootca`, `sproutrootcatofu: false`); curl verifies saasapi with it too |
| `--ssh-key` | per run, sensitive (UAT.1) | Linux sprouts over SSH |
| `--winrm-password-file` or `--winrm-password-dir` | per run, sensitive (UAT.1) | One password for every Windows VM, or a directory with one file per VM name |
| `--core-state`, `--core-kubeconfig`, `--endpoints` (and `--core-scripts`, default `uat/hub/core`) | the `<state-dir>`, `<kubeconfig>` and `<endpoints.json>` the core hub's scripts took (UAT.3b) | Select `core-token.sh` as the token command; see below |
| `--internal-auth-file` | default `<core-state>/core/sensitive/internal-auth-secret` (UAT.3b) | saasapi's `X-Internal-Auth` shared secret, required on every route |
| `--token-cmd`, or `--token-t1` and `--token-t2` | instead of `--core-state` | See below |
| `--saasapi-url` | default `core.json`'s `saasapi_url`, else `https://<core.fqdn>` | `scheme://host[:port]` with no path; `/v1/...` is appended |
| `--envoy-host`, `--envoy-port` | default `dmz.<private_dns_zone>`, i.e. `dmz.uat.imas.internal`, and `8443` | Written as `farmerinterface` and `farmerapiport`. The DMZ's private DNS name, not its public FQDN (owner decision, 2026-10-06; see "What the inventory sets") |
| `--bus-url` | optional | Pins `busurls`. By default the sprout uses the `nats_urls` farmer returns (`bus.sproutBusURLs`) |

Everything is written below `--state` (mode 0700):

| File | Secret? | Contents |
|---|---|---|
| `run.json` | no | `run_id` and the saasapi URL, so a state directory is never reused for another run |
| `tenants.json` | no | `{"1": {"tenant_id", "name", "status"}, "2": ...}`, the form `uat/tests/harness` reads |
| `keys.json` | no | Per VM: tenant, tenant id, `key_id`, `expires_at` |
| `keys/<vm>.key` | **yes**, 0600 | The `registration_key` (join token) |
| `inventory/` | no | `hosts.yml`, `group_vars/`, `plan.json` (what each sprout should become) |
| `ssh/known_hosts` | no | This run's host keys |
| `enrolled.json` | no | Per VM, the sprout ID it enrolled with (from `collect.yml`) |
| `sprouts.json` | no | **The hand-off for the tests**: `{"<vm>": {"sprout_id", "asset_id"}}`, exactly the fields `uat/tests/harness` accepts (it reads the file strictly) |
| `sprouts-detail.json` | no | The same with `tenant`, `tenant_id` and `os`, for people |

`tenants.json` and `sprouts.json` have the names and shapes `uat/tests/harness`
reads from its material directory, so the workflow (UAT.6) can copy them
straight in. They match UAT.5's draft as it stood when this was written:
check them again once UAT.5 merges.

Nothing secret is printed or put on a command line. The scripts print tenant
ids and key ids. curl reads the shared secret and the token from a mode 0600
header file (`-H @file`), which is deleted after each call. The inventory
holds only file paths. The enrolment key, the CA and the WinRM password reach
Ansible through `lookup('ansible.builtin.file', ...)` at run time, and the
SSH key through `ansible_ssh_private_key_file`. The role writes the key to
the host with `no_log`. Don't upload `--state` as a workflow artifact: it
holds the keys. Upload `sprouts.json`, `sprouts-detail.json`, `tenants.json`,
`run.json` and `keys.json` only.

## Tokens and the tenant id

saasapi accepts a tenant-scoped call only when the Keycloak token's
`organization.id` equals the path's `tenant_id` (docs/api/saasapi.md,
"Authentication"). It **generates** that id itself (`t_` plus 16 characters)
when `POST /v1/tenants` succeeds. A token minted before the tenant exists
therefore can't carry the right `organization.id`. Someone has to map the
tenant's Keycloak users to the new id between creating the tenant and using
it.

**Owner decision (2026-10-06):** the core hub (UAT.3b, `uat/hub/core`) owns
that binding. Its `bind-tenant.sh` is called once per tenant. It sets the
user attribute behind `organization.id` on `t<N>-admin` and `t<N>-reader`,
with kcadm.sh inside the Keycloak pod, and records the binding in
`<state>/core/out/core.json`. This directory reads the files the core hub
writes, in that hub's shape:

- `out/core.json`: `saasapi_url`, `ca_file`, `keycloak.token_url` and
  `client_id`, the `users` with their tenant and roles, and `tenants`
  (the bindings).
- `sensitive/credentials.json`: the test client's secret and the users'
  passwords.
- `sensitive/internal-auth-secret`.

`keycloak.json`, which the core hub also writes, is for the harness's
scratch users and isn't read here.

- `--core-state DIR --core-kubeconfig FILE --endpoints FILE` (in
  `enroll.sh`) runs `core-token.sh` as the token command. For each tenant it
  calls `bind-tenant.sh <kubeconfig> <endpoints.json> <state> N <tenant_id>`
  once, the first time it sees a tenant id that `core.json` doesn't bind
  yet. It refuses a `core.json` that binds the tenant to another id. Then it
  takes the token of the tenant's admin (the user holding the write role)
  with a password grant on `keycloak.token_url`. It has been tested against
  a stand-in `bind-tenant.sh` and a fake token endpoint, and the files'
  shapes were taken from PR #132's `install.sh`.
- `--token-cmd EXE`: `EXE <tenant number> <tenant id>` prints one access
  token for that tenant's admin user (both roles), whose `organization.id`
  is `<tenant id>`. Before the tenant exists it is called with an empty
  tenant id, and any valid token will do: `POST /v1/tenants` skips the
  organization check. It is called again for every request, so tokens with
  Keycloak's default 5 minute lifetime never go stale during a long wait.
- `--token-t1 FILE --token-t2 FILE`: static tokens, read again on every
  request. They work only if their `organization.id` already equals the
  tenant id, for example on a re-run once the mapping has been done. If it
  doesn't match, `create-tenants.sh` stops with exit code 3 after creating
  and recording the tenant, and says which id to map. Re-running with fresh
  tokens reuses that tenant; it never creates a second one.

The scripts check the claim locally and print only `organization.id`, never
the token.

## How the sprouts are reached

| `connection` | How | Notes |
|---|---|---|
| `ssh` (Linux, and every sprout of the local rig) | `host:ssh_port` from `access.json` (127.0.0.1 through a tunnel), the per run key, `become: true` | **Host key checking is off**, into a known hosts file of this run only (`StrictHostKeyChecking=no`, `UserKnownHostsFile=<state>/ssh/known_hosts`, and `HostKeyAlias=<vm>` so a key is recorded under the VM name rather than a port). Every tunnel is 127.0.0.1 on some port, the VMs are new every run, and the tunnel endpoint is Azure Bastion reached with the run's Azure login, so there is no earlier key to check against |
| `winrm` (Windows) | `https://127.0.0.1:<winrm_port>`, NTLM, the admin user and password | **Certificate validation is ignored** (`ansible_winrm_server_cert_validation: ignore`). Through a tunnel the name we connect to is always 127.0.0.1, which never matches the certificate's name, and the WinRM listener's certificate is self-signed per VM. TLS still encrypts, and NTLM authenticates the user. This assumes UAT.1 gives Windows a WinRM HTTPS listener and makes the admin user the built-in Administrator, which Azure does for its admin account; any other local administrator is filtered by UAC over the network |
| `docker` | refused | **Owner decision (2026-10-06):** the local rig connects over SSH, its containers running sshd, so it writes `connection: ssh` and its own `access.json`. There is no docker connection plugin, and `community.docker` is not used |

## What the inventory sets

- `sprouts` (every host): `imas_farmer_host` is Envoy's private DNS name,
  `dmz.uat.imas.internal`, and `imas_farmer_api_port` is 8443. This
  follows the owner's decision of 2026-10-06 to put the private names in
  the Shared contract. UAT.1 creates them as an Azure Private DNS zone
  pointing at the hubs' private addresses, and sprouts can reach Envoy
  only there. If the uat JSON carries a top-level `private_dns_zone`, the
  name is `dmz.<that zone>`; `--envoy-host` overrides it. Only the sprouts
  resolve this name: the runner still reaches saasapi on the core's public
  FQDN. `imas_sprout_root_ca` is the UAT CA, and
  with it the role writes `sproutrootca` and sets `sproutrootcatofu: false`.
  `imas_sprout_package_state` is `present` and `imas_verify_timeout` is 600.
  The role's default registries are kept: Buildkite `yogzblr`'s `imasdeb`,
  `imasrpm` and `imasnget`.
- `linux_sprouts`: `imas_sprout_version` is the repository's package version
  for the tag: `v0.1.0-rc.4` is `0.1.0~rc.4+git` and `v1.2.3` is
  `1.2.3+git`. nfpm writes a prerelease after `~` and goreleaser's
  `version_metadata: git` after `+` (`internal/ingredients/selfupdate/pkgmeta.go`;
  BUILD-STATUS records `0.1.0~rc.1+git`). apt gets `imas-sprout=<v>`, dnf
  gets `imas-sprout-<v>`.
- `windows_sprouts`: `imas_sprout_version` is the NuGet version, `0.1.0-rc.4`
  or `1.2.3`. `--windows-msi-url` and `--windows-msi-sha256` are optional:
  they install that MSI instead of the feed's.
- Per host: `imas_join_token` (the lookup), `uat_tenant`, `uat_os`,
  `uat_sprout_id`, `uat_asset_id`. Extra groups: `tenant_1`, `tenant_2`,
  `os_ubuntu`, `os_alma`, `os_windows`, and `conn_*`.

Requirement 20 holds: the sprout gets no artifact URL. It installs from the
repository the role configures, and its self-update repository is the same
one.

## Sprout IDs: where they come from, and what the tests should assume

The sprout asks farmer for the ID in its config key `sproutid`. If that key
is empty, it asks for its hostname, normalized: lowercase, with `.` and `_`
turned into `-` (`internal/pki/pki.go`, `GetSproutID`, `createSproutID`,
`NormalizeSproutID`). farmer grants the ID as asked unless another sprout in
the **same tenant** already holds it, in which case it adds `_1`, `_2`, and
so on (`resolveEnrollSproutID`, checked per tenant only). The sprout writes
the ID it got back into `sproutid` (`cmd/sprout/main.go`).

The `imas_sprout` role has **no variable for `sproutid`**. It does keep every
config key it doesn't manage, though, and both packages keep an existing
config file:

- the deb and rpm mark `/etc/imas/sprout` `config|noreplace`, so dpkg keeps
  it under the apt module's `force-confold` and rpm writes its own copy as
  `.rpmnew`;
- the MSI's config component is `NeverOverwrite`.

So `playbooks/seed-sproutid.yml` writes `sproutid: <id>` into the config
file before the role runs. On Windows it first creates `%ProgramData%\imas`
with the DACL the MSI and the sprout use. It only touches hosts that haven't
enrolled. The IDs are `ubuntu-01`, `alma-01` and `win-01`, the same in tenant
1 and tenant 2. A tenant with several VMs of one OS gets `-02` and up, in VM
name order. `collect.yml` then reads back the ID each sprout enrolled with
and fails if it isn't the expected one.

**The tests should assume** the IDs in `<state>/sprouts.json`. In a normal
run that's `ubuntu-01`, `alma-01` and `win-01` in both tenants, each
addressed by its own `tenant_id` and its asset id `uat-<run_id>-<vm>`. With
`--no-seed-sproutid` the IDs are the normalized hostnames UAT.1 gives the
VMs (for example `t1-ubuntu`), which differ per tenant: the run then does
not test scenario S2. The tests should read `sprouts.json` rather than
assume either form.

## Asset links

`wait-connected.sh` links each sprout to the asset id `uat-<run_id>-<vm>` in its
own tenant (`POST .../sprouts/{sprout_id}/asset-link`: 201, or 200 when the
link already exists). It then polls `GET .../sprouts?asset_ids=...` until
every sprout is `accepted` and `connected`. The asset id is the same one
`uat/tests/harness` uses by default (`DefaultAssetID`), so when the harness
links it again it gets 200, not a 409. That flag is farmer's view: the
Valkey heartbeat key farmer keeps per `(tenant_id, sprout_id)` from the bus's
connect events, which saasapi reads. It stays false if saasapi has no
`SAASAPI_VALKEY_ADDRS`. The batch-action scenarios address sprouts by asset
id, so the links have to exist anyway. Scenario S3 ("new link: 201") has to
unlink first (`DELETE .../asset-link`) or use an asset id of its own.

`imas_verify` alone can't prove the connection here. Envoy serves both
enrolment and the bus on 8443, which is the role's documented blind spot:
the enrolment request's own connection can look like a bus connection for up
to 90 seconds. Farmer's view doesn't have that blind spot.

## Windows with a pre-release tag

**Yes, UAT can enrol Windows with a pre-release tag** such as `v0.1.0-rc.4`,
with two conditions:

1. The pre-release must be on the `imasnget` feed. `publish-packages.yml`
   skips pre-releases when a release is published and publishes one only by
   `workflow_dispatch`. BUILD-STATUS records that rc.4 went through it, NuGet
   included.
2. The version must be pinned, which `gen-inventory.py` always does
   (`imas_sprout_version: 0.1.0-rc.4`). With a pinned version, the role
   builds the `.nupkg` URL itself (`<base>/imas.sprout.windows.msi/0.1.0-rc.4/...`).
   Its "newest" lookup, which skips pre-releases, isn't used.

The MSI's ProductVersion is `0.1.0` with no rc suffix. That doesn't matter
for a fresh VM: `win_package` keys on the ProductCode, which is new for
every build.

What a pre-release can't do on Windows:

- **Self update** (scenario L5) to a pre-release target is refused by
  design. The sprout refuses it (`ErrPrereleaseOnWindows`,
  `internal/ingredients/selfupdate/pkgmeta.go`, PR #88, a follow-up to #86), and saasapi
  plans no MSI rows for a pre-release (`fleet_update_dispatch.go`).
- **Package upgrade** (L4) between two pre-releases of the same X.Y.Z is a
  same-version MSI upgrade (`AllowSameVersionUpgrades`), which proves nothing
  about version ordering.

L4 and L5 belong to UAT.7, which should skip Windows for them with that
reason whenever the target is a pre-release.

If the feed lacks the `.nupkg`, there are two options:

- Publish it with `workflow_dispatch` of Publish packages for that tag.
- Pass `--windows-msi-url <the release's MSI asset> --windows-msi-sha256 <from checksums.txt>`.
  The role then installs that MSI and points the sprout's update repository
  at the asset's directory (`flat`). That's fine for enrolment, but not for
  update tests.

## AlmaLinux 9 compared with RHEL 9, for the role

AlmaLinux stands in for RHEL, which needs a subscription to fetch. For the
role the two take exactly the same path:

- `ansible_os_family` is `RedHat` and `ansible_pkg_mgr` is `dnf`, so
  `repo_yum.yml` adds the `imasrpm` repository (signed metadata,
  `repo_gpgcheck`; unsigned packages).
- dnf installs `imas-sprout-0.1.0~rc.4+git`.
- systemd runs the unit, and `$basearch` is `x86_64`.
- The role never reads `ansible_distribution`.
- The sprout rpm declares no dependencies, so nothing comes from the
  distribution's own repositories.
- SELinux is enforcing on both images, and the unit runs unconfined either
  way.

What AlmaLinux does not cover:

- RHEL's subscription and Azure RHUI repositories. The role doesn't use
  them, but a customer's RHEL host must reach `packages.buildkite.com`
  alongside them.
- RHEL's own image defaults. Azure's RHEL images ship different cloud
  tooling (RHUI client, insights), and FIPS or a stricter crypto policy may
  be turned on there. A FIPS host is untested by this gate.
- Red Hat's support statement.

The Molecule scenario covers the same rpm path on Rocky 9.

## Findings for the role owner (no role was changed)

1. `imas_sprout` has no variable for `sproutid`. This directory works around
   it with `seed-sproutid.yml`. A role variable (for example `imas_sprout_id`,
   written only while the host isn't enrolled, like `jointoken`) would replace
   the seed play and make a fixed ID a supported thing for customers too.
2. `imas_verify` can pass on the enrolment connection when enrolment and the
   bus share Envoy's port (documented in ansible/README.md).
   `wait-connected.sh` adds farmer's view to cover it. The role could check
   the connection against the bus URL it actually dials, or hold longer than
   90 seconds when the two share a host and port.
3. Windows: with `imas_sprout_version` empty, the role installs the newest
   **final** release. On a feed holding only pre-releases it fails ("no
   release of ..."), and with an older final release present it silently
   installs that one instead of the pre-release under test. UAT always
   pins, so this is a note, not a blocker.

## Contract gaps and assumptions (open questions)

- **Answered by the owner (2026-10-06):**
  - **Tenant binding.** `uat/hub/core/bind-tenant.sh` binds each tenant
    once, and this directory reads `core.json` and `credentials.json` in
    the core hub's shape (`core-token.sh`).
  - **Shared secret.** It comes from the core hub's sensitive directory.
  - **`community.docker`.** It is dropped.
  - **Install order.** Core first, then the DMZ. That needs no change here:
    enrolment runs after both hubs either way.
  - **Who binds.** UAT.4 binds tenants 1 and 2, here through
    `core-token.sh`. The harness binds only tenants the run creates that
    aren't in `core.json`.
  - **The local rig's connection.** SSH, with sshd in the containers; no
    docker connection plugin.
  - **Private DNS names.** `dmz.uat.imas.internal` and
    `core.uat.imas.internal` go in the Shared contract, and
    `farmerinterface` uses the DMZ name.
- **Envoy's certificate (UAT.3a, UAT.2)**: sprouts pin the UAT CA with
  `sproutrootcatofu: false` and dial `dmz.uat.imas.internal`. Enrolment
  fails unless Envoy's downstream certificate carries that name as a SAN,
  which the decision assigns to the other briefs.
- **`access.json` shape (UAT.1)**: assumed `{"<vm>": {"host", "ssh_port" | "winrm_port", ...}}`,
  or the same under `vms`.
- **saasapi URL (UAT.3b)**: assumed `https://<core.fqdn>` with routes at
  `/v1`, while Keycloak shares 443 on another path. Override with
  `--saasapi-url`.
- **Envoy's external port (UAT.2, UAT.3a)**: assumed 8443. Override with
  `--envoy-port`.
- **WinRM (UAT.1)**: assumed an HTTPS listener, with NTLM for the built-in
  Administrator.
- **Local rig (UAT.8)**: assumed to write `connection: ssh` for every
  sprout, plus an `access.json` with each container's `host` and `ssh_port`,
  and to accept the per run SSH key for `admin_user` (root works:
  `become` is harmless there). Its containers also need systemd as PID 1
  for the role's checks. They must resolve `dmz.uat.imas.internal`, or the
  rig passes `--envoy-host` with a name they can resolve, which Envoy's
  certificate must then carry.

## Tests

```sh
python3 -m unittest discover -s uat/enroll/tests -p 'test_*.py'   # the inventory generator
bash uat/enroll/tests/test_scripts.sh                            # the scripts, against a fake saasapi, Keycloak token endpoint and bind-tenant.sh
shellcheck -x uat/enroll/*.sh uat/enroll/tests/*.sh uat/enroll/tests/fake/{token-cmd,ansible-playbook,ansible-galaxy,hub-core/bind-tenant.sh}
yamllint -c uat/enroll/.yamllint uat/enroll
(cd uat/enroll && ANSIBLE_ROLES_PATH=../../ansible/roles ansible-lint)
```

The generator tests use `testdata/uat.json` (the Azure layout) and
`testdata/uat-lite.json` (the local rig, over SSH). They check that both tenants get
the same sprout ID per OS while IDs stay unique within a tenant, check the
pins and connections, and check that no secret reaches the inventory. When
`ansible-inventory` is installed, it also loads the result. The script tests
use a stand-in for curl that answers as saasapi and Keycloak's token endpoint
do, and a stand-in `bind-tenant.sh`. When the real
`ansible-playbook` is installed and the tests run as root, they also run
`seed-sproutid.yml` and `collect.yml` against localhost with temporary
paths.

## Licences

Nothing here is a dependency of a released artifact.

- Ansible and its collections (`ansible.windows` and `community.general`,
  both already used by `ansible/`) are GPL-3.0-or-later controller tooling.
  No other collection is used: `community.docker` was dropped (owner
  decision, 2026-10-06).
- `pywinrm` (Windows sprouts) is MIT.
