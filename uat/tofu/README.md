# UAT.1: the Azure side of the UAT gate (`uat/tofu`)

**FLAG FOR SECURITY REVIEW** (cloud credentials, network rules and destroy
semantics). **This module has never been applied.** It was written without
access to Azure: `tofu fmt`, `tofu validate` and `tofu test` with mocked
providers ran (see [Tests](#tests)); no plan or apply has run against a
subscription. Expect fix rounds after the first real run.

It builds, per run, everything in section 4h of
`docs/claude-code-parallel-build-plan.md` ("The shape" and the Shared contract)
in one resource group, `imas-uat-<run_id>`, and destroys it afterwards:

- one VNet `10.60.0.0/16` with subnets `dmz` `10.60.1.0/24`, `core`
  `10.60.2.0/24`, `tenants` `10.60.3.0/24` and `AzureBastionSubnet`
  `10.60.4.0/26`, one network security group per subnet;
- one Azure Bastion (Standard SKU, native client tunnelling on, its own
  Standard public IP), the only path to SSH, WinRM and the Kubernetes API;
- the two hubs, `uat-dmz` and `uat-core`, and the six sprouts, `t1-ubuntu`,
  `t1-alma`, `t1-win`, `t2-ubuntu`, `t2-alma` and `t2-win`, each with its own
  Standard public IP.

`bootstrap/` holds the only pieces that stay up between runs: the state
storage and a budget alert. `destroy.sh` tears a run down and proves nothing is
left. The access scripts (Bastion tunnels, VM control) are in `uat/access`.

Files:

| File | What |
|---|---|
| `versions.tf` | OpenTofu and provider versions, the `azurerm` backend, the provider settings that make destroy complete |
| `variables.tf` | Inputs (below) |
| `main.tf` | Resource group, tags, expiry, per-run SSH key and Windows password, VNet and subnets |
| `dns.tf` | The private DNS zone: `dmz.<zone>` and `core.<zone>` to the hubs' private addresses |
| `network-security.tf` | The four NSGs (rules tabled below) |
| `vms.tf` | Public IPs, NICs, the eight VMs, the WinRM extension, the Bastion |
| `winrm-https.ps1` | What the Windows extension runs: WinRM over HTTPS on 5986 |
| `outputs.tf` | `uat` (the contract object) and the two sensitive credential outputs |
| `destroy.sh` | Teardown helper |
| `bootstrap/` | The persistent stack, applied once by the owner |
| `tests/` | `main.tftest.hcl` (tofu test, mocked providers), `destroy_test.sh` and its stubs |
| `scripts_test.go` | Runs the shell tests, shellcheck and `tofu fmt -check` from `go test ./...` when the tools are on PATH |

## Inputs

From the Shared contract, plus what the brief makes a variable.

| Variable | Default | Notes |
|---|---|---|
| `run_id` | required | 6 to 10 lowercase letters and digits |
| `release_tag` | required | `vX.Y.Z` or `vX.Y.Z-rc.N`. Recorded as a tag only; the hub and enrolment briefs install from it |
| `region` | `centralindia` | The owner confirms sizes and quota there |
| `runner_cidr` | required | One `/32`, the only internet source let in (Envoy, 443 on core, 443 on the Bastion) |
| `keep_hours` | `0` | 0 to 168. Above 0 the workflow skips the final destroy and the janitor deletes the group after `expires_at` |
| `run_budget_hours` | `4` | `expires_at` = time of the first apply + `run_budget_hours` + `keep_hours`, so even a run whose destroy never ran is collected by the janitor |
| `dmz_size`, `core_size` | `Standard_D2s_v5`, `Standard_D8s_v5` | |
| `linux_sprout_size`, `windows_sprout_size` | `Standard_B1ms`, `Standard_B2s` | |
| `dmz_os_disk_gb`, `core_os_disk_gb` | `64`, `128` | Standard SSD |
| `sprout_os_disk_gb` | `30` | Standard SSD; cannot be smaller than the image (30 GB for Ubuntu and the Windows smalldisk image) |
| `ubuntu_image` | `Canonical:ubuntu-24_04-lts:server:latest` | Hubs and Ubuntu sprouts |
| `alma_image` | `almalinux:almalinux-x86_64:9-gen2:latest` | Marketplace image; terms accepted once (section 4h) |
| `alma_image_has_plan` | `true` | Adds the purchase plan (publisher, offer as product, sku as name) |
| `windows_image` | `MicrosoftWindowsServer:WindowsServer:2022-datacenter-core-smalldisk-g2:latest` | |
| `admin_user` | `imasuat` | On every VM |
| `envoy_port` | `8443` | Envoy's external port on the DMZ host: 8443, the owner's decision (2026-10-06), as a NodePort. A variable so every Envoy rule moves together |
| `bus_port` | `8442` | The farmerbus node port core dials on the DMZ: 8442, the owner's decision (2026-10-06), so the DMZ node port range is 8442-8443 only |
| `farmer_api_port`, `core_public_port` | `5405`, `443` | farmer's API (Envoy's upstream; the owner: "farmer ports can be anything"), saasapi and Keycloak on core. See the network table |
| `private_dns_zone` | `uat.imas.internal` | The private DNS zone linked to the VNet (see [Private DNS](#private-dns)) |

The image URNs are unverified: the owner checks them with `az vm image list
--all --publisher <p> --offer <o> --sku <s>` before the first run.

Subscription, tenant and client ids are not inputs and are not in any file:
they come from the environment (`ARM_SUBSCRIPTION_ID`, `ARM_TENANT_ID`,
`ARM_CLIENT_ID`, `ARM_USE_OIDC=true` in the workflow, or an `az login` by hand).

## Outputs

`tofu output -json uat` is the interface to every other UAT brief:

```json
{
  "run_id": "abc123",
  "region": "centralindia",
  "resource_group": "imas-uat-abc123",
  "dmz":  { "name": "uat-dmz",  "id": "/subscriptions/.../virtualMachines/uat-dmz",  "private_ip": "10.60.1.4", "public_ip": "...", "fqdn": "uatabc123-dmz.centralindia.cloudapp.azure.com",  "admin_user": "imasuat" },
  "core": { "name": "uat-core", "id": "...", "private_ip": "10.60.2.4", "public_ip": "...", "fqdn": "uatabc123-core.centralindia.cloudapp.azure.com", "admin_user": "imasuat" },
  "sprouts": {
    "t1-ubuntu": { "tenant": 1, "os": "ubuntu",  "connection": "ssh",   "id": "...", "private_ip": "...", "public_ip": "...", "admin_user": "imasuat" },
    "t1-win":    { "tenant": 1, "os": "windows", "connection": "winrm", "id": "...", "private_ip": "...", "public_ip": "...", "admin_user": "imasuat" }
  },
  "bastion": { "name": "uat-bastion", "id": "..." },
  "subnets": { "dmz": { "cidr": "10.60.1.0/24", "id": "..." }, "core": {}, "tenants": {}, "bastion": {} }
}
```

The top-level keys are exactly the Shared contract's (owner's decision,
2026-10-06: "uat output shape per the Shared contract"); `tofu test` checks
that. The contract does not fix the shape of `subnets`; here it is a map of
name to `{cidr, id}`. `release_tag` and `expires_at` are resource tags, not
output keys.
`uat/access/testdata/uat.json` is a full sample, and `tofu test` fails if its
shape drifts from the real output.

Credentials are not in `uat`. Two separate outputs hold them, both
`sensitive`, so `tofu output` and plans print `(sensitive value)`. The owner
accepted this hand-over (2026-10-06: "sensitive outputs yes"):

| Output | What |
|---|---|
| `ssh_private_key` | RSA 4096 private key (OpenSSH format) for `admin_user` on every Linux VM, generated per run by the `tls` provider |
| `windows_admin_password` | 24 random characters for `admin_user` on both Windows sprouts, generated per run by the `random` provider |

The workflow reads them with `tofu output -raw <name>` into `0600` files (masking
the password with `::add-mask::` first) and never uploads them. They also live
in this run's state blob (Entra ID access only; see the bootstrap). Nothing is
written to disk by tofu and nothing is committed.

## Network rules

Ports derived from `deploy/helm/nats/README.md` (the diagram at the top and
"NetworkPolicy") and `deploy/helm/farmer/README.md` ("NetworkPolicy", "Reaching
the bus"). Azure's default rules allow everything inside the VNet
(`AllowVnetInBound`, `AllowVnetOutBound`) and from the Azure load balancer, so
each workload NSG ends with three explicit denies; only the allows above them
pass. NSGs are stateful, so replies need no rule. Inbound rules match the VM's
private address, including traffic that arrived on its public IP.

Owner's decisions (2026-10-06) this table applies: sprouts connect to nats
only through Envoy, on the DMZ **private** address, by a private DNS name;
farmer and saasapi connect to farmerbus; Envoy is node port **8443** and the
bus node port **8442**, so the DMZ node port range is 8442-8443 only; no load
balancer.

| NSG | Dir | Prio | Rule | From | To | Port | Reason |
|---|---|---|---|---|---|---|---|
| dmz | in | 100 | AllowBastionSshKubeIn | `10.60.4.0/26` | dmz | TCP 22, 6443 | Management only through Bastion tunnels: SSH (k0sctl) and the Kubernetes API (helm, kubectl) |
| dmz | in | 110 | AllowSproutsEnvoyPrivateIn | tenants `10.60.3.0/24` | dmz | TCP `envoy_port` (8443, owner's decision) | Owner: sprouts connect to nats via Envoy, on the DMZ private address (`dmz.<zone>`), and Envoy is node port 8443. Envoy serves `/v1/enroll`, `/v1/refresh`, `/files/` and `wss://` |
| dmz | in | 130 | AllowRunnerEnvoyIn | `runner_cidr` | dmz | TCP `envoy_port` (8443, owner's decision) | The runner's Envoy checks (UAT.3a) and tests (X2) |
| dmz | in | 140 | AllowCoreBusIn | core `10.60.2.0/24` | dmz | TCP `bus_port` (8442, owner's decision) | Owner: farmer and saasapi connect to farmerbus, through its node port 8442. Behind it is the bus client port 5406 (nats `bus.ports.client`), which they dial at `farmerbusurl`; core dials out, the bus never dials core |
| dmz | in | 4000 | DenyVnetIn | VirtualNetwork | any | any | Overrides `AllowVnetInBound` |
| dmz | in | 4096 | DenyAllIn | any | any | any | Everything else, including the Azure load balancer default |
| dmz | out | 100 | AllowFarmerApiOut | dmz | core | TCP 5405 | Envoy's upstreams `farmer_api` and `recipe_service` (5405), and its remote JWKS fetch (`/v1/.well-known/jwks.json` on the same port) |
| dmz | out | 4000 | DenyVnetOut | any | VirtualNetwork | any | Overrides `AllowVnetOutBound`: the DMZ reaches nothing else in the VNet. Internet outbound (images) stays allowed |
| core | in | 100 | AllowBastionSshKubeIn | `10.60.4.0/26` | core | TCP 22, 6443 | As for dmz |
| core | in | 110 | AllowDmzFarmerApiIn | dmz `10.60.1.0/24` | core | TCP 5405 | Envoy to farmer's API (farmer `farmer.apiPort`; farmer NetworkPolicy "farmer in from the nats chart's Envoy") |
| core | in | 120 | AllowRunnerHttpsIn | `runner_cidr` | core | TCP 443 | saasapi and Keycloak, from the runner only (Shared contract) |
| core | in | 4000, 4096 | DenyVnetIn, DenyAllIn | | | | As for dmz. A sprout cannot open a connection to core |
| core | out | 100 | AllowBusOut | core | dmz | TCP `bus_port` (8442, owner's decision) | farmer and saasapi to the bus node port (see dmz 140) |
| core | out | 4000 | DenyVnetOut | any | VirtualNetwork | any | Core reaches nothing else in the VNet. Internet outbound (images, the Keycloak and object store are on the same host) stays allowed |
| tenants | in | 100 | AllowBastionAdminIn | `10.60.4.0/26` | tenants | TCP 22, 5986 | SSH to Linux sprouts and WinRM over HTTPS to Windows sprouts, through Bastion tunnels only |
| tenants | in | 4000, 4096 | DenyVnetIn, DenyAllIn | | | | Nothing else in; the sprouts' public IPs are outbound only |
| tenants | out | 100 | AllowEnvoyPrivateOut | tenants | dmz | TCP `envoy_port` (8443, owner's decision) | Owner: sprouts connect to nats via Envoy, and to nothing else |
| tenants | out | 200 | DenyCorePublicOut | any | core public IP `/32` | any | Defence in depth: a sprout must not open a connection to core, not even to its public address (core's NSG would refuse it too) |
| tenants | out | 210 | DenyDmzPublicOut | any | DMZ public IP `/32` | any | Owner: sprouts use the DMZ private address. The DMZ NSG admits no sprout public IP either |
| tenants | out | 4000 | DenyVnetOut | any | VirtualNetwork | any | No sprout-to-sprout or sprout-to-core traffic. Internet outbound (packages) stays allowed |
| bastion | | | (below) | | | | Azure's documented rules |

What the owner decided, what I derived from the two READMEs, and what I
assumed:

1. **Core to the DMZ: the bus node port 8442 (owner, 2026-10-06).** The Shared
   contract said "core reaches only the bus websocket port on the DMZ". The
   owner: "The design is sprouts connect to nats via envoy. Farmer and saaapi
   connect to farmerbus. So farmer ports can be anything", then "Option (b):
   bus node port 8442, DMZ node port range 8442-8443 only". Behind node port
   8442 is the bus client port 5406 (`bus.ports.client`; farmer `bus.port`,
   `farmerbusurl`), which both chart READMEs name; the websocket port 5407 is
   used only by Envoy inside the DMZ and is not opened between subnets.
2. **Envoy is node port 8443 (owner, 2026-10-06).** The owner: "The envoy
   should be behind an app gateway in production. For simplicity let's use
   8443 as node port. It should support both load balancer and node port",
   and later "no load balancer". So the runner (`runner_cidr` only) and the
   sprouts reach Envoy on the DMZ host at 8443 (`envoy_port`; it is also the
   chart's `envoy.listenerPort`). This module creates no load balancer or
   Application Gateway. `farmer_api_port` defaults to the chart's 5405; per
   the owner, farmer's port can be anything, so set it to whatever UAT.2 and
   UAT.3b expose. 443 on core is from the Shared contract, not the charts
   (saasapi's own port is 8081).
3. **Sprouts dial the DMZ private address by a private DNS name (owner,
   2026-10-06).** The only Envoy path from the tenants subnet is to the DMZ
   subnet; the DMZ public address is denied to sprouts, and the DMZ NSG admits
   no sprout public IP. The name is `dmz.<private_dns_zone>` (see [Private
   DNS](#private-dns)).
4. **SSH 22, WinRM 5986 and the Kubernetes API 6443** are not in the READMEs:
   22 and 5986 are the standard ports, 6443 is k0s's default.
5. **Pod traffic.** The source rules assume traffic from a pod leaving a hub is
   SNATed to the node's address (kube-router's default pod egress in k0s).
   Azure drops a packet whose source is not the NIC's address anyway.
6. **Same-host flows** need no NSG rule: on core, farmer and saasapi to PXC,
   Valkey, OpenBao and MinIO, and saasapi to Keycloak's JWKS (the core FQDN
   resolves to core's private IP in the cluster); on the DMZ, Envoy to the bus
   on 5407. The bus's OpenBao TLS mode (`bus.tls.mode=openbao`, DMZ to OpenBao
   8200 on core) is **not** opened; the UAT CA is from cert-manager.

### AzureBastionSubnet

An NSG **is attached**, with Azure's documented rules for that subnet
(learn.microsoft.com, "Working with NSG access and Azure Bastion"), narrowed
where Azure allows it:

| Dir | Prio | Rule | From | To | Port |
|---|---|---|---|---|---|
| in | 120 | AllowHttpsInbound | `runner_cidr` (Azure allows Internet or a list of public addresses) | any | TCP 443 |
| in | 130 | AllowGatewayManagerInbound | GatewayManager | any | TCP 443 |
| in | 140 | AllowAzureLoadBalancerInbound | AzureLoadBalancer | any | TCP 443 |
| in | 150 | AllowBastionHostCommunication | VirtualNetwork | VirtualNetwork | 8080, 5701 |
| in | 4096 | DenyAllInbound | any | any | any |
| out | 100 | AllowSshRdpOutbound | any | VirtualNetwork | 22, 3389, plus 5986 and 6443 for native client tunnels to those ports |
| out | 110 | AllowAzureCloudOutbound | any | AzureCloud | TCP 443 |
| out | 120 | AllowBastionCommunication | VirtualNetwork | VirtualNetwork | 8080, 5701 |
| out | 130 | AllowHttpOutbound | any | Internet | 80 |
| out | 4096 | DenyAllOutbound | any | any | any |

Azure checks this NSG when the Bastion is created. **The Bastion fails
closed** (owner's decision, 2026-10-06): if Azure refuses the NSG as not
compliant (for example because of the narrowed internet source), the apply
fails; there is no switch to run the Bastion without an NSG (confirmed by the
owner: "Bastion NSG stays fail-closed"). To reach a kept
environment from your own machine, re-apply with your address as
`runner_cidr`; that also moves the Envoy and core 443 rules to you.

### Private DNS

An Azure Private DNS zone, `private_dns_zone` (default `uat.imas.internal`),
is linked to the VNet (auto-registration off) and holds two A records with a
60 second TTL:

| Name | Resolves to |
|---|---|
| `dmz.uat.imas.internal` | `uat-dmz`'s private address: what sprouts use for Envoy (8443) and core for the bus (8442) |
| `core.uat.imas.internal` | `uat-core`'s private address: what Envoy may use for farmer (5405) |

Every VM in the VNet resolves these through Azure's resolver (168.63.129.16),
and so do pods whose DNS forwards to the node's resolver. Nothing outside the
VNet can. The names are not keys of `uat`, whose keys the Shared contract
fixes; the owner decided (2026-10-06) that the names themselves go in the
Shared contract, and that the Envoy and bus certificate SANs, the sprouts'
`farmerinterface` and farmer's `farmerbusurl` use them (UAT.3a, UAT.3b,
UAT.4). The zone is deleted with the run's resource group.

## Destroy semantics

- **Disks.** OS disks go with their VM: the provider feature
  `delete_os_disk_on_deletion = true` (set explicitly in `versions.tf`). There
  are no data disks.
- **NICs and public IPs** are tofu resources, destroyed with the VM.
  `azurerm_linux_virtual_machine` and `azurerm_windows_virtual_machine` have no
  per-NIC `delete_option` attribute (that is an ARM property of the legacy
  resource), so this, plus the next point, is the equivalent.
- **The resource group** is deleted last, with
  `prevent_deletion_if_contains_resources = false`, so anything Azure added
  that tofu does not track (for example an extension's leftovers) goes with it.
  If tofu cannot finish, `destroy.sh` deletes the group with `az group delete`,
  which removes every child resource.
- **Teardown speed.** `skip_shutdown_and_force_delete = true`; `destroy.sh`
  passes `--force-deletion-types Microsoft.Compute/virtualMachines`.
- **Outside the group.** If Network Watcher is auto-enabled in the
  subscription, Azure creates `NetworkWatcher_<region>` in `NetworkWatcherRG`
  the first time a VNet is made in a region. It is free, untagged, shared, and
  never deleted by these scripts.
- **No ephemeral OS disks.** None of the default sizes supports one with these
  images: Dsv5 sizes have no local temp disk or cache, and the temp disks of
  B1ms (4 GiB) and B2s (8 GiB) are smaller than the 30 GB images.

## Bootstrap, once

The owner runs this by hand, as the subscription Owner, after the section 4h
prerequisites (resource providers registered, the `imas-uat-github`
application created). It creates `imas-uat-state` (tagged
`purpose=imas-uat-state`, never `purpose=imas-uat`, so the janitor cannot match
it) with:

- a StorageV2 account `imasuatstate<8 random>` (TLS 1.2, HTTPS only, no public
  blobs, **shared keys off** so access is Entra ID only, blob versioning and
  7-day soft delete, a lifecycle rule that deletes run state blobs 30 days after
  their last change and old versions after 7), and a private container
  `tfstate`;
- `Storage Blob Data Contributor` on that account for the principals you name
  (the GitHub identity: Contributor has no blob data access) and, by default,
  for yourself;
- a `CanNotDelete` lock on the group (a Contributor cannot remove it);
- a monthly subscription budget, `imas-uat-monthly`, default 100 in the
  subscription's billing currency, emailing at 50 % and 90 % actual and 100 %
  forecast. It alerts; it stops nothing.

It does not create the GitHub OIDC application.

```sh
cd uat/tofu/bootstrap
az login
az account set --subscription "<subscription id>"
export ARM_SUBSCRIPTION_ID=$(az account show --query id -o tsv)
SP=$(az ad sp show --id "<AZURE_CLIENT_ID of imas-uat-github>" --query id -o tsv)
tofu init
tofu apply -var budget_email=you@example.com -var "state_blob_contributors=[\"$SP\"]"
tofu output backend_config
```

Its own state is local (`terraform.tfstate`, git-ignored). Keep it somewhere
safe; it holds no usable credential. To remove the bootstrap later, `tofu
destroy` removes the lock first.

## Running the main stack by hand

```sh
cd uat/tofu
export ARM_SUBSCRIPTION_ID=$(az account show --query id -o tsv)
RUN=abc123
tofu init \
  -backend-config=resource_group_name=imas-uat-state \
  -backend-config=storage_account_name=<from the bootstrap output> \
  -backend-config=container_name=tfstate \
  -backend-config=key=imas-uat/$RUN.tfstate
tofu apply -var run_id=$RUN -var release_tag=v0.1.0-rc.4 -var runner_cidr=<your address>/32
tofu output -json uat > uat.json
```

In GitHub Actions (UAT.6) the same `init` and `apply` run with
`ARM_USE_OIDC=true`, `ARM_CLIENT_ID`, `ARM_TENANT_ID` and `ARM_SUBSCRIPTION_ID`
from the `uat` environment's variables and `permissions: id-token: write`; the
backend reads the same variables. Expect the Bastion to take about ten minutes.

## Destroying by hand

```sh
uat/tofu/destroy.sh <run_id>
```

It runs `tofu init` against the run's state blob (it finds the state account in
`imas-uat-state` by its tag, or takes `TFSTATE_STORAGE_ACCOUNT`), `tofu destroy`,
then checks that `imas-uat-<run_id>` is gone. If it is not, it runs `az group
delete` on it, but only if the group carries `purpose=imas-uat` and that
`run_id`; otherwise it refuses (exit 3). It then checks, with retries, that no
resource tagged `run_id=<run_id>` remains anywhere in the subscription, and
exits 1 listing them if any does. `--skip-init` reuses an already initialised
directory (same job as the apply). Destroy needs no real `release_tag` or
`runner_cidr`; the script fills placeholders unless you set `TF_VAR_*`.

Last resort, by hand:

```sh
az group show -n imas-uat-<run_id> --query tags   # check purpose=imas-uat first
az group delete -n imas-uat-<run_id> --yes
az resource list --tag run_id=<run_id> -o table   # must be empty
```

## Resources per run

| Resource | Count | Size |
|---|---|---|
| `uat-dmz` | 1 | Standard_D2s_v5: 2 vCPU, 8 GiB; 64 GB Standard SSD |
| `uat-core` | 1 | Standard_D8s_v5: 8 vCPU, 32 GiB; 128 GB Standard SSD |
| `t1-ubuntu`, `t2-ubuntu`, `t1-alma`, `t2-alma` | 4 | Standard_B1ms: 1 vCPU, 2 GiB; 30 GB Standard SSD |
| `t1-win`, `t2-win` | 2 | Standard_B2s: 2 vCPU, 4 GiB; 30 GB Standard SSD |
| Azure Bastion `uat-bastion` | 1 | Standard SKU, 2 scale units |
| Standard public IPs | 9 | 8 VMs and the Bastion; static |
| VNet, subnets, NSGs, NICs | 1, 4, 4, 8 | |
| Private DNS zone, VNet link, A records | 1, 1, 2 | `dmz` and `core` |
| VM extensions | 2 | `winrm-https` on each Windows sprout |

18 vCPUs in all: 10 in the Dsv5 family and 8 in the B family (quota is per
family and per region; section 4h). Costs are the guesses in section 4h.

Windows sprouts: patching is `Manual` with automatic updates off, so Windows
Update does not reboot a VM in the middle of a run. WinRM: `winrm-https.ps1`
creates a 30-day self-signed certificate, an HTTPS listener on 5986, removes the
HTTP listener, keeps Basic auth and unencrypted traffic off (NTLM over HTTPS
works with the local admin) and opens 5986 in Windows Firewall. Clients go
through a Bastion tunnel, where the certificate name never matches, so they
skip certificate validation (UAT.4).

## Tests

What ran here (no Azure access):

- `tofu fmt -check -recursive` and `tofu validate` on both stacks, with
  OpenTofu 1.11.5 and azurerm 4.81.0, random 3.9.1, tls 4.4.1 (from a local
  mirror, as the OpenTofu registry was unreachable).
- `tofu test` (`tests/main.tftest.hcl`), with mocked providers: names, tags,
  the expiry, the layout, sizes and disks, the AlmaLinux plan, the Windows image
  and extension, the `uat` output shape and that it carries no credential, that
  `uat/access/testdata/uat.json` has the same shape, every NSG's allow list and
  ports, that 22, 5985, 5986 and 6443 are open only from `AzureBastionSubnet`,
  the deny tail, that the bus is reached only on 8442 and Envoy only on 8443
  from the DMZ private range, that sprouts are denied the DMZ and core public
  addresses, that the Bastion NSG is always attached, that `uat` has exactly
  the contract's keys, the private DNS records and the input validations.
- `tests/destroy_test.sh`: `destroy.sh` against stubbed `tofu` and `az`, all
  three branches (clean destroy; fallback to `az group delete`; leftovers exit
  1), the refusal to delete a group without our tags, fail-closed on `az`
  errors, `--skip-init` and argument handling.
- shellcheck on every script.

`go test ./uat/tofu/` runs the shell test, shellcheck and `tofu fmt -check` when
the tools are on PATH. `tofu validate` and `tofu test` need the providers:

```sh
cd uat/tofu && tofu init -backend=false && tofu validate && tofu test
cd bootstrap && tofu init -backend=false && tofu validate
```

The provider lock file is not committed yet: it was generated from HashiCorp's
release zips through a local mirror, and its hashes may not match what the
OpenTofu registry serves. Commit it after the first `tofu init` against the
registry (`tofu providers lock -platform=linux_amd64 -platform=darwin_arm64`).

## Licences

OpenTofu and the `azurerm`, `random` and `tls` providers are MPL-2.0 (the
recorded MPL exception). The scripts also need the Azure CLI (MIT) and `jq`
(MIT) at run time; the tests use `python3` (PSF) and shellcheck (GPL-3.0, a
tool only, never shipped).
