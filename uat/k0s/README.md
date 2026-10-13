# uat/k0s: the two UAT hub clusters (UAT.2, P24)

Installs a [k0s](https://k0sproject.io) cluster on each hub of the Azure UAT
gate. The DMZ and core become two separate clusters. In the single-node run
each hub is one VM with the controller and the worker on it (role `single`).
In the HA run (workflow input `hub_nodes` 3, P24) each hub is three VMs, every
one a controller+worker on etcd (see [HA hubs](#ha-hubs)). It then adds what the hub
charts need: a default StorageClass, cert-manager, each cluster's NodePort
range for the ports the hubs expose (see [Exposure](#exposure)), the per-run
UAT CA as a ClusterIssuer, and the DNS rule from the Shared contract (plan
section 4h).

It installs no application chart. The hub briefs (uat/hub/dmz, uat/hub/core)
do that against the kubeconfigs and files written here.

**Status.** The single-node clusters have run on Azure: the gate's smoke and
core tiers passed on them (rc.11 to rc.13, 2026-10-09 to 2026-10-11). The HA
hubs are for the HA run (Run 3); what was checked for them is listed under
[Tests](#tests).

## Usage

```sh
# After tofu apply (uat/tofu) and uat/access/tunnels.sh open:
uat/k0s/install-tools.sh "$RUNNER_TEMP/bin" && PATH="$RUNNER_TEMP/bin:$PATH"
uat/k0s/bootstrap.sh \
  --uat uat.json \
  --access "$STATE/access.json" \
  --ssh-key "$STATE/hub_ssh_key" \
  --out "$STATE/k0s" \
  --nodes 1                             # or 3: the workflow's hub_nodes
uat/k0s/check.sh --out "$STATE/k0s"     # again at any time; read only
```

| Input | From |
|---|---|
| `--uat` | `tofu output -json uat`. Reads `run_id` and, for `dmz` and `core`: `name`, `private_ip`, `public_ip`, `fqdn`, `admin_user`, `node_names` and `node_private_ips` (the hub's nodes, in order; without them the hub is its `name` and `private_ip`), `api_address` and `api_fqdn` (the hub's stable API address and its private name; required on an HA hub). A hub has 1, 3 or 5 nodes (`UAT_HUB_NODE_COUNTS`), and its `name` and `private_ip` are its first node's. |
| `--access` | `access.json` from `uat/access/tunnels.sh open`. Reads, for each node, `host` and `ssh_port`; for the hub's API tunnel, `host` and `kube_port` of the node's entry on a single node or of the `dmz-api` or `core-api` entry on an HA hub. The entries may sit at the top level or under a `vms` or `hosts` object. |
| `--nodes` | Optional. Every hub must have this many nodes (the workflow passes `hub_nodes`), so a stale `uat.json` is refused. |
| `--ssh-key` | The per-run SSH private key for `admin_user`. A sensitive tofu value, so it is passed as a file and never written into the uat JSON. |

Everything read from these files is checked before it is used: IPv4
addresses, lower-case FQDNs, ports, user and VM names, and paths limited to a
safe character set. A bad value stops the run before anything is written.
This also means nothing in the files can inject YAML, a Corefile directive or
a k0sctl `$` expansion into the rendered configuration.

Everything bootstrap.sh writes goes to `--out`:

| File | What | Sensitive |
|---|---|---|
| `dmz.kubeconfig`, `core.kubeconfig` | Admin kubeconfigs. Server `https://127.0.0.1:<kube_port>`, through the hub's API tunnel (on an HA hub the one to its internal load balancer, so it keeps working while a node is stopped). | **Yes** (mode 600). Never upload them as workflow artifacts. |
| `uat-ca.crt` | The UAT CA certificate. Sprouts pin it (`sproutrootca`, `sproutrootcatofu: false`) and the tests trust it. | No |
| `endpoints.json` | The hubs' names, addresses, FQDNs and exposed ports, how each hub exposes them, each hub's node port range, nodes (`nodes`, `node_private_ips`), API address (`api_address`, `api_fqdn`) and datastore (`kine` or `etcd`), and the ClusterIssuer name. | No |
| `k0sctl-dmz.yaml`, `k0sctl-core.yaml` | The rendered k0sctl files. They hold the key's path, not the key. | No |
| `known_hosts` | The hubs' SSH host keys, recorded on first use for this run. | No |
| `cache/` | The pinned add-on manifests, after their checksums were verified. | No |

`--render-only` writes the k0sctl files and `endpoints.json` and stops. It
needs no k0sctl, kubectl or network. A re-run is safe: k0sctl apply and the
add-on applies are idempotent, and an existing UAT CA is reused (see below).

## What gets installed

| Piece | How | Pinned in |
|---|---|---|
| k0s, role `single` (one node) or `controller+worker` on every node (HA hub) | k0sctl, over SSH through each node's Bastion tunnel. The nodes download k0s themselves. | `versions.env` `K0S_VERSION`, the only place it is set (a test checks that) |
| local-path-provisioner, the default StorageClass `local-path` | The release manifest, SHA-256 checked, applied, and the class annotated default. Volumes go under `/opt/local-path-provisioner` on the OS disk. The upstream helper pod image is untagged, so it is pinned (`LOCAL_PATH_HELPER_IMAGE`). | `versions.env` |
| cert-manager, CRDs included | The release's static manifest, SHA-256 checked, server-side apply. | `versions.env` |
| UAT CA and ClusterIssuer `imas-uat-ca` | See [The UAT CA](#the-uat-ca). | `config.env` |
| k0sctl and kubectl on the runner | `install-tools.sh DIR`, checksums checked (Linux amd64 and arm64). bootstrap.sh refuses another k0sctl version. | `versions.env` |

Every version is in one file, `versions.env`. A manifest whose checksum
differs from the pin is refused. Nothing uses `latest`.

k0s keeps its defaults where nothing above says otherwise: kube-router as the
CNI (it also enforces NetworkPolicy), kube-proxy in iptables mode, pod CIDR
10.244.0.0/16 and service CIDR 10.96.0.0/12 (neither overlaps the VNet
10.60.0.0/16), and kine on SQLite as the datastore of a single-node
controller. Telemetry is off. An HA hub changes the datastore, the overlay
and the API path ([HA hubs](#ha-hubs)).

## HA hubs

A hub with more than one node (3 in the HA run; 5 is accepted too, etcd needs
an odd number) is rendered from the same template
(`templates/k0sctl.yaml.tmpl`, with `templates/k0sctl-host.yaml.tmpl` per
node and the fragments in `templates/ha/`). A hub of one node renders
the same configuration as before P24 (only the comments changed).

- **Every node `controller+worker`**, with `noTaints: true`: every node
  runs the hub's workloads as well (P24: three replicas spread over the
  nodes).
- **etcd** (`spec.storage.type: etcd`), one member per node. k0sctl sets each
  member's peer address to the node's `privateAddress`. kine on SQLite cannot
  serve several controllers.
- **The API address.** `spec.api` sets neither `address` (each controller
  binds its own private IP) nor `externalAddress`. The internal load
  balancer's address (`api_address`) and private name (`api_fqdn`) are in
  `spec.api.sans` with every node's IP, so the runner verifies the server
  through the tunnel to the load balancer. k0s rejects `externalAddress`
  with node-local load balancing (`k0s config validate`: "node-local load
  balancing cannot be used in conjunction with an external Kubernetes API
  server address"), and with `externalAddress` set k0s points kube-proxy,
  the konnectivity agents and the controller join tokens at it: through the
  internal load balancer, which drops a node's flow to its own frontend
  (Azure) and carries neither konnectivity (8132) nor the join API (9443).
- **Node-local load balancing** (`spec.network.nodeLocalLoadBalancing`,
  Envoy): kube-proxy and the konnectivity agents reach the API through a
  load balancer on each node's loopback (7443, 7132) over every controller's
  own address; the kubelet of a controller+worker node uses its own API
  server. So no node ever reaches its hub's API through `api_address`.
- **The pod overlay is FOU.** Azure drops IP-in-IP inside a VNet, so
  kube-router runs with `overlay-type: full`, `overlay-encap: fou` and
  `overlay-encap-port` `UAT_KUBE_ROUTER_FOU_PORT` (5555, UDP), which
  `uat/tofu` opens between a hub's nodes (a test checks both agree). A
  k0sctl hook loads the `fou` kernel module on each node before k0s starts
  and lists it in `/etc/modules-load.d`, so a restarted node has it too.
- **CoreDNS.** In each cluster the hub's own FQDN maps to every one of its
  nodes and the other hub's FQDN to that hub's `api_address` (its internal
  load balancer, which carries the private ports and keeps one address
  while a node is stopped). A pod never dials its own hub's internal load
  balancer.
- **Waits.** bootstrap.sh waits until the hub has as many Ready nodes as
  `node_names` lists, then until k0s's `EtcdMember` objects
  (`etcdmembers.etcd.k0sproject.io`) show that many members joined. check.sh
  fails on fewer of either.
- **Access.** k0sctl dials every node through its own SSH tunnel
  (`HostKeyAlias` the node's name). The kubeconfig's server is the tunnel to
  the hub's API address (`dmz-api`, `core-api` in access.json,
  `uat/access/README.md`).

NodePorts and hostPorts work the same on every node: kube-proxy serves a
node port on each node, and a hostPort pod takes its port on the node it runs
on. check.sh reads every pod and Service of the cluster, whatever its node,
and prints each hostPort pod's node.

### Licences

| Component | Licence | Note |
|---|---|---|
| k0s, k0sctl (and CoreDNS, kube-router, which k0s ships) | Apache-2.0 | Named in the Shared contract. |
| cert-manager | Apache-2.0 | Named in the Shared contract. |
| local-path-provisioner | Apache-2.0 | Named in the Shared contract. |
| kubectl | Apache-2.0 | A runner tool. |
| **busybox** (local-path-provisioner's helper pod image) | **GPL-2.0** | **Flagged. Owner, 2026-10-06: recorded as a UAT-only exception pending owner confirmation; this PR stays as is.** The upstream manifest uses busybox to create and delete volume directories. It is pulled and run unmodified as a container on the UAT hubs only. It is not linked, not shipped, and not a dependency of any released artifact. |

## Exposure

Owner decisions, 2026-10-06:

- **DMZ.** uat/hub/dmz (UAT.3a) owns the Envoy and bus Services, made from
  the chart values with pinned node ports. uat/k0s creates none of them.
  The node ports are **8443** (Envoy) and **8442** (bus client port, which
  core dials). The DMZ cluster's NodePort range is **8442-8443 only**.
  Production puts Envoy behind an application gateway; the owner wants
  NodePort and LoadBalancer both supported, which is UAT.3a's chart values'
  job now.
- **Core.** 443 uses hostPorts, as in UAT.3b's PR #132. That PR's edge
  proxy takes 443 (saasapi and Keycloak behind its TLS front) and 5405
  (farmer's API, which the DMZ's Envoy dials) as hostPorts on the node.
  k0s's kube-router CNI chain includes the `portmap` plugin, so hostPorts
  work. This was checked in k0s's source for the pinned version, not on a
  node. RustFS (uat/hub/core) also takes 9000 as a hostPort: the DMZ bus's
  account loader reads the accounts bucket there, read-only (design D22).
  Core's node-port mode is dropped: core exposes no node port, and
  its NodePort range is Kubernetes' default, **30000-32767**.

What uat/k0s does about exposure:

- It sets each cluster's API server NodePort range:
  - DMZ `8442-8443`;
  - core `30000-32767`, Kubernetes' default.

  Neither range holds a port k0s or the node uses. bootstrap.sh refuses a
  hub port that is one (`UAT_RESERVED_NODE_PORTS`: 6443, 8080, 8132, 8133,
  9443, 10249, 10250, 10256), and warns if a range ever contains one. It
  also refuses a hub hostPort inside that hub's NodePort range: a node port
  that Kubernetes picks by itself could otherwise take 443 or 5405 from the
  edge, or 9000 from RustFS.
- check.sh fails on any node port, or any hostPort of a pod off the host
  network, that the hub does not expose:
  - DMZ: node ports 8443 and 8442, no hostPorts.
  - Core: hostPorts 443, 5405 and 9000, no node ports.

| Hub | Port | How | Who creates it | Who connects |
|---|---|---|---|---|
| dmz | **8443** | node port (NodePort or LoadBalancer Service) | uat/hub/dmz, chart values | sprouts, and the runner |
| dmz | **8442** | node port, to the bus client port 5406 (`bus.ports.client`) | uat/hub/dmz, chart values | core (farmer and saasapi, `farmerbusurl`) |
| core | **443** | hostPort on the edge (saasapi and Keycloak behind its TLS front) | uat/hub/core | the runner (the tests, the tenant scripts) |
| core | **5405** | hostPort on the edge, passed through to farmer's API (`farmer.apiPort`) | uat/hub/core | the DMZ's Envoy (`/v1/enroll`, `/v1/refresh`, `/files/`, the JWKS) |
| core | **9000** | hostPort on RustFS's S3 port (`rustfs.hostPort`; `UAT_CORE_ACCOUNTS_STORE_PORT`) | uat/hub/core | the DMZ bus's account loader (the accounts bucket, read-only) |

The ports and ranges live in `config.env`. `endpoints.json` repeats them in
the keys uat/hub/dmz and uat/hub/core read (`dmz.ports.envoy`,
`dmz.ports.bus`, `core.ports.https`, `core.ports.farmer_api`,
`cluster_issuer`). It writes `core.exposure` as exactly `hostPort`, the only
value uat/hub/core's endpoint loader accepts. `dmz.exposure` is a
description that no reader on main uses. The `expose.sh` of earlier
revisions of PR #130 is removed (owner decision 0).

Notes for the hub briefs, unverified:

- **NetworkPolicy.** Traffic from the other cluster arrives from that
  node's address, because its pod egress is masqueraded. Traffic through a
  node port without `externalTrafficPolicy: Local` is masqueraded again by
  kube-proxy. The charts' cross-zone
  rules select peers by namespace and pod (for example nats
  `networkPolicy.core.namespaceSelector`, farmer `networkPolicy.dmz.*`). That
  can never match a pod in the other cluster, and kube-router enforces it.
  Expect to add `ipBlock` peers for the other hub's subnet or node address,
  or to widen those values for UAT.
- Envoy's upstreams to farmer and the bus check the server name (`sni`). A
  name that resolves to the core private IP (the core FQDN, see below)
  needs to be in farmer's certificate. The same goes for the DMZ FQDN in the
  bus certificate, for core's dial to the bus.

## The UAT CA

- On the first run, bootstrap.sh makes one self-signed root per run on the
  runner with openssl: ECDSA P-256, `CN=imas UAT CA <run_id>`,
  `basicConstraints CA:TRUE, pathlen:0`, `keyUsage keyCertSign, cRLSign`,
  valid `UAT_CA_DAYS` (7) days. The run's destroy step, or the janitor
  (UAT.6), removes the hubs long before then.
- The same root goes into the `kubernetes.io/tls` Secret
  `cert-manager/imas-uat-ca` on **both** hubs. A CA ClusterIssuer
  `imas-uat-ca` is created on it on each hub, and bootstrap.sh waits until it
  is Ready. One root on both hubs means the Envoy edge certificate, the bus
  and farmer certificates and the core 443 certificate all chain to the one
  file that sprouts and the tests pin. Certificates the issuer signs carry
  the root as `ca.crt`, which the nats chart's bus TLS Secret needs.
- The certificate is written to `OUT/uat-ca.crt`. The private key is written
  only to a temporary directory under `OUT` with mode 700, loaded into the
  two Secrets, and deleted. After that it exists only in those Secrets.
- On a re-run, a CA already on either hub is reused and copied to the other
  hub, never replaced, because sprouts may already pin it. If the two hubs
  hold different CAs, the run stops. No name constraints are set on the
  root: the chart certificates' SANs (short Service names, pod names) are not
  known in advance, and the root lives a week at most.

## DNS (the Shared contract's hostnames rule)

Each hub's CoreDNS gets a `hosts` block, so these names resolve inside both
clusters:

```
<core.private_ip>  <core.fqdn>
<dmz.private_ip>   <dmz.fqdn>
```

On an HA hub the lines differ per cluster: the hub's own FQDN has one line
per node (`<node private IP> <fqdn>`), the other hub's FQDN one line to that
hub's `api_address` ([HA hubs](#ha-hubs)). With one node per hub both are
the lines above.

The contract requires the core line in both clusters. That way Keycloak's
issuer URL, saasapi's `SAASAPI_KEYCLOAK_JWKS_URL` and the token's `iss` can be
one string built on the core FQDN, and a pod never dials a node's public
address. The DMZ line is an addition, made the same way: core can dial the
bus by the DMZ FQDN and reach the DMZ private IP. Other names still resolve
normally (`fallthrough`).

k0s manages the `coredns` ConfigMap and rewrites it on reconcile, so editing
the ConfigMap would be reverted. Instead the block is set through k0s's own
`spec.network.coreDNS.patches`, a MergePatch of the Corefile, in the k0sctl
file. k0s applies it every time it writes the manifest. The Corefile is
k0s's own Corefile plus the `hosts` block. On a k0s upgrade, compare it with
k0s's template (`pkg/component/controller/coredns.go`). k0s documents
component patches as **experimental**. check.sh confirms that the lines are
in the live ConfigMap.

## Access through the tunnels

- k0sctl dials `host:ssh_port` from access.json (127.0.0.1) with the system
  OpenSSH client (k0sctl's `openSSH` transport). That gives control over
  host keys: `UserKnownHostsFile OUT/known_hosts`,
  `StrictHostKeyChecking accept-new` and `HostKeyAlias <vm name>`. The key is
  accepted on first use through the Bastion tunnel and pinned for the rest of
  the run. A port that is reused by another tunnel cannot confuse it. The
  admin user needs passwordless sudo, which Azure's Linux images give.
- The API server certificate lists `127.0.0.1` (and the tunnel host when it
  is something else), the private IP and the FQDN in `spec.api.sans` (on an
  HA hub also the load balancer's address and name, and every node's IP). So
  kubectl and helm verify the server through the kube tunnel without
  `--insecure-skip-tls-verify`. `k0sctl kubeconfig --address
  https://127.0.0.1:<kube_port>` writes that address into the kubeconfig.
- `spec.api.address` (single node only) and each host's `privateAddress` are
  the VM's private IP, never the tunnel's.

## check.sh

`check.sh --out DIR` (or `--dmz-kubeconfig`, `--core-kubeconfig` and
`--endpoints`) prints, for each hub, the nodes, the etcd members (HA hub),
StorageClasses, cert-manager Deployments, the issuer, the CoreDNS lines, the
node ports and the hostPorts (with each pod's node). It exits 1, listing every
failure, when:

- a node is not Ready, or there is none;
- fewer nodes are Ready than the hub has (`nodes` in the endpoints file; 1
  without one);
- on an HA hub (datastore `etcd` in the endpoints file), fewer etcd members
  have joined than the hub has nodes, or they cannot be listed;
- there is no default StorageClass, or more than one;
- one of cert-manager's three Deployments is not Available;
- the ClusterIssuer is not Ready;
- CoreDNS lacks a FQDN line (only with an endpoints file): the hub's own
  FQDN for each of its nodes, the other hub's for its `api_address`;
- a node port lies outside the hub's exposed ports;
- a pod off the host network uses a hostPort the hub does not expose.

It changes nothing. bootstrap.sh runs it at the end unless `--skip-check` is
given.

## Tests

`uat/k0s/tests/run.sh` runs:

- **shellcheck** on every script and test stub.
- **yamllint** (`.yamllint.yaml`) on the golden rendered files (what every
  template renders to, single-node and HA) and the test manifests. The
  templates themselves are not YAML until rendered (a block token sits at
  the start of its line).
- **`tests/test-k0s.sh`**, the bash tests. k0sctl, kubectl, curl and sleep
  are stubs (`tests/stubs`), and the clusters' answers are JSON fixtures
  (`testdata/kube`). They cover:
  - argument handling for both scripts;
  - building both k0sctl files from `testdata/uat.json` and
    `testdata/access.json`, and the HA ones from `testdata/uat-ha.json` and
    `testdata/access-ha.json` (3 + 3 nodes), compared with
    `testdata/expected` (`*-ha.*` for HA; refresh with `UPDATE_GOLDEN=1` and
    review the diff);
  - for an HA hub: three controller+worker hosts without taints, each
    through its own tunnel, etcd, no `externalAddress` and no shared
    `address`, the load balancer's address and name in the SANs, the FOU
    overlay on the port `uat/tofu` opens, node-local load balancing, the
    CoreDNS lines per cluster, `endpoints.json`'s nodes and datastore, a mix
    of one HA hub and one single node, and refusal of an even node count,
    node lists of different lengths, a missing or node-owned `api_address`,
    a bad `api_fqdn`, a missing API tunnel or node tunnel, and `--nodes`
    that differs from the uat JSON;
  - the SANs, the node port range, the CoreDNS lines and the single place
    the k0s version is set;
  - refusal of bad addresses, FQDNs carrying YAML, `$` or Corefile syntax,
    bad users, run ids, missing tunnels, and settings that would expose a
    port k0s uses; the warning when a range contains one;
  - the install order and kubeconfig addresses against stubs, and on an HA
    hub the kubeconfig through the API tunnel, the wait for every node and
    every etcd member, and its failures (a node short, a member not
    joined);
  - checksum refusal and the helper image pin;
  - the CA: a real openssl run, one CA on both hubs, reuse, and refusing two
    different CAs;
  - every failure branch of check.sh, including node ports and hostPorts,
    and on an HA hub a node not Ready or missing, an etcd member missing,
    left or not listable, and a CoreDNS line missing or pointing at a node
    instead of the other hub's `api_address`.

`go test ./uat/k0s/` runs `tests/test-k0s.sh`, shellcheck and yamllint (each
skipped when its tool is missing).

Checked with the pinned binaries, outside the committed tests (P24, 2026-10-13):
`k0s config validate` of the k0s that `versions.env` pins accepts the
rendered ClusterConfig of both hubs, single-node and HA, and refuses the HA
one with `externalAddress` added; the pinned k0sctl's own parser (`yaml.UnmarshalStrict`
into its `Cluster`) and `Validate` accept all four rendered files (3 unique
controller+worker hosts with the hooks, and the single host). The pinned
manifests' checksums were taken from the published releases. The single-node
clusters have run on Azure (see Status).

## Answered by the owner (2026-10-06)

- **Envoy's port.** Node port 8443, with NodePort and LoadBalancer both
  supported (UAT.3a's chart values).
- **The DMZ range and the API port.** The bus moves to node port 8442 and
  the DMZ range is `8442-8443` only. It holds no reserved port. UAT.1's
  network rule (PR #135) and UAT.3a (PR #133) change to match; that is
  their job, not this PR's.
- **Core 443.** It uses hostPorts on UAT.3b's edge, as in PR #132. That
  edge is also the TLS front for saasapi and Keycloak.
- **Who owns the Envoy and bus Services.** uat/hub/dmz (UAT.3a), from the
  chart values with pinned node ports. expose.sh is removed.
- **The core NodePort range.** Core's node-port mode is dropped, and the
  core range is 30000-32767.
- **busybox.** Recorded as a UAT-only exception pending owner
  confirmation. It stays pinned as it is. An earlier owner note asked for
  it to be replaced with a Go test binary; the analysis of how is kept
  below, under "busybox, for the record".

## Open questions (for the owner and the other UAT briefs)

1. **Core to DMZ bus port.** The owner, 2026-10-06: "Farmer and saasapi
   connect to farmerbus. So farmer ports can be anything."
   - The Shared contract says core reaches "the bus websocket port on the
     DMZ".
   - The charts say farmer and saasapi dial the bus **client** port 5406
     (`farmerbusurl`). The websocket port 5407 is Envoy's upstream inside
     the DMZ, and core never uses it.
   - With the owner's decision, the client port is reached on DMZ node port
     8442, and UAT.1's network rule from core to the DMZ needs 8442.
   - farmer's `farmerbusurl` then has to name port 8442 (farmer chart
     `bus.port`). That is UAT.3b's to set; here it is only noted.
2. **The endpoints file.** The contract does not fix its fields.
   `OUT/endpoints.json` is offered as that file. Its key names match what
   UAT.3a's PR #133 reads. If another brief defines a different shape,
   UAT.6 should reconcile them.
3. **The ClusterIssuer name** (`imas-uat-ca`) and the CA file
   (`OUT/uat-ca.crt`) are not in the contract. The hub briefs and UAT.4
   need them.
4. **access.json shape.** It is read tolerantly (top level, `vms` or
   `hosts`). If UAT.1 nests ports differently, `access_get` in lib.sh is the
   one place to change.
5. **Pulls from Docker Hub** (local-path-provisioner, busybox) are anonymous
   from Azure addresses and may be rate limited. cert-manager pulls from
   quay.io.
6. That this Kubernetes minor works with the pinned cert-manager release is
   assumed, not verified.

### busybox, for the record

The pinned local-path-provisioner runs its helper pod as
`/bin/sh /script/setup` and `/bin/sh /script/teardown`, unless its
`config.json` sets `setupCommand` and `teardownCommand`. Those name one
executable in the helper image. It is called with `-p <dir> -s <size>
-m <mode>` and the `VOL_*` environment variables.

If the exception is not confirmed, a small static Go program in a minimal
image could do that job, with local-path's ConfigMap pointing at it. That
needs work outside `uat/k0s`: a Go package, a Dockerfile, and a workflow
that publishes the image to a registry. Another option is a static
`no-provisioner` StorageClass with pre-created local volumes.
