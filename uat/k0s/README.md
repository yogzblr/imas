# uat/k0s: the two UAT hub clusters (UAT.2)

Installs a single-node [k0s](https://k0sproject.io) cluster on each hub VM of
the Azure UAT gate. uat-dmz and uat-core become two separate clusters, each
with the controller and the worker on its one node. It then adds what the hub
charts need: a default StorageClass, cert-manager, a way in from outside
without a cloud load balancer, the per-run UAT CA as a ClusterIssuer, and the
DNS rule from the Shared contract (plan section 4h).

It installs no application chart. The hub briefs (uat/hub/dmz, uat/hub/core)
do that against the kubeconfigs and files written here.

**Status: none of this has run against a real node.** The agent that wrote it
could not reach Azure. What was checked is listed under [Tests](#tests).

## Usage

```sh
# After tofu apply (uat/tofu) and uat/access/tunnels.sh open:
uat/k0s/install-tools.sh "$RUNNER_TEMP/bin" && PATH="$RUNNER_TEMP/bin:$PATH"
uat/k0s/bootstrap.sh \
  --uat uat.json \
  --access "$STATE/access.json" \
  --ssh-key "$STATE/hub_ssh_key" \
  --out "$STATE/k0s"
uat/k0s/check.sh --out "$STATE/k0s"     # again at any time; read only
```

| Input | From |
|---|---|
| `--uat` | `tofu output -json uat`. Reads `run_id` and, for `dmz` and `core`: `name`, `private_ip`, `public_ip`, `fqdn`, `admin_user`. |
| `--access` | `access.json` from `uat/access/tunnels.sh open`. Reads, for each hub's VM name, `host`, `ssh_port` and `kube_port`. The entries may sit at the top level or under a `vms` or `hosts` object. |
| `--ssh-key` | The per-run SSH private key for `admin_user`. A sensitive tofu value, so it is passed as a file and never written into the uat JSON. |

Everything read from these files is checked before it is used: IPv4
addresses, lower-case FQDNs, ports, user and VM names, and paths limited to a
safe character set. A bad value stops the run before anything is written.
This also means nothing in the files can inject YAML, a Corefile directive or
a k0sctl `$` expansion into the rendered configuration.

Everything bootstrap.sh writes goes to `--out`:

| File | What | Sensitive |
|---|---|---|
| `dmz.kubeconfig`, `core.kubeconfig` | Admin kubeconfigs. Server `https://127.0.0.1:<kube_port>`, through the kube tunnel. | **Yes** (mode 600). Never upload them as workflow artifacts. |
| `uat-ca.crt` | The UAT CA certificate. Sprouts pin it (`sproutrootca`, `sproutrootcatofu: false`) and the tests trust it. | No |
| `endpoints.json` | The hubs' names, addresses, FQDNs and exposed ports, the node port range and the ClusterIssuer name. | No |
| `k0sctl-dmz.yaml`, `k0sctl-core.yaml` | The rendered k0sctl files. They hold the key's path, not the key. | No |
| `known_hosts` | The hubs' SSH host keys, recorded on first use for this run. | No |
| `cache/` | The pinned add-on manifests, after their checksums were verified. | No |

`--render-only` writes the k0sctl files and `endpoints.json` and stops. It
needs no k0sctl, kubectl or network. A re-run is safe: k0sctl apply and the
add-on applies are idempotent, and an existing UAT CA is reused (see below).

## What gets installed

| Piece | How | Pinned in |
|---|---|---|
| k0s, role `single` | k0sctl, over SSH through the Bastion tunnel. The node downloads k0s itself. | `versions.env` `K0S_VERSION`, the only place it is set (a test checks that) |
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
controller. Telemetry is off.

### Licences

| Component | Licence | Note |
|---|---|---|
| k0s, k0sctl (and CoreDNS, kube-router, which k0s ships) | Apache-2.0 | Named in the Shared contract. |
| cert-manager | Apache-2.0 | Named in the Shared contract. |
| local-path-provisioner | Apache-2.0 | Named in the Shared contract. |
| kubectl | Apache-2.0 | A runner tool. |
| **busybox** (local-path-provisioner's helper pod image) | **GPL-2.0** | **Flagged: not named in the contract.** The upstream manifest uses it to create and delete volume directories. It is pulled and run unmodified as a container on the UAT hubs only. It is not linked, not shipped, and not a dependency of any released artifact. The owner decides. |

## Reaching services: NodePort

**Choice: NodePort Services whose node port equals the port the network rules
open, with the API server's NodePort range narrowed to `443-5406`.** No cloud
load balancer, no port translation.

Why NodePort and not host ports:

- A NodePort Service works with the charts as they are. It selects the
  charts' pods and adds nothing to them (see expose.sh below). None of the
  charts has a hostPort or hostNetwork value. Host ports would mean patching
  the charts' Deployments and StatefulSets after every install. They would
  also depend on kube-router's CNI chain carrying the portmap plugin, which
  nobody has checked on this k0s build.
- `externalTrafficPolicy: Local` (expose.sh `--local`) keeps the client's
  source address for Envoy. Its enroll rate limit and its logs rely on that.
- The narrowed range lets a node port be a well-known port such as 443. It
  also stays below the Kubernetes API (6443), so an automatically allocated
  node port can never land on the API server or the kubelet (10250).
  check.sh fails on any NodePort or LoadBalancer node port a hub does not
  expose.

| Hub | Node port | Service (chart value) | Who connects | Source |
|---|---|---|---|---|
| dmz | **443** | Envoy (`envoy.service.port` 443, pod `envoy.listenerPort` 8443) | sprouts, and the runner | nats README: Envoy and NetworkPolicy |
| dmz | **5406** | bus client (`bus.ports.client`) | core (farmer and saasapi dial `farmerbusurl`, `tls://...:5406`) | nats README: Before you install, item 5; farmer README: Reaching the bus |
| core | **443** | saasapi and Keycloak, behind one TLS front (open question 3) | the runner (the tests, the tenant scripts) | Shared contract |
| core | **5405** | farmer API (`farmer.apiPort`) | the DMZ's Envoy (`/v1/enroll`, `/v1/refresh`, `/files/`, the JWKS) | farmer README: NetworkPolicy; nats `envoy.upstreams.farmerAPI.port` |

The ports live in `config.env`. `endpoints.json` repeats them for the hub
scripts and the tests.

### How a hub script exposes a Service

The charts have no nodePort value, and making a chart's Service a NodePort
would give every one of its ports a node port (the bus Service would expose
its websocket port too). So the hub script leaves the charts' Services as
they are (ClusterIP) and calls `expose.sh`. It adds a sibling Service,
`<service>-np`, of type NodePort: same selector, only the chosen port, the
node port pinned. expose.sh refuses any node port the hub does not expose.
Re-running it is safe.

```sh
# DMZ (uat/hub/dmz), after helm install of deploy/helm/nats:
uat/k0s/expose.sh --kubeconfig "$K/dmz.kubeconfig" --hub dmz \
  --namespace imas-dmz --service <release>-nats-envoy --port https --node-port 443 --local
uat/k0s/expose.sh --kubeconfig "$K/dmz.kubeconfig" --hub dmz \
  --namespace imas-dmz --service <release>-nats-bus --port client --node-port 5406
# Core (uat/hub/core), after helm install of deploy/helm/farmer:
uat/k0s/expose.sh --kubeconfig "$K/core.kubeconfig" --hub core \
  --namespace imas-core --service <release>-farmer --port api --node-port 5405
```

Notes for the hub briefs, unverified:

- **NetworkPolicy.** Traffic that arrives through a node port reaches a pod
  from the node's address. That happens for every Service without
  `externalTrafficPolicy: Local`, because kube-proxy masquerades it, and the
  peer cluster's own egress is masqueraded as well. The charts' cross-zone
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
  is something else), the private IP and the FQDN in `spec.api.sans`. So
  kubectl and helm verify the server through the kube tunnel without
  `--insecure-skip-tls-verify`. `k0sctl kubeconfig --address
  https://127.0.0.1:<kube_port>` writes that address into the kubeconfig.
- `spec.api.address` and the host's `privateAddress` are the VM's private IP,
  never the tunnel's.

## check.sh

`check.sh --out DIR` (or `--dmz-kubeconfig`, `--core-kubeconfig` and
`--endpoints`) prints, for each hub, the nodes, StorageClasses, cert-manager
Deployments, the issuer, the CoreDNS lines and the exposed node ports. It
exits 1, listing every failure, when:

- a node is not Ready, or there is none;
- there is no default StorageClass, or more than one;
- one of cert-manager's three Deployments is not Available;
- the ClusterIssuer is not Ready;
- CoreDNS lacks a FQDN line (only with an endpoints file);
- a node port lies outside the hub's exposed ports.

It changes nothing. bootstrap.sh runs it at the end unless `--skip-check` is
given.

## Tests

`uat/k0s/tests/run.sh` runs:

- **shellcheck** on every script and test stub.
- **yamllint** (`.yamllint.yaml`) on the templates, the golden rendered files
  and the test manifests.
- **`tests/test-k0s.sh`**, the bash tests. k0sctl, kubectl, curl and sleep
  are stubs (`tests/stubs`), and the clusters' answers are JSON fixtures
  (`testdata/kube`). They cover:
  - argument handling for all three scripts;
  - building both k0sctl files from `testdata/uat.json` and
    `testdata/access.json`, compared with `testdata/expected` (refresh with
    `UPDATE_GOLDEN=1` and review the diff);
  - the SANs, the node port range, the CoreDNS lines and the single place
    the k0s version is set;
  - refusal of bad addresses, FQDNs carrying YAML, `$` or Corefile syntax,
    bad users, run ids, missing tunnels, and settings that would put the API
    port in the node port range;
  - the install order and kubeconfig addresses against stubs;
  - checksum refusal and the helper image pin;
  - the CA: a real openssl run, one CA on both hubs, reuse, and refusing two
    different CAs;
  - every failure branch of check.sh;
  - expose.sh's port allow-list, the NodePort Service it builds, and its
    read-back.

Checked by hand, outside the committed tests: the k0s binary of the pinned
version (`k0s config validate`) accepts the rendered ClusterConfig, including
the CoreDNS patch block. The pinned k0sctl parses the rendered file (its
config parser rejects unknown fields). The pinned manifests' checksums were
taken from the published releases.

**Not run:** k0sctl against a real host, k0s coming up, the add-ons on a
cluster, the CoreDNS patch taking effect, NodePort 443 on a real node, or any
traffic through a Bastion tunnel. Expect fixes after the first Azure run.

## Open questions (for the owner and the other UAT briefs)

1. **Core to DMZ bus port.** The Shared contract says core reaches "the bus
   websocket port on the DMZ". The charts say farmer and saasapi dial the bus
   **client** port 5406 (`farmerbusurl`, `tls://...:5406`). The websocket
   port 5407 is Envoy's upstream inside the DMZ, and core never uses it.
   This brief exposes 5406 and gives 5407 no node port. UAT.1's network rule
   from core to the DMZ needs 5406.
2. **Envoy's external port.** The contract says "Envoy's port". Here it is
   443: the chart's `envoy.service.port`, and what a production
   LoadBalancer edge serves. The pod listens on 8443 (`envoy.listenerPort`).
   If UAT.1 opens 8443 instead, change `UAT_DMZ_ENVOY_PORT` and the range in
   config.env (the range must then not reach 6443), or change UAT.1.
3. **One 443 on core for saasapi and Keycloak.** saasapi serves plain HTTP
   (Service port 80, pod 8081: "terminate TLS in front"). Keycloak is a
   second service on the same FQDN and port. A NodePort maps one port to one
   Service, so core needs a small TLS-terminating front:
   - a certificate for the core FQDN from `imas-uat-ca`;
   - path routing: Keycloak's `/realms/`, `/resources/` and `/js/` to
     Keycloak, everything else to saasapi;
   - exposed with `expose.sh --hub core ... --node-port 443`.

   Not built here: the brief limits this part to NodePort or host ports, and
   the front depends on UAT.3b's Service names. Proposed owner: UAT.3b.
4. **The endpoints file.** The contract says scripts take "an endpoints file
   (the hub names, ports and private addresses in the contract's shape)" but
   does not fix its fields. `OUT/endpoints.json` is offered as that file. Its
   `dmz` and `core` objects copy the uat JSON's and add `ports`. If another
   brief defines a different shape, UAT.6 should reconcile them.
5. **The ClusterIssuer name** (`imas-uat-ca`) and the CA file
   (`OUT/uat-ca.crt`) are not in the contract. The hub briefs and UAT.4 need
   them.
6. **access.json shape.** It is read tolerantly (top level, `vms` or
   `hosts`). If UAT.1 nests ports differently, `access_get` in lib.sh is the
   one place to change.
7. **Pulls from Docker Hub** (local-path-provisioner, busybox) are anonymous
   from Azure addresses and may be rate limited. cert-manager pulls from
   quay.io. A mirror is a later step if it bites.
8. That this Kubernetes minor works with the pinned cert-manager release is
   assumed, not verified.
