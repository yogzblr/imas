# Units for the next Azure runs (P20, P13, P24, P23, P25a)

Read `docs/briefs/ORCHESTRATOR.md` first: its session prompt (zero open items, repo-wide
search, brief errors decided by a fixed order) applies to every unit here. Owner decisions
for this file, made 2026-10-13, are final:

- Two runs, in this order. **Run 2**: the single-node gate re-run on current main, with the
  fleet-update path on (unit R1). **Run 3**: the HA run on 3 core and 3 DMZ k0s nodes
  (units H1 to H5). The single-node run stays as the plumbing pass (owner, 2026-10-11).
- The HA run uses **Versity Gateway over Azure Blob** as its object store (design D18); no
  distributed RustFS. The single-node run keeps RustFS.
- Error windows for the HA tests: **pod kill**: no API call fails after 3 client retries
  (waits 1 s, 2 s, 4 s) and every sprout is connected again within 30 s. **Node stop**: the
  API, a new enrolment and a `cmd.run` are served by other pods within 60 s, and every sprout
  that was on the stopped node's bus node is connected again within 60 s.
- Storage: local volumes (owner, 2026-10-11). Stateful services (PXC, OpenBao, Valkey) are
  3-node replicated on their own; farmer, saasapi and the bus carry no volume.
- Sizes: core nodes `Standard_D4s_v5` (3), DMZ nodes `Standard_D2s_v5` (3), kept as tofu
  variables. Quota to request: 18 Dsv5 vCPU plus the 12 B2ls_v2 vCPU the sprouts use today.

Every unit checks the facts it relies on against main before using them (paths and value
names below come from reading main on 2026-10-13). A fact that is wrong is a brief
correction, not a stop.

## R1: UAT registers the sprout release and turns the update path on (P20 option C, P13)

Scope: `uat/hub/core` (`gen-values.sh`, `install.sh`, `finish.sh`, `values/farmer-uat.yaml`,
`check.sh`, secrets scripts), `uat/tests`, `.github/workflows/uat.yml`, `uat/README.md`, docs.

1. Enable the operator plane in the UAT values (`saasapi.operator.enabled`). The registration
   hook Job needs, and `seeds.sh`/`saasapi-secrets.sh` must now create: the operator listener
   TLS Secret with its CA (the Job verifies the listener with that CA) and the operator bearer
   token Secret. Take the exact value and Secret names from `deploy/helm/farmer/values.yaml`
   and `_helpers.tpl` (`sproutRelease.registers`). No `fleetreleaser`, no fleet-releaser token,
   no signing key: P22 removed them; delete any UAT reference to them.
2. `finish.sh` registers the release by the existing `helm upgrade --reuse-values --set
   sproutRelease.register=true`, then waits for the registration Job to complete and checks,
   through the operator API, that the stamped version is registered with the GPG-signed
   `checksums.txt` and signature stored; the script fails if it is not. The chart under test
   must be the published chart for the release tag being tested (it carries the stamped
   `files/sprout-release.json`); `uat.yml` already takes the tag, so make the chart reference
   and the tag one input and check at the start that the tag's release is GPG-signed (the
   `checksums.txt.sig` asset exists) and fail early if not.
3. `dispatch_flags` today only tells the tests the flags are on. Make the input turn them on:
   when it is true, the UAT values set `SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED` and
   `IMAS_SELF_UPDATE_ENABLED` through the chart values (names from the chart), and when it is
   false they are off. Fix the comment in `uat.yml` lines 79 to 82. The tests keep checking
   `IMAS_UAT_DISPATCH_FLAGS`.
4. L5 (self-update) must exercise the P22 path: a sprout on an older package updates to the
   registered release, verifying the GPG signature against `/etc/imas/fleet-signing-keys.asc`
   (the repo's `gpg-public-key.asc`), and refuses a release whose `checksums.txt` has been
   altered (the test posts an altered pair to a scratch version and expects a refusal and no
   install). Extend the existing L5 test; keep its other checks.
5. P13 items that touch these files and that a run depends on: `check.sh` "must refuse" checks
   assert the refusal reason (the response body's error code), not only a 401; add
   `validate-rustfs.sh` (it is referenced and missing) as a script that PUTs, GETs and lists
   in the three buckets and the accounts bucket with the scoped credentials; pin the Keycloak
   and Envoy images by digest in the UAT values.
6. P20's row, P13's row and `uat/README.md` item list are updated to match.

Search gate: `operator.enabled`, `register`, `fleetreleaser`, `fleetReleaser`, `dispatch_flags`,
`DISPATCH_FLAGS`, `IMAS_SELF_UPDATE_ENABLED`, `SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED`, `minio`
across `uat/`, `deploy/`, `docs/`, `.github/`. Tests: the existing Go tests that render both
UAT hubs must cover the new values (flags on and off, operator on); a test that `finish.sh`
fails when the registration Job fails (using the repo's script-test pattern).

## H1: tofu for 3 + 3 nodes (P24 item 1)

Scope: `uat/tofu`, `.github/workflows/uat.yml` (inputs and outputs only), `uat/access`.

1. Variables `core_node_count` and `dmz_node_count` (default 1 so the single-node run is
   unchanged; the HA run sets 3), `core_node_size` (default current, HA run D4s_v5) and
   `dmz_node_size`. VMs spread across availability zones where the region has them (use
   `zones` from a data source; fall back to none).
2. A stable address per hub for the k0s API: an internal Standard load balancer for the core
   hub's API (6443) and the DMZ hub's API, backend pool all nodes of the hub, health probe on
   6443. For the DMZ's public ports, a Standard public load balancer replaces the single VM's
   public IP when `dmz_node_count > 1`, with rules for the ports the DMZ publishes today
   (read them from `network-security.tf` and `dns.tf`).
3. NSG rules: node to node inside each hub for etcd (2380, 2379), kubelet (10250), k0s join
   (9443), konnectivity (8132) and the CNI ports the k0s config uses; keep every existing
   rule. `dns.tf`: Private DNS records for the API addresses and for each node.
4. Outputs: node names and private addresses as lists, API addresses, and the VM names the HA
   tests stop (`ha_node_names`). `destroy.sh` removes everything the new resources created
   and `verify teardown` still passes; add the new resources to the teardown check.
5. Quota check at the start of `tofu apply` (a plan-time `check` or a script step) that fails
   with the vCPU numbers when the subscription's quota is short.

Tests: the repo's tofu tests (`uat/tofu/tests`, `scripts_test.go`) updated; `tofu validate` and
`tofu plan` with both variable sets render (use the repo's fake-provider approach if the tests
cannot reach Azure); counts, zones, rules and outputs asserted.

Corrections made while building H1 (2026-10-13; the code on main and the error windows above
decide):
- The size variables were `core_size` and `dmz_size`; they are renamed to `core_node_size` and
  `dmz_node_size` (defaults unchanged). The node counts accept 1, 3 or 5 (etcd quorum).
- The internal load balancer of an HA hub carries the hub's private ports as well as the API
  (DMZ: Envoy 8443, bus 8442; core: farmer 5405, accounts store 9000), and `<hub>.<zone>`
  points at it: with a node's own address, stopping that node would cut sprouts, enrolment and
  the core-to-bus path, against the node-stop window.
- Core gets a public load balancer too (443), not only the DMZ: the runner reaches saasapi on
  core 443, and the node-stop test stops a core node.
- The health probes come from `AzureLoadBalancer`, which the NSGs' `DenyAllIn` drops, so an HA
  hub adds a probe rule on the load-balanced ports.
- The CNI ports: the k0s config uses kube-router; Azure drops IP-in-IP inside a VNet, so the
  NSG opens kube-router's BGP (TCP 179) and its FOU overlay (UDP 5555), and H2 sets the
  overlay to FOU (below).
- `ha_node_names` is its own tofu output (per hub, the nodes of an HA hub): the `uat` output
  keeps the Shared contract's top-level keys; each hub object gains `node_names`, `node_ids`,
  `node_private_ips`, `api_address` and `api_fqdn`.
- The workflow takes one input, `hub_nodes` (1 or 3), checked and mapped to the tofu variables
  by `uat/scripts/check-inputs.sh` (3 sets `core_node_size=Standard_D4s_v5`).
- `tofu validate` takes no variables; both variable sets are planned and applied on mocked
  providers by `tofu test`.

## H2: k0s with 3 controller+worker nodes on etcd (P24 item 2)

Needs H1. Scope: `uat/k0s` and its tests, `uat/access`, `.github/workflows/uat.yml` (the k0s step).

1. k0sctl config template for N nodes: every node `controller+worker`, etcd as the datastore
   (not kine on SQLite), `spec.api.externalAddress` the load balancer address and the load
   balancer name in `sans`; single-node mode unchanged when N is 1. The address is the `uat`
   output's `<hub>.api_address` and its name `<hub>.api_fqdn` (H1). Two Azure facts H1 found:
   Azure drops IP-in-IP inside a VNet, so kube-router's pod overlay must be FOU
   (`overlay-type` full, `overlay-encap` fou, UDP 5555, which H1 opens between a hub's nodes);
   and an internal load balancer drops a flow from a backend to its own frontend when it lands
   on that node, so a node reaches its own hub's API on its own address or through k0s
   node-local load balancing, never through `api_address`.
2. `bootstrap.sh` and `check.sh`: remove the single-node assumptions (hostPort and NodePort
   handling run against all nodes; kubeconfig uses the external address; waits are for N nodes
   Ready and for etcd to have N members). `check.sh` fails when the hub has fewer Ready nodes
   or etcd members than expected.
3. Bastion tunnels in `uat/access` reach the hub's API through its address and each node for the
   VM-stop tests.

Tests: the existing k0s script tests with a 3-node fixture; template rendering for 1 and 3
nodes; `check.sh` negative cases.

## H3: Versity Gateway as an optional chart component (P25 first half)

Scope: `deploy/helm/farmer` (templates, values, README, chart tests), `DEPENDENCIES.md`.

1. Add Versity Gateway (Apache-2.0, design D18) as an optional component, off by default
   (`versity.enabled`). Image pinned by digest; Deployment with `replicas` (default 2) and
   topology spread, run as non-root with a read-only root file system; backend `azure` with
   account name and key from a Secret (`versity.azure.credentialsSecret`, keys named in the
   README); a Service on the S3 port that farmer, saasapi and the bus use as their S3 endpoint
   when `versity.enabled` (the chart sets `objectStore.endpoint` and `accountStore.endpoint`
   defaults to it, still overridable); a NetworkPolicy allowing the S3 clients in and the Azure
   Blob endpoint out; readiness and liveness probes on the gateway's health endpoint (read it
   from the image's documentation); the S3 root credential and the per-component users
   (farmer writer, accounts reader for the DMZ, saasapi, sprout JWT) created through the
   gateway's IAM file from Secrets, scoped to their buckets as in design D22. Containers for
   the buckets (`imas-accounts`, `imas-sprout-jwts`, recipes and jobs buckets as the chart
   names them) are created by a hook Job (`versity.createBuckets`).
2. Add the licence line for Versity Gateway to `DEPENDENCIES.md`.
3. README: how to set it up for Azure Blob, the Secret formats, and how a customer uses a
   different S3 endpoint instead.

Tests: chart tests render with `versity.enabled` true and false; the S3 endpoints, Secret
references, NetworkPolicy and bucket job are asserted; a values-schema/validation test fails
when `versity.enabled` is true without the Azure credential Secret.

Corrections found while building H3 (2026-10-13; built as below):

- The chart has four object store credentials, not one per bucket: `farmer`
  (`objectStore.credentialsSecret`, which already covers the recipe, job **and sprout JWT**
  buckets; there is no separate sprout JWT credential), `accounts-writer`
  (`accountStore.credentialsSecret`), `accounts-reader` (new
  `versity.accountsReader.credentialsSecret`, the DMZ loader's pair) and `saasapi-recipes`
  (`saasapi.recipes.credentialsSecret`). Those are the gateway's users.
- Helm cannot render the gateway's IAM file from Secrets it does not read, so each gateway pod's
  init container writes it (`farmer versity-iam`, `internal/versitysetup`) into a memory-backed
  volume the gateway mounts read-only. The bucket hook is `farmer versity-buckets`; the scoping
  is per-bucket policies naming the users' access key IDs (Versity's internal IAM has no
  per-user policy). `versity.createBuckets` is the Job's settings map.
- The bus is the nats chart's: the farmer chart cannot set its S3 endpoint. NOTES prints the
  nats chart's `accountStore.*` values for the gateway; H4 wires them in UAT.
- The gateway's Service is plain HTTP in the cluster (the S3 clients have no custom-CA setting);
  with `versity.enabled`, `objectStore.endpoint` must stay empty (set, the render fails).

## H4: HA hub values and wiring (P24 items 3 and 4)

Needs H2 and H3. Scope: `uat/hub/core`, `uat/hub/dmz`, `uat/tests/harness` where it reads the
hub layout, `uat/README.md`.

1. A values overlay per hub for the HA run (`values-ha.yaml`, selected by the node count
   input, the workflow's `hub_nodes` from H1): farmer, saasapi, Envoy and the bus at 3 replicas with `topologySpreadConstraints`
   over nodes (maxSkew 1, `DoNotSchedule`), PodDisruptionBudgets on, bus 3 nodes with the
   `emptyDir` resolver directory; PXC 3 nodes with no `unsafeFlags`; OpenBao 3-node raft
   (replacing single-node raft, `retry_join` between pods, auto-unseal as the UAT already
   does); Valkey replicated (read the chart for the supported mode and use it with 3 nodes);
   `versity.enabled=true` with the Azure Blob account created by tofu (add a storage account
   and containers to H1's tofu output list if H1 did not, as part of this unit) and the
   loader/accounts credentials wired as in design D22; the single-node values stay the default.
2. The scripts (`install.sh`, `finish.sh`, `seeds.sh`, `openbao-bootstrap.sh`, DMZ `install.sh`)
   work for N nodes: join OpenBao peers, init once, wait for every replica Ready, and copy the
   DMZ trust as today.
3. Local volumes: stateful services use the nodes' local volume class; document in
   `uat/README.md` that a stateful pod on a stopped node stays unavailable until the node
   returns while the replicas on the other nodes serve (the tests below assume this).

Tests: both hubs render with the HA overlay; asserted: replica counts, spread, PDBs, PXC 3
without `unsafeFlags`, OpenBao 3 peers, Versity on, no PVC for farmer, saasapi, bus.

## H5: the `ha` test tier (P24 item 6, P23)

Needs R1 and H4. Scope: `uat/tests` (new `ha_test.go`, harness, `catalogue.tsv`, `run.sh`),
`.github/workflows/uat.yml` (an `ha` tier input, a step that stops and starts VMs with the
Azure login the tests step already has), `uat/README.md`.

Scenarios (each logs its timings; windows are the ones at the top of this file):
- **HA1 pod kill.** For farmer, saasapi, Envoy and each bus pod in turn: delete one pod while a
  loop makes an API call every second, enrols a new sprout every 10 s and runs `cmd.run` on
  an enrolled sprout every 5 s. Assert the pod-kill window, no duplicate sprout JWT or box
  key for the enrolments made during the kill, and that the account loader on a restarted bus
  pod is ready only after loading every account.
- **HA2 node stop.** Stop the VM of one core node (the one hosting a farmer pod, a bus pod and a
  replica of each stateful service), then the same for a DMZ node. During the stop run the
  same loops; assert the node-stop window; assert PXC, OpenBao and Valkey still serve with two
  replicas. Start the VM again and assert the node and all its pods are Ready within 10
  minutes and that no data was lost (the sprouts and recipes created during the stop exist).
- **HA3 rolling restart.** `helm upgrade` with a changed pod annotation for farmer, saasapi and
  the bus; assert sprouts stay enrolled and no call fails after 3 retries.
- **HA4 empty bus node.** Delete one bus pod and its `emptyDir`, and while farmer is scaled to 0
  assert the node comes back ready from the object store alone; scale farmer back.
- **HA5 lost event.** Block the event subject for one bus pod (a NetworkPolicy test) while an
  account is created and a sprout revoked; assert the timer repairs it within the reconcile
  period and every bus node rejects the revoked sprout.
- Design tests T1 to T8 (`docs/design/imas-openbao-signing-design.md` section 11) are mapped
  one to one onto these scenarios and the existing tiers in a table in `uat/tests/README.md`;
  any T that none of them covers is added as a scenario.

Tests: the harness unit tests with the fake stack (`uat/tests/fakestack`) for the loops, the
window assertions (a test where the fake takes 45 s and one where it takes 90 s) and the VM
stop/start wrapper (fake `az`).

## H6: final gate for the next runs

Needs every other unit in this file. No features. On main: `go build`, `go vet`,
`go test -race ./...`, `CGO_ENABLED=0 go build ./...`, `helm template` for both charts with
every ci and uat values file including the HA overlay and `versity.enabled`, `tofu validate`
for 1 and 3 nodes, `scripts/status/rollup.py --check`. Write the runbook `uat/RUNBOOK.md`: the
exact dispatch inputs for Run 2 and Run 3, the quota to request, the owner prerequisites
(GPG secrets in the `goreleaser` environment only, `v*` tag ruleset, a signed release
candidate tag, the security review before the dispatch flags are used outside UAT), what each
run proves, and how to read the report. Status fragment: P20 and P13 updated, P24 and P23
built and awaiting the run (Amber), P25 first half built (Fluent Bit still open), P1 left
awaiting the runs.
