# UAT DMZ hub (UAT.3a)

Installs the published DMZ chart, `deploy/helm/nats` (farmerbus and the Envoy
gateway), on the `uat-dmz` cluster, waits until both are Ready, exposes them
on the DMZ address, and checks the gateway from the runner. It is one step of
the Azure UAT gate (`docs/claude-code-parallel-build-plan.md`, section 4h).

**Status: never run against a cluster.** The scripts were written against the
Shared contract while the clusters (UAT.2) and the core hub (UAT.3b) were
being written in parallel. What was checked offline is under
[Tests](#tests); expect fix rounds after the first real run.

Nothing here is Azure specific. Every script takes a kubeconfig and an
endpoints file, so the local rig (UAT.8) runs the same scripts.

| File | What it is |
|---|---|
| `values-uat.yaml` | The static half of the chart values: one replica each, small requests, the bus settings the farmer chart expects, the certificate Secret names |
| `install.sh` | Pulls the chart for `release_tag`, writes the run's values and manifests, installs, waits, exposes |
| `check.sh` | The checks from the runner, with curl and openssl only |
| `lib.sh` | Shared by both: the endpoints file, the fixed names, the generated values and manifests |
| `dmz_test.go` | The offline tests (`go test ./uat/hub/dmz/`) |
| `testdata/` | Sample endpoints files |

## Endpoints file

JSON. The `dmz` and `core` objects have the shape of the tofu output `uat`
(section 4h, Shared contract), plus optional ports and the issuer name, so
the tofu `uat` JSON is itself a valid endpoints file. Extra keys are ignored.

```json
{
  "cluster_issuer": "imas-uat-ca",
  "dmz":  { "name": "uat-dmz", "private_ip": "10.60.1.4", "public_ip": "203.0.113.10",
            "fqdn": "uatabc123-dmz.centralindia.cloudapp.azure.com",
            "ports": { "envoy": 8443, "bus": 8442 } },
  "core": { "name": "uat-core", "private_ip": "10.60.2.4",
            "fqdn": "uatabc123-core.centralindia.cloudapp.azure.com",
            "ports": { "farmer_api": 5405 } }
}
```

| Key | Required | Default | Used for |
|---|---|---|---|
| `dmz.fqdn` | yes | | the Envoy certificate's only name; SNI and Host in `check.sh` |
| `dmz.private_ip` | yes | | the node address core dials for the bus; an IP SAN of the bus certificate |
| `dmz.public_ip` | no | `dmz.fqdn` | where `check.sh` connects (the FQDN is still sent and verified) |
| `dmz.ports.envoy` | no | 8443 | Envoy's node port (and load balancer port): sprouts and the runner connect here. Owner's decision, 2026-10-06 |
| `dmz.ports.bus` (or `dmz.ports.bus_client`) | no | 8442 | the bus client node port: core connects here. Owner's decision, 2026-10-06 |
| `dmz.envoy_service_type` | no | `NodePort` | `NodePort` or `LoadBalancer`, as UAT.2's PR #130 writes it; `install.sh --expose` overrides it |
| `core.private_ip` | yes | | Envoy's farmer upstream; the NetworkPolicy peer for core |
| `core.fqdn` | yes | | the SNI Envoy sends to farmer |
| `core.ports.farmer_api` | no | 5405 | Envoy's farmer upstream port |
| `cluster_issuer` | no | `imas-uat-ca` | the cert-manager ClusterIssuer of the UAT CA (UAT.2) |

The defaults are the ports in the nats and farmer chart READMEs. The shape is
this brief's proposal: the contract names the file but does not spell it
out. UAT.2's PR #130 writes nearly the same file (`uat/k0s`,
`endpoints.json`): it names the bus port `bus_client`, which is read too
(`testdata/endpoints-uat2.json`). If UAT.2, UAT.6 or UAT.8 settle on another
shape, only `dmz_load_endpoints` in `lib.sh` changes.

## install.sh

```sh
uat/hub/dmz/install.sh --kubeconfig dmz.kubeconfig --endpoints endpoints.json \
  --release-tag v0.1.0-rc.4 --seeds-from-kubeconfig core.kubeconfig --workdir out/dmz
```

`--help` lists every option. In order, it:

1. **Pulls the chart of the release.** The chart version and the farmerbus
   image tag are both `release_tag` without its leading `v`; the tag must
   be `vX.Y.Z` or `vX.Y.Z-rc.N`, so `latest` can never get in. The chart
   comes from the Buildkite Helm registry the release publishes to
   (`packaging/buildkite/publish-helm.sh`, `docs/RELEASING.md`):

   ```
   https://packages.buildkite.com/<org>/imashelm/helm
   ```

   with `<org>` from `BUILDKITE_ORGANIZATION_SLUG` (default `yogzblr`, the
   org `ansible/README.md` uses), or `--chart-repo-url`. It is added as
   `imas-uat-imashelm` in a private, temporary Helm home (removed on exit,
   and never in the work directory, since it would hold the token), then
   `helm pull imas-uat-imashelm/nats --version <X.Y.Z[-rc.N]>`. The pulled
   `.tgz` is kept in the work directory.
   **Pre-releases:** an exact `--version` selects `0.1.0-rc.4` like any
   other version. Helm leaves pre-releases out only when it resolves a
   range or "the newest" (that is what `--devel` is for), and this script
   never does either, so nothing but the named version can be pulled. The
   pulled chart's `version` and `appVersion` are both checked against the
   tag, and the farmerbus image tag is set explicitly as well. If `imashelm`
   is private, export a Buildkite read token as `IMAS_HELM_REGISTRY_TOKEN`;
   it goes to `helm repo add --username buildkite --password-stdin`, never
   on a command line. Envoy's image is the chart's pinned
   `envoyproxy/envoy:v1.35.3`, not an imas image.
2. **Writes the run's values and manifests** into the work directory:
   `values-run.yaml` (image tag, farmer upstream, NetworkPolicy egress to
   core), `manifests.yaml` (two Certificates, two Services, one
   NetworkPolicy), then renders the chart offline into `rendered.yaml` and
   refuses a render that runs another farmerbus image or any `:latest`.
3. **Checks the cluster** (UAT.2's part): reachable, cert-manager present,
   the ClusterIssuer Ready.
4. **Creates the seed Secret** `imas-farmer-nats-seeds` in `imas-dmz`. The
   bus must hold byte-identical copies of core's five seeds
   (`deploy/helm/nats/README.md`, "Seeds"), so they come from core: either
   `--seeds-dir` (a directory with `operator.nk`, `operator-signing.nk`,
   `sys-account.nk`, `tenant.nk`, `tenant-signing.nk`) or
   `--seeds-from-kubeconfig` (copied from `imas-core/imas-farmer-nats-seeds`
   on the core cluster). Only those five keys are copied: `saasapi-user.nk`
   never enters the DMZ. With neither option the Secret must already exist.
   Nothing is printed and nothing is written outside a 0700 temporary
   directory that is removed.
5. **Applies the manifests** and waits for both certificates.
6. **Installs** release `imas-dmz` in namespace `imas-dmz` with
   `values-uat.yaml` then `values-run.yaml`, and waits for the StatefulSet
   and the Deployment to roll out, both pods to be Ready, and both exposure
   Services to have a ready endpoint.
7. With `--expose loadbalancer`, **waits for the load balancer's address**
   (up to `--timeout`) and fails if none comes.
8. **Writes `dmz.json`**, nothing secret, for the core side and enrolment:
   the sprouts' `wss://` URL, how Envoy is exposed (and the load balancer's
   address), and the bus addressing (see below).

`--render-only` stops after step 2 and touches no cluster (`--chart` then
takes a local chart; an install always pulls the published one).

### Names

Fixed, so the core side can rely on them (`values-uat.yaml` sets
`fullnameOverride`): release and namespace `imas-dmz`, bus client Service
`imas-dmz-nats-bus`, Envoy Deployment `imas-dmz-nats-envoy`, certificates
`imas-envoy-dmz-tls` and `imas-farmerbus-tls`. These are the names
`deploy/helm/farmer`'s `TestContractWithNatsChart` uses.

### Exposure

The owner's decisions of 2026-10-06, verbatim:

- "The envoy should be behind an app gateway in production. For simplicity
  let's use 8443 as node port. It should support both load balancer and
  node port."
- "Envoy and bus Services are owned by UAT.3a install.sh via chart values
  with pinned node ports; UAT.2 expose.sh must not create them."
- "Option (b): bus node port 8442, DMZ node port range 8442-8443 only."

So `install.sh` creates both Services, with their node ports pinned, and
leaves the chart's own ClusterIP Services as they are:

| Service | Selects | `--expose nodeport` (default) | `--expose loadbalancer` |
|---|---|---|---|
| `imas-dmz-nats-envoy-edge` | the Envoy pod | NodePort, node port `dmz.ports.envoy` (8443), to the `https` container port (8443) | LoadBalancer on port 8443, to the same container port, node port pinned to 8443 too |
| `imas-dmz-nats-bus-core` | the bus pod | NodePort, node port `dmz.ports.bus` (8442), to the `client` container port (5406) | the same: only core dials the bus |

- The DMZ's NodePort range is 8442-8443 (UAT.2 sets it), so both node ports
  are pinned in both modes and nothing is left to allocation. 6443, 8080
  and the other ports k0s uses stay outside the range.
- **"Via chart values" is not done** (see Open questions): the nats chart has
  no value for a node port, and its bus Service carries the websocket port
  too. The Services are this script's own manifests instead.
- **LoadBalancer** needs a load balancer controller in the cluster (k0s ships
  none; in production an application gateway sits in front instead).
  `install.sh` waits up to `--timeout` for the Service's address, writes it
  to `dmz.json` (`envoy.load_balancer_address`), and fails, naming
  `--expose nodeport`, if none comes. `check.sh --connect <address>` then
  probes it. The DMZ FQDN must resolve to that address for sprouts.
- Without `--expose`, the endpoints file's `dmz.envoy_service_type` picks the
  mode, else NodePort.
- Both Services use `externalTrafficPolicy: Local`, so traffic is not
  source-NATed: the bus rule below sees core's own address, and Envoy sees
  the client's.

Section 4h restricts who reaches these ports with the NSGs (UAT.1): core to
8442, sprouts and the runner to 8443. Inside the cluster, the chart's Envoy
policy already admits anyone on the listener port, and
`imas-dmz-nats-bus-uat-core` adds `core.private_ip/32` to the bus's client
pod port, 5406 (policies are additive; it opens nothing else).

## check.sh

```sh
uat/hub/dmz/check.sh --endpoints endpoints.json --ca-file uat-ca.pem [--kubeconfig dmz.kubeconfig]
```

Only curl and openssl touch the network (plus jq for the endpoints file and
coreutils). OpenSSL 3 is required. Every probe connects to `dmz.public_ip`
(or the FQDN, or `--connect ADDRESS`, for instance a load balancer's) and
sends the FQDN as SNI and Host; curl never uses a proxy,
because the DMZ admits only the runner's own address. The UAT CA is the only
trust anchor: the system store is switched off for openssl (`-no-CAfile
-no-CApath -no-CAstore`) and for curl (an empty `--capath`).

The expected answers are the ones `deploy/envoy/envoy.yaml`'s header
documents and the chart's rendering of it keeps
(`deploy/helm/nats/README.md`, "Envoy and `jwt_authn`"), checked against
what the repo's real-Envoy tests assert (`internal/pki/envoy_e2e_test.go`,
`internal/api/envoy_e2e_test.go`: "want 401 from jwt_authn"):

| Id | Request | Pass when |
|---|---|---|
| D1 | `openssl s_client` to the listener | the chain verifies against the UAT CA alone and the certificate names the DMZ FQDN (`Verify return code: 0 (ok)`) |
| D2 | the same with the system store only | it does not verify (the listener serves the UAT certificate, not a public one) |
| D3 | `GET /files/uat-dmz-check`, no token | 401 with jwt_authn's body (`Jwt is missing`) |
| D4 | the same with a forged token | 401 with jwt_authn's body. The token is a well-formed EdDSA JWT with `iss: imas-gateway`, signed by a key made on the spot, so only the signature is wrong |
| D5 | `GET /` with a websocket upgrade, no token | 401 with jwt_authn's body |
| D6 | the same with the forged token | 401 with jwt_authn's body |
| D7 | `GET /v1/sprout/update-manifest`, no token | 401 with jwt_authn's body (route 2b) |
| D8 | `POST /v1/enroll` with `{}` | farmer's own `401 {"error":"enrollment_failed"}` (`internal/api/handlers/enroll.go`): no JWT gate, and Envoy reaches farmer. 502, 503 or 504 is reported as farmer unreachable |
| D9 | `POST /v1/enroll` repeatedly, at most `--max-burst` (41) times | Envoy answers `429 local_rate_limited`. Its bucket holds 20 and refills 20 every 60 s, so it should come after at most 20 answered requests; a refill landing mid-burst can let 40 through, which is reported but passes |
| D10 | `POST /v1/refresh` with `{}`, while `/v1/enroll`'s bucket is empty | farmer's `401 enrollment_failed`, not 429: no JWT gate, and a bucket of its own |
| D11 | `POST /v1/enroll` every 5 s for up to `--refill-wait` (75) s | the bucket refills and farmer answers again |

"jwt_authn's body" means a 401 whose body starts with `Jwt ` or `Jwks `
(Envoy's reasons: `Jwt is missing`, `Jwt verification fails`, `Jwks doesn't
have key to match kid or alg from Jwt`), so a 401 from farmer cannot pass for
one from Envoy.

D1 to D7 and D9 need only the DMZ hub. D8, D10 and D11 need farmer up on
core. **Run it before enrolment:** D9 empties `/v1/enroll`'s bucket, and
enrolling through this Envoy is refused with 429 until it refills; D11 waits
for that (skip it with `--refill-wait 0` only if nothing enrols for the next
minute). Each check prints `PASS`, `FAIL` or `SKIP` with its id; the exit
code is 1 if any failed. With `--kubeconfig`, a failure also prints the
pods, Services and endpoint slices of `imas-dmz`.

## What is assumed about the core side

UAT.3b builds the core hub in parallel; these are the assumptions this side
makes, and what `dmz.json` gives it.

1. **The seeds are core's.** UAT.3b creates `imas-farmer-nats-seeds` in
   `imas-core` with the repo's tooling. This side copies five of its keys
   and generates nothing. **Owner's decision, 2026-10-06: "Install order is
   core first, then DMZ."** So by the time this runs, the core hub and its
   seed Secret exist, `--seeds-from-kubeconfig core.kubeconfig` is the way
   to pass them, and D8, D10 and D11 of `check.sh` can reach farmer.
   (Section 4h of the plan still says "DMZ install, core install"; amending
   it is outside this brief.)
2. **farmer's API is reachable at `core.private_ip:core.ports.farmer_api`**
   from the DMZ node, over HTTPS, and serves `/v1/enroll`, `/v1/refresh`,
   `/files/`, `/v1/sprout/update-manifest` and the JWKS at
   `/v1/.well-known/jwks.json` there. How core exposes it (NodePort, host
   port) is UAT.3b's choice, as long as the endpoints file
   names the port. farmer's NetworkPolicy admits the DMZ: its
   `networkPolicy.dmz.*` selects pods, which a peer in another cluster is
   not, so core needs an `ipBlock` for `dmz.private_ip/32` on the farmer API
   port (traffic from Envoy is source-NATed to the DMZ node's address).
3. **farmer and saasapi reach the bus at
   `tls://imas-dmz-nats-bus.imas-dmz.svc.cluster.local:5406`**: the farmer
   chart's `bus.serviceName=imas-dmz-nats-bus`, `bus.namespace=imas-dmz`,
   `bus.port=5406` (its defaults apart from the service name). That name has
   to resolve inside the core cluster to `dmz.private_ip`, with port 5406
   arriving at `dmz.ports.bus` (node port 8442); for example a namespace
   `imas-dmz` in the core cluster with a selectorless Service
   `imas-dmz-nats-bus` on 5406 and an EndpointSlice for
   `dmz.private_ip:8442`. `dmz.json`'s `bus`
   object carries both halves. TLS: farmer and saasapi verify the bus
   Service FQDN, which the bus certificate carries; it also carries
   `dmz.private_ip` and `dmz.fqdn` in case core sets `bus.tlsServerName`
   instead. Core's own egress policy needs an `ipBlock` for
   `dmz.private_ip/32` on that port, for the same reason as in 2.
4. **Core's connections arrive from `core.private_ip`.** Pod egress leaving
   the core node is source-NATed to the node's address (true of k0s's
   default kube-router and of kind); the bus rule admits that address only.
5. **One UAT CA on both hubs.** UAT.2 sets up the same per-run root as a
   ClusterIssuer on each hub, so the bus certificate's `ca.crt` is the CA
   farmer's and saasapi's bus CA settings (`bus.ca`, `tls`) must trust.
6. **farmer hands sprouts `wss://<dmz.fqdn>:<dmz.ports.envoy>/`** as
   `bus.sproutBusURLs` (`dmz.json`, `envoy.sprout_bus_url`), and the
   enrolment (UAT.4) points sprouts' `farmerinterface` and `farmerapiport`
   at the same host and port, with the UAT CA as `sproutrootca` and
   `sproutrootcatofu: false`.
7. **Same `organization`** on both charts (`imas`, the farmer chart's
   default), and farmer's `gatewayjwtttl` at its 24 h default, which the
   `/v1/refresh` bucket here is sized for (a six-sprout fleet: 1 per second,
   300 burst).
8. **farmer's API certificate is not checked by Envoy.** Upstream TLS
   verification is off, as in the reference `envoy.yaml`, because the
   farmer certificate comes from core's own PKI. Envoy sends `core.fqdn` as
   SNI so that turning verification on later needs only that name in
   farmer's certificate and its CA in `envoy.upstreamTLS`.

## Tests

`go test ./uat/hub/dmz/` (part of `go test ./...`; each test skips when a
tool it needs is missing, and with `IMAS_REQUIRE_HELM=1`, as in CI, a missing
helm, bash or jq fails the render tests instead):

- **Render** (`TestRender*`): packages `deploy/helm/nats` the way
  `publish-packages.yml` does (version and appVersion `0.1.0-rc.4`), runs
  `install.sh --render-only` for four endpoints files (a full one, a bare
  tofu `uat` JSON, UAT.2's shape, and one with NodePort-range ports) and for
  `--expose loadbalancer`, runs `helm lint` with the same values, and checks the render:
  the Envoy Deployment mounts `imas-envoy-dmz-tls`, which the Certificate
  for exactly the DMZ FQDN from the UAT ClusterIssuer writes; the listener
  is 8443 with that certificate; the `farmer_api` and `recipe_service`
  clusters are the core private IP and farmer API port; the JWKS URL;
  `nats_websocket` is the bus Service on 5407; the bus settings the farmer
  chart expects; replicas of one and the small requests; the farmerbus
  image is the release's and nothing is `:latest`; the NetworkPolicy
  egress to the core IP; the exposure Services select the right pods and
  target ports that exist, Envoy as NodePort 8443 (or a LoadBalancer on
  8443, node port pinned to 8443) and the bus as NodePort 8442; and
  `dmz.json`. `TestRenderServiceTypeFromEndpoints`: the endpoints file's
  `dmz.envoy_service_type` picks the mode unless `--expose` is given.
- **The install path with stub kubectl and helm** (`TestInstallWithStubs`):
  the order of the steps; the registry token reaching `helm repo add` on
  stdin only and never left in the work directory; an exact-version `helm
  pull` and no `--devel`; only the five bus seeds read from core (never
  `saasapi-user.nk`) and put in the DMZ Secret unchanged; every DMZ call
  carrying the DMZ kubeconfig. `TestInstallLoadBalancerWithStubs`: the load
  balancer's address lands in `dmz.json`, and no address fails the
  install.
- **Refusals** (`TestInstallRefuses`, `TestCheckRefuses`): bad tags
  (`latest`, no `v`, `-beta`), a chart whose version or appVersion differs
  from the tag, bad endpoints, conflicting options.
- **check.sh against a fake Envoy** (`TestCheck*`), with the real curl and
  openssl: a TLS server with a test CA that answers as `envoy.yaml`
  documents passes D1 to D11; fakes that leave `/files/` open, accept a
  forged token, do not rate limit, cannot reach farmer, share the
  `/v1/refresh` bucket, present another CA's certificate, or a certificate
  for another name each fail the right checks.
- **Lint** (`TestLint`): `shellcheck -x` on the scripts and `yamllint -s` on
  `values-uat.yaml` and the generated values and manifests.

Also run by hand for this brief: `kubeconform -strict` (Kubernetes 1.30
schemas, cert-manager from the CRDs catalog) on the rendered chart and the
generated manifests, valid. **Not run:** anything against a cluster, the
Buildkite registry, GHCR or a real Envoy; `envoy --mode validate` on the
render (no Envoy binary here); the API server accepting node ports 8442
and 8443, which depends on UAT.2's range.

## Owner's decisions (2026-10-06), answering earlier open questions

- **Exposure:** Envoy on node port 8443, NodePort or LoadBalancer; the Envoy
  and bus Services are this script's, with pinned node ports, and UAT.2's
  `expose.sh` must not create them. The bus is on node port 8442 and the DMZ
  NodePort range is 8442-8443 only (option (b) of UAT.2's PR #130). This
  answers the earlier questions about 8443 falling outside UAT.2's range and
  about two Services wanting one node port.
- **Install order:** core first, then DMZ (assumption 1 above).

## Open questions

1. **"Via chart values".** The owner's decision says the Services are owned
   "via chart values with pinned node ports". `deploy/helm/nats` cannot do
   that today: `envoy.service` and `bus.service` have a `type` value but no
   node port value, and the bus Service carries both the client port (5406)
   and the websocket port (5407), so making it a NodePort would also give
   5407 a node port, which the 8442-8443 range has no room for and which
   only Envoy should reach. This PR keeps the Services in `install.sh`'s own
   manifests, with pinned node ports. Doing it through chart values needs a
   change to `deploy/helm/nats` (node port values, and a bus Service that
   can expose only the client port), outside this brief.
2. **Bus port toward core.** The Shared contract says "core reaches only the
   bus websocket port on the DMZ". farmer and saasapi dial the bus's TCP
   client port, `tls://...:5406` (farmer chart, "Reaching the bus"); only
   Envoy uses the websocket port 5407, inside the DMZ cluster. Core reaches
   the client port on node port 8442 (owner's decision), so the NSG rule is
   core to 8442 (PR #135 is being updated by its owner).
3. **The endpoints file's shape** is this brief's proposal (above); UAT.2's
   PR #130 writes nearly the same file and both are read here. UAT.3b and
   UAT.8 should read and write the same one.
4. **Section 4h still lists "DMZ install, core install"**; the owner's
   install-order decision needs it amended, outside this brief.
5. **LoadBalancer in UAT.** No load balancer controller is installed on the
   k0s hubs, so `--expose loadbalancer` would wait and fail there; it is
   ready for a cluster that has one.
6. **Is `imashelm` private?** If it is, the workflow needs a Buildkite
   read token as `IMAS_HELM_REGISTRY_TOKEN`; the Buildkite Helm URL and the
   `buildkite` user name are from Buildkite's documentation and have not
   been tried against this registry.
