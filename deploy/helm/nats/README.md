# imas DMZ bus chart (`deploy/helm/nats`)

**FLAG FOR SECURITY REVIEW.** This chart deploys the front door of imas's
trust chain: the DMZ-facing NATS bus and the Envoy gateway in front of it.
Read [Security review notes](#security-review-notes) before exposing it
to anything. Treat the defaults as a non-production starting point.

It deploys:

- **The bus.** `cmd/farmerbus` runs as a StatefulSet. It is the DMZ half
  of the old single `farmer` binary (`RunNATSServer()`), an embedded
  nats-server with decentralized JWT auth: Operator → Account-per-tenant
  → User-per-sprout (`docs/design/imas-nats-jwt-auth-design.md`).
- **The gateway.** Envoy runs as a Deployment, configured from
  `deploy/envoy/envoy.yaml` (`docs/design/imas-envoy-enrollment-design.md`):
  - `/v1/enroll` (join token) and `/v1/refresh` (NKey proof of
    possession, checked by farmer) have no JWT check. Each has its own
    rate-limit bucket.
  - `/files/` (recipe download) and the `wss://` NATS route are both
    gated by `jwt_authn` on the EdDSA gateway JWT.
- **NetworkPolicies** for both, limited to the documented ports.

It does **not** deploy farmer (core) or saasapi. Those belong to the
separate `deploy/helm/farmer` chart.

```
 sprouts ──wss/https:8443──▶ Envoy ──wss:5407──▶ farmerbus (StatefulSet)
                              │                     ▲
                              └─https:5405──▶ farmer (core, other namespace)
                                  /v1/enroll,        │
                                  /v1/refresh,       │
                                  /files/, JWKS      └─tls:5406 (core dials out)
```

## Before you install

1. **A seed Secret** (`natsSeeds.secretName`). The chart never generates
   one. See [Seeds](#seeds).
2. **A bus TLS certificate.** Either a `kubernetes.io/tls` Secret with
   `ca.crt`, or OpenBao PKI. See [Bus TLS](#bus-tls).
3. **A DMZ edge certificate** for Envoy (`envoy.tls.secretName`). This is
   what sprouts' `wss://` connections terminate against.
4. **A farmerbus image.** This repo doesn't publish one yet: `docker/`
   and `.goreleaser.yaml` only have farmer and sprout targets. Build one
   from `./cmd/farmerbus` with `CGO_ENABLED=0`, on the same pattern as
   `docker/farmer.dockerfile`, and set `bus.image.*`.
5. **Core-side settings**, in the farmer chart, not here:
   - farmer's `farmerorganization` must equal `bus.organization`.
   - farmer must dial the bus at
     `tls://<release>-nats-bus.<ns>.svc.cluster.local:5406`.
   - farmer must mount the same seed Secret.
   - farmer's `IMAS_SPROUT_BUS_URLS` must list Envoy's external `wss://`
     address.
   - farmer's namespace needs its own NetworkPolicy: egress to the bus on
     5406, and ingress from this chart's Envoy on 5405.

```sh
helm install imas-dmz deploy/helm/nats -n imas-dmz \
  --set bus.image.repository=<registry>/imas-farmerbus --set bus.image.tag=<tag>
```

## Seeds

`internal/pki/jwtauth.go` resolves each NKey seed in this order:

1. `IMAS_NATS_<NAME>_SEED_FILE`
2. `IMAS_NATS_<NAME>_SEED`
3. the file on disk
4. generate and persist a new one

A seed supplied externally is never written back to disk. The chart
mounts each entry of `natsSeeds.seeds` from the Secret and sets the
matching `_SEED_FILE` variable. It never uses the raw `_SEED` form, never
renders a Secret, and projects only the listed keys. For example,
`saasapi-user.nk` stays out of the DMZ even if the Secret has it.

All five default seeds are required, and rendering fails without them.
Each must be **byte-identical to the seed cmd/farmer uses**. Here's why
each one is needed:

| Seed | Why the bus needs farmer's copy |
|---|---|
| `OPERATOR` | The bus mints its `operator.jwt` from it. A different key means a different trust anchor, so every Account JWT farmer pushes is rejected. |
| `OPERATOR_SIGNING` | It's listed in the bus's operator JWT. farmer signs Account JWTs with it. |
| `SYS_ACCOUNT` | It's the system account. farmer pushes claims updates as a SYS user. |
| `TENANT`, `TENANT_SIGNING` | They form the legacy tenant Account the bus seeds at boot. farmer's own User JWT lives in this Account. farmer only pushes it when it changes, so a bus with its own tenant seed would reject farmer until then. |

`deploy/farmer/externalsecrets.yaml` currently syncs only
`sys-account.nk` and `saasapi-user.nk` into `imas-farmer-nats-seeds`. Add
`operator.nk`, `operator-signing.nk`, `tenant.nk` and `tenant-signing.nk`
to it, or to a DMZ-namespace ExternalSecret reading the same OpenBao
path.

**On an existing install, import farmer's current seeds from
`{FarmerPKI}/nats-auth/`. Don't generate new ones.** The reason is the
same as for the SYS seed in `deploy/farmer/README.md`.

The bus still generates some material on its PVC, because that's what
the binary does:

- `sys-user.nk` and `.jwt`: a SYS-account user. The bus already holds
  the SYS Account seed, so this adds no privilege.
- The resolver's JWT store.

Per-tenant Account seeds (`IMAS_NATS_TENANT_<ID>_SEED_FILE`) are
optional. Set them through `natsSeeds.extraSeeds`.

`/etc/imas/farmer` is mounted read-only on purpose. `config.LoadConfig`
folds **every** environment variable into its config and ends with
`jety.WriteConfig()`, which would otherwise write them all back into that
file. For the same reason the pods set `enableServiceLinks: false`.

## Bus TLS

- **`bus.tls.mode: secret`** (the default) mounts `tls.crt`, `tls.key`
  and `ca.crt` from `bus.tls.secretName`, for example a cert-manager
  Certificate. `internal/certs.GenCert` sees the files and issues
  nothing.
  - The SANs must cover what Envoy dials: `envoy.upstreams.natsWebsocket.sni`,
    which defaults to the bus Service FQDN.
  - They must also cover what core dials. core uses its own
    `farmerinterface` as the TLS ServerName.
- **`bus.tls.mode: openbao`** issues a cert from OpenBao PKI at startup
  through `IMAS_CERTS_OPENBAO_*`, into a memory `emptyDir`. The SANs are
  `bus.tls.certHosts` or the Service and per-pod DNS names.

Nothing in farmerbus rotates a cert while it runs. It only reloads on
SIGHUP, and nothing here sends one. Roll the pods when the cert changes,
for example with `bus.podAnnotations: {reloader.stakater.com/auto: "true"}`.
In openbao mode, a restart is the rotation.

## Clustering

`bus.replicaCount` sets the StatefulSet size. When it's above 1, the
chart renders:

- a cluster port on the pods and the headless Service,
- bus↔bus NetworkPolicy rules and a PDB,
- `IMAS_BUS_CLUSTER_NAME`, `IMAS_BUS_CLUSTER_PORT` and
  `IMAS_BUS_CLUSTER_ROUTES` (comma-separated
  `tls://<pod>.<headless>.<ns>.svc.cluster.local:<port>`).

That shape follows `docs/design/imas-1m-scale-plan.md` Phase 2: a
full-mesh core-NATS cluster, and a "full" resolver that syncs Account
JWTs between nodes.

**`cmd/farmerbus` does not support this yet.** `ConfigureNats` sets no
`Cluster` options, so extra replicas would be unconnected servers:

- A claims push from core (one TCP connection, one pod) would reach one
  node only.
- A message published on one node would never reach subscribers on
  another.

The chart therefore refuses `replicaCount > 1` unless you set
`bus.cluster.routesSupported: true`. Only set that once farmerbus reads
the `IMAS_BUS_CLUSTER_*` variables. The expected contract:

- a route listener on `IMAS_BUS_CLUSTER_PORT`,
- `Routes` parsed from `IMAS_BUS_CLUSTER_ROUTES`,
- route TLS with the node cert, verified against the root CA (so the
  cert also needs client-auth usage).

## Envoy and `jwt_authn`

The Envoy config (`templates/envoy-configmap.yaml`) matches
`deploy/envoy/envoy.yaml` route for route:

| Route | Gate | Rate limit | Upstream |
|---|---|---|---|
| `/v1/enroll` (prefix) | none; the join token is checked by farmer | fixed 20 per 60s per Envoy | `farmer_api` |
| `/v1/refresh` (exact path) | none; farmer checks an NKey proof of possession | `envoy.refreshRateLimit`, sized from the fleet | `farmer_api` |
| `/files/` (prefix) | `jwt_authn` | none | `recipe_service` |
| `/` (everything else) | `jwt_authn` | none | `nats_websocket` (the bus) |

`chart_test.go`'s `TestRoutesMatchReferenceEnvoyConfig` fails if the
routes, their gates, clusters or buckets drift from the reference file,
or if `requirement_map` or `rules` do.

**`/v1/enroll`'s bucket is deliberately not a value.** The join token is
its only credential, so the small budget is what bounds join-token
guessing, and it should not grow with the fleet.

**`/v1/refresh`'s bucket** uses the formula and values shape from
`deploy/envoy/_refresh-rate-limit.tpl` and `values.rate-limit.yaml`, so
an ops values block merges as-is:

```
tokens_per_fill = ceil(fleetSize * 30 * headroom * fillIntervalSeconds
                       / (17 * gatewayJwtTtlSeconds * envoyReplicas))
max_tokens      = tokens_per_fill * (burstSeconds / fillIntervalSeconds)
```

`envoyReplicas: null` (the default) uses `envoy.replicaCount`. With the
defaults (1M sprouts, 24h TTL, 2 replicas, headroom 2) that renders 21
per second and 6,300 max. With 4 replicas it renders the reference's 11
and 3,300. See `deploy/envoy/README.md`, "Sizing the /v1/refresh
bucket". Keep `gatewayJwtTtlSeconds` equal to farmer's `gatewayjwtttl`.

Where the chart adds to the reference:

- **Early header stripping.** Client-supplied copies of the
  `claim_to_headers` headers (`x-imas-sprout-nkey`) are removed before
  any filter runs, including on the two un-gated routes.
- **Optional upstream TLS verification** through
  `envoy.upstreamTLS.caSecretName`/`caConfigMapName`. It checks the SAN
  against each upstream's SNI. The reference file doesn't verify
  upstream certs at all.
- **TLS 1.2 minimum** downstream, plus `--disable-hot-restart`, a
  read-only root filesystem and a non-root user.

The JWKS source is a value:

- **`jwks.source: remote`** (the default) fetches
  `https://<farmerAPI>/v1/.well-known/jwks.json`, or `jwks.remote.uri`.
  It re-fetches every `cacheDuration`, so gateway-key rotation needs no
  restart.
- **`jwks.source: local`** reads a static JWKS, inline or from a
  ConfigMap. Rotation then needs a new document and a rollout.

### Verification status

Revalidated on 2026-09-26 against `main` after PRs #5–#13, with no
patches. Everything ran against real binaries: `envoyproxy/envoy:v1.35.3`,
OpenBao 2.4.1 (dev) for PKI and Transit, MySQL 8.4, Valkey 8.1, and
farmer, farmerbus and sprout built from this branch.

- **The repo's own real-Envoy e2e suites pass through this chart's
  rendered Envoy config.** These are
  `internal/pki` `TestSproutLifecycle_ThroughRealEnvoy` and
  `internal/api` `TestSproutDownloadsStagedRecipe_ThroughRealEnvoy`.
  They cover:
  - enroll, then `wss://` to the bus;
  - upgrade refused with no token, an expired token or a bad signature
    (`401`);
  - `/v1/refresh`, then reconnecting with the new token;
  - `/files/` download, including a validly signed token for another
    sprout, which Envoy passes and farmer refuses.

  To run them this way, the rendered config replaced
  `deploy/envoy/envoy.yaml` in a scratch copy of the repo. They also pass
  against the reference file on Envoy 1.35.3. These suites stub OpenBao
  Transit.
- **Full stack with real OpenBao.** farmer served its JWKS from the real
  OpenBao Ed25519 Transit key (PR #5's fix), and Envoy fetched it.
- **The real `cmd/sprout` binary enrolled through the chart's Envoy**
  (`POST /v1/enroll`), with the NKey proof of possession and the Valkey
  replay cache. It then fetched `/files/` through `jwt_authn`. It still
  can't reach the bus; see [Known gaps](#known-gaps-outside-this-chart)
  (1) and (2).
- **The bus container ran exactly as templated:** read-only root, UID
  65532, seeds only from `_SEED_FILE`, and no seed written to its
  volume. Core joined it over TLS on 5406.
- **`envoy --mode validate` passes** for every `ci/*-values.yaml`
  variant.

## NetworkPolicy

Only these flows are allowed:

| Pods | Direction | Peer | Port |
|---|---|---|---|
| bus | in | core (`networkPolicy.core.*`) | `bus.ports.client` (5406) |
| bus | in | this release's Envoy | `bus.ports.websocket` (5407) |
| bus | in/out | other bus pods (only if `replicaCount > 1`) | `bus.cluster.port` (6222) |
| bus | out | DNS | 53/UDP+TCP |
| bus | out | OpenBao (only in `bus.tls.mode=openbao`) | `networkPolicy.openbao.port` |
| Envoy | in | `networkPolicy.envoyIngress.from` (default: anyone) | `envoy.listenerPort` (8443) |
| Envoy | out | bus pods | `bus.ports.websocket` |
| Envoy | out | core | `envoy.upstreams.farmerAPI.port` and `recipeService.port` (5405) |
| Envoy | out | DNS | 53/UDP+TCP |

- The bus never opens a connection into the core network.
- The Envoy admin port is bound to 127.0.0.1.
- If `jwks.remote.cluster=jwks` points outside the cluster, add a rule
  through `networkPolicy.envoyExtraEgress`.

Kubelet TCP probes originate from the node. Most CNIs allow them
regardless of policy. Check yours.

## Values

### Top level

| Key | Default | Description |
|---|---|---|
| `nameOverride` | `""` | Replaces the chart name in resource names. |
| `fullnameOverride` | `""` | Replaces `<release>-<chart>` as the name prefix. |
| `commonLabels` | `{}` | Labels added to every resource. |

### `natsSeeds`

| Key | Default | Description |
|---|---|---|
| `natsSeeds.secretName` | `imas-farmer-nats-seeds` | Existing Secret with the NKey seeds. Required. |
| `natsSeeds.mountPath` | `/var/run/secrets/imas/nats` | Where the seed files are mounted. |
| `natsSeeds.seeds.OPERATOR` | `operator.nk` | Secret key for `IMAS_NATS_OPERATOR_SEED_FILE`. Required. |
| `natsSeeds.seeds.OPERATOR_SIGNING` | `operator-signing.nk` | Secret key for `IMAS_NATS_OPERATOR_SIGNING_SEED_FILE`. Required. |
| `natsSeeds.seeds.SYS_ACCOUNT` | `sys-account.nk` | Secret key for `IMAS_NATS_SYS_ACCOUNT_SEED_FILE`. Required. |
| `natsSeeds.seeds.TENANT` | `tenant.nk` | Secret key for `IMAS_NATS_TENANT_SEED_FILE`. Required. |
| `natsSeeds.seeds.TENANT_SIGNING` | `tenant-signing.nk` | Secret key for `IMAS_NATS_TENANT_SIGNING_SEED_FILE`. Required. |
| `natsSeeds.extraSeeds` | `{}` | More `NAME: secret-key` pairs. `NAME` must match `^[A-Z0-9_]+$` and becomes `IMAS_NATS_<NAME>_SEED_FILE`. |

### `bus`

| Key | Default | Description |
|---|---|---|
| `bus.image.repository` | `ghcr.io/yogzblr/imas-farmerbus` | farmerbus image. Not published by this repo yet. |
| `bus.image.tag` | `""` | Image tag. Empty uses the chart `appVersion`. |
| `bus.image.digest` | `""` | `sha256:…` digest. Takes precedence over the tag. |
| `bus.image.pullPolicy` | `IfNotPresent` | Image pull policy. |
| `bus.imagePullSecrets` | `[]` | Pull secrets. |
| `bus.command` | `[]` | Container command. Empty uses the image ENTRYPOINT, which is expected to be `/farmerbus`. |
| `bus.args` | `[]` | Container args. |
| `bus.replicaCount` | `1` | Bus nodes. Values above 1 need `bus.cluster.routesSupported`. |
| `bus.podManagementPolicy` | `Parallel` | StatefulSet pod management. |
| `bus.updateStrategy` | `{type: RollingUpdate}` | StatefulSet update strategy. |
| `bus.logLevel` | `info` | `loglevel` in `/etc/imas/farmer`. |
| `bus.organization` | `imas` | `farmerorganization`, the legacy tenant ID. Must match core and `^[0-9A-Za-z_-]{1,191}$`. farmer's built-in default `"imas farmer"` is not a valid tenant ID. |
| `bus.ports.client` | `5406` | TCP NATS listener (`farmerbusport`), used by core. |
| `bus.ports.websocket` | `5407` | NATS websocket listener (`farmerwsport`), used by Envoy. |
| `bus.cluster.name` | `imas-bus` | `IMAS_BUS_CLUSTER_NAME` when clustered. |
| `bus.cluster.port` | `6222` | Route port when clustered. |
| `bus.cluster.routesSupported` | `false` | Allows `replicaCount > 1`. See [Clustering](#clustering). |
| `bus.extraConfig` | `{}` | Extra `/etc/imas/farmer` keys. Chart-managed keys win. |
| `bus.extraEnv` | `[]` | Extra env vars. Never put a raw `IMAS_NATS_*_SEED` here. |
| `bus.extraVolumes` | `[]` | Extra pod volumes. |
| `bus.extraVolumeMounts` | `[]` | Extra container mounts. |
| `bus.tls.mode` | `secret` | `secret` or `openbao`. |
| `bus.tls.secretName` | `imas-farmerbus-tls` | secret mode: the Secret with `tls.crt`, `tls.key` and `ca.crt`. |
| `bus.tls.certHosts` | `[]` | openbao mode: SANs to request. Empty uses the Service and per-pod names. |
| `bus.tls.openbao.addr` | `https://openbao.openbao.svc:8200` | `IMAS_CERTS_OPENBAO_ADDR`. |
| `bus.tls.openbao.pkiMount` | `pki` | `IMAS_CERTS_OPENBAO_PKI_MOUNT`. |
| `bus.tls.openbao.role` | `imas-farmerbus` | `IMAS_CERTS_OPENBAO_ROLE`. |
| `bus.tls.openbao.caConfigMap` | `openbao-ca` | ConfigMap with OpenBao's CA as `ca.crt` (`IMAS_CERTS_OPENBAO_CACERT`). Empty uses the system roots. |
| `bus.tls.openbao.authMethod` | `kubernetes` | `kubernetes` or `token`. |
| `bus.tls.openbao.k8sRole` | `imas-farmerbus` | `IMAS_CERTS_OPENBAO_K8S_ROLE`. |
| `bus.tls.openbao.k8sMount` | `kubernetes` | `IMAS_CERTS_OPENBAO_K8S_MOUNT`. |
| `bus.tls.openbao.k8sAudience` | `openbao` | Audience of the projected ServiceAccount token (10-minute expiry). |
| `bus.tls.openbao.tokenSecretName` | `""` | token auth: the Secret holding the token. |
| `bus.tls.openbao.tokenSecretKey` | `token` | token auth: the key in that Secret. |
| `bus.persistence.enabled` | `true` | Keep FarmerPKI (resolver store) on a PVC per node. Off uses `emptyDir`, so pushed Account JWTs are lost on restart. |
| `bus.persistence.size` | `1Gi` | PVC size. |
| `bus.persistence.storageClassName` | `""` | StorageClass. Empty uses the default. |
| `bus.persistence.accessModes` | `[ReadWriteOnce]` | PVC access modes. |
| `bus.persistence.annotations` | `{}` | Annotations on the volumeClaimTemplate. |
| `bus.resources` | 100m CPU and 128Mi requests, 512Mi limit | Container resources. |
| `bus.podSecurityContext` | non-root 65532, fsGroup 65532, RuntimeDefault seccomp | Pod securityContext. |
| `bus.securityContext` | read-only root, no privilege escalation, drop ALL | Container securityContext. |
| `bus.terminationGracePeriodSeconds` | `60` | Grace period. |
| `bus.startupProbe` | TCP on `client`, 5s × 24 | Startup probe. |
| `bus.readinessProbe` | TCP on `client`, every 10s | Readiness probe. |
| `bus.livenessProbe` | TCP on `client`, every 20s | Liveness probe. |
| `bus.podAnnotations` | `{}` | Pod annotations. |
| `bus.podLabels` | `{}` | Pod labels. |
| `bus.nodeSelector` | `{}` | Node selector. |
| `bus.tolerations` | `[]` | Tolerations. |
| `bus.affinity` | `{}` | Affinity. Empty gives soft anti-affinity across hosts. |
| `bus.topologySpreadConstraints` | `[]` | Topology spread. |
| `bus.priorityClassName` | `""` | PriorityClass. |
| `bus.service.type` | `ClusterIP` | Client Service type. Keep ClusterIP: sprouts go through Envoy. |
| `bus.service.annotations` | `{}` | Client Service annotations. |
| `bus.serviceAccount.create` | `true` | Create a ServiceAccount (token automount off). |
| `bus.serviceAccount.name` | `""` | Name. Empty uses `<fullname>-bus`. |
| `bus.serviceAccount.annotations` | `{}` | ServiceAccount annotations. |
| `bus.pdb.enabled` | `true` | PodDisruptionBudget, rendered only when `replicaCount > 1`. |
| `bus.pdb.maxUnavailable` | `1` | PDB maxUnavailable. |

### `envoy`

| Key | Default | Description |
|---|---|---|
| `envoy.enabled` | `true` | Deploy the gateway. |
| `envoy.image.repository` | `envoyproxy/envoy` | Envoy image. |
| `envoy.image.tag` | `v1.35.3` | Pinned. This is the version whose EdDSA `jwt_authn` was verified live (see above). |
| `envoy.image.digest` | `""` | Digest. Takes precedence over the tag. |
| `envoy.image.pullPolicy` | `IfNotPresent` | Pull policy. |
| `envoy.imagePullSecrets` | `[]` | Pull secrets. |
| `envoy.replicaCount` | `2` | Replicas. |
| `envoy.logLevel` | `info` | `--log-level`. |
| `envoy.extraArgs` | `[]` | Extra Envoy args. |
| `envoy.listenerPort` | `8443` | Downstream listener port. |
| `envoy.adminPort` | `9901` | Admin port, bound to 127.0.0.1. |
| `envoy.tls.secretName` | `imas-envoy-dmz-tls` | DMZ edge cert Secret (`tls.crt` and `tls.key`). |
| `envoy.jwtAuthn.providerName` | `sprout_jwt` | Provider and requirement name. |
| `envoy.jwtAuthn.issuer` | `imas-gateway` | Required `iss` (`internal/gatewayjwt` GatewayIssuer). |
| `envoy.jwtAuthn.audiences` | `[]` | Allowed `aud` values. Empty skips the check. Gateway JWTs carry no `aud` today. |
| `envoy.jwtAuthn.forward` | `true` | Forward the JWT upstream. |
| `envoy.jwtAuthn.clockSkewSeconds` | `60` | Allowed `exp`/`nbf` skew. |
| `envoy.jwtAuthn.claimToHeaders` | `[{headerName: x-imas-sprout-nkey, claimName: sub}]` | Claims copied to headers. Client copies are stripped first. |
| `envoy.jwtAuthn.jwks.source` | `remote` | `remote` or `local`. |
| `envoy.jwtAuthn.jwks.remote.uri` | `""` | JWKS URL. Empty uses `https://<farmerAPI.host>:<port>/v1/.well-known/jwks.json`. |
| `envoy.jwtAuthn.jwks.remote.cluster` | `farmer_api` | Cluster used for the fetch: `farmer_api` or `jwks` (uses `upstreams.jwks`). |
| `envoy.jwtAuthn.jwks.remote.timeout` | `5s` | Fetch timeout. |
| `envoy.jwtAuthn.jwks.remote.cacheDuration` | `300s` | JWKS cache lifetime, which is the rotation pickup delay. |
| `envoy.jwtAuthn.jwks.remote.asyncFetch.enabled` | `true` | Fetch at startup and in the background. |
| `envoy.jwtAuthn.jwks.remote.asyncFetch.fastListener` | `false` | Open the listener before the first fetch completes. |
| `envoy.jwtAuthn.jwks.local.inline` | `""` | Inline JWKS JSON, stored in the chart's ConfigMap. |
| `envoy.jwtAuthn.jwks.local.configMapName` | `""` | Or an existing ConfigMap with the JWKS. |
| `envoy.jwtAuthn.jwks.local.configMapKey` | `jwks.json` | Key in that ConfigMap. |
| `envoy.upstreams.farmerAPI.host` | `farmer.imas-core.svc.cluster.local` | farmer's HTTPS API (`/v1/enroll`, `/v1/refresh`, JWKS). |
| `envoy.upstreams.farmerAPI.port` | `5405` | Its port. |
| `envoy.upstreams.farmerAPI.sni` | `""` | SNI and verified SAN. Empty uses the host. |
| `envoy.upstreams.recipeService.host` | `""` | `/files/` upstream. Empty uses `farmerAPI.host`. |
| `envoy.upstreams.recipeService.port` | `5405` | Its port. |
| `envoy.upstreams.recipeService.sni` | `""` | SNI and verified SAN. Empty uses the host. |
| `envoy.upstreams.natsWebsocket.host` | `""` | Bus websocket upstream. Empty uses this release's bus Service FQDN. |
| `envoy.upstreams.natsWebsocket.port` | `""` | Empty uses `bus.ports.websocket`. |
| `envoy.upstreams.natsWebsocket.sni` | `""` | SNI and verified SAN. Empty uses the host. |
| `envoy.upstreams.jwks.host` | `""` | Separate JWKS host, used when `remote.cluster=jwks`. |
| `envoy.upstreams.jwks.port` | `443` | Its port. |
| `envoy.upstreams.jwks.sni` | `""` | SNI and verified SAN. Empty uses the host. |
| `envoy.upstreamTLS.caSecretName` | `""` | Secret with the upstream CA. When set, every upstream cert and SAN is verified. |
| `envoy.upstreamTLS.caConfigMapName` | `""` | Same, from a ConfigMap. Set only one of the two. |
| `envoy.upstreamTLS.caKey` | `ca.crt` | Key holding the CA. |
| `envoy.routes.enrollTimeout` | `30s` | `/v1/enroll` timeout. |
| `envoy.routes.refreshTimeout` | `30s` | `/v1/refresh` timeout. |
| `envoy.routes.filesTimeout` | `60s` | `/files/` timeout. |
| `envoy.routes.websocketIdleTimeout` | `0s` | Websocket route idle timeout. `0s` means none. |
| `envoy.refreshRateLimit.fleetSize` | `1000000` | Enrolled sprouts behind these Envoys. Size for where the fleet is going. |
| `envoy.refreshRateLimit.gatewayJwtTtlSeconds` | `86400` | Must match farmer's `gatewayjwtttl`, in seconds. |
| `envoy.refreshRateLimit.envoyReplicas` | `null` | Envoys sharing `/v1/refresh`. `null` uses `envoy.replicaCount`. |
| `envoy.refreshRateLimit.headroom` | `2` | Whole-number multiplier over the steady-state rate. |
| `envoy.refreshRateLimit.fillIntervalSeconds` | `1` | `fill_interval`, in whole seconds. |
| `envoy.refreshRateLimit.burstSeconds` | `300` | `max_tokens` as seconds' worth of the per-Envoy rate. Must be at least `fillIntervalSeconds`. |
| `envoy.refreshRateLimit.tokensPerFill` | `null` | Explicit `tokens_per_fill`. `null` computes it. |
| `envoy.refreshRateLimit.maxTokens` | `null` | Explicit `max_tokens`, at least `tokensPerFill`. `null` computes it. |
| `envoy.configOverride` | `""` | Full `envoy.yaml` replacement. Bypasses every setting above. |
| `envoy.resources` | 100m CPU and 128Mi requests, 512Mi limit | Container resources. |
| `envoy.podSecurityContext` | non-root 101, RuntimeDefault seccomp | Pod securityContext. |
| `envoy.securityContext` | read-only root, no privilege escalation, drop ALL | Container securityContext. |
| `envoy.terminationGracePeriodSeconds` | `30` | Grace period. |
| `envoy.readinessProbe` | TCP on `https`, every 10s | Readiness probe. |
| `envoy.livenessProbe` | TCP on `https`, every 20s | Liveness probe. |
| `envoy.podAnnotations` | `{}` | Pod annotations. |
| `envoy.podLabels` | `{}` | Pod labels. |
| `envoy.nodeSelector` | `{}` | Node selector. |
| `envoy.tolerations` | `[]` | Tolerations. |
| `envoy.affinity` | `{}` | Affinity. Empty gives soft anti-affinity across hosts. |
| `envoy.topologySpreadConstraints` | `[]` | Topology spread. |
| `envoy.priorityClassName` | `""` | PriorityClass. |
| `envoy.extraEnv` | `[]` | Extra env vars. |
| `envoy.extraVolumes` | `[]` | Extra volumes. |
| `envoy.extraVolumeMounts` | `[]` | Extra mounts. |
| `envoy.service.type` | `ClusterIP` | Service type. A production DMZ edge is usually `LoadBalancer`. |
| `envoy.service.port` | `443` | Service port. |
| `envoy.service.annotations` | `{}` | Service annotations. |
| `envoy.service.externalTrafficPolicy` | `""` | Applies to LoadBalancer/NodePort only. `Local` keeps client IPs for the rate limit and logs. |
| `envoy.service.loadBalancerSourceRanges` | `[]` | Applies to LoadBalancer only. |
| `envoy.serviceAccount.create` | `true` | Create a ServiceAccount (token automount off). |
| `envoy.serviceAccount.name` | `""` | Name. Empty uses `<fullname>-envoy`. |
| `envoy.serviceAccount.annotations` | `{}` | Annotations. |
| `envoy.pdb.enabled` | `true` | PDB, rendered only when `replicaCount > 1`. |
| `envoy.pdb.maxUnavailable` | `1` | PDB maxUnavailable. |

### `networkPolicy`

| Key | Default | Description |
|---|---|---|
| `networkPolicy.enabled` | `true` | Render both NetworkPolicies. |
| `networkPolicy.core.namespaceSelector` | `kubernetes.io/metadata.name: imas-core` | Core's namespace. |
| `networkPolicy.core.podSelector` | `app.kubernetes.io/name: farmer` | Core's pods. |
| `networkPolicy.envoyIngress.from` | `[]` | Peers allowed to reach Envoy's listener. Empty allows anyone, on that port only. |
| `networkPolicy.dns.namespaceSelector` | `kubernetes.io/metadata.name: kube-system` | DNS namespace. |
| `networkPolicy.dns.podSelector` | `k8s-app: kube-dns` | DNS pods. |
| `networkPolicy.openbao.namespaceSelector` | `kubernetes.io/metadata.name: openbao` | OpenBao namespace. Used only in `bus.tls.mode=openbao`. |
| `networkPolicy.openbao.podSelector` | `{}` | OpenBao pods. |
| `networkPolicy.openbao.port` | `8200` | OpenBao port. |
| `networkPolicy.busExtraEgress` | `[]` | Extra egress rules for bus pods. |
| `networkPolicy.envoyExtraEgress` | `[]` | Extra egress rules for Envoy pods, for example an external JWKS host. |

## Testing the chart

```sh
helm lint deploy/helm/nats
go test ./deploy/helm/nats/   # renders with the helm CLI; skips if helm isn't on PATH
```

`ci/*-values.yaml` follow the chart-testing convention.

## Known gaps outside this chart

Still open after PRs #5–#13. Each is outside this chart's file scope.

1. **The real sprout can't reach the bus through Envoy.** `ConnectSprout`
   (`cmd/sprout/main.go`) dials `config.FarmerBusURL`, which is always
   `farmerinterface:farmerbusport` with no scheme, so plain `nats://`
   TCP. The `nats_urls` (`wss://…`) from the enrollment response is
   parsed but never used.
   - Live, Envoy counted 0 websocket upgrades. The sprout's attempts
     never completed a TLS handshake, because each side waits for the
     other to speak first.
   - The e2e suites don't catch this: they call `nats.Connect(env.BusURL)`
     with a `wss://` URL themselves.
2. **The root CA bootstrap fails through Envoy.** `FetchRootCA`
   (`internal/pki/pki.go`) fetches `https://<farmerinterface>:<farmerapiport>/auth/cert/`.
   - Envoy doesn't route `/auth/cert/`, so it lands on the JWT-gated
     default route and gets `401 Jwt is missing`.
   - `FetchRootCA` doesn't check the status. It writes that body into
     `tls-rootca.pem`, and because the file now exists, it never
     re-fetches. The sprout loops on "cannot load the RootCA" until the
     file is deleted.
   - Pre-provisioning the CA (e.g. from Ansible) works around it. Adding
     an un-gated `/auth/cert/` route would be a trust-bootstrap design
     decision, so this chart doesn't.
3. **`cmd/farmerbus` has no cluster routes, and there's no farmerbus
   image.** See [Clustering](#clustering).
4. **farmer's default tenant ID is invalid.** `config.go` still defaults
   `farmerorganization` to `"imas farmer"`, which fails
   `IsValidTenantID`, so core exits at boot unless it's overridden.
5. **core can't be configured with the bus's address.** It still uses
   one `farmerinterface` as its API bind address, its bus URL host and
   its TLS ServerName for the bus.
6. **The Keycloak harness still doesn't start on current Keycloak.**
   `deploy/envoy/testing/docker-compose.keycloak.yml` still pulls from
   quay.io and mounts the realm under a file name Keycloak 26 refuses
   (it must be `imas-gateway-jwt-validation-realm.json`).

Fixed by PRs #5–#13 and verified above: Ed25519 Transit key parsing
(#5), `requirement_map` in `deploy/envoy/envoy.yaml` (#6), and sprouts
sending the gateway JWT on `wss://` and `/files/` (#8, #12).

## Security review notes

- **The DMZ bus holds the Operator root seed.** `ConfigureNats` derives
  `operator.jwt` by signing with the Operator seed. It also needs
  `OPERATOR_SIGNING`, which can sign any Account. So a compromise of the
  DMZ bus pod exposes the whole trust chain. The design doc wants the
  Operator key cold, and it wants this process to "expose as little as
  possible". Fixing that is a code change: have farmerbus load a
  pre-minted `operator.jwt` and the SYS Account's public key instead of
  seeds. Until then, the seed Secret in the DMZ namespace is the most
  sensitive object in the deployment. Restrict who can read it.
- Upstream TLS verification is **off by default**, matching the
  reference config. Set `envoy.upstreamTLS.*` for anything real.
- The `/v1/enroll` and `/v1/refresh` rate limits are per Envoy process
  and per replica, not global.
- The gateway JWT has no `aud`. Envoy checks only `iss`, the signature
  and `exp`. Adding an audience needs a change to `internal/gatewayjwt`
  plus `envoy.jwtAuthn.audiences`.
