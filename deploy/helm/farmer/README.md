# imas core chart (`deploy/helm/farmer`)

**FLAG FOR SECURITY REVIEW.** This chart carries the OpenBao *write*
policy for the SaaS API credential hand-off, which `deploy/farmer/README.md`
flags as needing human review. Carrying it into a chart doesn't reduce that
need. The same goes for the fleet signing policies from
`deploy/fleetreleaser/policies/`. Read
[Security review notes](#security-review-notes) first. The defaults are a
non-production eval install.

It deploys imas's non-DMZ core:

- **farmer** (`cmd/farmer`, `ConnectFarmer()`): the API, the job, facts and
  cook subscribers, and tenant provisioning. It runs as one replica on a
  PVC (see [Why one farmer replica](#why-one-farmer-replica)).
- **saasapi** (`cmd/saasapi`): the customer-facing SaaS API.
- **The SaaS API credential hand-off**: the `farmer publish-saasapi-credential`
  Job, its ServiceAccount and its NetworkPolicy, from
  `deploy/farmer/saasapi-credential-publish-job.yaml`.
- **Optional subcharts**, each behind its own toggle. With all three on,
  the chart is self-contained for an eval install. With them off, it points
  at externally managed instances.

  | Toggle | Subchart | What it's for |
  |---|---|---|
  | `openbao.enabled` | `openbao/openbao-helm` 0.29.6 | Dev-mode OpenBao, plus a bootstrap Job that configures it |
  | `pxc.enabled` | `percona/pxc-db` 1.20.0, plus `percona/pxc-operator` 1.20.1 | One PXC cluster holding both the `farmer` and `saas` schemas |
  | `valkey.enabled` | `valkey-io/valkey-helm` 0.12.0 | Heartbeats, the replay cache and the rate limit |

The database is **PXC, not Postgres**. farmer and saasapi share one PXC
cluster with one schema each (`docs/design/cloudxp-machine-manager-api-design.md`
§5.1), so the toggle is `pxc.enabled`. A values file carrying
`postgresql.*` fails the render and says so.

It does **not** deploy the DMZ bus or Envoy. Those are `deploy/helm/nats`.

```
          DMZ (deploy/helm/nats)                  core (this chart)
 sprouts ─▶ Envoy ──https:5405──────────────────▶ farmer ─┬─▶ PXC (farmer.*, reads saas.*)
              │                                     │     ├─▶ Valkey
              └─wss─▶ farmerbus ◀──tls:5406─────────┘     ├─▶ OpenBao (4 roles)
                          ▲    (farmerbusurl)             └─▶ object storage
                          └──────tls:5406──────── saasapi ─┬─▶ PXC (saas.*, reads farmer.*)
                                                           └─▶ Valkey (same one)
```

## Before you install

1. **Fetch the subcharts:** run `helm dependency build deploy/helm/farmer`.
   `Chart.lock` pins the exact versions; `charts/` is gitignored. Use
   `helm dependency update` only to move a pin, and commit the new lock.
2. **The seed Secret** (`natsSeeds.secretName`, default
   `imas-farmer-nats-seeds`) must exist in the release namespace. The chart
   never generates seeds. See [Seeds](#seeds).
3. **The nats chart**, installed or planned, so you know
   `bus.serviceName` and `bus.namespace`, and Envoy's external `wss://`
   address for `bus.sproutBusURLs`.
4. **saasapi's inputs:**
   - the Keycloak realm (`saasapi.jwt.*`);
   - the BFF shared-secret Secret (`saasapi.internalAuthSecret.secretName`,
     key `current`, and optionally `previous`).
5. **Images.** The repo doesn't publish a farmer or saasapi image to a
   registry yet. Build them with `CGO_ENABLED=0`, following
   `docker/farmer.dockerfile` (`FROM scratch`), and set `farmer.image.*`
   and `saasapi.image.*`.

### Eval install (everything bundled)

```sh
kubectl create namespace imas-core
# Seeds for a NEW install only (never on an existing one, see "Seeds").
# `nk` is github.com/nats-io/nkeys/nk. Create the same Secret in the nats
# chart's namespace too.
kubectl -n imas-core create secret generic imas-farmer-nats-seeds \
  --from-literal=operator.nk="$(nk -gen operator)" \
  --from-literal=operator-signing.nk="$(nk -gen operator)" \
  --from-literal=sys-account.nk="$(nk -gen account)" \
  --from-literal=tenant.nk="$(nk -gen account)" \
  --from-literal=tenant-signing.nk="$(nk -gen account)" \
  --from-literal=saasapi-user.nk="$(nk -gen user)"
kubectl -n imas-core create secret generic imas-saasapi-internal-auth \
  --from-literal=current="$(openssl rand -hex 32)"

helm dependency build deploy/helm/farmer
helm install imas-core deploy/helm/farmer -n imas-core -f deploy/helm/farmer/ci/default-values.yaml \
  --set farmer.image.repository=<registry>/imas-farmer --set saasapi.image.repository=<registry>/imas-saasapi
```

Then, because the eval install has no ESO, deliver saasapi's credential by
hand. The publish Job has already written the JWT to OpenBao:

```sh
kubectl -n imas-core exec imas-core-openbao-0 -- env BAO_TOKEN=root bao kv get -field=jwt secret/platform/imas/saasapi-nats-user > jwt
kubectl -n imas-core create secret generic imas-saasapi-nats \
  --from-file=nats-user.nk=<(kubectl -n imas-core get secret imas-farmer-nats-seeds -o jsonpath='{.data.saasapi-user\.nk}' | base64 -d) \
  --from-file=SAASAPI_NATS_USER_JWT=jwt
```

What to expect on first install:

- PXC takes a few minutes to come up. farmer and saasapi crash-loop until
  the `db-bootstrap` Job has created their users.
- The OpenBao bootstrap and publish Jobs are hooks. Helm waits for them,
  so `helm install` needs the seed Secret in place, or it times out.
- **Dev-mode OpenBao is in memory.** If its pod restarts, the keys, the
  eval CA, the policies and the roles are gone. `helm upgrade` re-runs the
  bootstrap, but it mints *new* gateway and fleet keys and a new CA.

### Production (everything external)

`ci/external-values.yaml` is the worked example. It sets:

- `openbao.enabled=false` and `openbaoClient.addr`/`caConfigMap`;
- `pxc.enabled=false`, `database.host` and `database.existingSecret` (both
  full DSNs);
- `valkey.enabled=false` and `valkey.addrs`;
- `tls.mode=secret` (e.g. cert-manager);
- `externalSecrets.enabled=true`.

The OpenBao policies and roles are then the ops repo's job. See
[OpenBao](#openbao).

## Reaching the bus

Since yogzblr/imas#18, farmer keeps its bind address and its bus address
apart (`internal/config`):

| farmer setting | The chart sets it to | What it does |
|---|---|---|
| `farmerinterface` | `0.0.0.0` | The API's bind address, and nothing else |
| `farmerbusurl` | `tls://<bus.serviceName>.<bus.namespace>.svc.<clusterDomain>:<bus.port>` | Where farmer dials the bus: its tenant connections, its SYS connection and its resolver pushes |
| `farmerbustlsservername` | `bus.tlsServerName`, when set | The name farmer verifies the bus certificate against. Unset (the default), it is the host of `farmerbusurl`, the bus Service FQDN (`config.BusTLSServerName()`). |

saasapi dials the same URL (`SAASAPI_NATS_URL`) and verifies the same
FQDN. The nats chart's default bus SANs cover it. In its
`bus.tls.mode=secret`, or if you set `bus.tlsServerName`, make sure the bus
certificate carries the name farmer verifies.

There is no sidecar and no `hostAliases`. Before #18, this chart pinned
the bus name to `0.0.0.0` and ran a loopback TCP relay to work around
`farmerinterface` doing all three jobs; that workaround is gone.

This was checked against the real `farmerbus` with farmer's own config and
bus code (see [Verification status](#verification-status)).
`TestContractWithNatsChart` keeps the URL, the verified name, the SANs,
the seeds and the NetworkPolicy selectors in step with `deploy/helm/nats`.

## Seeds

farmer mounts the six `natsSeeds.seeds` from the Secret, each as an
`IMAS_NATS_<NAME>_SEED_FILE`. It never uses the raw `_SEED` form, and it
projects only the listed keys. This is
`deploy/farmer/farmer-deployment-nats-seeds.patch.yaml`, driven from
values. All six are required:

- `SYS_ACCOUNT` and `SAASAPI_USER`: the patch's two. The publish Job mounts
  only these.
- `OPERATOR`, `OPERATOR_SIGNING`, `TENANT` and `TENANT_SIGNING`: the nats
  chart's bus mints its trust chain from the same seeds, so farmer's copies
  must be byte-identical (`deploy/helm/nats/README.md`, "Seeds").

**Import the existing seeds. Don't generate new ones.** On an install that
is already running, put farmer's current `{FarmerPKI}/nats-auth/*.nk` into
OpenBao. A new SYS seed means a new SYS Account public key. `operator.jwt`
names the system account, so it gets re-minted, and every bus node still
configured with the old one stops trusting it (`deploy/farmer/README.md`).

`externalSecrets.enabled` renders `deploy/farmer/externalsecrets.yaml`,
extended to all six seeds. Each seed's property is its name in lowercase:
`sys_account`, `saasapi_user`, `operator`, `operator_signing`, `tenant`,
`tenant_signing`. It also renders `imas-saasapi-nats`: saasapi's seed from
the seed path, and the published JWT from `credentialPublisher.kvPath`.

## The SaaS API credential hand-off

The Job is `deploy/farmer/saasapi-credential-publish-job.yaml`, driven from
values. `chart_test.go`'s `TestPublishJobMatchesReference` renders it with
the reference's own placeholders filled in and compares it field for field
against the reference file.

The chart keeps every property the reference README requires:

- It runs as a `post-install,post-upgrade` hook, weight 10, after the
  OpenBao bootstrap. The Argo CD `PostSync` annotations are included.
- It uses farmer's image and tag, the `publish-saasapi-credential` args,
  and an **emptyDir** at `/etc/imas`.
- It mounts only `sys-account.nk` and `saasapi-user.nk`.
- Its ServiceAccount `imas-saasapi-cred-publisher` has no RBAC and no token
  automount. OpenBao login uses a 10-minute projected token with audience
  `openbao`.
- Its NetworkPolicy allows egress to OpenBao and DNS only. It is rendered
  whatever `networkPolicy.enabled` says, because it is part of the reviewed
  boundary.
- farmer's Deployment gets no `IMAS_SAASAPI_CRED_OPENBAO_*` variable. The
  render fails if the publisher is given:
  - farmer's or saasapi's ServiceAccount;
  - one of farmer's OpenBao roles;
  - a KV path that equals, or is a prefix of, the seed path (or the other
    way round).

The rotation runbook in `deploy/farmer/README.md` applies unchanged. Step 4
("a no-op `helm upgrade` re-runs the hook") is this chart. The chart
defaults `reloader.stakater.com/auto` on both Deployments, which steps 3
and 5 rely on.

## OpenBao

Each OpenBao client runs under its own role and gets exactly one policy.

| Client | Env prefix | Kubernetes auth role (value) | Policy |
|---|---|---|---|
| farmer, API certificate (`tls.mode=openbao`) | `IMAS_CERTS_OPENBAO_*` | `imas-farmer-certs` (`tls.openbao.k8sRole`) | `imas-farmer-certs`: `pki/issue/imas-farmer` |
| farmer, gateway JWT signer | `IMAS_GATEWAY_OPENBAO_*` | `imas-farmer-gateway` | `imas-farmer-gateway`: sign and read on `transit/*/imas-gateway-jwt` only |
| farmer, fleet key (read-only) | `IMAS_FLEETSIGN_OPENBAO_*` | `imas-farmer-fleet-verify` | `imas-fleet-verify` (reviewed copy) |
| farmer, tenant box keypair | `IMAS_TENANTBOX_OPENBAO_*` | `imas-farmer-tenantbox` | `imas-farmer-tenantbox`: KV v2 on `secret/data/imas/tenant-x25519` |
| saasapi, fleet key (only with `fleetUpdateDispatch`) | `IMAS_FLEETSIGN_OPENBAO_*` | `imas-saasapi-fleet-verify` | `imas-fleet-verify` |
| the publish Job | `IMAS_SAASAPI_CRED_OPENBAO_*` | `imas-saasapi-cred-publisher` | `imas-saasapi-cred-publisher` (reviewed copy) |

- **Shared connection settings.** `openbaoClient.addr`, `caConfigMap` and
  `authMethod` are shared by all clients. In `authMethod=token`, each
  client reads its own key from `openbaoClient.tokenSecretName`. The
  publisher can use its own Secret (`credentialPublisher.tokenSecretName`),
  and should.
- **Bootstrap (bundled OpenBao only).** `openbaoBootstrap` is a hook Job
  that does all of the following, idempotently:
  - enables Transit, KV v2, PKI (when `tls.mode=openbao`) and Kubernetes
    auth;
  - creates `imas-gateway-jwt` and `imas-fleet-signing`, the latter with
    `exportable=false allow_plaintext_backup=false`;
  - writes every file in `files/openbao-policies` plus the farmer policies;
  - creates the roles above.

  Each role gets `token_no_default_policy=true`, and the publisher's TTL is
  5m. The `imas-fleet-signer` policy is written, but no role binds it,
  because `cmd/fleetreleaser` isn't deployed here. The bootstrap never
  writes NATS seeds.
- **Sharing a CA with the nats chart.** With
  `openbaoBootstrap.farmerbus.enabled`, it also creates the nats chart's
  `imas-farmerbus` PKI role and a Kubernetes auth role bound to the bus's
  ServiceAccount, so both charts share one eval CA.
- **Reviewed policies travel verbatim.** `imas-fleet-signer.hcl` and
  `imas-fleet-verify.hcl` are byte copies of
  `deploy/fleetreleaser/policies/`. `imas-saasapi-cred-publisher.hcl`'s
  statements are the README's `hcl` block. `TestPoliciesMatchReference`
  fails on drift.
- **Values that would leave a policy behind are refused.** The bootstrap
  fails the render if you move the publisher's KV path or rename the fleet
  key away from what those policies name. Change the policy, and its
  review, together with the values.
- **External OpenBao.** Create the same roles and policies in the ops repo.
  Then run the checks from `deploy/farmer/README.md` and
  `deploy/fleetreleaser/README.md` (`bao token capabilities ...`). They
  must print `deny` where those READMEs say so.

## PXC

- **Both services, one cluster.** farmer's `IMAS_PXC_DSN` and saasapi's
  `SAASAPI_DSN` point at the same host, each with its own user and schema.
  - `pxc.enabled`: the host is `<cluster>-haproxy`. Passwords are generated
    once (kept across upgrades with `lookup`) into `<release>-farmer-db`.
  - External: `database.existingSecret` holds both full DSNs.
- **`db-bootstrap`** (only with `pxc.enabled` and the generated Secret)
  creates both schemas and users, then applies §5.1:

  ```sql
  GRANT ALL    ON farmer.* TO farmer_svc;   GRANT SELECT ON saas.*   TO farmer_svc;
  GRANT ALL    ON saas.*   TO saas_svc;     GRANT SELECT ON farmer.* TO saas_svc;
  GRANT UPDATE (used_count, last_used_at) ON saas.enrollment_keys TO farmer_svc;
  ```

  - **The last grant waits for saasapi's first migration.** A column grant
    needs the table, and saasapi's AutoMigrate creates it.
  - **It is a plain Job, not a hook.** Waiting on saasapi, which itself
    waits on its NATS credential, must not block `helm install`.
  - **It is named by a hash of its pod template.** An unchanged spec is a
    no-op on upgrade and on Argo CD sync; a changed one is a new Job
    rather than an immutable-field error.
  - To re-run it as is, delete the Job and `helm upgrade`.
  - The root password comes from the operator's `<cluster>-secrets`, via
    an option file, never argv.
- **Declarative `users` isn't used.** The operator's `users` field applies
  one grant list to every listed schema, which can't express §5.1's split
  or the column grant.

## Valkey

farmer (`IMAS_VALKEY_ADDRS`) and saasapi (`SAASAPI_VALKEY_ADDRS`) get the
same address list. That's required: saasapi reads the heartbeat keys farmer
writes, and enforces the enrollment-key rate limit across pods
(`deploy/saasapi/README.md`).

- **Bundled:** `<release>-valkey:6379`, standalone.
- **External:** `valkey.addrs`, the same key as
  `deploy/saasapi/values.rate-limit.yaml`, so that block merges as is.

Neither client does auth or TLS yet, so the bundled Valkey has neither.
Restrict network access to it.

## Why one farmer replica

FarmerPKI is on one ReadWriteOnce PVC (kept on uninstall). It holds:

- `nats-auth/`: JWTs and the resolver state farmer pushes;
- the SaaS API credential, and the state `EnsureSaaSAPICredential` uses to
  detect and revoke a rotated key;
- farmer's own NKey;
- the audit logs.

A second replica would mint and push from a divergent copy. The chart
therefore renders `replicas: 1` with `strategy: Recreate`, and refuses
`farmer.replicaCount` other than 1. Horizontal core scaling needs that
state moved off local disk first.

## NetworkPolicy

| Pods | Direction | Peer | Port |
|---|---|---|---|
| farmer | in | the nats chart's Envoy (`networkPolicy.dmz.*`) | `farmer.apiPort` (5405) |
| farmer | out | the nats chart's bus pods | `bus.port` (5406), at `farmerbusurl` |
| farmer, saasapi | out | PXC / Valkey | 3306 / 6379 |
| farmer | out | OpenBao | 8200 |
| saasapi | out | OpenBao, only for fleet dispatch or the bus CA fetch | 8200 |
| saasapi | in | `networkPolicy.saasapiIngress.from` (default: anyone) | `saasapi.port` (8081) |
| saasapi | out | the bus pods | `bus.port` |
| saasapi | out | `saasapiExtraEgress`, default HTTPS anywhere (the Keycloak JWKS). **Narrow it.** | 443 |
| publish Job | out | OpenBao, DNS; nothing else, no ingress | 8200, 53 |
| db-bootstrap / openbao-bootstrap | out | PXC / OpenBao, DNS | 3306 / 8200, 53 |
| all | out | DNS | 53 |

- **Peers.** A bundled dependency's peer is this namespace's pods. An
  external one uses `networkPolicy.external.<dep>`. An empty list means any
  destination, on that port only. OpenBao defaults to the reference's
  `openbao` namespace.
- **Object storage** needs `networkPolicy.farmerExtraEgress`.
- **The nats chart must admit this namespace.** Set its
  `networkPolicy.core.namespaceSelector` to this namespace (NOTES prints
  it). Its default core pod selector, `app.kubernetes.io/name: farmer`,
  matches both farmer and saasapi.

## Values

Only this chart's own keys are listed. Anything under `openbao`, `pxc`
(pxc-db), `pxc-operator` and `valkey` goes to that subchart unchanged.

| Key | Default | Description |
|---|---|---|
| `organization` | `imas` | `farmerorganization`. Must equal the nats chart's `bus.organization`. |
| `clusterDomain` | `cluster.local` | For the FQDNs the chart builds. |
| `bus.serviceName` / `bus.namespace` | `""` / `imas-dmz` | The nats chart's bus client Service. Required. |
| `bus.port` | `5406` | Bus client port, in `farmerbusurl` and `SAASAPI_NATS_URL`. |
| `bus.sproutBusURLs` | `[]` | `IMAS_SPROUT_BUS_URLS`, Envoy's external `wss://` addresses. Required. |
| `bus.ca.secretName` / `configMapName` / `key` | `""` / `""` / `ca.crt` | saasapi's bus CA. Empty: `tls.secretName`'s `ca.crt`, or fetched from OpenBao PKI in openbao mode. |
| `bus.tlsServerName` | `""` | `farmerbustlsservername`. Empty: the bus Service FQDN. See [Reaching the bus](#reaching-the-bus). |
| `natsSeeds.secretName` | `imas-farmer-nats-seeds` | The seed Secret. Required. |
| `natsSeeds.seeds` | the six above | `NAME: key` pairs. All six are required. |
| `natsSeeds.extraSeeds` | `{}` | More seeds, e.g. per-tenant Account seeds. |
| `tls.mode` | `openbao` | `secret` (`tls.secretName`) or `openbao` (`tls.openbao.*`). |
| `tls.certHosts` | `[]` | openbao mode SANs. Empty: the farmer Service's names. |
| `openbaoClient.addr` | `""` | Empty with `openbao.enabled`: this release's OpenBao. Required otherwise. |
| `openbaoClient.caConfigMap` / `caKey` | `""` / `ca.crt` | OpenBao's CA (`*_OPENBAO_CACERT`). |
| `openbaoClient.authMethod` | `kubernetes` | Or `token`, which uses `tokenSecretName` with per-client keys. |
| `openbaoClient.k8sMount` / `k8sAudience` | `kubernetes` / `openbao` | Kubernetes auth mount, and the projected token's audience. |
| `openbaoTools.image` | `quay.io/openbao/openbao:2.6.3` | The bao CLI, for the bootstrap Job and the CA fetch. |
| `database.host` / `port` / `params` | `""` / `3306` / `parseTime=true&charset=utf8mb4&loc=UTC` | PXC. Empty host with `pxc.enabled`: its HAProxy Service. |
| `database.farmer.*` / `database.saasapi.*` | `farmer`/`farmer_svc`, `saas`/`saas_svc` | Schemas and users. |
| `database.existingSecret` | `""` | Both DSNs (`existingSecretKeys`). Required without `pxc.enabled`. |
| `database.bootstrap.*` | on | The `db-bootstrap` Job. |
| `objectStore.*` | empty | `IMAS_S3_*`. `jobBucket` must differ from `bucket`. |
| `farmer.image.*` | `ghcr.io/yogzblr/imas-farmer` | Also the publish Job's image. |
| `farmer.replicaCount` | `1` | Must be 1. |
| `farmer.logLevel` / `apiPort` / `gatewayJWTTTL` | `info` / `5405` / `24h` | `loglevel`, `farmerapiport`, `gatewayjwtttl`. |
| `farmer.adminPubKeys` | `[]` | `pubkeys.admin`. |
| `farmer.jobs.reconcileWindow` | `"2h"` | `IMAS_JOB_RECONCILE_WINDOW` (`deploy/farmer/values.job-reconcile.yaml`). |
| `farmer.openbao.{gateway,fleetSign,tenantBox}.*` | see values.yaml | Mount, key or path, role, and token key per client. |
| `farmer.extraConfig` | `{}` | Extra `/etc/imas/farmer` keys. Chart-managed keys win. |
| `farmer.persistence.*` | 1Gi RWO, kept | FarmerPKI and audit logs. |
| `saasapi.enabled` / `replicaCount` / `port` | `true` / `2` / `8081` | |
| `saasapi.jwt.*` | `""` | Keycloak JWKS URL, issuer and audience. Required. |
| `saasapi.internalAuthSecret.*` | `imas-saasapi-internal-auth` | `INTERNAL_AUTH_SECRET_CURRENT`/`_PREVIOUS`. |
| `saasapi.natsCredentials.*` | `imas-saasapi-nats` | The seed (as a file) and the JWT. |
| `saasapi.fleetUpdateDispatch.enabled` | `false` | Also turns on saasapi's verify-only OpenBao client. |
| `saasapi.enrollmentKeys.rateLimit.*` | `1` / `5` | `deploy/saasapi/values.rate-limit.yaml`. `null` emits no env var. |
| `credentialPublisher.*` | enabled, `platform/imas/saasapi-nats-user` | The publish Job. |
| `externalSecrets.*` | off | ESO wiring. |
| `openbaoBootstrap.*` | on | The bundled OpenBao's setup Job. |
| `networkPolicy.*` | on | See above. |

## Testing the chart

```sh
helm lint deploy/helm/farmer -f deploy/helm/farmer/ci/default-values.yaml
go test ./deploy/helm/farmer/   # renders with the helm CLI; skips if helm isn't on PATH
```

- **Without subcharts.** The tests render the chart with its dependencies
  stripped. `TestSubchartsRender` also renders the real subcharts once
  `helm dependency build` has populated `charts/`.
- **Parity with the reference files.** Tests pin the chart to everything it
  was built from:
  - `farmer-deployment-nats-seeds.patch.yaml`,
    `saasapi-credential-publish-job.yaml` and `externalsecrets.yaml`;
  - `deploy/saasapi`'s rate-limit fragment, and `deploy/farmer`'s
    reconcile-window fragment;
  - `deploy/fleetreleaser/policies/*.hcl`, and the publisher policy in
    `deploy/farmer/README.md`.
- **The pairing with `deploy/helm/nats`.** `TestContractWithNatsChart`
  renders both charts side by side and checks every name, port, SAN,
  seed, NetworkPolicy selector and OpenBao role each relies on from the
  other.
- **`Chart.lock`.** `TestChartLockMatchesChartYaml` fails if the lock and
  `Chart.yaml` disagree.
- **Chart-testing values.** `ci/*-values.yaml` follow the chart-testing
  convention: eval defaults, external production, and token auth.

### Verification status

Done on 2026-09-27, in a sandbox with no Kubernetes cluster and no image
registry.

- **Static checks.** For each `ci/*-values.yaml`, with the real subcharts
  (fetched from their upstream sources at the pinned versions):
  - `helm lint` passes;
  - `kubeconform -strict` passes against Kubernetes 1.30 (the PXC and
    ExternalSecret CRDs are skipped);
  - `go test ./deploy/helm/farmer/`, including `TestSubchartsRender`,
    passes.
- **The OpenBao bootstrap, against a real OpenBao** (`bao server -dev`,
  built from source on the v2.6 line):
  - The rendered script ran twice without error, so it is idempotent.
    Locally only, `auth/kubernetes/config` needed an explicit CA, because
    the server wasn't in a pod. In-cluster, the subchart mounts one and
    binds `system:auth-delegator`.
  - **Every role holds only its own paths.** `bao token capabilities`
    printed `deny` on every other probed path, including:
    - `transit/sign`, `rotate`, `config`, `export` and `backup` on
      `imas-fleet-signing`, for farmer's and saasapi's roles;
    - `secret/metadata`, `delete` and `destroy` for the publisher;
    - the seed path for every role.
  - **The PKI roles issue exactly the right names.** Each issued its own
    workload's SANs and refused the other's.
  - The repo's own `TestOpenBaoEnforcesReadOnlyFleetKey` passed against it.
- **The real `farmer publish-saasapi-credential`**, built from this branch
  and logged in with only the chart's publisher policy:
  - it wrote `{jwt, public_key}`;
  - a second run from a fresh config root wrote nothing, and the KV stayed
    at version 1;
  - it was refused on the seed path.
- **The `db-bootstrap` script**, run against a stub `mysql`: it sent
  exactly the §5.1 SQL above, and waited for `saas.enrollment_keys` before
  the column grant.

**Revalidated on 2026-09-27 against `main` at `84f352b`** (PRs #4, #15,
#16 and #18 included; #18 gave farmer `farmerbusurl`, so the relay is
gone):

- **`Chart.lock`** was written by `helm dependency update` from the four
  projects' published repo indexes. All four pins are published, and each
  is the newest release. `helm dependency build` from a clean copy
  accepts it, and it rejects a `Chart.yaml` edited out of step.
- **The real `farmerbus`**, built from that `main`, ran with the nats
  chart's rendered config and env in `bus.tls.mode=openbao`. It got its
  certificate from this chart's `imas-farmerbus` PKI role in a real
  OpenBao, set up by this chart's bootstrap, using a token scoped to that
  role's policy. The certificate carried exactly the nats chart's SANs,
  including the per-pod headless name.
- **farmer's own code, fed this chart's rendered `/etc/imas/farmer`** and
  the same seeds, with the bus FQDN resolving to the bus (as cluster DNS
  would) and nothing pinned:
  - `config.LoadConfig("farmer")` gave `FarmerBusURL =
    tls://imas-dmz-nats-bus.imas-dmz.svc.cluster.local:5406`,
    `BusTLSServerName()` = that FQDN, and an API bind on `0.0.0.0:5405`;
  - farmer's real `pki.ConnectSystemAccount` (its SYS connection) reached
    the bus, verified it against the OpenBao PKI CA and got a `$SYS` ping
    reply;
  - a tenant connection as farmer's own User JWT for tenant `imas`, with
    the TLS config `dialTenantBus` builds (`ServerName =
    BusTLSServerName()`), connected.
- **Earlier on the same day** (against `4d81cc4`, with the relay): a
  saasapi-style connection to the FQDN reached the same bus directly, and
  a client trusting another CA was refused. saasapi's URL is unchanged
  since.
- **`TestContractWithNatsChart`** was checked by mutation. Each of six
  deliberate breakages made it fail: the nats chart's core pod selector,
  the bus port, the organization, a seed key, the bus SANs, and a
  `bus.tlsServerName` the bus certificate doesn't carry (plus the gateway
  JWT TTL, in the earlier run).

**Not verified:**

- A real install. There was no cluster, so none of this was tested:
  - the PXC operator or Valkey pods;
  - farmer booting against PXC, including `pki.ReloadNKeys`, which needs
    PXC;
  - the Kubernetes auth login itself;
  - the SQL against a real MySQL server.

## Known gaps

1. **No published farmer or saasapi images.**
2. **Horizontal farmer scaling** needs FarmerPKI off local disk.
3. **saasapi runs in the release namespace.** The reference put its
   ExternalSecret in a separate `saasapi` namespace. Here saasapi shares a
   namespace with farmer's seed Secret, but it mounts only its own
   credential Secret. Whoever can create pods in this namespace could
   mount either one.

## Licensing

CLAUDE.md's default is Apache-2.0 or MIT. These are the recorded
exceptions, all subcharts and none of them Go dependencies:

- **OpenBao:** chart and server are MPL-2.0.
- **PXC:** the server is GPLv2; the Percona charts are Apache-2.0. Both
  are accepted in `docs/design/imas-master-plan.md`.
- **Valkey:** the official `valkey-io/valkey-helm` chart is BSD-3-Clause,
  as is the server. It was chosen over Bitnami's Apache-2.0 chart, whose
  free images are no longer published. The project owner signed off on
  this choice when it was flagged.

## Security review notes

- **The publisher boundary** is `deploy/farmer/README.md`'s, carried over
  unchanged and enforced at render time where a chart can enforce it. Two
  things remain up to whoever runs the cluster:
  - Nothing that runs as farmer, and nobody but the deploy pipeline, may
    create pods or Jobs in this namespace, `pods/exec` into them, mint
    `serviceaccounts/token` for `imas-saasapi-cred-publisher`, or read its
    Secrets.
  - With an external OpenBao, the ops repo's roles must match the table
    above. Check with `bao token capabilities` as described.
- **Dev-mode OpenBao is not a security boundary.** Its root token is
  `root`, it's in values, and it's in a Secret the bootstrap reads. Eval
  only.
- **The eval CA and the saasapi CA fetch.** In `tls.mode=openbao` with the
  bundled OpenBao, saasapi fetches the bus CA over plain HTTP. With an
  external OpenBao, set `openbaoClient.caConfigMap` so that fetch, and
  every client, verifies OpenBao.
- **Credentials in the environment.** `IMAS_PXC_DSN` holds a password in
  farmer's environment, as farmer's config requires. farmer's config file
  is mounted read-only, and `enableServiceLinks` is off, so jety can't
  write it back to disk.
- **saasapi's default egress** includes HTTPS to anywhere, for the Keycloak
  JWKS. Narrow `networkPolicy.saasapiExtraEgress`.
