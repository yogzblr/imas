# imas core chart (`deploy/helm/farmer`)

**FLAG FOR SECURITY REVIEW.** This chart carries the OpenBao *write*
policy for the SaaS API credential hand-off, which `deploy/farmer/README.md`
flags as needing human review. Carrying it into a chart doesn't reduce that
need. The same goes for the fleet signing policies from
`deploy/fleetreleaser/policies/`, and for the operator credential the
sprout release hook presents to saasapi. Read
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
- **Schema migrations**: `cmd/migrate` as Helm hook Jobs (see
  [Migrations](#migrations)).
- **Sprout release registration**: a hook Job that registers the sprout
  release a published chart carries with saasapi's operator plane (see
  [Sprout release registration](#sprout-release-registration)).
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
5. **Images.** Each release publishes signed multi-arch farmer and saasapi
   images to `ghcr.io/yogzblr/imas-farmer` and `imas-saasapi`; the chart
   defaults to the tag equal to its `appVersion`. Set `farmer.image.*` and
   `saasapi.image.*` only to use your own build or mirror.

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
  --timeout 30m \
  --set farmer.image.repository=<registry>/imas-farmer --set saasapi.image.repository=<registry>/imas-saasapi \
  --set database.migrate.image.repository=<registry>/imas-migrate
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

- PXC takes a few minutes to come up. The migrate Job is a post-install
  hook that waits for it, so `helm install` doesn't return until PXC is up
  and both schemas are migrated: give it a `--timeout` of at least
  `database.migrate.activeDeadlineSeconds` (Helm's default, 5m, is too
  short). Until then farmer and saasapi wait for their schema.
- The OpenBao bootstrap and publish Jobs are hooks too. Helm waits for
  them, so `helm install` needs the seed Secret in place, or it times out.
- **Dev-mode OpenBao is in memory.** If its pod restarts, the keys, the
  eval CA, the policies and the roles are gone. `helm upgrade` re-runs the
  bootstrap, but it mints *new* gateway and fleet keys and a new CA.

### Production (everything external)

`ci/external-values.yaml` is the worked example. It sets:

- `openbao.enabled=false` and `openbaoClient.addr`/`caConfigMap`;
- `pxc.enabled=false`, `database.host` and `database.existingSecret` (both
  full DSNs). The migrate Job runs at pre-install; see
  [Migrations](#migrations) for who creates the users and grants;
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

## Control-plane box keys

**FLAG FOR SECURITY REVIEW.** J.1 of "Sealing the control plane"
(`docs/design/imas-payload-encryption-design.md`). Off by default
(`controlPlaneBoxKeys.enabled`), and nothing uses these keys yet: farmer
starts sealing SaaS API traffic at rollout step 5.

The SaaS API and farmer seal `internal.*` to each other with NaCl box:
the SaaS API with its own **SaaS API box key**, farmer with the
**platform key**, one per deployment. Both live in **OpenBao KV v2**, not
in a Kubernetes Secret this chart renders, under farmer's tenant box base
path (`farmer.openbao.tenantBox.kvMount`/`kvPath`, `<base>`):

| Secret | Fields | Who reads it |
|---|---|---|
| `<base>/platform` | `pub`, `priv`, `origin` | farmer only (`imas-farmer-tenantbox`, read only) |
| `<base>/saasapi-box` | `pub`, `priv` | the SaaS API only, through its External Secret (step 5). No farmer policy reaches it. |
| `<base>/controlplane-pub` | `platform_pub`, `saasapi_box_pub` | farmer, which pins `saasapi_box_pub`; the SaaS API, which pins `platform_pub` |

`farmer ensure-controlplane-box-keys` (`internal/pki` `controlplanekeys.go`)
writes them, as a `post-install,post-upgrade` hook Job (weight 5: after
the OpenBao bootstrap, before the credential publisher) with farmer's
image, its own ServiceAccount (`imas-controlplane-box-keygen`, no RBAC, no
token automount) and its own OpenBao role. Its policy can **create and
read** the keypairs and never update them, so a re-run (every upgrade)
creates only what is missing and can't replace a key. It rewrites
`controlplane-pub` only if it doesn't match the keypairs. It logs
fingerprints, never key material. Its NetworkPolicy allows OpenBao and DNS
only. The render fails if the Job is given another workload's
ServiceAccount or OpenBao role.

**Pinning.** Each end pins the other's public key from OpenBao, never
from the bus: farmer reads `saasapi_box_pub` (and, inside a rotation's
grace window, the version before it) through its tenantbox client; the
SaaS API gets `platform_pub` and its own private key from one External
Secret mounted only in its pods. Rotating either key is deliberate and
manual for now (the design's open question 4).

**Off by default, on purpose.** `cmd/farmer` dispatches
`ensure-controlplane-box-keys` before loading any config, as it does
`register-sprout-release`, so the Job works when enabled. It stays off
until rollout step 5 gives the keys a consumer: until then enabling it
only adds a hook that can fail a release (with an external OpenBao, its
role and policy must exist first) and a private key nothing reads. With
the bundled OpenBao and `openbaoBootstrap`, enabling it is safe to try.

## OpenBao

Each OpenBao client runs under its own role and gets exactly one policy.

| Client | Env prefix | Kubernetes auth role (value) | Policy |
|---|---|---|---|
| farmer, API certificate (`tls.mode=openbao`) | `IMAS_CERTS_OPENBAO_*` | `imas-farmer-certs` (`tls.openbao.k8sRole`) | `imas-farmer-certs`: `pki/issue/imas-farmer` |
| farmer, gateway JWT signer | `IMAS_GATEWAY_OPENBAO_*` | `imas-farmer-gateway` | `imas-farmer-gateway`: sign and read on `transit/*/imas-gateway-jwt` only |
| farmer, fleet key (read-only) | `IMAS_FLEETSIGN_OPENBAO_*` | `imas-farmer-fleet-verify` | `imas-fleet-verify` (reviewed copy) |
| farmer, tenant box keypairs | `IMAS_TENANTBOX_OPENBAO_*` | `imas-farmer-tenantbox` | `imas-farmer-tenantbox`: KV v2 read/write on `secret/data/imas/tenant-x25519/tenants/+` (one secret per tenant), and read only on `.../platform` and `.../controlplane-pub` (J.1), nothing else |
| saasapi, fleet key (only with `fleetUpdateDispatch` or `operator`) | `IMAS_FLEETSIGN_OPENBAO_*` | `imas-saasapi-fleet-verify` | `imas-fleet-verify` |
| the publish Job | `IMAS_SAASAPI_CRED_OPENBAO_*` | `imas-saasapi-cred-publisher` | `imas-saasapi-cred-publisher` (reviewed copy) |
| the control-plane keygen Job (`controlPlaneBoxKeys.enabled`, off by default) | `IMAS_CPBOX_OPENBAO_*` | `imas-controlplane-box-keygen` | `imas-controlplane-box-keygen`: create and read on `.../platform` and `.../saasapi-box`, create, read and update on `.../controlplane-pub` |

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
- **Namespaces (optional, unset by default).** Each client also reads
  `<prefix>NAMESPACE`: `IMAS_CERTS_OPENBAO_NAMESPACE`,
  `IMAS_GATEWAY_OPENBAO_NAMESPACE`, `IMAS_FLEETSIGN_OPENBAO_NAMESPACE`,
  `IMAS_TENANTBOX_OPENBAO_NAMESPACE` and
  `IMAS_SAASAPI_CRED_OPENBAO_NAMESPACE`. When one is set, that client sends
  it as `X-Vault-Namespace` on every request, logins included; when it is
  unset, no namespace header is sent. The chart sets none of them. To use
  a namespace, add the variables to `farmer.extraEnv` (farmer's four
  clients) and `saasapi.extraEnv` (saasapi's `IMAS_FLEETSIGN_OPENBAO_*`
  client). The publish Job has no `extraEnv`, so the chart can't set
  `IMAS_SAASAPI_CRED_OPENBAO_NAMESPACE`, and the `bao` CLI steps (the
  bootstrap Job and saasapi's `fetch-bus-ca` init container) don't set a
  namespace either. `docs/INSTALL.md` has the full `<prefix>OPENBAO_*` set.

## PXC

- **Both services, one cluster.** farmer's `IMAS_PXC_DSN` and saasapi's
  `SAASAPI_DSN` point at the same host, each with its own user and schema.
  - `pxc.enabled`: the host is `<cluster>-haproxy`. Passwords are generated
    once (kept across upgrades with `lookup`) into `<release>-farmer-db`.
  - External: `database.existingSecret` holds both full DSNs.
  - saasapi refuses to start unless its DSN sets `parseTime=true` (the
    `database.params` default does), and warns if `loc` isn't UTC.
- **Schemas, users and grants** are the migrate Job's; see
  [Migrations](#migrations).
- **Declarative `users` isn't used.** The operator's `users` field applies
  one grant list to every listed schema, which can't express §5.1's split
  or the column grant.

## Migrations

Schema changes are versioned goose migrations compiled into `cmd/migrate`
(image `ghcr.io/yogzblr/imas-migrate`, tag defaulting to the chart's
`appVersion`), run by Helm hook Jobs. farmer and saasapi no longer
migrate on startup; each waits until the schema version it needs is
there (`docs/design/cloudxp-machine-manager-api-design.md` §4.1a).

| Job | Hooks | Runs | Root password |
|---|---|---|---|
| `<release>-farmer-db-migrate` | `post-install` with `pxc.enabled`, else `pre-install`; `pre-upgrade` | `migrate up` | mounted, unless the root step is skipped |
| `<release>-farmer-db-migrate-check` | `pre-rollback` | `migrate check` | never |

- **`migrate up`**, in one pod: waits for PXC; as PXC root creates both
  schemas and users and applies §4.1:

  ```sql
  GRANT ALL    ON farmer.* TO farmer_svc;   GRANT SELECT ON saas.*   TO farmer_svc;
  GRANT ALL    ON saas.*   TO saas_svc;     GRANT SELECT ON farmer.* TO saas_svc;
  ```

  then migrates `farmer` as `farmer_svc` and `saas` as `saas_svc` (single
  writer per schema), and last grants
  `UPDATE (used_count, last_used_at) ON saas.enrollment_keys` to
  `farmer_svc`. The migration creates that table, so nothing waits for
  saasapi any more.
- **Install.** The bundled PXC doesn't exist at `pre-install`, so with
  `pxc.enabled` the Job is `post-install`. With an external PXC it is
  `pre-install`, and farmer and saasapi start on a migrated schema.
- **Rollback.** `helm rollback` runs the *target* revision's
  `pre-rollback` hook: that release's binary checks that the schema the
  newer one left is within the range it supports, and changes nothing.
  Migrations are forward-only and backward compatible for one version, so
  a one-version rollback passes. A rollback to a revision older than this
  chart has no check.
- **The root step** runs whenever the chart knows a root password:
  - `pxc.enabled`: the operator's `<cluster>-secrets` (or
    `pxc.pxc.clusterSecretName`), key `root`, unless
    `database.migrate.rootPasswordSecret` names another;
  - external PXC: only with `database.migrate.rootPasswordSecret` (and
    `rootPasswordKey`, `rootUser`). Without it the Job runs
    `migrate up --skip-root`: the schemas, users, the grants above and the
    `enrollment_keys` column grant must already exist, and the column
    grant can only be given once the first migration has created the
    table.

  The users and passwords come from the two DSNs (the generated
  `<release>-farmer-db` or `database.existingSecret`), so the root step
  also works with `pxc.enabled` and your own DSN Secret.
- **Credentials are files.** The root password and both DSNs are mounted
  from their Secrets (`IMAS_MIGRATE_*_FILE`); none is in the Job's env,
  args or spec, and `cmd/migrate` never logs one.
- **Hook lifecycle.** `before-hook-creation,hook-succeeded`: a successful
  run is deleted, a failed one is kept for its logs until the next run
  replaces it. `backoffLimit` and `activeDeadlineSeconds` come from
  `database.migrate`. Keep `helm --timeout` above the deadline.
- **Argo CD** has no install/upgrade split and no rollback hook. With
  `database.migrate.argoCDHooks` (on) the `up` Job is a `Sync` hook with
  the bundled PXC (the cluster is created in the same phase) and
  `PreSync` with an external one; the check Job never runs under Argo CD.
- **Renaming a user or schema** (`database.farmer.*`, `database.saasapi.*`)
  on upgrade: the `pre-upgrade` Job still reads the previous DSN Secret,
  so the new user is only created by the following upgrade. Don't rename
  in place.

## Sprout release registration

**FLAG FOR SECURITY REVIEW: the operator credential.** A published farmer
chart carries the sprout release it was tested with,
`files/sprout-release.json`, which `packaging/helm/stamp-sprout-release.sh`
writes at release time: the version (the tag, `vX.Y.Z`), its
`min_sprout_version`, and, for each OS/arch/package type, the package file
name and SHA-256. A `post-install`/`post-upgrade` hook Job,
`farmer register-sprout-release` (`internal/sproutrelease`) in farmer's own
image, registers it with saasapi's operator plane (`POST /v1/operator/fleet-releases`, API design §2.5,
`docs/api/saasapi-operator-openapi.yaml`). saasapi has `cmd/fleetreleaser`
sign each new package and stores the rows; only then can tenants approve
and roll it out. There is no CI call.

```
helm upgrade ──▶ hook Job ──operator token, https──▶ saasapi operator plane ──▶ fleetreleaser (sign)
           (farmer register-     <release>-saasapi-operator:8443     └──▶ saas.fleet_versions
            sprout-release)
```

**When it runs.** The Job renders only when all of these hold; otherwise
NOTES says which one is missing and nothing is registered:

- the chart has `files/sprout-release.json` (a chart from a source
  checkout doesn't, so a dev install skips the hook);
- `sproutRelease.register` (default on);
- `saasapi.enabled` and `saasapi.operator.enabled` (default off: see
  [Known gaps](#known-gaps)).

**What it sends.** The stamped release verbatim, plus
`sproutRelease.channel` (default `stable`).

- **`min_sprout_version` is set at release time**, not per install: the
  stamp script reads it from `packaging/helm/min-sprout-version` (one
  version line, `#` comments), so the floor is reviewed in a PR and ships
  under the tag with everything else (`docs/RELEASING.md`,
  "Compatibility"). It is the oldest sprout that may update straight to
  this release, signed into every manifest, and immutable once the version
  is registered. The script refuses a floor that isn't canonical semver or
  is above the tag by semver precedence (so `v1.0.0` can't be the floor of
  `v1.0.0-rc.1`).
- The render fails if the file's version isn't the canonical
  `v`+`appVersion` (the farmer chart and the sprout release ship under one
  tag), if `min_sprout_version` is missing, not canonical or above the
  version, or if the file has fields beyond `version`,
  `min_sprout_version` and `packages`. Setting the removed
  `sproutRelease.minSproutVersion` value fails the render rather than being
  ignored. Nothing is rewritten to pass: saasapi refuses non-canonical
  values, and so does the chart.

**Outcome.**

| saasapi answers | The Job | The release |
|---|---|---|
| 201: registered | succeeds | succeeds |
| 200: already registered with the same contents (every later `helm upgrade`) | succeeds | succeeds |
| 409 `release_conflict`: this version is registered with different contents (or another `min_sprout_version`) | prints saasapi's message and the request it sent; fails at once (exit 2, `podFailurePolicy` `FailJob`) | **fails** |
| 409 `version_revoked`, any other 4xx or a 3xx (400, 401, 422 `signing_refused`; redirects are never followed), a certificate that doesn't verify, a local configuration error (bad token or request file) | prints why; fails at once | **fails** |
| no answer (saasapi still rolling out), 408, 429, 5xx | retries with exponential backoff (`sproutRelease.retry`: 8 attempts, 5s doubling to 60s), then fails; the Job then gets `backoffLimit` (1) more pods | fails if every attempt does |

Releases are immutable. A 409 means the version was already registered
with other contents: don't re-stamp it, cut a new version. The failed Job
is kept for its logs (`kubectl logs job/<release>-farmer-sprout-release-register`)
until the next run or `ttlSecondsAfterFinished`.

**Ordering.** Hook weight 20: after the OpenBao bootstrap (0) and the
publish Job (10), because saasapi only starts once the JWT the publish Job
writes has reached it. Helm doesn't wait for Deployments before
`post-*` hooks unless you pass `--wait`; without it the in-pod retries cover
saasapi coming up. Under Argo CD it is a `PostSync` hook (sync-wave 1), so
it runs once the sync is healthy. `helm install/upgrade --timeout` must
cover `sproutRelease.activeDeadlineSeconds` (1500), as for the migrate Job.
There is no `post-rollback` hook: `helm rollback` leaves a registered
release registered, and sprouts already on it keep it.

**The Job's boundary.**

- Its own ServiceAccount (`sproutRelease.serviceAccountName`,
  `imas-sprout-release-registrar`): no RBAC, no API token, no OpenBao role.
  The render fails if it names farmer's, saasapi's or the publisher's.
- One Secret key: the current operator token
  (`saasapi.operator.token.secretName`/`currentKey`), as a 0440 file. Never
  the previous one. From the operator TLS Secret, `ca.crt` only, to verify
  saasapi; never the key.
- The token is read from that file by `farmer register-sprout-release`
  and sent only in the `Authorization` header to saasapi's operator
  listener: never in argv or the environment, never printed. https only,
  TLS 1.2+, trusting only the mounted `ca.crt` (not the system roots); proxy
  settings are ignored and redirects are not followed. The subcommand
  checks the token the way saasapi does (32+ characters, no whitespace)
  before sending anything.
- It runs before farmer loads its config: no `/etc/imas`, no PKI
  directory, no seeds, no database, bus or OpenBao. The pod mounts the
  request ConfigMap and the two Secret items, nothing else.
- Egress to saasapi's pods on the operator port, and DNS. No ingress. The
  policy is rendered whatever `networkPolicy.enabled` says. Its pods carry
  `app.kubernetes.io/name: imas-sprout-release-registrar`, so the nats
  chart's bus policy never admits them.
- Pod Security `restricted`, read-only root. The image is farmer's
  (`farmer.image`, `FROM scratch`: no shell), at the same tag as the farmer
  Deployment, with farmer's `imagePullSecrets`.

### saasapi's operator plane

`saasapi.operator.enabled` configures saasapi's second listener
(`internal/saasapi` `NewOperatorServer`) and a Service of its own,
`<release>-saasapi-operator` (port `saasapi.operator.port`, 8443), which
the gateway's route to `<release>-saasapi` never reaches.

| Value | saasapi gets | Notes |
|---|---|---|
| `saasapi.operator.tls.secretName` | `SAASAPI_OPERATOR_TLS_CERT_FILE`/`_KEY_FILE` (`tls.crt`, `tls.key`) | A `kubernetes.io/tls` Secret whose `ca.crt` the hook Job verifies against. SAN: the operator Service FQDN, `<release>-saasapi-operator.<ns>.svc.<clusterDomain>` (NOTES prints it). cert-manager writes all three keys. |
| `saasapi.operator.token.secretName` / `currentKey` / `previousKey` | `SAASAPI_OPERATOR_TOKEN_FILE` / `_PREVIOUS_FILE` | A Secret of its own: the render fails if it is the BFF's, the NATS credential's, the seeds', fleetreleaser's or the TLS Secret. At least 32 characters, no whitespace. `previousKey` only during a rotation. |
| `saasapi.operator.fleetReleaser.url` | `SAASAPI_FLEETRELEASER_URL` | `https://host[:port]`, no path. saasapi's egress opens on its port (`networkPolicy.fleetreleaser.to`; empty: any destination). |
| `saasapi.operator.fleetReleaser.tokenSecretName` / `tokenKey` | `SAASAPI_FLEETRELEASER_TOKEN_FILE` | The caller token fleetreleaser checks (`deploy/fleetreleaser/README.md`). |
| `saasapi.operator.fleetReleaser.caConfigMap` / `caKey` | `SAASAPI_FLEETRELEASER_CA_FILE` | Optional; the system roots otherwise. |

It also turns on saasapi's read-only fleet key client
(`IMAS_FLEETSIGN_OPENBAO_*`, role `imas-saasapi-fleet-verify`), which the
operator plane needs to check fleetreleaser's signatures; the bootstrap
creates that role. saasapi's operator port admits the hook Job's pods, plus
`networkPolicy.saasapiOperatorIngress.from` (empty by default), and nothing
else.

Generate the token with at least 32 random bytes, e.g.
`openssl rand -base64 48 | tr -d '\n='`, and keep it in OpenBao/ESO like the
BFF secret. Whoever holds it can get any well-formed release above
fleetreleaser's floor signed and offered to tenants for approval
(`deploy/fleetreleaser/README.md`, "What the split does not stop").

### Rotating the operator token

saasapi reads the token once, at start. The hook Job is its only
in-cluster presenter and runs only during `helm install/upgrade`, so a
rotation between upgrades needs no overlap:

1. Write the new token to the Secret's `currentKey`.
2. Make sure saasapi has restarted onto it: Reloader does this on the
   Secret change (`saasapi.podAnnotations`); without Reloader,
   `kubectl -n <ns> rollout restart deploy/<release>-farmer-saasapi`. Wait
   for the rollout. A hook that reaches a pod still holding the old token
   gets a 401, which fails the release.
3. The next `helm upgrade` presents the new token.

If other tooling (the revoke runbook's operators, say) still holds the old
token while you roll the new one out, keep both for a while: put the old
one under another key and `helm upgrade` with
`saasapi.operator.token.previousKey=<that key>`; saasapi then accepts both.
Remove the key and set `previousKey=""` again afterwards.

### Revoking a sprout release

A bad sprout version is withdrawn with the revoke call, not with
`helm rollback`. It is permanent: no rollout of the version is created or
continued, no tenant can newly approve it, and farmer serves no manifest
for it. Sprouts already running it keep it, because they refuse downgrades;
ship the fix as a new version, which they can update to.

1. Confirm the version: `helm get values` and
   `kubectl -n <ns> get configmap <release>-farmer-sprout-release -o jsonpath='{.data.request\.json}'`.
2. Reach the operator listener. It is not on the gateway, and its
   NetworkPolicy admits only the hook Job and
   `networkPolicy.saasapiOperatorIngress.from`. From an admitted
   operations host, or through a port-forward (which NetworkPolicy doesn't
   see, so `pods/portforward` on saasapi is access to the listener; the
   token is still required):

   ```sh
   NS=imas-core; REL=imas-core; VERSION=v2.4.1
   SVC=$REL-farmer-saasapi-operator
   kubectl -n $NS port-forward svc/$SVC 8443:8443 &
   kubectl -n $NS get secret <saasapi.operator.tls.secretName> -o jsonpath='{.data.ca\.crt}' | base64 -d > /tmp/operator-ca.crt
   ```

3. Call revoke, with the token read from its Secret straight into curl's
   stdin, never onto a command line or into shell history:

   ```sh
   kubectl -n $NS get secret <saasapi.operator.token.secretName> -o jsonpath='{.data.current}' | base64 -d \
     | sed 's/^/Authorization: Bearer /' \
     | curl -sS --fail-with-body --proto '=https' --cacert /tmp/operator-ca.crt \
         --resolve "$SVC.$NS.svc.cluster.local:8443:127.0.0.1" \
         -X POST -H @- "https://$SVC.$NS.svc.cluster.local:8443/v1/operator/fleet-releases/$VERSION/revoke"
   ```

   `200 {"version": ..., "revoked": true, "packages": N, "already_revoked": false}`.
   Repeating it is a 200 with `already_revoked: true`. A 404 means the
   version was never registered.
4. Stop the port-forward and delete `/tmp/operator-ca.crt`. Record the
   revoke in the release log.

There is no un-revoke. A later `helm upgrade` of a chart carrying the
revoked version gets a 200 no-op (same contents) and leaves it revoked.

## Tenant recipe upload

`saasapi.recipes.enabled` (default off) turns on
`GET/PUT/DELETE /v1/tenants/{tenant_id}/recipes[/{name}]` (REC.1, API
design §1.6; **FLAG FOR SECURITY REVIEW**). saasapi writes tenants' recipes
straight into `objectStore.bucket`, the bucket farmer cooks from, at
`tenants/<tenant_id>/recipes/<name with dots as slashes>.imas`.

It does so with **its own** object-store credential,
`saasapi.recipes.credentialsSecret`, never farmer's (the chart refuses the
same Secret). Its policy must allow only what the routes need, in every
tenant's prefix, and nothing on `sprouts/` (staged recipes), the job bucket
or the platform recipe prefix. The example,
[`files/objectstore-policies/saasapi-recipes.json`](files/objectstore-policies/saasapi-recipes.json)
(replace `RECIPE_BUCKET`), works as a MinIO policy or an AWS IAM policy:

- `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject` on `tenants/*/recipes/*`;
- `s3:ListBucket` with the prefix limited to `tenants/*/recipes/*`;
- `s3:PutObject` only on `tenants/*/recipe-audit/*`, saasapi's audit
  records, so saasapi can add records but never read or delete them;
- `s3:GetBucketLocation`, which the client calls first.

The design allows saasapi to read the platform prefix, but nothing uses it
yet, so the example grants none. With MinIO:

```bash
sed 's/RECIPE_BUCKET/imas-recipes/' files/objectstore-policies/saasapi-recipes.json > /tmp/p.json
mc admin policy create ALIAS imas-saasapi-recipes /tmp/p.json
mc admin user add ALIAS imas-saasapi "$SECRET_KEY"
mc admin policy attach ALIAS imas-saasapi-recipes --user imas-saasapi
kubectl -n imas create secret generic saasapi-s3 \
  --from-literal=access-key-id=imas-saasapi --from-literal=secret-access-key="$SECRET_KEY"
```

`internal/saasapi`'s `TestRecipeObjectStorePolicy` checks this file against
the keys the code writes. saasapi gets the access key id as an env var and
the secret key only as a file. It validates uploads under
`farmer.recipes.templateLimits`, which it receives as the same
`IMAS_RECIPE_*` variables farmer gets, so a recipe that uploads is a recipe
farmer will render. That one set of limits for both is an owner decision
(2026-10-04): there is no separate saasapi value to override it. Reading needs `saasapi.recipes.readRole` or `writeRole`
(Keycloak realm roles, or client roles of `saasapi.jwt.audience`), and
writing needs `writeRole`. Egress to the object store goes through
`networkPolicy.saasapiExtraEgress`: its default allows 443, so add the port
for a MinIO on 9000.

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
| saasapi | out | OpenBao, only for the fleet key client (fleet dispatch, operator plane) or the bus CA fetch | 8200 |
| saasapi | in | `networkPolicy.saasapiIngress.from` (default: anyone) | `saasapi.port` (8081) |
| saasapi | in | with `saasapi.operator`: the sprout release hook Job's pods, plus `networkPolicy.saasapiOperatorIngress.from` (default: none) | `saasapi.operator.port` (8443) |
| saasapi | out | with `saasapi.operator`: fleetreleaser (`networkPolicy.fleetreleaser.to`, default any destination) | `fleetReleaser.url`'s port |
| saasapi | out | the bus pods | `bus.port` |
| saasapi | out | `saasapiExtraEgress`, default HTTPS anywhere (the Keycloak JWKS, and the object store with `saasapi.recipes`). **Narrow it.** | 443 |
| publish Job | out | OpenBao, DNS; nothing else, no ingress | 8200, 53 |
| migrate Jobs | out | PXC, DNS; nothing else, no ingress | 3306, 53 |
| sprout release hook Job | out | saasapi's pods on the operator port, DNS; nothing else, no ingress | 8443, 53 |
| openbao-bootstrap | out | OpenBao, DNS | 8200, 53 |
| all | out | DNS | 53 |

- **The migrate Jobs' policy** is a hook itself, created before them at
  every event (at `pre-install` and `pre-upgrade` the release's own
  resources aren't applied yet), and rendered whatever
  `networkPolicy.enabled` says. Their pods carry
  `app.kubernetes.io/name: imas-migrate`, not the chart's name, so the
  nats chart's bus policy never admits them.
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
| `database.migrate.image.*` | `ghcr.io/yogzblr/imas-migrate`, tag `appVersion` | `cmd/migrate`. Keep it at farmer's and saasapi's version. |
| `database.migrate.rootPasswordSecret` / `rootPasswordKey` / `rootUser` | `""` / `root` / `root` | PXC root, for the root step. Empty: the operator's Secret with `pxc.enabled`, `--skip-root` otherwise. |
| `database.migrate.wait` / `backoffLimit` / `activeDeadlineSeconds` | `15m` / `2` / `1800` | How long to wait for PXC; the Job's retry and time budget. |
| `database.migrate.argoCDHooks` | `true` | Argo CD hook annotations. See [Migrations](#migrations). |
| `objectStore.*` | empty | `IMAS_S3_*`. `jobBucket` must differ from `bucket`. |
| `farmer.image.*` | `ghcr.io/yogzblr/imas-farmer` | Also the publish Job's image. |
| `farmer.replicaCount` | `1` | Must be 1. |
| `farmer.logLevel` / `apiPort` / `gatewayJWTTTL` | `info` / `5405` / `24h` | `loglevel`, `farmerapiport`, `gatewayjwtttl`. |
| `farmer.adminPubKeys` | `[]` | `pubkeys.admin`. |
| `farmer.jobs.reconcileWindow` | `"2h"` | `IMAS_JOB_RECONCILE_WINDOW` (`deploy/farmer/values.job-reconcile.yaml`). |
| `farmer.recipes.templateLimits.maxSourceBytes` | `262144` | `IMAS_RECIPE_MAX_SOURCE_BYTES`: largest recipe source farmer reads or renders. |
| `farmer.recipes.templateLimits.maxRenderedBytes` | `1048576` | `IMAS_RECIPE_MAX_RENDERED_BYTES`: largest output of one recipe render. |
| `farmer.recipes.templateLimits.maxValueBytes` | `262144` | `IMAS_RECIPE_MAX_VALUE_BYTES`: largest string one template function returns; at most `maxRenderedBytes`. |
| `farmer.recipes.templateLimits.renderTimeout` | `"2s"` | `IMAS_RECIPE_RENDER_TIMEOUT`: time limit of one recipe render, a quoted Go duration up to `1m`. |
| `farmer.recipes.templateLimits.maxRangeIterations` | `10000` | `IMAS_RECIPE_MAX_RANGE_ITERATIONS`: total `range` iterations in one render. Recipes are tenant-written (untrusted); all five are required, and farmer refuses to start if one is out of range (sizes up to 64 MiB, iterations up to 10000000). |
| `farmer.selfUpdate.enabled` | `false` | `IMAS_SELF_UPDATE_ENABLED`: farmer's own switch for `self_update` (security review L1). Off, farmer refuses every update whatever saasapi sends. A rollout needs this and `saasapi.fleetUpdateDispatch.enabled`. |
| `farmer.sproutActions.{concurrency,selfUpdateConcurrency,tenantConcurrency}` | `64`, `16`, `8` | `IMAS_SPROUT_ACTION_CONCURRENCY`, `IMAS_SELF_UPDATE_CONCURRENCY`, `IMAS_SPROUT_ACTION_TENANT_CONCURRENCY`: per replica, the cmd.run/cook pool, the pool reserved for `self_update`, and one tenant's cap in each (security review M5). A request that doesn't fit is refused at once (`farmer_busy`) and saasapi sends it again. Null emits no env var. |
| `farmer.openbao.{gateway,fleetSign,tenantBox}.*` | see values.yaml | Mount, key or path, role, and token key per client. |
| `farmer.extraConfig` | `{}` | Extra `/etc/imas/farmer` keys. Chart-managed keys win. |
| `farmer.extraEnv` | `[]` | Extra env vars for farmer, e.g. the optional `*_OPENBAO_NAMESPACE` (see [OpenBao](#openbao)) or `HTTPS_PROXY`/`NO_PROXY`. Never a raw `IMAS_NATS_*_SEED` or any `IMAS_SAASAPI_CRED_OPENBAO_*`. |
| `farmer.persistence.*` | 1Gi RWO, kept | FarmerPKI and audit logs. |
| `saasapi.enabled` / `replicaCount` / `port` | `true` / `2` / `8081` | |
| `saasapi.jwt.*` | `""` | Keycloak JWKS URL, issuer and audience. Required. |
| `saasapi.internalAuthSecret.*` | `imas-saasapi-internal-auth` | `INTERNAL_AUTH_SECRET_CURRENT`/`_PREVIOUS`. |
| `saasapi.natsCredentials.*` | `imas-saasapi-nats` | The seed (as a file) and the JWT. |
| `saasapi.fleetUpdateDispatch.enabled` | `false` | Also turns on saasapi's verify-only OpenBao client. |
| `saasapi.actionDispatch.{concurrency,selfUpdateConcurrency,tenantConcurrency}` | `64`, `16`, `8` | `SAASAPI_ACTION_DISPATCH_CONCURRENCY`, `SAASAPI_SELF_UPDATE_DISPATCH_CONCURRENCY`, `SAASAPI_ACTION_DISPATCH_TENANT_CONCURRENCY`: per replica, the cmd.run/cook dispatch pool, the pool reserved for rollout waves, and one tenant's cap in each (security review M5). The cap must be at most half of `concurrency`. Keep each at or below farmer's matching value times farmer's replicas. Null emits no env var. |
| `saasapi.fleetUpdateDispatch.clockSkew` | `""` (30s) | `SAASAPI_FLEET_UPDATE_CLOCK_SKEW`: clock-skew margin of the rollout wave gate, a Go duration up to `5m`. Empty emits no env var. |
| `saasapi.outboxSweeper.enabled` | `true` | `SAASAPI_OUTBOX_SWEEPER_ENABLED`: re-dispatch outbox work no live pod is dispatching, under row leases (safe on every replica). |
| `saasapi.outboxSweeper.{interval,provisioningStaleAfter,actionStaleAfter,actionMaxAge,leaseTTL}` / `maxAttempts` | `""` / `null` (30s, 2m, 2m, 15m, 2m / 5) | `SAASAPI_OUTBOX_SWEEP_INTERVAL`, `_PROVISIONING_STALE_AFTER`, `_ACTION_STALE_AFTER`, `_ACTION_MAX_AGE`, `_LEASE_TTL`, `_MAX_ATTEMPTS`. Empty or null emits no env var. See [`docs/api/saasapi.md`](../../../docs/api/saasapi.md#outbox-sweeper). |
| `saasapi.operator.*` | off, port `8443` | The operator plane: TLS Secret, token Secret, fleetreleaser client. See [saasapi's operator plane](#saasapis-operator-plane). |
| `saasapi.enrollmentKeys.rateLimit.*` | `1` / `5` | `deploy/saasapi/values.rate-limit.yaml`. `null` emits no env var. |
| `saasapi.recipes.enabled` | `false` | Tenant recipe upload: `SAASAPI_RECIPES_S3_*` from `objectStore.endpoint`/`bucket`/`useSSL` and saasapi's own credential. Off, the recipe routes answer 503. See [Tenant recipe upload](#tenant-recipe-upload). |
| `saasapi.recipes.credentialsSecret` / `accessKeyIdKey` / `secretAccessKeyKey` | `""` / `access-key-id` / `secret-access-key` | saasapi's own access key pair, limited to `tenants/*/recipes/*`. Required when enabled; must not be `objectStore.credentialsSecret`. |
| `saasapi.recipes.readRole` / `writeRole` | `imas-recipes-read` / `imas-recipes-write` | `SAASAPI_RECIPES_READ_ROLE` / `_WRITE_ROLE`: Keycloak roles for GET, and for PUT/DELETE. Must differ. |
| `saasapi.recipes.maxCount` / `maxTotalBytes` | `500` / `20971520` | `SAASAPI_RECIPES_MAX_COUNT` / `_MAX_TOTAL_BYTES`: per-tenant caps. |
| `saasapi.recipes.writeRateLimit.*` | `1` / `10` | `SAASAPI_RECIPES_WRITE_RATE_LIMIT` / `_BURST`: PUT and DELETE per tenant. |
| `saasapi.extraEnv` | `[]` | Extra env vars for saasapi, e.g. `IMAS_FLEETSIGN_OPENBAO_NAMESPACE` (see [OpenBao](#openbao)) or `HTTPS_PROXY`/`NO_PROXY`. |
| `credentialPublisher.*` | enabled, `platform/imas/saasapi-nats-user` | The publish Job. |
| `sproutRelease.register` | `true` | Register `files/sprout-release.json` when the chart has it and the operator plane is on. |
| `sproutRelease.channel` | `stable` | Sent with the release. `min_sprout_version` is not a value: it is stamped at release time from `packaging/helm/min-sprout-version`. |
| `sproutRelease.serviceAccountName` | `imas-sprout-release-registrar` | The hook Job's own ServiceAccount. It runs `farmer register-sprout-release` in `farmer.image`. |
| `sproutRelease.retry.*` / `requestTimeoutSeconds` | `8`, `5`s doubling to `60`s / `600` | In-pod retries for no answer, 408, 429 and 5xx. |
| `sproutRelease.backoffLimit` / `activeDeadlineSeconds` / `ttlSecondsAfterFinished` | `1` / `1500` / `3600` | Keep `helm --timeout` above the deadline. |
| `sproutRelease.argoCDHooks` | `true` | `PostSync`, sync-wave 1. |
| `externalSecrets.*` | off | ESO wiring. |
| `openbaoBootstrap.*` | on | The bundled OpenBao's setup Job. |
| `networkPolicy.*` | on | See above. `saasapiOperatorIngress.from` and `fleetreleaser.to` are the operator plane's peers. |

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

**Sprout release registration (FU.5), 2026-10-02**, with helm v3.16 built
from source and no cluster:

- `farmer register-sprout-release` (`internal/sproutrelease` tests) ran
  against a local HTTPS server standing in for saasapi: every outcome in
  the table above, the backoff sequence, an untrusted CA and a wrong host
  name (final, nothing sent), proxy settings ignored, a redirect not
  followed, and every local configuration error refused before sending.
  The token was never printed. The built `farmer` binary dispatches the
  subcommand without creating `/etc/imas`.
- `packaging/helm/stamp-sprout-release.sh`'s real output, with the repo's
  `min-sprout-version`, renders into the request body; the semver
  precedence check was run over the spec's ordering examples, prereleases
  included (`TestStampedReleaseRenders`).

**Not verified:**

- A real install. There was no cluster, so none of this was tested:
  - the PXC operator or Valkey pods;
  - farmer booting against PXC, including `pki.ReloadNKeys`, which needs
    PXC;
  - the Kubernetes auth login itself;
  - the SQL against a real MySQL server;
  - the migrate hook Jobs (rendering and `go test` only; `cmd/migrate`
    itself has its own tests against MySQL in `internal/migrations`);
  - the sprout release hook against a real saasapi, which can't serve the
    operator plane yet (Known gaps), and `podFailurePolicy` failing the Job
    on exit 2.

## Known gaps

1. **`cmd/saasapi` doesn't start the operator plane yet.**
   `NewOperatorServer` and its configuration exist in `internal/saasapi`,
   but `main` never calls it (`docs/api/saasapi.md`, "Operator plane"). Until
   it does, `saasapi.operator.enabled=true` configures a listener nothing
   serves, and the sprout release hook fails its release after its retries
   (saasapi not reachable). So both stay off by default, and a published
   chart says in NOTES that its sprout release was not registered.
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
- **The migrate Job holds PXC's root password.** Only the `up` Job's pod
  mounts it, one key, as a file; farmer, saasapi and the rollback check
  never see it, and `TestRootSecretOnlyInMigrateJob` fails the build if
  any other manifest names that Secret. The pod has no ServiceAccount
  token and reaches only PXC and DNS. Whoever can create pods in this
  namespace can still mount the operator's root Secret: the same
  namespace-access rule as the publisher's applies.
- **Credentials in the environment.** `IMAS_PXC_DSN` holds a password in
  farmer's environment, as farmer's config requires. farmer's config file
  is mounted read-only, and `enableServiceLinks` is off, so jety can't
  write it back to disk.
- **saasapi's default egress** includes HTTPS to anywhere, for the Keycloak
  JWKS. Narrow `networkPolicy.saasapiExtraEgress`.
- **saasapi's recipe credential** ([Tenant recipe upload](#tenant-recipe-upload))
  can write every tenant's recipes, which run as root on that tenant's
  sprouts. Tenant scoping is enforced in saasapi's code, not by the bucket
  policy, which can only limit the credential to `tenants/*/recipes/*`. Keep
  it a Secret of its own, scoped by the example policy, and never reuse
  farmer's (farmer's can write `sprouts/` and the platform tree).
- **The operator credential** ([Sprout release registration](#sprout-release-registration)).
  Whoever holds the operator token can get any well-formed release above
  fleetreleaser's floor signed and offered to tenants. Only two pods get
  it: saasapi (which checks it) and the hook Job (which presents it, from
  one Secret key, with no ServiceAccount token, RBAC or OpenBao role, and
  egress to saasapi's operator port only). The tests pin that:
  `TestSproutReleaseSecretWiring` fails if any other manifest names the
  token Secret, and `internal/sproutrelease`'s tests fail if the token is
  ever printed. What the chart can't
  enforce, the cluster must:
  - the namespace-access rule above, again: whoever can create pods here,
    read Secrets, or `port-forward` to saasapi (NetworkPolicy doesn't see a
    port-forward) can use the token or reach the listener;
  - the operator listener's certificate must carry the operator Service's
    FQDN, from a CA you control (its `ca.crt` is what the Job trusts);
  - the operator Service must stay off the gateway's routes.
