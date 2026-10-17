# imas core chart (`deploy/helm/farmer`)

**FLAG FOR SECURITY REVIEW.** This chart carries the OpenBao *write*
policy for the SaaS API credential hand-off, which `deploy/farmer/README.md`
flags as needing human review. Carrying it into a chart doesn't reduce that
need. The same goes for the operator credential the sprout release hook
presents to saasapi. Read
[Security review notes](#security-review-notes) first. The defaults are a
non-production eval install.

## The published chart

Each release pushes this chart to GitHub Container Registry as an OCI chart,
signed by digest with keyless cosign (`docs/RELEASING.md`, "Helm charts on
GHCR"). Pull it anonymously, at an exact version (no `--devel`, no range;
Helm 3.8 or later, or 4):

```sh
helm pull oci://ghcr.io/yogzblr/charts/farmer --version 0.1.0-rc.5 --destination .
```

The chart `version` and `appVersion` are the release version without its `v`.
If the pull is refused, the chart package may still be private: the owner
makes each chart package public once, in its GHCR package settings, after the
first push. The Buildkite `imashelm` registry is superseded for charts.

It deploys imas's non-DMZ core:

- **farmer** (`cmd/farmer`, `ConnectFarmer()`): the API, the job, facts and
  cook subscribers, and tenant provisioning. It is stateless and runs as
  two replicas by default (see [Farmer is stateless](#farmer-is-stateless)).
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
cluster with one schema each (`docs/design/imas-machine-manager-api-design.md`
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

1. **Fetch the subcharts.** Add the three repositories `Chart.lock` names,
   then build:

   ```sh
   helm repo add openbao https://openbao.github.io/openbao-helm
   helm repo add percona https://percona.github.io/percona-helm-charts
   helm repo add valkey https://valkey.io/valkey-helm/
   helm dependency build deploy/helm/farmer
   ```

   Without the `helm repo add` lines, Helm 3 and 4 both refuse with
   `no repository definition for ...`. CI runs the same commands
   (`.github/workflows/ci.yml`). `Chart.lock` pins the exact versions;
   `charts/` is gitignored. Use `helm dependency update` only to move a pin,
   and commit the new lock.
2. **The seed Secret** (`natsSeeds.secretName`, default
   `imas-farmer-nats-seeds`) must exist in the release namespace, with the
   two user seeds `sys-user.nk` and `saasapi-user.nk`. The chart never
   generates seeds. Next to it, **farmer's NKey Secret**
   (`farmer.nkeySecret.secretName`, default `imas-farmer-nkey`, key
   `farmer.nk`): one user seed that every farmer replica shares.
   See [Seeds](#seeds). The NATS trust chain itself
   (operator, operator-signing, SYS account and tenant keys) is created in
   OpenBao Transit by the bootstrap Job; see [NATS trust](#nats-trust).
3. **The nats chart**, installed or planned, so you know
   `bus.serviceName` and `bus.namespace` (or, for a bus in another
   cluster, the DNS name to dial it at, `bus.host`; see
   [Reaching the bus](#reaching-the-bus)), and Envoy's external `wss://`
   address for `bus.sproutBusURLs`.
4. **saasapi's inputs:**
   - the Keycloak realm (`saasapi.jwt.*`);
   - the BFF shared-secret Secret (`saasapi.internalAuthSecret.secretName`,
     key `current`, and optionally `previous`).
5. **The bootstrap admin's keys** (`farmer.bootstrapAdmin.pubkey` and
   `boxpub`). Required: see [Bootstrap admin](#bootstrap-admin).
6. **Images.** Each release publishes signed multi-arch farmer and saasapi
   images to `ghcr.io/yogzblr/imas-farmer` and `imas-saasapi`; the chart
   defaults to the tag equal to its `appVersion`. Set `farmer.image.*` and
   `saasapi.image.*` only to use your own build or mirror.

### Bootstrap admin

Since J.3 the imas CLI can't register a user over the bus: the first admin
comes from farmer's config file, rendered from `farmer.bootstrapAdmin`, and
every further user is added by that admin. A release with no bootstrap
admin therefore has nobody who can make a single CLI request, so the chart
refuses to render one (FIX.3). On the admin's own machine, before the
install (both commands work offline):

```sh
imas auth privkey && imas auth pubkey   # farmer.bootstrapAdmin.pubkey (A...)
imas auth keygen                        # farmer.bootstrapAdmin.boxpub ("Box key:"), and its fingerprint
```

Pass both, and optionally `farmer.bootstrapAdmin.username`. Check the box
key's fingerprint with the admin out of band: whoever's key this is
becomes the platform's first admin. Farmer imports the box key once; the
database is authoritative after that, so the values can stay set on
upgrades and changing them later does nothing.

`farmer.bootstrapAdmin.skip=true` renders no admin instead, and NOTES says
so. Use it only when farmer's database already holds an admin: an upgrade
of a release installed before this check, or a reinstall against the same
database. It can't be combined with `pubkey`, `boxpub` or `username`.

The `ci/` values files carry a placeholder admin so they render: an
all-zero box key, which farmer refuses to import (a weak key), so it can
never be anyone's. NOTES warns while it is set. Replace it.

### Eval install (everything bundled)

```sh
kubectl create namespace imas-core
# The two user seeds (see "Seeds"). `nk` is github.com/nats-io/nkeys/nk.
# The trust chain keys are created in OpenBao Transit by the bootstrap Job.
kubectl -n imas-core create secret generic imas-farmer-nats-seeds \
  --from-literal=sys-user.nk="$(nk -gen user)" \
  --from-literal=saasapi-user.nk="$(nk -gen user)"
# farmer's NKey: one seed for every replica, in a Secret of its own.
kubectl -n imas-core create secret generic imas-farmer-nkey \
  --from-literal=farmer.nk="$(nk -gen user)"
kubectl -n imas-core create secret generic imas-saasapi-internal-auth \
  --from-literal=current="$(openssl rand -hex 32)"
# The accounts bucket's writer (accountStore): get, put and list on the
# bucket accountStore.bucket (imas-accounts) of an S3 store you provide.
kubectl -n imas-core create secret generic imas-farmer-accounts-writer \
  --from-literal=access-key-id=<writer access key> \
  --from-literal=secret-access-key=<writer secret key>

helm repo add openbao https://openbao.github.io/openbao-helm
helm repo add percona https://percona.github.io/percona-helm-charts
helm repo add valkey https://valkey.io/valkey-helm/
helm dependency build deploy/helm/farmer
helm install imas-core deploy/helm/farmer -n imas-core -f deploy/helm/farmer/ci/default-values.yaml \
  --timeout 30m \
  --set farmer.bootstrapAdmin.pubkey=<imas auth pubkey> --set farmer.bootstrapAdmin.boxpub=<imas auth keygen's box key> \
  --set accountStore.endpoint=<host:port of the S3 store> \
  --set farmer.image.repository=<registry>/imas-farmer --set saasapi.image.repository=<registry>/imas-saasapi \
  --set database.migrate.image.repository=<registry>/imas-migrate
```

Then copy the public NATS trust the bootstrap Job wrote into the nats
chart's namespace ([NATS trust](#nats-trust)):

```sh
kubectl -n imas-core get configmap imas-nats-trust -o json \
  | jq '{apiVersion, kind, data, metadata: {name: .metadata.name}}' \
  | kubectl -n imas-dmz apply -f -
```

With the bus in `bus.tls.mode=openbao` (its certificate from this chart's
OpenBao PKI), copy the bus CA ConfigMap as well, public data only: from
this release's `natsTrust.busCAConfigMapName` to the nats release's
`loader.caConfigMap` (both default `imas-bus-ca`; see
[NATS trust](#nats-trust)).

Then, because the eval install has no ESO, deliver Valkey's password by
hand: the bootstrap Job generated it into OpenBao (see [Valkey](#valkey)).
Valkey, farmer and saasapi wait for this Secret:

```sh
kubectl -n imas-core create secret generic imas-valkey-auth \
  --from-file=password=<(kubectl -n imas-core exec imas-core-openbao-0 -- env BAO_TOKEN=root bao kv get -field=valkey_password secret/platform/imas/nats-seeds)
```

And saasapi's credential. The publish Job has already written the JWT to
OpenBao:

```sh
kubectl -n imas-core exec imas-core-openbao-0 -- env BAO_TOKEN=root bao kv get -field=jwt secret/platform/imas/saasapi-nats-user > jwt
kubectl -n imas-core create secret generic imas-saasapi-nats \
  --from-file=nats-user.nk=<(kubectl -n imas-core get secret imas-farmer-nats-seeds -o jsonpath='{.data.saasapi-user\.nk}' | base64 -d) \
  --from-file=SAASAPI_NATS_USER_JWT=jwt
```

That JWT expires after `credentialPublisher.userJWTTTL` (24h). The refresh
CronJob writes a new one to OpenBao at its first run after only a third of
that is left (with the defaults, between 16 and 20 hours after the first
one was minted). Without ESO, copy it again after that run has written the
new JWT and before the old one expires: once the remaining third of
`userJWTTTL` begins, wait at most `credentialPublisher.refresh.everyHours`
(the same two commands, with
`kubectl create secret ... --dry-run=client -o yaml | kubectl apply -f -`),
then restart saasapi (`kubectl -n imas-core rollout restart deployment
imas-core-farmer-saasapi`). A copy made before the refresh run only copies
the old JWT again.

And saasapi's control-plane box key (J.4, [Control-plane box keys](#control-plane-box-keys)):
its private key and the platform public key, both written by the keygen
Job. Only these two fields, and never `.../platform`:

```sh
kubectl -n imas-core create secret generic imas-saasapi-box \
  --from-file=saasapi-box.key=<(kubectl -n imas-core exec imas-core-openbao-0 -- env BAO_TOKEN=root bao kv get -field=priv secret/imas/tenant-x25519/saasapi-box) \
  --from-file=SAASAPI_PLATFORM_BOX_PUB=<(kubectl -n imas-core exec imas-core-openbao-0 -- env BAO_TOKEN=root bao kv get -field=platform_pub secret/imas/tenant-x25519/controlplane-pub)
```

No object store is bundled (the optional [Versity Gateway](#versity-gateway)
is an S3 front for Azure Blob, not a store of its own), and the accounts
bucket is required: the bus keeps no Account across a restart, its loaders
read every Account from that bucket, so farmer refuses to start without it
and the chart refuses to render without `accountStore.bucket` and an
endpoint (`accountStore.endpoint`, `objectStore.endpoint`, or the gateway
with `versity.enabled`). `ci/default-values.yaml` carries a placeholder
endpoint; set the real one.

What to expect on first install:

- PXC takes a few minutes to come up. The migrate Job is a post-install
  hook that waits for it, so `helm install` doesn't return until PXC is up
  and both schemas are migrated: give it a `--timeout` of at least
  `database.migrate.activeDeadlineSeconds` (Helm's default, 5m, is too
  short). Until then farmer and saasapi wait for their schema.
- The OpenBao bootstrap, control-plane keygen and publish Jobs are hooks
  too. Helm waits for them, so `helm install` needs the seed Secret in
  place, or it times out. farmer waits (`ContainerCreating`) until the
  bootstrap Job has written the trust ConfigMap, then checks it against
  Transit at start.
- Valkey, farmer and saasapi wait (`ContainerCreating`) until
  `imas-valkey-auth` exists; the bootstrap Job writes the password it is
  made from.
- saasapi's pods wait (`ContainerCreating`, or `CreateContainerConfigError`
  in their events) until both `imas-saasapi-nats` and `imas-saasapi-box`
  exist. That is expected: they don't crash-loop, and they start once the
  Secrets appear. Don't pass `--wait` on a first install: Helm would wait
  for saasapi before running the hooks that produce its credentials.
  NOTES prints a WARNING naming both Secrets whenever External Secrets
  doesn't sync them (`externalSecrets.enabled` or
  `externalSecrets.saasapi.enabled` false), so this is visible at install
  time and not only in pod events.
- **Dev-mode OpenBao is in memory.** If its pod restarts, the keys, the
  eval CA, the policies and the roles are gone. `helm upgrade` re-runs the
  bootstrap, but it mints a *new* gateway key and a new CA, and the NATS
  platform keys it would create no longer match the trust ConfigMap: the
  bootstrap refuses to replace a trust anchor (`ErrTrustWouldChange`).
  Delete the `imas-nats-trust` ConfigMap (and its DMZ copy) and every
  tenant's provisioning to start over. The bootstrap rewrites the bus CA
  ConfigMap (`imas-bus-ca`) with the new CA; copy it to the DMZ again.

### Production (everything external)

`ci/external-values.yaml` is the worked example. It sets:

- `openbao.enabled=false` and `openbaoClient.addr`/`caConfigMap`;
- `pxc.enabled=false`, `database.host` and `database.existingSecret` (both
  full DSNs). The migrate Job runs at pre-install; see
  [Migrations](#migrations) for who creates the users and grants;
- `valkey.enabled=false` and `valkey.addrs`, with `valkey.tls.enabled`
  and `valkey.tls.caConfigMap` (see [Valkey](#valkey));
- `tls.mode=secret` (e.g. cert-manager);
- `externalSecrets.enabled=true`.

The OpenBao policies and roles are then the ops repo's job. See
[OpenBao](#openbao). That includes the control-plane keygen Job's role
and policy (`imas-controlplane-box-keygen`), which must exist before
install now that the Job is on by default, and read access for the ESO
SecretStore to `<base>/saasapi-box` and `<base>/controlplane-pub` (see
[Control-plane box keys](#control-plane-box-keys)).

## Reaching the bus

Since yogzblr/imas#18, farmer keeps its bind address and its bus address
apart (`internal/config`):

| farmer setting | The chart sets it to | What it does |
|---|---|---|
| `farmerinterface` | `0.0.0.0` | The API's bind address, and nothing else |
| `farmerbusurl` | `tls://<bus.serviceName>.<bus.namespace>.svc.<clusterDomain>:<bus.port>`, or `tls://<bus.host>:<bus.port>` when `bus.host` is set | Where farmer dials the bus: its tenant connections, its SYS connection and its resolver pushes |
| `farmerbustlsservername` | `bus.tlsServerName`, when set | The name farmer verifies the bus certificate against. Unset (the default), it is the host of `farmerbusurl`, the bus Service FQDN or `bus.host` (`config.BusTLSServerName()`). |

saasapi dials the same URL (`SAASAPI_NATS_URL`) and verifies the same
host. The nats chart's default bus SANs cover the Service FQDN. In its
`bus.tls.mode=secret`, or if you set `bus.tlsServerName`, make sure the bus
certificate carries the name farmer verifies.

### A bus outside this cluster (`bus.host`)

When the bus runs in another cluster (the UAT core hub reaches the DMZ
bus at the private name `dmz.uat.imas.internal`, on node port 8442), set
`bus.host` to the bare DNS name to dial and `bus.port` to the port it
answers on. Both URLs become `tls://<bus.host>:<bus.port>`, and
`bus.serviceName` and `bus.namespace` are no longer required.

- `bus.host` is a DNS name only: not a URL (`tls://...`), not
  `host:port`, and not an IP address (IPv4 or IPv6; the bus certificate
  carries `bus.host` as a DNS SAN, and the addresses belong in
  `bus.egressCIDRs`). The chart refuses anything else.
- **The bus certificate must carry `bus.host` as a SAN.** saasapi always
  verifies the name it dials; farmer does too unless `bus.tlsServerName`
  names another, which the certificate must then carry as well. The nats
  chart's default SANs are the in-cluster Service names, so add `bus.host`
  to the DMZ's bus certificate (NOTES prints the name).
- **NetworkPolicy:** the bus egress rule of farmer and saasapi selects the
  nats chart's bus pods by namespace and pod labels, which can't match a
  bus outside this cluster. List the addresses `bus.host` resolves to in
  `bus.egressCIDRs`: the rule then has an `ipBlock` peer per entry, on
  `bus.port`, and no selector. **Without `bus.egressCIDRs` the egress rule
  does not match a bus outside the cluster**, and with
  `networkPolicy.enabled` farmer and saasapi can't reach it (NOTES warns).
  Without `bus.host`, `bus.egressCIDRs` entries are added next to the
  selector.
- **`bus.egressCIDRs` is kept in step with the bus name by hand.**
  NetworkPolicy matches addresses, not DNS names, and the chart doesn't
  resolve `bus.host`. When the addresses behind `bus.host` change, update
  `bus.egressCIDRs` (and upgrade the release) yourself. The owner accepted
  this for UAT (2026-10-06).
- `openbaoBootstrap.farmerbus.enabled` with `bus.host` needs an explicit
  `openbaoBootstrap.farmerbus.allowedNames` (including `bus.host`): the
  default names are the in-cluster bus Service's.

There is no sidecar and no `hostAliases`. Before #18, this chart pinned
the bus name to `0.0.0.0` and ran a loopback TCP relay to work around
`farmerinterface` doing all three jobs; that workaround is gone.

This was checked against the real `farmerbus` with farmer's own config and
bus code (see [Verification status](#verification-status)).
`TestContractWithNatsChart` keeps the URL, the verified name, the SANs,
the trust ConfigMap and the NetworkPolicy selectors in step with
`deploy/helm/nats`.

## Seeds

Since P21 slice 1 only **user-kind** seeds remain. The operator,
operator-signing, SYS account and tenant keys are OpenBao Transit keys
([NATS trust](#nats-trust)); no seed of theirs exists, and none is read.

farmer mounts the two `natsSeeds.seeds` from the Secret, each as an
`IMAS_NATS_<NAME>_SEED_FILE`. It never uses the raw `_SEED` form, and it
projects only the listed keys. This is
`deploy/farmer/farmer-deployment-nats-seeds.patch.yaml`, driven from
values. Both are required:

- `SYS_USER`: farmer's user in the SYS account, for its resolver
  connection to the bus. farmer refuses to start without it and never
  generates one.
- `SAASAPI_USER`: the SaaS API's user key, whose JWT farmer mints. The
  publish Job mounts only this one.

farmer's own NKey, the user every farmer bus connection authenticates as,
is a third user seed in a Secret of its own (`farmer.nkeySecret`, default
`imas-farmer-nkey`, key `farmer.nk`). Every replica mounts it read-only at
`farmer.nkeySecret.mountPath` and reads it from
`IMAS_FARMER_NKEY_SEED_FILE`, so all replicas are the same NATS user.
farmer refuses to start without it and never generates one; the render
fails without `secretName` and `key`, and refuses the seed Secret's or
saasapi's credential Secret's name. No other pod mounts it.

The old seeds (`OPERATOR`, `OPERATOR_SIGNING`, `SYS_ACCOUNT`, `TENANT`,
`TENANT_SIGNING`) are refused at render time. Delete them from the Secret
and from OpenBao KV: nothing reads them, and a private key nobody uses is
still a private key to lose (design D6: no migration, the old seeds just
stop being read).

`externalSecrets.enabled` renders `deploy/farmer/externalsecrets.yaml`:
each seed's property is its name in lowercase, `sys_user` and
`saasapi_user`. It also renders `farmer.nkeySecret.secretName` from the
same seed path, property `farmer_nkey`, `valkey.auth.secretName` from
property `valkey_password` (see [Valkey](#valkey)), and `imas-saasapi-nats`:
saasapi's seed from the seed path, and the published JWT from
`credentialPublisher.kvPath`.

## NATS trust

FLAG FOR SECURITY REVIEW. The NATS trust chain (P21 slice 1,
`docs/briefs/P21-slice1-transit-signer.md`) lives in OpenBao Transit:

| Transit key | NKey | Signs | Who may sign with it |
|---|---|---|---|
| `nats-operator` | operator identity | the operator JWT | the bootstrap Job's handoff token only |
| `nats-operator-signing` | operator signing key | account JWTs | farmer |
| `nats-sys-account` | SYS account | SYS users (farmer's, the SaaS API's, the bus fence user) | farmer, the publish Job |
| `nats-tsign-<tenant>` | tenant signing key | the tenant's user JWTs | farmer |
| `nats-tacct-<tenant>` | tenant account identity | nothing | nobody |

Every key is `ed25519`, `exportable=false`, `allow_plaintext_backup=false`;
farmer refuses one that isn't.

**The bootstrap Job** (`openbaoBootstrap`) creates the three platform keys
and the public trust on every install and upgrade, idempotently:

1. `prepare` (`bao`, root token) configures OpenBao, writes the
   policies, and mints one orphan, non-renewable 10-minute token with the
   ephemeral policy `imas-nats-bootstrap` into a memory-backed volume.
2. `nats-trust` (`farmer bootstrap-nats-trust`, farmer's image) creates the
   keys, mints the operator JWT, the SYS account JWT and, with
   `natsTrust.busFenceUserPub`, the bus fence user JWT, and writes them
   with the three public keys to the ConfigMap `natsTrust.configMapName`
   (default `imas-nats-trust`). It never replaces an existing anchor, and
   revokes its token before it exits. When the Job sets up OpenBao PKI
   (`tls.mode=openbao` or `openbaoBootstrap.farmerbus.enabled`) it also
   writes the bus CA ConfigMap `natsTrust.busCAConfigMapName` (default
   `imas-bus-ca`): key `ca.crt`, the PEM of `<tls.openbao.pkiMount>/cert/ca`,
   which is the `issuing_ca` of every certificate the bus role issues (a
   root or an intermediate issuer alike). It creates it when absent and
   updates it when the PEM changed. `cert/ca` is unauthenticated, so the
   handoff token's policy has no PKI grant. Its ServiceAccount
   (`<release>-farmer-openbao-bootstrap`, `templates/nats-trust-rbac.yaml`)
   may create ConfigMaps and get, update and patch only the trust one and,
   with PKI, the bus CA one; its token is mounted in this container alone.
3. `bootstrap` (`bao`) writes the roles, revokes the handoff token by
   accessor, deletes `imas-nats-bootstrap`, and last revokes its own token
   ([OpenBao bootstrap token](#openbao-bootstrap-token)).

**The trust ConfigMap** holds public data only (`operator.jwt`,
`operator.pub`, `operator-signing.pub`, `sys-account.pub`,
`sys-account.jwt`, `bus-fence-user.jwt`). farmer and the publish Job mount
it at `/var/run/imas/nats-trust` (`IMAS_NATS_TRUST_DIR`). **The nats chart's
bus needs a copy in its namespace**, made by hand or by your pipeline
(owner decision 2026-10-11 (c)); see the command under
[Eval install](#eval-install-everything-bundled) and
`deploy/helm/nats/README.md`, "NATS trust". Copy it again after adding a
fence user. `natsTrust.kvCopy.enabled` also copies it to OpenBao KV v2 at
`secret/data/platform/imas/nats-trust`, for a pipeline to read.

**The bus CA ConfigMap** holds public data only (`ca.crt`). A bus in
`bus.tls.mode=openbao` needs a copy in its namespace, made the same way
(by hand or by your pipeline), under the nats chart's
`loader.caConfigMap`: its loader verifies its node with it and never
mounts the bus's TLS volume (unit S1). The copy reads the source name from
this release and writes the destination name from the nats release; see
`deploy/helm/nats/README.md`, "The bus CA". Copy it again after a CA
rotation (`docs/OPENBAO-RUNBOOK.md`, section 6.6).

**A clustered bus** needs a fence user: generate a user seed for the nats
chart (`BUS_FENCE_USER`), set its public key here as
`natsTrust.busFenceUserPub`, upgrade, and copy the trust again.

### OpenBao bootstrap token

`openbaoBootstrap.tokenSecretName` names a Secret with a root token
generated from the recovery quorum. With `openbaoBootstrap.revokeToken`
(default) the Job revokes it when done, so no standing admin remains
(owner decision 2026-10-11 (a)). Then:

- **Delete the Secret** after the run. The reference is optional: without
  it, every later upgrade's Job configures nothing, and only checks that
  the trust ConfigMap is complete. A Secret still holding the revoked
  token fails the Job with a message saying so.
- **A policy or role change** (an upgrade that changes one of the files
  in `files/openbao-policies` or a role) needs a fresh root token from the
  recovery quorum in that Secret for the upgrade's Job.

Dev mode (`openbao.server.dev.enabled`) never revokes the dev root token.

### Erasing an offboarded tenant's data

FLAG FOR SECURITY REVIEW (S6). Offboarding a tenant (`DELETE
/v1/tenants/{tenant_id}`) locks it out at once: farmer's
`DeprovisionTenant` closes its bus connections, pushes a locked-out
Account JWT and soft-deletes its two Transit keys. Its data is erased
later, by a purge:

- **When.** saasapi's outbox sweeper starts a purge for a tenant that has
  been offboarded for `saasapi.tenantPurge.after` (`SAASAPI_TENANT_PURGE_AFTER`,
  default `720h`, 30 days; `1h` to `8760h`), unless
  `saasapi.tenantPurge.enabled` is `false`. `GET
  /v1/tenants/{tenant_id}/status` shows when (`purge_after`). An operator
  can purge sooner on the operator plane (`saasapi.operator.enabled`):

  ```sh
  curl --cacert ca.crt -H "Authorization: Bearer $OPERATOR_TOKEN" \
    -X POST https://<release>-saasapi-operator.<ns>.svc:8443/v1/operator/tenants/<tenant_id>/purge
  ```

  202 with the job ID; 409 `not_offboarded` or `purge_in_progress`; 404
  for an unknown tenant. Poll the tenant's status for the outcome.
- **What is erased.** Farmer, on the sealed `internal.tenant.purge`
  subject, in this order: the tenant's Valkey keys (heartbeats and
  acceptance markers); its rows in every farmer table with a `tenant_id`
  (props, sprout NKeys and revocations, box keys, sprout JWT index, users
  and CLI box keys, roles, user roles, cohorts, job status); its objects
  (`tenants/<id>/` in the recipe bucket, recipes and recipe audit;
  `sprouts/<id>/`, staged recipes; `jobs/<id>/` in the job bucket;
  `<id>/` in the sprout JWT bucket); its payload-encryption keypair in
  OpenBao KV (`<kvPath>/tenants/<id>` under `farmer.openbao.tenantBox`,
  every version and the metadata, by one delete on its metadata); and
  last its Transit keys, destroyed (`deletion_allowed`, then delete; see
  the policy notes above). Then saasapi deletes the tenant's enrollment keys, asset links,
  action batches and items and update policy. Every step deletes by
  `tenant_id` equality or the exact tenant prefix, in batches; a step that
  fails stops the run, the tenant stays offboarded with `last_error` in
  its status, and the sweeper tries again at most once a day (an operator
  can at once). Re-running finishes a partial run. Farmer writes one
  audit entry per run (`internal.tenant.purge`: tenant ID, job ID,
  trigger, counts per category; never names, keys or content).
- **What stays (the tombstone).** saasapi's `tenants` row (status
  `purged`, name and plan cleared) and the tenant's `provisioning_jobs`
  rows; farmer's `pki_tenants` row (deleted, its name replaced by the
  ID); the tenant's Account JWT in the accounts bucket, re-signed locked
  out from nothing but its public key and the ID; and the
  `pushall:<id>` and `purge:<id>` rows of `farmer.job_leases`. They keep
  the ID from being reused and the tenant locked out on every replica and
  on a bus node started empty. A purged tenant accepts no new data:
  every tenant route but `GET` answers 404 or 409 for it.
- **Grants.** farmer's object store user has delete on the sprout JWT
  bucket (Versity plan, UAT RustFS policy); farmer's tenantbox policy
  has `delete` on `<kvPath>/tenants/+` metadata, nothing else there;
  farmer's Transit policy allows the key destruction above. A purge
  cannot be undone: an OpenBao snapshot taken before it is the only way
  back for the keys
  ([`docs/OPENBAO-RUNBOOK.md`](../../../docs/OPENBAO-RUNBOOK.md) §5.3).

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
- It mounts only `saasapi-user.nk`, and the trust ConfigMap. It signs
  through Transit as `imas-natssign-publisher` (SYS account key only).
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
(`docs/design/imas-payload-encryption-design.md`) made the keys; J.4
(rollout step 5) uses them: farmer opens and seals every `internal.*`
message with them, and saasapi refuses to start without its half. The
keygen Job is on by default (`controlPlaneBoxKeys.enabled`).

The SaaS API and farmer seal `internal.*` to each other with NaCl box:
the SaaS API with its own **SaaS API box key**, farmer with the
**platform key**, one per deployment. Both live in **OpenBao KV v2**, not
in a Kubernetes Secret this chart renders, under farmer's tenant box base
path (`farmer.openbao.tenantBox.kvMount`/`kvPath`, `<base>`):

| Secret | Fields | Who reads it |
|---|---|---|
| `<base>/platform` | `pub`, `priv`, `origin` | farmer only (`imas-farmer-tenantbox`, read only) |
| `<base>/saasapi-box` | `pub`, `priv` | the SaaS API only, through its Secret `saasapi.controlPlaneBox.secretName` (below). No farmer policy reaches it. |
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

**saasapi's half (J.4).** saasapi gets exactly two things, from one
Secret (`saasapi.controlPlaneBox.secretName`, default `imas-saasapi-box`)
that only its pods mount:

| Secret key | From | In saasapi |
|---|---|---|
| `saasapi-box.key` (`privKey`) | `<base>/saasapi-box`, field `priv` | a file, `/var/run/secrets/imas/saasapi-box/saasapi-box.key`, read-only, mode `0440` (owner root, group the pod's `fsGroup`, nothing for others), mounted by the saasapi container only (not its init container); `SAASAPI_BOX_PRIV_FILE` names it |
| `SAASAPI_PLATFORM_BOX_PUB` (`platformPubKey`) | `<base>/controlplane-pub`, field `platform_pub` | the env var of that name (a public key) |

With `externalSecrets.enabled`, an ExternalSecret renders it from exactly
those two fields, through the same SecretStore as saasapi's NATS
credential, so `farmer.openbao.tenantBox.kvMount` must be that store's
mount (`credentialPublisher.kvMount`; the render fails otherwise). The
store's OpenBao role needs read on both paths and nothing under
`<base>/platform`. Without ESO, create it by hand (eval: see
[Eval install](#eval-install-everything-bundled)).

What the chart guarantees, and `saasapibox_test.go` checks across the
default, eval, production, token-auth, ESO and fleet-dispatch renders:

- **farmer never gets the SaaS API's private key**: no pod but saasapi's
  references its Secret, no farmer policy reaches `<base>/saasapi-box`,
  and no farmer role binds the keygen policy. The render fails if
  `saasapi.controlPlaneBox.secretName` names a Secret anything else
  mounts (the seeds, saasapi's NATS credential, the DB Secret, the BFF
  secret, `tls.secretName`).
- **saasapi never gets the platform private key**: it has no OpenBao
  client that reaches `<base>/platform` (no tenantbox or keygen identity,
  no role on its ServiceAccount binding those policies), and no
  ExternalSecret reads `<base>/platform`.

**Order on a fresh install.** The keygen Job is a `post-install,
post-upgrade` hook (weight 5: after the OpenBao bootstrap, which writes
its role, and before the credential publisher), so the keys can't exist
before the release's resources do. saasapi's Deployment is created at
install, and its pods can't start until `imas-saasapi-box` exists: the
volume and the `SAASAPI_PLATFORM_BOX_PUB` reference aren't optional, so
the kubelet holds the pod rather than starting saasapi without keys. ESO
creates the Secret once both remote fields exist, at its next refresh
(`externalSecrets.saasapi.refreshInterval`, 1m); by hand, once you create
it. This is the same wait saasapi already has for `imas-saasapi-nats`,
whose JWT another post-install hook writes. The alternatives were worse:
an init container that polls OpenBao would give saasapi an OpenBao
identity it otherwise doesn't need, and the keygen Job can't be a
pre-install hook, because the bundled OpenBao and its bootstrap only
exist after install. If the Secret exists but is wrong, saasapi exits at
startup (fail closed) and Kubernetes restarts it.

**Turning it off.** `cmd/farmer` dispatches `ensure-controlplane-box-keys`
before loading any config, so you can also run it yourself (same image,
same `IMAS_CPBOX_OPENBAO_*` identity) and set
`controlPlaneBoxKeys.enabled=false`. Without the keys farmer refuses every
`internal.*` request (`no-keys`) and saasapi never starts; NOTES warns.
With an external OpenBao the Job's role and policy must exist before
install, or the hook fails the release.

## OpenBao

Each OpenBao client runs under its own role and gets exactly one policy.

| Client | Env prefix | Kubernetes auth role (value) | Policy |
|---|---|---|---|
| farmer, API certificate (`tls.mode=openbao`) | `IMAS_CERTS_OPENBAO_*` | `imas-farmer-certs` (`tls.openbao.k8sRole`) | `imas-farmer-certs`: `pki/issue/imas-farmer` |
| farmer, gateway JWT signer | `IMAS_GATEWAY_OPENBAO_*` | `imas-farmer-gateway` | `imas-farmer-gateway`: sign and read on `transit/*/imas-gateway-jwt` only |
| farmer, NATS signer (P21 slice 1) | `IMAS_NATSSIGN_OPENBAO_*` | `imas-farmer-natssign` (`farmer.openbao.natsSign.k8sRole`) | `imas-farmer-natssign` (file): read the three platform keys, sign with `nats-operator-signing` and `nats-sys-account`, never `nats-operator`; create and read keys on `transit/keys/+` (one path segment, so never `rotate`), soft-delete on `transit/keys/+/soft-delete` except the platform and gateway keys, destroy (config `deletion_allowed="true"` only, then delete) one-segment keys except the platform and gateway keys (the purge, S6), sign with `nats-tsign-*` only |
| farmer, tenant box keypairs | `IMAS_TENANTBOX_OPENBAO_*` | `imas-farmer-tenantbox` | `imas-farmer-tenantbox`: KV v2 read/write on `secret/data/imas/tenant-x25519/tenants/+` (one secret per tenant), delete only on `secret/metadata/imas/tenant-x25519/tenants/+` (a tenant purge, S6), and read only on `.../platform` and `.../controlplane-pub` (J.1), nothing else |
| the publish Job | `IMAS_SAASAPI_CRED_OPENBAO_*` | `imas-saasapi-cred-publisher` | `imas-saasapi-cred-publisher` (reviewed copy) |
| the publish Job, NATS signer | `IMAS_NATSSIGN_OPENBAO_*` | `imas-natssign-publisher` (`credentialPublisher.natsSign.k8sRole`) | `imas-nats-sys-signer` (file): read the three platform keys, sign with `nats-sys-account` only |
| the bootstrap Job's `nats-trust` | `IMAS_NATSBOOT_OPENBAO_*` | none: a 10-minute handoff token | `imas-nats-bootstrap` (file, ephemeral): create and read the three platform keys (exact paths), sign with all three, revoke itself; deleted by the Job |
| the control-plane keygen Job (`controlPlaneBoxKeys.enabled`, on by default since J.4) | `IMAS_CPBOX_OPENBAO_*` | `imas-controlplane-box-keygen` | `imas-controlplane-box-keygen`: create and read on `.../platform` and `.../saasapi-box`, create, read and update on `.../controlplane-pub` |

- **Shared connection settings.** `openbaoClient.addr`, `caConfigMap` and
  `authMethod` are shared by all clients. In `authMethod=token`, each
  client reads its own key from `openbaoClient.tokenSecretName`. The
  publisher can use its own Secret (`credentialPublisher.tokenSecretName`),
  and should.
- **Bootstrap (bundled OpenBao only).** `openbaoBootstrap` is a hook Job
  that does all of the following, idempotently:
  - enables Transit, KV v2, PKI (when `tls.mode=openbao`) and Kubernetes
    auth;
  - creates the `imas-gateway-jwt` Transit key;
  - writes every file in `files/openbao-policies` plus the farmer policies;
  - creates the NATS platform keys and the trust ConfigMap
    ([NATS trust](#nats-trust));
  - creates the roles above.

  Each role gets `token_no_default_policy=true`, and the publisher's TTLs
  are 5m. The bootstrap never writes NATS seeds. With `valkey.auth.enabled`
  it generates Valkey's password, property `valkey_password` of the seed
  path, only when absent and with check-and-set (see [Valkey](#valkey)).
- **The tenant-key policy shape** (FLAG FOR SECURITY REVIEW). Creating a
  Transit key needs `update` on `transit/keys/<name>`, and `update` on a
  `transit/keys/nats-tsign-*` glob also reaches `<name>/rotate` and
  `<name>/config`. On OpenBao 2.7.1 no deny can take those back: a rule
  whose first wildcard comes later in the path always outranks one whose
  wildcard comes earlier, and a `*` in the middle of a path is a literal
  (`openbao_policy_test.go` shows rotate, config and a hard delete going
  through). So `imas-farmer-natssign` uses `transit/keys/+`, which matches
  one path segment and nothing below it. The cost: farmer can create keys
  of any name on the `transit` mount (it can sign with none outside
  `nats-tsign-*`), and could soft-delete or destroy a key another client
  later adds to that mount; give such a key exact denies in the policy, or
  its own mount.
- **The purge's Transit grants** (S6, FLAG FOR SECURITY REVIEW). Farmer
  destroys an offboarded tenant's two keys when it purges the tenant's
  data ([Erasing an offboarded tenant's data](#erasing-an-offboarded-tenants-data)):
  `POST transit/keys/<name>/config` with `deletion_allowed` set, then
  `DELETE transit/keys/<name>`. So `transit/keys/+` also has `delete`, and
  `transit/keys/+/config` has `update` with `allowed_parameters`
  `deletion_allowed = ["true"]`: the one parameter, and the one value,
  OpenBao accepts there from a farmer token. A config call that sets
  anything else (exportable, plaintext backup, auto-rotation, minimum
  versions), or `deletion_allowed` as a JSON boolean, is refused 403
  (checked against OpenBao 2.7.1 by `TestOpenBaoFarmerPolicy`). Exact
  rules keep the platform keys read only and the gateway key at create and
  read, and exact denies refuse config on all four.
- **Accepted: farmer can soft-delete or destroy another client's Transit
  key** (owner decision 2, #215, widened by S6's purge; goes to the
  security review, P3). What a farmer token may do on the `transit`
  mount, per key name, as OpenBao's ACL answers it
  (`TestOpenBaoFarmerPolicyKeySet` asserts exactly this table, through
  `sys/capabilities-self`, and fails if the policy changes it):

  | Key | create | read | sign | soft-delete | config (`deletion_allowed` only) | hard delete |
  |---|---|---|---|---|---|---|
  | `nats-operator` | no | yes | no | no (exact deny) | no (exact deny) | no |
  | `nats-operator-signing`, `nats-sys-account` | no | yes | yes | no (exact deny) | no (exact deny) | no |
  | `imas-gateway-jwt` | yes (an existing key is left unchanged) | yes | no | no (exact deny) | no (exact deny) | no |
  | `nats-tsign-<tenant>` | yes | yes | yes | yes | yes | yes |
  | `nats-tacct-<tenant>` | yes | yes | no | yes | yes | yes |
  | any other name | yes | yes | no | **yes** | **yes** | **yes** |

  For every name it is refused rotate, trim, export, backup, restore and
  soft-delete-restore. So a key another client keeps on this mount
  without exact denies here can be soft-deleted by farmer, and then signs
  nothing for that client until someone with a token other than farmer's
  restores it (`soft-delete-restore`), or destroyed for good (a snapshot
  restore is the only way back). The test does both to a key it creates.
  Keep other clients' keys off this mount, or add exact
  `transit/keys/<name>/soft-delete` and `transit/keys/<name>/config`
  denies for each to `imas-farmer-natssign.hcl` and a row to the test.
- **The NATS policies are files, checked against a real OpenBao.**
  `openbao_policy_test.go` runs them in
  `.github/workflows/natskeys-openbao-realserver.yml`: the bootstrap
  policy creates and signs with the platform keys and can't rotate or
  reconfigure them; farmer's creates, signs with, soft-deletes and
  destroys tenant keys and is refused rotate, any other config and
  restore, and its whole per-key-name capability set is pinned (table
  above); the publish
  Job's signs with the SYS key only. They name the `transit` mount, so
  `farmer.openbao.natsSign.transitMount` other than `transit` is refused.
- **Sharing a CA with the nats chart.** With
  `openbaoBootstrap.farmerbus.enabled`, it also creates the nats chart's
  `imas-farmerbus` PKI role and a Kubernetes auth role bound to the bus's
  ServiceAccount, so both charts share one eval CA.
- **The reviewed policy travels verbatim.**
  `imas-saasapi-cred-publisher.hcl`'s statements are
  `deploy/farmer/README.md`'s `hcl` block. `TestPoliciesMatchReference`
  fails on drift.
- **Values that would leave a policy behind are refused.** The bootstrap
  fails the render if you move the publisher's KV path away from what its
  policy names. Change the policy, and its review, together with the
  values.
- **No fleet signing key.** Sprout release trust is the release's
  GPG-signed `checksums.txt`, which only the sprout verifies, against the
  keyring in its package (`/etc/imas/fleet-signing-keys.asc`;
  `docs/design/imas-openbao-signing-design.md` D9, D20). Neither farmer
  nor saasapi holds an OpenBao role for it.
- **External OpenBao.** Create the same roles and policies in the ops repo.
  Then run the checks from `deploy/farmer/README.md`
  (`bao token capabilities ...`). They must print `deny` where that README
  says so.
- **Namespaces (optional, unset by default).** Each client also reads
  `<prefix>NAMESPACE`: `IMAS_CERTS_OPENBAO_NAMESPACE`,
  `IMAS_GATEWAY_OPENBAO_NAMESPACE`, `IMAS_TENANTBOX_OPENBAO_NAMESPACE` and
  `IMAS_SAASAPI_CRED_OPENBAO_NAMESPACE`. When one is set, that client sends
  it as `X-Vault-Namespace` on every request, logins included; when it is
  unset, no namespace header is sent. The chart sets none of them. To use
  a namespace, add the variables to `farmer.extraEnv` (farmer's three
  clients). saasapi has no OpenBao client. The publish Job has no `extraEnv`, so the chart can't set
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
there (`docs/design/imas-machine-manager-api-design.md` §4.1a).

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
`min_sprout_version`, for each OS/arch/package type the package file name
and SHA-256, and the release's GPG-signed `checksums.txt` with its detached
signature (`checksums_txt`, `checksums_sig`, base64). The stamp script
verifies that signature against the release keyring before writing. A `post-install`/`post-upgrade` hook Job,
`farmer register-sprout-release` (`internal/sproutrelease`) in farmer's own
image, registers it with saasapi's operator plane (`POST /v1/operator/fleet-releases`, API design §2.5,
`docs/api/saasapi-operator-openapi.yaml`). saasapi checks that
`checksums.txt` is well-formed and lists every package with its hash, and
stores the rows with `checksums.txt` and its signature as given; it signs
nothing and does not verify the signature. Only then can tenants approve
and roll it out, and each sprout verifies `checksums.txt` against the
keyring in its package (`/etc/imas/fleet-signing-keys.asc`) before it
installs anything (`docs/design/imas-openbao-signing-design.md` D9, D20).
There is no CI call.

```
helm upgrade ──▶ hook Job ──operator token, https──▶ saasapi operator plane ──▶ saas.fleet_versions
           (farmer register-     <release>-saasapi-operator:8443
            sprout-release)
```

**When it runs.** The Job renders only when all of these hold; otherwise
NOTES says which one is missing and nothing is registered:

- the chart has `files/sprout-release.json` (a chart from a source
  checkout doesn't, so a dev install skips the hook);
- `sproutRelease.register` (default on);
- `saasapi.enabled` and `saasapi.operator.enabled` (default off: the
  operator plane needs its TLS and token Secrets).

**What it sends.** The stamped release verbatim, plus
`sproutRelease.channel` (default `stable`).

- **`min_sprout_version` is set at release time**, not per install: the
  stamp script reads it from `packaging/helm/min-sprout-version` (one
  version line, `#` comments), so the floor is reviewed in a PR and ships
  under the tag with everything else (`docs/RELEASING.md`,
  "Compatibility"). It is the oldest sprout that may update straight to
  this release, and immutable once the version
  is registered. The script refuses a floor that isn't canonical semver or
  is above the tag by semver precedence (so `v1.0.0` can't be the floor of
  `v1.0.0-rc.1`).
- The render fails if the file's version isn't the canonical
  `v`+`appVersion` (the farmer chart and the sprout release ship under one
  tag), if `min_sprout_version` is missing, not canonical or above the
  version, if `checksums_txt` or `checksums_sig` is missing, or if the
  file has fields beyond `version`, `min_sprout_version`, `packages`,
  `checksums_txt` and `checksums_sig`. Setting the removed
  `sproutRelease.minSproutVersion` value fails the render rather than being
  ignored. Nothing is rewritten to pass: saasapi refuses non-canonical
  values, and so does the chart.

**Outcome.**

| saasapi answers | The Job | The release |
|---|---|---|
| 201: registered | succeeds | succeeds |
| 200: already registered with the same contents (every later `helm upgrade`) | succeeds | succeeds |
| 409 `release_conflict`: this version is registered with different contents (or another `min_sprout_version`) | prints saasapi's message and the request it sent; fails at once (exit 2, `podFailurePolicy` `FailJob`) | **fails** |
| 409 `version_revoked`, any other 4xx or a 3xx (400, 401, 422 `invalid_checksums` or `checksums_mismatch`; redirects are never followed), a certificate that doesn't verify, a local configuration error (bad token or request file) | prints why; fails at once | **fails** |
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
| `saasapi.operator.token.secretName` / `currentKey` / `previousKey` | `SAASAPI_OPERATOR_TOKEN_FILE` / `_PREVIOUS_FILE` | A Secret of its own: the render fails if it is the BFF's, the NATS credential's, the seeds' or the TLS Secret. At least 32 characters, no whitespace. `previousKey` only during a rotation. |

The operator plane makes no outbound call and needs no OpenBao role.
saasapi's operator port admits the hook Job's pods, plus
`networkPolicy.saasapiOperatorIngress.from` (empty by default), and nothing
else.

Generate the token with at least 32 random bytes, e.g.
`openssl rand -base64 48 | tr -d '\n='`, and keep it in OpenBao/ESO like the
BFF secret. Whoever holds it can register any well-formed release whose
`checksums.txt` they supply, and offer it to tenants for approval; a sprout
installs only what verifies against its packaged keyring
(`docs/design/imas-openbao-signing-design.md` D20).

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

**The limit is checked, not just documented (FIX.3, FIX.5).** With
`saasapi.recipes.enabled` the chart sets `SAASAPI_RECIPES_CREDENTIAL_CHECK`
(`saasapi.recipes.credentialCheck`, default `true`; saasapi's own default
is on too, so only an explicit `false` turns it off), and at startup saasapi
asks the object store, with its own credential, to do what that credential
must not be able to do. In the recipe bucket (`objectStore.bucket`):

- create an object at the bucket root (outside `tenants/`);
- create an object under `sprouts/` (farmer's staged recipes);
- read a key under `sprouts/`;
- list `sprouts/`;
- create an object under the platform recipe prefix (farmer's `recipedir`,
  default `/srv/imas/recipes/prod/`, the key prefix
  `srv/imas/recipes/prod/` in the bucket);
- delete a key under the platform recipe prefix.

In farmer's job bucket (`objectStore.jobBucket`), where the credential must
have no access at all:

- create an object under `jobs/`;
- read a key under `jobs/`;
- delete a key under `jobs/`;
- list `jobs/`;
- list the bucket root.

Every probe runs before saasapi decides. If the store allows any of them,
saasapi logs which and exits instead of serving: farmer's key, a
bucket-wide key or an admin key never runs as the recipe credential. Only
`AccessDenied` counts as denied, so a store that can't be reached within
about 30 seconds, a rejected key or a missing bucket also stops it (the pod
restarts and tries again). Writes are create-only at random keys under
`imas-saasapi-credential-check/`, never overwriting anything, and an object
a wrongly allowed probe created is deleted again before saasapi exits (or
named in the error if it can't be). Deletes are of fresh random keys that
nothing wrote, so a wrongly allowed one removes nothing; a versioned bucket
gets a delete marker at that key.

**The check needs the job bucket.** While `saasapi.recipes.enabled` and
`saasapi.recipes.credentialCheck` are both on, the chart refuses to render
without `objectStore.jobBucket`, and passes it to saasapi as
`SAASAPI_RECIPES_JOB_BUCKET`. The saasapi binary refuses to start without
`SAASAPI_RECIPES_JOB_BUCKET` while the check is on, so it never runs a
check that can't see the job bucket. The job bucket must differ from the
recipe bucket. The platform recipe prefix comes from
`SAASAPI_RECIPES_PLATFORM_RECIPE_DIR`, whose default
`/srv/imas/recipes/prod` is farmer's default `recipedir`. The chart doesn't
change farmer's `recipedir` and doesn't set this variable. If you run
farmer with a different `recipedir`, set
`SAASAPI_RECIPES_PLATFORM_RECIPE_DIR` to the same path through
`saasapi.extraEnv`. Why a self-check rather than a Job that
creates the MinIO policy and user: it works for any S3 store (MinIO, AWS,
others) and checks the credential saasapi actually runs with, whoever made
it, and it needs no MinIO client image (`mc` is AGPL-3.0) and no MinIO admin
credential in the cluster. What it doesn't prove: the whole policy. One
known gap: AWS answers a read of a missing key with `AccessDenied` to a
caller without `s3:ListBucket`, so a credential that may read `sprouts/*`
(or job bucket keys) but not list that bucket at all passes the read probe
(the list probes still fail a bucket-wide key). `saasapi.recipes.credentialCheck=false` turns it
off, and NOTES warns; do that only for a store whose answers the check
can't classify, after limiting the credential some other way.

`internal/saasapi`'s `TestRecipeObjectStorePolicy` checks this file against
the keys the code writes. saasapi gets the access key id as an env var and
the secret key only as a file. It validates uploads under
`farmer.recipes.templateLimits`, which it receives as the same
`IMAS_RECIPE_*` variables farmer gets, so a recipe that uploads is a recipe
farmer will render. That one set of limits for both is an owner decision
(2026-10-04): there is no separate saasapi value to override it. saasapi also
gets `maxIncludes` (`IMAS_RECIPE_MAX_INCLUDES`) and refuses an upload whose own
`include` list is longer; it does not get the per-cook budget (`cook*`), since
it never cooks. Reading needs `saasapi.recipes.readRole` or `writeRole`
(Keycloak realm roles, or client roles of `saasapi.jwt.audience`), and
writing needs `writeRole`. With `saasapi.recipes.enabled`, saasapi's
NetworkPolicy opens egress on `objectStore.endpoint`'s port (443 or 80 by
`useSSL` when it has none) to `networkPolicy.external.objectStore` (empty:
any destination, on that port only). That rule is separate from
`saasapiExtraEgress`, so narrowing that to your Keycloak doesn't break
uploads.

### Per-cook render budget

A cook renders the recipe it names and every recipe it includes, each twice:
once to find the includes and once to build the steps. Every render is
bounded by the per-render limits above, and the cook as a whole by a budget
of its own (security review B4, S4), shared by every render of both phases:

| Value | Default | Bounds |
|---|---|---|
| `cookRenderTimeout` (`IMAS_RECIPE_COOK_RENDER_TIMEOUT`) | `"10s"` | at least `renderTimeout`, at most `5m` |
| `cookMaxRenderedBytes` (`IMAS_RECIPE_COOK_MAX_RENDERED_BYTES`) | `8388608` (8 MiB) | at least `maxRenderedBytes`, at most 256 MiB |
| `cookMaxRangeIterations` (`IMAS_RECIPE_COOK_MAX_RANGE_ITERATIONS`) | `100000` | at least `maxRangeIterations`, at most 100000000 |
| `maxIncludes` (`IMAS_RECIPE_MAX_INCLUDES`) | `64` | 1 to 256 |

All four are under `farmer.recipes.templateLimits`, and farmer refuses to
start if one is out of range. A cook that runs out of its budget fails
before anything is staged or dispatched; farmer logs the counter that ran
out and its limit (`cook exceeded its render budget: total render time over
10s`). A cook including more than `maxIncludes` distinct recipes fails the
same way (`more than 64 recipes included`). saasapi gets only `maxIncludes`:
it refuses an upload whose own `include` list is longer, but it does not
resolve includes, because a recipe may include one uploaded later, so the
cook-time budget is the enforcement.

## Versity Gateway

The production object store is Azure Blob behind
[Versity Gateway](https://github.com/versity/versitygw) (design D18;
Apache-2.0, `DEPENDENCIES.md`). imas only speaks S3, so the gateway is an
optional component of this chart, **off by default** (`versity.enabled`):
any other S3 endpoint works too (see [A different S3 endpoint](#a-different-s3-endpoint)).

With `versity.enabled=true` the chart renders:

- **The gateway**, `<release>-farmer-versity`: a Deployment of
  `versity.replicas` (default 2) pods running `versitygw azure`, image
  pinned by digest (`versity.image.digest`; the render fails without one),
  non-root (65532), read-only root file system, no ServiceAccount token,
  spread over nodes (`kubernetes.io/hostname`, maxSkew 1, `ScheduleAnyway`,
  or `versity.topologySpreadConstraints`), a PodDisruptionBudget with more
  than one replica (`maxUnavailable: 1`). Readiness and liveness probes
  call the gateway's health endpoint, `GET /_/health` on the S3 port
  (`versity.healthPath`, `VGW_HEALTH`), which answers 200 with no
  credential. The gateway is stateless: the buckets, their objects and
  their bucket policies live in the storage account (policies as container
  metadata), and its users are a file each pod writes at start.
- **A Service**, `<release>-farmer-versity:7070` (`versity.port`), plain
  HTTP inside the cluster. It is the **default S3 endpoint**: with
  `objectStore.endpoint` and `accountStore.endpoint` left empty, farmer's
  `IMAS_S3_ENDPOINT` and `IMAS_ACCOUNTS_S3_ENDPOINT`, and saasapi's
  `SAASAPI_RECIPES_S3_ENDPOINT`, are this Service, with TLS off
  (`objectStore.useSSL` is then ignored). Every request is SigV4-signed, so
  no secret key crosses the wire; the leg to Azure is HTTPS. Set
  `accountStore.endpoint` to keep the accounts bucket elsewhere; setting
  `objectStore.endpoint` with the gateway on fails the render, since it
  would then serve nothing.
- **The users**, written into the gateway's internal IAM file
  (`users.json`, `VGW_IAM_DIR`) by an init container
  (`farmer versity-iam`, `internal/versitysetup`) from the Secrets below,
  into a memory-backed volume the gateway mounts read-only. Every replica
  has the same users and none writes shared state; a changed Secret takes
  effect when the pods restart (`reloader.stakater.com/auto` rolls them,
  as it rolls farmer and saasapi). Every user has role `user`: it owns no
  bucket and reaches only what a bucket policy grants it.
- **The buckets**: the `createBuckets` hook Job
  (`<release>-farmer-versity-buckets`, `farmer versity-buckets`,
  post-install and post-upgrade) creates `objectStore.bucket`,
  `.jobBucket`, `.sproutJWTBucket` and `accountStore.bucket` as Azure Blob
  containers with the gateway's root credential, then writes each bucket's
  policy from the plan in ConfigMap `<release>-farmer-versity-buckets` and
  reads it back. It mounts the root credential and the users' access key
  IDs only, never their secret keys, and retries while the gateway starts
  (`versity.createBuckets.timeout`). Every run replaces the policies, so a
  grant removed from the chart goes too. A bucket someone else owns fails
  it. Bucket names must be valid container names: 3 to 63 of `a-z`, `0-9`
  and `-`, no leading, trailing or double hyphen.
- **A NetworkPolicy**: in, on the S3 port, from farmer, saasapi (with
  `saasapi.recipes.enabled`), the createBuckets Job, the nats chart's bus
  pods in this cluster (`networkPolicy.dmz`; the account loader) and
  `versity.networkPolicy.extraIngressFrom`; out, Azure Blob on 443
  (`versity.networkPolicy.azureEgress`, default any destination on 443
  only) and DNS. farmer's and saasapi's object store rules point at the
  gateway's pods instead of `networkPolicy.external.objectStore`.

### Users and bucket policies

One user per component credential, scoped as in design D22 and the UAT's
RustFS policies (`uat/hub/core/rustfs-setup.sh`):

| User | Secret (`access-key-id`, `secret-access-key` by default) | Grants |
|---|---|---|
| `farmer` | `objectStore.credentialsSecret` | recipe and job buckets: list, get, put, delete; sprout JWT bucket: list, get, put, delete (the purge, S6) |
| `saasapi-recipes` (with `saasapi.recipes.enabled`) | `saasapi.recipes.credentialsSecret` | recipe bucket: `files/objectstore-policies/saasapi-recipes.json` (list under `tenants/*/recipes/*`, read and write there, put under `tenants/*/recipe-audit/*`) |
| `accounts-writer` | `accountStore.credentialsSecret` | accounts bucket: list, get, put (no delete) |
| `accounts-reader` | `versity.accountsReader.credentialsSecret` | accounts bucket: list, get. The DMZ bus's account loader |

No user reaches a bucket it is not listed for, and the sprout JWT bucket
is farmer's alone (it is in farmer's credential; there is no separate
sprout JWT user). saasapi's startup credential check
(`saasapi.recipes.credentialCheck`) passes against these policies and
fails with farmer's key.

### Setting it up for Azure Blob

1. Create a StorageV2 storage account (hierarchical namespace off). The
   gateway uses its account name and a shared key.
2. Create the Secrets in the release namespace. Values are exact bytes: no
   trailing newline (use `--from-literal` or `printf`, not `echo`). Access
   key IDs are 3 to 128 characters of `A-Z a-z 0-9 . _ ~ + = -`; secret
   keys 8 to 128 printable characters with no whitespace. Every access key
   ID must be its own, and none may be the root's; `versity-iam` refuses
   otherwise, and the render refuses one Secret used for two users.

   ```sh
   ns=imas-core
   kubectl -n $ns create secret generic imas-versity-azure \
     --from-literal=account-name=<storage account> --from-literal=account-key=<key>
   kubectl -n $ns create secret generic imas-versity-root \
     --from-literal=access-key-id=vgw-root --from-literal=secret-access-key="$(openssl rand -hex 24)"
   for s in imas-s3-farmer:farmer imas-farmer-accounts-writer:accounts-writer \
            imas-bus-accounts-reader:accounts-reader imas-s3-saasapi:saasapi-recipes; do
     kubectl -n $ns create secret generic "${s%%:*}" \
       --from-literal=access-key-id="imas-${s##*:}" --from-literal=secret-access-key="$(openssl rand -hex 24)"
   done
   ```

   | Secret value | Keys (value) | Holds |
   |---|---|---|
   | `versity.azure.credentialsSecret` | `account-name`, `account-key` (`versity.azure.accountNameKey`, `accountKeyKey`) | the storage account name and key; the gateway alone |
   | `versity.rootCredentials.secretName` | `access-key-id`, `secret-access-key` | the gateway's root; the gateway and the createBuckets Job alone |
   | the four user Secrets above | `access-key-id`, `secret-access-key` (each one's `accessKeyIdKey`, `secretAccessKeyKey`) | one component each |

3. Install with (`ci/versity-values.yaml` is the worked example):

   ```yaml
   versity:
     enabled: true
     azure: { credentialsSecret: imas-versity-azure }   # endpoint: for a sovereign cloud or private endpoint
     rootCredentials: { secretName: imas-versity-root }
     accountsReader: { credentialsSecret: imas-bus-accounts-reader }
   objectStore:          # endpoint left empty: the gateway
     bucket: imas-recipes
     jobBucket: imas-jobs
     sproutJWTBucket: imas-sprout-jwts
     credentialsSecret: imas-s3-farmer
   accountStore:         # endpoint left empty: the gateway
     bucket: imas-accounts
     credentialsSecret: imas-farmer-accounts-writer
   ```

   `helm install/upgrade --timeout` must cover
   `versity.createBuckets.activeDeadlineSeconds` (900 s by default).
4. Point the nats chart's account loader at the gateway: its
   `accountStore.endpoint` is `<release>-farmer-versity.<namespace>.svc.<domain>:7070`
   with `accountStore.useSSL=false`, its `accountStore.credentialsSecret`
   (in the DMZ namespace) holds the same pair as
   `versity.accountsReader.credentialsSecret`, and its
   `networkPolicy.accountStoreEgress` allows port 7070 to the address the
   loader's traffic has when NetworkPolicy sees it: for a ClusterIP Service
   that is the gateway pods' addresses (the pod CIDR), since the Service
   address is translated first. NOTES prints the endpoint values. A bus
   in another cluster needs the Service reachable from there
   (`versity.service.type`/`annotations`, e.g. an internal load balancer,
   whose address then goes in `accountStore.endpoint` and
   `accountStoreEgress`) and its nodes' addresses in
   `versity.networkPolicy.extraIngressFrom`.
5. Narrow `versity.networkPolicy.azureEgress` to the storage account's
   addresses (or its private endpoint's) as `ipBlock` peers.

### A different S3 endpoint

Leave `versity.enabled=false` and set `objectStore.endpoint` (and
`accountStore.endpoint` when the accounts bucket is elsewhere) to the
customer's S3 endpoint, with `objectStore.useSSL`. The chart then creates
no bucket and no user: create the four buckets and one credential per
component yourself, scoped as in the table above (the createBuckets plan
of a `versity.enabled` render, `helm template ... --show-only
templates/versity-buckets-job.yaml`, and `files/objectstore-policies/` are
the reference), and narrow farmer's and saasapi's object store egress with
`networkPolicy.external.objectStore`.

## Valkey

farmer (`IMAS_VALKEY_ADDRS`) and saasapi (`SAASAPI_VALKEY_ADDRS`) get the
same address list. That's required: saasapi reads the heartbeat keys farmer
writes, and enforces the enrollment-key rate limit across pods
(`deploy/saasapi/README.md`).

- **Bundled:** `<release>-valkey:6379`, standalone.
- **External:** `valkey.addrs`, the same key as
  `deploy/saasapi/values.rate-limit.yaml`, so that block merges as is.

Valkey holds security state: the replay cache (`internal/pki/replaycache.go`,
`sealedclaim.go`) that makes enrolment, refresh and sealed messages
single-use, and the heartbeat keys that say which sprouts are online. So
both clients authenticate, can use TLS, and the bundled Valkey never evicts
(unit S5).

### Password

- farmer and saasapi authenticate as ACL user `default` with the password
  in Secret `valkey.auth.secretName` (`imas-valkey-auth`), key
  `valkey.auth.key` (`password`). It is mounted, that key only, as the file
  `/var/run/secrets/imas/valkey/password` in farmer's and saasapi's pods
  (`IMAS_VALKEY_PASSWORD_FILE`, `SAASAPI_VALKEY_PASSWORD_FILE`). It is
  never an environment variable, a Helm value or a ConfigMap. Each process
  reads it once at startup, trailing newline trimmed; set but missing or
  empty, the process refuses to start.
- The password is property `valkey_password` of the seed path in OpenBao
  (`externalSecrets.seedMount`/`externalSecrets.seedPath`,
  `secret/platform/imas/nats-seeds`). The OpenBao bootstrap Job generates
  it, 32 random bytes in base64 without padding, when it is absent, and
  never overwrites it (a KV patch with check-and-set, so the seeds in the
  same path are untouched). With an external OpenBao (no bootstrap Job)
  ops writes it; see `docs/OPENBAO-RUNBOOK.md`. With
  `externalSecrets.enabled`, the ExternalSecret `imas-valkey-auth` syncs it
  into the Secret. Without ESO, create the Secret from the property, as in
  the eval install above.
- **Bundled Valkey:** the subchart's own authentication
  (`valkey.auth.enabled`, `usersExistingSecret`, `aclUsers.default`). Its
  init step reads the password from the same Secret, which the subchart
  mounts in that step only (at `/valkey-users-secret`), and writes its
  SHA-256 into the ACL file; the password is never in values or an
  environment variable. In the replicated mode (`valkey.replica.enabled`)
  every replica authenticates to the primary as `default` with the same
  password (`masteruser`/`masterauth`): the subchart writes `masterauth`
  into the replica's generated `valkey.conf` on its data volume. The
  chart refuses `aclUsers` other than `default` with `passwordKey`
  `valkey.auth.key`, inline passwords and `aclConfig` (which would put a
  password in values). The subchart's health probes (`valkey-cli ping`)
  stay as they are: a `NOAUTH` answer still proves the server is up.
- **Rotation** is a restart: write a new `valkey_password`, let ESO sync
  the Secret (or update it by hand), then restart Valkey, farmer and
  saasapi (`kubectl rollout restart`). Until all three have restarted,
  the ones still on the old password can't reach Valkey.
- **Upgrading from a release without a password:** the bootstrap Job
  (post-upgrade) writes `valkey_password`; with an external OpenBao write
  it first (`docs/OPENBAO-RUNBOOK.md` 5.6). Until ESO (or you) creates
  `imas-valkey-auth`, the new Valkey, farmer and saasapi pods wait in
  `ContainerCreating` while the old ones keep serving; once it exists the
  rollout completes with every client on the password.
- `valkey.auth.enabled=false` renders only with
  `valkey.auth.allowInsecure=true`, and NOTES warns. It is for a
  throwaway install only.

### TLS

- `valkey.tls.enabled=true` makes farmer and saasapi connect with TLS 1.2
  or later (`IMAS_VALKEY_TLS`, `SAASAPI_VALKEY_TLS`), verifying the server
  against the CA in ConfigMap `valkey.tls.caConfigMap` (key
  `valkey.tls.caKey`, default `ca.crt`; public data, mounted as a file at
  `/var/run/secrets/imas/valkey-ca/`, `*_VALKEY_TLS_CA_FILE`) and never the
  system roots, and against `valkey.tls.serverName` when set (default: the
  host dialled). A CA that isn't PEM, or TLS without one, stops the
  process. Certificates are never skipped.
- The production Valkey is external and is expected to serve TLS.
- The bundled Valkey supports TLS too (the subchart's `tls.*`): set
  `valkey.tls.existingSecret` to its server certificate Secret
  (`server.crt`, `server.key`, `ca.crt`); the chart refuses
  `valkey.enabled` with `valkey.tls.enabled` without it. It then serves
  TLS on the same port, 6379, so the NetworkPolicies don't change.

### No eviction

- The bundled Valkey runs with `maxmemory-policy noeviction`
  (`valkey.valkeyConfig`, the subchart's config hook): a write that would
  exceed `maxmemory` fails instead of evicting a key.
- Both clients read `INFO memory` after connecting. When `maxmemory` is
  above 0 and `maxmemory_policy` is not `noeviction` they log one warning
  that names the replay cache and the heartbeats as security state. Only
  a warning: a managed Valkey may not let the policy be changed. An `INFO`
  that fails is only logged too.

### Accepted residual: failover

Valkey replication is asynchronous, so a failover (or the loss of the
primary in the bundled replicated mode) can lose the most recent claims.
The impact is bounded to the 6-minute claim window and to the replay path:
no gateway JWT is issued without a separately claimed box-key proof
(`docs/security-review-pack.md`, item 3.5.3).

Restrict network access to Valkey all the same.

## Farmer is stateless

Farmer keeps no state on local disk, so it has no PVC and any number of
replicas can run (`farmer.replicaCount`, default 2). Everything it keeps is
in the shared services, and the replicas take turns through PXC row leases
(a conditional `UPDATE` of `lease_owner`/`lease_until`, never `GET_LOCK`,
which is local to one PXC node):

- **NATS signing keys**: OpenBao Transit keys; Account JWTs are signed when
  needed and never stored.
- **Sprout User JWTs**: in the private bucket `objectStore.sproutJWTBucket`
  (`IMAS_S3_SPROUT_JWT_BUCKET`), under `<tenant>/<sprout>/<sha256>.jwt`,
  indexed by `farmer.sprout_user_jwt` on `(tenant_id, sprout_id)`. That row's
  lease makes one replica mint a sprout's JWT and the others reuse it.
  Without the bucket every enrolment fails (NOTES warns).
- **SaaS API credential rotation state**: `saas.saasapi_credential_state`.
- **Account JWTs for the bus**: every Account JWT farmer pushes is first
  written to the accounts bucket (`accountStore`, `accounts/<account>.jwt`
  plus `accounts/index`), then pushed to every bus node, then announced on
  `imas.bus.accounts.changed`; each bus node's account loader reads the
  bucket, so a bus node started empty loads every Account from it. One
  replica at a time per account, under the `account:<pub>` row of
  `farmer.job_leases`; a newer object is never replaced by an older JWT.
  Required: farmer exits at start with `accounts bucket: no accounts
  bucket` (or no endpoint, or no write credential) when it is not
  configured, rather than pushing to the bus alone and losing every
  Account at the next bus node restart; the chart refuses to render
  without it. See [Account publisher log fields](#account-publisher-log-fields).
- **Hourly jobs** (job expiry, the cohort refresher, the account push per
  tenant): one replica at a time under a `farmer.job_leases` row
  (`farmer.jobs.leaseTTL`, `IMAS_JOB_LEASE_TTL`, default 120s).
- **Job logs**: the job bucket. **Audit**: JSON lines on stdout, whatever
  `farmer.logFormat` says, shipped by the node's log agent (see
  [What the audit log never contains](#what-the-audit-log-never-contains)).
- **Per-tenant bus connections**: opened on first use on each replica,
  reconnecting without limit. One is closed once it has been unused for
  `farmer.tenantConnections.idleTTL` (10m) and its tenant has had no sprout
  heartbeat for `farmer.tenantConnections.heartbeatWindow` (15m), so a tenant
  with online sprouts stays subscribed on every replica.

The pod's root filesystem is read-only. Its only writable volumes are the
`tmp` emptyDir (the process's temp directory) and the TLS directory.
Farmer writes no JWT or key file: the Account JWTs it signs are held in
memory and kept in the accounts bucket, which every replica reads, sprout
User JWTs are in the sprout JWT bucket, and its own User JWTs are signed
on first use and held in memory. Nothing a farmer process writes is read
by a later one, so a replica can be killed at any time and loses
nothing. farmer's NKey is not written either: every replica reads the
same seed from the read-only `farmer.nkeySecret` mount ([Seeds](#seeds)).

Farmer and saasapi roll one pod at a time (`RollingUpdate`,
`maxUnavailable: 0`, `maxSurge: 1`), and a PodDisruptionBudget (`farmer.pdb`, `minAvailable: 1`,
rendered only with more than one replica) keeps one up through a drain. With
no `farmer.affinity` set, a preferred pod anti-affinity on
`kubernetes.io/hostname` puts the replicas on different nodes;
`farmer.topologySpreadConstraints` adds zone spread where you want it.

Rate limits that are kept per replica (saasapi's rate limiter, the update
manifest limiter) allow N times the configured rate with N replicas.

### What the audit log never contains

Every audit line goes through one function (`audit.Logger.Log`), which
redacts before it writes, so no caller can skip it. An ordinary write
method's params are logged with secrets masked as `[REDACTED]`; a
free-form method's params are logged only as their size, SHA-256 and the
top-level key names its handler reads (any other key name is left out). The log (stdout, then the log platform, 30 days)
never contains:

- the params of `cmd.run`, `cook`, `props.set`, `shell.open`,
  `auth.users.add`, `auth.users.resetkey` or `auth.rotatekey`: no command
  text, recipe, property value, shell request or public key;
- the value of any key, at any depth, whose name contains `pass`,
  `password`, `passwd`, `passphrase`, `secret`, `token`, `apikey`/`api_key`/`api-key`,
  `private`, `seed`, `credential`, `authorization`, `bearer`, `cookie`,
  `otp`, `sdb` or `key_material`, in any case;
- in any string param, target or the error text: a JWT, a PEM private
  key block, an NATS seed, an AWS access key ID (`AKIA...`), a bearer
  credential, a `Basic` credential (base64 of `user:pass`), URL userinfo (`://user:pass@`), or the value of a
  `name=value` or `name: value` pair, or of a `--name value` command
  option, whose name contains one of the words above;
- params that are not JSON or are over 1 MiB (only their size and SHA-256);
- anything typed or printed in a shell session.

### Account publisher log fields

The account publisher has no metrics (there is no metrics system in this
phase). It logs two fields that the log platform alerts on; farmer logs
JSON to stdout (`farmer.logFormat`, default `json`) and Fluent Bit ships it
(design D16). Each field is a `name=value` token in the log record's `msg`:

| Field | Level | Logged when | Alert on |
|---|---|---|---|
| `farmer_account_push_missing_nodes=N` | warn (error if no node took it) | N bus nodes did not answer a push of an Account JWT after the retries. Not a failure of the call: the bucket has the JWT and those nodes' loaders apply it. | Any record, repeated: a bus node or its loader is not keeping up. |
| `farmer_account_bucket_write_failed=N` | error | N writes to the accounts bucket failed: an Account JWT on an API call (N=1; the call reports the failure, and an ordinary update is not pushed, a lock-out or revocation is pushed anyway), or the reconcile at start and in every push-all (N accounts plus the index). The next reconcile retries. | Any record: a bus node that restarts now loads an older Account. |

For example, with Fluent Bit's `grep` filter, `Regex msg farmer_account_bucket_write_failed=`.

## NetworkPolicy

| Pods | Direction | Peer | Port |
|---|---|---|---|
| farmer | in | the nats chart's Envoy (`networkPolicy.dmz.*`) | `farmer.apiPort` (5405) |
| farmer | out | the nats chart's bus pods, plus `bus.egressCIDRs` (with `bus.host`, only `bus.egressCIDRs`; see [A bus outside this cluster](#a-bus-outside-this-cluster-bushost)) | `bus.port` (5406), at `farmerbusurl` |
| farmer, saasapi | out | PXC / Valkey | 3306 / 6379 |
| farmer | out | OpenBao | 8200 |
| farmer | out | with `objectStore.endpoint` set: the object store (`networkPolicy.external.objectStore`, default any destination); with `versity.enabled`: the Versity Gateway's pods | `objectStore.endpoint`'s port, or `versity.port` |
| farmer | out | the accounts bucket, when `accountStore.endpoint` is its own on another port than `objectStore.endpoint`, or there is no `objectStore.endpoint` (same peers) | `accountStore.endpoint`'s port |
| saasapi | out | OpenBao, only for the bus CA fetch | 8200 |
| saasapi | in | `networkPolicy.saasapiIngress.from` (default: anyone) | `saasapi.port` (8081) |
| saasapi | in | with `saasapi.operator`: the sprout release hook Job's pods, plus `networkPolicy.saasapiOperatorIngress.from` (default: none) | `saasapi.operator.port` (8443) |
| saasapi | out | the bus pods, plus `bus.egressCIDRs` (as farmer) | `bus.port` |
| saasapi | out | with `saasapi.recipes`: the object store (`networkPolicy.external.objectStore`, default any destination), or the Versity Gateway's pods | `objectStore.endpoint`'s port, or `versity.port` |
| saasapi | out | `saasapiExtraEgress`, default HTTPS anywhere (the Keycloak JWKS). **Narrow it.** | 443 |
| publish Job | out | OpenBao, DNS; nothing else, no ingress | 8200, 53 |
| migrate Jobs | out | PXC, DNS; nothing else, no ingress | 3306, 53 |
| sprout release hook Job | out | saasapi's pods on the operator port, DNS; nothing else, no ingress | 8443, 53 |
| openbao-bootstrap | out | OpenBao, DNS | 8200, 53 |
| Versity Gateway (`versity.enabled`) | in | farmer, saasapi (with `saasapi.recipes`), the createBuckets Job, the nats chart's bus pods (`networkPolicy.dmz`), `versity.networkPolicy.extraIngressFrom` | `versity.port` (7070) |
| Versity Gateway | out | Azure Blob (`versity.networkPolicy.azureEgress`, default any destination), DNS | 443, 53 |
| createBuckets Job | out | the gateway's pods, DNS; nothing else, no ingress (rendered whatever `networkPolicy.enabled` says) | 7070, 53 |
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
- **Object storage:** farmer's own rule (recipes, staged recipes, job
  logs), rendered whenever `objectStore.endpoint` is set, and saasapi's
  (recipe upload) are separate rules on the endpoint's port, both narrowed
  by `networkPolicy.external.objectStore`. Before FIX.3 farmer's needed a
  hand-written `networkPolicy.farmerExtraEgress` rule, so a default install
  couldn't serve a recipe or store a job log; `farmerExtraEgress` is now
  only for anything else farmer must reach.
- **saasapi after J.4 and REC.1** (OPS.1, 2026-10). Every connection
  saasapi makes or receives, and what the policy does about it:
  - *in:* the BFF on `saasapi.port`; with the operator plane, the release
    hook Job (and `saasapiOperatorIngress.from`) on its port. Nothing else:
    farmer never dials saasapi.
  - *out:* the bus (NATS, `bus.port`), PXC, Valkey, DNS, Keycloak's JWKS
    (`saasapiExtraEgress`) and the object store with `saasapi.recipes`.
    OpenBao only for the bus CA fetch.
  - *farmer, over sealed `internal.*` (J.4):* no new path. The sealed
    requests and replies are NATS messages on saasapi's existing bus
    connection; saasapi never connects to farmer's pods or API port, and
    the chart tests check that.
  - *the box key:* no new path. It is a Kubernetes Secret that External
    Secrets syncs from OpenBao; ESO talks to OpenBao, saasapi doesn't, so
    holding the key adds no OpenBao egress.
  - *the object store (REC.1):* a new path, now its own rule (above).
    Before it, a MinIO on 9000, or a `saasapiExtraEgress` narrowed to
    Keycloak, silently blocked uploads.
  - *PDB:* unchanged. saasapi is stateless across replicas (the box key is
    the same Secret in each pod, the outbox uses leases), so
    `maxUnavailable: 1` at the default two replicas keeps one serving
    through a drain, and one replica gets no PDB, which would otherwise
    block every drain.
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
| `bus.serviceName` / `bus.namespace` | `""` / `imas-dmz` | The nats chart's bus client Service. Required unless `bus.host` is set. |
| `bus.host` | `""` | A bare DNS name for a bus outside this cluster (e.g. `dmz.uat.imas.internal`). Set: `farmerbusurl` and `SAASAPI_NATS_URL` are `tls://<bus.host>:<bus.port>`, and the bus certificate must carry it as a SAN. Not a URL, `host:port` or IP address. See [A bus outside this cluster](#a-bus-outside-this-cluster-bushost). |
| `bus.port` | `5406` | Bus client port, in `farmerbusurl` and `SAASAPI_NATS_URL` (with `bus.host`, the port it answers on, e.g. a node port). |
| `bus.egressCIDRs` | `[]` | CIDRs rendered as `ipBlock` peers of farmer's and saasapi's bus egress rule, on `bus.port`. With `bus.host` they replace the bus pod selector; **without them the rule does not match a bus outside the cluster**. Kept in step with what `bus.host` resolves to by hand. |
| `bus.sproutBusURLs` | `[]` | `IMAS_SPROUT_BUS_URLS`, Envoy's external `wss://` addresses. Required. |
| `bus.ca.secretName` / `configMapName` / `key` | `""` / `""` / `ca.crt` | saasapi's bus CA. Empty: `tls.secretName`'s `ca.crt`, or fetched from OpenBao PKI in openbao mode. |
| `bus.tlsServerName` | `""` | `farmerbustlsservername`. Empty: the bus Service FQDN, or `bus.host`. See [Reaching the bus](#reaching-the-bus). |
| `bus.expectedNodes` | `0` | `IMAS_BUS_EXPECTED_NODES`: how many bus nodes a claims push waits for (the nats chart's `bus.replicaCount`). 0: the nodes that answer a server ping. A node still missing is logged; its loader applies the JWT from the accounts bucket. |
| `natsSeeds.secretName` | `imas-farmer-nats-seeds` | The seed Secret. Required. |
| `natsSeeds.seeds` | `SYS_USER`, `SAASAPI_USER` | `NAME: key` pairs. Both are required; the removed trust chain seeds are refused. |
| `natsSeeds.extraSeeds` | `{}` | More user-kind seeds. |
| `farmer.nkeySecret.secretName` / `key` / `mountPath` | `imas-farmer-nkey` / `farmer.nk` / `/var/run/secrets/imas/farmer-nkey` | farmer's NKey seed, shared by every replica (`IMAS_FARMER_NKEY_SEED_FILE`). Required; a Secret of its own. With ESO: property `farmer_nkey` of `externalSecrets.seedPath`. See [Seeds](#seeds). |
| `natsTrust.configMapName` | `imas-nats-trust` | The trust ConfigMap the bootstrap writes and farmer and the publish Job mount. |
| `natsTrust.busCAConfigMapName` | `imas-bus-ca` | The bus CA ConfigMap (`ca.crt`, from `<tls.openbao.pkiMount>/cert/ca`) the bootstrap writes when it sets up OpenBao PKI; copied to the nats chart's `loader.caConfigMap`. Must differ from `configMapName`. |
| `natsTrust.busFenceUserPub` | `""` | The nats chart's fence user public key (`U...`); set, the bootstrap mints `bus-fence-user.jwt`. |
| `natsTrust.busLoaderUserPub` | `""` | The nats chart's account loader user public key (`U...`, the public half of its `loader.sysUserSecret` seed); set, the bootstrap mints `bus-loader-user.jwt`, which every bus pod's loader needs. Must differ from `busFenceUserPub`. |
| `natsTrust.kvCopy.enabled` | `false` | Also copy the trust to `secret/data/platform/imas/nats-trust`. |
| `farmer.openbao.natsSign.*` | role `imas-farmer-natssign`, `transit`, `15s`, `64`, `4` | farmer's NATS signer: `k8sRole`, `tokenSecretKey`, `transitMount` (must be `transit`), `timeout`, `batchMax`, `workers` (`IMAS_NATSSIGN_*`). `retiredTenantKeyRetentionDays` was removed (S6) and fails the render: the purge's delay is `saasapi.tenantPurge.after`. |
| `credentialPublisher.natsSign.*` | role `imas-natssign-publisher` | The publish Job's NATS signer role and token key. |
| `openbaoBootstrap.revokeToken` | `true` | Revoke the bootstrap token when done (never in dev mode). |
| `networkPolicy.external.kubeApi` | `cidrs: []`, `ports: [443, 6443]` | The bootstrap Job's egress to the Kubernetes API. |
| `tls.mode` | `openbao` | `secret` (`tls.secretName`) or `openbao` (`tls.openbao.*`). |
| `tls.certHosts` | `[]` | openbao mode SANs. Empty: the farmer Service's names. |
| `openbaoClient.addr` | `""` | Empty with `openbao.enabled`: this release's OpenBao. Required otherwise. |
| `openbaoClient.caConfigMap` / `caKey` | `""` / `ca.crt` | OpenBao's CA (`*_OPENBAO_CACERT`). |
| `openbaoClient.authMethod` | `kubernetes` | Or `token`, which uses `tokenSecretName` with per-client keys. |
| `openbaoClient.k8sMount` / `k8sAudience` | `kubernetes` / `openbao` | Kubernetes auth mount, and the projected token's audience. |
| `openbaoTools.image` | `quay.io/openbao/openbao:2.7.1` | The bao CLI, for the bootstrap Job and the CA fetch. |
| `database.host` / `port` / `params` | `""` / `3306` / `parseTime=true&charset=utf8mb4&loc=UTC` | PXC. Empty host with `pxc.enabled`: its HAProxy Service. |
| `database.farmer.*` / `database.saasapi.*` | `farmer`/`farmer_svc`, `saas`/`saas_svc` | Schemas and users. |
| `database.existingSecret` | `""` | Both DSNs (`existingSecretKeys`). Required without `pxc.enabled`. |
| `database.migrate.image.*` | `ghcr.io/yogzblr/imas-migrate`, tag `appVersion` | `cmd/migrate`. Keep it at farmer's and saasapi's version. |
| `database.migrate.rootPasswordSecret` / `rootPasswordKey` / `rootUser` | `""` / `root` / `root` | PXC root, for the root step. Empty: the operator's Secret with `pxc.enabled`, `--skip-root` otherwise. |
| `database.migrate.wait` / `backoffLimit` / `activeDeadlineSeconds` | `15m` / `2` / `1800` | How long to wait for PXC; the Job's retry and time budget. |
| `database.migrate.argoCDHooks` | `true` | Argo CD hook annotations. See [Migrations](#migrations). |
| `valkey.enabled` / `valkey.addrs` | `true` / `[]` | The bundled Valkey, or an external one's `host:port` list (`IMAS_VALKEY_ADDRS`, `SAASAPI_VALKEY_ADDRS`). See [Valkey](#valkey). |
| `valkey.auth.enabled` / `allowInsecure` | `true` / `false` | Valkey's password (`*_VALKEY_PASSWORD_FILE`). `false` renders only with `allowInsecure` (a throwaway install). |
| `valkey.auth.secretName` / `key` | `imas-valkey-auth` / `password` | The Secret (ESO: property `valkey_password` of `externalSecrets.seedPath`) mounted as `/var/run/secrets/imas/valkey/password`. The bundled Valkey reads it too (`usersExistingSecret`, `aclUsers.default.passwordKey`, which must stay as they are). |
| `valkey.tls.enabled` / `caConfigMap` / `caKey` / `serverName` | `false` / `""` / `ca.crt` / `""` | TLS from farmer and saasapi (`*_VALKEY_TLS`, `*_VALKEY_TLS_CA_FILE`, `*_VALKEY_TLS_SERVER_NAME`): the CA ConfigMap is required. |
| `valkey.tls.existingSecret` | `""` | The bundled Valkey's server certificate Secret; required with `valkey.enabled` and `valkey.tls.enabled`. |
| `valkey.valkeyConfig` | `maxmemory-policy noeviction` | The bundled Valkey's extra config. Keep `noeviction`. |
| `externalSecrets.seedPath` / `seedMount` | `platform/imas/nats-seeds` / `secret` | The ops seed path and its KV v2 mount; the bootstrap Job writes `valkey_password` there. |
| `objectStore.*` | empty | `IMAS_S3_*`. `jobBucket` must differ from `bucket`. |
| `accountStore.bucket` / `endpoint` / `useSSL` | `imas-accounts` / `""` / `null` | `IMAS_ACCOUNTS_S3_*`: the accounts bucket the bus loaders read (see [Farmer is stateless](#farmer-is-stateless)). Required: the chart fails to render without `bucket` and an endpoint (`endpoint`, else `objectStore.endpoint`), and farmer refuses to start without them. `endpoint` and `useSSL` default to `objectStore`'s. Must differ from every `objectStore` bucket. |
| `accountStore.credentialsSecret` / `accessKeyIdKey` / `secretAccessKeyKey` | `imas-farmer-accounts-writer` / `access-key-id` / `secret-access-key` | farmer's own write credential for the accounts bucket (get, put, list; no delete). Required. Must not be `objectStore.credentialsSecret`. |
| `accountStore.eventSubject` | `imas.bus.accounts.changed` | `IMAS_ACCOUNTS_EVENT_SUBJECT`; the nats chart's `accountStore.eventSubject`. |
| `objectStore.sproutJWTBucket` | `""` | `IMAS_S3_SPROUT_JWT_BUCKET`: the private bucket of sprout User JWTs. Must differ from `bucket` and `jobBucket`. Empty: every enrolment fails, and NOTES says so. |
| `farmer.image.*` | `ghcr.io/yogzblr/imas-farmer` | Also the publish Job's image. |
| `farmer.replicaCount` | `2` | At least 1. See [Farmer is stateless](#farmer-is-stateless). |
| `farmer.logLevel` / `apiPort` / `gatewayJWTTTL` | `info` / `5405` / `24h` | `loglevel`, `farmerapiport`, `gatewayjwtttl`. |
| `farmer.logFormat` / `saasapi.logFormat` | `json` / `json` | `IMAS_LOG_FORMAT`: `json` or `text`. |
| `farmer.pdb.enabled` / `minAvailable` | `true` / `1` | farmer's PodDisruptionBudget; only with `replicaCount` > 1. |
| `farmer.affinity` / `topologySpreadConstraints` | `{}` / `[]` | Empty affinity: preferred anti-affinity on `kubernetes.io/hostname` over farmer's pods. |
| `farmer.bootstrapAdmin.pubkey` | `""` | The first imas CLI admin's NKey public key (`imas auth pubkey`), rendered as `users.admin`. Required, with `boxpub`, unless `skip`: see [Bootstrap admin](#bootstrap-admin). |
| `farmer.bootstrapAdmin.boxpub` | `""` | Required with `pubkey`: the CLI box public key the admin's `imas auth keygen` printed. Farmer imports it once at start; the database is authoritative after that (J.3). |
| `farmer.bootstrapAdmin.username` | `""` | Optional name for listings and audit entries. |
| `farmer.bootstrapAdmin.skip` | `false` | `true` renders no admin and lifts the requirement. Only when farmer's database already holds an admin; not with `pubkey`, `boxpub` or `username`. NOTES says so. |
| `farmer.adminPubKeys` | `[]` | Removed in J.3: rendering fails if set. An admin with no CLI box key can't make a request; use `farmer.bootstrapAdmin`. |
| `farmer.jobs.reconcileWindow` | `"2h"` | `IMAS_JOB_RECONCILE_WINDOW` (`deploy/farmer/values.job-reconcile.yaml`). |
| `farmer.jobs.leaseTTL` | `""` | `IMAS_JOB_LEASE_TTL`: lease TTL of the hourly jobs, a quoted Go duration. Empty: farmer's 120s. |
| `farmer.tenantConnections.idleTTL` / `heartbeatWindow` | `"10m"` / `"15m"` | `IMAS_TENANT_CONN_IDLE_TTL` / `IMAS_TENANT_CONN_HEARTBEAT_WINDOW`: a tenant bus connection is closed once unused this long and with no sprout heartbeat in the window. Quoted Go durations. |
| `farmer.recipes.templateLimits.maxSourceBytes` | `262144` | `IMAS_RECIPE_MAX_SOURCE_BYTES`: largest recipe source farmer reads or renders. |
| `farmer.recipes.templateLimits.maxRenderedBytes` | `1048576` | `IMAS_RECIPE_MAX_RENDERED_BYTES`: largest output of one recipe render. |
| `farmer.recipes.templateLimits.maxValueBytes` | `262144` | `IMAS_RECIPE_MAX_VALUE_BYTES`: largest string one template function returns; at most `maxRenderedBytes`. |
| `farmer.recipes.templateLimits.renderTimeout` | `"2s"` | `IMAS_RECIPE_RENDER_TIMEOUT`: time limit of one recipe render, a quoted Go duration up to `1m`. |
| `farmer.recipes.templateLimits.maxRangeIterations` | `10000` | `IMAS_RECIPE_MAX_RANGE_ITERATIONS`: total `range` iterations in one render. Recipes are tenant-written (untrusted); all nine `templateLimits` are required, and farmer refuses to start if one is out of range (sizes up to 64 MiB, iterations up to 10000000). |
| `farmer.recipes.templateLimits.cookRenderTimeout` | `"10s"` | `IMAS_RECIPE_COOK_RENDER_TIMEOUT`: total render time of one cook, a quoted Go duration from `renderTimeout` up to `5m`. See [Per-cook render budget](#per-cook-render-budget). |
| `farmer.recipes.templateLimits.cookMaxRenderedBytes` | `8388608` | `IMAS_RECIPE_COOK_MAX_RENDERED_BYTES`: total rendered output of one cook, from `maxRenderedBytes` up to 268435456 (256 MiB). |
| `farmer.recipes.templateLimits.cookMaxRangeIterations` | `100000` | `IMAS_RECIPE_COOK_MAX_RANGE_ITERATIONS`: total `range` iterations of one cook, from `maxRangeIterations` up to 100000000. |
| `farmer.recipes.templateLimits.maxIncludes` | `64` | `IMAS_RECIPE_MAX_INCLUDES`: distinct recipes one cook may include (the recipe it names is not counted), 1 to 256. saasapi gets it too and refuses an upload whose own include list is longer. |
| `farmer.selfUpdate.enabled` | `false` | `IMAS_SELF_UPDATE_ENABLED`: farmer's own switch for `self_update` (security review L1). Off, farmer refuses every update whatever saasapi sends. A rollout needs this and `saasapi.fleetUpdateDispatch.enabled`. |
| `farmer.sproutActions.{concurrency,selfUpdateConcurrency,tenantConcurrency}` | `256`, `16`, `32` | `IMAS_SPROUT_ACTION_CONCURRENCY`, `IMAS_SELF_UPDATE_CONCURRENCY`, `IMAS_SPROUT_ACTION_TENANT_CONCURRENCY`: per replica, the cmd.run/cook pool, the pool reserved for `self_update`, and one tenant's cap in each (security review M5). A request that doesn't fit is refused at once (`farmer_busy`) and saasapi sends it again. Null emits no env var. |
| `farmer.openbao.{gateway,tenantBox}.*` | see values.yaml | Mount, key or path, role, and token key per client. |
| `farmer.extraConfig` | `{}` | Extra `/etc/imas/farmer` keys. Chart-managed keys win. |
| `farmer.extraEnv` | `[]` | Extra env vars for farmer, e.g. the optional `*_OPENBAO_NAMESPACE` (see [OpenBao](#openbao)) or `HTTPS_PROXY`/`NO_PROXY`. Never a raw `IMAS_NATS_*_SEED` or any `IMAS_SAASAPI_CRED_OPENBAO_*`. |
| `saasapi.enabled` / `replicaCount` / `port` | `true` / `2` / `8081` | |
| `saasapi.jwt.*` | `""` | Keycloak JWKS URL, issuer and audience. Required. |
| `saasapi.internalAuthSecret.*` | `imas-saasapi-internal-auth` | `INTERNAL_AUTH_SECRET_CURRENT`/`_PREVIOUS`. |
| `saasapi.natsCredentials.*` | `imas-saasapi-nats` | The seed (as a file) and the JWT. |
| `saasapi.controlPlaneBox.{secretName,privKey,platformPubKey}` | `imas-saasapi-box`, `saasapi-box.key`, `SAASAPI_PLATFORM_BOX_PUB` | saasapi's box private key (a read-only file, `SAASAPI_BOX_PRIV_FILE`) and the platform public key it pins (`SAASAPI_PLATFORM_BOX_PUB`). Required; ESO renders it with `externalSecrets.enabled`. See [Control-plane box keys](#control-plane-box-keys). |
| `controlPlaneBoxKeys.enabled` | `true` | The keygen hook Job that writes the platform and SaaS API box keys. |
| `saasapi.fleetUpdateDispatch.enabled` | `false` | `SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED`. A rollout also needs `farmer.selfUpdate.enabled`. |
| `saasapi.actionDispatch.{concurrency,selfUpdateConcurrency,tenantConcurrency}` | `256`, `16`, `32` | `SAASAPI_ACTION_DISPATCH_CONCURRENCY`, `SAASAPI_SELF_UPDATE_DISPATCH_CONCURRENCY`, `SAASAPI_ACTION_DISPATCH_TENANT_CONCURRENCY`: per replica, the cmd.run/cook dispatch pool, the pool reserved for rollout waves, and one tenant's cap in each (security review M5). The cap must be at most half of `concurrency`. Keep each at or below farmer's matching value times farmer's replicas (the defaults match farmer's, so they hold at any replica count). Null emits no env var. |
| `saasapi.actionDispatch.maxPendingPerTenant` | `2000` | `SAASAPI_ACTION_MAX_PENDING_PER_TENANT`, 1 to 100000: `POST .../sprouts/actions` is refused as a whole with `429 backlog_full` (`Retry-After: 60`, nothing written) when the tenant's `queued` and `dispatching` items plus the request's `asset_ids` would exceed it, so a tenant learns at submit time instead of from `expired_not_sent` items. A soft limit (requests in flight at once may each pass); update rollouts are never refused by it. Null emits no env var. See [`docs/api/saasapi.md`](../../../docs/api/saasapi.md#batch-actions). |
| `saasapi.fleetUpdateDispatch.clockSkew` | `""` (30s) | `SAASAPI_FLEET_UPDATE_CLOCK_SKEW`: clock-skew margin of the rollout wave gate, a Go duration up to `5m`. Empty emits no env var. |
| `saasapi.outboxSweeper.enabled` | `true` | `SAASAPI_OUTBOX_SWEEPER_ENABLED`: re-dispatch outbox work no live pod is dispatching, under row leases (safe on every replica). |
| `saasapi.outboxSweeper.{interval,provisioningStaleAfter,actionStaleAfter,actionMaxAge,leaseTTL}` / `maxAttempts` | `""` / `null` (30s, 2m, 2m, 30m, 2m / 5) | `SAASAPI_OUTBOX_SWEEP_INTERVAL`, `_PROVISIONING_STALE_AFTER`, `_ACTION_STALE_AFTER`, `_ACTION_MAX_AGE`, `_LEASE_TTL`, `_MAX_ATTEMPTS`. Empty or null emits no env var. See [`docs/api/saasapi.md`](../../../docs/api/saasapi.md#outbox-sweeper). |
| `saasapi.tenantPurge.enabled` | `null` (on) | `SAASAPI_TENANT_PURGE_ENABLED`: the sweeper erases an offboarded tenant's data after `after`. `false`: only the operator route purges. null emits no env var. See [Erasing an offboarded tenant's data](#erasing-an-offboarded-tenants-data). |
| `saasapi.tenantPurge.after` | `null` (`720h`) | `SAASAPI_TENANT_PURGE_AFTER`: the retention delay after offboarding, a Go duration, `1h` to `8760h` (saasapi refuses to start otherwise). null emits no env var. |
| `saasapi.operator.*` | off, port `8443` | The operator plane: TLS Secret, token Secret. See [saasapi's operator plane](#saasapis-operator-plane). |
| `saasapi.enrollmentKeys.rateLimit.*` | `1` / `5` | `deploy/saasapi/values.rate-limit.yaml`. `null` emits no env var. |
| `saasapi.recipes.enabled` | `false` | Tenant recipe upload: `SAASAPI_RECIPES_S3_*` from `objectStore.endpoint`/`bucket`/`useSSL` and saasapi's own credential. Off, the recipe routes answer 503. See [Tenant recipe upload](#tenant-recipe-upload). |
| `saasapi.recipes.credentialsSecret` / `accessKeyIdKey` / `secretAccessKeyKey` | `""` / `access-key-id` / `secret-access-key` | saasapi's own access key pair, limited to `tenants/*/recipes/*`. Required when enabled; must not be `objectStore.credentialsSecret`. |
| `saasapi.recipes.readRole` / `writeRole` | `imas-recipes-read` / `imas-recipes-write` | `SAASAPI_RECIPES_READ_ROLE` / `_WRITE_ROLE`: Keycloak roles for GET, and for PUT/DELETE. Must differ. |
| `saasapi.recipes.maxCount` / `maxTotalBytes` | `500` / `20971520` | `SAASAPI_RECIPES_MAX_COUNT` / `_MAX_TOTAL_BYTES`: per-tenant caps. |
| `saasapi.recipes.writeRateLimit.*` | `1` / `10` | `SAASAPI_RECIPES_WRITE_RATE_LIMIT` / `_BURST`: PUT and DELETE per tenant. |
| `saasapi.recipes.credentialCheck` | `true` | `SAASAPI_RECIPES_CREDENTIAL_CHECK`: saasapi refuses to start unless the object store denies its recipe credential outside `tenants/`, on `sprouts/`, creating and deleting under the platform recipe prefix (farmer's `recipedir`, default `/srv/imas/recipes/prod/`), and put, get, delete and list (of `jobs/` and of the bucket root) in the job bucket. Requires `objectStore.jobBucket`, passed as `SAASAPI_RECIPES_JOB_BUCKET`; the chart refuses to render without it while this is on. `false` turns it off; NOTES warns. See [Tenant recipe upload](#tenant-recipe-upload). |
| `saasapi.extraEnv` | `[]` | Extra env vars for saasapi, e.g. `HTTPS_PROXY`/`NO_PROXY`. |
| `credentialPublisher.*` | enabled, `platform/imas/saasapi-nats-user` | The publish Job, and its refresh CronJob. |
| `credentialPublisher.userJWTTTL` | `24h` | `IMAS_SAASAPI_USER_JWT_TTL`: the SaaS API User JWT's lifetime (its `exp`), hours and minutes, 1h to 720h, more than 3 x (`refresh.everyHours` + the CronJob's start delay and run time). A run writes a new JWT once a third of it is left. |
| `credentialPublisher.refresh.everyHours` | `4` | The refresh CronJob (`<release>-farmer-saasapi-credential-refresh`): the publish run every this many hours (1, 2, 3, 4, 6, 8 or 12), so the JWT is renewed before it expires. The render fails unless `userJWTTTL` is more than 3 times this plus `refresh.startingDeadlineSeconds` and `activeDeadlineSeconds` (12h45m with the defaults): the renewing run may start late and take time to publish. |
| `credentialPublisher.refresh.minute` | `17` | The minute of the hour it runs at: schedule `<minute> */<everyHours> * * *`. |
| `credentialPublisher.refresh.startingDeadlineSeconds` | `600` | How late a missed run may still start. |
| `sproutRelease.register` | `true` | Register `files/sprout-release.json` when the chart has it and the operator plane is on. |
| `sproutRelease.channel` | `stable` | Sent with the release. `min_sprout_version` is not a value: it is stamped at release time from `packaging/helm/min-sprout-version`. |
| `sproutRelease.serviceAccountName` | `imas-sprout-release-registrar` | The hook Job's own ServiceAccount. It runs `farmer register-sprout-release` in `farmer.image`. |
| `sproutRelease.retry.*` / `requestTimeoutSeconds` | `8`, `5`s doubling to `60`s / `600` | In-pod retries for no answer, 408, 429 and 5xx. |
| `sproutRelease.backoffLimit` / `activeDeadlineSeconds` / `ttlSecondsAfterFinished` | `1` / `1500` / `3600` | Keep `helm --timeout` above the deadline. |
| `sproutRelease.argoCDHooks` | `true` | `PostSync`, sync-wave 1. |
| `externalSecrets.*` | off | ESO wiring. |
| `openbaoBootstrap.*` | on | The bundled OpenBao's setup Job. |
| `versity.enabled` | `false` | The Versity Gateway in front of Azure Blob as the S3 endpoint ([Versity Gateway](#versity-gateway)). |
| `versity.image.*` | `docker.io/versity/versitygw` `v1.8.0` by digest | The gateway image; `digest` is required. |
| `versity.replicas` / `port` / `region` / `healthPath` | `2` / `7070` / `us-east-1` / `/_/health` | Replicas, the S3 port of pods and Service, `VGW_REGION`, the probes' path (`VGW_HEALTH`). |
| `versity.azure.credentialsSecret` / `accountNameKey` / `accountKeyKey` / `endpoint` | `""` / `account-name` / `account-key` / `""` | The storage account name and key (required when enabled); `AZ_ENDPOINT` (empty: `https://<account>.blob.core.windows.net/`). |
| `versity.rootCredentials.*` | `""`, `access-key-id`, `secret-access-key` | The gateway's root S3 credential (required when enabled). |
| `versity.accountsReader.*` | `""`, `access-key-id`, `secret-access-key` | The DMZ bus's read-only accounts credential (required when the accounts bucket is the gateway's). |
| `versity.createBuckets.*` | `imas-versity-buckets`, `10m`, ... | The bucket hook Job: ServiceAccount, in-pod timeout, backoff, deadline, Argo CD hooks, resources. |
| `versity.networkPolicy.extraIngressFrom` / `azureEgress` | `[]` / `[]` | More S3 clients (e.g. a DMZ cluster's nodes); the Azure Blob egress peers (empty: any destination on 443). |
| `versity.topologySpreadConstraints`, `pdb.*`, `service.*`, `resources`, `podSecurityContext`, `securityContext`, probes, `podAnnotations` | see `values.yaml` | As for farmer. |
| `networkPolicy.*` | on | See above. `saasapiOperatorIngress.from` is the operator plane's peer; `external.objectStore` is the object store's peer for farmer and for saasapi's recipe writes; `farmerExtraEgress` and `saasapiExtraEgress` are added on top. |

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
  - the publisher policy in `deploy/farmer/README.md`.
- **The pairing with `deploy/helm/nats`.** `TestContractWithNatsChart`
  renders both charts side by side and checks every name, port, SAN,
  seed, NetworkPolicy selector and OpenBao role each relies on from the
  other.
- **`Chart.lock`.** `TestChartLockMatchesChartYaml` fails if the lock and
  `Chart.yaml` disagree.
- **Chart-testing values.** `ci/*-values.yaml` follow the chart-testing
  convention: eval defaults, external production, token auth, and the
  Versity Gateway as every S3 endpoint (`versity-values.yaml`).
- **The Versity Gateway.** `versity_test.go` renders it on and off and
  checks the S3 endpoints, the Secret references, the NetworkPolicies, the
  bucket Job and its plan (parsed with the Job's own reader,
  `versitysetup.ReadPlan`), and every validation failure.

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
    - `transit/sign`, `rotate`, `config`, `export` and `backup` on the
      then Transit fleet key, for farmer's and saasapi's roles (that key
      and those roles are retired, P22);
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
- **The Versity Gateway, against a real gateway on the Azure backend**
  (2026-10-13): `versitygw` v1.8.0, built from its source (CGO off), ran
  `versitygw azure` against Azurite (Microsoft's Azure Blob emulator) as
  uid 65532 with the IAM directory read-only and the environment the chart
  renders. `GET /_/health` answered 200 with no credential. `farmer
  versity-iam` wrote the IAM file from four user directories; `farmer
  versity-buckets`, run twice with the plan of a `versity.enabled` render,
  created the four buckets and wrote and read back their policies (the
  `StringLike` `s3:prefix` condition included). Then, through
  `internal/objectstore`: farmer's key read, wrote, listed and deleted in
  the recipe and job buckets, read, wrote and listed sprout JWTs, and was
  refused a sprout JWT delete (since S6 farmer's statement grants that
  delete, for the purge; `TestVersityCreateBucketsJob` pins it) and the
  accounts bucket; the accounts writer
  wrote and listed but was refused a delete and the recipe bucket; the
  reader read and listed but was refused a write and the sprout JWT
  bucket; saasapi's key wrote, conditionally wrote (`If-None-Match`, then
  `If-Match`), listed and deleted under `tenants/*/recipes/*`, and
  saasapi's own startup credential check (`checkRecipeCredentialScope`)
  passed with it and failed with farmer's key; a wrong secret key was
  refused.

**Not verified:**

- A real install. There was no cluster, so none of this was tested:
  - the PXC operator or Valkey pods;
  - farmer booting against PXC, including `pki.ReloadNKeys`, which needs
    PXC;
  - the Kubernetes auth login itself;
  - the migrate hook Jobs (rendering and `go test` only). The SQL itself
    is tested against a real PXC (the image this chart runs): `cmd/migrate`,
    the migration sets and the lease and sweeper SQL, in CI's test job
    (`.github/workflows/ci.yml`, `IMAS_TEST_MYSQL_ROOT_DSN`);
  - the sprout release hook against a real saasapi, and `podFailurePolicy`
    failing the Job on exit 2.

## Known gaps

1. **saasapi runs in the release namespace.** The reference put its
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

Not an exception: the optional **Versity Gateway** image
(`versity.enabled`) is Apache-2.0 (design D18; `DEPENDENCIES.md`).

## Security review notes

- **The Versity Gateway** (`versity.enabled`, [Versity Gateway](#versity-gateway)).
  Its pods hold the Azure storage account key (full access to every
  container in the account), the gateway's root credential and every
  component's object store credential (in a memory-backed volume, read
  only by the gateway). The createBuckets Job holds the root credential
  and writes the bucket policies, the only thing that keeps one component
  out of another's buckets; the plan is rendered by the chart and checked
  by the Job (an Allow per user, plain `s3:` actions, resources inside the
  bucket), and the policies are read back. The gateway serves plain HTTP
  inside the cluster behind its NetworkPolicy: requests are SigV4-signed,
  but object contents (recipes, job logs, sprout JWTs, Account JWTs) cross
  the pod network unencrypted. Use a storage account of its own, and the
  namespace-access rule below applies to these Secrets too.

- **The publisher boundary** is `deploy/farmer/README.md`'s, carried over
  unchanged and enforced at render time where a chart can enforce it. Two
  things remain up to whoever runs the cluster:
  - Nothing that runs as farmer, and nobody but the deploy pipeline, may
    create pods or Jobs in this namespace, `pods/exec` into them, mint
    `serviceaccounts/token` for `imas-saasapi-cred-publisher`, or read its
    Secrets.
  - With an external OpenBao, the ops repo's roles must match the table
    above. Check with `bao token capabilities` as described.
- **The NATS trust chain** ([NATS trust](#nats-trust)). No pod holds a
  private key of it: farmer and the publish Job sign through Transit, each
  with its own role and policy, and only the bootstrap Job's short-lived,
  self-revoking handoff token may sign with the operator identity. The
  bootstrap Job's own ServiceAccount may write ConfigMaps in this
  namespace (create can't be narrowed by name), so the namespace-access
  rule above covers it too. farmer's tenant-key policy lets it create keys
  of any name on the `transit` mount (see [OpenBao](#openbao)).
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
  farmer's (farmer's can write `sprouts/` and the platform tree). saasapi
  checks the scope itself at startup (`saasapi.recipes.credentialCheck`,
  FIX.3, FIX.5) and refuses to run with a credential the store lets outside
  `tenants/`, onto `sprouts/`, onto the platform recipe prefix or into the
  job bucket; see that section for what the check does not prove.
- **The bootstrap admin** (`farmer.bootstrapAdmin`) becomes the platform's
  first CLI admin, with every right. The chart requires it (or an explicit
  `skip`), but can't check whose key it is: verify the box key's
  fingerprint with its owner out of band, and never ship the `ci/`
  placeholder (NOTES warns while it's set).
- **The operator credential** ([Sprout release registration](#sprout-release-registration)).
  Whoever holds the operator token can register any well-formed release
  whose `checksums.txt` they supply and offer it to tenants; a sprout
  installs only what verifies against its packaged keyring. Only two pods get
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
