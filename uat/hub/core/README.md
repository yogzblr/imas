# uat/hub/core: the core hub of the UAT gate (UAT.3b)

**FLAG FOR SECURITY REVIEW** (secret generation, the OpenBao bootstrap, the
UAT identity provider). **UAT only.** Nothing here is shipped, published or
used by a release. Plan: `docs/claude-code-parallel-build-plan.md`, section 4h.

> [!WARNING]
> **UAT ONLY: OpenBao's unseal keys and root token are not protected.**
> `openbao-bootstrap.sh` initialises the chart's OpenBao and stores **all of
> its unseal keys and its root token** in a Kubernetes Secret in the core
> namespace (`imas-uat-openbao-unseal`) **and** in
> `<state>/core/sensitive/openbao-init.json`, which the run keeps as a
> sensitive artifact. Anyone who can read either one can unseal this OpenBao
> and read everything in it. That is acceptable for a throwaway environment
> that lives for one run, and nowhere else. Never reuse this layout, and
> never upload `<state>/core/sensitive` anywhere but a sensitive artifact
> store that expires with the run.

## What it installs on the uat-core cluster

| Piece | Where | What |
|---|---|---|
| farmer, saasapi, PXC (1 node, 1 HAProxy), Valkey (1), OpenBao (1, standalone, single-node raft storage) | namespace `imas-core`, release `imas-core` | the **published** `deploy/helm/farmer` chart of `release_tag`, with `values/farmer-uat.yaml` and a run-specific values file from `gen-values.sh` |
| **RustFS** (resources still named `imas-uat-minio`) | `imas-uat` | the object store, one pod, pinned image, root credential generated per run in a Secret. Its S3 port is also hostPort 9000 (`minio.hostPort`), where the DMZ bus's account loader reads the accounts bucket. Apache-2.0. It replaced MinIO (AGPL-3.0); the UAT-only exception is withdrawn (requirements.md item 21). With `object_store.mode` `external` nothing is deployed here (see "External S3"). |
| **Keycloak** | `imas-uat` | Apache-2.0, pinned image, **dev style**: one replica, `start-dev`, the **embedded H2 database** (`dev-file`) on a 1 GiB PVC so a pod restart keeps the tenant bindings. Realm `imas-uat` imported from `chart/files/imas-uat-realm.json`. |
| edge proxy | `imas-uat` | one Envoy (Apache-2.0, the nats chart's pin), hostPorts only (owner decision 2026-10-06; there is no node port mode, the core node port range being 30000-32767), on the core FQDN: 443 for saasapi (`/v1/`) and Keycloak (`/realms/imas-uat/` only, never `/admin` or the master realm), and a TCP passthrough on 5405 to farmer's API for the DMZ's Envoy |
| the DMZ bus, as seen from core | no object of its own | the farmer chart is installed with `bus.host` set to the DMZ's private name (`dmz.uat.imas.internal` by default, read from the endpoints file by `gen-values.sh`; UAT.1's Private DNS zone), `bus.port` the DMZ's bus node port 8442 and `bus.egressCIDRs` the DMZ private address, so `farmerbusurl` and `SAASAPI_NATS_URL` are `tls://dmz.uat.imas.internal:8442` and both verify that name, which the DMZ's bus certificate carries as a SAN. (This replaces the ExternalName Service of earlier versions.) |
| certificates | `imas-core`, `imas-uat` | farmer's API certificate (`tls.secretName`; SANs: its Service names, `core.uat.imas.internal`, the core FQDN and private IP) and the edge's (the core FQDN), both from the per-run UAT CA ClusterIssuer (UAT.2) |
| NetworkPolicies | both | additive to the chart's: farmer in from the edge on 5405; farmer and saasapi out to the DMZ IP on the bus port; the edge in on 443 and, from the DMZ IP only, 5405; Keycloak in from the edge only; RustFS in from farmer and saasapi, and from the DMZ IP on 9000 (the bus's account loader, read-only on the accounts bucket; design D22). Farmer's API and the accounts store are the only DMZ-to-core paths |

`chart/` holds the UAT-only pieces as a small local Helm chart
(`imas-uat-core`, never packaged or published).

## Inputs

Every script takes the same first three arguments and calls nothing Azure
specific, so UAT.8's local rig runs them unchanged:

```
install.sh   <kubeconfig> <endpoints.json> <state-dir> <release_tag>
finish.sh    <kubeconfig> <endpoints.json> <state-dir> <release_tag>   (after the DMZ hub)
check.sh     <kubeconfig> <endpoints.json> <state-dir>
bind-tenant.sh <kubeconfig> <endpoints.json> <state-dir> <1|2> <tenant_id>
bind-tenant.sh <kubeconfig> <endpoints.json> <state-dir> --scratch-user <scratch-name> <admin|readonly> <tenant_id>
token.sh     <kubeconfig> <endpoints.json> <state-dir> <t1-admin|t1-reader|t2-admin|t2-reader> [tests|other]
```

`openbao-bootstrap.sh`, `seeds.sh`, `admin-keys.sh`, `minio-setup.sh` and
`saasapi-secrets.sh` are the steps `install.sh` runs, each runnable on its
own with the same arguments. `gen-values.sh` reads files only.

- **`release_tag`**: `vX.Y.Z` or `vX.Y.Z-rc.N` (the contract). The chart
  version and every imas image tag are the tag without the `v`; `latest` is
  refused everywhere.
- **The endpoints file** is the `tofu output uat` JSON of the contract, or
  anything with the same `dmz` and `core` objects. Read from it:

  | Key | Required | Default | Used for |
  |---|---|---|---|
  | `core.fqdn` | yes | | Keycloak issuer, saasapi URL, edge and farmer certificates |
  | `core.private_ip` | yes | | farmer certificate IP SAN |
  | `dmz.fqdn` | yes | | the public name (not used for `bus.sproutBusURLs`, see below) |
  | `dmz.private_ip` | yes | | the bus endpoint, and the only source admitted to farmer's API |
  | `core.ports.https` | no | `443` | the edge's external HTTPS port; a port other than 443 becomes part of the issuer |
  | `core.ports.farmer_api` | no | `5405` | the edge's external farmer API port (the DMZ's Envoy dials it) |
  | `core.private_fqdn` | no | `core.uat.imas.internal` | the core's private name (the Shared contract), on farmer's certificate. Else `core.<private_dns_zone>` |
  | `dmz.private_fqdn` | no | `dmz.uat.imas.internal` | the DMZ's private name: farmer's `bus.host`. Else `dmz.<private_dns_zone>` |
  | `private_dns_zone` | no | `uat.imas.internal` | the zone `uat/hub/dmz` reads its private names from; used here when `core.private_fqdn` or `dmz.private_fqdn` is absent. An explicit `*.private_fqdn` wins |
  | `core.exposure` | no | `hostPort` | only `hostPort` is accepted: the node port mode was dropped (owner decision 2026-10-06) |
  | `dmz.ports.envoy` | no | `8443` | Envoy's external port (nats chart `envoy.listenerPort`) |
  | `dmz.ports.bus` | no | `8442` | the DMZ node port of the bus client port (owner decision 2026-10-06: the DMZ node port range is 8442-8443, bus on 8442). `bus.port` of the farmer chart: farmer and saasapi dial `bus.host` on it |
  | `ca.cluster_issuer` | no | `imas-uat-ca` | UAT.2's cert-manager ClusterIssuer (a CA issuer: its Secrets carry `ca.crt`). `uat/hub/dmz` spells it `cluster_issuer`; either is read, `ca.cluster_issuer` first |
  | `cluster_domain` | no | `cluster.local` | |
  | `object_store.mode` | no | `rustfs` | `rustfs`: RustFS is deployed in `imas-uat` and `minio-setup.sh` provisions it. `external`: an S3 endpoint you run; nothing is deployed or provisioned (see "External S3") |
  | `object_store.endpoint` | external: yes | `imas-uat-minio.imas-uat.svc.cluster.local:9000` | `host[:port]`, no scheme: farmer's `objectStore.endpoint` and saasapi's recipe store |
  | `object_store.use_ssl` | no | `false` | `true` or `false`: `objectStore.useSSL` |
  | `object_store.egress_cidrs` | no | `[]` | IPv4 CIDRs: narrows farmer's and saasapi's object store egress (`networkPolicy.external.objectStore`). Empty: any destination, on the endpoint's port |

- **Environment** (all optional): `UAT_SEEDS_DIR` (see Seeds),
  `IMAS_HELM_OCI_BASE` (default `oci://ghcr.io/yogzblr/charts`; the farmer chart is
  `<base>/farmer`; it replaces `IMAS_HELM_REPO_URL`, which is no longer read),
  `IMAS_RELEASE_BASE_URL` (default the GitHub releases of yogzblr/imas),
  `HELM_TIMEOUT` (default `45m`), `OPENBAO_KEY_SHARES` / `OPENBAO_KEY_THRESHOLD`
  (default 3 / 2), `SKIP_CHECK=1` (finish.sh doesn't run check.sh).

**What the cluster must already have (UAT.2):** the ClusterIssuer above, a
default StorageClass, cert-manager, the core FQDN resolving to the core
private IP inside the cluster (so saasapi fetches Keycloak's JWKS from the
same URL as the issuer and never dials the node's public IP), hostPort
support in the CNI, cluster DNS that resolves `dmz.uat.imas.internal` (CoreDNS
forwarding to the node's resolver, which answers from the Private DNS zone),
and the DMZ hub's bus
client port reachable from core. **On the runner:** kubectl, helm, jq, curl,
openssl, go (to build `nk`), tar, sha256sum, and this repository checked out.

## What install.sh does, in order

1. Namespaces; generates the run's credentials (MinIO root, Keycloak admin,
   the test client secret, four user passwords, saasapi's BFF secret) with
   `openssl rand`, keeps them under `<state>/core/sensitive` (0700, files
   0600) and puts them in Secrets. Values go from files to `kubectl create
   secret --from-file | kubectl apply`, never through argv or the log. A
   re-run keeps what exists.
2. **Seeds** (`seeds.sh`): the NKey user seeds, made with `nk`
   (`github.com/nats-io/nkeys/nk`, the tool the chart README names, built at
   this repo's own `go.mod` pin), never hand written: `sys-user.nk`
   (`SYS_USER`) and `saasapi-user.nk` (`SAASAPI_USER`) into the Secret
   `imas-farmer-nats-seeds`; farmer's NKey `farmer.nk` into the Secret
   `imas-farmer-nkey` (the chart's `farmer.nkeySecret`, mounted by every
   farmer replica); and the DMZ bus loader's SYS user `bus-loader-user.nk`,
   which stays a file (the DMZ install takes it with `--loader-seed`) and
   whose public key goes to `out/bus-loader-user.pub`, which `gen-values.sh`
   turns into `natsTrust.busLoaderUserPub`. Each Secret is handled on its
   own: it refuses to replace the seeds of an install that already has it,
   and restores missing local files from it. Since P21 slice 1 there is no
   operator, operator-signing, SYS account or tenant seed: those are
   OpenBao Transit keys (step 7).
3. **Bootstrap admin** (`admin-keys.sh`): downloads the `imas` CLI of
   `release_tag` from the GitHub release, checks it against the release's
   `checksums.txt`, and runs `imas auth privkey`, `imas auth pubkey` and
   `imas auth keygen` in a HOME of its own. Public halves go to the chart
   (`farmer.bootstrapAdmin`); the private material stays in
   `sensitive/admin-home`.
4. **The chart**: `helm pull oci://ghcr.io/yogzblr/charts/farmer --version
   <tag without v> --destination <dir>`, anonymously (an empty registry
   config, so no login of the runner's is used), and checks its `version`
   and `appVersion`. The version is exact, so a pre-release
   (`0.1.0-rc.5`) is selected and no `--devel` or range is used. Needs Helm
   3.8 or later (or 4). If the pull fails, the chart package may still be
   private: the owner makes each chart package public once, in its GHCR
   package settings, after the first push (`docs/RELEASING.md`). The
   Buildkite `imashelm` registry is superseded for charts.
5. **UAT-only pieces** (`chart/`), waits for them and for both certificates,
   and copies the UAT CA (the issued Secret's `ca.crt`, a public certificate)
   to the ConfigMap `imas-uat-ca` and `out/uat-ca.crt`.
6. **Object store** (`minio-setup.sh`, RustFS): buckets `imas-recipes` (`objectStore.bucket`),
   `imas-jobs` (`objectStore.jobBucket`), `imas-sprout-jwts`
   (`objectStore.sproutJWTBucket`, private, the sprout User JWTs) and
   `imas-accounts` (`accountStore.bucket`); user `imas-farmer` with the
   recipe and job buckets and get and put on the sprout JWT bucket; user
   `imas-saasapi` with the **release chart's own**
   `files/objectstore-policies/saasapi-recipes.json`; user
   `imas-farmer-accounts` (get, put and list on the accounts bucket only)
   and user `imas-bus-accounts-reader` (get and list on it only); the
   Secrets `imas-uat-s3-farmer` (`objectStore.credentialsSecret`),
   `imas-uat-s3-saasapi` (`saasapi.recipes.credentialsSecret`) and
   `imas-farmer-accounts-writer` (`accountStore.credentialsSecret`). The
   reader's pair stays in `sensitive/s3/accounts-reader/` for the DMZ
   install's `--accounts-reader-dir`; it never becomes a core Secret. It uses the
   `curl` inside the RustFS server image through `kubectl exec` (signed with
   `--aws-sigv4` against RustFS's admin API), so no client image is pulled
   and the RustFS root credential never leaves its pod.
   saasapi's startup credential check then proves the saasapi user is
   limited.
7. **The farmer chart** (`helm upgrade --install`, no `--wait`, as the chart
   README says for a first install), and **while it runs**
   `openbao-bootstrap.sh`: waits for OpenBao's pod, `bao operator init`
   (3 shares, threshold 2), unseals, waits for the single-node raft node to
   become active, enables Transit and creates
   `transit/keys/imas-gateway-jwt` as **ed25519** (the name
   `farmer.openbao.gateway.keyName` expects), then mints the token the
   chart's bootstrap Job gets and writes it to the Secret
   `openbaoBootstrap.tokenSecretName` names (`imas-uat-openbao-root`). That
   is **not the root token**: the Job revokes the token it is handed when
   it is done (owner decision a, no standing admin), so every run of the
   script mints a fresh orphan token with the root policy, valid one hour,
   not renewable, UAT's stand-in for "a fresh root token from the recovery
   quorum". The root token stays in the sensitive files and
   `imas-uat-openbao-unseal`. The chart's own bootstrap Job waits for an
   unsealed OpenBao and for that Secret, and does the rest (KV, policies,
   roles, the fleet key, and P21 slice 1's NATS platform Transit keys and
   the public trust ConfigMap `imas-nats-trust`, which the DMZ install
   copies); it checks before it creates, so the two never conflict. When
   the install returns, `install.sh` checks the trust ConfigMap exists,
   records it in `out/nats-trust.json` (the first install only) and
   deletes `imas-uat-openbao-root`, whose token is revoked: later runs of
   the Job without it only check the trust. Re-running the script after a
   pod restart unseals again, from local files or, failing that, from the
   Secret.
8. **saasapi's Secrets** (`saasapi-secrets.sh`), by hand because there is no
   External Secrets here, exactly as the chart README's eval install:
   `imas-saasapi-nats` (seed and published JWT) and `imas-saasapi-box`
   (`priv` of `saasapi-box` and `platform_pub`, never `platform`).
9. Waits for OpenBao (Ready means unsealed), the PXC cluster, its pxc and
   haproxy StatefulSets, Valkey, MinIO, Keycloak and the edge; writes the
   outputs. It does not wait for farmer or saasapi, and installs the chart
   with `sproutRelease.register=false`: both need the DMZ's NATS bus (farmer's
   `/ready` latches once it has connected to it, saasapi exits at startup
   without it), and the registration hook POSTs to saasapi.

## finish.sh (after the DMZ hub)

Run it once `uat/hub/dmz/install.sh` has finished, with the same arguments as
`install.sh`. It waits for the farmer and saasapi rollouts, registers the
sprout release (`helm upgrade --reuse-values --set sproutRelease.register=true`;
the chart's post-upgrade hooks are idempotent, as for any re-run of
`install.sh`), then runs `check.sh` unless `SKIP_CHECK=1`. Safe to re-run.
The upgrade re-runs the OpenBao bootstrap Job without a token, so it only
checks the trust ConfigMap; `check.sh` then confirms it is unchanged
(design T4).

## Outputs

`<state>/core/out/` (not secret):

- `core.json`: release tag and version, `saasapi_url`, the BFF header name,
  `ca_file`, the Keycloak `issuer`, `jwks_url`, `token_url`, realm,
  audience, test client id, role names and tenant claim, the four users
  with their tenant and roles, `tenants` (filled by `bind-tenant.sh`), the
  bootstrap admin's public keys, and where the sensitive directory is.
- `nats-trust.json`: the trust ConfigMap's data and `resourceVersion` as the
  first install left them (public data), which `check.sh` compares against.
- `uat-ca.crt` (and the same file as `uat-ca.pem`, the name `uat/tests`
  reads), `admin.json` (public keys), `bus-loader-user.pub` (the DMZ bus
  loader's NKey public key, `natsTrust.busLoaderUserPub`).

`<state>/core/sensitive/` (**SENSITIVE**, 0700; keep only as a sensitive
artifact of the run):

- `keycloak.json`: the shape `uat/tests` (UAT.5) and `uat/enroll` (UAT.4)
  read (owner decision 2026-10-06): `issuer`, `client_id`, `client_secret`,
  `tenant_attribute` (`organization_id`), `other_audience_client`, and
  `tenants.<1|2>` with `admin` and `readonly` users and, once
  `bind-tenant.sh` has run, `tenant_id`. It has no `admin` block (see
  "Keycloak, tokens and tenants");
- `credentials.json`: the BFF secret, the test client secret, the four user
  passwords, the Keycloak master admin, and pointers to the files below;
- `admin.json` and `admin-home/.config/imas/` (the bootstrap admin's NKey
  private key and CLI box key; run the CLI with `HOME=<home>`);
- `openbao-init.json`, `openbao-root-token`, `openbao-unseal-keys.json`,
  `openbao-bootstrap-token` (the last token handed to the chart's Job;
  revoked once the Job has run);
- `seeds/` (unless `UAT_SEEDS_DIR` points elsewhere; `bus-loader-user.nk`
  is the DMZ install's `--loader-seed`), `keycloak/`, `minio/`, `s3/`
  (`s3/accounts-reader/` is the DMZ install's `--accounts-reader-dir`),
  `internal-auth-secret`.

## Keycloak, tokens and tenants

saasapi checks a Keycloak token's signature, issuer, audience and expiry,
and on every route with `{tenant_id}` requires the token's
`organization.id` claim to equal it (`docs/api/saasapi.md`,
"Authentication"). The recipe routes also need the realm roles
`imas-recipes-read` / `imas-recipes-write` (`saasapi.recipes.readRole` /
`writeRole`). Every request also needs the BFF's shared secret in
`X-Internal-Auth`; the tests stand in for the BFF.

The realm `imas-uat` has:

- the issuer `https://<core.fqdn>/realms/imas-uat`: `KC_HOSTNAME` and the
  realm's `frontendUrl` are both the core FQDN URL, so `iss` never depends on
  how a request arrived, and it is the same string as saasapi's
  `SAASAPI_JWT_ISSUER` and the base of `SAASAPI_KEYCLOAK_JWKS_URL`;
- the client `imas-saasapi` (the audience; bearer only, issues nothing) and
  the confidential client `imas-uat-tests` (password grant only, secret
  generated per run) with two mappers: the audience `imas-saasapi`, and the
  user attribute `organization_id` as the claim `organization.id`; and
  `imas-uat-other-audience` (password grant, no mappers), whose tokens lack
  saasapi's audience, for the wrong-audience test;
- access tokens that live 5 minutes (Keycloak's default), because the tests
  wait for a token to expire;
- the two realm roles, and four users: `t1-admin` and `t2-admin` (both
  roles), `t1-reader` and `t2-reader` (read only). Passwords are `${...}`
  placeholders Keycloak fills from a Secret at import; none is committed;
- a user profile in which only an admin can see or edit `organization_id`,
  so a user can't move to another tenant.

A tenant_id only exists after `POST /v1/tenants` (saasapi generates it), so
the realm can't carry it. Owner decision 2026-10-06: the harness calls
`bind-tenant.sh` once per tenant. The flow:

1. `token.sh ... t1-admin` (no `organization.id` yet) is enough for
   `POST /v1/tenants` and `GET /v1/versions`, which have no `{tenant_id}`.
2. Create the tenant, then `bind-tenant.sh ... 1 <tenant_id>`: it sets
   `organization_id` on `t1-admin` and `t1-reader` (kcadm.sh inside the
   Keycloak pod, master realm, password over stdin) and records it in
   `core.json` and as `tenants.1.tenant_id` in `keycloak.json`.
3. Fetch a new token; it now carries `organization.id`. Same for tenant 2.

`keycloak.json` carries no Keycloak admin identity, and Keycloak's admin
REST API and master realm are never on the edge (owner decision
2026-10-06). Tenants created during a test run (UAT.5's T1, T4 and T5) get
their users from the scratch mode of `bind-tenant.sh` instead, through
`kubectl exec` like the rest:

```
bind-tenant.sh <kubeconfig> <endpoints.json> <state-dir> --scratch-user <name> <admin|readonly> <tenant_id>
```

- `<name>` must match `scratch-[a-z0-9][a-z0-9-]{0,50}`, so the realm's own
  users can't be touched. `admin` gets both recipe roles, `readonly` the read
  role. `<tenant_id>` must be a saasapi tenant_id and not tenant 1's or 2's.
- It creates the user if absent, sets a password generated into
  `sensitive/keycloak/scratch/<name>.password` (0600, passed to Keycloak over
  stdin, never argv), grants the roles and sets `organization_id`.
- It prints one JSON line and nothing secret:
  `{"username", "tenant_id", "role", "password_file"}`. Get the token with a
  password grant on `keycloak.json`'s `client_id`/`client_secret` and that
  file's content, or `token.sh ... <name>`.
- It records `scratch_users.<name> = {tenant_id, role}` in `core.json`.
  Running it again for the same user and tenant only re-sets the password
  from its file; a scratch user already bound to another tenant is refused
  (use a new name). Scratch users are not deleted; they go with the run.
- Exit status non zero, with the reason on stderr, on any refusal or
  Keycloak error.

## check.sh

One line per check, non zero on any failure, nothing secret printed:
farmer, saasapi, the PXC cluster and its StatefulSets, Valkey and OpenBao
Ready (OpenBao initialised and unsealed, single-node raft and active, the
gateway key ed25519), RustFS, Keycloak and the edge Ready, saasapi's
Secrets, the seeds Secret and farmer's NKey Secret present; **design T4**
(`docs/design/imas-openbao-signing-design.md` section 11, the OpenBao
bootstrap Job): the trust ConfigMap `imas-nats-trust` holds the six
required keys (with `bus-loader-user.jwt`) and no NKey seed and is byte for byte what the first install
recorded in `out/nats-trust.json` (data and `resourceVersion`: a re-run of
the Job, such as `finish.sh`'s upgrade, wrote nothing), no bootstrap token
Secret is left, and in OpenBao (`openbao_t4`, root token over stdin) the
token handed to the Job is revoked, the ephemeral policy
`imas-nats-bootstrap` is gone, a probe token with `imas-farmer-natssign`
and `imas-nats-sys-signer` gets `deny` on `transit/sign/nats-operator` and
on `transit/keys/nats-operator/soft-delete` and only `read` on
`transit/keys/nats-operator`, and the three platform keys are hardened
ed25519 keys (farmer Ready also means its start-up check matched the trust
to Transit); the migration
finished (the release is `deployed`, so its migrate hook succeeded, which
also deletes that Job; no failed migrate Job is left; both schemas have an
applied goose version, read with the PXC root password over stdin); every
imas image at the release version and none at `latest`; Keycloak's discovery
document gives the expected issuer and JWKS URL, and saasapi is configured
with the same; a token for each of the four users, with that `iss`, the
audience and the right roles; saasapi answers `GET /v1/versions` with 200
for `t1-admin` and `t2-admin`, and 401 with no token, with no token and no
BFF secret, with a valid token and no BFF secret, with a token from
`imas-uat-other-audience` (no saasapi audience), and with a forged
signature. Once both tenants are bound it also checks each admin reads its
own tenant (200) and is refused on the other's (403).

## Tests

`test/run.sh` (no cluster needed): shellcheck; yamllint on the values files,
the chart metadata and the rendered UAT chart; the realm's jq checks
(`test/check-realm.sh`: roles, issuer placeholder, clients, mappers, users,
no committed password); `gen-values.sh` and the endpoint validation;
`seeds.sh` against a stub kubectl with the real `nk`; `admin-keys.sh`
against a stub curl and a fake CLI (checksum mismatch, missing checksum,
reuse, file modes); argument checks; `openbao-bootstrap.sh` and
`saasapi-secrets.sh` against a **real local OpenBao** when a `bao` binary is
in `BAO_BIN` or on PATH (init, unseal, restart, unseal from the Secret with
no local files, the ed25519 key, a fresh one-hour root-policy bootstrap token
per run that is not the root token, no token or key in argv or output; and
`check.sh`'s T4 probe, `openbao_t4`, against the chart's own policy files:
a live bootstrap token, the ephemeral policy and an exportable key fail,
the farmer and publisher policies cannot sign with the operator key); and
`go test ./uat/hub/core/`, which renders `deploy/helm/farmer` with
`values/farmer-uat.yaml` plus `gen-values.sh`'s output, and `chart/` with
`extras_set_args`, and checks the values that matter (issuer, JWKS URL and
audience equal Keycloak's; the UAT CA for saasapi; RustFS and the recipe,
job and sprout JWT buckets; the accounts bucket and its writer Secret;
the bus URL and sprout bus URL; tls from cert-manager; release image tags; the
OpenBao bootstrap token Secret, no dev mode, single-node raft storage with a
fixed node_id and api_addr and cluster_addr on the pod's Services; the two
user seeds and farmer's NKey Secret, no trust chain seed, the trust
ConfigMap mounted, the Transit signer configured and the loader key in the
bootstrap; every farmer-chart key in `values/farmer-uat.yaml` known to the
chart (so a dropped key such as `farmer.persistence` fails);
the bootstrap Job's `prepare` and `nats-trust` steps, policy deletion and
token revocation; one replica each; the
certificate SANs; policies naming only the DMZ address;
the edge routes). It renders the subcharts too when `helm dependency build`
has filled `deploy/helm/farmer/charts` (CI does), and skips without helm
unless `IMAS_REQUIRE_HELM=1`.

## Assumptions about the other briefs

- **UAT.2**: the ClusterIssuer is a cert-manager CA issuer named by
  `ca.cluster_issuer`, the same CA on both hubs (farmer verifies the bus with
  it, and the DMZ's Envoy verifies farmer with it); the core FQDN resolves to
  the core private IP in-cluster, and `dmz.uat.imas.internal` resolves too;
  nothing else binds 443 or 5405 on the core node (the edge takes them as
  hostPorts).
- **UAT.3a**: the bus certificate carries the DMZ's private name
  (`dmz.private_fqdn`, else `dmz.<private_dns_zone>`: uat/hub/dmz reads the same
  two forms) as a SAN, and the
  DMZ exposes the bus **client** port (5406, NATS over TLS) to core on node
  port 8442 (`dmz.ports.bus`; owner decision 2026-10-06). The DMZ bus
  holds no farmer seed: `uat/hub/dmz/install.sh --seeds-from-kubeconfig` copies the
  public trust ConfigMap `imas-nats-trust` from here, and its loader gets
  `--loader-seed <seeds>/bus-loader-user.nk` and `--accounts-reader-dir
  <sensitive>/s3/accounts-reader` from this hub's state directory. It reads
  the accounts bucket at `<core private IP>:9000` (RustFS's hostPort). Envoy's `farmer_api` upstream is
  `core.uat.imas.internal:5405` (or the core FQDN or private IP) and
  verifies against the UAT CA; farmer's certificate carries all three.
- **UAT.4**: creates tenants 1 and 2 with `t1-admin` and `t2-admin` tokens
  and calls `bind-tenant.sh` after each.
- **UAT.5**: for tenants it creates during a run (not in `core.json`), calls
  `bind-tenant.sh --scratch-user`.
- **UAT.5**: reads `out/core.json` and `sensitive/credentials.json`.
- **UAT.6**: keeps `<state>/core/sensitive` out of every uploaded artifact
  except a sensitive one.

## Seeds

Four user seeds exist, as files in `UAT_SEEDS_DIR` (default
`<state>/core/sensitive/seeds`): farmer's two (`sys-user.nk`,
`saasapi-user.nk`, Secret `imas-farmer-nats-seeds`), farmer's NKey
(`farmer.nk`, Secret `imas-farmer-nkey`) and the DMZ bus loader's SYS user
(`bus-loader-user.nk`, no core Secret). `seeds.sh` uses any seed file
already there and generates only the missing ones. The DMZ bus itself needs
no seed (P21 slice 1): it starts from the public trust ConfigMap, which
carries no secret; only its loader sidecar holds `bus-loader-user.nk`, in
the DMZ's own Secret. Once the trust ConfigMap carries
`bus-loader-user.jwt`, which is never re-minted (design T4), `seeds.sh`
refuses to regenerate a missing loader seed (restore it from the DMZ
Secret `imas-bus-loader-sys-user`, key `user.nk`) and refuses a seed whose
public key is not the one that JWT names.

## Open points

- **`farmerbusurl` with the private name: settled.** The farmer chart's
  `bus.host` (a bare DNS name, with `bus.port` and `bus.egressCIDRs`) makes
  `farmerbusurl` and `SAASAPI_NATS_URL` `tls://dmz.uat.imas.internal:8442`, so
  the earlier ExternalName Service is gone. The name is read from the endpoints
  file, never written in the script. Both farmer and saasapi verify the name
  they dial, so the DMZ's bus certificate must carry it as a SAN (uat/hub/dmz
  does, from the same two key forms). `bus.egressCIDRs` is the DMZ private
  address as a /32 and has to be kept in step with what the name resolves to
  (a NetworkPolicy can't match a name). `bus.tlsServerName` is unset.
  Not run: nothing here has been installed against a cluster.
- **In-cluster resolution of the private zone** relies on CoreDNS forwarding
  to the node's resolver (Azure's 168.63.129.16 on the hub). Not tested.

## Deferred

- The sprout release registration hook and saasapi's operator plane stay
  off here, so this hub registers no sprout release and scenario L5 (self
  update) needs more setup.
- Signature verification of the release's `checksums.txt` (cosign or GPG)
  before trusting the CLI archive; only the SHA-256 is checked.
- Image digests for RustFS, Keycloak and Envoy (tags are pinned; the agent
  sandbox could not reach the registries to read digests).
- Narrowing the chart's default saasapi egress (HTTPS anywhere) to the
  edge.

## External S3

The S3 endpoint is a variable. To use an S3 service you run instead of the
bundled RustFS (for example [Versity Gateway](https://github.com/versity/versitygw),
Apache-2.0, which fronts POSIX storage, Azure Blob and other S3 servers),
set in the endpoints file:

```json
"object_store": {"mode": "external", "endpoint": "s3gw.example.internal:7070",
                 "use_ssl": true, "egress_cidrs": ["10.70.0.0/24"]}
```

In this mode `install.sh` deploys no object store, skips `minio-setup.sh`
and its rollout and check, and applies the three Secrets the farmer chart
names from files you place first, under `<state-dir>/core/sensitive/s3/`:
`farmer-access-key-id`, `farmer-secret-access-key`, `saasapi-access-key-id`,
`saasapi-secret-access-key`, `accounts-writer-access-key-id` and
`accounts-writer-secret-access-key`, plus `accounts-reader/access-key-id`
and `accounts-reader/secret-access-key` for the DMZ install's
`--accounts-reader-dir` (no trailing newline). You also provide the
buckets `imas-recipes`, `imas-jobs`, `imas-sprout-jwts` and
`imas-accounts`, the four users with the limits `minio-setup.sh` gives
them, and an endpoint for the accounts bucket the DMZ can reach:
`dmz.account_store.endpoint` in the endpoints file is required in this mode
(`load_endpoints` stops without it, since the DMZ's default,
`<core private IP>:9000`, is the bundled RustFS), plus the matching network
path.

What the service must do, because imas relies on it (RustFS 1.0.1 was
checked for each; a gateway has to be checked too):

- Conditional PUT: `If-None-Match: *` and `If-Match: <etag>` answered 412
  on a failed precondition (recipe and audit writes).
- saasapi's user limited to `tenants/*/recipes/*` (read, write, delete),
  list with that prefix, and `PutObject` only on `tenants/*/recipe-audit/*`,
  per `deploy/helm/farmer/files/objectstore-policies/saasapi-recipes.json`.
  saasapi's startup check (`saasapi.recipes.credentialCheck`) proves that
  limit holds. A gateway without per-prefix policies is expected to fail
  it; that is a finding, not something to switch off quietly.
- Requests to the given `host[:port]` (no scheme), the way minio-go sends
  them to a non-AWS endpoint.

## Licences

RustFS: Apache-2.0 (it replaced MinIO, AGPL-3.0). Keycloak and Envoy: Apache-2.0. OpenBao
(MPL-2.0), PXC (GPLv2) and Valkey (BSD-3-Clause) are the farmer chart's
recorded exceptions. `nk` is part of `github.com/nats-io/nkeys` (Apache-2.0),
already a dependency. No new Go dependency.
