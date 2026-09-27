# Installing imas

imas is no longer a single farmer binary on one server with sprouts dialing
it directly. What's on `main` is a multi-tenant SaaS deployment:

- a **DMZ** holding the NATS bus (`farmerbus`) and an **Envoy** gateway,
  which is the only thing sprouts ever connect to;
- a **non-DMZ core** holding `farmer`, the **SaaS API** (`saasapi`), PXC,
  Valkey, OpenBao and object storage;
- **sprouts**, each enrolled into a **tenant** with a one-time **enrollment
  key** (join token) minted through the SaaS API.

The picture is [`diagrams/imas-architecture.svg`](diagrams/imas-architecture.svg).
The API is documented in [`api/saasapi.md`](api/saasapi.md).

If you have questions, [open an issue](https://github.com/yogzblr/imas/issues/new/choose).

## Contents

1. [Components](#components)
2. [Prerequisites](#prerequisites)
3. [Install on Kubernetes (recommended)](#install-on-kubernetes-recommended)
4. [Install on Linux hosts with systemd](#install-on-linux-hosts-with-systemd)
5. [Create a tenant and an enrollment key](#create-a-tenant-and-an-enrollment-key)
6. [Install and enroll a sprout](#install-and-enroll-a-sprout)
7. [The imas CLI](#the-imas-cli)
8. [Ports](#ports)
9. [Coming from the single-tenant install](#coming-from-the-single-tenant-install)

## Components

| Component | Source | Runs in | Packaged as |
|---|---|---|---|
| `farmer` (core) | `cmd/farmer` | core | deb/rpm/apk with [`packaging/systemd/imas-farmer.service`](../packaging/systemd/imas-farmer.service); Helm chart `deploy/helm/farmer` |
| `saasapi` | `cmd/saasapi` | core | Helm chart `deploy/helm/farmer`; no OS package |
| `farmerbus` | `cmd/farmerbus` | DMZ | Helm chart `deploy/helm/nats`; no OS package or unit |
| Envoy | [`deploy/envoy/envoy.yaml`](../deploy/envoy/envoy.yaml) | DMZ | Helm chart `deploy/helm/nats` (pins `envoyproxy/envoy:v1.35.3`) |
| `imas-sprout` | `cmd/sprout` | managed hosts | deb/rpm/apk with [`packaging/systemd/imas-sprout.service`](../packaging/systemd/imas-sprout.service); Windows MSI and winget |
| `imas` CLI | `cmd/imas` | operator machine | release archives |

No farmer, saasapi or farmerbus container image is published yet. Build them
with `CGO_ENABLED=0` following `docker/farmer.dockerfile`
([`deploy/helm/farmer/README.md`](../deploy/helm/farmer/README.md),
"Before you install").

To build every binary from source, run `make` on Linux (or `GOOS=linux make`
elsewhere); binaries land in `bin/`. You need a Go toolchain
([install instructions](https://go.dev/doc/install)). The build is CGO-free.

## Prerequisites

The core needs these before farmer can enroll a single sprout:

| Service | Used by | Required? |
|---|---|---|
| **PXC** (Percona XtraDB Cluster / MySQL 8) with a `farmer` and a `saas` schema | farmer (`IMAS_PXC_DSN`), saasapi (`SAASAPI_DSN`) | farmer exits at startup without it. The grants are design doc §5.1; see [`deploy/helm/farmer/README.md`](../deploy/helm/farmer/README.md), "PXC". |
| **OpenBao** | farmer: PKI (API certificate), Transit `imas-gateway-jwt` (gateway JWTs), Transit `imas-fleet-signing` (read-only), KV v2 `secret/imas/tenant-x25519` (tenant box key) | farmer starts without the Transit keys, but `POST /v1/enroll` fails closed until both are configured. Without OpenBao PKI you must place farmer's certificate and key yourself. |
| **Valkey** | farmer (heartbeats, enrollment replay cache), saasapi (rate limits, `connected`) | `/v1/enroll` and `/v1/refresh` fail closed without it. Give farmer and saasapi the same address list. |
| **S3-compatible object storage** | farmer: recipes and job logs, in two different buckets | recipe and job requests fail until it's configured. |
| **Keycloak** | saasapi verifies the end-user JWTs the BFF forwards | saasapi won't authenticate anything without it. |

## Install on Kubernetes (recommended)

The two Helm charts are the tested, supported way to deploy imas. Their
READMEs are the full reference; this is the order to do things in.

1. **Create the NATS seed Secret in both namespaces.** The charts never
   generate seeds, and farmer and the bus must hold byte-identical copies.
   Six seeds: `operator`, `operator-signing`, `sys-account`, `tenant`,
   `tenant-signing`, `saasapi-user`. For an existing install, import the
   seeds farmer already has instead of generating new ones. See "Seeds" in
   both chart READMEs.
2. **Install the core chart**, `deploy/helm/farmer`. It deploys farmer and
   saasapi, and optionally bundled PXC, OpenBao (dev mode) and Valkey for an
   eval. `ci/default-values.yaml` is the eval example and
   `ci/external-values.yaml` is the production one. Set `bus.serviceName`,
   `bus.namespace`, and `bus.sproutBusURLs` (Envoy's external `wss://`
   address, which farmer hands to sprouts as `nats_urls`).
3. **Deliver saasapi's NATS credential.** A post-install Job has farmer mint
   saasapi's SYS-Account User JWT and write it to OpenBao. External Secrets
   syncs it into saasapi's Secret; without ESO (the eval), copy it by hand as
   the chart README shows.
4. **Install the DMZ chart**, `deploy/helm/nats`. It deploys farmerbus and
   Envoy. It needs a bus TLS certificate and a DMZ edge certificate for
   Envoy. Point `envoy.upstreams.farmerAPI.host` at the core farmer Service.
   `TestContractWithNatsChart` in the core chart checks that the two
   charts' settings line up.
5. **Check it:** `kubectl logs` for farmer should show the gateway JWT
   signer and fleet signing key configured, and a connection to the bus.
   saasapi logs `connected to the NATS bus`.

Then [create a tenant](#create-a-tenant-and-an-enrollment-key).

## Install on Linux hosts with systemd

This works, but it's more manual than Helm, and two components have no
package or unit. Everything the charts wire together, you wire yourself.

### farmer

The deb/rpm/apk package installs `/usr/bin/imas-farmer`, the `farmer` user,
`/etc/imas/pki/farmer/`, `/var/cache/imas/farmer/`, a config template at
`/etc/imas/farmer`, and the systemd unit
[`packaging/systemd/imas-farmer.service`](../packaging/systemd/imas-farmer.service).
That unit is the canonical one; `.goreleaser.yaml` packages only from
`packaging/systemd/`.

To install by hand instead:

```bash
install -m 0755 bin/farmer /usr/bin/imas-farmer
install -m 0644 packaging/systemd/imas-farmer.service /etc/systemd/system/imas-farmer.service
useradd --system farmer
install -d -o farmer -g farmer /etc/imas/pki/farmer /var/cache/imas/farmer
```

The unit runs farmer as `farmer` with `ProtectSystem=strict`, so the only
writable paths are `/etc/imas/pki/farmer` and `/var/cache/imas/farmer`.
Write `/etc/imas/farmer` before starting the service (start from
`packaging/etc/imas-farmer.conf`). The unit's `IMAS_CONFIG` variable isn't
read by the code: farmer always uses `/etc/imas/farmer`.

Settings that differ from the pre-SaaS install:

```yaml
farmerinterface: 0.0.0.0              # bind address only
farmerapiport: 5405
farmerbusurl: tls://bus.example.internal:5406   # where farmer dials farmerbus
farmerorganization: <your org>         # must match the bus's
pxcdsn: farmer_svc:<pw>@tcp(pxc:3306)/farmer?parseTime=true
valkeyaddrs: valkey:6379
s3endpoint: s3.example.internal
s3bucket: imas-recipes
s3jobbucket: imas-jobs                 # must differ from s3bucket
sproutbusurls:                         # nats_urls handed to sprouts at enrollment
  - wss://gateway.example.com:8443
```

Each of those keys can also be set from the environment (`IMAS_PXC_DSN`,
`IMAS_VALKEY_ADDRS`, `IMAS_S3_*`, `IMAS_SPROUT_BUS_URLS`, `FARMERBUSURL`).
The OpenBao clients are configured only from the environment. Put them in a
drop-in (`systemctl edit imas-farmer`), and use a token that carries only
that client's policy:

```ini
[Service]
Environment=IMAS_CERTS_OPENBAO_ADDR=https://openbao:8200
Environment=IMAS_CERTS_OPENBAO_ROLE=imas-farmer
Environment=IMAS_GATEWAY_OPENBAO_ADDR=https://openbao:8200
Environment=IMAS_FLEETSIGN_OPENBAO_ADDR=https://openbao:8200
Environment=IMAS_TENANTBOX_OPENBAO_ADDR=https://openbao:8200
# ...and each client's _TOKEN (or _AUTH_METHOD=kubernetes), _CACERT, etc.
```

The policies to create are in
[`deploy/helm/farmer/README.md`](../deploy/helm/farmer/README.md), "OpenBao".
The Transit key setup is in [`deploy/envoy/README.md`](../deploy/envoy/README.md).
Without `IMAS_CERTS_OPENBAO_*`, place `tls-cert.pem`, `tls-key.pem` and
`tls-rootca.pem` in `/etc/imas/pki/farmer/` yourself: farmer no longer
generates a self-signed CA.

```bash
systemctl daemon-reload
systemctl enable --now imas-farmer
```

### farmerbus

No package or unit ships for farmerbus. It reads the same `farmer` config
file and PKI directory as farmer, and needs the same NATS seeds. If you run
it under systemd, base a unit on `packaging/systemd/imas-farmer.service`
with `ExecStart=` pointed at the farmerbus binary. What it needs is in
[`deploy/helm/nats/README.md`](../deploy/helm/nats/README.md) ("Seeds",
"Bus TLS"). In production it belongs on a DMZ host, reachable by core on
`:5406` and by Envoy on `:5407`, and by nothing else.

### saasapi

No package or unit ships for saasapi either. It's configured entirely from
environment variables; the table is in
[`api/saasapi.md`](api/saasapi.md#configuration). It needs its own NATS User
credential, which farmer mints (`imas-farmer publish-saasapi-credential`,
described in [`deploy/farmer/README.md`](../deploy/farmer/README.md)). It
serves plain HTTP on `:8081`, so put TLS in front of it.

### Envoy

Use [`deploy/envoy/envoy.yaml`](../deploy/envoy/envoy.yaml) with an Envoy
build that supports EdDSA in `jwt_authn`. The config is tested against the
official v1.34.1 and v1.35.3 release builds, and the Helm chart pins
v1.35.3. Replace the placeholders first: the DMZ edge certificate paths and
the `farmer.internal` upstreams. [`deploy/envoy/README.md`](../deploy/envoy/README.md)
covers them, plus sizing the `/v1/refresh` rate-limit bucket.

## Create a tenant and an enrollment key

Tenants and enrollment keys are created through the SaaS API. Every call
needs the BFF's shared secret and a Keycloak user JWT whose
`organization.id` matches the tenant (see [`api/saasapi.md`](api/saasapi.md#authentication)).

```bash
H=(-H "X-Internal-Auth: $INTERNAL_SECRET" -H "Authorization: Bearer $USER_JWT" -H "Content-Type: application/json")

# 1. Create the tenant. Asynchronous: 202, status "pending".
curl -s "${H[@]}" -X POST https://saasapi.example.internal/v1/tenants -d '{"name":"Acme"}'
# {"tenant_id":"t_mfrggzdfmztwq2lk","status":"pending"}

# 2. Poll until "active" (farmer provisions the tenant's NATS Account).
curl -s "${H[@]}" https://saasapi.example.internal/v1/tenants/t_mfrggzdfmztwq2lk/status

# 3. Mint an enrollment key: valid for 24 hours, up to 50 sprouts.
curl -s "${H[@]}" -X POST https://saasapi.example.internal/v1/tenants/t_mfrggzdfmztwq2lk/enrollment-keys \
  -d '{"expires_in_hours":24,"max_uses":50}'
# {"key_id":"ek_…","registration_key":"ek_….<secret>","expires_at":"…","max_uses":50}
```

`registration_key` is the join token. It's shown only once: saasapi stores
just its hash. Treat it as a secret. List keys with
`GET .../enrollment-keys` and revoke one with
`DELETE .../enrollment-keys/{key_id}`.

## Install and enroll a sprout

A sprout runs as root (or LocalSystem on Windows) so it can manage the whole
system.

**Linux.** Install the `imas-sprout` package. It ships
[`packaging/systemd/imas-sprout.service`](../packaging/systemd/imas-sprout.service)
and `/usr/bin/imas-sprout`. By hand:

```bash
install -m 0755 bin/sprout /usr/bin/imas-sprout
install -m 0644 packaging/systemd/imas-sprout.service /etc/systemd/system/imas-sprout.service
install -d /etc/imas/pki/sprout /var/cache/imas/sprout
```

**Windows.** Install the MSI (`imas-sprout`), or use winget from the
`imasnget` feed. Either one registers the `imas-sprout` service. The config
lives under `%ProgramData%\imas`. `imas-sprout install` / `uninstall` /
`start` / `stop` / `status` manage the service by hand.

**Configure it.** The sprout talks only to Envoy. Put the CA that issued
Envoy's DMZ edge certificate at `/etc/imas/pki/sprout/tls-rootca.pem`, then
write `/etc/imas/sprout`:

```yaml
farmerinterface: gateway.example.com   # Envoy's external name
farmerapiport: 8443                     # Envoy's listener, not farmer's 5405
sproutrootcatofu: false                 # use the pre-placed CA; never trust on first use
jointoken: ek_….<secret>                # the registration_key from above
```

The join token can instead come from the `IMAS_JOIN_TOKEN` environment
variable or `imas-sprout --join-token`. The flag wins over the variable,
and the variable wins over the file. `imas-sprout` refuses to run a first
enrollment without one.

```bash
systemctl daemon-reload
systemctl enable --now imas-sprout
```

**What happens on first start.**

1. The sprout generates its NKey and its X25519 box keypair locally. Neither
   private key ever leaves the host.
2. It calls `POST /v1/enroll` through Envoy with the join token, its public
   keys and hostname, and a signature proving it holds the NKey seed.
3. farmer redeems one use of the key and accepts the sprout into the key's
   tenant. It answers with the sprout's NATS User JWT, a gateway JWT, the
   tenant's X25519 public key, the fleet signing keys and the `wss://`
   `nats_urls`. The sprout ID is the one the sprout asked for (its
   `sproutid`, by default derived from the hostname), normalized, and
   suffixed (`_1`, `_2`, …) if that name is already taken in the tenant.
4. The sprout writes all of that under `/etc/imas/pki/sprout/`, deletes
   `jointoken` from its config file, and connects to the bus over `wss://`
   through Envoy.

If the token came from the environment or the flag, the sprout can't delete
it and logs a warning: remove it yourself. A failed enrollment is retried
with backoff, and retries don't spend another use of the key. Every failure
looks the same from outside (`401 enrollment_failed`); farmer's log has the
reason.

**Link it to your asset.** To address the sprout through the SaaS API, link
it to your CloudXP asset id:

```bash
curl -s "${H[@]}" -X POST \
  https://saasapi.example.internal/v1/tenants/t_mfrggzdfmztwq2lk/sprouts/web-01/asset-link \
  -d '{"asset_id":"vm-001"}'
curl -s "${H[@]}" "https://saasapi.example.internal/v1/tenants/t_mfrggzdfmztwq2lk/sprouts?asset_ids=vm-001"
# {"results":[{"sprout_id":"web-01","asset_id":"vm-001","key_state":"accepted","connected":true}],"unresolved":[]}
```

## The imas CLI

The CLI still authenticates to farmer with its own keypair, and it is
optional for SaaS operation.

1. Put `imas` on your `PATH`.
2. In `~/.config/imas/imas`, set `farmerinterface` and `farmerapiport` to
   farmer's API address, and `farmerbusurl` to the bus (for example
   `tls://bus.example.internal:5406`). The CLI dials the bus from there; it
   doesn't assume the bus is on the API host.
3. Run `imas auth privkey` to generate a key and pin farmer's TLS
   certificate, then `imas auth pubkey` to print the public key.
4. Add it on farmer and restart farmer:

   ```yaml
   pubkeys:
     admin:
       - <YOUR PUBKEY>
   ```

5. Run `imas version` to check you're authenticated.

## Ports

| Port | Listener | Who connects |
|---|---|---|
| 8443 | Envoy (HTTPS and WSS) | sprouts, from anywhere |
| 5407 | farmerbus websocket | Envoy only |
| 5406 | farmerbus TLS NATS | farmer and saasapi (core dials out to the DMZ) |
| 5405 | farmer HTTPS API | Envoy (`/v1/enroll`, `/v1/refresh`, JWKS, `/files/`) and the CLI |
| 8081 | saasapi HTTP | the BFF, through your TLS terminator |

Sprouts never connect to 5405, 5406 or 5407 directly. The core never
accepts a connection from the DMZ bus: its only inbound DMZ traffic is
Envoy's forwarded HTTPS on 5405.

## Coming from the single-tenant install

The old instructions ran one `farmer` that embedded the bus, generated its
own CA, and had an operator accept each sprout's key with `imas keys accept`.
That model no longer applies:

- The bus is a separate process (`farmerbus`), and sprouts reach it only
  through Envoy.
- farmer needs PXC, and gets its TLS certificate from OpenBao PKI or from
  files you place.
- A sprout needs a join token for its first enrollment. Presenting a valid
  one is the approval, so there is no pending-key step.
- Sprouts pin a pre-provisioned CA (`sproutrootcatofu: false`) rather than
  fetching farmer's over TOFU, because Envoy doesn't route `/auth/cert/`.
- The systemd units are `packaging/systemd/imas-{farmer,sprout}.service`,
  with binaries in `/usr/bin` and hardening directives. The old copies in
  `docs/` are gone.
