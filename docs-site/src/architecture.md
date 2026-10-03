# Architecture

![imas architecture diagram](https://raw.githubusercontent.com/yogzblr/imas/main/docs/diagrams/imas-architecture.svg)

*(Diagram source: [`docs/diagrams/imas-architecture.svg`](https://github.com/yogzblr/imas/blob/main/docs/diagrams/imas-architecture.svg)
— hand-maintained and re-verified against the code, not the design docs, as
of the date noted in its own header comment.)*

## Components

| Component | Runs in | Role |
|---|---|---|
| **farmer** (`cmd/farmer`) | non-DMZ core | dispatches recipes to sprouts over NATS, owns the `farmer` schema in PXC |
| **saasapi** (`cmd/saasapi`) | non-DMZ core | the tenant-facing control-plane API — see [SaaS API reference](./api-reference.md) |
| **fleetreleaser** (`cmd/fleetreleaser`) | non-DMZ core | the only signer of fleet (sprout update) manifests; a stateless TLS service saasapi calls, with no database access |
| **migrate** (`cmd/migrate`) | non-DMZ core, Helm hook Job | creates the schemas and applies versioned goose migrations before farmer and saasapi start or upgrade |
| **farmerbus** (NATS) + **Envoy** | DMZ | the only thing sprouts ever connect to; Envoy validates a gateway JWT before traffic reaches nats-server |
| **sprout** (`cmd/sprout`) | managed VM / bare-metal host | the managed endpoint; connects outbound to the DMZ, applies recipes locally via [ingredients](./ingredients/index.md) |
| **imas CLI** (`cmd/imas`) | operator's machine | talks to saasapi/farmer to create tenants, enrollment keys, and dispatch recipes |

Only farmer, saasapi, fleetreleaser and the migration Job live in the non-DMZ core; the connection is always
outbound from core to the DMZ bus, never the reverse.

## Tenancy and identity

A sprout is enrolled into exactly one **tenant** using a one-time
**enrollment key** (a join token: tenant-scoped, short-lived, usage-capped).
Enrollment mints, in one response, the sprout's identity as **two paired
JWTs**: a NATS User JWT (`ed25519-nkey`, Account-signed — consumed only by
nats-server's own decentralized auth) and a standard EdDSA JWT
(gateway-signed — presented to Envoy). The two aren't interchangeable; NATS's
`ed25519-nkey` header algorithm isn't a registered JOSE algorithm, so a
standard JWT validator like Envoy's can't consume the NATS one directly. Full
identity-hierarchy rationale:
[`imas-nats-jwt-auth-design.md`](https://github.com/yogzblr/imas/blob/main/docs/design/imas-nats-jwt-auth-design.md),
[`imas-envoy-enrollment-design.md`](https://github.com/yogzblr/imas/blob/main/docs/design/imas-envoy-enrollment-design.md).

`sprout_id` is unique **per tenant only, never globally** — every table,
index, cache and map in the codebase keys on `(tenant_id, sprout_id)`.

## Storage

| Store | Holds | Notes |
|---|---|---|
| **PXC** (Percona XtraDB Cluster / MySQL 8) | durable metadata: PKI, RBAC, tenant accounts, sprout X25519 public keys | `farmer` and `saas` schemas, one PXC cluster; farmer has read access to the `saas` schema |
| **Valkey Cluster** | heartbeat / connection-state | fed from NATS connection lifecycle events; no tenant hash-tagging |
| **Object storage** (S3-compatible) | job logs, recipes | two separate buckets |
| **OpenBao** | operator/account signing keys, TLS cert issuance, per-tenant X25519 keypairs, fleet-release signing keys | see [`imas-sdb-secrets-design.md`](https://github.com/yogzblr/imas/blob/main/docs/design/imas-sdb-secrets-design.md), [`imas-payload-encryption-design.md`](https://github.com/yogzblr/imas/blob/main/docs/design/imas-payload-encryption-design.md) |

PXC (GPLv2, under commercial Percona agreement) and OpenBao (MPL-2.0) are the
two accepted exceptions to the project's Apache-2.0/MIT-only default for
everything else.

## Platform

Kubernetes for NATS, Valkey, farmer, and PXC, split across separate DMZ and
non-DMZ node pools/namespaces — never one flat cluster. Every binary builds
CGO-free.

## Further reading

This page is a map, not the full rationale. For *why* the platform is built
this way, see, in `docs/design/` on GitHub:

- [`imas-master-plan.md`](https://github.com/yogzblr/imas/blob/main/docs/design/imas-master-plan.md) — the phase-wise build plan and the "settled architecture" decisions it works from
- [`imas-fork-roadmap.md`](https://github.com/yogzblr/imas/blob/main/docs/design/imas-fork-roadmap.md) — per-workstream detail on what changed from the original grlx fork
- [`cloudxp-machine-manager-api-design.md`](https://github.com/yogzblr/imas/blob/main/docs/design/cloudxp-machine-manager-api-design.md) — the SaaS API's design (the [reference](./api-reference.md) here follows the shipped code where they differ)
