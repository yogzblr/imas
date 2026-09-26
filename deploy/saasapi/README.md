# saasapi deployment reference: enrollment-key rate limit

Same precedent as `deploy/farmer/` and `deploy/envoy/`: these are reviewed
*reference* files. **saasapi's real Deployment and Helm chart are not in
this repo.** They live in the separate ops repo. Nothing in imas applies
or renders the YAML here.

| File | What it is |
|---|---|
| `values.rate-limit.yaml` | Values block to merge into the chart's `values.yaml` |
| `deployment.env.rate-limit.yaml` | Template fragment to paste under the saasapi container's `env:` list |

## What it configures

`POST /v1/tenants/{tenant_id}/enrollment-keys` is rate-limited per tenant
(keyed by the verified JWT's `organization.id`). These env vars tune it,
all read once at startup by `saasapi.LoadConfig`:

| Env var | Helm value | Default | Valid values |
|---|---|---|---|
| `SAASAPI_ENROLLMENT_KEY_RATE_LIMIT` | `enrollmentKeys.rateLimit.perSecond` | `1` | decimal > 0 (`0.5` = one every 2 s) |
| `SAASAPI_ENROLLMENT_KEY_RATE_BURST` | `enrollmentKeys.rateLimit.burst` | `5` | integer >= 1 |
| `SAASAPI_VALKEY_ADDRS` | `valkey.addrs` (list) | unset | comma-separated `host:port` |

A tenant that exceeds the limit gets `429` with error code `rate_limited`.

## Shared across pods via Valkey

With `valkey.addrs` set, the limit is enforced across **all** saasapi
pods together: a tenant gets `perSecond`/`burst` in total, however many
replicas run and however the load balancer spreads its requests. Set it in
any deployment with more than one replica (or an HPA).

- **State:** one key per tenant, `imas:saasapi:ratelimit:enrollment-keys:<tenant_id>`,
  holding a single integer and a TTL of at most `burst / perSecond`
  seconds. Idle tenants cost nothing. The prefix keeps it clear of
  farmer's `imas:heartbeat:` keys if the two share a Valkey.
- **Atomic:** the check-and-update is one Lua script (GCRA), so
  concurrent requests on different pods can't both take the last token.
- **Clock:** time comes from Valkey's `TIME`, not the pods' clocks, so
  clock skew between pods doesn't matter.
- **Valkey unreachable at startup:** saasapi exits with an error, and
  Kubernetes' restart backoff retries. A pod that quietly ran per-pod
  for its whole life would multiply the limit by the replica count
  without anyone noticing.
- **Valkey fails mid-flight** (error, or no answer within 250 ms): that
  request is decided by the pod's own in-memory limiter, at the same rate
  and burst, and a warning is logged. Issuance stays available and stays
  bounded, but only per pod (see below) until Valkey is back.
- **No auth or TLS** on the connection yet, matching farmer's Valkey
  client. Restrict network access to Valkey (e.g. a NetworkPolicy)
  accordingly.

## Without Valkey the limit is per pod

With `valkey.addrs` empty (and during a Valkey outage, as above), each
replica keeps its own buckets. With `replicaCount: N` behind a load
balancer that spreads a tenant's requests evenly, the tenant's effective
limit is up to **N x** the configured rate and burst. That's fine for a
single replica or local development.

## How bad values fail

- **Unset or null** in values: the fragment emits no env var and saasapi
  uses the default.
- **Fractional burst** (e.g. `2.5`): `helm template`/`helm upgrade` fails
  with `enrollmentKeys.rateLimit.burst must be a whole number`.
- **Anything else invalid** (`0`, negative, not a number): the pod fails
  at startup with an error naming the env var, instead of quietly
  running with a default. With `helm upgrade --atomic` or a readiness
  gate, the rollout stops there.

## Changing the values

Env vars are read only at startup, so a new value takes effect when the
Deployment rolls. Changing the Helm value changes the pod template, and
`helm upgrade` rolls it. With Valkey, existing per-tenant state carries
over (a new rate or burst applies to it from the next request); without
Valkey, each new pod starts with full buckets.
