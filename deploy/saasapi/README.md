# saasapi deployment reference: enrollment-key rate limit

Same precedent as `deploy/farmer/`: these are the reviewed *reference*
files. **The chart that deploys saasapi is `deploy/helm/farmer`**, which
runs it next to farmer on the same Valkey. The chart takes these values
under `saasapi.` (`saasapi.enrollmentKeys.rateLimit.*`; `valkey.addrs`
keeps its name and is used for an external Valkey), and ports the env
fragment with the same semantics.
`TestSaasapiRateLimitEnv` in its `chart_test.go` pins them together.

| File | What it is |
|---|---|
| `values.rate-limit.yaml` | The values block (`enrollmentKeys` is `saasapi.enrollmentKeys` in `deploy/helm/farmer`) |
| `deployment.env.rate-limit.yaml` | The env fragment, as ported into `deploy/helm/farmer/templates/saasapi-deployment.yaml` |

## What it configures

`POST /v1/tenants/{tenant_id}/enrollment-keys` is rate-limited per tenant
(keyed by the verified JWT's `organization.id`). These env vars tune it,
all read once at startup by `saasapi.LoadConfig`:

| Env var | Helm value | Default | Valid values |
|---|---|---|---|
| `SAASAPI_ENROLLMENT_KEY_RATE_LIMIT` | `enrollmentKeys.rateLimit.perSecond` | `1` | decimal > 0 (`0.5` = one every 2 s) |
| `SAASAPI_ENROLLMENT_KEY_RATE_BURST` | `enrollmentKeys.rateLimit.burst` | `5` | integer >= 1 |
| `SAASAPI_VALKEY_ADDRS` | `valkey.addrs` (list) | unset | comma-separated `host:port` |
| `SAASAPI_VALKEY_PASSWORD_FILE` | `valkey.auth.*` (the file `/var/run/secrets/imas/valkey/password`) | set by the chart | path of the password file (Secret `imas-valkey-auth`) |
| `SAASAPI_VALKEY_TLS` | `valkey.tls.enabled` | `false` | `true` or `false` |
| `SAASAPI_VALKEY_TLS_CA_FILE` | `valkey.tls.caConfigMap` / `caKey` | unset | path of a PEM CA bundle; required with TLS |
| `SAASAPI_VALKEY_TLS_SERVER_NAME` | `valkey.tls.serverName` | unset | name to verify the certificate against |

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
- **Password and TLS:** saasapi authenticates as Valkey user `default`
  with the password read once at startup from
  `SAASAPI_VALKEY_PASSWORD_FILE` (a Secret mounted as a file; never an env
  var), and with `SAASAPI_VALKEY_TLS=true` connects with TLS 1.2 or
  later, verifying the server against `SAASAPI_VALKEY_TLS_CA_FILE` only.
  A password file that is missing or empty, or TLS without a usable CA,
  stops it at startup. Rotation is a pod restart. Same settings as
  farmer's `IMAS_VALKEY_*` (`internal/valkeyconn`; `deploy/helm/farmer`
  README, "Valkey"). After connecting it reads `INFO memory` and warns if
  Valkey may evict keys. Restrict network access to Valkey (e.g. a
  NetworkPolicy) all the same.

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
