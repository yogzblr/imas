# Envoy DMZ gateway (workstream H)

`envoy.yaml` is the reference config for
`docs/design/imas-envoy-enrollment-design.md` — Envoy sitting at the DMZ
edge in front of nats-server's websocket listener and a recipe-download
route, both gated by `jwt_authn`, plus an ungated, rate-limited
`/v1/enroll` route. Read the file's own header comment first; this file
covers what a deployer needs to fill in before it's usable.

**FLAG FOR SECURITY REVIEW** — see the task brief this was built from.
Treat this as a reviewed starting point, not a drop-in production config.

## Before deploying this

- **TLS material**: `/etc/envoy/tls/dmz-cert.pem`/`dmz-key.pem` are
  placeholder paths for the DMZ edge's own downstream certificate (what
  sprouts' `wss://` connections terminate against) — not farmer's own
  cert (`config.CertFile`/`KeyFile`), which is used for the *upstream*
  hop to farmer/nats-server instead. Sprouts behind this Envoy pin the CA
  that issued `dmz-cert.pem`: the enrollment tooling writes it to each
  sprout's `sproutrootca` path and sets `sproutrootcatofu: false`. There
  is deliberately no `/auth/cert/` route here for sprouts to fetch it by
  trust on first use (see "Root CA" in
  `docs/design/imas-envoy-enrollment-design.md`).
- **Upstream hostnames**: `farmer.internal` throughout the `clusters:`
  section is a placeholder. Point it at wherever farmer/nats-server
  actually run relative to this Envoy instance.
- **Ports**: `5405` (farmer API / recipe download interim target) and
  `5407` (nats-server websocket) match this repo's config defaults
  (`config.FarmerAPIPort`, `config.FarmerWSPort`) — keep them in sync if
  those are overridden at deploy time.
- **OpenBao Transit key**: `remote_jwks` now points at a real, built
  endpoint (`internal/api/handlers/jwks.go`, `GET
  /v1/.well-known/jwks.json`), but that endpoint serves whatever
  `internal/gatewayjwt` signs with — which requires an OpenBao Transit
  Ed25519 key to exist before farmer can mint or serve anything real. See
  `internal/gatewayjwt/obtransit.go`'s `IMAS_GATEWAY_OPENBAO_*` env vars
  and the ops prerequisite in the "Gateway JWT Companion Token"
  implementation brief this package was built from:
  ```
  vault secrets enable transit   # or: bao secrets enable transit
  vault write -f transit/keys/imas-gateway-jwt type=ed25519
  vault write transit/keys/imas-gateway-jwt/config auto_rotate_period=2160h
  ```
  Until that key exists and farmer's `IMAS_GATEWAY_OPENBAO_*` env vars
  are set, farmer starts fine (see `cmd/farmer/main.go`'s
  `initGatewaySigner` — deliberately non-fatal) but `POST /v1/enroll`
  fails closed with the generic `enrollment_failed` response, and the two
  `jwt_authn`-gated routes below reject every connection. Both are safe
  failure modes, not a functional end-to-end config on their own.
- **Envoy version**: confirm the deployed Envoy build supports `EdDSA` in
  `jwt_authn` (added in a relatively recent release) — gateway JWTs are
  Ed25519-signed, not RS256/ES256. This config is tested end to end
  against the official Envoy v1.34.1 release build (see
  `testing/README.md`); pin that or a later version. That testing is what
  caught the missing `requirement_map` that made every gated route answer
  403. The Keycloak harness in `testing/` (a second, independent JWKS
  consumer) still hasn't been run.
- **Recipe route target**: `/files/` proxies to farmer's own
  `GET /files/<key>` (`internal/api/handlers/recipes.go`'s `GetFile`), the
  sprout-facing download path. Farmer re-verifies the forwarded gateway
  JWT and serves only keys under that sprout's own
  `sprouts/<tenant_id>/<sprout_id>/` prefix. `/v1/recipes` (the CLI and
  web UI browse endpoints) is deliberately not routed: it accepts only the
  CLI's RBAC token, never a gateway JWT. `docs/design/imas-fork-roadmap.md`
  workstream I describes a dedicated, non-DMZ recipe service this route
  is meant to front instead. Repoint the `recipe_service` cluster once that
  exists.
- **Rate limiting on `/v1/enroll`**: the `local_ratelimit` bucket here is
  per Envoy process: one bucket shared by all of that Envoy's worker
  threads (Envoy's default, since `local_rate_limit_per_downstream_connection`
  is unset), so with N replicas the fleet-wide budget is N × 20 per
  minute. Real protection at scale needs a shared/global rate-limit
  service, not this config alone.
- **Rate limiting on `/v1/refresh`**: its own bucket, sized from the
  fleet. See "Sizing the /v1/refresh bucket" below before deploying.

## Sizing the /v1/refresh bucket

`POST /v1/refresh` is how an enrolled sprout renews its short-lived
gateway JWT. It gets its own route and its own `local_ratelimit` bucket,
never `/v1/enroll`'s, because the two need opposite budgets:

| Route | Authenticated by | Volume | Budget |
|---|---|---|---|
| `/v1/enroll` | the join token only | an Ansible rollout at a time | small and fixed (20 per 60 s per Envoy): it is what bounds join-token guessing |
| `/v1/refresh` | a request sealed with the sprout's box key, opened by farmer (the reply is sealed back) | every sprout, every ~⅔ of the TTL | large, sized from fleet size ÷ TTL |

Both buckets are **per Envoy process** (shared by its worker threads;
Envoy's default) and **per route** (Envoy builds a separate bucket for
each route-level `local_ratelimit` config). `/v1/refresh` has no
`jwt_authn` gate: a sprout that was powered off past its TTL holds only
an expired gateway JWT and must still be able to renew it.

### The math

A sprout refreshes when its token is ⅔ of the way through its lifetime,
minus up to 1/10 of the lifetime of random jitter
(`internal/pki/enrollclient.go`, `gatewayRefreshDelay`). So the time
between one sprout's refreshes is between 17/30 and 20/30 of the TTL.
Size for the shortest interval, 17/30 × TTL:

```
fleet-wide refreshes/s   R = fleetSize / (17/30 × TTL)
                           = 30 × fleetSize / (17 × TTL)

per-Envoy refreshes/s    r = R × headroom / envoyReplicas

tokens_per_fill          = ceil(r × fill_interval)
max_tokens               = tokens_per_fill × (burstSeconds / fill_interval)
```

- **TTL** is farmer's `gatewayjwtttl` (`config.GatewayJWTTTL`), in
  seconds. Halving the TTL doubles the load.
- **headroom** (a whole number, default 2) covers uneven load balancing,
  losing a replica, and sprouts catching up after an outage.
- **max_tokens** is the burst Envoy absorbs before returning `429`
  (default: 5 minutes' worth). A rate-limited sprout backs off (up to
  5 minutes) and retries; its token expires only if refreshes keep
  failing for roughly the last third of its lifetime (8 h at a 24 h TTL).
  So an undersized bucket shows up as `429`s and delayed refreshes first,
  and as expired tokens only if it stays undersized.

### Worked examples (fill_interval 1 s, burst 300 s, headroom 2)

| Fleet | TTL | Envoy replicas | R (fleet-wide) | tokens_per_fill (per Envoy) | max_tokens |
|---|---|---|---|---|---|
| 1,000,000 | 24 h | 4 | 20.4/s (1,225/min) | **11** | 3,300 |
| 1,000,000 | 1 h | 4 | 490/s | 246 | 73,800 |
| 100,000 | 24 h | 2 | 2.0/s | 3 | 900 |

The first row is what `envoy.yaml` ships with. Compare `/v1/enroll`: 20
per 60 s is 0.33/s per Envoy, about 1/30 of the first row.

**Farmer has to keep up too.** Each refresh is a PXC lookup, a few NaCl
box opens and one seal (against the tenant's key set, read from OpenBao
KV and cached for a minute), a Valkey `SET NX` claiming the request, and
an OpenBao Transit `sign` call. Size farmer and the Transit backend for R ×
headroom, not just the Envoy bucket; raising the bucket past what they
can serve only moves the `429`s to `5xx`s.

### Setting it

`envoy.yaml` is static. In a Helm-rendered deployment (the ops repo's
Envoy chart, as with `deploy/saasapi/`):

| File | What it is |
|---|---|
| `values.rate-limit.yaml` | `envoy.refreshRateLimit` values block to merge into the chart's `values.yaml` |
| `_refresh-rate-limit.tpl` | Named templates rendering the `/v1/refresh` route and computing its bucket; include `imas.envoy.refreshRoute` in the Envoy config's route list |

`tokens_per_fill` and `max_tokens` are computed from `fleetSize`,
`gatewayJwtTtlSeconds`, `envoyReplicas`, `headroom`, `fillIntervalSeconds`
and `burstSeconds`, unless `tokensPerFill`/`maxTokens` are set
explicitly. Missing, zero or fractional inputs fail `helm template`
with a message naming the value. The `/v1/enroll` bucket is deliberately
not a value: it should not grow with the fleet.

## What this pairs with in the Go codebase

- `internal/api/handlers/enroll.go` / `internal/api/routers.go` — the
  farmer-side `POST /v1/enroll` handler this config's enroll route
  proxies to.
- `internal/api/handlers/refresh.go` / `internal/pki/refreshsealed.go` —
  the farmer-side `POST /v1/refresh` handler, which opens the sprout's
  sealed request and seals its reply, behind this config's refresh route.
- `internal/pki/enroll.go` — the token validation, atomic redemption, and
  minting logic behind that handler (mints both the native NATS JWT and,
  via `internal/gatewayjwt`, the gateway JWT).
- `internal/gatewayjwt` — mints the gateway JWT (`mint.go`), talks to
  OpenBao Transit (`obtransit.go`, `signer.go`), and serves the JWKS
  document (`jwks.go`) this config's `remote_jwks` fetches.
- `internal/pki/nats.go`'s `ConfigureNats` — the nats-server websocket
  listener (`config.FarmerWSPort`) this config's default route proxies
  to.
