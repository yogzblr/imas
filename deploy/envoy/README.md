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
  hop to farmer/nats-server instead.
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
  Ed25519-signed, not RS256/ES256. `internal/gatewayjwt`'s own tests
  (`mint_test.go`) validate the minted token and served JWKS against
  `jwx` (an independent, standards-compliant Go JOSE library) as the
  closest check achievable without a live Envoy/Keycloak instance in this
  environment's sandboxed network — see the PR description for why an
  actual Keycloak/Envoy run wasn't possible here, and re-run that
  validation somewhere with normal network access before relying on this
  config in production.
- **Recipe route target**: `/v1/recipes` currently proxies to farmer's own
  `GET /files/` (`internal/api/handlers/recipes.go`) as the nearest
  existing analogue. `docs/design/imas-fork-roadmap.md` workstream I
  ("Recipe storage migration") describes a dedicated, non-DMZ recipe
  service this route is meant to front instead — repoint the
  `recipe_service` cluster once that exists.
- **Rate limiting on `/v1/enroll`**: the `local_ratelimit` filter here is
  per-Envoy-worker and per-instance — real protection at scale (multiple
  Envoy replicas) needs a shared/global rate-limit service, not this
  config alone.

## What this pairs with in the Go codebase

- `internal/api/handlers/enroll.go` / `internal/api/routers.go` — the
  farmer-side `POST /v1/enroll` handler this config's enroll route
  proxies to.
- `internal/pki/enroll.go` — the token validation, atomic redemption, and
  minting logic behind that handler (mints both the native NATS JWT and,
  via `internal/gatewayjwt`, the gateway JWT).
- `internal/gatewayjwt` — mints the gateway JWT (`mint.go`), talks to
  OpenBao Transit (`obtransit.go`, `signer.go`), and serves the JWKS
  document (`jwks.go`) this config's `remote_jwks` fetches.
- `internal/pki/nats.go`'s `ConfigureNats` — the nats-server websocket
  listener (`config.FarmerWSPort`) this config's default route proxies
  to.
