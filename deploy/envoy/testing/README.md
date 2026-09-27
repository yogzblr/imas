# Real-Envoy tests

Two tests run a real Envoy binary on `../envoy.yaml`, rendered by
`internal/envoytest` with only its deployment placeholders (listener
port, DMZ cert paths, `farmer.internal` upstreams, admin port) pointed at
local listeners. A placeholder that doesn't occur exactly as often as
expected fails the test, so the shipped file is what's tested. In both,
the sprout talks only to Envoy.

- `internal/pki/envoy_e2e_test.go`: a sprout's whole life. It enrolls
  through `/v1/enroll` (real `EnrollSprout` → `Enroll`, NKey proof of
  possession), connects through `pki.LoadSproutBus` (what `ConnectSprout`
  uses: the `nats_urls` persisted at enrollment, here Envoy's `wss://`
  address, with SproutRootCA-pinned TLS, User JWT + seed and the gateway
  JWT header) to the real operator-mode bus's websocket listener and
  round-trips a message, checks that the legacy `FarmerBusURL` (TLS NATS
  to Envoy's HTTPS listener) does not connect, refreshes through
  `/v1/refresh` (real `RefreshGatewayJWT` → `RefreshSprout`) and
  reconnects with the new token, and downloads a recipe through `/files/`
  (`FetchFarmerFile`). It also checks Envoy's own 401 for a missing,
  expired or forged token on the upgrade.
- `internal/api/envoy_e2e_test.go`: the staged-recipe download
  (`cook.FetchStagedRecipe`) against farmer's real router, with `Auth` on
  its production key source, the same signer the router's JWKS endpoint
  serves Envoy. Envoy and farmer both verify the token. A token Envoy
  rejects is refreshed through Envoy and retried. Bad tokens never reach
  farmer. A validly signed token for another sprout passes Envoy and is
  refused by farmer's scoping.

OpenBao Transit is mocked (`internal/gatewayjwt/transittest`). Both tests
are skipped unless `IMAS_TEST_ENVOY_BIN` is set:

```
curl -Lo envoy https://github.com/envoyproxy/envoy/releases/download/v1.34.1/envoy-1.34.1-linux-x86_64
chmod +x envoy
IMAS_TEST_ENVOY_BIN=$PWD/envoy go test ./internal/pki/ ./internal/api/ -run ThroughRealEnvoy -v
```

Set `IMAS_TEST_ENVOY_LOG_LEVEL=debug` to see Envoy's `jwt_authn`
decisions. Validated against the official v1.34.1 and v1.35.3 release
builds.

# Keycloak validation harness

A way to confirm, using an independent, real-world OIDC implementation
(not code this repo wrote), that `internal/gatewayjwt`'s served JWKS
document is something a standard identity broker actually accepts —
closer to what Envoy's own `jwt_authn` filter does than any hand-rolled
check could be. This is what the "configure keycloak in sandbox and run
the tests for jwks" request (see the PR description) asked for.

## Why this wasn't run for you already

This harness needs to pull `quay.io/keycloak/keycloak`. The sandbox this
code was written in blocks that registry at the network-policy level (see
the PR description's account of the earlier attempt — Docker itself ran
fine, but every container-registry CDN tried, including quay.io's, came
back `403` from the proxy). Run this wherever that restriction doesn't
apply.

What *was* validated in this sandbox, without needing Keycloak or any
container registry: `internal/gatewayjwt/mint_test.go` and `jwks_test.go`
mint a real gateway JWT and serve a real JWKS document, then verify both
against `github.com/lestrrat-go/jwx/v2` — a genuine, independent JOSE
implementation, checking the same things Keycloak's OIDC identity-
provider machinery would (signature validity, `alg: EdDSA`, RFC 7517/8037
JWK shape, rotation-overlap key sets, tampered/expired-token rejection).
That test suite is real, executable, evidence; this harness is the
additional, heavier check using a second, independent implementation
maintained by neither this repo nor jwx's author.

## Running it

1. Stand up farmer with a real (or `vault server -dev`) OpenBao Transit
   instance configured — see `../README.md`'s "OpenBao Transit key"
   section for the exact `vault write` commands and the
   `IMAS_GATEWAY_OPENBAO_*` env vars farmer needs.
2. Edit `keycloak-realm.json`'s `identityProviders[0].config.jwksUrl` to
   point at that farmer's actual, network-reachable
   `/v1/.well-known/jwks.json` address.
3. `docker compose -f docker-compose.keycloak.yml up`
4. Open the Keycloak admin console (`http://localhost:8080`, `admin` /
   `admin` from the compose file) → the `imas-gateway-jwt-validation`
   realm → Identity Providers → `imas-gateway`. Keycloak fetches and
   parses the JWKS at startup (via `import-realm`); if the document were
   malformed, this page will show an error rather than the imported
   config.
5. To confirm actual *signature* validation (not just JWKS parsing),
   mint a gateway JWT (`internal/gatewayjwt.MintGatewayJWT`, or a real
   `POST /v1/enroll` call against farmer) and exercise Keycloak's
   identity-provider token-exchange/brokered-login flow with it — the
   exact steps depend on the Keycloak version in use; consult Keycloak's
   own "Identity brokering" docs for driving that flow via its Admin REST
   API rather than the browser UI, if you want this scripted for CI.
   That last mile — full automation of step 5 — was left for whoever runs
   this outside the sandbox, rather than guessed at without a real
   Keycloak instance to check the exact request/response shapes against.
