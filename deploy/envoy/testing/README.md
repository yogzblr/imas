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
