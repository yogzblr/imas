# imas: Envoy Gateway & Enrollment Subsystem

Companion to `imas-nats-jwt-auth-design.md`. Covers Phase 0 of `imas-master-plan.md` — the part of the plan called out as the single biggest structural dependency, since every later phase assumes the identity this subsystem issues is trustworthy.

## Implementation notes: Go libraries

**Gateway JWT construction + JWKS serving:** `github.com/lestrrat-go/jwx/v2` (MIT). Its `jws` package supports detached signing — build the signing input, get a signature from wherever (here, OpenBao Transit), assemble the compact token — rather than insisting on holding a local private key, which fits the Transit-based custody model directly. Its `jwk` package builds a correct OKP/Ed25519 JWK (`jwk.FromRaw()`) for the JWKS response without hand-rolling base64url encoding.

**OpenBao client:** `github.com/openbao/openbao/api/v2` (MPL-2.0, same accepted licensing exception already carved out for OpenBao itself), through `internal/openbao` — TLS, auth (static token, or kubernetes login repeated before the lease runs out) and error decoding against OpenBao's Transit `sign` endpoint, rather than hand-written HTTP calls. As built (CL.2a), requests are not retried, as before the switch.

**Libraries evaluated and rejected for this role:**
- `golang-jwt/jwt/v5` (MIT) — fine for parsing/verifying, but its `SigningMethodEdDSA` type-asserts on a concrete local `ed25519.PrivateKey`; no detached-signing path, so it fights the Transit custody model rather than fitting it.
- `gourdiantoken` (MIT) — a comprehensive access/refresh-token library (rotation, revocation, multi-tenant bulk revocation), but built around holding `PrivateKeyPEM` directly in its config and signing locally; no external-signer hook. Better fit for the SaaS API's own human-user login session layer (§1.7's open item) than for this gateway/NATS problem — separate decision, not pursued further here. Also young (single maintainer, several breaking changes within `v2.x` by the project's own admission) — worth weighing that against a well-established primitive if adopted for the human-auth case.
- `infamousjoeg/jwt-service` — confirms the two-endpoint (`generate-jwt` + `/.well-known/jwks.json`) shape is a reasonable pattern, but not adopted directly: built on the archived, unmaintained `dgrijalva/jwt-go`; RSA-only (no Ed25519, breaking consistency with NKeys/gateway-key/X25519 elsewhere in this design); and manages its own key generation/rotation in-process rather than deferring to an external KMS/HSM — the opposite of the Transit-backed custody model here. Its own README candidly notes thin documentation and test coverage.
- OpenBao's Identity/OIDC "identity token" feature (native ID-token issuance with an automatic JWKS and built-in rotation) was also considered and set aside for this specific role: it issues tokens about the *caller's own authenticated OpenBao entity*, which would require modeling one OpenBao entity per sprout — a second, duplicated identity store at odds with `farmer.sprouts`/PXC already being the source of truth, and not a scale shape OpenBao's identity store is built for at 1M sprouts. Worth keeping in mind for the SaaS API's own future human-user SSO/OIDC need (§1.7), a materially better-matched use case.

## Two gates, checking different things, not redundant with each other

Requirement set specified: Envoy in front of NATS doing JWT validation, each sprout holding a JWT to connect, and recipe download authenticating with the same JWT. **Revised from the original single-JWT framing** — that's not achievable as literally specified, because the two validators speak incompatible JWT profiles (see "Why one JWT can't serve both gates" below). What ships instead is one signing identity, expressed as two paired tokens, three surfaces:

1. **Envoy** — terminates the sprout's `wss://` connection at the DMZ edge, validates the **gateway JWT**'s signature/claims/expiry via a `jwt_authn` filter against a JWKS trust configuration, **before the connection ever reaches nats-server**.
2. **nats-server itself** — once past Envoy, the sprout presents its **NATS User JWT** for NATS's own native Account/User decentralized-auth model (see the companion doc), which enforces ongoing, per-subject publish/subscribe permissions for the life of the connection.
3. **Recipe HTTP endpoint** — the **gateway JWT** again, as a bearer token, validated by the same Envoy instance on a second route, which proxies the authenticated request through to a small non-DMZ recipe-service (never lets the DMZ side hold direct object-storage credentials).

These are complementary, not duplicated: Envoy's check is a one-time gate at connection establishment; NATS's own model enforces fine-grained, ongoing subject permissions Envoy has no visibility into at all. A security-relevant side effect worth being explicit about: Envoy rejecting malformed or unauthenticated connections before they reach nats-server directly mitigates the 2026 pre-auth websocket CVE class (memory-exhaustion DoS) discussed earlier — a compromised or malicious pre-auth payload targeting that class never touches nats-server's websocket listener at all.

## Why one JWT can't serve both gates

NATS's decentralized-auth JWTs (`nats-io/jwt` v2) use a non-standard header: `{"typ":"JWT","alg":"ed25519-nkey"}`. That `alg` value isn't a JOSE-registered algorithm (RFC 7518/8037 define `RS256`, `ES256`, `EdDSA`, etc.) — Envoy's `jwt_authn` filter is a generic JOSE validator with no NATS awareness, and rejects the `alg` field outright before it ever reaches signature or JWKS matching. So the NATS User JWT cannot be the token Envoy validates, as originally scoped.

**Resolution: mint two tokens from the same identity, at the same time.**
- **NATS User JWT** — unchanged from the companion doc's design: `ed25519-nkey` alg, Account-signed, consumed only by nats-server.
- **Gateway JWT** — a standard RFC 8037-compliant token (`alg: EdDSA`, key type `OKP`), signed by a **single, dedicated gateway signing key** (see below), carrying enough claims (tenant ID, sprout ID, expiry) for Envoy's `jwt_authn` filter to validate and for routing decisions, but doing no NATS-side authorization itself — that stays entirely nats-server's job via the paired NATS JWT.

## Gateway signing key — one key for the whole platform, not per-tenant

Unlike the per-tenant Account signing keys, the gateway JWT is signed by **one Ed25519 keypair shared across every tenant**, delegated from the Operator the same way Account signing keys are, OpenBao-custodied, rotated on its own schedule (current + previous key both valid during the overlap window).

This is deliberate, not a shortcut: Envoy's check never needs to distinguish tenants to do its job — it only decides "was this connection allowed to open," with tenant-scoped authorization enforced entirely afterward by NATS Accounts. Reusing per-tenant Account keys for the gateway JWT would tie Envoy's JWKS to tenant-onboarding and per-tenant-rotation cadence for no benefit, and would blur two credentials that should have separate blast radii: compromise of a tenant's Account key threatens only that tenant's NATS-side authorization; compromise of the gateway key threatens the connection-admission gate for every tenant, and should get Operator-adjacent custody treatment accordingly.

**Consequence for the JWKS:** it stays small and effectively static — one entry (two during the gateway key's own rotation), never growing with tenant count, never touched by tenant onboarding/offboarding or by any tenant's own Account-key rotation.

## JWKS endpoint

- **Owner:** farmer. It already fetches signing-key material from OpenBao when minting; converting the gateway public key to JWK format (`kty: OKP, crv: Ed25519, x: <base64url pubkey>, kid: <stable key id>, use: sig`) is pure data transformation, no new secret access.
- **Shape:** a plain, unauthenticated `{"keys": [...]}` document (public keys only, same trust model as any standard `/.well-known/jwks.json`) — reachable from Envoy's DMZ side, not behind the `jwt_authn` filter itself.
- **Envoy config:** `remote_jwks` with a periodic refresh interval (e.g. 5–10 min), not `local_jwks` — a static inline JWKS would need an Envoy config reload on every gateway-key rotation.
- **Rotation:** during the gateway key's overlap window, the JWKS carries both the outgoing and incoming public keys, distinguished by `kid`, exactly matching the grace-period pattern already used elsewhere in this plan (payload-encryption key rotation, PKI accept/deny/revoke lifecycle).

## Enrollment: the chicken-and-egg problem this subsystem exists to solve

Every credential elsewhere in this design (the JWT, the X25519 keypairs) assumes a sprout already has an identity to present. At the exact moment a fresh host runs its Ansible playbook, it doesn't. This needs its own answer, separate from the JWT-authenticated Envoy routes above.

**Design, borrowed deliberately from `kubeadm`'s join-token model** — the same problem, solved the same way, by a project with a lot of production hardening behind it:

- **Short-lived** (expires in hours, not indefinitely valid).
- **Tenant-scoped**, not global — a leaked key only threatens one customer's enrollment window.
- **Usage-capped**, ideally matched to the actual fleet size being rolled out in one Ansible run, rather than unlimited use.
- Own PXC table: `tenant_id`, key hash (never the raw key), expiry, max/used count, revoked flag.
- Own endpoint, deliberately **not** behind Envoy's `jwt_authn` filter — a sprout enrolling has no JWT yet, so this route validates the presented registration key by direct lookup against the PXC table above (constant-time hash comparison, check expiry/usage, decrement/mark used), not via Envoy's JWT machinery.
- **Proof of possession on every request**: the sprout signs the request with its NKey seed, and farmer verifies that signature before anything else. See "Proof of possession" below.
- **Response:** the sprout's signed NATS User JWT (from the workstream B model), its NKey identity, and the tenant's X25519 public key (from workstream J's payload encryption bootstrap), and, on the request that proves possession of the sprout's box key, its paired gateway JWT (see below, for Envoy's `jwt_authn` on the websocket and recipe routes). As built, a first enrollment is two requests: the first issues the identity and names the tenant key; the second carries `sprout_pub_proof` and is the only one answered with a gateway JWT (J.2; see "Proof of possession" below and `imas-payload-encryption-design.md`, "As built: J.2"). The gateway JWT in that answer is plaintext inside TLS, by design (owner decision, 2026-10-04).

### Root CA: pre-provisioned, not fetched, for sprouts behind the DMZ

A sprout needs a trusted TLS root before it can make any of the calls above, and the join token is sent on the very first one (`/v1/enroll`). A sprout that reaches farmer directly bootstraps that root by trust on first use: `pki.FetchRootCA` does an unverified `GET /auth/cert/` and pins a 200 response that parses as PEM certificates. A sprout behind the DMZ does **not**. Envoy has no `/auth/cert/` route (the request falls to the JWT-gated default route), and none will be added:

- **Which CA to pin.** Envoy terminates TLS, so every connection a DMZ sprout makes (`/v1/enroll`, `/v1/refresh`, `/files/`, `wss://`) is checked against **the CA that issued Envoy's DMZ edge certificate** (`dmz-cert.pem` in `deploy/envoy/envoy.yaml`), not farmer's internal `config.RootCA`. The two need not be the same PKI.
- **How it gets there.** The enrollment tooling (the Ansible playbook that already delivers the join token over its own authenticated SSH/WinRM channel) writes that CA to the sprout's `sproutrootca` path (default `/etc/imas/pki/sprout/tls-rootca.pem`) before the sprout starts, and sets `sproutrootcatofu: false` in the sprout config file.
- **Fail closed.** With `sproutrootcatofu: false`, a sprout never fetches a root CA. If the file is missing it logs `root CA has not been provisioned` at Warn and retries until the file appears; if the file is present but not a PEM certificate it reports the path and does not replace it.
- **Why not TOFU through Envoy.** An unverified first fetch across the DMZ would let anyone on the path hand the sprout their own CA, which it would then pin permanently and use to send the join token straight to them. It would also expose farmer's internal CA at the edge and add another unauthenticated DMZ route.

`sproutrootcatofu` defaults to `true`, so existing direct-to-farmer installs are unchanged. Rotating the DMZ edge certificate onto a different CA means re-provisioning `sproutrootca` on every sprout first.

## Proof of possession: every request signs with the sprout's NKey seed

`nkey_pub` is not a secret. Envoy forwards it upstream as `x-imas-sprout-nkey` on every JWT-gated request, and it is the `sub` of both tokens the sprout holds. The idempotency replay (`cloudxp-machine-manager-api-design.md` §3.3 step 1) runs before the join token is checked, so if `nkey_pub` alone were enough, anyone who had seen an enrolled sprout's `nkey_pub` could call `/v1/enroll` and get a freshly minted gateway JWT for that sprout. Every request must therefore prove it holds the NKey seed behind the `nkey_pub` it presents.

**The NKey signature is not enough for a gateway JWT either (J.2, FLAG FOR SECURITY REVIEW).** The same seed signs the bus's `CONNECT` nonce, and a compromised bus chooses that nonce. A JSON nonce can carry newlines, so the bus can get `EnrollSigningPayload` signed for any sprout, with any `join_token` it likes, and the replay path never checks the token. Before J.2 that was enough to replay an enrolled sprout's identity with a fresh gateway JWT, which reads the sprout's staged rendered recipe from `/files/`. So `/v1/enroll` now answers a request carrying only the NKey proof (step 1, on either path, or a retry of it) with the identity, the tenant and its key, and **no** gateway JWT. The gateway JWT comes only with step 2's `sprout_pub_proof`, sealed with the sprout's box key, whose message ID farmer claims once cluster-wide; or from a sealed refresh (below). The NKey proof below stays: it still binds the request to the seed's holder, and the join token still gates a first enrollment.

**A first box key only from the exchange that issued the identity (SEC.7b; security review 2026-10-b, B2; FLAG FOR SECURITY REVIEW).** Step 2's `sprout_pub_proof` proves that its sealer holds the private half of the `sprout_pub` it names. It doesn't prove that key is the sprout's: anyone can seal such a proof under a key of their own. Before SEC.7b, farmer recorded the first proven key for any accepted sprout with no active box key (one between steps 1 and 2, one whose box keys were revoked, or one accepted outside this flow). The bus can get the NKey signature that request needs over a `CONNECT` nonce, so it could register a box key it held, read that sprout's sealed `cmd.run` and `cook`, and get a gateway JWT. Now:

- **Step 1, and only step 1, issues an enrollment binding.** The join-token path, which issues the identity, returns `enroll_binding`: a `payloadbox` message, purpose `f2f.enroll.binding`, naming the tenant, the sprout ID, `nkey_pub`, and the `sprout_pub` from the NKey-signed step 1 request. Farmer seals it to itself under each current tenant key paired with its own public half. Only a holder of the tenant's private key can seal or open under that pair, so nobody but farmer can make one. A bus that reads step 1's response, which the DMZ can (Envoy terminates this TLS), learns nothing it can use, because the binding names the real `sprout_pub`. The replay path never issues one.
- **Step 2 returns it** (`enroll_binding` in the request, next to `sprout_pub_proof`). Farmer records a first box key only when all of these hold: the proof verifies; the binding opens; the binding names this tenant, sprout, `nkey_pub` and exactly the `sprout_pub` being proven; it was issued at most `pki.EnrollBindingTTL` (5 minutes) ago; and both the proof's message ID and the binding's are claimed for the first time in Valkey (`ClaimSealedMessage`, 10-minute TTL). So a binding records one key, once. Both are checked before either claim, so a request that fails a check spends nothing. Valkey holds only the claims, never the binding. Its connection has no auth yet, so a Valkey writer can pre-claim a binding and refuse an enrollment, but it can't forge one.
- **A proof for the key already on record** needs no binding. It is a retried step 2, and only the sprout can seal a proof under its own key. A proof for a different key while one is active is still refused: replacing a key is a rotation.
- **An accepted sprout with no active box key is closed.** A replay request from it is refused whether or not it carries a proof. This covers a sprout whose step 2 never completed inside the binding's TTL, whose box keys were revoked, or that was accepted outside this flow. Owner decision: nothing is deployed, so there is no compatibility window, and a sprout with no box key is refused, not downgraded. **Recovery:** an operator deletes the sprout (`imas keys delete`, which revokes its NKey per SEC.3a). The host then enrolls again with a new NKey and box key (remove its NKey seed and box key files) and a fresh join token. The freed sprout ID is handed out again.
- **The client** (`pki.EnrollSprout`) returns step 1's binding with its proof, and retries step 2 up to 5 times with a fresh signature and proof each time (1s, 2s, 4s, 8s apart, well inside the TTL). A network failure between the steps shouldn't strand a host.

*Why a sealed binding, not a nonce stored in Valkey.* A nonce kept in Valkey would make Valkey the authority for which key a sprout may register, and Valkey is unauthenticated today. *Why the binding rides next to the proof, not inside it.* The proof's body (`enrollProofBody`) is defined in `sproutbox.go`, outside SEC.7b's file scope. The binding doesn't need to be inside the proof to be safe: it fixes `sprout_pub` and the proof must be sealed under that key's private half. Putting the binding's ID inside the proof would also stop a proof made before step 1 from being used, but only the holder of the real key could make such a proof. The step 2 request and the binding are each single-use, and the NKey signature stays single-use too.

**Request shape** (`POST /v1/enroll`, JSON):

```json
{
  "join_token": "<key_id>.<secret>",
  "nkey_pub":   "U...",
  "hostname":   "web-01",
  "sprout_pub": "<base64 X25519 public key>",
  "timestamp":  1790000000,
  "nkey_sig":   "<unpadded base64url Ed25519 signature>"
}
```

- `timestamp` is Unix seconds at signing time.
- `nkey_sig` is the sprout's NKey seed's signature (`nkeys` `KeyPair.Sign`) over these bytes, joined with `\n` and with no trailing newline:
  ```
  imas-enroll-v1
  <timestamp, decimal>
  <nkey_pub>
  <hostname>
  <sprout_pub>
  <join_token>
  ```
  `pki.EnrollSigningPayload` builds this. The `imas-enroll-v1` domain tag keeps an enrollment signature from being mistaken for any other signature the same NKey makes, such as a NATS `CONNECT` nonce signature. A field containing a newline is rejected, so the encoding is unambiguous. The signature covers every field, so none can be swapped under a captured signature (for example, substituting a different `sprout_pub` on a first-time enrollment).
- Farmer verifies the signature against `nkey_pub` and requires `timestamp` within ±5 minutes of its own clock (`pki.EnrollSigMaxSkew`). It does this before the idempotency lookup, the join-token lookup, and any redemption. A failure returns the same generic `enrollment_failed` as every other failure (§3.4).
- **Required on first-time enrollments too, not only replays.** Without it, a join-token holder could register a `nkey_pub` whose seed they don't hold. If the real owner later enrolled against a different tenant's token, the replay would put its sprout in the first tenant. One rule for every request also keeps the wire contract to a single shape.

**Why a timestamp rather than a server-issued nonce.** A nonce would need a second round trip (fetch a challenge, then enroll) and single-use nonce state shared by every farmer behind Envoy. A signed timestamp keeps enrollment to one blocking call, which is what the Ansible-driven flow above needs. On its own, a timestamp leaves a replay window: a captured signed request would verify until its timestamp left the ±5 minute window. The replay cache below closes it.

**Clock requirement.** A sprout whose clock is more than 5 minutes off farmer's cannot enroll or replay. Freshly provisioned hosts should have NTP running before the enrollment step.

### Replay cache: each signed request is accepted once

Farmer records every signed `/v1/enroll` request it accepts in Valkey and refuses one it has already recorded (`internal/pki/replaycache.go`). Since J.2, `/v1/refresh` carries no NKey signature; its sealed request's message ID is claimed instead, in the same Valkey with the same fail-closed rule (`pki.ClaimSealedMessage`, `imas:replay:sealed:<tenant_id>:<sprout_id>:<id>`, 10-minute TTL), and so are the message IDs of an enrollment's `sprout_pub_proof` and, for a first box key, its `enroll_binding` (SEC.7b). It uses the same Valkey cluster farmer already writes sprout heartbeats to (`IMAS_VALKEY_ADDRS`).

- **Shared across farmers.** Farmer runs as several replicas behind Envoy, and a resubmission routed to a different replica, or arriving after a farmer restart, must still be caught. An in-process map would catch neither.
- **One `SET imas:replay:<digest> 1 NX EX <ttl>` per request.** `SET NX` is atomic, so of two replicas recording the same request at once, exactly one wins. Each key is a single slot, so this works unchanged on Valkey Cluster.
- **The digest is the hex SHA-256 of the decoded signature followed by the signed payload.** It uses the decoded signature bytes, not the `nkey_sig` string: base64url decoding tolerates non-zero trailing bits, so one signature has several string forms, but Ed25519 verification accepts only one byte form. It includes the signature, not only the payload, because a signed payload can be predictable (domain tag, timestamp, public `nkey_pub`). Farmer's Valkey connection has no auth yet, so anyone able to write to Valkey could otherwise record a sprout's future payloads in advance and lock it out. The signature needs the NKey seed. The digest is globally unique without a tenant component: the payload carries its domain tag, `nkey_pub` and timestamp.
- **Fails closed.** A Valkey error, a round trip over 1 second, or no Valkey client at all (farmer couldn't connect at boot) rejects the request with the generic `enrollment_failed`. Enrollment and refresh are unavailable while Valkey is. That is the same trade-off as a missing gateway JWT signer, and `/health` already fails, so the pod is restarted, when farmer has no Valkey client.
- **Recorded only after the request's credentials check out, and before anything is issued**: on the enrollment replay path once `nkey_pub` is found to be accepted; on a first-time enrollment once the join token has validated, before it is redeemed. (A sealed refresh is claimed only once it has opened under the sprout's keys and passed its freshness checks.) Anyone can make a valid signature with a freshly generated NKey, so recording straight after signature verification would let unauthenticated callers write keys. Two identical first-time requests racing past the idempotency check both reach the record step, and only one goes on to redeem.
- **Keys expire on their own.** The TTL runs to the payload's timestamp plus 5 minutes (the end of its skew window) plus a 1-minute margin for clock differences between farmer replicas. It is computed from farmer's clock and sent as a relative `EX`, so Valkey's clock doesn't matter. A key that outlives its TTL would do no harm: its payload's timestamp already fails the skew check.
- **Legitimate retries are unaffected.** A sprout signs every attempt afresh, and its timestamps are strictly increasing within a process (`pki.nextSigningTimestamp`), so two requests signed in the same second (an enrollment's two requests, say) are still distinct. A request that was recorded but then failed for another reason (a database error while minting) is retried with a new signature. Recording never touches the join token, so a retry still doesn't spend one.
- **Residual gaps.** Valkey replicates asynchronously, so a failover can lose claims written just before it, and those requests could each be resubmitted once more before their window closes. Anyone with write access to Valkey can delete claims. Both reopen at most the ±5 minute window this cache closes, and both need access to an internal service or a TLS session. Auth and TLS on farmer's Valkey connection would narrow the second.

## Gateway JWT refresh: its own route and contract

The gateway JWT is short-lived by design (`config.GatewayJWTTTL`), so every enrolled sprout renews it continuously. That is a different job from enrollment, and it gets its own endpoint rather than reusing `/v1/enroll`'s replay path.

**Sealed since J.2 (FLAG FOR SECURITY REVIEW).** The refresh used to be authenticated by an NKey signature over `imas-refresh-v1\n<timestamp>\n<nkey_pub>` (`pki.RefreshSigningPayload`). The seed that makes it also signs the bus's `CONNECT` nonce, which a compromised bus chooses, so the bus could get that proof made and refresh as any sprout. Farmer now refuses that contract outright, for every sprout: there is no NKey-only fallback and no per-sprout ratchet, and a sprout farmer has no box key for re-enrolls (owner decisions, 2026-10-04). `imas-payload-encryption-design.md`, "As built: J.2", has the detail.

**Request shape** (`POST /v1/refresh`, JSON). There is no `join_token` field and no NKey signature; farmer refuses a body with either, or with any other unknown field.

```json
{
  "nkey_pub": "U...",
  "sealed":   { "v": 2, "s": [ { "n": "...", "c": "..." } ] }
}
```

- `sealed` is a `payloadbox` message, purpose `s2f.refresh`, naming the sprout's pinned tenant and its pinned sprout ID, with the body `{nkey_pub, timestamp}`. It is sealed with the sprout's box private key to the tenant key it pinned (`pki.SproutSealedRefresh`): one copy under its current box key, and a second under its pending one while a box key rotation is in progress.
- Farmer looks `nkey_pub` up among **accepted** sprouts only, opens the request under that sprout's valid box keys (active and in grace) and every retained tenant key back to the last severing rotation, requires a request (no `ReplyTo`) naming that `nkey_pub`, checks its timestamp and issue time within ±5 minutes, and claims its message ID once in Valkey (fail closed) before issuing anything. Anything else (unknown, denied, rejected or deleted sprout, no box key on record, a request that doesn't open, is stale or was seen before) gets the same generic `enrollment_failed`. Refresh can only re-issue an existing identity. It never redeems a join token or creates a sprout, so a sprout deleted on farmer can't bring itself back from its refresh loop.
- **The answer is sealed too:** `{"sealed": ...}` and nothing else, a `payloadbox` reply (purpose `f2s.refresh`) bound by `ReplyTo` to the request's message ID and sealed to the sprout's active box key under the tenant key it pinned. Its result is the existing NATS User JWT, a freshly minted gateway JWT, the tenant ID and X25519 public key, and the continuity proof after a tenant key rotation. The sprout accepts only the reply to the request it just sent. Nothing in the HTTP exchange, at Envoy or anywhere else in the DMZ, carries a gateway JWT in the clear.
- **Not `jwt_authn`-gated at Envoy.** A sprout powered off for longer than the TTL holds only an expired gateway JWT and must still be able to renew it; the sealed request is the authentication, and it needs no gateway JWT.
- **Its own rate-limit bucket.** `/v1/enroll`'s bucket stays small because the join token is its only credential, so that budget is what bounds join-token guessing. Refresh is authenticated and legitimately high-volume (every sprout, roughly every two-thirds of the TTL), so it gets a separate, much larger bucket sized from fleet size ÷ TTL. The two never share tokens. See `deploy/envoy/README.md`, "Sizing the /v1/refresh bucket".

**A gateway JWT ends with its sprout, not with its `exp` (SEC.7c, security review 2026-10-b B3; FLAG FOR SECURITY REVIEW).** Envoy's `jwt_authn` checks only signature, issuer and expiry, and so did farmer until SEC.7c: deleting a sprout, or replacing it by accepting `<id>_<n>`, revoked the old host's User JWT and box keys but left its gateway JWT reading `/files/` until it expired, and after a replace the token's `(tenant_id, sprout_id)` named the **new** host's staged recipe. Farmer now checks every gateway JWT it is handed, on `/files/` and `/v1/sprout/update-manifest` alike (`internal/api/middleware.go`, `verifySproutGatewayJWT`), against its current state (`pki.VerifyGatewaySubject`): the token's `sub` must not be on the tenant's `pki_revoked_nkeys` list, the tenant must be live, and `sub` must be the NKey of the **accepted** `pki_nkeys` row for `(tenant_id, sprout_id)`, compared byte for byte. Every lookup is keyed on `tenant_id` together with the NKey or sprout ID. A database error, or no database, refuses (403) exactly as a revoked NKey does. So a delete or a replace cuts the old host off from both routes the moment its transaction commits.

- **No cache.** The check is two indexed point reads (three for a non-legacy tenant) per request, on routes a sprout calls a few times per cook or update check. A cache would reopen the window this closes, and would need invalidating on delete and accept on every replica; it is left out until load says otherwise.
- **`gatewayjwtttl` stays at 24 hours.** It no longer bounds how long a retired host can read farmer's routes, so lowering it buys nothing there. What the TTL still bounds is Envoy's admission of the websocket on route 3: a retired host's unexpired gateway JWT still opens that upgrade, but the bus then refuses its revoked User JWT, so it gets no further. Lowering the TTL would cost refresh volume (the `/v1/refresh` bucket is sized from it) and would shorten the tenant key grace window, `max(boxkeygraceduration, gatewayjwtttl)`, that lets an offline sprout follow a rotation.

**Sprout side** (`internal/pki/enrollclient.go`):
- The refresh is scheduled two-thirds of the way through the token's lifetime, less up to a tenth of the lifetime of random jitter, and retried with backoff (capped at 5 minutes) on failure.
- **The tenant X25519 public key is pinned at enrollment**, with the tenant ID and (since J.2) the sprout ID beside it. The key pin moves only on a continuity proof sealed under the pinned key (authenticated tenant key rotation, `imas-payload-encryption-design.md`). A refresh reply naming a different key without one, or another tenant or sprout ID, is refused whole: nothing from it is persisted, and the sprout exits with an error so its service manager records a failure. So does a sprout missing its box key or a pin: it can't make a sealed refresh and must be re-enrolled.
- **A severing tenant key rotation cuts a sprout off.** Farmer no longer holds the key the sprout pinned, so it can't open the sprout's refresh, and nothing it could send back would be authenticated. The refusal is an ordinary, retried `enrollment_failed`, not a fatal error, and the sprout stays cut off until an operator re-enrolls it (owner decision, 2026-10-04: "let the sprout re-enroll").
- **The join token is deleted by the sprout itself** once enrollment is fully persisted (the NATS User JWT, written last, is on disk): it is removed from the sprout config file, which is kept at mode 0600. A token supplied by environment variable or command-line flag can't be removed by the sprout, so it logs where the token still is. The token has no use left after enrollment: every later call is a sealed refresh.

## Why this is safe even crossing the DMZ bus before any payload encryption exists

The only things transiting the bus during this exchange are the sprout's own generated **public** keys (NKey public key, X25519 public key) and a signature made with the NKey seed — none of them secret even if a compromised bus observes them. Observing a `nkey_pub` is not enough to obtain that sprout's identity, because every request must be signed by its seed (see "Proof of possession" above). A compromised bus can, however, get that seed to sign a nonce of its choosing at `CONNECT`, so no NKey signature alone earns a gateway JWT: that takes the sprout's box key, on enrollment's second request or a sealed refresh (J.2). The sprout's private key material never leaves the sprout; the tenant's private key never leaves OpenBao custody. No bootstrapping-before-security-exists problem here, by construction.

## What still needs deciding at implementation time

- Exact revocation semantics for a spent or expired registration key — should a spent key's row be deleted, or retained with `used = true` for audit purposes? Given CERT-In/DPDP audit expectations, retention with a clear revoked/used state is likely the safer default, but worth an explicit decision rather than defaulting silently either way.
- Rate-limiting the enrollment endpoint itself — since it's deliberately not JWT-gated, it's the one DMZ-facing surface without that layer of protection, and deserves its own abuse-resistance treatment (e.g., IP-based rate limiting at Envoy, even though the route itself skips JWT validation).
