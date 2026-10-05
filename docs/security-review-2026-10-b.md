# Security review of Wave 7, 2026-10 (part B)

**FLAG FOR SECURITY REVIEW.** This is a read-only code review of everything
merged to `main` since `eacdc79` (PR #80), the point `docs/security-review-2026-10.md`
was written at. It is input to the human security review that
`docs/BUILD-STATUS.md` (Open item 4) asks for, **not** a replacement for it, and
**not** a clean bill of health. No code was changed. The work under review stays
**ready for review**, not "done" or "safe to merge."

Reviewed on `main` at `f645a93`, 2026-10-04. The whole of `go test ./...` passes
at this commit (one clean run).

## Method

The same seven questions as the first review, per area: what is trusted; what a
compromised bus can do; what a hostile tenant can do; what a malicious update
repository can do; whether every table, index, cache and map is keyed on
`tenant_id` and `sprout_id` together; whether secrets reach logs, errors or job
results; where a failure opens instead of closing.

Areas, in the order the brief asked:

1. Every High and Medium finding of the first review: is each fixed, with a
   test, and is the fix complete.
2. SEC.0 to SEC.5 (and SEC.5b).
3. J.1 to J.5: sealed refresh, the CLI API, `internal.*`, and shell. For the
   sealed designs, the table "What a compromised bus can still do"
   (`docs/design/imas-payload-encryption-design.md`) tested claim by claim
   against the code.
4. Recipes: a hostile tenant uploading a recipe, templates, staged files and
   `/files/`.

**Hostile-bus / hostile-tenant tests.** For the claims that could be tested, I
wrote throwaway tests, ran them, recorded the result, and deleted them (nothing
is committed). Three ran and are reported inline: a forged staged recipe cooked
over `/files/` (B1), a deleted/replaced host's gateway JWT still reading
`/files/` (H1-residue), and a keyless-but-accepted sprout accepting an
attacker-chosen box key at enrollment (B2). A fourth, recipe render cost scaling
with include count, ran as a DoS probe (B3).

**Marks.** CONFIRMED: the path was traced from attacker input to effect (and,
where noted, exercised by a throwaway test). UNCONFIRMED: a link depends on
behaviour not verified here (a race window, a deployment shape, an upstream
internal); the finding says which.

Line numbers are at `f645a93`.

## Summary

| ID | Sev | Area | Finding | Mark |
|---|---|---|---|---|
| B1 | High | J.2 / recipes | The sprout decodes and cooks a staged recipe pulled over `/files/` with no proof farmer produced it; Envoy (DMZ) terminates that TLS, so whoever answers the pull chooses the steps that run as root | CONFIRMED (throwaway test); **addressed by SEC.7a** (ready for review) |
| B2 | High | J.1 / enrollment | An accepted sprout with no active box key (pre-J, mid-enrollment, or post-revocation) accepts an attacker-chosen box key proven under the attacker's own private half, and is handed a gateway JWT — the enrollment PoP binds the key to itself, not to the sprout | CONFIRMED code path (throwaway test); the compromised-bus race to win step 2 is UNCONFIRMED. **Addressed by SEC.7b** (in review) |
| B3 | High (incomplete fix) | CL.1 / J (H1 residue) | H1 revokes the NATS User JWT and box keys of a deleted or replaced host, but not its **gateway JWT**; that credential reads `/files/` for up to its TTL (default 24h), and on the replace path it is scoped to the reused `(tenant_id, sprout_id)`, so the old host reads the **new** host's staged recipe | CONFIRMED (throwaway test); **addressed by SEC.7c** (ready for review) |
| B4 | Medium | SEC.3b / recipes | A hostile tenant's recipe render cost scales with its own include count (up to 256), each include rendered under its own `RecipeRenderTimeout`; one cook can burn many CPU-seconds, and tenants now upload recipes | CONFIRMED (throwaway probe); absolute impact not load-measured |
| B5 | Medium | M6, carried | Same-second Account-JWT `iat` tie in the bus fence is unchanged (`fence.go:484`), as planned (deferred past the UAT gate); with SCALE.2's single-node push it can still turn a missed revocation into a permanent cluster-wide revert | CONFIRMED in code; upstream `jti` sharing per repo comments |
| B6 | Medium | J.4 | Forged "no responders" on `internal.sprout.action` still lets one action run up to `SAASAPI_OUTBOX_MAX_ATTEMPTS` times (owner-accepted residual, unchanged by J.4) | CONFIRMED; accepted |
| B7 | Low | J.5 | The built-in `operator` role still grants `shell` on every sprout (`rbac/config.go:100`), contrary to the agreed default; deferred to a follow-up PR | CONFIRMED; fixed in SH.1 (PR #102) |
| B8 | Low | SEC.5 | M1's binding of the package to the manifest is complete on deb/rpm but an MSI `ProductVersion` carries no prerelease, so on Windows an rc and the final of one MAJOR.MINOR.PATCH are indistinguishable; zypper's downgrade-skip was read, not run | CONFIRMED (deb/rpm); MSI residual and zypper UNCONFIRMED |
| B9 | Low | J.2 / cook | A sprout cooks whatever a pulled staged recipe's `DispatchedAt` lets through within `StagedRecipeMaxAge`; combined with B1 the staleness check is the only bound on a forged pull, and it is attacker-set | CONFIRMED; **addressed by SEC.7a** with B1 (ready for review) |
| B10 | Info | — | Smaller notes (I1–I6 below) | — |

**What the first review's four Highs and eight Mediums look like now:** H2, H4,
M2, M3, M4, M7, M8 are fixed with tests and I found the fixes complete. H1 and H3
are fixed in the parts the briefs named, but each leaves a related path open (B3
for H1, B2 for H3's enrollment side). M1 is fixed with a documented residual
(B8). M5 is fixed with its documented residual (several tenants can still fill the
shared pool). M6 is deliberately not fixed (B5).

**Before `SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED` is turned on**, and before
requirement 14 is called Green, this review recommends closing B1, B2 and B3:
all three let the DMZ read or write what sealing exists to protect, through the
one plaintext-inside-TLS channel sealing deliberately left (`/files/` and the
enrollment PoP), so they weaken the same boundary the J work strengthened.

## High

### B1. A pulled staged recipe is cooked with no proof farmer produced it (J.2, recipes)

- **Where:**
  - `internal/cook/stagedfetch.go:30-37`: `FetchStagedRecipe` does
    `pki.FetchFarmerFile` then `json.Unmarshal(data, &env)` into a
    `RecipeEnvelope`, with no signature, MAC or tenant-key check on the bytes.
  - `internal/cook/stagedsync.go:142-178`: `pullStagedRecipe` accepts the
    decoded envelope on three conditions — no push raced, the job ID is not
    already handled, and `DispatchedAt` is within `StagedRecipeMaxAge` — none
    cryptographic.
  - `cmd/sprout/nats.go:113` and `cmd/sprout/main.go:300,350`: the pull runs on
    startup, on every NATS reconnect, and on a farmer nudge.
  - The fetch is a plain `GET /files/<key>` with a gateway JWT bearer token
    (`internal/pki/fileclient.go`). Envoy terminates that TLS in the DMZ
    (`deploy/envoy/envoy.yaml:96-102`), and farmer's API port is reachable
    without Envoy.
- **Scenario:** A compromised bus/Envoy, or anything between the sprout and
  farmer's object store, answers the sprout's `GET /files/sprouts/<tid>/<sid>/recipe.json`
  with a `RecipeEnvelope` of its own: steps of its choice, a fresh
  `DispatchedAt`, a `JobID` the sprout hasn't handled. The sprout cooks it as
  root. This is the integrity half of what sealed `cook` protects on the NATS
  path — `cook` dispatch is sealed, but its pull-readable twin is not.
- **Throwaway test (ran, deleted):** stubbed `FetchStagedRecipe` to return the
  exact `json.Unmarshal` of a forged envelope carrying one
  `cmd.run` step, called `SyncStagedRecipe(SyncOnReconnect)`. Outcome `cooked`,
  one envelope, the forged step passed to the cooker verbatim. The only thing
  standing between a forged `/files/` body and `exec` is the JSON decoder.
- **Fix:** sign the staged envelope farmer-side (it holds `tenant_priv`) and
  verify it on the sprout before cooking — a `payloadbox` message under the
  tenant key, like the sealed push, or a detached signature over the bytes.
  Failing that, document `/files/` as a trusted channel and state plainly that
  requirement 14 is not met while the staged pull is forgeable, because the pull
  is an alternative to the sealed push that the sprout acts on automatically.
- **Mark:** CONFIRMED, exercised.
- **Status: addressed by SEC.7a** (FLAG FOR SECURITY REVIEW; ready for review,
  not closed until the human review accepts it). Farmer seals every staged
  copy with `pki.SealToSprout` under its own purpose, `f2s.staged`, bound to
  `tenant_id`, `sprout_id`, the job ID and `DispatchedAt` (the body), under
  every tenant key in its grace set; a sprout with no box key gets no staged
  copy. The sprout opens it with `pki.SproutOpenStagedFromFarmer` against its
  own keys and pins before decoding, refuses anything else (plain JSON
  included), and only then runs the push-race, handled-job and max-age checks
  on the opened envelope, plus a new one: not older than the newest job it
  already handled. The throwaway test above is now kept as
  `internal/cook/stagedsealed_test.go`
  `TestStagedSealed_ForgedPlainEnvelopeIsRefused`, and is refused. Details,
  and how a copy staged before a tenant key rotation is handled, in
  `docs/design/imas-payload-encryption-design.md` ("Staged recipes").

### B2. A keyless accepted sprout accepts an attacker's box key at enrollment, and is handed a gateway JWT (J.1, enrollment PoP)

- **Where:**
  - `internal/pki/enroll.go:364-382`: on the idempotency replay path, `proven :=
    len(req.SproutPubProof) > 0`; a proof recorded the submitted `sproutPub` as
    the active key and (`reissueExistingIdentity`, `enroll.go:654-671`, `withGateway`)
    mints a gateway JWT.
  - `internal/pki/enroll.go:568-591` (`recordProvenSproutBoxKey`): records the
    key only when `ValidSproutBoxKeys` returns `ErrNoActiveBoxKey` — i.e. when
    the sprout has no active box key.
  - `internal/pki/farmerbox.go:143-158` (`openEnrollProof`): opens the proof
    with candidates `{PeerPub: sproutPub, Priv: tenantPriv}`, where `sproutPub`
    is the value **from the request**. So a proof sealed by the holder of *that*
    key's private half opens — the proof binds the key to itself, not to the
    sprout's identity.
- **Scenario:** The target is an accepted sprout with no active box key: a
  sprout enrolled before workstream J (BUILD-STATUS records these and farmer's
  plaintext fallback for them), one between enrollment step 1 and step 2, or one
  whose box keys were revoked. A compromised bus obtains an NKey signature over
  `EnrollSigningPayload(ts, nkey_pub, hostname, sprout_pub=X, token)` by choosing
  that payload as the sprout's `CONNECT` nonce (the capture is exactly what
  `internal/api/handlers/connect_capture_test.go` builds), where `X` is a box key
  the attacker holds. It then sends the replay-path request with a
  `sprout_pub_proof` sealed under `X`. Farmer records `X` as the sprout's active
  key and returns a gateway JWT. The attacker now seals/opens that sprout's
  `cmd.run` and `cook` and reads its `/files/`; the real sprout's own step 2
  later fails with "already has a different active box key."
- **Throwaway test (ran, deleted):** enrolled a sprout (step 1, keyless), then
  called `Enroll` with a proof sealed under an attacker key `X` naming `X` as
  `sprout_pub`. Result: no error, a gateway JWT minted, the active box key is
  `X`, and the real sprout's subsequent step-2 proof is refused. The existing
  `TestConnectNonceCannotEarnAGatewayJWTByEnrolling` does not catch this: it uses
  a sprout that already has a box key, where `openEnrollProof` refuses a
  foreign-sealed proof; the keyless case is the gap.
- **Fix:** bind the enrollment proof to the sprout's identity, not to the key it
  carries — accept a first box key only on the same TLS exchange that issued the
  identity (fold the PoP into enrollment step 1's response-bound follow-up so a
  replay can't substitute the key), or refuse to register a first box key for an
  already-accepted sprout over the replay path at all and require re-enrollment
  with a fresh join token. At minimum, treat an accepted-but-keyless sprout as a
  state to be closed, not a standing window.
- **Mark:** CONFIRMED code path (tested). Whether a compromised bus reliably wins
  the step-1/step-2 race against a live sprout is UNCONFIRMED; the pre-J and
  post-revocation keyless states need no race.
- **Addressed by SEC.7b** (FLAG FOR SECURITY REVIEW; ready for review, not
  approved). Built the first fix above. Only the join-token request, which
  issues the identity, returns an `enroll_binding`: a `payloadbox` message
  farmer seals to itself under the tenant key, naming the tenant, sprout ID,
  `nkey_pub` and the `sprout_pub` that request carried. A first box key is
  recorded only from a step 2 that returns it within 5 minutes, with both its
  message ID and the proof's claimed once in Valkey. Valkey holds claims only,
  so it can't forge a binding. A binding names the real `sprout_pub`, so the
  attacker's `X` is refused even by a DMZ that read step 1's response. An
  accepted sprout with no active box key is refused on the replay path,
  with or without a proof, and has to be deleted and enrolled again under a
  new NKey with a fresh join token. That covers pre-J, revoked, accepted
  outside the flow, and step 2 not done within the TTL. The throwaway test
  is kept as `internal/pki`'s
  `TestEnroll_KeylessSproutRefusesAnAttackerBoxKey`, which records no key
  and mints no JWT. The keyless case is added to
  `TestConnectNonceCannotEarnAGatewayJWTByEnrolling`. Residual: an attacker
  who can submit its own step 1 before the real sprout does (it would need
  the join token and an NKey signature over a step 1 naming its key, and the
  sprout signs no bus nonce before its first response) binds its own key.
  That is a failed enrollment the real sprout notices, not a silent
  takeover. See `docs/design/imas-envoy-enrollment-design.md`, "A first
  box key only from the exchange that issued the identity".

### B3. H1 leaves the deleted or replaced host's gateway JWT live (CL.1 / J, H1 residue)

- **Where:**
  - SEC.3a revokes, for a deleted or replaced host, the NATS User JWT (via
    `pki_revoked_nkeys`, `applyRevokedNKeys`, `jwtusers.go:142-156`) and the box
    keys (`revokeSproutBoxKeysTx`, `store.go:184-210`). The "As built" text
    (`imas-payload-encryption-design.md`) says the bus "refuses its User JWT on
    reconnect."
  - It does **not** revoke the **gateway JWT**, the separate credential for
    `GET /files/`. Verification is signature + issuer + `exp` + the
    `tenant_id`/`sprout_id` claims only (`internal/gatewayjwt/verify.go:52-77`,
    `internal/api/middleware.go:88-110`); there is no revocation or deny-list, and
    no lookup against `pki_revoked_nkeys`.
  - Default `gatewayjwtttl` is 24h (`internal/config/config.go:520,675`).
  - On the replace path (`pki.go:198-204`), the new host takes `<id>`, and the
    gateway JWT's claims are `(tenant_id, sprout_id)` — the reused id.
- **Scenario:** A tenant deletes a compromised host, or a rebuilt host takes the
  id by `pki.accept`. The old host (or whoever holds its gateway JWT) keeps
  reading `GET /files/sprouts/<tid>/<id>/recipe.json` until the token expires
  (up to 24h). After a replace, that key path now holds the **new** host's staged
  recipe, secrets included.
- **Throwaway test (ran, deleted):** accepted `web-01` under one NKey, deleted
  it, re-accepted `web-01` under a new NKey, then minted a gateway JWT with the
  **old** host's NKey as `sub` and `(t_acme, web-01)` claims and presented it to
  the real `Auth`/`GetFile` router. Result: 200, the file served. The gateway JWT
  is accepted regardless of the NKey revocation.
- **Fix:** check the presented gateway JWT's `sub` (the NKey) against the
  tenant's revoked list in `sproutFileAccess` and `sproutIdentityAuth`
  (fail closed on a DB error), or shorten `gatewayjwtttl` sharply and document the
  residual window, or bind `/files/` reads to the live NATS session rather than a
  standalone bearer token.
- **Mark:** CONFIRMED, exercised.
- **Status: addressed by SEC.7c (FLAG FOR SECURITY REVIEW, ready for
  review).** The first fix was taken, for both routes. `sproutFileAccess`
  and `sproutIdentityAuth` now share one check
  (`internal/api/middleware.go`, `verifySproutGatewayJWT`) that, after the
  signature, calls `pki.VerifyGatewaySubject`
  (`internal/pki/gatewaysubject.go`): the token's `sub` must not be on the
  tenant's `pki_revoked_nkeys` list, the tenant must be live, and `sub` must
  equal the NKey of the accepted `pki_nkeys` row for `(tenant_id,
  sprout_id)`, so a replace cuts the old host off even before its
  revocation is consulted. Every lookup is keyed on `tenant_id`; a database
  error, or no database, refuses. No cache. The throwaway test above is kept
  as `TestFilesRoute_ReacceptedSproutIDRefusesOldHostsGatewayJWT`
  (`internal/api/gateway_revocation_test.go`), which first reproduces the
  200 with the check stubbed out and then shows the 403; the same file
  covers the replace path, a deleted sprout, a database error, cross-tenant
  tokens and `/v1/sprout/update-manifest`. `gatewayjwtttl` stays at 24h:
  it no longer bounds access to farmer's routes, only Envoy's admission of
  the websocket, where the bus refuses the revoked User JWT
  (`imas-envoy-enrollment-design.md`, "A gateway JWT ends with its
  sprout").

## Medium

### B4. Recipe render cost scales with a tenant's include count (SEC.3b, recipes)

- **Where:**
  - `internal/cook/helpers.go:146` caps includes at `maxRecipeIncludes = 256`.
  - `resolveRecipeSteps` (`farmercook.go:949-1013`) renders each included recipe,
    and `collectIncludesRecurse` (`helpers.go:593-633`) renders each again while
    collecting includes. Each render gets its own `RecipeRenderTimeout`
    (`farmercook.go:290`, default 2s) and its own range/output budget — the budgets
    are per render, not per cook.
  - REC.1 upload validation (`internal/saasapi/recipes.go`,
    `cook.ValidateRecipeSource`) does not resolve includes, so a recipe that
    passes upload can pull in 256 others at cook.
- **Scenario:** A tenant uploads (REC.1) a top recipe that `include:`s many of
  its own recipes, each with a template near its per-render time/range budget. One
  cook then costs the sum, many CPU-seconds on a farmer replica. Tenants upload
  recipes now (owner decision, 2026-10-04), so this is reachable by any tenant.
- **Throwaway probe (ran, deleted):** one near-budget render took ~0.23s; a top
  recipe including 16 such recipes cooked in ~6.3s on one core (render timeout
  2s), i.e. the cost tracked the include count rather than one render's bound.
- **Fix:** a per-cook render budget (total time and total rendered bytes across
  all includes), well below `includes * RecipeRenderTimeout`; and/or count and
  cap distinct includes lower for tenant recipes. Consider resolving and bounding
  includes at upload too, so the cost is visible before cook time.
- **Mark:** CONFIRMED the cost scales; absolute DoS impact on a real deployment
  not load-measured (UNCONFIRMED).

### B5. Same-second Account-JWT `iat` tie, unchanged (M6, carried)

- **Where:** `cmd/farmerbus/fence.go:477-485`: `claimRank.beats` still breaks an
  equal `iat` by `a.raw > b.raw`. Ordinary Account re-signs still do not wait for
  a strictly newer `iat` (only lockouts do, `tenant.go:516`).
- **Scenario:** As the first review's M6: two Account JWTs re-signed in the same
  second (a bulk deny, say) tie on `iat`; a node that missed the superset pull,
  on rejoin, can have healthy nodes replace the newer JWT with the older one,
  re-admitting a revoked sprout cluster-wide until the account next changes. With
  SCALE.2 still pushing to one node and not waiting for all (BUILD-STATUS Open
  item 3), a missed push becomes a durable revert rather than a transient one.
- **Fix:** the first review's — give every Account re-sign a strictly newer
  `iat`, and in `beats`, on equal `iat` with different content prefer the superset
  of revocations. The build plan defers M6 past the UAT gate; this records that it
  is still open and interacts with the known SCALE.2 push gap.
- **Mark:** CONFIRMED in code; that the two JWTs share a `jti` comes from the
  repo's own comments, not re-read from nats-server.

### B6. Forged "no responders" re-runs an action (J.4)

- **Where:** `internal/saasapi/sealedbus.go` / `dispatchItem`: a genuine request
  the bus answers "no responders" (the bus's own status, which nothing can seal)
  is put back to queued and re-dispatched as a fresh sealed message farmer
  accepts, up to `SAASAPI_OUTBOX_MAX_ATTEMPTS` times. Documented in
  `imas-payload-encryption-design.md` ("What a compromised bus can still do here")
  and accepted by the owner (PR #97).
- **Scenario:** a non-idempotent `cmd.run` dispatched via `internal.sprout.action`
  runs more than once.
- **Fix (not built, owner-accepted):** at-most-once per action item on farmer (an
  idempotency key claimed in Valkey before dispatch), or B2a/B2b core-only
  transport. Recorded here so the human review sees it is a live residual, not
  closed by J.4.
- **Mark:** CONFIRMED; accepted.

## Low

- **B7. `operator` keeps `shell`.** `internal/rbac/config.go:100`:
  `BuiltinOperatorRole` grants `{Action: ActionShell, Scope: "*"}`, so any
  operator can open a shell on any sprout, against the agreed default that
  `operator` loses `shell` unless granted. Deferred to a follow-up PR per J.5's
  owner decision; `TestOperatorRoleNATSAccess` pins today's behaviour. Fix: drop
  `ActionShell` from the built-in role. CONFIRMED.
  **Status (SH.1, PR #102):** fixed as proposed; the built-in role no longer
  grants `shell`, and `TestOperatorRoleNATSAccess` expects it denied.
- **B8. MSI version binding is MAJOR.MINOR.PATCH only.** `internal/ingredients/selfupdate/pkgmeta.go:60-70,196-205`:
  an MSI `ProductVersion` has no prerelease, so an rc's MSI and the final's both
  read `2.5.0`; the code refuses a prerelease manifest on Windows
  (`ErrPrereleaseOnWindows`) to compensate, but two release builds of one
  MAJOR.MINOR.PATCH are indistinguishable by metadata. zypper's downgrade-skip
  (relied on by `verifyInstalled`, `pkgmeta.go:366-385`) was read from source, not
  run on SUSE. Fix: carry the full version in an MSI property the build sets, or
  document the residual. CONFIRMED (deb/rpm); MSI residual and zypper UNCONFIRMED.
- **B9. Staleness is the only bound on a forged pull.** `internal/cook/stagedsync.go:173-176`:
  a pulled recipe is cooked if `DispatchedAt` is within `StagedRecipeMaxAge`; with
  B1 the attacker sets `DispatchedAt`, so the window is no bound at all. Folded
  into B1's fix (authenticate the envelope). CONFIRMED. **Addressed by SEC.7a**
  with B1 (ready for review): `DispatchedAt` and the job ID are read only from
  inside the verified envelope, so the window is farmer's, and a copy older
  than the newest job already handled is refused too.

## Info

- **I1.** The sprout's replay guard is persisted and keyed per process file
  (`internal/pki/sproutbox.go`, `payloadbox/replay.go`); M2 is fixed. A guard file
  that can't be read fails closed for one window (floor = process start + skew),
  which is correct; worth a note that a sprout whose clock is >5m off farmer's
  refuses all farmer messages until fixed (by design).
- **I2.** `handleShellOpen` validates the CLI ephemeral key against low-order
  points and the tenant keys (`internal/natsapi/shell.go:308-325`), and the shell
  stream derives per-session, per-direction keys with forward secrecy
  (`payloadbox/stream.go`); the Decision 3 table's confidentiality and integrity
  claims hold against the `shell_test.go` bus-injection suite. Keystroke timing is
  an accepted, recorded residual.
- **I3.** `internal/facts/listener.go:59-116` takes the sprout from subject token
  2 and drops a body whose id differs; H2 is fixed. Reserved prop names are
  refused in `props.set`/`props.delete` (`internal/natsapi/props.go:52-60`).
- **I4.** The job store (`internal/jobs/store.go`, `listener.go:170-233`) keys
  objects on `jobs/<sprout_id>/<jid>/...` with no tenant in the key; the listeners
  are per-tenant connections, so the tenant is implicit in which connection
  delivered the event. It predates this window (merge `d2692c8`) and is the one
  sprout-keyed store outside H2's scope; a cross-tenant `sprout_id` collision in
  the shared bucket would mix job logs. Worth confirming the bucket is
  per-tenant or the key gains a tenant segment.
- **I5.** `statusError` now drops a raw OpenBao body when `RawError` is set
  (`internal/openbao/openbao.go`); M7 is fixed and pinned by
  `TestKubernetesAuth_LoginRawBodyDropped`.
- **I6.** SEC.5's URL redaction (`internal/ingredients/selfupdate/download.go:227-257`)
  strips query and fragment from URLs in repository errors; L2 is fixed. The regex
  `reURLQuery` handles the common `url.Error` and quoted-Location cases; an
  exotic error string embedding a URL without a scheme would slip through, but the
  repo token itself stays on the repo host and is not in these messages.

## What held up (checked, found sound)

- **Sealed CLI ↔ farmer (J.3).** Bearer tokens are gone from `internal/auth`,
  `internal/api/client`, `cmd/imas` and the audit path; `TestForgedTokenRegression`
  and `nats_nonce_test.go` show a captured `CONNECT` signature is worth nothing.
  Every `imas.api.*` request opens under the verified user's registered CLI box
  key, is bound to method and subject, is replay-guarded per replica and
  Valkey-claimed when mutating, and the reply is sealed. The caller is derived
  from the key, never from params (`sealedrouter.go`, `sealedapi.go`,
  `clibox.go`). The read-only list is explicit and fails closed on Valkey only for
  mutating methods.
- **Sealed SaaS API ↔ farmer (J.4).** `internal.*` requests and results are
  sealed between the SaaS API box key and the platform key, bound to method,
  subject and tenant, replay-guarded and Valkey-claimed; point-of-effect checks
  (`VerifySproutInTenant`, release/signature/window) still run behind the seal.
  The `tenant_provision_test.go` and `sprout_action_sealed_test.go` suites cover
  forged, moved, stale and replayed messages.
- **Sealed refresh (J.2).** `/v1/refresh` takes only `{nkey_pub, sealed}`; the
  NKey-signed contract is gone; the reply is sealed and carries the gateway JWT so
  the DMZ never sees it in the clear. `connect_capture_test.go` shows a captured
  `CONNECT` signature authorises no refresh.
- **Tenant binding and replay (SEC.3b).** `payloadbox.Message` carries `tid` and
  `rk`; `Open` refuses another tenant even under a shared key
  (`TestOpenRefusesAnotherTenantEvenUnderASharedKey`, `sproutbox_tenant_test.go`).
  Replay survives a restart (M2). Opened bodies reach no log sink, the NATS sink
  included (`sealed_sec3b_test.go`); H4 fixed.
- **One active box key, revocation on delete/replace (SEC.3a, H1/M3/M4).** The
  schema enforces one active row per `(tenant_id, sprout_id)`; a grace key may
  only re-assert the active key; dotted and reserved sprout IDs are refused. The
  gap is B2 (enrollment of a first key) and B3 (the gateway JWT), not these.
- **Self-update binding (SEC.5/M1).** The package's own metadata must name
  `imas-sprout` at the manifest's canonical version before install, dpkg gets
  `--refuse-downgrade`, and the installed version is read back. Farmer's own
  `IMAS_SELF_UPDATE_ENABLED` and the rollout window gate it (SEC.5/SEC.5b).
- **Recipe tenant isolation (SEC.4/REC.1).** A name resolves under the cooking
  sprout's tenant prefix, then the platform prefix, never another tenant's
  (`cook/tenant_recipes_test.go`, `api/tenant_recipe_isolation_test.go`); upload
  names are validated to one key each and can't name a reserved root; the SaaS API
  writes only under `tenants/`. The template sandbox removes `env`/`call`/`html`/`js`,
  quotes prop/fact values so a newline can't become recipe structure, and bounds a
  single render's time, output and ranges. The unbounded dimension is the include
  count across one cook (B4).

## Open questions for the human review

1. **`/files/` as a trust boundary (B1, B3, B9).** The staged recipe pull and the
   gateway JWT are the one farmer↔sprout channel sealing left as plaintext-inside-
   TLS, and the DMZ terminates that TLS. Should the staged envelope be
   authenticated end to end, and should the gateway JWT be revocable? Until then,
   can requirement 14 be Green while the staged pull farmer stages is forgeable by
   the DMZ?
2. **First box key at enrollment (B2).** Should a first box key be accepted only on
   the identity-issuing exchange (not the replay path), and should an
   accepted-but-keyless sprout be a closed state rather than a standing window?
3. **Per-cook render budget (B4).** Now that tenants upload recipes, is a total
   per-cook render budget wanted before dispatch is enabled?
4. **M6 (B5), no-responders (B6).** Confirm these deferrals are still intended
   for after the UAT gate. (B7, `operator` and `shell`, was fixed in SH.1, PR #102.)
