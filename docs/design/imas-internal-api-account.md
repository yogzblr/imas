# The SaaS API's NATS identity: which Account, which permissions

Follow-up to `cloudxp-machine-manager-api-design.md` §2 ("Internal API —
Farmer (SaaS API only)"), which says the SaaS API talks to farmer over
privileged internal NATS subjects "authenticated via a privileged internal
NATS identity (system-account-scoped user or mTLS), distinct from any
tenant's sprout/user credentials", but never picks which. Until this
change, the SaaS API had no NATS connectivity at all, and
`internal/saasapi/provisioning.go`'s `dispatchProvisioning`/
`dispatchDeprovisioning` only logged a warning. Nothing published
`internal.tenant.provision`, and farmer had no subscriber for it.

This doc has the same shape as `imas-tenant-context-threading.md`: what we
found, what we decided, and why. **FLAG FOR SECURITY REVIEW:** this adds a
new privileged NATS credential and makes an Account-level trust decision.
The decision and the permission scoping below are the parts that most need
a human to look at them. The plumbing matters less.

## Investigation findings

### The two existing Accounts

`internal/pki/jwtauth.go`'s `natsAuthMaterial` holds the whole trust chain.
Only two of its Accounts could host the new credential:

- **SYS** (`sysAccountKP`/`sysAccountPub`/`sysAccountJWT`). This is the
  server's designated system account (`NatsConfig.SystemAccount` in
  `pki/nats.go`), seeded into the resolver at bus start. It has exactly one
  User today, `imas-farmer-sys-push` (`sysUserKP`/`sysUserJWT`). That User
  is signed directly by the SYS Account's own key and has **no permission
  restrictions**. Farmer uses it in two ways:
  1. **Resolver pushes** (`resolver.go`'s `pushAccountUpdate`). This opens
     a short-lived connection per push, sends one
     `$SYS.REQ.CLAIMS.UPDATE` request, and closes it. It is not
     persistent.
  2. **Heartbeat** (`cmd/farmer/main.go`'s `initHeartbeatListener`, which
     calls `pki.ConnectSystemAccount`). This connection **is**
     long-lived. Farmer opens it once, after the legacy tenant's
     connection is up, and keeps it for the life of the process. It holds
     `$SYS.ACCOUNT.*.CONNECT`/`DISCONNECT` subscriptions and is closed on
     shutdown.
- **tenant / legacy** (`tenantKP`/`tenantPub`/`tenantJWT`). This is the
  Account named by `config.FarmerOrganization`. Its Users are the legacy
  tenant's sprouts, farmer (`allowAllPermissions()` = `imas.>` and
  `_INBOX.>`), and imas CLI admins (same permissions). Since Option A
  (`imas-tenant-context-threading.md`), it is one tenant among many. It
  has its own entry in `cmd/farmer/main.go`'s `tenantConns`, and its
  handlers run bound to `pki.CurrentTenantID()`.

No Account in the codebase has an export or import configured (see
`imas-tenant-context-threading.md`'s Phase 1 finding, which still holds).
Whichever Account hosts the SaaS API's User, farmer's handler for
`internal.tenant.*` has to live on a connection authenticated into **that
same Account**. No cross-account routing exists to bridge them.

### Is the heartbeat SYS connection fit to carry provisioning handlers?

It is **almost** fit. It's persistent, it's authenticated as SYS, and its
lifecycle matches farmer's. It had two weaknesses. Both hurt heartbeat
already, and both would be serious for provisioning:

1. **A boot-time failure was logged and never retried.** If the bus wasn't
   reachable when `initHeartbeatListener` ran, farmer ran with no SYS
   listener until it restarted. For heartbeat that means sprouts look
   offline. For provisioning it would mean every new tenant stays
   `pending` with nothing in the logs after boot.
2. **It used nats.go's default reconnect budget** (60 attempts at 2s
   each). A bus outage longer than about two minutes would close the
   connection permanently, and every subscription on it would stop
   silently.

Both are fixed here, in the connection itself rather than with a second
connection. `pki.ConnectSystemAccount` now takes optional `nats.Option`s,
and `initSystemAccountListeners` (renamed from `initHeartbeatListener`)
dials with `nats.RetryOnFailedConnect(true)` and `nats.MaxReconnects(-1)`.
Subscriptions registered on a connection that isn't connected yet are sent
once it connects, so heartbeat and provisioning both come up whenever the
bus does. Once hardened, the connection is genuinely fit for purpose, so
**we extend it rather than open a new farmer-side connection.**

The short-lived resolver-push connection (`pushAccountUpdate`) is not a
candidate: it closes after each push.

## Decision

**The SaaS API's credential is a new, narrowly-scoped User under the SYS
Account (`imas-saasapi`). Farmer's `internal.tenant.provision`/
`deprovision` handlers are registered on farmer's existing, now-hardened
SYS listener connection** (`natsapi.RegisterTenantProvisioning`,
`internal/natsapi/tenant_provision.go`).

### The User's permissions (the part to review)

Minted by `pki.EnsureSaaSAPICredential` (`internal/pki/saasapi_user.go`);
the subject strings come from `internal/controlplane`:

| Direction | Allow (nothing else) |
|---|---|
| **pub** | `internal.tenant.provision`, `internal.tenant.deprovision` |
| **sub** | `internal.tenant.provisioned.*`, `internal.tenant.deprovisioned.*` |

Other claims on the same JWT:

- `allowed_connection_types: [STANDARD]`. The SaaS API connects over plain
  TCP+TLS inside the control plane. The credential is refused on the
  websocket listener that Envoy's DMZ route terminates onto, and on
  leafnode or MQTT connections. If it leaked, it couldn't be used from the
  DMZ side.
- No `_INBOX.>`. Both flows are fire-and-forget plus a callback subject
  (design doc §2.2), not request-reply, so the User needs no inbox. See
  "Open questions" for when the `internal.sprout.*` request-reply subjects
  land.
- The reply subjects use a single-token wildcard (`*`), not `>`. Job IDs
  are one subject token, and farmer validates this with
  `controlplane.ValidJobID` before building a reply subject from one.
- No `imas.>`, no `imas.api.>`, no `imas.sprouts.>`, no `_INBOX.>`, and no
  `$SYS.>`. Explicit allow-lists deny everything unlisted.

`internal.sprout.*` is **deliberately not included yet.** None of those
subjects has a farmer handler today (`internal.sprout.mint`, `.revoke`,
`.action`, `internal.sprouts.list`, `internal.sprout.enrolled`). Granting
them now would pre-authorize subjects that do nothing. The least-privilege
reading of "exactly the subjects it needs" is the subjects it needs
*today*. Adding them later takes one line in `saasAPIUserPermissions` and
nothing else. `EnsureSaaSAPICredential` re-mints automatically when the
permission set changes, because it compares permissions, not just the
subject.

`internal/pki/saasapi_user_integration_test.go` proves this scoping
against a real embedded bus. It doesn't just assert on the JWT's fields.
It checks that the credential connects, can publish and subscribe on its
own subjects, and is refused (Permissions Violation) for
`$SYS.REQ.SERVER.PING`, `$SYS.REQ.ACCOUNT.*`, `imas.api.*`, and
`imas.sprouts.*`. It also checks that the credential can't subscribe to
`internal.tenant.provision` (only farmer should receive requests), can't
subscribe to `$SYS.ACCOUNT.*.CONNECT` (a cross-tenant connection-metadata
stream), and can't publish a forged `internal.tenant.provisioned.*`
result.

## Reasoning

### Why SYS over the legacy tenant Account

1. **The legacy Account is a tenant.** Since Option A it is one tenant's
   namespace like any other. A platform control-plane credential inside it
   would cross the boundary this whole design rests on ("isolation is a
   property of which Account a connection authenticated into"). It would
   also put platform handlers on a connection whose other handlers all
   receive `tenantID = pki.CurrentTenantID()` as connection-level
   identity. That would muddy Option A's invariant that *a connection's
   Account is its tenant*.
2. **Who else can publish where.** Under SYS, the only identities that can
   publish `internal.tenant.provisioned.*` are farmer's own SYS user and,
   in principle, the operator. The SaaS API itself cannot. So the SaaS API
   can trust that a result came from farmer. Under the legacy Account, the
   same guarantee would depend on every *tenant-owned* identity there
   (sprouts, CLI admins, farmer's tenant User) never being granted
   `internal.>`. Today that holds, because they get `imas.>` at most. But
   the guarantee would then live in tenant-facing permission code that
   gets edited for tenant reasons.
3. **Lifecycle.** The legacy Account is named by
   `config.FarmerOrganization`, and its material is regenerated if that
   name's key material changes. SYS is platform-wide and fixed for the
   operator's lifetime, which fits a platform-wide credential.
4. **Existing infrastructure.** Farmer already maintains a persistent SYS
   connection (above). Reusing it adds zero farmer-side connections. The
   legacy-tenant connection would also have worked mechanically, but only
   because of reasons 1 and 2, which are exactly why it shouldn't be used.

### What choosing SYS does *not* grant

NATS doesn't treat "is a User in the system account" as a capability of
its own. Every publish and subscribe, including on `$SYS.>`, is checked
against the connecting User's own JWT permissions. A User under SYS with
the allow-lists above has no more `$SYS` reach than a User anywhere else.
The integration test above checks this against a real server rather than
assuming it. `$SYS.REQ.CLAIMS.UPDATE` would additionally need an
Operator-signed Account JWT to do anything, but the SaaS API can't reach
that subject in the first place.

### The real cost of SYS, stated plainly

- **Blast radius if the permissions are widened by mistake.** If someone
  later widens `saasAPIUserPermissions` to `>`, the SaaS API gains
  server-administration reach (kick, account info, connection metadata for
  every tenant). Under the legacy Account the same mistake would give
  command dispatch over the legacy tenant's sprouts. Neither is
  acceptable, and the mitigation is the same: exact allow-lists, plus a
  test that fails on any widening.
  `TestSaaSAPIUserPermissions_ExactAllowLists` pins the exact lists, so
  changing them has to be deliberate and reviewed.
- **NATS's general guidance is not to run application traffic in the
  system account.** The concerns behind that guidance are volume, mixing
  app data with server events, and system-account-only features such as
  the lack of JetStream there. They don't apply to a handful of messages
  per tenant onboarding or offboarding, on a bus that doesn't use
  JetStream anyway. If the `internal.*` surface grows into high-volume
  traffic (`internal.sprout.action` at fleet scale, for instance), that's
  the point to revisit the dedicated-Account option below.

### Considered and rejected: a new dedicated "platform" Account

A third Account that is neither SYS nor any tenant's would remove the
widened-permission blast radius above entirely. It costs new Account key
material, a resolver seed in `ConfigureNats` (both binaries), a new farmer
User under it, and a **new** persistent farmer connection, because the
heartbeat connection can't be reused across Accounts. That's the "another
connection" the brief asked us to avoid when an existing one is fit for
purpose, and the existing one is fit once hardened. We rejected it for
now. It's the natural next step if `internal.*` traffic outgrows the
control-plane-only profile described above.

## Signing and delivery: how this matches the rest of the system

The brief asked for the same pattern as `FarmerUserJWTForTenant`/
`GetSproutUserJWTForTenant`, signed "via the existing OpenBao-backed
signing path", and "pushed to the bus resolver the same way every other
User JWT is delivered." Two findings qualify that wording:

- **No NATS JWT in this codebase is signed by OpenBao Transit today.** The
  only Transit-signed token is the *gateway* JWT (`internal/gatewayjwt`).
  Every NATS User and Account JWT, including the two functions named
  above, is signed in-process with an `nkeys.KeyPair`. That key pair's
  seed comes from `loadOrCreateSeed`, which already accepts an
  OpenBao-sourced seed via ESO (`IMAS_NATS_<NAME>_SEED_FILE`/`_SEED`). The
  SaaS API User follows that real, existing pattern exactly. It is signed
  by the SYS Account's key (as `imas-farmer-sys-push` is), and its own
  seed is resolved by `loadOrCreateSeed(..., "SAASAPI_USER", ...)`, so
  `IMAS_NATS_SAASAPI_USER_SEED_FILE` works. Moving NATS JWT signing onto
  Transit is workstream F, and applies to every NATS signer at once. We
  didn't build a one-off Transit signer for this one credential.
- **User JWTs are never pushed to the resolver.** The resolver stores
  Account JWTs only. A User JWT is handed to the client, which presents it
  when it connects, and the server checks it against the issuing
  Account's JWT, which is already in the resolver. Like
  `imas-farmer-sys-push`, the SaaS API User is signed by the SYS Account's
  identity key, so minting it needs **no** push. The one case that does
  need a push reuses the existing mechanism: when the SaaS API's seed
  rotates, `EnsureSaaSAPICredential` adds a revocation for the *previous*
  public key to the SYS Account JWT, re-signs it, and sends it through the
  same `pushAccountUpdate` → `$SYS.REQ.CLAIMS.UPDATE` path every tenant
  Account update uses. Without this, rotating the seed would leave the old
  credential valid forever, because the User JWT carries no expiry.

### Getting the credential to the saasapi Deployment

`SAASAPI_NATS_NKEY_SEED_FILE` and `SAASAPI_NATS_USER_JWT` (plus
`SAASAPI_NATS_URL` and `SAASAPI_NATS_CA_FILE`) are read once at startup in
`internal/saasapi/config.go`. This is the same operational model as
`INTERNAL_AUTH_SECRET_CURRENT`/`PREVIOUS`: a Kubernetes Secret kept in
sync with OpenBao by External Secrets Operator, with Reloader rolling the
Deployment when it changes.

**The seed is only ever taken as a file** (decided on review): the Secret
is mounted as a volume and `SAASAPI_NATS_NKEY_SEED_FILE` names the path.
There is no raw-seed environment variable. A mounted Secret isn't
inherited by child processes or captured in crash dumps or `env` output
the way an environment variable is. This matches `jwtauth.go`'s preference
for the `IMAS_NATS_*_SEED_FILE` form. The JWT isn't secret and stays an
environment variable.

**Not in this repo:** the real OpenBao KV paths and policies, the
`ExternalSecret` manifests, the Reloader annotation, and farmer's own
Deployment/Helm chart. They belong in the separate ops/infra repo, which
this change doesn't have access to. That's the same situation as the
gatewayjwt Envoy wiring. `deploy/farmer/` holds reviewed *reference*
versions of the parts this design depends on (see below). The intended
production flow is:

1. Ops generates the SaaS API's NKey seed and stores it in OpenBao KV.
2. ESO syncs it to farmer as `IMAS_NATS_SAASAPI_USER_SEED_FILE`, so farmer
   never writes the seed to its own disk, and to saasapi as a mounted
   Secret file named by `SAASAPI_NATS_NKEY_SEED_FILE`.
3. At boot, farmer calls `pki.EnsureSaaSAPICredential()`. That mints the
   User JWT (re-minting only if the key or permissions changed), revokes
   and pushes the previous key if it rotated, and writes the JWT to
   `{FarmerPKI}/nats-auth/users/saasapi.jwt`.
4. The JWT gets into OpenBao KV. It's not secret, but it has to travel
   with the seed. `farmer publish-saasapi-credential`, run as a
   Kubernetes Job with farmer's own image, writes it to a dedicated KV v2
   path. ESO syncs it to saasapi as `SAASAPI_NATS_USER_JWT`, and
   Reloader restarts saasapi. See "JWT -> OpenBao hand-off" below.

Farmer holding the SaaS API's seed (step 2) grants farmer nothing new:
farmer already holds the SYS Account key, which can mint any SYS User. If
that ever changes, for example once SYS signing moves to Transit, farmer
only needs the *public* key, and step 2 can drop the farmer half.

## SaaS API boot posture: fail closed

`cmd/saasapi/main.go` calls `log.Fatalf` if the NATS credential is missing
or malformed, or if the first connection attempt fails. This is the
opposite of farmer's per-tenant `connectTenantWithRetry`, and deliberately
so:

- **One required connection, not N optional ones.** Farmer's per-tenant
  retry exists so that one tenant's trouble can't block every other
  tenant. The SaaS API has exactly one bus connection, and every async
  write path (`POST /tenants`, `DELETE /tenants/{id}`) depends on it. No
  other tenant would be isolated from the failure by degrading instead.
- **Degrading silently would be worse than not starting.** A replica that
  accepts `POST /tenants` with no bus connection would write a `pending`
  tenant and return 202, and nothing would ever move that tenant forward:
  the outbox re-dispatch sweeper is deferred (see below). Crash-looping
  surfaces the misconfiguration in the rollout, where Kubernetes' own
  restart backoff does the retrying.
- **After boot, reconnect forever.** Once connected,
  `nats.MaxReconnects(-1)` rides out bus restarts. Publishes during a
  reconnect are buffered by nats.go. If one fails outright, the job stays
  `pending` with its attempt counted, which is the outbox's job.

## Error handling: no internal detail crosses the boundary

`GET /tenants/{id}/status` returns the latest failed job's `last_error` to
external callers (pre-existing behavior), and a pki error's text can name
farmer filesystem paths, key files, or database detail. So raw error text
never leaves farmer:

- **Farmer** logs the full error locally, keyed by job ID, and publishes
  only a fixed `controlplane.ErrorCode`: `invalid_tenant_id` or
  `tenant_not_found` for pki's own sentinel errors, and `internal_error`
  for everything else (`natsapi.tenantErrorCode`). No free-text error
  field exists on `TenantResult`.
- **The SaaS API** stores and displays only
  `controlplane.PublicErrorMessage(code)`, a fixed caller-safe string,
  plus the job ID as a reference an operator can match against farmer's
  logs (`saasapi.publicJobError`). An unrecognized code maps to the
  generic message rather than being echoed, so even a farmer bug that put
  detail in `error_code` couldn't surface it.

The end-to-end failure test provokes a real pki error whose text contains
a farmer path, and asserts that the text appears in none of the published
result, `saas.provisioning_jobs.last_error`, or the `GET` status
response. Putting `err.Error()` back on the bus makes that test fail.

## Offboarding rules (decided on review)

- **DELETE is refused while provisioning is in flight.** If the tenant is
  `pending`, or any provision job for it is still `pending`, `DELETE
  /tenants/{id}` returns 409 `provisioning_in_progress` and changes
  nothing. Only `active` or `failed` tenants can be offboarded, and that's
  enforced by a conditional update inside the transaction, not just the
  pre-check. This closes the race where farmer's queue group could run a
  tenant's provision and deprovision requests out of order on different
  replicas and leave a live Account for a tenant that `saas` considers
  offboarded. The result listener's status guards remain as defense in
  depth: a late provision success never moves an `offboarding` tenant
  back to `active`.
- **Offboarding a tenant farmer never provisioned succeeds, with a
  warning.** If `pki.DeprovisionTenant` finds no `pki_tenants` row
  (`ErrTenantNotFound`), there's nothing to tear down. Farmer reports
  `offboarded` with `warning_code: tenant_not_provisioned`, the tenant
  moves to `offboarded`, and `GET /tenants/{id}/status` answers 200 with a
  fixed `warning` message (`controlplane.PublicWarningMessage`). The
  `DELETE` itself stays 202, because the async contract is unchanged:
  farmer is what finds out there was nothing to tear down.
- **What makes that safe.** `getTenantRow` used to map *every* lookup
  error, including a transient DB error, to `ErrTenantNotFound`. It now
  returns `ErrTenantNotFound` only for an absent row, and wraps any other
  database error. Without that, a DB outage during a deprovision would
  have been reported as success while the tenant's Account stayed live on
  the bus. The same fix closes a latent bug in `ensureTenantAccountLocked`:
  on any lookup error it fell through to `upsertTenantRow`, whose upsert
  resets `deleted`, so a transient error could silently un-delete a
  deprovisioned tenant. It now returns the error instead
  (`TestTenantLookup_NotFoundVsDBError`).

## JWT -> OpenBao hand-off (decided)

Closes what was the last open question here. **FLAG FOR SECURITY
REVIEW:** this adds the repo's first OpenBao *write* policy.

- **SYS Account seed: an ops change only.** The SYS Account key already
  loads through `loadOrCreateSeed(path, "SYS_ACCOUNT", ...)` like every
  other key, so `IMAS_NATS_SYS_ACCOUNT_SEED_FILE` pointing at an
  ESO-mounted Secret is all it takes. farmer's Deployment isn't in this
  repo, so the exact volume, mount path and env var are specified in
  `deploy/farmer/farmer-deployment-nats-seeds.patch.yaml` for the ops
  repo. farmerbus needs the same seed, and an existing install must
  import its current `sys-account.nk` rather than generate a new one
  (`deploy/farmer/README.md`).
- **The JWT: a farmer subcommand run as a Job, not farmer's server.** A
  mounted Secret only flows from the secret store into the pod, so
  publishing the minted JWT needs a real KV write.
  `farmer publish-saasapi-credential` (`internal/saasapicred`) runs
  `pki.EnsureSaaSAPICredential()` and then `pki.PublishSaaSAPICredential`.
  That writes `{jwt, public_key}` (never the seed) to a configurable
  KV v2 path through a hand-rolled client (`internal/openbaokv`; the
  OpenBao SDK is MPL-2.0). It writes nothing when the published JWT is
  already current by claims. The reference Job
  (`deploy/farmer/saasapi-credential-publish-job.yaml`) runs farmer's image
  with the same seed Secret and an emptyDir PKI directory. That means it
  never pushes to the resolver, never reaches the bus, and never races
  farmer on its PKI files. Revocation on rotation stays farmer's job, at
  boot. The subcommand refuses to run if either key would have to be
  generated.
- **Least privilege.** Only the Job's own OpenBao role
  (`imas-saasapi-cred-publisher`, bound to its own ServiceAccount) gets
  `create`/`update`/`read` on that one data path. farmer's server process
  gets no capability on it, and none of the `IMAS_SAASAPI_CRED_OPENBAO_*`
  configuration. The exact policy, and what farmer's policies must keep
  excluding, is in `deploy/farmer/README.md`.
- **When it runs:** automatically after every farmer deployment
  (post-install/post-upgrade hook). Permission changes to the credential
  only ship with a farmer deployment, and re-running is a read-only no-op.
  Seed rotation isn't a deployment, so the rotation runbook also triggers
  the Job explicitly.

## Deferred / open questions

- **Outbox re-dispatch sweeper.** NATS core gives no redelivery guarantee
  (design doc §4). If farmer is down when a provision request is
  published, or saasapi is down when the result comes back, the job stays
  `pending`. `ProvisionTenant` and `DeprovisionTenant` are idempotent, so
  a periodic re-publish of stale `pending` jobs is safe. That's the
  natural follow-up and isn't built here. `attempts` is incremented on
  every dispatch so the sweeper has something to bound on.
- **`internal.sprout.*` permissions.** Added when those handlers land (see
  above). `internal.sprout.mint`, `.revoke`, `.action`, and
  `internal.sprouts.list` are request-reply, so that change also has to
  grant a *scoped* inbox. Use `nats.CustomInboxPrefix` with, for example,
  `_INBOX.saasapi.>` rather than a bare `_INBOX.>`, so the SaaS API can't
  subscribe to other SYS users' reply inboxes.
- **A tenant stuck `pending` can't be deleted.** Because of the DELETE
  guard above, a tenant whose provision request was lost (farmer down at
  dispatch time) stays `pending` and undeletable until the outbox sweeper
  exists to re-dispatch it. That's one more reason the sweeper is the
  next piece of work.
