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

**Deployment:** `deploy/helm/farmer` deploys farmer and saasapi with this
design's pieces: the seed mounts, the publish Job, the `ExternalSecret`
manifests (`externalSecrets.enabled`), the Reloader annotation and the
OpenBao policies. `deploy/farmer/` holds the reviewed *reference* versions
the chart is tested against (see below). The real OpenBao KV paths are
still an operator choice. The intended production flow is:

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
  tenant and return 202, and only another replica's outbox sweeper would
  ever move that tenant forward (see "Outbox re-dispatch sweeper" below).
  Crash-looping surfaces the misconfiguration in the rollout, where
  Kubernetes' own restart backoff does the retrying.
- **After boot, reconnect forever.** Once connected,
  `nats.MaxReconnects(-1)` rides out bus restarts. Publishes during a
  reconnect are buffered by nats.go. If one fails outright, the job stays
  `pending` with its attempt counted, and the outbox sweeper publishes it
  again. A sweep on a replica that is between reconnects is skipped.

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
  KV v2 path through `internal/openbaokv`, on the official OpenBao Go
  client (`internal/openbao`). It writes nothing when the published JWT is
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

## Outbox re-dispatch sweeper (CL.3, built)

**FLAG FOR SECURITY REVIEW.** NATS core gives no redelivery guarantee
(design doc §4), and every async operation (tenant provisioning, §1.5
batch actions, §1.8 update rollouts) is dispatched by goroutines of the
process that accepted the request. Before CL.3, a pod that died, or had no
bus connection, left tenant jobs `pending`, batch items `queued` forever,
and an update rollout stopped with its tenant's one rollout slot taken for
good. `internal/saasapi/sweeper.go` is the sweeper; it runs on every
replica (`SAASAPI_OUTBOX_SWEEPER_ENABLED`, default on), every
`SAASAPI_OUTBOX_SWEEP_INTERVAL` (30s), and skips a sweep when the replica
has no bus connection.

**Row leases, not `GET_LOCK`** (`internal/saasapi/outbox_lease.go`,
migration `saas/00006`). `GET_LOCK` is local to one PXC node. A lease is
two columns on the row whose work it guards, `lease_owner` (a token: the
pod name plus a random suffix per claim) and `lease_until`:

- *Claim*: one conditional `UPDATE ... SET lease_owner = <new token>,
  lease_until = now + TTL WHERE <row key incl. tenant_id> AND (lease_until
  IS NULL OR lease_until < now) AND <row-specific conditions>`. The caller
  owns the row only if the `UPDATE` affected it. Two claims on one node
  serialize on InnoDB's row lock and the second matches nothing; on two PXC
  nodes both write the same row and Galera certification refuses one, which
  sees an error. An error is never taken as a claim.
- *Renew*: `UPDATE lease_until WHERE lease_owner = <token>`, every third of
  `SAASAPI_OUTBOX_LEASE_TTL` (2m). The new value is always later than the
  stored one, so MySQL (which reports changed rows, not matched ones) never
  reports a renewal as zero rows. Zero rows means another holder took it:
  the lease is lost at once.
- *Hold*: work under a lease checks it before every send (each item, each
  wave) and stops once it is lost or has expired on its own clock. A holder
  that can't reach the database stops sending before anyone can claim the
  row. Leases are never released; they lapse, so `lease_until IS NULL`
  keeps meaning "written by the previous release, never leased".
- Clocks: lease times are each replica's own clock. Replicas are assumed to
  agree to well within the TTL (NTP); a replica whose clock runs ahead by
  more could claim a row early. Every individual send is still guarded by
  the row-level claim each job already uses (below), so the worst case is
  pacing (two holders working one rollout's waves), never one item sent
  twice.

Everything is keyed on the existing composite keys with `tenant_id`
(`provisioning_jobs` by id and tenant, batches by id and tenant, items by
batch, asset and tenant); nothing is keyed on `sprout_id` alone.

**Job 1: provisioning jobs.** A `pending` job whose backoff has passed
since its last publish (`last_dispatched_at`, or creation if it was never
published) is published again: `SAASAPI_OUTBOX_PROVISIONING_STALE_AFTER`
(2m), doubling per attempt, capped at 64×. The claim is the same `UPDATE`
that counts the attempt (`WHERE status = 'pending' AND attempts = <read>`),
so two sweepers can't both publish one attempt. After
`SAASAPI_OUTBOX_MAX_ATTEMPTS` (5) publishes and one more backoff with no
result, the job is failed with a fixed `last_error` ("no result was
received ... (reference pj_…)") and, for a provision job, the tenant moves
`pending` → `failed` so it can be deleted. A result that arrives later is
ignored like any duplicate.

*Farmer and a repeated `job_id` (checked for CL.3).* Harmless on its own:
`handleTenantProvision` calls `pki.ProvisionTenant`, which finds the
existing `pki_tenants` row, re-confirms the Account material and re-pushes
it (idempotent by design); `handleTenantDeprovision` calls
`pki.DeprovisionTenant`, which finds the row already deleted and returns
nil, so farmer reports `offboarded` again. Each copy publishes a result on
`internal.tenant.{de,}provisioned.<job_id>`; `applyProvisioningResult`
applies the first (conditional on `status = 'pending'`) and ignores the
rest. A provision request for a tenant already deprovisioned is refused by
`ensureTenantAccountLocked` ("tenant was deprovisioned"), so a late copy
can't recreate a deleted tenant row. **The one hazard** is a late copy of a
provision request still *running* on one farmer replica while a
deprovision of the same tenant runs on another: `ProvisionTenant` reads the
Account JWT before the deprovision locks it out and pushes it afterwards,
outside `tenantAuthMu`. The bus's full resolver keeps the JWT with the later
`iat`, so the stale push loses unless `syncTenantSprouts` re-signed the
JWT during the race, but that isn't a guarantee. Without the sweeper this
can't happen (DELETE requires the provision result first, and there is one
copy). With it, saasapi now refuses `DELETE` with
`409 provisioning_in_progress` for `SAASAPI_OUTBOX_PROVISIONING_STALE_AFTER`
after the last publish of a provision job that was published more than
once, which far outlasts the seconds farmer's handler takes. The farmer
side fix belongs in `internal/pki`, outside CL.3's scope, and is listed as
an open question below.

**Job 2: §1.5 action items.** A batch is written already leased to the
process that accepted it (`createBatch`), which renews the lease while it
dispatches. Once the lease has lapsed, the sweeper claims the batch and
re-dispatches its `queued` items, from the batch's stored
`action_params`, once each item's backoff has passed
(`SAASAPI_OUTBOX_ACTION_STALE_AFTER`, from the item's last change, doubling
per attempt). Every send still goes through `dispatchItem`'s
`queued → dispatching` claim, so a dispatcher that outlived its lease and a
sweeper can't both send one item. What is and isn't re-sent:

- `queued`: re-sent. A queued item has provably never reached farmer: it
  was never claimed, or its claim ended in "no responders" (no farmer
  subscribed), which `dispatchItem` moves back to `queued` with
  `dispatched_at` cleared.
- `dispatching`: **never re-sent.** Its request went out, or may have, and
  no reply was recorded. Once the process waiting on the reply would have
  given up (its reply timeout, `farmerSproutWait + dispatchReplyMargin`
  plus a `cmd.run`'s own timeout, plus another `dispatchReplyMargin` for
  clock skew: `stuckDispatchAfter`), and the batch's lease has lapsed, the
  sweeper fails it with `dispatch_outcome_unknown`. That is the code
  `dispatchItem` itself records when a reply times out. The conditional
  update (`dispatching` → `failed`) means a late reply recorded first wins.
- `queued` past `SAASAPI_OUTBOX_MAX_ATTEMPTS`: failed with
  `dispatch_not_delivered`, unsent. `queued` whose tenant is no longer
  `active`: failed with `tenant_not_active`, unsent.
- `queued` past `SAASAPI_OUTBOX_ACTION_MAX_AGE` (15m) since the POST:
  failed with `expired_not_sent`, unsent. The original dispatcher applies
  the same limit to an item still waiting for a dispatch slot, so no §1.5
  command is ever sent more than that long after it was accepted. Update
  rollout items are exempt: they wait for their wave by design, and every
  wave re-checks the tenant's policy.

*No re-send exception for idempotent commands (checked for CL.3).* Nothing
on the path deduplicates a second send of one item. saasapi's
`SproutActionRequest` carries only tenant, sprout and action, with no
request id. Farmer seals every send with a fresh random envelope id
(`payloadbox.NewMessage`), and gives a cook or self_update a fresh jid
(`cook.GenerateJobID`). The sprout's replay guard keys on the envelope id,
so it only catches a byte-for-byte replay of one sealed message. Its
handled-jobs file keys on the jid and is only read when it pulls a staged
recipe, never for a pushed command. A re-sent `cmd.run` or cook would run
twice; a re-sent self_update would update a second time unless the
sprout is already on the target. So a stuck item is never re-sent
automatically; an operator retries deliberately.

*No age limit downstream (checked for CL.3).* The sealed envelope's
freshness window is ±5 minutes (`payloadbox.DefaultMaxSkew`), but it is
measured from `IssuedAt`, which farmer sets when it seals the message at
dispatch, not from when saasapi accepted the request. Nothing else on the
farmer or sprout side rejects a command for its age. Farmer's
`IMAS_JOB_RECONCILE_WINDOW` and the sprout's `stagedrecipemaxage` both
count from farmer's dispatch, and `stagedrecipemaxage` only applies to
pulled cooks. So `SAASAPI_OUTBOX_ACTION_MAX_AGE` is the only bound on how
late a command can arrive. It is not capped at the envelope window, which
measures something else.
- `self_update` batches are never re-dispatched by this job (job 3).

**Job 3: update rollouts** (only with
`SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED=true`). `runRollout` now renews the
batch's lease, checks it before every wave and before halting, and stops
without halting once it is lost. A `self_update` batch with `queued`,
`dispatching` or `running` items whose lease has lapsed is taken over: the lease claim and a
rewrite of the tenant's `tenant_update_policy.rollout_claimed_at` (the
tenant's rollout claim, `claimRollout`) happen in one transaction, so on
PXC the takeover certifies against any other claim on the tenant. The
resumed run (`resumeRollout`) rebuilds its state from the rows:

- Wave size, gate and target version: the batch's `rollout_batch_size`,
  `rollout_gate` and `action_params`, as created.
- Which items were sent, and when: the new `asset_action_items.dispatched_at`
  (set by `dispatchItem`'s claim, cleared on "no responders"). Items that
  existed before had no dispatch time anywhere: `updated_at` is the reply
  time, not the dispatch time. Rows from before the migration fall back to
  their status and error code, and to `updated_at` for the time (stricter,
  as `runningSinceProof` already is).
- Which items may pass on their job's success: the new
  `asset_action_items.planned_at_target` (`planUpdateItems`' `atTarget`),
  which was only in the dead process's memory. Without it, a sprout already
  on the target would never write a fresh report and would always end
  `unresponsive_after_update`, wrongly halting the rollout.

Every item already sent forms one wave, each with its own deadline
(`dispatched_at` + 30m) and proof; it must pass the batch's gate before
anything else is sent (`job_status`: all succeeded; `dispatch`: all
accepted, none failed). An item left in `dispatching` is never re-sent:
its deadline is `stuckDispatchAfter` from its dispatch (75 seconds for a
self_update), after which it fails with `dispatch_outcome_unknown`. That
fails the gate, halts the rest with `rollout_halted`, and leaves nothing
`queued`, `dispatching` or `running`, so the tenant's rollout slot
(`updateInProgress`) is free. An operator can start a new rollout
deliberately; sprouts already on the target answer "already running".
Then
the `queued` items go out in request order, in waves of the original size,
exactly as `runRollout` sends them. Before every resumed wave the tenant's
policy and window and the version's revocation are checked
(`rolloutPolicyCheck`, failing unsent items with the same codes as a live
rollout: `version_revoked`, `version_approval_withdrawn`,
`rollout_window_closed`), and also that the tenant is still `active`
(`tenant_not_active`) and the version is still registered with every
row's signature verifying and building the batch's exact params
(`rollout_halted`), mirroring `CreateFleetUpdateBatch` and farmer's FU.7
re-verification. A batch with no lease at all (written by the previous
release, whose process may still be running it) is taken over only once
none of its items has changed for longer than any live wave goes without a
write (wave timeout + reply wait + lease TTL).

## Deferred / open questions

- **Farmer-side provision/deprovision race** (BUILD-STATUS "Open
  items"). See job 1 above. `pki.ProvisionTenant` should re-check
  `deleted` after its resolver push (under `tenantAuthMu`) and re-push the
  locked-out JWT if a deprovision won the race. `pki.DeprovisionTenant`
  should re-push the locked-out JWT even when the row is already deleted,
  so a retried deprovision repairs the bus. `internal/pki` was outside
  CL.3's file scope. Until it lands, saasapi's DELETE wait is the
  mitigation. That wait is read from `provisioning_jobs.attempts` and
  `last_dispatched_at` in the DELETE's own transaction, so every saasapi
  replica sees it, not just the one whose sweeper re-published
  (`TestMySQLDeleteWaitIsSharedAcrossReplicas`).
- **Items stuck in `dispatching`: decided and built (CL.3).** Failed with
  `dispatch_outcome_unknown` once their dispatcher would have given up,
  never re-sent, and for an update rollout that halts it and frees the
  tenant's slot (job 2 and job 3 above).
- **Maximum age for queued §1.5 items: decided and built (CL.3).**
  `SAASAPI_OUTBOX_ACTION_MAX_AGE`, 15 minutes by default (job 2 above).
- **`internal.sprout.*` permissions.** Added when those handlers land (see
  above). `internal.sprout.mint`, `.revoke`, `.action`, and
  `internal.sprouts.list` are request-reply, so that change also has to
  grant a *scoped* inbox. Use `nats.CustomInboxPrefix` with, for example,
  `_INBOX.saasapi.>` rather than a bare `_INBOX.>`, so the SaaS API can't
  subscribe to other SYS users' reply inboxes.
- **A tenant stuck `pending` can't be deleted: resolved by CL.3.** The
  sweeper re-publishes a lost provision request and, after
  `SAASAPI_OUTBOX_MAX_ATTEMPTS`, fails the job and moves the tenant to
  `failed`, which can be deleted.
