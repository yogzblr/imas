# Real per-request tenant identity: findings and threading plan

Follow-up to workstream E's dynamic tenant Account provisioning
(`internal/pki/tenant.go`), whose own header comment names this
limitation explicitly: `ProvisionTenant` mints and pushes a new tenant's
NATS Account, but every already-existing read/write handler still
resolves "which tenant" through the single process-global
`tenantID()`/`config.FarmerOrganization` seam, not real per-connection
identity. This doc is Phase 1's investigation (does farmer's one bus
connection actually see more than one tenant's traffic today?) and the
resulting design for Phase 2 (threading real tenant identity through the
listed call sites).

## Phase 1 finding: today, it does not work for more than one tenant

**`cmd/farmer/main.go`'s `ConnectFarmer` opens exactly one NATS
connection for the whole farmer process, and that connection is
authenticated into exactly one NATS Account: the legacy "current tenant"
Account (`natsAuthMaterial.tenantPub` in `internal/pki/jwtauth.go`, named
by `config.FarmerOrganization`).** Concretely:

- `jwtusers.go`'s `syncNatsAuth` mints farmer's own User JWT
  (`farmerUserJWTPath()`) with `IssuerAccount = mat.tenantPub` — the one
  legacy Account, unconditionally.
- `ConnectFarmer` connects with exactly that JWT
  (`pki.FarmerUserJWT()`) plus farmer's NKey seed, once, at process
  startup. There is no second, third, ... connection for any other
  tenant.
- `internal/natsapi.Subscribe(nc)` registers every `imas.api.>` handler,
  and every ingredient package's `RegisterNatsConn(nc)`
  (`internal/cook`, `internal/cmd`, `internal/test`, `internal/jobs`,
  `internal/facts`) registers its sprout-facing subscriptions, all on
  that one connection.
- `internal/pki/tenant.go`'s `ProvisionTenant` mints a *new*, distinct
  Account (`tenantAccountMaterial.pub`, keyed by `tenantID`, disjoint
  from `mat.tenantPub`) for every dynamically-provisioned tenant, and
  `enroll.go` issues each such tenant's sprouts a User JWT
  (`GetSproutUserJWTForTenant`) under *that* Account — never under the
  legacy `mat.tenantPub`. `tenant.go`'s own header comment already notes
  it "configures no exports/imports anywhere in this file."

NATS Accounts are a hard isolation boundary by design (see
`docs/design/imas-nats-jwt-auth-design.md`'s "isolation is enforced by
which Account a connection authenticated into"): two Accounts share
*nothing* — no cross-account pub/sub — unless an explicit export/import
is configured on their JWTs. We confirmed by reading every file that
touches Account claims (`jwtauth.go`, `tenant.go`, `nats.go`,
`resolver.go`) that **no export or import is configured anywhere in this
codebase, for any Account.**

The consequence: a sprout enrolled under tenant B's dynamically
provisioned Account (`enroll.go` -> `ReloadNKeysForTenant` ->
`ProvisionTenant`) can authenticate to the bus, but every message it
publishes — to `imas.api.>`, `imas.sprouts.<id>.>`, the box-key submit
subject, everything — lands in an Account namespace that farmer's single
connection (parked in the legacy Account) structurally cannot see.
**It's not that farmer mis-identifies tenant B's traffic as some other
tenant's; it's that farmer never receives it at all.** Today, exactly one
tenant — whichever one `config.FarmerOrganization` names at boot — can
talk to farmer over NATS. This is a connectivity ceiling, not merely a
tenant-*identification* bug, and it sits upstream of everything else in
this doc.

There is exactly one existing exception, and it's instructive: **the
`$SYS.ACCOUNT.*.CONNECT`/`DISCONNECT` event stream farmer's heartbeat
listener subscribes to (`internal/heartbeat.RegisterListener`, connected
via `pki.ConnectSystemAccount` as the SYS account) already fires for
*every* Account on the server, not just one** — that's what the SYSTEM
account is for in NATS's decentralized-auth model, and it's independent
of the export/import mechanism entirely (a different, privileged data
plane, not ordinary subject routing). Each event's JSON body
(`nats-server/v2/server.ClientInfo`) already carries the connecting
Account's public key in a field tagged `"acc"` — `heartbeat.go`'s own
`clientInfo` struct simply doesn't decode it today, and its `tenantID()`
doc comment explicitly says why it doesn't use it: "that's the tenant
NATS Account's public key ..., a different identifier space than
`config.FarmerOrganization`." No reverse mapping
(Account pubkey -> tenant ID) existed to make use of it. That mapping is
easy to add (see below) and requires no new connectivity — which is why
`internal/heartbeat` is the one call site in this doc's scope that gets a
*complete*, uncapped fix rather than a documented ceiling.

## What a message handler can actually derive tenant identity from, today

| Path | Mechanism available today | Real tenant available? |
|---|---|---|
| `$SYS.ACCOUNT.*.CONNECT`/`DISCONNECT` (heartbeat) | `ClientInfo.Account` (`"acc"` in the event JSON) — the connecting user's real Account pubkey, delivered because SYS account visibility spans every Account by NATS design | **Yes**, once reverse-mapped to a tenant ID (new: `pki.TenantIDForAccountPub`) |
| `imas.api.>` / `imas.sprouts.>` / box-key submit (everything `natsapi.Subscribe` and friends register) | None — single connection, single Account, no export/import, no per-message header carrying tenant | **No.** The only tenant reachable at all is the one the shared connection authenticated into (`pki.CurrentTenantID()`) |
| HTTP admin API (`internal/api/handlers`) | Same RBAC/token model as NATS — `internal/auth`/`internal/rbac`'s policy has no tenant concept in it at all (one loaded policy per farmer process) | **No** — same ceiling, for a different reason (auth itself is single-tenant, not just transport) |

Subject structure after import re-mapping and per-connection metadata are
both real NATS mechanisms in general — they're listed here because they
are the two candidate *fixes* for the middle row, not because either is
wired up today.

## The prerequisite: making the shared connection multi-tenant

Two designs would close the gap in the "no" rows above. Recording both
because the choice affects where a future PR's diff lands; only the
lighter-weight groundwork (the reverse-lookup helper any option needs) is
implemented in this PR — see "Scope of this PR" below.

**Option A — one connection per tenant.** `ConnectFarmer` maintains a
`map[tenantID]*nats.Conn`, opening one dedicated connection per
provisioned tenant (its own farmer-User JWT, minted under that tenant's
own Account — `tenant.go` would need to mint one, the way `jwtusers.go`
does for the legacy Account today) and calling
`natsapi.Subscribe(nc, tenantID)` once per connection. Each handler
closure captures its own connection's `tenantID` as connection-level
metadata — no message needs to carry it. New tenants (first enrollment,
or an explicit `internal.tenant.provision`) open a new connection at
runtime; a deprovisioned tenant's connection is closed. Keeps
`subjects.go` completely unprefixed, exactly as
`imas-nats-jwt-auth-design.md` recommends. Cost: connection lifecycle
management in `cmd/farmer/main.go`, and every `RegisterNatsConn`-style
registration (`cook`, `cmd`, `test`, `jobs`, `facts`, `natsapi.Subscribe`
itself) needs to run once per tenant connection instead of once per
process.

**Option B — account exports/imports with subject remapping.** Every
tenant Account exports its sprout-facing subjects
(`ProvisionTenant`/`ensureTenantAccountMaterial` in `tenant.go` would add
an `Export`); a new, dedicated "core" Account (not any tenant's, and not
the legacy `mat.tenantPub`) imports each tenant's export, remapped to a
per-tenant local prefix (e.g. tenant `t_8f2a`'s traffic surfaces locally
under `tenants.t_8f2a.>`). Farmer connects once, as a User under this new
core Account. A handler derives tenant identity by parsing the prefix off
`msg.Subject` after the import remap — "subject structure after import
re-mapping." Cost: the reverse direction (farmer/core publishing
*to* a sprout, e.g. `PublishEncryptedTo`, and NATS request-reply's reply
subject) needs its own import/export pair per tenant too, which
`nats-server`'s import/export model supports but makes request-reply
noticeably more fiddly to get right; and every tenant's import must be
added to core's Account JWT as tenants are provisioned, so core's own
Account JWT keeps growing and needs re-signing/re-pushing on each
`ProvisionTenant` call, alongside the tenant's own Account push.

**Recommendation: Option A.** It matches the design doc's own stated
intent ("isolation... as a property of which account a connection
authenticated into, not a string convention"), avoids re-deriving
identity from string parsing on every message, and doesn't need core's
own Account JWT to be mutated on every tenant onboarding. Its cost is
concentrated in `cmd/farmer/main.go`'s connection lifecycle and
`internal/natsapi.Subscribe`'s signature — outside this task's stated
file scope (`internal/pki`, `internal/natsapi/crypto.go`,
`internal/props`, `internal/rbac`, `internal/heartbeat`) and touching
every ingredient package that calls `RegisterNatsConn`
(`internal/cook`, `internal/cmd`, `internal/test`, `internal/jobs`,
`internal/facts`) besides. Per this repo's file-scope convention
(CLAUDE.md: "stop and say why" rather than silently expanding), this PR
does **not** implement Option A — it's flagged here as the concrete,
recommended next workstream, sized at roughly the same order of effort as
workstream E's original per-tenant-Account provisioning work.

## Scope of this PR, given the above

1. **`internal/heartbeat`**: real fix, no ceiling. `clientInfo` decodes
   `ClientInfo.Account` (`"acc"`); a new `pki.TenantIDForAccountPub`
   (backed by a new `tenantRow.AccountPub` column, populated at
   provisioning time, with the legacy `mat.tenantPub` Account also
   resolving to `pki.CurrentTenantID()`) maps it to a real tenant ID per
   CONNECT/DISCONNECT event. Tests exercise two real tenants' Accounts
   concurrently and assert their heartbeat keys land under, and only
   under, their own tenant.
2. **`internal/pki`, `internal/natsapi/crypto.go`**: every function named
   in the task brief (`AcceptNKey`, `DenyNKey`, `RejectNKey`,
   `UnacceptNKey`, `DeleteNKey`, `GetNKey`, `NKeyExists`,
   `GetNKeysByType`, `ListNKeysByType`, `ValidSproutBoxKeys`,
   `RotateSproutBoxKey`, and `crypto.go`'s `sealForSprout`/
   `openFromSprout`/`PublishEncryptedTo`/`DecryptEncryptedFrom`) now
   takes an explicit `tenantID` parameter and no longer reads the
   package-global seam internally. This is real, unit-testable
   tenant-parameterization — calling any of these with two different
   tenant IDs produces genuinely isolated results, provably (see the new
   concurrent two-tenant tests), regardless of the transport ceiling
   above. `Accept/Deny/Reject/Unaccept/DeleteNKey`'s deferred reload now
   calls `ReloadNKeysForTenant(tenantID)` instead of unconditionally
   reloading the legacy Account — a real correctness fix in its own
   right (previously, admin-accepting a sprout under a
   dynamically-provisioned tenant would reload and push the *wrong*
   Account).
   Every existing caller of these functions (`internal/api/handlers`,
   its `ingredients/{cmd,test}` subpackages, and every file under
   `internal/natsapi` that calls into PKI) is updated to compile — most
   pass `pki.CurrentTenantID()` explicitly, which is the honest
   ceiling documented above: production behavior at the transport layer
   is unchanged (still exactly one reachable tenant) until Option A (or
   B) lands, but the dependency on "which tenant" is now an explicit,
   visible argument at each call site instead of a hidden package
   global — the localized, mechanical change Option A's follow-up needs
   to make is now confined to swapping that one argument per call site,
   not touching `internal/pki`/`internal/natsapi/crypto.go` again.
3. **`internal/props`**: adds explicit-tenant twins
   (`GetStringPropForTenant`, `SetPropForTenant`, `DeletePropForTenant`,
   `GetPropsForTenant`, `GetStringPropFuncForTenant`, ...) alongside the
   existing bare functions, following the `...ForTenant`/`...InTenant`
   convention `internal/pki/store.go` and `internal/rbac` already use for
   this exact migration. Only the two in-scope callers move onto them:
   `internal/natsapi/props.go`'s handlers (passing
   `props.CurrentTenantID()`, same ceiling as above) and
   `internal/rbac/cohort.go`'s dynamic-cohort resolution (passing the
   `Registry`'s own `tenantID` — see next point). The bare functions stay
   in place, unchanged, for `internal/cook` and `internal/facts`: neither
   package has any tenant concept of its own today (they only know
   `sproutID`), and giving fact ingestion and cook templating real tenant
   scoping is a separate, larger workstream outside this task's file
   scope — flagging it here rather than silently dragging two more
   packages into this diff.
4. **`internal/rbac`**: `RoleStore`/`UserRoleMap`/`Registry` already
   carry an explicit `tenantID` fixed at construction (workstream E
   groundwork already landed) — that part needed no change. The actual
   bug fixed here: `cohort.go`'s `resolveDynamic` called
   `props.GetStringPropFunc(sproutID)`, which resolves properties through
   *props' own* global seam rather than the calling `Registry`'s
   `tenantID` — so a `Registry` explicitly constructed for tenant A could
   silently resolve a dynamic cohort's membership against tenant B's (or
   the legacy tenant's) prop values. Fixed to call
   `props.GetStringPropFuncForTenant(r.tenantID, sproutID)`. Policy
   loading itself (`LoadRolesFromConfig`/`LoadUsersFromConfig`/
   `LoadCohortsFromConfig`, driven by `auth.LoadPolicy`/
   `loadCohortRegistry` in `cmd/farmer/main.go`) stays on the
   process-global seam deliberately: it's genuinely boot/SIGHUP-time,
   config-file-driven, one-policy-per-farmer-process today, with no
   per-request notion of "whose policy" anywhere else in `internal/auth`
   either — that's a structural, single-tenant property of the whole
   RBAC/auth subsystem, not something this task's file list can fix
   piecemeal, and it's flagged here as its own follow-up (FLAG FOR
   SECURITY REVIEW: today, PKI/props/heartbeat data is tenant-isolated by
   this PR and its prerequisite, but the RBAC policy deciding who may act
   on it is not tenant-scoped at all).
5. `tenantID()` remains, package-private, in `internal/pki/store.go`,
   `internal/props/store.go`, and `internal/rbac/store.go` for exactly
   the boot/SIGHUP-time contexts named above, exposed where needed via a
   new exported `CurrentTenantID()` — not removed, since those contexts
   are genuinely process-level today, not a per-message identity being
   papered over.

## FLAG FOR SECURITY REVIEW

This PR's pki/props/rbac/heartbeat storage-layer changes are correctness
fixes with real test coverage (two concurrent tenants, not one tenant
asserted twice) for the code paths listed above. They do **not** by
themselves make farmer safe to run multi-tenant in production: until
Option A (or B) is implemented, only one tenant's sprouts can reach
farmer's `imas.api.>`/`imas.sprouts.>` surface at all, and the RBAC/auth
policy layer has no tenant concept regardless of transport. Treat this PR
as "the storage/business-logic layer is now provably tenant-correct when
given a real tenant ID," not as "multi-tenant NATS traffic isolation is
solved" — those are still open, and are named above as the concrete next
steps.

## Update, post PR #40/#41: the RBAC/auth gap above is resolved, not deferred

Option A (per-tenant NATS connections, PRs #40 and #41) closed the
transport and storage-layer gaps this doc originally flagged. The
RBAC/auth policy-layer gap named just above was re-examined against this
codebase's actual access model, rather than against RBAC's role model in
the abstract, and closed as a deliberate non-issue:

- Farmer's entire NATS API surface is called exclusively by the SaaS
  API's own privileged service credential
  (`cloudxp-machine-manager-api-design.md`'s "Internal API — Farmer (SaaS
  API only)"). A tenant, a human, or CloudXP itself never calls farmer
  directly.
- `cmd/imas`, the only other code path that authenticates to farmer's bus
  independently of the SaaS API, is never issued to anyone — confirmed,
  not assumed.
- Tenant boundary enforcement was never RBAC's job on the SaaS-API path
  regardless: it happens via the point-of-effect data-ownership checks
  this doc's own Phase 2 work built into `internal/pki`/`internal/props`/
  `internal/facts` (a request's asserted `tenant_id` checked against a
  sprout's actually-stored `tenant_id`). RBAC's role model answers "is
  this kind of action allowed," never "for which tenant" — it was never
  the right tool for this specific boundary.

See `internal/auth/auth.go`'s `policyState` doc comment for the
authoritative version of this decision, kept next to the code it governs.
**Revisit this if the access model ever changes** — the CLI gets issued
to anyone for direct access, or any caller other than the SaaS API's own
credential is ever granted access to farmer's internal subjects.
