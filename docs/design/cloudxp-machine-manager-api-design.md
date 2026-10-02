# CloudXP Machine Manager — API Design

Two codebases, one trust boundary:

- **SaaS API** — external, customer/CloudXP-facing. Standard Go REST service, GORM, `saas` schema.
- **Farmer** (+ sprout) — internal, data-plane. Existing imas NATS API, `farmer` schema. Its entire API surface is now **privileged and internal-only** — callable exclusively by the SaaS API's service credential, never directly by a tenant, a human user, or CloudXP.

Both schemas live in one shared PXC cluster. Single-writer-per-schema: farmer writes only `farmer.*`, SaaS API writes only `saas.*`; each has read-only grants into the other's schema for local joins (see §5.1).

```
CloudXP / tenant admins / portal
        │  REST, bearer token (tenant-scoped claims)
        ▼
   SaaS API  ──── privileged internal calls (mTLS / system NATS user) ────►  Farmer
   (saas schema)                                                          (farmer schema)
        │                                                                       │
        └───────────────────── shared PXC cluster, cross-schema reads ─────────┘
```

---

## 1. External API — SaaS API

Base path: `/v1`. All endpoints require a bearer token whose claims include the caller's `tenant_id` — the gateway/SaaS API injects or validates this on every request; a client can never supply a `tenant_id` that doesn't match its own token.

Standard error shape for every endpoint:
```json
{ "error": "<snake_case_code>", "message": "<human readable>", "details": {} }
```

### 1.1 Tenants

| Method | Path | Notes |
|---|---|---|
| `POST` | `/tenants` | Create a tenant. **Async** — see below. |
| `GET` | `/tenants/{tenant_id}` | Fetch tenant + status. |
| `PATCH` | `/tenants/{tenant_id}` | Update name/plan/metadata. |
| `DELETE` | `/tenants/{tenant_id}` | Offboard. Async, same pattern as create. |
| `GET` | `/tenants/{tenant_id}/status` | Lightweight status-only poll. |

**`POST /tenants`**
```json
// request
{ "name": "Acme Bank", "plan_id": "plan_std" }

// response 202 Accepted
{ "tenant_id": "t_8f2a", "status": "pending" }
```
Status values: `pending → active`, or `pending → failed` (see `provisioning_jobs`, §5.2). `DELETE` follows the same `offboarding → offboarded`/`failed` shape.

### 1.2 Enrollment keys

Owned entirely by the SaaS API (`saas.enrollment_keys`); farmer validates against this table directly via its read grant at the moment a fresh sprout enrolls.

| Method | Path | Notes |
|---|---|---|
| `POST` | `/tenants/{tenant_id}/enrollment-keys` | Issue a one-time, tenant-scoped key. |
| `GET` | `/tenants/{tenant_id}/enrollment-keys` | List (with usage/expiry state). |
| `DELETE` | `/tenants/{tenant_id}/enrollment-keys/{key_id}` | Revoke. |

```json
// POST request
{ "expires_in_hours": 24, "max_uses": 50 }

// response
{ "key_id": "ek_91cd", "registration_key": "<opaque, shown once>", "expires_at": "2026-09-15T10:00:00Z", "max_uses": 50 }
```

### 1.3 Asset linking

The only place `asset_id` (CloudXP's own, stable-for-life VM identifier) enters the system. Purely an external attribute — farmer never sees it.

| Method | Path | Notes |
|---|---|---|
| `POST` | `/tenants/{tenant_id}/sprouts/{sprout_id}/asset-link` | Link. `{ "asset_id": "..." }` |
| `DELETE` | `/tenants/{tenant_id}/sprouts/{sprout_id}/asset-link` | Unlink. |

### 1.4 Sprouts — list by asset id

| Method | Path | Notes |
|---|---|---|
| `GET` | `/tenants/{tenant_id}/sprouts?asset_ids=a1,a2,...` | Max **100** ids per call → `400 too_many_asset_ids` above that. |

```json
// response
{
  "results": [
    { "sprout_id": "s_1", "asset_id": "a1", "key_state": "accepted", "connected": true },
    { "sprout_id": "s_2", "asset_id": "a2", "key_state": "accepted", "connected": false }
  ],
  "unresolved": ["a17"]
}
```
`unresolved` covers both "never linked" and "linked to a different tenant" — never distinguished in the response, to avoid leaking cross-tenant existence.

Implementation note: this is a single local SQL statement, no NATS round-trip —
```sql
SELECT a.asset_id, n.sprout_id, n.state AS key_state
FROM saas.asset_links a
JOIN farmer.pki_nkeys n
  ON n.tenant_id = a.tenant_id AND n.sprout_id = a.sprout_id
WHERE a.tenant_id = ? AND a.asset_id IN (?, ...);
```
The join is on the composite `(tenant_id, sprout_id)` — `pki_nkeys`' primary key — because a `sprout_id` is only unique within a tenant (§4, *Tenant safety*). `connected` is not a column in either table: it comes from `internal/heartbeat.IsOnline` (the sprout's live Valkey heartbeat key), filled in per resolved row after the join, and degrades to `false` on a heartbeat-store error rather than failing the request.

### 1.5 Sprout actions — batch, async

| Method | Path | Notes |
|---|---|---|
| `POST` | `/tenants/{tenant_id}/sprouts/actions` | Max 100 `asset_id`s. Returns a batch id. |
| `GET` | `/tenants/{tenant_id}/sprouts/actions/{batch_id}` | Poll status, per-item detail. |

```json
// POST request
{
  "asset_ids": ["a1", "a2", "a17"],
  "action": { "type": "cmd.run", "params": { "cmd": "systemctl restart nginx" } }
}
// or: { "type": "cook", "params": { "recipe": "nginx.harden" } }

// 202 response
{ "batch_id": "b_123" }

// GET status response
{
  "status": "in_progress",
  "items": [
    { "asset_id": "a1",  "sprout_id": "s_1", "status": "succeeded" },
    { "asset_id": "a2",  "sprout_id": "s_2", "status": "queued" },
    { "asset_id": "a17", "status": "unresolved" }
  ]
}
```
Batch/item status backed by `saas.asset_action_batches` / `saas.asset_action_items` (§5.2). Once an item's underlying farmer `jid` is known, its status is refreshed via a local read into `farmer.jobs` — no NATS call needed for polling, same pattern as §1.4.

### 1.6 Recipes, jobs, audit (read-through proxies)

Thin, tenant-scoped wrappers over farmer's existing `recipes.*`, `jobs.*`, and `audit.*` subjects (§2.1) — same shapes, tenant filter enforced by the SaaS API before forwarding.

| Method | Path |
|---|---|
| `GET` | `/tenants/{tenant_id}/recipes` |
| `GET` | `/tenants/{tenant_id}/recipes/{name}` |
| `GET` | `/tenants/{tenant_id}/jobs` |
| `GET` | `/tenants/{tenant_id}/jobs/{jid}` |
| `GET` | `/tenants/{tenant_id}/audit?date=...` |

### 1.7 Request auth (decided), plus teams, API keys, webhooks, usage — *(surface only; not detailed yet)*

These close the gaps identified earlier but haven't been through a design pass the way §1.1–1.6 have:

| Method | Path |
|---|---|
| `POST/GET/DELETE` | `/tenants/{tenant_id}/api-keys` |
| `POST/GET/DELETE` | `/tenants/{tenant_id}/teams`, `/teams/{team_id}/members` |
| `POST/GET/DELETE` | `/tenants/{tenant_id}/webhooks` |
| `GET` | `/tenants/{tenant_id}/usage`, `/tenants/{tenant_id}/plan` |

Webhook delivery/retry semantics and billing-system integration remain **not yet designed**. Auth for every SaaS API request — human-user requests included — is now **decided** (internal/saasapi/middleware.go's `Auth`, FLAG FOR SECURITY REVIEW): two independent layers, both required, checked in order.

1. **Shared service secret (BFF identity).** The BFF (a browser-facing frontend, not modeled elsewhere in this doc) is the SaaS API's only intended caller. It presents a pre-shared secret on a dedicated `X-Internal-Auth` header, compared with `crypto/subtle.ConstantTimeCompare` — never `==` — against `INTERNAL_AUTH_SECRET_CURRENT` and, during a rotation window, the optional `INTERNAL_AUTH_SECRET_PREVIOUS`. Both are plain environment variables, sourced from a Kubernetes Secret that External Secrets Operator keeps in sync with Vault/OpenBao, with Reloader triggering a rolling restart on change; the service reads them once at startup, the same as its other config, not polled or hot-reloaded in-process. The two-value scheme exists because a rolling restart doesn't update every replica (of this service or the BFF) atomically — without it, the overlap window between old and new secret would cause spurious 401s. This check runs first, before any JWKS fetch or JWT parsing, since it's the cheaper of the two layers.
2. **Keycloak-issued end-user JWT.** The BFF authenticates end users against Keycloak and forwards the user's own Keycloak-issued JWT (`Authorization: Bearer ...`) on every request. Verified with `github.com/lestrrat-go/jwx/v2` (already a dependency, minting `internal/gatewayjwt`'s sprout-facing tokens) against the realm's JWKS (`/realms/{realm}/protocol/openid-connect/certs`), fetched through an auto-refreshing `jwk.Cache`, checking signature, issuer, audience, and expiry.

   The end-user token's `organization` claim is a single flat object, always present:
   ```json
   { "organization": { "id": "a1b2c3d4-...", "name": "acme-corp", "attributes": { "tier": "enterprise" } } }
   ```
   `organization.id` is CloudXP's `customer_id` — the same concept as `tenant_id` everywhere else in this codebase (this section's own `{tenant_id}` path parameter, `internal/pki`'s and `internal/props`'s `tenantID`). There is deliberately no separate `customer_id` field or type: for any route with a `{tenant_id}` path parameter, `organization.id` is compared directly against it (routes without one, e.g. §1.8's fleet-catalog routes, skip this check). Because the claim is confirmed always present on a correctly-configured realm, an absent or unparseable claim on an otherwise-valid, otherwise-verified token is treated as a defensive safety net for misconfiguration, not an expected path — logged as a warning and rejected with 403, not trusted or allowed to panic.

Both layers fail identically from the caller's point of view: a missing/mismatched secret, a missing/malformed bearer token, and a signature/issuer/audience/expiry failure are all `401` with the same generic `unauthorized` body — the real reason is only in the server-side log — matching §3.4's enrollment-endpoint discipline of never handing a caller a diagnostic oracle. A tenant mismatch, or a missing/unparseable `organization` claim, is `403`: a valid caller on both layers asking for the wrong resource. On success, the full parsed organization (id, name, attributes) is attached to the request context for handlers to read, not just the boolean match result.

The remaining §1.7 surface — teams, API keys as a *caller-manageable credential* (distinct from the BFF's own fixed shared secret above), webhooks, and usage/billing — is still a surface-only sketch, not detailed to this level. Two candidates remain worth evaluating if a caller-manageable API-key scheme is designed later, surfaced while working through the sprout-JWT design and set aside there as a better fit here instead: `gourdiantoken` (Go, MIT — access/refresh rotation, revocation, multi-tenant bulk revocation via a `tid` claim, matching this API's own tenant model closely; young/single-maintainer, worth weighing against a more established primitive), and OpenBao's own Identity/OIDC provider (native ID-token issuance against OpenBao's existing entity model, if human users end up modeled there) as an alternative to standing up a separate IdP.

### 1.8 Fleet updates

Owned by the SaaS API (`saas.fleet_versions`, `saas.tenant_update_policy`).
Dispatch reuses `saas.asset_action_batches`/`asset_action_items` (§5.2) —
no new batch/item tables — since an update rollout is just another batched
action, tracked and audited identically to a `cmd.run` or `cook` batch
(§1.5).

**Update model (decided).** Sprout updates come from the repository
configured **in the sprout**, exactly as the Ansible role `imas_sprout`
installs them (apt / rpm / zypper repositories, or the Windows feed or MSI
URL; requirement 20). imas does not host or serve artifacts and an update
command never carries an artifact URL. What imas controls is the
**manifest**: which versions exist, their per-OS/arch file names and
checksums, and which version each tenant may run. The sprout:

1. asks farmer for the update manifest for its own OS/arch over the
   authenticated recipe HTTP endpoint (JWT, `SproutRootCA`-pinned), §2.6;
2. verifies the manifest signature against the public keyring shipped with
   the sprout package (§2.5);
3. downloads the named file from its **configured repo** over ordinary
   HTTPS using the OS trust store (`SproutRootCA` is *not* used for this
   hop; the repo is an external host) and its configured proxy, with no
   JWT and, for private repos, the same repo token the Ansible role
   supports;
4. checks the file's SHA-256 against the signed manifest and only then
   installs it from that local file (`dpkg -i`, `rpm -U`, `msiexec`), so
   the installed bytes are exactly what imas signed. Repo package
   signatures (GPG) are checked in addition, not instead.

Release registration is wired into the **farmer Helm release** (§2.5): the
chart carries the sprout release (version, per-OS/arch file names and
checksums), so the farmer and sprout versions ship together. There is no
CI call into saasapi.

**Status.** The sprout-side install (item 4) and the manifest endpoint
(§2.6) are not built yet; `POST /tenants/{tenant_id}/sprouts/updates`
stays behind `SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED` (default off) until
they are. Upstream's `internal/update` skeleton (`yogzblr/imas#286`) is no
longer the dependency: the sprout-side work is imas's own (§2.3).

| Method | Path | Notes |
|---|---|---|
| `GET` | `/versions` | List registered sprout versions (`saas.fleet_versions`, one row per OS/arch). **CloudXP's own signed catalog**, not upstream's GitHub release feed — see rationale below. |
| `GET` | `/tenants/{tenant_id}/update-policy` | Fetch the tenant's approved version and rollout window. |
| `PATCH` | `/tenants/{tenant_id}/update-policy` | Set the approved/pinned version and rollout window. No sprout updates automatically without a tenant explicitly approving a version — this is opt-in, not upstream's ambient "check `/latest` every N minutes" model. |
| `POST` | `/tenants/{tenant_id}/sprouts/updates` | Trigger a staged update batch. Same request/response shape as §1.5's `/sprouts/actions`, with rollout-specific fields (below). |
| `GET` | `/tenants/{tenant_id}/sprouts/updates/{batch_id}` | Poll status — identical shape to §1.5's batch status endpoint. |

**`PATCH /tenants/{tenant_id}/update-policy`**
```json
// request
{ "approved_version": "v2.4.1", "auto_update": false }

// response
{ "tenant_id": "t_8f2a", "approved_version": "v2.4.1", "auto_update": false, "updated_at": "2026-09-15T10:00:00Z" }
```

**`POST /tenants/{tenant_id}/sprouts/updates`**
```json
// request
{
  "asset_ids": ["a1", "a2", "a17"],
  "target_version": "v2.4.1",
  "batch_size": 10,
  "gate": "probe"
}
// 202 response
{ "batch_id": "b_456" }
```
`target_version` is the only update parameter. It must equal a version the
tenant has approved (`tenant_update_policy`); saasapi rejects anything else.
`gate` accepts `job_status` and `dispatch` (the `probe` gate is rejected
until it is implemented). `batch_size` and `gate` default conservatively
smaller and stricter than an ordinary `cmd.run`/`cook` batch (§1.5) — see
§2.3, Rollout safety, for why a bad update is a worse failure mode than a
bad recipe step.

**Why CloudXP's own version catalog, not upstream's release feed.**
Upstream's skeleton polls `<UpdateURL>/latest` directly from each sprout,
independent of farmer, with no tenant concept at all — every sprout across
every tenant would land on whatever upstream ships, whenever upstream ships
it. That's incompatible with a BFSI/government customer's own change-control
expectations. `GET /versions` and the per-tenant `update-policy` instead
give each tenant explicit, audited control over which version their fleet
runs and when — consistent with the tenant-scoping discipline applied
everywhere else in this design (§4's "every query includes `tenant_id`").

---

## 2. Internal API — Farmer (SaaS API only)

Transport: NATS subjects under `imas.api.*` (existing) and a new `imas.internal.*` prefix. Authenticated via a privileged internal NATS identity (system-account-scoped user or mTLS), distinct from any tenant's sprout/user credentials. Never exposed to a tenant, a sprout, or a human directly.

**Decided for `internal.tenant.*`:** a narrowly-scoped User under the SYS Account, handled on farmer's existing SYS listener connection. See `imas-internal-api-account.md` for the reasoning and the exact permission set. The `internal.tenant.*` subjects are implemented; the `internal.sprout*` subjects below are not yet.

### 2.1 Existing subjects (unchanged shape, now tenant-scoped + internal-only)

| Subject | Purpose | Tenant-scoping note |
|---|---|---|
| `health`, `version` | Liveness/build info | Global, no scoping needed |
| `pki.{list,accept,reject,deny,unaccept,delete}` | Sprout key lifecycle | Scoped by NATS Account once JWT model lands |
| `sprouts.{list,get}` | Sprout metadata | **Superseded for external use by `internal.sprouts.list`** (§2.2) — paginated, tenant-scoped. Raw form stays for farmer-local/CLI use. |
| `test.ping` | Sprout health probe | — |
| `cmd.run`, `cook` | Command/recipe dispatch | Called by SaaS API only, per §1.5's batch flow |
| `jobs.{list,get,delete,cancel,forsprout}` | Job tracking | Proxied read-only via §1.6; SaaS API also reads `farmer.jobs` directly for batch-status polling |
| `props.{getall,get,set,delete}` | Sprout properties | — |
| `cohorts.*` | Sprout groupings | — |
| `auth.*` | Human RBAC (today: static config-file check) | Superseded long-term by SaaS API's `/api-keys`, `/teams` (§1.7) |
| `shell.start` | Interactive shell | — |
| `recipes.{list,get}` | Recipe catalog | Proxied via §1.6 |
| `audit.{dates,query}` | Audit log | Proxied via §1.6, tenant-filtered |

### 2.2 New subjects — tenant & sprout lifecycle

| Subject | Direction | Purpose |
|---|---|---|
| `internal.tenant.provision` | SaaS API → Farmer, fire-and-forget | Create the NATS Account + `farmer`-schema tenant partition. Async (§5.2) — no reply expected. |
| `internal.tenant.provisioned.{job_id}` | Farmer → SaaS API, published | Completion callback. Farmer has no write access to `saas` schema, so this event is how status gets back. |
| `internal.tenant.deprovision` | SaaS API → Farmer | Reverse of provision. Same async/callback shape. |
| `internal.tenant.deprovisioned.{job_id}` | Farmer → SaaS API, published | Deprovision's completion callback, same shape as `provisioned`. |
| `internal.sprout.mint` | SaaS API → Farmer, request-reply | Mint a User JWT + NKey identity for a newly-enrolled sprout, given `tenant_id` + submitted pubkeys. Called from farmer's own pre-enrollment HTTP path (which validates the registration key against `saas.enrollment_keys` directly, per §1.2) — this subject is the step after that validation succeeds — full sequence in §3. |
| `internal.sprout.revoke` | SaaS API → Farmer, request-reply | Revoke a sprout's JWT/NKey (backs "unenroll"). |
| `internal.sprouts.list` | SaaS API → Farmer, request-reply | Tenant-scoped, **paginated** version of `sprouts.list` (the existing subject returns an unbounded list — not viable at 1M sprouts). |
| `internal.sprout.action` | SaaS API → Farmer, request-reply | Dispatches `cmd.run`/`cook`/`self_update` for a resolved `sprout_id`, given the batch context from §1.5 (and, for updates, §1.8). Farmer independently checks the sprout's own stored `tenant_id` against the caller's asserted `tenant_id` before executing — the point-of-effect check that holds even if something upstream is wrong. |

```json
// internal.sprout.mint request
{ "tenant_id": "t_8f2a", "nkey_pub": "U...", "sprout_id_hint": "web-01" }
// reply
{
  "sprout_id": "s_1",
  "nats_jwt": "<signed NATS User JWT, ed25519-nkey alg, Account-signed>",
  "gateway_jwt": "<signed gateway JWT, EdDSA alg, gateway-key-signed, for Envoy jwt_authn>",
  "nkey_identity": "U..."
}
```
Two tokens, one signing event, minted together every time this subject (or the enrollment flow's internal equivalent, §3.3) is invoked — including at rotation, not just first enrollment. See `imas-envoy-enrollment-design.md` for why a single JWT can't serve both the NATS and Envoy gates.

```json
// internal.sprouts.list request
{ "tenant_id": "t_8f2a", "limit": 100, "cursor": "s_87" }
// reply
{ "sprouts": [ /* ... */ ], "next_cursor": "s_142" }
```

`internal.sprout.action`'s `action.type` enum now includes `self_update`
alongside `cmd.run`/`cook` (§1.8):

```json
// internal.sprout.action request, self_update variant
{
  "tenant_id": "t_8f2a",
  "sprout_id": "s_1",
  "action": {
    "type": "self_update",
    "params": { "target_version": "v2.4.1" }
  }
}
```

The command is sealed like other dispatches (`box1`, purpose-bound) and
carries **no** artifact URL, checksum or signature. The sprout resolves
those itself from the signed manifest (§2.6) and its own configured repo
(§1.8). Farmer still checks the sprout's stored `tenant_id` against the
caller's before dispatch.

### 2.3 Rollout safety — fleet updates

A failed `cmd.run` or `cook` step leaves a sprout in a knowable, recoverable
state. A failed self-update can leave a sprout **unable to reconnect to
farmer at all** — the failure mode is categorically worse. Before any
`self_update` action type is enabled, at minimum:

- **Smaller default batch size and stricter default gate** than §1.5's
  ordinary actions (default wave 5, max 25) — don't inherit the
  general-purpose defaults.
- **Install goes through the OS installer, from a verified local file.**
  The sprout verifies the manifest signature and the file SHA-256 first,
  then installs (`dpkg -i`, `rpm -U`, `msiexec`). The package manager,
  not custom swap code, owns replacement, service restart and file
  placement, so `internal/update`'s backup/rename/restore scaffolding is
  retired rather than finished. Windows relies on the MSI's own
  in-use-file handling.
- **Downgrade and replay protection.** The sprout refuses any version
  lower than the one it runs unless the signed manifest carries an
  explicit, signed `allow_downgrade` for that version. `allow_downgrade`
  is not in the manifest format yet; adding it means a new message tag
  (§2.5). Each manifest also carries a signed `min_sprout_version`
  (§2.5), the oldest sprout the current farmer still supports.
- **Health-based gating.** A wave is complete only when each sprout
  reconnects and reports the *new* version (from facts), not merely when
  the command was acked. Waves reuse the batch-and-gate mechanism
  (`imas-sprout-orchestration.md`).
- A sprout that goes dark mid-update is distinguishable in
  `asset_action_items` status: `unresponsive_after_update` is its own
  status, not a generic `failed`.
- **Mixed OS/arch fleets.** A batch may span OS/arch; each sprout resolves
  its own manifest row, so one `target_version` covers all of them.

---

### 2.4 JWKS endpoint — for Envoy, not internal-only

Unlike everything else in §2, this route is deliberately **not** on the privileged `imas.internal.*`/system-NATS-identity path — it serves public key material only, so it carries no confidentiality requirement, the same trust model as any standard `/.well-known/jwks.json`.

| Method | Path | Notes |
|---|---|---|
| `GET` | `https://enroll.<region>/v1/.well-known/jwks.json` | Served by farmer, plain HTTP (TLS-terminated, unauthenticated). Envoy's `jwt_authn` filter polls this via `remote_jwks` (5–10 min refresh), not `local_jwks`. |

```json
// response
{
  "keys": [
    { "kty": "OKP", "crv": "Ed25519", "x": "<base64url pubkey>", "kid": "gw-2026-q3", "use": "sig" }
  ]
}
```

Contains the **gateway signing key's** public key only (see `imas-nats-jwt-auth-design.md`'s key-custody section) — one entry, or two during the gateway key's own rotation overlap window (old + new `kid`). Never grows with tenant count: this is not a per-tenant Account-key JWKS, since Envoy's `jwt_authn` check never needs tenant granularity. Farmer already holds this public key (fetched from OpenBao alongside the signing operation itself), so this route is a pure data-transformation read, no new secret access.

### 2.5 Fleet release signing — one signer, Helm-driven registration

A `saas.fleet_versions` row is trusted because it is signed, not because
of who wrote it. The signature is Ed25519 over the canonical string

```
imas-fleet-manifest-v1|version|os|arch|file_name|checksum_sha256|min_sprout_version
```

built by `internal/fleetsign` (`Manifest.Message`), the one encoder shared
by the signer and every verifier.

- **Six signed fields, every manifest field but the signature.**
  `min_sprout_version` is signed so that nobody between fleetreleaser and
  the sprout (farmer included) can lower the floor and let a sprout too
  old for a release take it, or raise it to strand sprouts.
- **Deliberately no URL.** The URL comes from the sprout's own repo
  config.
- **A domain-separation tag** (`imas-fleet-manifest-v1`) comes first.
  Nothing else signed with this key, including the earlier
  `version|artifact_url|checksum_sha256` message, can verify as a
  manifest. A format change gets a new tag.
- **Strict validation, never normalization.** Each field is validated
  before signing or verifying:
  - no field may be empty or contain `|` or a control character;
  - `version` and `min_sprout_version` are canonical semver with a
    leading `v`, and `min_sprout_version` ≤ `version`;
  - `os` and `arch` are lowercase `[a-z0-9_]`;
  - `file_name` is a single plain file name;
  - `checksum_sha256` is 64 lowercase hex characters.

  A value is never rewritten to make it pass (an uppercase checksum is
  refused, not lowercased).

The signature is made with the OpenBao Transit key `imas-fleet-signing`
(non-exportable, separate from the gateway JWT key) and stored as
`signature = "v<key version>:<base64>"`.

**Registration flow.** The farmer Helm chart carries the sprout release
(`sprout.release`: version, channel, and per-OS/arch package name, file
name, sha256 — from the goreleaser `checksums.txt` of that release).

1. A `post-upgrade` (and `post-install`) Helm hook Job calls saasapi's
   operator-plane release-registration endpoint. It is not tenant-facing
   and uses an operator credential.
2. saasapi validates the entry (well-formed, version above the floor, and
   optionally that the file in the configured repo matches the checksum).
3. saasapi calls `fleetreleaser` to sign.
4. saasapi writes the signed rows to `saas.fleet_versions`; saasapi is the
   only writer of the `saas` schema.
5. Registering the same version with the same checksums is a no-op (so
   `helm upgrade` re-runs are safe); the same version with different
   checksums is rejected.

| Who | Transit access on `imas-fleet-signing` | Does |
|---|---|---|
| `cmd/fleetreleaser` | **sign** + read public key (`imas-fleet-signer`) | A stateless internal signing API. Only saasapi may call it (mTLS or a service token). It has **no DB access**. It signs a canonical manifest entry and enforces format and version-floor rules. |
| saasapi | read + verify only (`imas-fleet-verify`) | Calls the signer, stores the result, and refuses to create a rollout (§1.8) from a row whose signature is missing or invalid. |
| farmer | read + verify only (`imas-fleet-verify`, its own role) | Serves the manifest to sprouts (§2.6) read-only from `saas.fleet_versions`; re-verifies before it dispatches a `self_update`. |
| sprout | none | Verifies manifests against the public keyring **shipped in its package/config** (a key ID list), not fetched over NATS. |

**Why the split.** saasapi has PXC write access to `saas.fleet_versions`
(§4.1). If the same identity could also sign with Transit, one compromised
saasapi process could publish a "release" every sprout would install. So
writing a row and signing it stay two trust boundaries with two OpenBao
policies and two tokens: fleetreleaser is the only signer and is a separate
binary; saasapi and farmer are read-only, enforced by OpenBao
(`TestOpenBaoEnforcesReadOnlyFleetKey`). A missing signature is always a
refusal, at every hop, with no checksum-only fallback.

**Key rotation.** The keyring shipped with the sprout is the trust root, so
a new key version is added to the keyring in a sprout release signed by the
old key, and retired only after no approved tenant version depends on it
(`deploy/fleetreleaser/README.md`, "Rotating the key"). The previous live
key-set fetch over `imas.sprouts.<id>.fleetsigningkeys` and the JWKS-style
endpoint are dropped for fleet keys, which removes the bus from the trust
chain.

**Withdrawing a version.** `helm rollback` does not unregister a sprout
version; sprouts already on it keep it because they refuse downgrades. A bad
version is withdrawn with an explicit operator "revoke version" call to
saasapi, which marks the rows revoked so no manifest is served for them.

### 2.6 Update manifest endpoint

Served by farmer on the same dedicated HTTP endpoint sprouts already use
for recipes (requirement 9): `GET /v1/sprout/update-manifest?os=&arch=&version=`
authenticated with the sprout JWT (requirement 11). Farmer reads
`saas.fleet_versions` and `saas.tenant_update_policy` (read-only grants,
§4.1) and returns the row for the caller's tenant, OS and arch, only for a
version the tenant has approved. Response: `version`, `os`, `arch`,
`file_name`, `checksum_sha256`, `min_sprout_version`, `signature`. There is
no URL; the sprout builds it from its configured repo and `file_name`.

## 3. Sprout enrollment flow

### 3.1 Token format

`{key_id}.{secret}` — not just one opaque blob. `key_id` is a short random public identifier (e.g. 8-char base32), stored in plaintext and used purely as an **indexed lookup key**; `secret` is a 32-byte random value whose SHA-256 hash is what's actually stored (`saas.enrollment_keys.key_hash`). This mirrors `kubeadm`'s split for exactly the same reason: without it, validating a token means scanning and hash-comparing against every live key in the table; with it, it's a single indexed `WHERE key_id = ?` followed by one constant-time hash comparison.

`POST /tenants/{tenant_id}/enrollment-keys` (§1.2) returns the full `{key_id}.{secret}` string once — that's what goes into the Ansible playbook's `imas_join_token` variable.

### 3.2 The endpoint itself

`POST https://enroll.<region>/v1/enroll` — served by farmer, deliberately **not** behind Envoy's `jwt_authn` filter (a sprout enrolling has no JWT yet), but still TLS-terminated and, per the open item carried from the original enrollment design, deserving of Envoy-level IP-based rate limiting since it's the one DMZ-facing route without a JWT gate.

```json
// request (field-by-field, including how nkey_sig is computed:
// imas-envoy-enrollment-design.md, "Proof of possession")
{
  "join_token": "<key_id>.<secret>",
  "nkey_pub":   "U...",
  "hostname":   "web-01",
  "sprout_pub": "<base64 X25519 public key>",
  "timestamp":  1790000000,
  "nkey_sig":   "<unpadded base64url Ed25519 signature by the NKey seed>"
}

// success response
{
  "sprout_id": "s_1",
  "nats_jwt": "<signed NATS User JWT>",
  "gateway_jwt": "<signed gateway JWT, presented to Envoy on the ws upgrade and the recipe endpoint>",
  "fleet_signing_jwks": { "keys": [ /* imas-fleet-signing public key(s), pinned by the sprout — §2.5 */ ] },
  "nats_urls": ["wss://bus1.dmz...", "wss://bus2.dmz..."]
}

// failure response — deliberately generic, see §3.4
{ "error": "enrollment_failed" }
```

### 3.3 What farmer does, step by step

0. **Proof of possession**: verify `nkey_sig` against `nkey_pub` and require `timestamp` within ±5 minutes of farmer's clock, before anything is looked up. Each signed request is also single-use: farmer records it in Valkey (`SET NX` with a TTL, shared by every farmer replica) just before issuing anything, in step 1's replay or before step 4's redemption, and refuses a request it has already recorded. See `imas-envoy-enrollment-design.md`, "Proof of possession" and "Replay cache".
1. **Idempotency check first**: `SELECT * FROM farmer.sprouts WHERE nkey_pub = ?`. If a sprout already exists for this exact public key, return its existing JWT immediately and stop — no enrollment-key touched. This covers the ordinary case of Ansible retrying after a dropped connection: the sprout generates its keypair once, locally, before ever calling out, so a retry presents the same `nkey_pub` and gets the same identity back rather than burning a second use of a possibly single-use token.
2. **Look up the key**: `SELECT tenant_id, key_hash, expiry, max_uses, used_count, revoked, asset_id FROM saas.enrollment_keys WHERE key_id = ?` — a plain read via farmer's existing grant into `saas`.
3. **Validate**: unknown `key_id`, revoked, expired, or `used_count >= max_uses` all fail the same way (§3.4).
4. **Atomically redeem** — this is the one deliberate, narrow exception to the single-writer-per-schema rule:
   ```sql
   UPDATE saas.enrollment_keys
   SET used_count = used_count + 1, last_used_at = NOW()
   WHERE key_id = ? AND used_count < max_uses AND revoked = FALSE AND expiry > NOW();
   ```
   Checking `affected_rows = 1` after this statement *is* the concurrency control — two sprouts racing to redeem the same near-exhausted token can't both succeed, because the `WHERE` guard makes the whole check-and-increment atomic in one statement. This needs a narrow grant, not blanket write access:
   ```sql
   GRANT UPDATE (used_count, last_used_at) ON saas.enrollment_keys TO 'farmer_svc'@'%';
   ```
   Everything else in `saas` stays read-only to farmer, exactly as before.
5. **Mint**: generate the sprout's paired NATS User JWT (under the tenant's Account) and gateway JWT (under the platform-wide gateway signing key) in one signing step (`internal.sprout.mint`, §2.2), insert the row into `farmer.sprouts`.
6. **Respond** to the sprout synchronously — Ansible is blocking on this HTTP call, so this step can't be async.
7. **Notify the SaaS API**: publish `internal.sprout.enrolled` (`tenant_id`, `sprout_id`, `key_id`, `asset_id` if the key carried one). The SaaS API uses this to auto-create the `asset_links` row when the enrollment key was issued with a known `asset_id`, and to fire an `enrollment.succeeded` webhook (§1.7) — this is a fire-and-forget notification, not something the sprout's own response waits on.

### 3.4 Failure responses stay generic

Unknown key, expired, revoked, and exhausted all return the same `enrollment_failed` body. Distinguishing them in the response would hand an attacker a free oracle for guessing valid `key_id`s or timing a race against expiry — the specific reason is logged in farmer's audit trail (feeding the CERT-In/DPDP retention question already flagged in §6) but never returned over the wire.

---

## 4. Cross-cutting conventions

- **Pagination**: 100-item cap on caller-supplied ID batches (§1.4, §1.5); cursor-based for open-ended lists (`internal.sprouts.list`) — the existing `sprouts.list`/`jobs.list` farmer subjects lack this and should not be exposed externally as-is.
- **Async pattern**: every long-running operation (tenant provision/deprovision, batch actions, fleet updates) follows create-row-then-poll — `202` + a status endpoint, backed by an outbox-style table in `saas` schema, never a bare NATS publish, because NATS core (no JetStream, per the settled architecture) gives no redelivery guarantee.
- **Tenant safety**: every query that resolves a caller-supplied ID (`asset_id`, `sprout_id`) always includes `tenant_id` in the same `WHERE` clause — a mismatch resolves to "not found," never a distinguishable authorization error.
  - `sprout_id` is unique **per tenant only**, not globally: enrollment derives it from the sprout's hostname and de-duplicates only against that tenant's own sprouts (`internal/pki/enroll.go`, `resolveEnrollSproutID`), so two tenants can — and routinely will — both have a `web-01`. Any table, index, cache key, or map keyed on `sprout_id` alone (rather than `(tenant_id, sprout_id)`) is a cross-tenant collision bug.
- **Versioning**: `/v1` prefix on the external API; internal subjects aren't versioned in the path — farmer and the SaaS API deploy together as one control plane, so subject compatibility is managed by coordinated release rather than version negotiation.

---

## 5. Schema reference

### 4.1 Grants
```sql
GRANT ALL    ON farmer.* TO 'farmer_svc'@'%';
GRANT SELECT ON saas.*   TO 'farmer_svc'@'%';
GRANT ALL    ON saas.*   TO 'saas_svc'@'%';
GRANT SELECT ON farmer.* TO 'saas_svc'@'%';
```
One narrow, deliberate exception to single-writer: farmer also gets `GRANT UPDATE (used_count, last_used_at) ON saas.enrollment_keys` — the atomic redemption counter needed at enrollment time (§3.3). Nothing else in `saas` is writable by farmer.

No cross-schema foreign keys — `tenant_id`/`sprout_id` are enforced by convention at the application layer, to avoid adding Galera certification overhead across schemas at 1M-sprout scale.

### 4.1a Migrations

Schema changes are versioned goose migrations (MIT, embedded SQL, no CGO),
replacing GORM `AutoMigrate` at startup and the `db-bootstrap` Job. A
single Helm-hook Job runs one pod, `cmd/migrate`, which in order: waits for
PXC; using the PXC root secret (mounted only in this pod) creates the
schemas and users and applies §4.1's grants; migrates `farmer` as the
farmer user and `saas` as the saasapi user (single writer per schema
holds); then applies the `enrollment_keys` column grant. Hooks:
`pre-upgrade` and `pre-rollback`; on install `post-install`, since the
bundled PXC does not exist at `pre-install` (`pre-install` when PXC is
external). Farmer and saasapi check that the schema version they expect is
present and retry until it is. Migrations are forward-only and backward
compatible for one version (expand, then contract); there is no automatic
`down`. On rollback the pod only verifies the schema version is within the
supported range. Migrations are idempotent because MySQL DDL is not
transactional. A baseline migration (`CREATE TABLE IF NOT EXISTS`) covers
existing installs. PXC DDL is total-order-isolation, so large alters are
scheduled deliberately.

### 4.2 `saas` schema tables (new)
```sql
tenants               (id, name, status, plan_id, created_at, updated_at)
provisioning_jobs     (id, tenant_id, type, status, attempts, last_error, warning, created_at, updated_at)
enrollment_keys        (id, tenant_id, key_hash, expiry, max_uses, used_count, revoked)
asset_links           (id, tenant_id, sprout_id, asset_id UNIQUE, linked_at, UNIQUE(tenant_id, sprout_id))
asset_action_batches  (id, tenant_id, requested_asset_ids, created_at)
asset_action_items    (batch_id, asset_id, sprout_id, jid, status)
```

### 4.3 Fleet update tables (new)
```sql
fleet_versions        (id, version, os, arch, package_type, file_name, checksum_sha256,
                        min_sprout_version, signature, revoked, released_at, notes)
                        -- one row per OS/arch; UNIQUE(version, os, arch)
                        -- signature: produced only by cmd/fleetreleaser, stored by saasapi (§2.5)
tenant_update_policy  (tenant_id PK, approved_version, auto_update BOOLEAN,
                        rollout_window_start, rollout_window_end, updated_at)
```
No new batch/item tables — `asset_action_batches`/`asset_action_items` (§4.2)
already cover dispatch tracking for any `action.type`, including
`self_update`.

---

## 6. Open items (not yet designed)

- Caller-manageable API keys (`/tenants/{tenant_id}/api-keys`) as a credential type distinct from the BFF's fixed shared secret — §1.7. Request auth itself (shared-secret + Keycloak JWT) is decided, see §1.7.
- Webhook delivery/retry semantics — §1.7.
- Billing/metering integration specifics — §1.7.
- Quota/rate-limit enforcement values and where exactly they're checked (SaaS API is the intended enforcement point, per earlier discussion, but no limits have been set).
- Can a sprout's `tenant_id` ever change post-enrollment, or does a tenant move always mean re-enrollment? Not decided.
- **Fleet update rollout (§1.8, §2.3, §2.5, §2.6).** Design is settled;
  build remaining: sprout manifest fetch and verify, install from the
  verified local file, farmer manifest endpoint, saasapi registration
  endpoint, `fleetreleaser` as a signing API (dropping its direct DB
  write), Helm release hook, per-OS/arch `fleet_versions`, version floor,
  health-based gate. Keep `POST /tenants/{tenant_id}/sprouts/updates`
  behind `SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED` until then.
- Decided 2026-09-29: `helm rollback` leaves the sprout release
  registered (withdrawn only by explicit revoke); one `cmd/migrate` binary
  runs both schemas' migrations; private-repo tokens for sprouts are Linux
  only, as in the Ansible role today.
