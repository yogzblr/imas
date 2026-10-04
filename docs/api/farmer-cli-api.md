# Farmer: the imas CLI API (`imas.api.*`, sealed)

The imas CLI (and `imas serve`, which proxies the web UI through it) talks
to farmer over the bus, on `imas.api.<method>` subjects in the users
tenant's account. Every request and every reply is a sealed
[`internal/payloadbox`](../../internal/payloadbox) message (J.3). Design:
[payload encryption, "Sealing the control plane", Decision A and "As built:
J.3"](../design/imas-payload-encryption-design.md). **FLAG FOR SECURITY
REVIEW.**

There are no bearer tokens. The CLI's NKey authenticates its bus connection
(it signs the server's nonce) and signs nothing else; a request proves who
sent it only by opening under that user's registered CLI box key.

- Farmer: [`internal/natsapi`](../../internal/natsapi) (`sealedrouter.go`
  routes, `sealedapi.go` opens and seals, `middleware.go` authorizes).
- CLI: [`internal/api/client/nats.go`](../../internal/api/client/nats.go)
  (`NatsRequest`, `SealedRequest`) over
  [`internal/pki/cliboxclient.go`](../../internal/pki/cliboxclient.go).

## Keys

| Key | Who holds it | Where |
|---|---|---|
| CLI box key (X25519) | the user's CLI only | `cliboxprivfile` (mode 0600, default `~/.config/imas/cli-box.key`), made by `imas auth keygen` |
| its public half | farmer | `auth_cli_box_keys`, keyed on `(tenant_id, user_id)`; registered by `imas users add --boxpub`, `imas users reset-key`, the first admin's `boxpub` in farmer's config, or a rotation |
| tenant box key | farmer | OpenBao KV v2, `<mount>/<base>/tenants/<tenant_id>` (`pub`, `priv`) |
| its public half | the CLI | `tenantboxpub`, with `tenantid`, in the CLI config, copied out of band: never fetched over the bus |

Users and their keys belong to the users tenant (`farmerorganization`).

## Request

- Subject: `imas.api.<method>` (a cook's trigger: `imas.api.cook.trigger.<jid>`).
- Headers: `Imas-Payload: box1`; `Imas-Principal: <the user's NKey public key>`.
- Body: a payloadbox envelope (version 2) whose message has purpose
  `c2f.api` (`c2f.userkey.pub` for `auth.rotatekey`), `tid` = the pinned
  tenant ID, `sid` = the user's NKey public key, a fresh random `id`, `iat`
  = now, no `re`, sealed from the CLI box key to the pinned tenant key. Its
  body is `{"method": "<method>", "subject": "imas.api.<method>", "params": <JSON>}`.

Farmer, in order (any failure stops it):

1. The `Imas-Payload` marker: without it, `encryption-required`.
2. Opens under the principal's registered keys (active, then any in their
   15-minute grace window) against the tenant's keys (current, then the
   previous one inside a rotation's grace window). `sid` must equal the
   header, the purpose must be the method's, and `method` and `subject` must
   be the ones the message arrived on. Otherwise `open-failed`.
3. This replica's replay guard: `iat` within ±5 minutes, `id` not seen
   before for `(tenant, user)`. Otherwise `open-failed`.
4. A mutating method (every method not in the read-only list below) is
   claimed once across the cluster: Valkey `SET NX` on
   `imas:replay:sealed:<tenant>:<user>:<id>`, 10 minutes. Already claimed:
   `open-failed`. Valkey unreachable: a sealed error reply, `the replay store
   is unavailable`.
5. RBAC for the verified user: the method's action, then scope on its
   target sprouts. A request whose targets can't be read is refused.
   Refusals here are sealed error replies (`access denied`).

Read-only methods (no Valkey claim): `health`, `version`, `sprouts.list`,
`sprouts.get`, `jobs.list`, `jobs.get`, `jobs.forsprout`, `props.getall`,
`props.get`, `cohorts.list`, `cohorts.get`, `cohorts.resolve`,
`cohorts.validate`, `pki.list`, `auth.whoami`, `auth.users`, `auth.explain`,
`audit.dates`, `audit.query`, `recipes.list`, `recipes.get`.

## Reply

- `Imas-Payload: box1`; the body is a payloadbox message with purpose
  `f2c.api`, `re` = the request's `id`, the same `tid` and `sid`, sealed from
  the tenant key to the user's active CLI box key (one copy per tenant key).
  Its body is `{"method", "subject", "result": <JSON>, "error": "<text>"}`:
  a handler's error is inside the box, never in a header.
- A request that didn't get that far is answered with `Imas-Payload-Error:
  <code>` and an empty body. Codes: `encryption-required`, `open-failed`
  (didn't open, wrong principal, method or subject, stale, replayed),
  `internal` (it opened but the reply couldn't be sealed).

The CLI accepts only a reply that opens under its own key and names its
request's `id`, method and subject. A plaintext reply is an error, never a
result.

**Monitoring.** An unsealed request for `health` or `version` is still
answered in plaintext (`{"result": ...}`), with no identity. The CLI never
sends one.

## Methods that changed in J.3

| Method | Params | Who | Notes |
|---|---|---|---|
| `auth.users.add` | `{pubkey, role, username?, boxpub}` | admin | `boxpub` is required: the user and their first CLI box key are registered together. |
| `auth.users.resetkey` | `{pubkey, boxpub}` | admin | New. Retires every key the user holds and registers `boxpub` as their only key. |
| `auth.users.remove` | `{pubkey}` | admin | Also retires the user's keys. |
| `auth.users` | none | admin | Adds `box_keys`: user ID to active key fingerprint. |
| `auth.rotatekey` | `{pub}` | the caller | Purpose `c2f.userkey.pub`, sealed under the current key; the reply is sealed to the new key. |
| `auth.login`, `auth.whoami`, `auth.explain` | none | the caller | Report the verified caller. A `token` param is ignored. |
| `cook` | targeted cook | `cook` on the targets | Returns the JID; the job runs only when triggered. |
| `cook.trigger.<jid>` | `{jid}` | the user who created the job, with `cook` | New. Sent once the CLI is subscribed to the job's step events; answered by the replica holding the job, within 15 seconds, once. Returns the targeted sprout IDs. |
| `recipes.list` | none | `view` | New on the bus (was `GET /v1/recipes`). The platform recipe tree. Read-only. |
| `recipes.get` | `{name}` | `view` | New on the bus (was `GET /v1/recipes/{name}`). At most 256 KiB. Read-only. |

Every other method keeps its params and result; `token` is no longer read
anywhere.

## Still plaintext

Step events (`imas.cook.*.<jid>`, read by `imas cook`, `imas jobs watch`,
the CLI's local job store and `imas serve`'s log stream) and shell session
streams. See "What stays plaintext until Decision D" in the design.
