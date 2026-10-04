# imas: Payload Encryption & Key Rotation

Covers Phase 3 of `imas-master-plan.md`. Bootstrapped by the enrollment exchange in `imas-envoy-enrollment-design.md`.

## Why this exists: what TLS alone doesn't cover

NATS's TLS transport encrypts each hop (sprout↔bus, farmer↔bus), but nats-server necessarily decrypts the payload in memory to route it by subject — true of any subject-routing broker. Given the bus sits in the DMZ by design, and has had real disclosed pre-auth CVEs in 2026, a fully compromised bus under TLS-only protection still sees every job command and fact payload in plaintext. Payload-level encryption means a compromised bus sees only routing metadata and ciphertext, never content.

## Design: one tenant keypair, one keypair per sprout

- **Tenant keypair** (X25519): one per tenant, farmer-side, private key custodied in OpenBao (same model as the Operator/Account signing keys). Not per-sprout — a single farmer-side keypair reused across every sprout in that tenant.
- **Sprout keypair** (X25519): generated locally by the sprout at enrollment. Private key never leaves the sprout, ever — not at generation, not at rotation.
- **Why one tenant key still gives per-sprout-specific encryption:** NaCl `box`'s shared secret is derived from *both* sides' keys jointly (`DH(tenant_priv, sprout_pub)` and `DH(sprout_priv, tenant_pub)` produce the same secret). Reusing `tenant_priv` across sprouts doesn't mean sprouts share a key with each other — each (tenant, sprout) pair still gets a distinct derived secret.
- **Threat model match:** the bus never holds `tenant_priv`, `sprout_priv`, or any derived secret regardless of key-reuse scope, so this simplification costs nothing against the specific threat (a compromised DMZ bus) this feature exists to defend against.

## Bootstrap

Rides entirely on the enrollment exchange already designed — no separate protocol. Sprout generates its X25519 keypair locally, includes `sprout_pub` in its enrollment request alongside its NKey public key; farmer's enrollment response includes `tenant_pub` alongside the issued JWT. One existing round trip, two new fields.

**As built, with proof of possession (security review 2026-10, H3; FLAG FOR SECURITY REVIEW).** The NKey signature on the enrollment request proves the sprout holds its NKey seed, not that it holds the private half of `sprout_pub`. Without a second proof, an enroller could register a box public key it copied from another sprout (the bus can learn one), and farmer would seal that enroller's commands to it. X25519 keys can't sign, and before its first response the sprout doesn't know any farmer-side key it could prove possession to, so a first enrollment is two requests to `/v1/enroll`:

1. The usual request. Farmer issues the identity, returns `tenant_id` and `tenant_pub`, and records **no** box key. It seals nothing to the sprout.
2. The same request again, which farmer answers from its idempotent replay path without spending the join token, plus `sprout_pub_proof`: a `payloadbox` message (purpose `s2f.enroll.proof`) naming the tenant, the sprout ID, `nkey_pub` and `sprout_pub`, sealed with the sprout's box private key to `tenant_pub`. Farmer opens it with the tenant's private key paired with the `sprout_pub` in the request. `box` authenticates both ends, so only a holder of the `sprout_pub` private key (or of the tenant private key, which is farmer) can produce a box that opens under that pair. Farmer checks the tenant, sprout, NKey, box key and a ±5 minute `iat`, and only then records `sprout_pub` as the sprout's active box key.

A proof that doesn't verify fails the whole request. A proof on a first enrollment (the join-token path) is refused, because the sprout can't have known the tenant key yet. On the replay path a proof records only the sprout's first box key, or re-asserts the one already active. A different key while one is active is refused, because replacing a key is a rotation, which must be sealed under the current key. The brief's example was a farmer-sealed challenge the sprout opens. This is the same check run the other way round: the sprout seals to the tenant key instead of opening something farmer sealed to it. That keeps farmer stateless across the two requests (no challenge to store per replica) and reuses the existing `payloadbox` checks. The cost is one extra request at first enrollment.

The sprout also **pins its tenant ID** at enrollment (`tenant-id`, next to the tenant key pin), from the response's `tenant_id`. The pin never moves. `/v1/refresh` returns `tenant_id` too, and every refresh checks it against the pin. A response, enrollment or refresh, naming another tenant is `ErrSproutTenantMismatch` (fatal, like a tenant key mismatch). A sprout with box keys but no tenant pin can neither seal nor open anything, and its next refresh is refused (`ErrSproutTenantNotPinned`, fatal) rather than pinning whatever farmer names: the pin is set at enrollment only, so such a sprout re-enrolls. The sprout is the only caller of `/v1/refresh`.

## Key rotation — corrected from an earlier, unsafe framing

**The private key must never be transmitted, even encrypted, even over an already-encrypted channel.** An earlier version of this design considered "send the private key encrypted in NATS" — worth stating plainly why that's wrong, not just noting it was changed: it means farmer must generate and briefly hold a sprout's private key (a new exposure surface — memory, logs, crash dumps — that doesn't exist under the bootstrap model), and the sprout ends up trusting key material it didn't generate itself, with no way to verify it wasn't logged or weakly randomized somewhere in farmer's pipeline.

**Correct pattern — sprout-initiated, same shape as bootstrap:**
- Sprout generates a **new** keypair locally. New private key never leaves the sprout.
- Sprout sends only the new **public** key to farmer, re-registering it against its identity.
- Farmer may **trigger** rotation (e.g., scheduled policy, suspected exposure) by sending a command — but that command carries no key material, only an instruction.
- **Grace period:** both old and new public keys accepted for a short overlap window, so in-flight messages encrypted under the old key still decrypt correctly, then the old key is revoked once the window closes — reusing the existing PKI accept/deny/revoke lifecycle rather than a new mechanism.

## Forward secrecy — accepted tradeoff, not an oversight

Because `tenant_priv` is a single, long-lived key, extraction of it (a future OpenBao compromise, a backup leak) lets an attacker who has been passively recording bus ciphertext retroactively decrypt all of that tenant's historical traffic — the standard limitation of static-key NaCl `box` usage, versus schemes with ephemeral per-session keys (e.g., Signal's Double Ratchet) that bound exposure to the current session only.

Building genuine forward secrecy (session-level key agreement, ratcheting state) is a materially bigger lift, very likely disproportionate to what this feature needs. **Accepted mitigation: rotate the tenant keypair on a schedule** (e.g., quarterly, or immediately on suspected exposure) — this doesn't eliminate retroactive-decryption risk, but bounds its window to "since the last rotation" rather than "since the beginning of time." Worth a deliberate, documented decision given the CERT-In/DPDP context, even if the decision is "static key, rotated periodically, and this residual risk is accepted."

## Storage, consistent with decisions elsewhere in the plan

- `tenant_priv` → OpenBao, same custody model as Operator/Account signing keys.
- `sprout_pub` (per sprout) → PXC, an additional column alongside the sprout's existing identity record.
- `tenant_pub` → not sensitive, distributed to sprouts at bootstrap/rotation, no special custody needed.

## Implementation scope, worth sizing honestly

Broader-touching than most workstreams in this plan, not because any one piece is hard, but because it needs to wrap every meaningful payload boundary in `internal/natsapi`'s handlers (job dispatch, job results, facts) — best done by building it into the shared request/response helper layer so encryption is transparent to every handler, rather than opt-in per handler where it's easy to miss one.

## As built (J follow-up)

What the code does today, and where it departs from, or adds to, the sections above.

**Wire format (`internal/payloadbox`).** A sealed payload is a JSON envelope `{"v":2,"s":[{"n":nonce,"c":box}, …]}` sent with the NATS header `Imas-Payload: box1`. Each copy is `box.Seal` of the inner message under one key pair, with a fresh 24-byte nonce. More than one copy is sent only during a tenant key rotation's grace window, one per tenant key in use. The receiver tries every copy against every key pair it holds, so no key identifier goes on the wire outside the ciphertext. The inner message is `{v, p (purpose), tid (tenant_id), sid (sprout_id), rk (recipient key id), id (128 random bits), re (request id, replies only), iat, b (body)}`. Version 2 added `tid` and `rk` (security review 2026-10, H3); a version 1 envelope never opens. Plain `box` doesn't give the following, so this layer adds them:
- **Tenant binding.** Every message names its tenant, and `Open` refuses one for any tenant other than the one the caller expects; an empty expectation matches nothing. `sprout_id` is unique per tenant only, so without this a message farmer sealed for tenant B's `web01` would run on tenant A's `web01` whenever the keys let it open there (two tenants sharing a keypair, or a box key registered in both). The sprout expects the tenant it pinned at enrollment; farmer expects the tenant whose keys it used, on everything it opens (replies, Acks, box key submissions, enrollment proofs).
- **Recipient key binding.** Each copy names the box public key it was sealed to: `rk` is the first 16 bytes of SHA-256 over a domain tag and the key, base64url. `Seal` sets it per copy, and `Open` compares it with the public half of the private key that opened the copy, so no caller can leave the check out. A farmer->sprout message names the sprout's key, so reflected back at farmer it names a key farmer doesn't hold: a second, independent stop on reflection besides the purpose.
- **Purpose binding.** `box`'s shared key is the same in both directions, so without this a bus could reflect farmer's command back at farmer as the sprout's "reply", or a sprout's reply back at the sprout as a "command". Purposes carry the direction (`f2s.cmd.run`, `s2f.cmd.run`, `f2s.cook`, `s2f.cook`, `f2s.cook.nudge`, `s2f.cook.nudge`, `s2f.boxkey.pub`, `f2s.tenantkey.continuity`), and a receiver only accepts the purpose it expects. Each boundary has its own pair, so a message sealed for one is refused on any other.
- **Replay and freshness.** The sprout accepts each message ID once, and only within ±5 minutes of its own clock. Farmer accepts a reply only if its `re` is the ID of the request it just sent.
- **Replay across a sprout restart** (security review 2026-10, M2). The sprout's replay guard is persisted: each accepted message's ID and `iat` (never its content) are written atomically, 0600, to `payload-replay.json` next to the box private key **before** the message is acted on, and loaded back on the first message after a start. A write that fails refuses the message. This was chosen over the alternative, refusing anything issued before process start plus the skew allowance, because that refuses every legitimate command for up to five minutes after each restart. The alternative is kept as the fallback for a guard file that exists but can't be read or parsed: the sprout then refuses anything issued before its start plus five minutes, and rewrites the file with the next accepted message. A missing file is a fresh guard.
  - **Clock jumps.** The guard keeps a **floor**: when an ID ages out of the window it is forgotten and the floor rises to its `iat`, and anything issued at or before the floor is refused. A clock stepped **forward** makes everything look stale until it is corrected (farmer's messages too), and forgets the IDs it ages out, raising the floor past them. A clock stepped **backward** would otherwise make forgotten messages fresh again; the floor refuses them. Either way, a sprout whose clock is more than five minutes from farmer's refuses farmer's messages until the clock is fixed, as before.
  - **Cook jobs.** `RespondCook` also refuses a dispatch whose job ID is already in the handled jobs file (`sprouthandledjobsfile`, which survives restarts), answering with an Ack that isn't acknowledged. A replayed dispatch is then stopped twice, independently, and so is a fresh dispatch that reuses a handled job ID. `cmd.run` has no job ID, so the persisted guard is its only replay stop.
- **Refusals.** A refusal comes back with an `Imas-Payload-Error` header carrying a fixed code (`open-failed`, `encryption-required`, `no-keys`, `internal`), never error text.

**One keypair per tenant.** Each tenant's keypair is its own OpenBao KV v2 secret, `<base>/tenants/<tenant_id>`, where `<base>` is `IMAS_TENANTBOX_OPENBAO_KV_PATH`. The KV version history is the tenant's key history. The first time a tenant's secret is needed, farmer generates a fresh keypair for it (`origin: generated`). No two tenants ever share a private key. The one keypair per deployment that J first shipped at `<base>`, and the path that let tenants with already-enrolled sprouts adopt it (`origin: adopted-legacy`), were deleted in SEC.3a (security review 2026-10, H3; owner decision 2026-10-04: nothing is deployed, so no install needs migrating). Farmer neither reads nor writes `<base>` itself, and the Helm chart's `imas-farmer-tenantbox` policy no longer grants it.

**Rotation (the forward-secrecy mitigation) and how sprouts follow it.** `imas keys rotate-tenant-key` (NATS `pki.rotatetenantbox`) writes a new version with check-and-set on the version it read. A sprout can't simply accept whatever key farmer names: that is exactly what its pin exists to prevent. So `/v1/refresh` and `/v1/enroll` return `tenant_x25519_continuity`, a message whose body names the new public key. It is sealed to the sprout's box key once under each retained earlier tenant key, going back to the last severing rotation, or 8 versions at most. A sprout pinned to one of those keys opens its copy with that key. Only the holder of the corresponding private key (or the sprout itself) could have sealed it, so the sprout re-pins to exactly the key named. Anything else is still `ErrTenantKeyMismatch`. During the grace window, `max(boxkeygraceduration, gatewayjwtttl)`, the previous key also keeps sealing and opening payloads, so any online sprout re-pins on its next refresh before the window closes, with no gap. `--sever` (suspected exposure) writes a version with no grace window and no proofs, so continuity from the exposed key is cut: the tenant's sprouts fail their next pin check and must be re-enrolled. Deleting a version in OpenBao retires it the same way. This follows the design's rule that rotation carries no private key material. The proof carries only a public key, sealed under a key the sprout already trusts.

**Sprout box keys over the bus.** `imas.sprouts.<id>.boxkey.pub` only accepts a submission sealed (`s2f.boxkey.pub`) under one of the sprout's currently valid box keys, within ±5 minutes, and a superseded key never becomes active again. As first shipped, it accepted a plaintext key from anything able to publish there. A compromised bus could then have swapped in its own key and read everything farmer sealed for that sprout afterwards. Since SEC.3a (security review 2026-10, M3), only a submission sealed under the sprout's **active** key can change which key is active. One sealed under a key in its grace window may only re-assert the key that is already active, which is what a sprout retrying a submission farmer already recorded sends; naming any other key is refused. Otherwise an old key leaked from, say, a VM snapshot would take over the sprout's sealed channel for the grace window after the rotation meant to retire it. Farmer finds out which key opened a submission by trying the active key first and then each grace key on its own (`pki.OpenBoxKeySubmission`), and checks and records it in one transaction (`pki.RecordSproutBoxKeySubmission`).

**One active box key per sprout, and what deleting a sprout does** (SEC.3a, security review 2026-10, H1). At most one `pki_sprout_box_keys` row per `(tenant_id, sprout_id)` is active, and the schema enforces it (farmer migration 00002): `active_slot` is 1 on the active row and NULL on every other one, a CHECK ties it to `state`, and `(tenant_id, sprout_id, active_slot)` is unique. Recording a key at enrollment revokes any other active row for that ID in the same transaction, since an enrollment is a new trust anchor. If more than one row is somehow active, farmer seals nothing to and opens nothing from that sprout (`ErrMultipleActiveBoxKeys`) rather than guessing. Deleting a sprout (`pki.delete`), or replacing it by accepting `<id>_<n>` (`pki.accept`), revokes all of the old host's box keys, and on the replace path moves the new host's keys to `<id>`. In the same transaction the old host's NKey goes on the tenant's revoked list (`pki_revoked_nkeys`), which every rebuild of the tenant's Account JWT applies. The bus then closes the old host's connection and refuses its User JWT on reconnect, even though that JWT has no expiry. Such an NKey is never accepted or enrolled again. **A freed sprout ID can be enrolled again**, by a host with a fresh NKey: it gets the ID, and the box key it enrols with is the ID's only active key. The old host's NKey and box keys stay revoked.

**Sprout IDs are one subject token** (SEC.3a, security review 2026-10, M4). A sprout ID holds only lowercase letters, digits, `-` and `_`, never a dot, so sprout `web01`'s grant `imas.sprouts.web01.>` can't cover `web01.example.com`'s subjects. Enrollment maps a hostname's dots to dashes (`web01.example.com` enrols as `web01-example-com`). IDs that are control tokens in a sprout's position are reserved: today only `announce` (`imas.sprouts.announce.<id>`). Every subject that takes the sprout ID by position (`imas.sprouts.*.facts`, `imas.sprouts.*.boxkey.pub`, the `shell.start`, `cmd.run`, `cook` and `test.ping` subjects, `imas.cook.<id>.<jid>` and `imas.logs.sprouts.<id>.<LEVEL>`) is unambiguous under this rule.

**Sprout-side rotation, farmer-triggered only.** The sprout never decides on its own to rotate — no schedule, no local heuristic. It reacts solely to farmer's trigger on its own `imas.sprouts.<id>.boxkey.rotate` (`SproutBoxKeyRotateCmd`), which — as the "Key rotation" section above requires — carries no key material, only an instruction. Periodic rotation, if wanted operationally, is farmer's admin-triggered path (the sibling of `pki.rotatetenantbox` for sprout keys) driven by an external scheduler, not sprout-side logic. On a trigger, the sprout generates a fresh X25519 keypair (`crypto/rand`, the same as `EnsureSproutBoxKey`'s bootstrap path) and submits its public half sealed under the **current** key, as `handleBoxKeySubmit` requires. The new key is held as **pending**, not yet current: farmer seals new traffic to a sprout's active key only, with no grace on the seal side, so a submission farmer hasn't processed yet would otherwise be unopenable. The sprout has no reply on this subject to tell it the submission landed, so it treats the first farmer payload that opens under the pending key as that confirmation, and only then promotes it to current. A lost or refused submission leaves the sprout on its current key, which farmer still opens, and the next trigger resubmits the same pending key rather than generating another. The replaced key is kept as **previous** for `sproutboxkeyprevgrace` (default 15m, floored at twice the sprout's clock-skew tolerance so a payload farmer sealed to it just before the switch still opens) — opening tries current, then pending, then previous; sealing always uses current. A trigger arriving inside the previous key's grace window is refused, which is also, deliberately, the shortest interval between two rotations. The trigger itself stays unauthenticated (empty body, so nothing to steal, a superseded key is never reactivated, and only the active key can name a new one), so a rogue bus subscriber can force a nuisance rotation but not a key substitution — an accepted, low-severity gap, not an oversight. Already-enrolled sprouts needed a JWT re-mint (`mintOrReuseUserJWT`, the same path the log-shipping grant used) to add the `boxkey.pub` publish grant `sproutPermissions` was missing; without it nats-server refused every submission outright, so no farmer-triggered rotation could complete until a sprout's next refresh and restart picks up the re-minted JWT.

**Outbound proxy for the bus connection** (`busproxyurl`, sprout config, empty by default) is a separate, unrelated addition covered in `imas-master-plan.md`'s Phase 2 section, not this design — noted here only so a reader of "still open" lists doesn't conflate the two.

**Boundaries sealed so far.** `cmd.run` in both directions (`internal/ingredients/cmd/sealed.go`); `cook` in both directions, meaning the recipe dispatch on `imas.sprouts.<id>.cook` and its Ack, plus the resync nudge on `imas.sprouts.<id>.recipe.nudge` and its Ack (`internal/cook/sealed.go`); and box key submissions. (The `fleetsigningkeys` reply was also sealed until CL.1 removed that subject: a sprout now verifies releases against the keyring shipped in its package, so no fleet key crosses the bus.) On `cmd.run` and `cook`, farmer seals for every sprout that has a box key on record, and falls back to plaintext only for a sprout with none, i.e. one enrolled before J, with a warning. Any other failure to seal fails the request rather than sending plaintext. A sprout with keys refuses a plaintext `cmd.run`, cook dispatch or nudge (`encryption-required`). Farmer refuses a plaintext reply to a sealed request, and a sealed one whose `re` isn't the request it just sent. Live `cmd.run` output streaming (`stream_topic`) is dropped from sealed requests, because it publishes in plaintext to a subject the CLI reads without a tenant key.

**Cook job records.** Farmer's job store used to record a job's creation (placeholder steps, `invoked_by`, the status index's step count and dispatch time) by queue-subscribing to `imas.sprouts.*.cook` and reading the plaintext envelope. That subject now carries only ciphertext, so the replica that dispatches a job records it directly (`cook.SetDispatchRecorder`, installed by `internal/jobs`), after the request is sealed and before it is sent. A dispatch that can't be sealed is neither sent nor recorded.

**What the sprout logs, and what it ships** (security review 2026-10, H4). The sprout used to log every opened cook envelope at Trace, and log shipping published every level on the bus, so every sealed recipe was republished in plaintext. Now nothing logs an opened body at any level: cook logs a job's ID and step count, step completions log the step ID and status, and a `cmd.run` or cook body that doesn't decode is refused without quoting the decoder's error. A box public key isn't logged either, since the bus learning one is the first step of the H3 attack. Log shipping (`internal/log`) publishes only from a minimum level, `natslogminlevel` in the sprout config, default `info`; Trace and Debug stay in the local log. The same filter applies to farmer's own log shipping. Tests run the sealed `cmd.run` and cook paths with every sink capturing at Trace, the NATS one included, and fail if any opened content reaches a sink.

**Still plaintext inside TLS:** cook's step events (`imas.cook.<id>.<jid>`), which the imas CLI reads directly without a tenant key, and every other boundary listed in `docs/BUILD-STATUS.md`.

## Sealing `shell.*` (design, not built)

**FLAG FOR SECURITY REVIEW.** This section is a design and has not been built. It is ready for review, not approved. It closes `docs/BUILD-STATUS.md` Open item 2 (requirement 14). It reuses `internal/payloadbox` for every handshake message, along with its purposes, its ±5 minute freshness window, its single-use message IDs and its `ReplyTo` binding. It adds one thing `payloadbox` doesn't have: a sealed stream of numbered frames for the life of a session.

### What is wrong today

Read from `main` at `a38becb`:

- `imas ssh` (`cmd/imas/cmd/ssh.go`) calls `imas.api.shell.start` over the CLI's own bus connection, with the bearer token `injectToken` adds to every request. Farmer (`internal/natsapi/shell.go`) checks RBAC and forwards a **plaintext** `StartRequest` to `imas.sprouts.<id>.shell.start`. The sprout (`internal/shell/sprout.go`) runs `exec.Command(req.Shell)` under a PTY. `req.Shell` is any path the request names (default `/bin/sh`). The sprout then relays raw keystrokes and output, unauthenticated and in plaintext, on `imas.shell.<session>.{input,output,resize,done}`. The CLI and the sprout talk to each other directly. Farmer only watches `done` for its audit entry.
- So a compromised bus can (a) publish its own `shell.start` to any Unix sprout and get a root shell, (b) read every keystroke and every byte of output of a legitimate session, and (c) inject input into it. The bus is the nats-server that enforces subject permissions, so a compromised one ignores them. Any CLI admin can do (a) as well, without farmer's RBAC or audit: CLI admins are tenant Users with `imas.>`.
- **Shell doesn't work for a sprout with a per-sprout JWT.** `sproutPermissions` (`internal/pki/jwtusers.go`) grants no `imas.shell.>` subject. I checked this against a live embedded bus with the repo's JWT test harness (`startTestBus`, `acceptTestSprout`), in a throwaway test that I didn't commit. A sprout User is refused both the `imas.shell.<sid>.input` subscription and the `imas.shell.<sid>.output` publish (Permissions Violation). `shell.start` sits inside the sprout's `imas.sprouts.<id>.>` grant, so it still arrives and still spawns the PTY. After that, nothing flows. The shell also stays running unless an idle timeout was requested, and the default is none. `internal/shell/integration_test.go` uses an unauthenticated server, which is why nothing caught this. The redesign has to fix the subject grants anyway (see "Subjects and grants").
- **Finding beyond `shell.*`, which this design must not inherit.** The CLI's leg to farmer runs over the same bus. Its `token` is a bearer token: an NKey signature over an expiry time alone (`internal/auth/sign.go`), valid for 5 minutes and not bound to the request. A compromised bus sees every token in every `imas.api.*` request. It can replay one, with parameters of its choosing, to any farmer replica for up to 5 minutes. Worse, it can mint its own token, valid as long as it likes, from the nonce the CLI signs at connect time (see "Sealing the control plane"). Farmer then seals that `cmd.run` or `cook` to the sprout correctly. `internal.sprout.action` (`internal/natsapi/sprout_action.go`) is weaker still. It trusts that a message arrived on the SYS-account subject, plus the shape of its reply subject. A compromised bus can forge both. Sealing farmer↔sprout stops the bus from injecting **directly** into a sprout. It does not stop the bus from asking **farmer** to do it. The shell design below avoids this: a session can't be opened with a bearer token, or with anything the CLI's NKey signed. The same gap in `cmd.run`, `cook` and the SaaS API path is designed in "Sealing the control plane", after this section. Shell depends on it: leg 1 authenticates with that section's CLI box key.

### Decision 1: who seals

The CLI holds no tenant private key and must not get one. Four shapes were considered:

| | Shape | How it works | Verdict |
|---|---|---|---|
| A | CLI seals for the sprout | The CLI is given a tenant key. | **Rejected.** It hands every admin laptop a key that can command every sprout in the tenant. |
| B | CLI → farmer over HTTPS or WebSocket, farmer seals to the sprout | A new authenticated endpoint on farmer's HTTP API (behind Envoy) carries the terminal. Farmer relays sealed frames over the bus. | **Not chosen.** It protects against the bus only. Envoy, also in the DMZ, terminates the CLI's TLS and would see every keystroke. The CLI has no HTTP login today, and farmer core would gain a new inbound, human-facing surface. |
| C | **Farmer relays, both legs sealed, over the existing bus** | The CLI pins its tenant's box **public** key and seals its open request to it. The seal is made with the CLI's own registered **CLI box key** ("Sealing the control plane"), and that is what authenticates the user. Farmer verifies, then runs one sealed, numbered stream to the CLI and another to the sprout, and copies between them. | **Recommended.** |
| D | End to end, CLI ↔ sprout, with farmer as authoriser only | Farmer vouches for the CLI's ephemeral key to the sprout, and for the sprout's ephemeral key to the CLI. Frames go CLI ↔ sprout without passing through farmer. | Credible runner-up. |

**Why C over D.** C and D need the same trust anchors. In both, the CLI pins a farmer-side public key and authenticates its request with its own registered key. In D, farmer still has to vouch for the sprout's ephemeral key to the CLI. Without that, a bus could substitute its own key on the farmer→CLI leg and pose as the shell to harvest typed passwords, even though it can't reach the real sprout. So D saves no trust-anchor work. What C adds is one point of enforcement. Farmer can end a session the moment the user's role is revoked or the tenant key is severed. It knows why every session ended, for the audit log. It is also the only place a transcript could later be recorded (Decision 5) without trusting the sprout's root user to leave the recording alone. C's costs: farmer sees plaintext keystrokes, and each session is pinned to the farmer replica that opened it. Farmer already holds `tenant_priv`, so it can always open a shell itself, and this adds no access it didn't have. Shell sessions are rare and low-volume compared with fleet traffic, so relaying them doesn't weigh on requirement 7.

**Why C over B.** C defends against the whole DMZ (bus and Envoy), not just the nats-server process. It also needs no new transport or login in the CLI: the CLI keeps the bus connection it already has.

**The CLI's pinned key** is its tenant's existing box public key, `tenant_pub` (not secret). It is set in the CLI config as `tenantboxpub` (base64, shown with a fingerprint). It is copied out of band the same way the bus root CA and the CLI's NKey registration already are, never fetched over the bus. A tenant key rotation reaches the CLI through the mechanism sprouts already use. Farmer's replies carry a continuity proof sealed to the CLI's box key, once under each retained earlier tenant key. A CLI pinned to one of them re-pins to exactly the key named, and `--sever` cuts the chain, as it does for sprouts. The proof gets its own purpose (`f2c.tenantkey.continuity`), so it can't be confused with a sprout's.

### Decision 2: the protocol

Two legs, each set up by a `payloadbox` handshake and then carried as a sealed, numbered stream under ephemeral keys:

```
CLI                              farmer (owning replica)                 sprout
 |-- c2f.shell.open (payloadbox) -->|                                       |
 |   sealed cli_box -> tenant_pub   | open under user's box key; replay     |
 |   carries cli_eph_pub            | guard; RBAC (shell, scope, tenant)    |
 |<- f2c.shell.open (payloadbox) ---| session_id, farmer_eph1, limits,      |
 |   ReplyTo = open's id            | continuity proof if pin is old        |
 |== c2f frame 0: HELLO ===========>| key confirmation: only the real CLI   |
 |                                  | can produce it                        |
 |                                  |-- f2s.shell.start (payloadbox) ------>|
 |                                  |   session_id, farmer_eph2, cols/rows, | open; replay guard;
 |                                  |   shell, idle, max duration, user     | local policy; spawn PTY
 |                                  |<- s2f.shell.start (payloadbox) -------|
 |                                  |   sprout_eph, ReplyTo = start's id    |
 |<= f2c frame 0: READY ============|                                       |
 |<=========== DATA / RESIZE / ACK / HEARTBEAT / CLOSE frames ============>|
         leg 1 (c2f / f2c)                     leg 2 (f2s / s2f)
```

**Handshake messages are `payloadbox` messages with new purposes:** `c2f.shell.open`, `f2c.shell.open`, `f2s.shell.start`, `s2f.shell.start` and `f2c.tenantkey.continuity`. `c2f`/`f2c` are new direction prefixes, for CLI→farmer and farmer→CLI. `Message.SproutID` is the target sprout on both legs, so leg 1 is bound to one sprout as well.

- **`c2f.shell.open`.** A sealed control-plane request ("Sealing the control plane", Decision A), with its own purpose. The CLI seals with `KeyPair{PeerPub: pinned tenant_pub, Priv: cli_box}`, its registered CLI box key, and names the user in the `Imas-Principal` header. `Message.SproutID` (`sid`) carries the user ID, and the target sprout is in the body. The body is `{sprout_id, cols, rows, shell, idle_timeout_sec, cli_eph_pub, pinned_tenant_key_fpr}`. `cli_eph` is a fresh ephemeral X25519 key from `crypto/ecdh` in the standard library, used only for the session keys below. The box hides the request from the bus and means only the real farmer can open it. Only the holder of `cli_box` (or of `tenant_priv`) could have made it, and that is what authenticates the user. **Not an NKey signature:** the CLI's NKey signs whatever nonce the bus sends at connect time, so a signature from it proves nothing against the bus (verified; see "Sealing the control plane"). **No bearer token is accepted on this path.**
- **Farmer, on `c2f.shell.open`.** Farmer opens it under every key `TenantBoxKeys` returns, so a CLI still pinned to the previous key works during the grace window. It applies the `payloadbox.ReplayGuard` rules (a farmer-side guard for `c2f`, ±5 minutes, each ID once). It refuses a `cli_eph_pub` that is a low-order point or equal to `tenant_pub`. It opens it only under the box key registered for the user named in the header, checks that `sid` names that user, and checks that the user's role grants `shell` scoped to `sprout_id`. This is the same check `checkScopedAccess` makes, but keyed on the verified user, not a token. It checks that the sprout belongs to this tenant (`(tenant_id, sprout_id)`, never `sprout_id` alone) and has a box key. Then it picks `session_id` (128 random bits, `payloadbox.NewID`) and its own ephemeral `farmer_eph1`. It replies sealed under `(tenant_priv, cli_box_pub)` (purpose `f2c.shell.open`), one copy per tenant key, with `ReplyTo` set to the open's ID. The reply carries `farmer_eph1_pub`. Every refusal is one fixed `Imas-Payload-Error` code, as today, and the reason stays in farmer's log.
- **Key confirmation before anything runs.** Farmer contacts the sprout only after the CLI's first leg-1 frame (`HELLO`, seq 0) opens. A bus replaying a captured `c2f.shell.open` (to this replica or another) gets a reply it can't use, because it lacks `cli_eph`. It can't produce `HELLO`, so no PTY is ever spawned. Farmer drops a session that hasn't sent `HELLO` within 10 seconds. The per-replica replay guard is defence in depth. Key confirmation is what makes a replay to another replica harmless.
- **`f2s.shell.start` / `s2f.shell.start`.** This is request and reply on `imas.sprouts.<id>.shell.start`, under the same rules as sealed `cmd.run`: `pki.SealToSprout` and `pki.SproutOpenFromFarmer` (which already runs the sprout's `ReplayGuard`), the reply bound by `ReplyTo`, and farmer refusing a plaintext reply to a sealed start. The body is `{session_id, farmer_eph2_pub, cols, rows, shell, idle_timeout_sec, max_duration_sec, user {pubkey, name}}`. The `user` field is there so the sprout can log who opened the session locally. The sprout checks local policy before spawning: `disableshell`, the shell allow-list, and its concurrent-session cap. It then generates `sprout_eph`, spawns the PTY and replies `{sprout_eph_pub}`. A policy refusal goes back as a **sealed** reply body carrying a fixed code (`shell-disabled`, `shell-not-allowed`, `too-many-sessions`, `unsupported`, `spawn-failed`), so the bus learns nothing. Only a failure to open uses the `Imas-Payload-Error` header.

**Session keys.** Each leg runs X25519 between its two ephemeral keys (`crypto/ecdh` rejects an all-zero shared secret). That secret goes through HKDF-SHA256 (`crypto/hkdf`, standard library, Go 1.24 and later; `go.mod` is on 1.26). The salt is SHA-256 over the handshake transcript: both ephemeral public keys, `session_id`, `tenant_id`, `sprout_id`, the user ID, the leg label and the IDs of the two handshake messages. HKDF derives one key per direction: `c2f`/`f2c` on leg 1 and `f2s`/`s2f` on leg 2. The static tenant and sprout keys only authenticate the handshake. So:

- No two sessions, and no two directions, ever share a key.
- **Recorded shell traffic stays unreadable even if `tenant_priv` later leaks.** This is a forward-secrecy property the rest of this design explicitly gave up ("Forward secrecy — accepted tradeoff"). Shell sessions get it almost for free because they are stateful anyway. They carry the most sensitive traffic in the system: passwords typed at `sudo` prompts.

**Frames.** Each NATS message carries one frame, with the header `Imas-Payload: shell1` (a hint, never a security decision, like `box1`). The wire format is `version (1 byte) | seq (uint64, big-endian) | ciphertext`. The AEAD is ChaCha20-Poly1305 from `golang.org/x/crypto/chacha20poly1305`. `golang.org/x/crypto` is already a dependency (`nacl/box`), so no new module and no new licence. It is constant-time on sprouts without AES instructions. The nonce is 4 zero bytes followed by `seq`. The key differs per direction and `seq` never repeats within one, so a (key, nonce) pair is never reused. The associated data is `"imas-shell-v1" | direction | session_id | version | seq`. The plaintext is `type (1 byte) | payload`. The frame type is inside the ciphertext, so the bus sees only sizes and timing.

| Type | Direction | Payload | Notes |
|---|---|---|---|
| `HELLO` | c2f, seq 0 | cols, rows | Key confirmation (above). |
| `READY` | f2c, seq 0 | none | The sprout spawned the PTY. |
| `DATA` | all | bytes | Input toward the sprout, output toward the CLI. At most 16 KiB of plaintext. The sprout reads the PTY in chunks of up to 16 KiB and flushes after 10 ms without output, to keep the message rate down. |
| `RESIZE` | c2f, f2s | cols, rows (uint16 each) | Bounds-checked: 1 to 1000. |
| `ACK` | all | highest contiguous seq received | Flow control (below). |
| `HEARTBEAT` | all | none | Sent after 15 s with nothing else sent. |
| `CLOSE` | all | reason code, exit code, last seq sent | The final frame in each direction. Farmer forwards the sprout's `CLOSE` to the CLI, and the CLI's to the sprout. |

**Receiving rules, which fail closed.** A receiver tracks the next expected `seq` per direction. If `seq` equals the expected value and the frame opens, the receiver accepts it. Anything else ends the session: a lower `seq` (replay or duplicate), a higher one (a dropped frame), or a frame that doesn't open (tampering, wrong session, wrong direction). The receiver sends `CLOSE` with reason `integrity`, and the sprout kills the PTY. There is no resynchronisation. A single dropped keystroke can change what a command line does (`rm -rf /tmp/x` with characters missing), so a session that can't prove it received everything stops. A sender stops at 2^32 frames in one direction, which no real session reaches.

**Flow control** keeps an ordinary `cat` of a large file from turning into a NATS slow-consumer drop. Under the rule above, a drop now ends the session instead of quietly corrupting the screen. Each receiver sends `ACK` every 64 KiB or 250 ms. A sender with more than 512 KiB unacknowledged stops reading its source: the sprout stops reading the PTY, and farmer stops reading the other leg. Farmer keeps a window on each leg separately.

**Timeouts.**

- **Heartbeat.** If either end of a leg hears nothing for 45 s, it closes with reason `peer-lost`. This bounds how long a bus can black-hole a session without the user seeing it.
- **Idle timeout.** Measured on CLI `DATA` frames, as today. The sprout enforces it, using the value in the sealed start capped by a sprout-local maximum, and so does farmer. The default changes from "none" to a farmer policy value (Open question 3). The CLI may only ask for something shorter.
- **Maximum session duration** (new). A farmer policy value carried in the sealed start and enforced by both farmer and the sprout.
- **Close reasons** are fixed codes: `exit`, `client-close`, `idle`, `max-duration`, `peer-lost`, `integrity`, `revoked`, `key-severed`, `farmer-shutdown`, `spawn-failed`. They are shown to the user and written to the audit log.

**Subjects and grants.** Nothing secret goes in a subject: `session_id` is routing metadata.

- Leg 1: `imas.api.shell.open` (request and reply, queue group, like every `imas.api.*` method). Then `imas.shell.cli.<session_id>.c2f` and `imas.shell.cli.<session_id>.f2c`. The owning replica subscribes to its own session subjects without a queue group, as it does for `done` today.
- Leg 2: `imas.sprouts.<id>.shell.start` (request and reply). Then `imas.sprouts.<id>.shell.<session_id>.f2s`, which is already inside the sprout's `imas.sprouts.<id>.>` subscribe grant. And `imas.shell.sprout.<id>.<session_id>.s2f`, which needs a **new publish grant** `imas.shell.sprout.<id>.>` in `sproutPermissions`. It sits outside `imas.sprouts.<id>.>` so the sprout doesn't receive its own frames, for the same reason the log grant does. Already-enrolled sprouts pick the grant up through the `mintOrReuseUserJWT` re-mint on their next refresh and restart, as the `boxkey.pub` and log grants did.
- `imas.api.shell.start` and the `imas.shell.<session>.{input,output,resize,done}` subjects are **removed**. Leaving the bearer-token start in place would leave a path the bus can forge (above). An old CLI gets a fixed error naming the version it needs.

**State.**

- **Farmer** keeps sessions in memory on the owning replica, keyed `(tenant_id, session_id)`. Each record holds `sprout_id`, user, role, the tenant key version used for leg 2, per-direction keys and counters, windows and timers. `shell.Tracker`, keyed on `session_id` alone today, moves to that key, per the tenant-safety rule in `CLAUDE.md`. A replica that restarts or shuts down sends `CLOSE farmer-shutdown` on both legs. Sessions don't migrate between replicas.
- **The sprout** keys sessions on `session_id` (a sprout belongs to one tenant). It starts the shell in its own session and process group (`Setsid`), with `Pdeathsig: SIGKILL` on Linux, and kills the whole group on close. Today `cleanup` kills only the direct child, and nothing kills it if the sprout process exits.

### Decision 3: what a compromised bus can still do

| A compromised bus (or anything else between the endpoints, Envoy included) | After this design |
|---|---|
| Starts a shell on a sprout | **No.** A box-ready sprout acts only on a `f2s.shell.start` that opens under its tenant key and is fresh and unseen. Farmer sends one only for a `c2f.shell.open` that opens under the registered CLI box key of a user with the `shell` permission, and only after key confirmation. A captured open can be replayed but never confirmed. |
| Reads input or output | **No.** Frames are encrypted under per-session keys derived from ephemeral X25519. They stay unreadable even if `tenant_priv` or a sprout key leaks later. |
| Injects, alters, replays or reorders input or output | **No.** Every frame is authenticated, and its nonce is its sequence number in its direction. A frame from another session, another direction or another position doesn't open. |
| Drops frames silently | **No:** dropping is possible, silence isn't. A gap ends the session (`integrity`). Dropping everything ends it within 45 s (`peer-lost`). Cutting off the tail is visible because `CLOSE` is authenticated and carries the last seq sent. A session never appears to end normally when it didn't. |
| Poses as the shell to the user to collect typed passwords | **No.** The CLI accepts only an `f2c.shell.open` sealed under its pinned tenant key. |
| Denies service | **Yes.** It can drop the open or the start, drop or delay frames until the session closes, or flood session subjects with garbage. Each garbage frame costs the receiver one AEAD check, and the first one that fails to open ends that session. That is the accepted cost of failing closed. |
| Learns metadata | **Yes.** Which CLI connection opened a session to which sprout, when, for how long, and the size and timing of every frame. **Keystroke timing** is the notable leak: typing rhythm can hint at what was typed, including passwords typed at a no-echo prompt. OpenSSH has added keystroke-timing obfuscation for this reason. Not mitigated in v1 (Open question 5). |
| Spawns a PTY on a sprout that hasn't upgraded | **Yes, until that sprout upgrades.** An old build accepts a plaintext `shell.start` from anyone, whatever farmer does (see Decision 4). |

Not in scope: a compromised farmer (it holds `tenant_priv` and can always open a shell), a compromised CLI host or stolen CLI box key (that *is* the user), and the sprout's own root user.

### Decision 4: rollout

- **A sprout with no box key** (enrolled before workstream J) can't open a sealed start. `cmd.run` falls back to plaintext for such sprouts. Shell does **not**: farmer refuses with "re-enroll this sprout". Shell is the boundary where a downgrade costs most. A farmer setting `shellallowplaintextsprouts` (default `false`) can re-enable the old path during a migration. It is logged on every use, and can be removed once no tenant has such a sprout. This setting changes only what farmer sends. A pre-J sprout stays exposed to a bus injecting a start directly until it is re-enrolled.
- **A box-ready sprout running the new build** refuses a plaintext `shell.start` (`encryption-required`) without spawning anything, as `RespondCmdRun` does. It answers a sealed start with `no-keys` if it has lost its keys.
- **A box-ready sprout still on an old build** gets the sealed start, can't parse it, and answers in plaintext (today it would say "session_id is required"). Farmer treats any plaintext reply to a sealed start as "this sprout needs upgrading", as `ErrReplyNotSealed` does for `cmd.run`. Farmer **never** retries in plaintext.
- **Order.**
  1. `internal/payloadbox`: purposes and the frame codec. No change in behaviour.
  2. The sprout build: the sealed handler, plaintext refused when box-ready, local policy, process-group kill, the Windows handler.
  3. Farmer: the grant and re-mint, `imas.api.shell.open`, the relay, removal of `imas.api.shell.start`.
  4. The CLI: `imas ssh` over `shell.open`, and `tenantboxpub` with continuity re-pinning.

  Steps 3 and 4 need the CLI box keys and sealed `imas.api.*` from "Sealing the control plane" (its rollout step 4) to be in place first.

  Steps 2 to 4 ship in one release. Farmer and the CLI upgrade together, centrally. Sprouts follow by package upgrade or fleet update, and fleet-update dispatch is still off by default (requirement 20). Until a sprout upgrades, shell to it is unavailable, which is the safe failure. **The security gain arrives per sprout, with that sprout's upgrade.** An old sprout build accepts a plaintext start from the bus, and nothing farmer does changes that. Treat requirement 14 as met only once the fleet runs the new sprout build. Reporting can use the sprout version farmer already has from facts.
- **A sprout-local `disableshell`** (sprout config, exposed by the Ansible role `imas_sprout`) refuses every start before anything else is checked. It gives a customer a per-host off switch that doesn't depend on farmer. Default: Open question 3.
- **Windows** (`internal/shell/sprout_windows.go`) has no PTY and keeps refusing. It still follows the same rules, so its answers leak nothing and can't be used for a downgrade:
  - a sealed start is opened and answered with a sealed `unsupported`;
  - a plaintext start on a box-ready sprout gets `encryption-required`;
  - anything else gets today's "not supported" message.

  Real Windows shells would need ConPTY (`CreatePseudoConsole` through `golang.org/x/sys/windows`, no CGO). ConPTY exists only on Windows Server 2019 and Windows 10 1809 or later, and the stated floor is Server 2016. That is a separate design (Open question 9). It would reuse this protocol unchanged.

### Decision 5: RBAC, audit, transcripts, rotation

- **Who may open a shell.** A registered user whose role grants the existing scoped `shell` action (`rbac.ActionShell`) for that sprout's cohort or ID, in that tenant, proved by the request opening under that user's registered CLI box key. `cmd` doesn't imply `shell`. `dangerously_allow_root` skips neither the role check nor the sealing: it has no effect on the NATS path (owner decision 2026-10-04, PR #95). The SaaS API (`internal.sprout.action`) gets **no** shell action in this design. `translateAction` already rejects unknown actions, and a browser shell would need its own leg 1. Limits come from farmer policy: concurrent sessions per user, per tenant and per replica. The built-in `operator` role grants `shell` today (Open question 4).
- **Revocation while a session runs.** Every 60 s the owning replica re-checks that the user still exists and still has `shell` on that sprout. If not, it closes the session with `revoked`.
- **Audit (farmer, `internal/audit`).**
  - `shell.open`: user, role, tenant, sprout, `session_id`, shell, outcome, and the fixed refusal code if refused.
  - `shell.end`: duration, exit code, close reason, bytes and frames each way.

  Both are written by the handler. The router's generic entry for `imas.api.shell.open` stays, recording the verified user ID. There is no token or signature left in the parameters to redact. The sprout logs `session_id`, user and close reason locally, and never content. The sprout's log is shipped over the bus in plaintext (Decision 6), so the sprout log must never carry frame content or error text containing secrets.
- **Transcripts: none in v1.** Output can't be redacted reliably: a terminal stream has no structure to redact on, farmer doesn't know the secret values a sprout fetched (`sdb://`), and `sensitive` redaction applies only to cook variables. Input can't be recorded at all, because it contains passwords typed at no-echo prompts. Because farmer is the relay (Decision 1), a later opt-in **output-only** recording can be added there without touching the protocol: off by default, per tenant, stored encrypted with a retention limit. Whether one is needed (CERT-In, DPDP) is Open question 2.
- **Tenant key rotation while a session runs.**
  - A normal rotation doesn't affect running sessions. After the handshake, a session depends only on its ephemeral keys. New opens use the new key, and CLIs re-pin through the continuity proof.
  - **`--sever`, or deleting a key version,** means that key may be in someone else's hands, and whoever holds it could have opened sessions. Each farmer replica re-reads the tenant's key set at least every 60 s. It closes, with `key-severed`, every session whose leg 2 handshake used a version no longer in the set. This needs no bus signal that could be forged. A severed sprout fails its next pin check and exits, and the process-group kill takes its shells with it.
  - A sprout box key rotation doesn't affect running sessions either.

### Decision 6: the other plaintext boundaries

| Boundary | Direction | What a compromised bus gains today | Seal? | Why |
|---|---|---|---|---|
| Cook step events, `imas.cook.<id>.<jid>` | s2f | Reads each step's change notes and errors (`sensitive` values already redacted). **Forges results**, so a failed or skipped step reports success in job records and the UI. | **Yes, next after shell** | Integrity matters as much as confidentiality. Readers that hold no tenant key (`internal/jobs` listeners aside, also `internal/serve/logstream.go` and the CLI) would get events from farmer over a sealed leg like leg 1 here. Sealing only the sprout side would just move the plaintext to a farmer re-publish. |
| `test.ping` | f2s and reply | Forges a pong (says a sprout is up) or drops one. | **No** | It carries nothing, and the bus can always lie about or block liveness. The `$SYS` connect events farmer uses for heartbeat come from the bus as well. |
| Facts, `imas.sprouts.<id>.facts` | s2f | Reads host inventory (names, addresses, OS, hardware). **Forges facts**, which can move a sprout into or out of a fact-based cohort and so change which hosts a cook or shell scope covers. It still can't change what runs. | **Yes, medium priority** | Integrity of targeting, plus inventory confidentiality. Fire-and-forget, sealed with a new `s2f.facts` purpose and checked by farmer's facts listener against a timestamp window. |
| `cancel` | f2s | Forges a cancel (stops a job half-way) or drops one. | **Yes, low priority** | Both are denial of service, which the bus can already cause. Sealing it buys a simple invariant: **a box-ready sprout acts on no plaintext command at all**. That is easier to review and test than a list of exceptions. |
| `boxkey.rotate` trigger | f2s | Forces a nuisance rotation, rate-limited by the previous key's grace window. It can't substitute a key. | **Yes, low priority, same invariant** | Already documented above as an accepted, low-severity gap. Sealing removes it for one more purpose pair. |
| Log shipping, `imas.logs.sprouts.<id>.<LEVEL>` | s2f | Reads sprout logs and forges log lines. | **Not now** | High volume, so per-message boxes would need batching. The sealed handlers already keep secrets and error text out of the log. Keep that rule, and revisit if logs ever need to be evidence. |
| `imas.api.*` (CLI ↔ farmer) and `internal.*` (SaaS API ↔ farmer) | control plane ↔ farmer | **Replays or mints a CLI token, or forges a SaaS API request, to have farmer run a sealed `cmd.run` or `cook` on any sprout.** | **Yes, before claiming requirement 14 Green** | Designed in "Sealing the control plane" below. |

### Open questions

1. **The control-plane gap** is now designed in "Sealing the control plane" below, with its own open questions. Shell can't ship before that section's CLI box keys (its rollout step 4).
2. **Transcripts.** Do CERT-In, DPDP or customer contracts require session recording? If so: output only, per tenant, where it is stored, under what key, and for how long?
3. **Defaults:**
   - farmer's default and maximum idle timeout (proposed 15 min and 60 min);
   - maximum session duration (proposed 8 h);
   - whether sprout `disableshell` defaults to `true` for new installs (proposed: `false` for now, exposed in the Ansible role);
   - the sprout shell allow-list (proposed: `/etc/shells`, overridable in sprout config).
4. **Should the built-in `operator` role keep `shell`,** or should `shell` need an explicit grant? Proposed: drop it from `operator`.
5. **Keystroke timing.** Should v1 send input on a fixed tick with chaff frames, as OpenSSH does, or accept the leak as a recorded residual risk?
6. **Pinning `tenantboxpub` in the CLI.** Explicit config only (proposed), or trust on first use with a fingerprint prompt?
7. **Sessions die with their farmer replica.** Is that acceptable, and is an admin `imas shell list` / `imas shell kill` across replicas (a Valkey registry keyed `(tenant_id, session_id)`) needed in v1?
8. **Pre-J sprouts.** Confirm no deployment depends on plaintext shell to sprouts without a box key, so `shellallowplaintextsprouts` can ship defaulting to `false` and be removed later.
9. **Windows shells.** ConPTY rules out the Server 2016 floor. Build for Server 2019 and later only, or not at all?
10. **Leg 1 for a browser.** Should the SaaS API or web UI ever offer a shell? It would need its own leg 1, since a browser has an OIDC session, not a CLI box key.

## Sealing the control plane (design; J.1 building blocks, J.2 sealed refresh and J.3 sealed CLI built)

**FLAG FOR SECURITY REVIEW.** This section is a design. Its building blocks (rollout step 2, J.1) are built and ready for review, not approved (see "As built: J.1" at the end of this section). J.2 wires the first of them in: sealed sprout refresh, and a gateway JWT from `/v1/enroll` only for a box key proof (see "As built: J.2"); it too is ready for review, not approved. J.3 seals the CLI ↔ farmer API and removes bearer tokens (Decision A, rollout step 4; see "As built: J.3"); it too is ready for review, not approved. The SaaS API path is unchanged until J.4. The owner's decisions of 2026-10-04 there replace the compatibility flags and ratchets in "Rollout". It answers the shell section's Open question 1. Everything above seals farmer ↔ sprout. This section covers the other side of farmer: the imas CLI and the SaaS API, which reach farmer over the same bus, and the sprout's `/v1/refresh`. Until it is built, a compromised bus can't inject a command **into a sprout**, but it can get **farmer** to send one, and the sealing works exactly as designed while it does.

### What is wrong today

Read from `main` at `a38becb`. Items 2 and 3 were reproduced with a throwaway test (deleted, not committed). In it, a fake server sends a crafted `nonce` in its `INFO` and captures the signature from the client's `CONNECT`.

1. **Bearer tokens.** Each `imas.api.*` request carries a `token`, built by `auth.NewToken` and added by `injectToken`. It is the CLI's NKey signature over an expiry time and nothing else. It isn't bound to the method, the parameters or the tenant, and it travels in plaintext through the bus. A compromised bus can replay it with any parameters, to any farmer replica, until it expires.
2. **The bus can mint CLI tokens that never expire.** The CLI authenticates to the bus with `nats.Nkey(pubkey, auth.Sign)`, which signs whatever nonce the server sends. The token is a signature over the expiry string, and `UserAuth.IsValid` checks only that the expiry is in the future, with no upper bound. A bus that sends the nonce `2099-01-01T00:00:00Z` gets back a signature that is a valid token for that user until 2099. With an admin's token it can call `auth.users.add` to register a key of its own as admin (`handleAuthAddUser` writes it to farmer's config), and keep that access for good. No CLI request needs to be seen first: one connection is enough. **Verified.**
3. **The bus can refresh as any sprout.** The sprout's NKey seed signs both the bus `CONNECT` nonce (`nats.UserJWTAndSeed`) and its `/v1/refresh` proof, `RefreshSigningPayload(timestamp, nkey_pub)`. That proof is plain text: a domain string, the timestamp and the key, separated by newlines. A JSON nonce can carry newlines, and the signature from `CONNECT` passes `verifyTimestampedNKeySig` unchanged. **Verified.** With it, the bus calls `/v1/refresh` (through Envoy, reachable from the DMZ by design) and gets a fresh gateway JWT for that sprout. That JWT reads `GET /files/sprouts/<tenant_id>/<sprout_id>/recipe.json`, the **staged copy of the last rendered recipe**, including whatever secrets it was templated with (`internal/cook/stage.go`). That is exactly the content sealed `cook` protects on the bus. Single-use claiming (`claimSignedPayload`) doesn't help, because the bus chooses a fresh timestamp. J.2 found the same hole in `/v1/enroll`'s replay path (Decision C, corrected), and closes both ("As built: J.2").
4. **`internal.*` trusts the bus.** `tenant_provision.go` says it plainly: "authorization is the bus's own per-User permission check". A compromised bus ignores those permissions. It can:
   - forge `internal.tenant.provision`;
   - forge `internal.tenant.deprovision`, which locks a tenant out so all its sprouts are disconnected;
   - forge `internal.sprout.action`, which runs a sealed `cmd.run` or `cook` on any sprout of any tenant. `VerifySproutInTenant` passes, because tenant and sprout IDs are visible on the bus;
   - forge results back to the SaaS API: a tenant marked active or failed, or a batch item's status and output.

   Only `self_update` stays bounded, because farmer checks the version against the catalog and the fleet signing key, and the sprout checks it again against its own keyring.
5. **Nothing between the CLI and farmer is confidential or authenticated.** The bus reads every command line and its environment (`cmd.run` params can carry secrets), props values, audit queries and every reply, including `cmd.run` output. It can also forge replies: wrong output, a doctored `pki.list`.
6. **Minor.** The cook trigger (`imas.farmer.cook.trigger.<jid>`) is unauthenticated. The bus can fire it early or block it, which is denial of service. The CLI and `imas serve` read cook step events in plaintext (the shell section's Decision 6).

### Principles

- **P1. Key separation.** A key that signs a bus nonce signs nothing else, and no proof farmer accepts from a principal rests on such a key. NKeys keep authenticating bus connections and do nothing more. Two alternatives were considered and rejected:
  - Domain-separated signing with Ed25519ctx would be sound, but arguing that it is sound against a pure-Ed25519 nonce signature is subtle.
  - Separation by message prefix doesn't work at all: the nonce is chosen by the attacker.
- **P2. Every request farmer acts on is a sealed `payloadbox` message.** It is sealed under a key pair the bus doesn't hold and bound to its purpose, its principal, its method and a freshness window. It is accepted once.
- **P3. Every reply the requester relies on is sealed back.** It is bound by `ReplyTo`, or by `job_id` for asynchronous results.
- **P4. One mechanism.** Box authentication (static X25519 at both ends) through `internal/payloadbox`, the same as farmer ↔ sprout. There is no new signature format and no canonical encoding to get wrong.

### Principals and keys

| Principal | Authenticates with | Farmer's key | Where farmer gets the public half | How the principal pins farmer's key |
|---|---|---|---|---|
| Sprout | Its sprout box key (exists) | Tenant key (exists) | PXC (exists) | Enrollment and continuity (exist) |
| CLI user | **New: a CLI box key.** X25519, generated locally by `imas auth keygen`, private half in `cliboxprivfile` (mode 0600), never sent anywhere. | Tenant key | The users store, beside the user's NKey public key, which stays the user ID that roles and audit refer to | `tenantboxpub` in the CLI config (shell section, Decision 1) |
| SaaS API | **New: a SaaS API box key** | **New: a platform key.** One per deployment, in OpenBao KV v2 at `<base>/platform`. Its version history is its rotation history, as for tenant keys. | Delivered the way its NATS credential is (`imas-internal-api-account.md`, "JWT -> OpenBao hand-off"). Never over the bus. | The same hand-off, or a Helm value |

`Message.SproutID` (`sid` on the wire) holds the **non-farmer principal's ID**: a sprout ID, a user's NKey public key, or the fixed string `saasapi`. Principals of different kinds can't be confused, because each kind has its own purposes (`c2f`/`f2c` for the CLI, `a2f`/`f2a` for the SaaS API). A box public key already registered to any principal, or equal to a tenant or platform key, is refused at registration. Two principals sharing a key would also share the derived secret with farmer. Purposes already keep their messages apart, and the refusal is defence in depth.

### Decision A: CLI ↔ farmer (`imas.api.*`)

| | Option | Verdict |
|---|---|---|
| A1 | Request-bound signatures with the CLI's NKey | **Rejected** by P1. The bus can get any message signed. It also gives no confidentiality, and replies stay forgeable. |
| A2 | Request-bound signatures with a new Ed25519 key, plaintext otherwise | **Not chosen.** It fixes authentication but not confidentiality or reply integrity, and adds a second crypto format. |
| A3 | Move the CLI to HTTPS | **Rejected**, as in the shell section: Envoy, also in the DMZ, terminates the TLS. |
| A4 | **`payloadbox` with a CLI box key** | **Recommended.** Authentication, confidentiality and reply integrity in one, with the same code farmer uses for sprouts. Stateless per request, so any replica can serve any request. |

**Request.**

- The subject is unchanged: `imas.api.<method>`, on the queue group.
- Headers: `Imas-Payload: box1`, and `Imas-Principal: <user NKey public key>` (a hint telling farmer which key to try, never trusted on its own).
- Purpose `c2f.api` (or a method's own purpose, such as `c2f.shell.open`). `sid` is the user ID. The body is `{method, params}`.
- Sealed with `KeyPair{PeerPub: pinned tenant_pub, Priv: cli_box}`.

**Farmer.**

- **Opening.** Farmer tries the user's registered box keys (current and in grace) against every key `TenantBoxKeys` returns. `sid` must equal the header, and `body.method` must equal the subject's method. Without that binding, a bus could move a sealed `jobs.list` onto `imas.api.jobs.delete`.
- **Replay.** Every method goes through `payloadbox.ReplayGuard` (±5 minutes, each ID once), per replica. A **mutating** method also needs a cluster-wide claim: Valkey `SET NX` on `(tenant_id, user_id, message id)` with a 10-minute TTL. If Valkey is unreachable, mutating requests are refused (fail closed). Methods count as mutating by default, the way `NATSMethodAction` defaults to admin. Only an explicit read-only list is exempt:
  - `health`, `version`
  - `sprouts.list`, `sprouts.get`
  - `jobs.list`, `jobs.get`, `jobs.forsprout`
  - `props.getall`, `props.get`
  - `cohorts.list`, `cohorts.get`, `cohorts.resolve`, `cohorts.validate`
  - `pki.list`
  - `auth.whoami`, `auth.users`, `auth.explain`
  - `audit.dates`, `audit.query`

  A read replayed to another replica runs, but its reply is sealed to the requester, so the bus learns nothing from it.
- **RBAC.** Farmer looks the role up by the verified user ID. Scope checks are unchanged. **The token is removed:** `auth.NewToken`, `createSignedToken`, `injectToken`, and the `token` path in `authMiddleware` and `audit`.
- **Reply.** Purpose `f2c.api`, `ReplyTo` set to the request's ID, sealed `(tenant_priv, cli_box_pub)`, one copy per tenant key. It carries a continuity proof when the CLI's pin is old (shell section, Decision 1). A handler's error travels inside the sealed body. Only a failure to open uses the fixed `Imas-Payload-Error` codes.

**The CLI** accepts only a reply that opens under its pinned key and whose `ReplyTo` is its request. A plaintext reply is an error, never a result. `health` and `version` are also answered in plaintext, for monitoring. The CLI makes no decision on a plaintext reply.

**Where the work lands.** All of this sits in `client.NatsRequest` and in the handler wrapper in `natsapi.Subscribe`: one place on each side. Every method becomes sealed at once, as this document's "Implementation scope" section asked from the start. `imas serve` goes through `client.NatsRequest`, so it is covered. `imas tail` will show ciphertext. The cook trigger becomes a sealed method, `cook.trigger`, carrying the JID. Farmer accepts it only from the user who created that job, within the existing 15-second window.

**Key management.**

- **Creating a key.** `imas auth keygen` creates the CLI box key and prints its public half with a fingerprint.
- **Registering it.** The first admin is registered out of band in farmer's users config, as users are today. After that, `auth.users.add` carries the new user's box public key, sent as a sealed request by an admin. That request is now safe to accept, because the bus can no longer forge it.
- **Rotating it.** `imas auth rotate-key` sends a `c2f.userkey.pub` sealed under the current key, the CLI's version of `s2f.boxkey.pub`. The old key keeps opening requests for a 15-minute grace period, then is retired and never reactivated.
- **Removing a user** removes their key, which takes effect on the next request.
- Where the users store lives is unchanged here (Open question 2).

### Decision B: SaaS API ↔ farmer (`internal.*`)

| | Option | Verdict |
|---|---|---|
| B1 | **Seal on the existing bus, under a platform key** | **Recommended.** The same mechanism as Decision A. The defence doesn't depend on where things sit on the network. Results are authenticated too. |
| B2 | Move `internal.*` onto a transport only the core network can reach (a second nats-server in the core, or direct mTLS) | **Not instead of B1**, but worth adding later (Open question 5). It takes the DMZ out of the path entirely, but adds infrastructure and still trusts network placement. |
| B3 | Keep trusting SYS-account permissions | **Rejected.** That is the gap. |

**Wire.**

- Requests: purposes `a2f.tenant.provision`, `a2f.tenant.deprovision` and `a2f.sprout.action`, with `sid` set to `saasapi`. Sealed with `KeyPair{PeerPub: pinned platform_pub, Priv: saasapi_box}`. Farmer opens them with `(registered saasapi_box_pub, current and in grace) × (platform keys)`.
- Replay: all three are mutating, so each needs the per-replica guard **and** the Valkey claim.
- Farmer keeps its existing checks: `ValidSaaSAPIReplySubject`, the point-of-effect `VerifySproutInTenant`, and the catalog check for `self_update`. They still matter against a compromised SaaS API, which this section doesn't defend against.
- Results:
  - `internal.tenant.(de)provisioned.<job_id>` are sealed `f2a.tenant.provisioned` or `f2a.tenant.deprovisioned`. The body carries `job_id`, which must equal the one in the subject, and `tenant_id`. The SaaS API checks freshness (±5 minutes) and keeps its own replay guard. A replay of a genuine result is harmless under the provisioning job's state machine.
  - The `internal.sprout.action` reply is sealed `f2a.sprout.action` and bound by `ReplyTo`.
  - The outbox sweeper's re-publishes are new messages with new IDs. Legitimate at-least-once delivery is unchanged.

**Rotation.** The platform key rotates with a grace window, like a tenant key. The SaaS API re-pins from its configuration on its next rollout, or from a continuity proof `f2a.platformkey.continuity` (Open question 4).

### Decision C: sprout refresh

- **A box-ready sprout** sends `POST /v1/refresh` with the body `{nkey_pub, sealed}`. `sealed` is a `payloadbox` message with purpose `s2f.refresh` and `sid` set to the sprout ID, with the body `{nkey_pub, timestamp}`, made with `SproutSealForFarmer`. Farmer:
  - looks the sprout up by `nkey_pub`, giving `(tenant_id, sprout_id)`;
  - opens with `OpenFromSprout`, also trying retained tenant keys back to the last severing rotation, as continuity does, so a sprout whose pin is out of date can still refresh;
  - checks freshness (±5 minutes) and claims the message ID once, reusing the store `claimSignedPayload` already uses.
- **Per-sprout ratchet.** *(Superseded: owner decisions, 2026-10-04. Farmer refuses NKey-only refresh for every sprout, with no ratchet; see "As built: J.2".)* Once farmer has accepted one sealed refresh from a sprout, it records that, and refuses NKey-only refresh for that sprout from then on. No fleet-wide switch is needed. A sprout on an old build keeps refreshing the old way until it upgrades, and is protected from its first sealed refresh onwards.
- **A sprout with no box key** *(answered, Open question 3: it is refused and re-enrolls)* has only the NKey proof. It stays exposed until it is re-enrolled. It is already exposed in every other way listed in this document.
- **Enrollment is not safe unchanged (corrected by J.2).** This bullet used to say enrollment is unchanged, because its signed payload includes the one-time join token, so a signature the bus obtains over it is useless without a token. That is wrong for the replay path. An already-enrolled `nkey_pub` takes the idempotency replay before the join token is looked at, and the replay never checks the token. A compromised bus can get `EnrollSigningPayload` signed over a `CONNECT` nonce, with any token it likes, and before J.2 that replayed the sprout's identity with a fresh gateway JWT: the same hole as the NKey-signed refresh. So enrollment changes too: `/v1/enroll` issues a gateway JWT only for a request with a verified `sprout_pub_proof` (the second request of a first enrollment), whose message ID farmer claims once. A request with only the NKey proof gets the identity, the tenant and its key, and no gateway JWT.
- After this change the sprout's NKey signs bus nonces and its enrollment requests, and farmer issues a gateway JWT for neither on its own, so P1 holds for sprouts too: no proof farmer acts on rests on a signature the bus can obtain.

### Decision D: streams to the CLI (later)

**What stays plaintext until Decision D (checked at J.3).** J.3 seals every `imas.api.*` request and reply, including `shell.start` and the cook trigger. These CLI and `imas serve` reads are not requests to farmer and stay plaintext on the bus until Decision D (and, for shell, J.5). A compromised bus can read them and forge them; it can't use them to make farmer act:

| Who reads | Subject | What it carries | Until |
|---|---|---|---|
| `imas cook` (it always follows its job) | `imas.cook.*.<jid>` | step completions from each sprout: step IDs, status, changes, timings | Decision D |
| `imas jobs watch <jid>` | `imas.cook.*.<jid>` | the same | Decision D |
| The CLI's local job store (`internal/jobs` `CLIListener`, used by `imas cook`) | `imas.cook.*.<jid>` (and `imas.cook.*.*` in `Subscribe`) | the same, written to `~/.cache` | Decision D |
| `imas serve`'s log stream (`internal/serve/logstream.go`, the web UI's live log) | `imas.cook.*.*` | every step event of every job in the tenant | Decision D |
| `imas ssh` | the session's output and done subjects from the (sealed) `shell.start` reply | terminal output and exit status | J.5 (sealed shell) |
| `imas tail` | `imas.>` and `_INBOX.>` | everything on the bus; it now shows ciphertext for every API request and reply | a debugging tool; nothing to seal |

So until Decision D, `imas cook`'s on-screen result and `imas serve`'s live log are what the bus says they are: a compromised bus can hide a failure or show a forged success. The authoritative record is farmer's job store, read through the sealed `jobs.get` and `jobs.forsprout`. Sprouts publish step events in plaintext today (the shell section's Decision 6), so sealing the CLI's leg alone wouldn't help yet.

`cook --follow`, `jobs` watch and the `imas serve` log stream read step events off the bus in plaintext. Once sprouts seal their step events (`s2f.cook.event`, the shell section's Decision 6):

- The CLI's sealed request asks to follow and carries an ephemeral key.
- Farmer opens and records each event, then forwards it on `imas.stream.cli.<stream_id>` as frames in the shell stream format, f2c only.
- The plaintext `imas.cook.*.*` subscriptions in the CLI and in `imas serve` are removed.

### Stopgaps that can ship before the design is built

1. **Cap token lifetime (recommended now, a few lines).** `UserAuth.IsValid` refuses an expiry more than 5 minutes plus clock skew in the future. The bus can then mint tokens valid for 5 minutes at a time instead of until 2099. That is still a hole, but no longer a permanent one.
2. **Take `auth.users.add` and `auth.users.remove` off the bus API until Decision A lands.** Admins would edit farmer's users config directly instead. This closes the path from a forged token to permanent access. It is an operational cost (Open question 1).

Neither stopgap helps the sprout refresh (Decision C) or `internal.*` (Decision B). Only the designs do.

### What a compromised bus can still do

| A compromised bus | After this section and the shell section are built |
|---|---|
| Acts toward farmer as a CLI user, the SaaS API or a sprout | **No.** Each request must open under that principal's registered box key. |
| Mints a token, or refreshes as a box-ready sprout | **No.** Tokens are gone. Refresh is sealed for every sprout (J.2, no ratchet), and enrollment issues a gateway JWT only for a box key proof. |
| Reads requests or replies | **No.** It sees the subject (the method name), the principal header, sizes and timing. |
| Forges or alters a reply or result | **No.** |
| Replays a request | **Refused.** Every method is checked per replica. Mutating methods are also claimed across the cluster. A read replayed to another replica runs, but the bus can't open its reply. |
| Denies service, or delays a request inside the 5-minute window | **Yes.** |
| Attacks sprouts with no box key, or CLIs and SaaS APIs on old builds | **No, as built:** owner decisions of 2026-10-04 removed the flags and ratchets, so these are refused, not downgraded (a sprout with no box key re-enrolls). |

Not in scope: a compromised farmer, SaaS API, OpenBao or CLI host. A compromised **Valkey** can make farmer refuse mutating requests (fail closed). It can also let an authentic mutating request run a second time on another replica within 5 minutes. It can't create or change a request.

### Rollout

1. **Stopgap 1** (token lifetime cap). It can ship immediately.
2. **The building blocks**, with no change in behaviour: `payloadbox` purposes, the CLI box key store in the users store, the platform key, sealed request and reply helpers for both ends, and the Valkey claim helper.
3. **Sprout refresh (Decision C).** Farmer accepts sealed refresh and applies the ratchet. The sprout build sends sealed refresh. This can ride the same sprout release as sealed shell. *(As built in J.2: sealed only, no ratchet; see "As built: J.2".)*
4. **CLI (Decision A).**
   - Farmer accepts sealed `imas.api.*` and still accepts tokens, behind `apiallowbearertoken` (default `true` in this release). Farmer also ratchets **per user**: once a user has sent a sealed request, it refuses that user's tokens.
   - The CLI release sends only sealed requests. Each user runs `imas auth keygen` and has an admin register the key.
   - The next farmer release defaults `apiallowbearertoken` to `false` and drops the token code.
5. **SaaS API (Decision B).** Farmer accepts sealed and plaintext `internal.*` behind `internalallowplaintext` (default `true`). Then the SaaS API rolls out sending sealed. Then the default flips to `false`. In one Helm release that means three steps, for zero downtime.
6. **Shell** (the previous section), after step 4.
7. **Streams (Decision D)**, with step-event sealing.

Requirement 14 is Green only once steps 3 to 6 are done with both flags off, and the fleet runs the new sprout build.

**Owner decisions, 2026-10-04, replace the compatibility parts of steps 3 to 5.** Nothing is deployed, so there is no compatibility window: no `apiallowbearertoken`, no `internalallowplaintext`, no per-user or per-sprout ratchet, no plaintext and no bearer-token fallback. Steps 3 to 5 each end sealed only (J.3, J.4), and a sprout with no box key is refused, not downgraded. Sealing is built before the UAT gate.

### Open questions

1. **Stopgap 2.** Take user management off the bus API until Decision A lands?
2. **The users store with several farmer replicas.** `auth.users.add` writes farmer's local config file (`jety.WriteConfig`). Is that store actually consistent across replicas today? This design keeps whatever store exists, but key registration and rotation make it matter more. Not checked.
3. **Sprouts with no box key.** Keep NKey-only refresh for them (proposed, with a warning on every use), or refuse it and force re-enrollment? *Answered (owner, 2026-10-04): refuse it; the sprout re-enrolls. Built in J.2.*
4. **SaaS API keys.** Where is the SaaS API box key generated (proposed: a Helm hook job, private half to its Secret or OpenBao path)? Does the platform key need a continuity proof, or is re-pinning on rollout enough?
5. **B2 as well as B1.** Move `internal.*` onto a transport only the core can reach?
6. **The read-only list.** Confirm it. `cohorts.refresh` is treated as mutating.
7. **Valkey for mutating requests.** Is the fail-closed dependency on Valkey acceptable, or should the cluster-wide claim live in PXC?
8. **Forward secrecy for control traffic.** `cmd.run` output and audit queries are sealed under static keys, which matches this document's accepted tradeoff. Should they use ephemeral keys, as shell does?
9. **Method names in subjects.** Should they be hidden behind a single subject such as `imas.api.sealed`, or is that metadata acceptable?

### As built: J.1 (building blocks, no change in behaviour)

**FLAG FOR SECURITY REVIEW.** Rollout step 2. Nothing below was wired into a running path by J.1: the router, `client.NatsRequest`, `/v1/refresh` and saasapi's dispatch were unchanged, with one exception, the users store (below), which the brief asked to move. J.2 has since wired in the sealed refresh ("As built: J.2").

**Owner decisions, 2026-10-04.** Sealed only, with no compatibility window (see "Rollout"). Method names stay visible in subjects (Open question 9). Control traffic uses static keys (Open question 8). The Valkey claim for mutating methods fails closed (Open question 7).

**`internal/payloadbox` (`control.go`).**

- Purposes: `c2f.api`, `f2c.api`, `c2f.userkey.pub`; `a2f.tenant.provision`, `a2f.tenant.deprovision`, `a2f.sprout.action` and their answers `f2a.tenant.provisioned`, `f2a.tenant.deprovisioned`, `f2a.sprout.action`; `s2f.refresh`.
- Fields: a **Call** (a request, or an asynchronous f2a result) has the body `{method, subject, params}`; a **Reply** has `{method, subject, result, error, continuity}` and must name its Call's ID in `re`. `OpenCall` refuses a body whose method or subject isn't the one the receiver derived from the subject the message arrived on, and any message with a `re`; `OpenReply` refuses one whose `re`, method or subject differ. `Imas-Principal` is the header naming the sender, never trusted alone: the message's `sid` must equal it and the box must open under that principal's registered key. a2f/f2a messages carry `tid` = `@platform`, outside the tenant ID alphabet, and `sid` = `saasapi`.
- `CheckPublicKey` refuses a low-order X25519 point (one whose shared secret is the same for every private key), at every registration. `Fingerprint` is how a key is shown to a person.

**The users store (Open question 2, answered).** `auth.users.add` wrote farmer's local config file with `jety.WriteConfig` and mirrored the user into `rbac_user_roles`. That is **not** consistent across replicas:

- Each replica has its own file. In the Helm chart it is a read-only ConfigMap mount, so the write fails and `auth.users.add` doesn't work at all.
- With a writable file per replica, each farmer start wipes the tenant's `rbac_user_roles` rows and reloads them from its own file (`rbac.LoadUsersFromConfig`). A user added on one replica disappears when another restarts, and a user **removed** on one comes back: a revocation that doesn't hold.
- A user in the legacy `pubkeys` section is resolved from each replica's in-memory config, so removing one reached only the replica that handled the request.

So registration moved to the farmer database (migration `farmer/00003`): `auth_users`, keyed on `(tenant_id, user_id)`, is the durable record of a user registered through the API, shared by every replica. `AddUser` writes it (and mirrors into the policy's map), never the file; `LoadPolicy` re-applies the rows after the config reload; `RemoveUser` deletes the row and retires the user's CLI box keys in one transaction. The config file's `users`/`pubkeys` stay the out-of-band bootstrap (the first admin), and `RemoveUser` refuses a user defined there (`ErrUserInConfig`): remove them from the file on every replica. The user's tenant is the policy's existing seam (`farmerorganization`); per-request tenants arrive with sealed requests. **Exposure until J.4:** `auth.users.add` now persists on a Helm install too, while it still accepts a bearer token the bus can mint for 15 minutes (SEC.0). Owner decision, 2026-10-04: no stopgap (Stopgap 2 is not taken, Open question 1); the exposure is accepted until J.4 lands, and nothing is deployed.

**CLI box keys.** `auth_cli_box_keys`, keyed on `(tenant_id, user_id)`: the registered public key, its status (`active`, `grace`, `retired`), `created_at`, `rotated_at` and `grace_until`. At most one active key per `(tenant_id, user_id)` (`active_slot`, as for sprouts); `pub` is unique across the table, so no key is ever registered to two principals or reused after retirement. On farmer (`internal/pki` `clibox.go`):

- `RegisterCLIBoxKey` is the admin path (the sealed `auth.users.add` will carry the key at J.4). It refuses a key that is any sprout's box key in any tenant (new index `idx_pki_sprout_box_keys_pub`), the tenant's key or the platform key, and a second key while one is active (replacing is a rotation).
- `OpenFromCLI` opens a request under the user's active key, then each grace key on its own, against every tenant key, and reports which key opened it. A user with no key opens nothing.
- `RecordCLIBoxKeySubmission` applies a `c2f.userkey.pub`: only the active key may change the active key; a grace key may only re-assert it; a superseded key never comes back. The old key keeps opening for 15 minutes.
- `SealToCLI` seals a reply to the user's active key, one copy per tenant key.

On the CLI (`cliboxclient.go`, `cmd/imas/cmd/authbox.go`): `imas auth keygen` writes `cliboxprivfile` (0600, default `~/.config/imas/cli-box.key`) and prints the public key and fingerprint; it refuses to replace a key without `--force`. `imas auth rotate-key` writes a pending key (`<cliboxprivfile>.next`), sends `c2f.userkey.pub` sealed under the current key on `imas.api.auth.rotatekey`, and promotes the pending key only when farmer's sealed reply opens under it; the old private key is then deleted. Until farmer routes the method (J.4) it reports that farmer doesn't serve sealed requests and keeps the pending key. The CLI pins `tenantboxpub` and also `tenantid`, because every sealed message names its tenant.

**The first admin's CLI box key** (owner decision 2026-10-04). The first admin is a config-file user, so their key is too: a `boxpub` field beside their entry in the `users` section (`internal/auth` `bootstrapkeys.go`). Each farmer start imports it into `auth_cli_box_keys` under `(farmerorganization, user)`, but only while that user has no key history at all there. After that the database is authoritative: a config `boxpub` never overwrites a rotated key, never brings back a retired or revoked one, and never adds a second key; a mismatch is logged. The import gets the same checks as an API registration (weak keys, a key any principal holds, a farmer-side key), and a failed import is logged and skipped, never stopping farmer.

**Users are deployment-wide operators** (owner decision 2026-10-04). The imas CLI is for operators only, not end users, so user registration stays under the policy's existing `farmerorganization` tenant; it does not become per tenant.

**Platform key and SaaS API box key (Open question 4, answered).** Generated by a Helm hook Job, `farmer ensure-controlplane-box-keys`, into **OpenBao KV v2**, not a Secret, under the tenant box base path `<base>`: `<base>/platform` (`pub`, `priv`), `<base>/saasapi-box` (`pub`, `priv`), and `<base>/controlplane-pub` (`platform_pub`, `saasapi_box_pub`). The Job has its own ServiceAccount and OpenBao role, which may create and read the keypairs but never update them, so a re-run can't replace a key. Farmer's `imas-farmer-tenantbox` policy gains **read** on `platform` and `controlplane-pub` and nothing on `saasapi-box`. Each private half is readable only by its owner: farmer reads the platform key; the SaaS API's External Secret (step 5) reads `saasapi-box` into a Secret only its pods mount. Pinning: farmer pins `saasapi_box_pub` from `controlplane-pub` (plus the previous version inside a rotation's grace window); the SaaS API pins `platform_pub` from the same secret through its External Secret. Neither is ever fetched over the bus. A continuity proof for the platform key (`f2a.platformkey.continuity`) isn't built: re-pinning on rollout is enough while one team ships both ends. Helpers: `pki.OpenFromSaaSAPI`, `SealReplyToSaaSAPI` and `SealResultToSaaSAPI` on farmer; `pki.SaaSAPIBox` on the SaaS API, which also runs its own replay guard on results.

**Farmer's NATS side (`internal/natsapi` `sealedapi.go`).** In order: the `Imas-Payload` marker (else `encryption-required`); open under the named principal's key, method and subject bound (else `open-failed`); the replica's replay guard on `(tenant_id, principal, message id)`, ±5 minutes (else `open-failed`); and for a mutating method, the Valkey claim `SET NX imas:replay:sealed:<tenant_id>:<principal>:<id>` with a 10-minute TTL (`pki.ClaimSealedMessage`). A claim already taken is `open-failed`. Valkey unreachable refuses the request (`ErrSealedStoreUnavailable`), answered with a sealed error since the request did open. A read-only method never touches Valkey. The replay guard is 64 `payloadbox.ReplayGuard` shards of 16384 entries each, because a guard sweeps its whole map on every accept. **Known limitation, accepted** (owner decision 2026-10-04): there is no per-user rate limit, so a registered user sending more than about 3,500 requests a second to one replica fills its guard and other users' requests are refused until entries age out. Only operators use the CLI, so this isn't needed now.

**The read-only list (Open question 6).** The design's list, unchanged: `health`, `version`, `sprouts.list`, `sprouts.get`, `jobs.list`, `jobs.get`, `jobs.forsprout`, `props.getall`, `props.get`, `cohorts.list`, `cohorts.get`, `cohorts.resolve`, `cohorts.validate`, `pki.list`, `auth.whoami`, `auth.users`, `auth.explain`, `audit.dates`, `audit.query`. I checked each handler: none writes state (`sprouts.get` sends the sprout a liveness probe, which changes nothing). `cohorts.refresh` is mutating, agreed: it rewrites the membership cache and is costly to repeat. `auth.login` is read-only too but isn't on the list; it stays mutating by default, which costs it only a Valkey dependency. `auth.rotatekey` is mutating.

**Decision C (`internal/pki` `refreshsealed.go`).** `SproutSealedRefresh` builds `s2f.refresh` (`{nkey_pub, timestamp}`, sealed with the current box key to the pinned tenant key). `OpenSealedRefresh` looks the sprout up by `nkey_pub`, opens under every retained tenant key back to the last severing rotation against the sprout's valid box keys, checks `nkey_pub` and both timestamps (±5 minutes), and claims the message ID once in Valkey on `(tenant_id, sprout_id, id)`. Every failure is `ErrEnrollmentFailed`. J.2 wires these in and extends them (a pending-key copy, the `ReplyTo` check, a sealed `f2s.refresh` reply): see "As built: J.2".

**Not built in J.1.**

- Wiring: sealed `imas.api.*` (step 4, built in J.3, below), sealed `internal.*` (step 5), sealed `/v1/refresh` on both ends (step 3, built in J.2, below), and removing the token code (done in J.3).
- Turning the keygen Job on by default. `cmd/farmer` dispatches `ensure-controlplane-box-keys` before loading config (owner-approved outside J.1's scope), but `controlPlaneBoxKeys.enabled` stays off until step 5 gives the keys a consumer.
- saasapi's External Secret and mount for its box key and the platform pin (step 5).
- `f2c.tenantkey.continuity` for the CLI (the reply field is reserved).
- Platform key rotation tooling.
- Refusing, at sprout enrollment, a sprout box key that is a registered CLI key (registration already refuses the other way round).

### As built: J.2 (sealed sprout refresh)

**FLAG FOR SECURITY REVIEW.** Rollout step 3, ready for review, not approved. Decision C is wired in on both ends, under the owner decisions of 2026-10-04: sealed only, no NKey-only fallback and no per-sprout ratchet, and a sprout with no box key is refused and re-enrolls.

**The request (`POST /v1/refresh`).** The body is `{nkey_pub, sealed}`, and nothing else: a body with `nkey_sig`, `timestamp`, `join_token` or any other field is refused, so the NKey-signed contract is gone for every sprout. `sealed` is an `s2f.refresh` message (`pki.SproutSealedRefresh`): `tid` the sprout's pinned tenant, `sid` its pinned sprout ID, body `{nkey_pub, timestamp}`, sealed to the pinned tenant key with the sprout's current box key, plus a second copy under its pending key while a box key rotation is in progress. The sprout now pins the sprout ID farmer assigned it (`sprout-id`, beside `tenant-id`), written once at enrollment, because farmer opens a refresh only for the sprout its NKey belongs to, and that ID may carry a collision suffix. Farmer (`pki.RefreshSprout`):

- refuses an envelope of more than two copies before opening anything;
- looks the sprout up by `nkey_pub` among accepted sprouts, giving `(tenant_id, sprout_id)`;
- opens under each retained tenant key, newest first, back to the last severing rotation, against the sprout's active and grace box keys, re-reading the tenant's keys once if the cache is stale. A sprout with no box key on record opens nothing;
- requires a request (no `ReplyTo`) that names that `nkey_pub`, with its timestamp and issue time within ±5 minutes of farmer's clock;
- claims the message ID once cluster-wide (`ClaimSealedMessage` on `(tenant_id, sprout_id, id)`, Valkey, 10-minute TTL, fail closed);
- and only then mints the gateway JWT. Every failure is the generic `enrollment_failed`.

**The reply.** `{sealed}` and nothing else: an `f2s.refresh` Reply (`payloadbox.PurposeRefreshReply`, method `refresh`, subject `POST /v1/refresh`) whose `re` is the request's ID. It is sealed to the sprout's active box key under the tenant key the request opened with, which is the one the sprout has pinned. Its result is the NATS User JWT, the gateway JWT, the tenant ID and key, and the continuity proof after a tenant key rotation. The sprout accepts only the reply that opens under its pinned tenant key, for its tenant and sprout ID, naming the request it just sent. So nothing in the HTTP exchange, at Envoy or anywhere else in the DMZ, carries a gateway JWT in the clear, and an old reply can't answer a new request.

- **Box key rotation during a refresh.** Farmer seals the reply to the active key only, as it seals everything, so a reply that opens under the sprout's pending key promotes it. A sprout whose old key has left farmer's grace window before it heard from farmer still refreshes: its pending-key copy opens.
- **Tenant pin.** A pin older than the grace window still refreshes: farmer opens under the retained key and the continuity proof inside re-pins. After a severing rotation farmer holds no key the sprout pinned, so it can't open the request, and nothing it could answer would be authenticated. The refusal is unauthenticated, so it is an ordinary, retried error, not a fatal one.
- **Fatal on the sprout** (it must be re-enrolled): no box key, no tenant key, tenant ID or sprout ID pin, and a sealed reply naming another tenant key without continuity, or another tenant or sprout ID.
- **Expired gateway JWT.** The sealed refresh needs none. After one, the next websocket handshake (`GatewayJWTHeaders`, called on every nats.go reconnect) presents the new token, so the jittered reconnect loop recovers.

**Enrollment: a gateway JWT only for a box key proof.** Decision C first said enrollment was unchanged. That was wrong (see Decision C): the replay path never checks the join token, so an `EnrollSigningPayload` signed over a `CONNECT` nonce, with any token, replayed an enrolled sprout's identity with a fresh gateway JWT. `pki.Enroll` now mints a gateway JWT only on the request carrying a verified `sprout_pub_proof` (step 2 of a first enrollment), and claims that proof's message ID once cluster-wide, so a proof copied from an earlier request can't earn another. A request with only the NKey proof, on either path (step 1, or a retry of it), gets the identity, the User JWT, the tenant and its key, and no gateway JWT. The sprout never used step 1's. Step 2's gateway JWT travels plaintext inside TLS, as designed.

**Tests.** The SEC.0 fake-bus capture, extended to the sprout's real connect path (`pki.LoadSproutBus`): a `CONNECT` signature over a refresh-shaped nonce authorises no refresh in any form, and one over an enrollment-shaped nonce earns no gateway JWT. Both fail on `main` before J.2. The through-real-Envoy suites run on Envoy v1.35.3, including a nats.go reconnect loop refused by `jwt_authn` with an expired token that recovers after a sealed refresh through Envoy.

**Owner decisions, 2026-10-04 (PR #94).**

- **Severing rotation: "let the sprout re-enroll."** Read narrowly: the behaviour above is accepted. A sprout cut off by a severing rotation gets a retried refusal and stays cut off until an operator re-enrolls it. It does not detect the state, stop, or re-enroll itself. That would need a credential it doesn't hold: the join token is deleted after enrollment, and any unauthenticated signal it acted on (a refusal, a key named in an unsealed answer) would also let whoever sits in the DMZ trigger it.
- **The gateway JWT in step 2's enrollment response stays plaintext inside TLS**, as designed. No sealing.
- **`f2s.refresh` lives in `internal/payloadbox`'s purpose list** (`PurposeRefreshReply`), beside `s2f.refresh`.

**Not changed in J.2.** `ansible/molecule/stubfarmer` still speaks the old refresh contract (its 24-hour tokens mean a molecule run never refreshes), and `pki.RefreshSigningPayload` remains, unused by farmer, so it builds and the regression tests can build the refused proof.

### As built: J.3 (sealed CLI ↔ farmer, Decision A)

**FLAG FOR SECURITY REVIEW.** Rollout step 4, sealed only, as the owner decided on 2026-10-04: no bearer tokens, no plaintext fallback, no `apiallowbearertoken` flag and no per-user ratchet.

**Tokens are gone.** `auth.NewToken`, `createSignedToken`, `UserAuth` (sign, `IsValid`, the SEC.0 expiry cap and `apitokenclockskew`), `decodeToken`, every `Token*` check and `WhoAmI(token)` are deleted from `internal/auth`; `injectToken` from the client. The CLI's NKey signs the bus `CONNECT` nonce and nothing else (`auth.Sign`). Nothing in the repository turns an NKey signature into a credential, so a signature the bus collects at `CONNECT` (the SEC.0 attack, nonce `2099-01-01T00:00:00Z`) is worth nothing: `TestForgedTokenRegression` (`internal/natsapi`) presents it as the old plaintext token, inside a box the bus sealed under its own key labelled as the admin, and as a raw body, and each is refused; a captured genuine admin request replayed to the same replica or another is refused too. Farmer's checks are now `UserHasAction`, `UserHasScopedAccess`, `UserScopeFilter` and `UserIdentity`, all on a user ID.

**The router (`internal/natsapi` `sealedrouter.go`).** Every `imas.api.<method>` queue subscription goes through `sealedAPI.serve`, the one place that:

1. opens the request (`openCLIRequest`: marker, `Imas-Principal`, the box under that user's registered CLI box key in the connection's tenant, method and subject bound, the replica's replay guard, and the Valkey claim for a mutating method);
2. builds the caller, `apiCaller{TenantID, UserID}`, from what opened it. Handlers get the caller and the opened params; nothing in the params names the caller;
3. authorizes (`authorize`): the role's action for the method, looked up by the verified user, then `checkScopedAccess` on the method's targets. A request whose targets can't be read is refused (until J.3 it went to the handler, which might read them more leniently than the scope check did). The self methods (`health`, `version`, `auth.login`, `auth.whoami`, `auth.explain`, `auth.rotatekey`) need only to open. `dangerously_allow_root` has no effect here: the owner removed its bypass from the NATS path (2026-10-04, PR #95: "remove dangerously_allow_root bypass from the NATS path");
4. runs the handler, audits the call as the verified user (`audit.Entry` with the user's key, role and username, the method's targets, and a write's params), and seals the reply (`f2c.api`, `re` = the request's ID, one copy per tenant key, to the user's active key).

A request that doesn't open gets the fixed `Imas-Payload-Error` code and an empty body; the reason stays in farmer's log. A mutating request that opened while Valkey is down gets a sealed `ErrSealedStoreUnavailable`. A reply that can't be sealed (the user's key was revoked between open and reply, or the tenant keys are unreadable) gets the `internal` code, never plaintext. Unsealed `health` and `version` are still answered in plaintext, for monitoring, with no identity.

**The CLI (`internal/api/client` `nats.go`).** `NatsRequest` (and `SealedRequest`, for another connection or purpose) seals with `pki.CLISealRequest` and accepts only a reply with the `Imas-Payload: box1` marker that `pki.CLIOpenReply` opens under the CLI's key and that names this request's ID, method and subject. A plaintext reply is `ErrPlaintextReply`, a sealed one that doesn't open or answers another request `ErrReplyDidNotOpen`, a refusal a `RefusedError` with its code. `imas serve` goes through `NatsRequest`, so its API proxy is sealed too. `imas auth token` is removed. The auth commands connect on demand (root's pre-run skips them).

**Users and keys (`auth.users.*` on the J.1 key store).**

- `auth.users.add` takes `{pubkey, role, username?, boxpub}`; `boxpub` is required. The user row and their first CLI box key are written in one transaction, after the cross-principal check (no sprout's, tenant's or platform key; the CLI key table's own unique index). `imas users add <role> <pubkey> --boxpub <key> [--username <name>]`.
- `auth.users.resetkey` (new, admin): retires every key the user holds in the users tenant and makes the given one their only key, in one transaction: a lost or stolen key, or a config-file user who has none. A retired key never comes back. `imas users reset-key <pubkey> --boxpub <key>`. An admin can so act under any user's identity, including another admin's, but that is within an admin's existing power; owner decision, 2026-10-04 (PR #95): "lets keep it since it is admin only".
- `auth.users.remove` retires the user's keys with the row (J.1), so their next request opens nothing.
- `auth.users` also returns each user's active key fingerprint (`box_keys`), shown by `imas users list`.
- `auth.rotatekey` is routed: `c2f.userkey.pub` through the same path, recorded by `pki.RecordCLIBoxKeySubmission`; the reply is sealed to the new active key, so the CLI promotes its pending key only once farmer recorded it.
- Users and their keys live in the users tenant (`farmerorganization`, owner decision 2026-10-04), so CLI requests open only on that tenant's connection, which is the one the CLI's bus account lands on.

**The first admin without a bus token.** Farmer's config file names them: `users.admin: [{pubkey, username, boxpub}]`, imported once at start (J.1's `bootstrapkeys.go`). The Helm chart renders it from `farmer.bootstrapAdmin.{pubkey,boxpub,username}` and refuses to render `farmer.adminPubKeys` (an admin with no box key can't make a request). `users.admin` now means the built-in admin role whenever the config defines no role of that name: the check this replaced only ran when no role at all was defined, which never happened (the viewer and operator roles are always registered), so a config-file admin had no role. The CLI pins `tenantid` and `tenantboxpub`, never fetched over the bus: farmer logs both, with the key's fingerprint, when it subscribes for the users tenant (which also creates the tenant keypair if there is none yet), and they are in OpenBao at `<mount>/<base>/tenants/<tenant_id>` (`pub`). `docs/INSTALL.md` has the steps.

**Deviations from the design text above.**

- **The cook trigger** is `imas.api.cook.trigger.<jid>`, not `imas.api.cook.trigger` with the JID in the params. Only the replica that created the job holds it, and only that replica subscribes to the trigger, outside the queue group, for the existing 15 seconds; a queue-grouped subject would land on any replica. The JID is still bound inside the box (it is in the method and subject). It is sealed, mutating, needs `cook`, and is accepted once and only from the user who created the job; a refused trigger doesn't use the job up. `internal.sprout.action`'s cook no longer triggers itself over the bus: farmer holds it on the replica and starts it directly (`prepareSaaSAPICook`, `triggerLocalCook`). This deviation is accepted: owner decision, 2026-10-04 (PR #95), "yes fine".
- **Recipe browsing moved back onto the bus** as sealed `recipes.list` and `recipes.get`. It was farmer's HTTPS API (`GET /v1/recipes`) behind the CLI's bearer token; with tokens gone the CLI had no credential for it, and P4 (one mechanism) argues against inventing an HTTP one. Same keys as before: the platform tree only. `recipes.get` returns at most 256 KiB, so its sealed reply fits the bus's default payload limit. `cmd/farmer` installs the store with `natsapi.SetRecipeStore`.
- **Farmer's HTTP API accepts no CLI credential.** `internal/api` `Auth` lost its token branch: `/files/` takes a gateway JWT only, and `ListRecipes`/`GetRecipe` refuse every request, unless `dangerously_allow_root` is set, which (unchanged, dev only) skips authentication on all three (removing the recipe routes is a follow-up). After J.3 that HTTP bypass is all the flag does. `cmd/farmer` no longer installs a token resolver for the audit log; `internal.*` audit entries carry no identity, as before (they never had a token).

**Read-only list (open question 6): the design's 19, plus `recipes.list` and `recipes.get`.** Owner decision, 2026-10-04 (PR #95): "yes make it readonly". So the recipe reads take no Valkey claim and work with Valkey down. The other new methods, the cook trigger, `auth.users.resetkey` and `auth.rotatekey`, are mutating by default and claimed in Valkey.

**Tests.** `internal/natsapi`: `sealedrouter_test.go` (the verified user end to end; plaintext only for monitoring; the forged-token regression; wrong user, wrong key, a method not granted, a revoked key; replay on two replicas sharing Valkey, run once; Valkey down; `auth.users.*` with the key store including reset and removal; rotation through the router; audit identity), `middleware_test.go` (`authorize`), the cook trigger in `integration_test.go` (plaintext refused, another user refused, the creator accepted). `internal/api/client`: plaintext, replayed, moved and impostor-sealed replies are refused; nothing readable or token-like on the wire. `cmd/imas/cmd` `sealed_e2e_test.go`: the CLI's own commands against an embedded farmer and a nats-server that authenticates NKey users over TLS, with the first admin bootstrapped from farmer's config. Client-side tests stub farmer with `internal/api/client/clienttest`, a sealed stand-in.

**Not built in J.3.**

- `f2c.tenantkey.continuity`: after a tenant key rotation the CLI must re-pin `tenantboxpub` by hand (from OpenBao, or farmer's log at its next start). Until the grace window ends the old pin still works; after it, requests fail closed with `open-failed`.
- Decision D (the plaintext reads above) and J.5 (shell sessions).
- Removing farmer's HTTP `ListRecipes`/`GetRecipe` routes (and their stale comments) and `internal/audit`'s unused token resolver (`SetIdentityResolver`, `extractIdentity`), and sending `boxpub` from `imas serve`'s OpenAPI document and the web UI's add-user form, which fails until then. Owner decision, 2026-10-04 (PR #95): "leave the cleanup for a later PR".
- A per-user rate limit on the replay guard (J.1's accepted limitation).
