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

**Wire format (`internal/payloadbox`).** A sealed payload is a JSON envelope `{"v":1,"s":[{"n":nonce,"c":box}, …]}` sent with the NATS header `Imas-Payload: box1`. Each copy is `box.Seal` of the same inner message under one key pair, with a fresh 24-byte nonce. More than one copy is sent only during a tenant key rotation's grace window, one per tenant key in use. The receiver tries every copy against every key pair it holds, so no key identifier goes on the wire. The inner message is `{v, p (purpose), sid (sprout_id), id (128 random bits), re (request id, replies only), iat, b (body)}`. Plain `box` doesn't give the following, so this layer adds them:
- **Purpose binding.** `box`'s shared key is the same in both directions, so without this a bus could reflect farmer's command back at farmer as the sprout's "reply", or a sprout's reply back at the sprout as a "command". Purposes carry the direction (`f2s.cmd.run`, `s2f.cmd.run`, `f2s.cook`, `s2f.cook`, `f2s.cook.nudge`, `s2f.cook.nudge`, `f2s.fleetsigning`, `s2f.boxkey.pub`, `f2s.tenantkey.continuity`), and a receiver only accepts the purpose it expects. Each boundary has its own pair, so a message sealed for one is refused on any other.
- **Replay and freshness.** The sprout accepts each message ID once, and only within ±5 minutes of its own clock. Farmer accepts a reply only if its `re` is the ID of the request it just sent.
- **Refusals.** A refusal comes back with an `Imas-Payload-Error` header carrying a fixed code (`open-failed`, `encryption-required`, `no-keys`, `internal`), never error text.

**One keypair per tenant, and migration from one per deployment.** Each tenant's keypair is its own OpenBao KV v2 secret, `<base>/tenants/<tenant_id>`, where `<base>` is `IMAS_TENANTBOX_OPENBAO_KV_PATH`. The KV version history is the tenant's key history. The one keypair per deployment that J first shipped is still at `<base>` and is only read, never written. Sprouts pin the tenant key and exit on a mismatch, so switching every tenant to a fresh key would strand every sprout already enrolled. Instead, the first time a tenant's secret is needed, it adopts the legacy keypair (`origin: adopted-legacy`) if the tenant already has sprout box keys on record, and gets a fresh keypair otherwise. Enrollment reads the tenant key before recording the enrolling sprout's box key, so a brand new tenant's first sprout never triggers adoption. An adopted tenant still shares its private key with the other adopted tenants until its first rotation. The legacy secret can be deleted once no tenant has `origin: adopted-legacy` as its current version.

**Rotation (the forward-secrecy mitigation) and how sprouts follow it.** `imas keys rotate-tenant-key` (NATS `pki.rotatetenantbox`) writes a new version with check-and-set on the version it read. A sprout can't simply accept whatever key farmer names: that is exactly what its pin exists to prevent. So `/v1/refresh` and `/v1/enroll` return `tenant_x25519_continuity`, a message whose body names the new public key. It is sealed to the sprout's box key once under each retained earlier tenant key, going back to the last severing rotation, or 8 versions at most. A sprout pinned to one of those keys opens its copy with that key. Only the holder of the corresponding private key (or the sprout itself) could have sealed it, so the sprout re-pins to exactly the key named. Anything else is still `ErrTenantKeyMismatch`. During the grace window, `max(boxkeygraceduration, gatewayjwtttl)`, the previous key also keeps sealing and opening payloads, so any online sprout re-pins on its next refresh before the window closes, with no gap. `--sever` (suspected exposure) writes a version with no grace window and no proofs, so continuity from the exposed key is cut: the tenant's sprouts fail their next pin check and must be re-enrolled. Deleting a version in OpenBao retires it the same way. This follows the design's rule that rotation carries no private key material. The proof carries only a public key, sealed under a key the sprout already trusts.

**Sprout box keys over the bus.** `imas.sprouts.<id>.boxkey.pub` only accepts a submission sealed (`s2f.boxkey.pub`) under one of the sprout's currently valid box keys, within ±5 minutes, and a superseded key never becomes active again. As first shipped, it accepted a plaintext key from anything able to publish there. A compromised bus could then have swapped in its own key and read everything farmer sealed for that sprout afterwards. The sprout-side submitter isn't built yet.

**Boundaries sealed so far.** `cmd.run` in both directions (`internal/ingredients/cmd/sealed.go`); `cook` in both directions, meaning the recipe dispatch on `imas.sprouts.<id>.cook` and its Ack, plus the resync nudge on `imas.sprouts.<id>.recipe.nudge` and its Ack (`internal/cook/sealed.go`); the `fleetsigningkeys` reply (`internal/fleetkeys`); and box key submissions. On `cmd.run` and `cook`, farmer seals for every sprout that has a box key on record, and falls back to plaintext only for a sprout with none, i.e. one enrolled before J, with a warning. Any other failure to seal fails the request rather than sending plaintext. A sprout with keys refuses a plaintext `cmd.run`, cook dispatch or nudge (`encryption-required`). Farmer refuses a plaintext reply to a sealed request, and a sealed one whose `re` isn't the request it just sent. Live `cmd.run` output streaming (`stream_topic`) is dropped from sealed requests, because it publishes in plaintext to a subject the CLI reads without a tenant key.

**Cook job records.** Farmer's job store used to record a job's creation (placeholder steps, `invoked_by`, the status index's step count and dispatch time) by queue-subscribing to `imas.sprouts.*.cook` and reading the plaintext envelope. That subject now carries only ciphertext, so the replica that dispatches a job records it directly (`cook.SetDispatchRecorder`, installed by `internal/jobs`), after the request is sealed and before it is sent. A dispatch that can't be sealed is neither sent nor recorded.

**Still plaintext inside TLS:** cook's step events (`imas.cook.<id>.<jid>`), which the imas CLI reads directly without a tenant key, and every other boundary listed in `docs/BUILD-STATUS.md`.
