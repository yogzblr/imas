# Hardening units from the owner's decisions of 2026-10-18 (U1 to U4)

Read `docs/briefs/ORCHESTRATOR.md` first: its session prompt (zero open items,
repo-wide search, brief errors decided by a fixed order) applies to every unit.
Sources: `docs/security-review-2026-10.md` (L9, L15, L22, L23, L24, I6),
`docs/design/imas-payload-encryption-design.md` Decision 6 (facts and cook step
events) and the owner's answers below. Line numbers in the reviews have drifted:
find each place by name, and check on main that the finding still holds before
fixing it. A finding that no longer holds gets a test that pins the good
behaviour and a line under "Brief corrections".

Order: U1 first. U2 and U3 then run at the same time (U2 touches enrolment and
the join token, U3 touches facts, cook step events and their readers; if both
need one file, the later PR rebases). U4 last, because it adds chart values
that U2 and U3 also touch.

Owner decisions (2026-10-18, final):

- **U1.** All of L9, L15, L22, L23 and I6 are fixed as the review recommends,
  with the choices in the U1 section.
- **U2.** L24 is fixed by pre-provisioning the tenant key fingerprint in the
  join token (not by a farmer-signed response).
- **U3.** Cook step events and facts are sealed, as Decision 6 of the payload
  encryption design says. `test.ping` and the sprout's join event stay
  plaintext (owner: no need to seal them). Not in this unit and left as they
  are: `cancel` (no sprout handles it), the `boxkey.rotate` trigger, log
  shipping, the plaintext `health` and `version` answers. Do not touch them.
- **U4.** Every setting that decides how long data is kept is configurable in
  the charts, with the default below, and documented. The tenant purge delay
  (`SAASAPI_TENANT_PURGE_AFTER`, 720h) stays as it is; it is the model for the
  others.
- The repository keeps its "fork" naming (`docs/design/imas-fork-roadmap.md`
  stays).

## U1: bus fence, key chain, proofs, CLI keys, cmd.run output (L9, L15, L22, L23, I6)

Scope: `cmd/farmerbus` (fence), `internal/pki` (`tenantbox.go`, `sproutbox.go`,
`jwtusers.go`), `internal/natsapi/sprout_action.go`,
`internal/saasapi/sprout_actions.go`, charts and docs as needed.

- **L9.** On the `cmd.run` result subject farmer leaves `Stdout` and `Stderr`
  empty (saasapi reads only the exit code), and the sprout does not need to
  send them to farmer in the first place if the sealed result can carry them
  only to the CLI path that wants them: keep the sealed CLI path as it is. The
  tests that pin the old behaviour change with the fix. Payload size no longer
  matters for this subject; say so in the docs.
- **L15.** The fence counts only peers that are in the configured `Routes`, and
  it fences (stops serving) when a routed peer reports a different cluster size
  than its own. Test: a partitioned old pod with one new pod during a 3 to 5
  scale-up does not keep serving. Document the rollout order for a resize
  (grow the config on all pods in one rollout; a mixed set fences, by design).
- **L22.** The sever boundary is recorded in the current version's data and in
  KV `custom_metadata`, where deleting an older version cannot erase it; and a
  gap in the version chain stops the continuity walk (fails closed) instead of
  skipping. The test that pins the current behaviour (`tenantbox_test.go`)
  changes with this.
- **L23.** A continuity proof is accepted only when its `IssuedAt` is inside
  the skew window used by the other sealed s2f messages (±5 minutes) and it
  passes the replay guard. Fix the comment that says the proof carries no
  `IssuedAt`. Test an old K1 to K2 proof replayed after K2 was severed.
- **I6.** Removing a CLI admin key revokes it (its NKey is rejected and the
  Account is re-signed), with a test.

## U2: tenant key fingerprint in the join token (L24)

Scope: `internal/pki` enrolment (server side, `enrollclient.go`), the join-token
format and everything that creates or prints one (`internal/saasapi`, the imas
CLI, the web UI if it shows tokens), `cmd/sprout`, `ansible/roles/imas_sprout`,
`uat/enroll` and the other UAT scripts that enrol sprouts, `docs/`.

- A join token carries the SHA-256 fingerprint of the tenant box public key
  (`tenant_pub`), added in a way that older tokens still parse. Farmer puts the
  fingerprint in every token it issues (CLI, API, web UI, UAT scripts).
- The sprout compares the `tenant_pub` that enrolment returns with the
  fingerprint from its token **before** it pins anything, and refuses a mismatch
  with a distinct, documented error. A compromised Envoy that substitutes its
  own key at enrolment is therefore detected.
- A token without a fingerprint is refused by default (sprout setting
  `enrollpinrequired`, default true; Ansible role variable and package default
  match). Setting it false is possible and logs a warning at every enrolment.
- Tenant key rotation: a token is for a first enrolment only, so rotation is
  unaffected (the continuity proof carries later keys). Say so in the docs.
- Update every script, role, test and doc that creates a token or enrols a
  sprout so that the UAT suite and the rig still enrol (grep for the token
  creation calls and the enrol commands).

## U3: seal cook step events and facts (P6)

Scope: `internal/cook`, `internal/jobs`, `internal/serve/logstream.go`,
`internal/facts`, `cmd/sprout` (`factsloop.go`, `nats.go`), `cmd/imas`
(`cook.go`, `jobs.go`), `internal/pki` (`payloadbox` purposes), `internal/natsapi`,
`tools/loadtest`, `ansible/molecule/stubfarmer`, docs including the payload
encryption design and the sealing table in `docs/BUILD-STATUS.md` (through a
status fragment).

Follow the existing pattern (`payloadbox` purposes, `SealToFarmer`/`openAsSprout`
style helpers, pinned tenant and sprout IDs, a ±5 minute timestamp window, the
replay guard where a message can change state) and Decision 6 of the design.

- **Facts.** The sprout seals each facts message to farmer with a new purpose
  `s2f.facts` on `imas.sprouts.<id>.facts`. Farmer's facts listener opens it
  under the sprout's active and grace box keys, checks the pinned tenant and
  sprout IDs and the timestamp window, and refuses a plaintext facts message
  from every sprout (no plaintext fallback, as for `cmd.run` and `cook`). A
  sprout with no active box key waits and sends its facts as soon as it has one.
  Forged, stale, wrong-sprout, wrong-tenant and plaintext facts are refused
  without changing the stored facts: one test each, plus the fact-based cohort
  case from the design (a forged fact cannot move a sprout into a cohort).
- **Cook step events.** The sprout seals each step event (new purpose,
  `s2f.cook.step`) on `imas.cook.<id>.<jid>`. Farmer's job listeners open them,
  check tenant, sprout, job ID and the window, and refuse plaintext. Readers that
  hold no tenant key (the CLI and `imas serve` in `internal/serve/logstream.go`)
  get events from farmer over a sealed leg (farmer to CLI), built on the sealed
  CLI-to-farmer channel that already exists; the CLI opens only what is sealed to
  its pinned key and addressed to its request. Forged and reordered events cannot
  change a job record: test a forged "step succeeded" and a skipped step.
- **Compatibility.** Farmer and CLI upgrade together centrally; a sprout that
  cannot seal (older build) stops being able to report facts and step events,
  and the docs say what the operator sees (a clear "sprout needs an upgrade"
  state, not a silent gap). `test.ping`, the join event, `cancel`, the
  `boxkey.rotate` trigger and log shipping stay as they are.
- **Cost.** Facts are sent every interval for every sprout: measure with the
  load test and write the per-message overhead in the PR (sealing a few KiB).
  If facts exceed the bus payload limit when sealed, compress before sealing and
  say so.

## U4: retention is configurable in the charts

Scope: `deploy/helm/farmer` (and the other charts that keep data), `internal/config`,
`internal/saasapi`, `docs/`.

First make the inventory: every place where data is kept for a time or for ever.
Include at least the recipe audit objects (`tenants/<id>/recipe-audit/`), job
records and step events, staged recipe copies, completed and failed action
rows (`asset_action_items`), provisioning and purge job rows, expired
registration keys and join tokens, sprout box-key history, heartbeat and replay
keys in Valkey, and the service and audit logs shipped to the object store.
Put the inventory in the PR and in `docs/` as a table (what, where, default,
setting). For each item:

- If a setting already exists, expose it in the chart (a values key, the
  environment variable, README row) if it is not exposed yet.
- If there is no setting, add one. The default is today's behaviour, except
  these, which are the owner's chosen defaults: service and audit logs 30 days
  (Fluent Bit output and the bucket lifecycle rule), recipe audit objects 365
  days (a bucket lifecycle rule or an in-process sweep; `0` keeps them for
  ever), tenant purge 720h (unchanged).
- A value is validated (bounds, Go duration or days as the neighbours do), a bad
  value stops startup with a message naming the key, and `0` or empty means the
  documented default, never "delete at once".
- Terminal rows in the SaaS database (finished actions, finished jobs) are
  removed after a configurable age (default 90 days) by the existing outbox
  sweeper, batched and rate limited so it cannot lock the table; tests with a
  large table.
- Tests render the chart with each retention value set and unset; the
  environment variable reaches the pod; a lifecycle or sweep test proves an
  expired object or row is removed and a younger one is kept.
