# Security review of the flagged work, 2026-10

**FLAG FOR SECURITY REVIEW.** This is a read-only code review, written as
input to the human security review that `docs/BUILD-STATUS.md` (Open items,
item 4) asks for. It does not replace that review. It is also not a clean
bill of health: it records 4 High, 8 Medium and 25 Low findings, and the
work stays "ready for review", not "done" or "safe to merge".

Reviewed on `main` at `eacdc79` (PR #80), 2026-10-04. No code was changed.

## How this was done, and what it does not prove

- **Five passes, one per area.** Each pass read the code paths for one area
  end to end and answered the same seven questions:
  - what is trusted;
  - what a compromised bus can do;
  - what a hostile tenant can do;
  - what a malicious update repository can do (a sprout installs from the
    repository configured in it, never from an imas URL);
  - whether every map, table, index and cache is keyed on `tenant_id` and
    `sprout_id` together;
  - whether secrets can reach logs, errors or job results;
  - where a failure opens instead of closing.
- **The areas, in the order requested:**
  1. FU.0, FU.2, FU.3, FU.4 (manifest signing, the shipped keyring, the
     sprout install path).
  2. FU.6, FU.6b, FU.7, CL.3 (dispatch, rollout gates, re-verification,
     resume).
  3. CL.1 (enrollment), with PKI.1 and SCALE.2 (both merged).
  4. CL.2a, CL.2b (OpenBao client, proxy, redirects).
  5. The J follow-ups (sealed `cmd.run` and `cook`, tenant key rotation,
     box key submissions).
- **How findings were checked.** Every High and Medium finding was checked
  again against the source by a second reader before it was written here.
  For third-party behaviour, the module source was read too: `log-nats`
  v2.1.2, `log-mux` v1.2.0 and `openbao/api/v2` v2.7.1.
- **Not done.** No exploit was run, nothing was deployed, and no test was
  added.
- **What the marks mean.**
  - **CONFIRMED**: the code path was traced from the attacker's input to the
    effect.
  - **UNCONFIRMED**: some link depends on behaviour that was not verified
    (upstream internals, operator action, deployment shape). The finding
    says which link.
- **Line numbers** are at `eacdc79`.
- **Gaps BUILD-STATUS already records** are not repeated as findings. They
  are only ranked, in "Known gaps, ranked" at the end.

## Summary

| ID | Sev | Area | Finding | Mark |
|---|---|---|---|---|
| H1 | High | CL.1 / J | A deleted or replaced sprout keeps a valid bus credential, and a reused `sprout_id` can seal the new host's commands to the old host's key | CONFIRMED |
| H2 | High | FU.6 / FU.6b | Farmer stores facts under the `sprout_id` in the message body, so any sprout can forge another sprout's `sprout_version` (passing the rollout gate) and its props (which are templated into that sprout's recipes) | CONFIRMED |
| H3 | High | J | Sealed messages don't bind the tenant; tenants on the adopted legacy keypair share a private key, so a compromised bus plus one hostile tenant can run commands on another tenant's sprout | CONFIRMED (code path); exposure depends on adopted-legacy tenants existing |
| H4 | High | J | The sprout logs every opened cook envelope at Trace, and log shipping publishes every level on the bus in plaintext | CONFIRMED |
| M1 | Medium | FU.0 / FU.2 | The manifest's version is not bound to the package's bytes: a signed checksum can name an older genuine `.deb` (or any package in the repo), and `dpkg -i` downgrades | CONFIRMED (deb); zypper UNCONFIRMED |
| M2 | Medium | J | After a sprout restarts, any sealed `cmd.run` or `cook` from the last 5 minutes can be replayed | CONFIRMED |
| M3 | Medium | J | A box key submission sealed under a superseded (grace) key is accepted, so a leaked old key takes over the sprout's sealed channel | CONFIRMED |
| M4 | Medium | CL.1 | Sprout IDs may contain dots, so sprout `web01`'s grants cover `web01.example.com`'s subjects | CONFIRMED |
| M5 | Medium | FU.6 / CL.3 | One tenant can fill the shared 64-slot dispatch pools in saasapi and farmer and starve every tenant's actions and rollout waves | CONFIRMED |
| M6 | Medium | SCALE.2 | Account JWTs re-signed in the same second tie on `iat`; the fence breaks the tie by string order, so a stale JWT can overwrite a newer one cluster-wide | CONFIRMED in code; upstream ordering per repo comments |
| M7 | Medium | CL.2a | The server-side OpenBao wrapper copies a non-JSON response body into errors, and `pki.rotatetenantbox` returns that text to the tenant | CONFIRMED; needs an intermediary that echoes requests |
| M8 | Medium | outside scope | Recipe templates can call `env`, which reads farmer's environment (`IMAS_PXC_DSN`, S3 keys) into the rendered recipe | CONFIRMED; severity depends on who may write recipes |
| L1–L25 | Low | all | See "Low" below | |
| I1–I12 | Info | all | See "Info" below | |

**Before `SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED` is turned on**, this
review recommends fixing:

- H2, because the health gate trusts forgeable facts;
- M1, because downgrade protection is bypassable on deb;
- L1, because farmer has no switch of its own;
- L8, because a live rollout keeps going for a deleted tenant;
- M5, because rollout waves share the starvable pool;

and deciding on L4 (revocation is not enforced on the sprout). H1, H3 and H4
are not specific to fleet updates. They weaken the sealing that the update
path also relies on, so they belong ahead of the general release.

## High

### H1. A deleted or replaced sprout keeps a valid bus credential, and its box key stays active (CL.1, J)

- **Where:**
  - `internal/pki/pki.go:177-195`: `DeleteNKey` deletes only the
    `pki_nkeys` row. `AcceptNKey` calls it on the replace path
    (`pki.go:159-162`).
  - `internal/pki/jwtusers.go:211-224` and `internal/pki/tenant.go:715-725`:
    revocations are rebuilt only from rows in `unaccepted`, `denied` or
    `rejected`. A deleted row is never revoked.
  - `jwtusers.go:142-146`: User JWTs carry no `exp`.
  - Nothing deletes or demotes `pki_sprout_box_keys` rows (only
    `boxkeys.go` writes them, and only on rotation).
    `upsertSproutBoxKeyActive` (`boxkeys.go:106-116`) adds a second active
    row without graceing the first.
  - `ValidSproutBoxKeys` (`boxkeys.go:201-214`) keeps whichever active row
    the query returns last; there is no `ORDER BY`.
  - `resolveEnrollSproutID` (`enroll.go:570-571`) hands a freed id
    straight back.
- **Scenario:** A tenant deletes compromised host `web` (`pki.delete`).
  - The old host's User JWT is still valid and is never revoked, so it can
    stay connected, or reconnect through any valid gateway JWT. Envoy's
    gate is not bound to the NATS identity.
  - A rebuilt host enrols and gets `web` again. Now two active box-key rows
    exist for `(T, web)`. If the old one is read last, farmer seals every
    `cmd.run` and `cook` to the old host. The old host receives them
    through its `imas.sprouts.web.>` grant, opens them, and its sealed
    replies are accepted.
  - On the `pki.accept` replace path (`web_1` becomes `web`) this is
    deterministic: the only active box key for `web` is the old host's.
- **Fix:**
  - In `DeleteNKey` and on the replace path, record a revocation for the
    removed NKey in a per-tenant revoked-keys list. A revocation set
    derived from rows cannot remember deleted rows.
  - In the same transaction, revoke every `pki_sprout_box_keys` row for
    `(tenant, sprout)`.
  - Make `upsertSproutBoxKeyActive` demote other active rows.
  - Add a unique "one active key per `(tenant_id, sprout_id)`" constraint,
    and make `ValidSproutBoxKeys` fail closed if more than one row is
    active.
- **Mark:** CONFIRMED for the missing revocation and the two active rows.
  Which active row wins depends on database row order, which was not
  checked.

### H2. Facts are stored under the body's `sprout_id`, not the subject's (FU.6, FU.6b)

- **Where:**
  - `internal/facts/listener.go:49`: farmer subscribes to
    `imas.sprouts.*.facts`.
  - `listener.go:59,71`: the subject is never read; facts are stored under
    `sf.SproutID` from the body, which is not even validated with
    `IsValidSproutID`.
  - A sprout may publish only on its own subject
    (`internal/pki/jwtusers.go:46`), but the body overrides that. Compare
    the jobs listener, which takes the sprout from the subject
    (`internal/jobs/listener.go:177`).
  - saasapi takes `expiry - TTL` as a fact's write time
    (`internal/saasapi/fleet_sprout_facts.go:168-173`), so a forged row
    counts as fresh for the gate (`fleet_update_dispatch.go:1090`).
- **Scenario 1 (rollout gate):** Sprout A, compromised or simply hostile
  within its tenant, publishes on its own subject
  `{"sprout_id":"B","sprout_version":"<target>"}` for every sprout in the
  current wave.
  - Each item "succeeds" without its sprout ever coming back, and later
    waves go out. A bad release reaches the whole selection instead of
    halting after wave 1.
  - The reverse also works: A reports a higher version for B, or an unknown
    OS or arch, and B is refused at planning.
- **Scenario 2 (recipe injection into a neighbour):** Recipes are rendered
  on farmer with B's props (`internal/cook/farmercook.go:62-65`: `props`
  and `hostname`) through `text/template`, before YAML parsing
  (`internal/cook/helpers.go:441-452`).
  - A forged `hostname` or prop for B that contains a newline and YAML
    becomes recipe structure in B's next cook. That means extra steps, for
    example `cmd.run`, executed on B.
  - This works against any recipe that interpolates `hostname` or `props`.
  - Dynamic cohorts read the same props (`internal/rbac/cohort.go:429`), so
    A can also move B into or out of an RBAC cohort.
- **Second writer:** `props.set` (`internal/natsapi/props.go:48-60`) lets a
  CLI user with the `props` action write `sprout_version`, `os` or `arch`
  directly. Those names are not reserved.
- **Fix:**
  - Take the sprout id from subject token 2, drop a message whose body id
    differs, and validate the id.
  - Reserve the fact names (`os`, `arch`, `sprout_version`, `hostname`,
    `ip_addresses`, the hardware keys) in `props.set` and `props.delete`,
    or record a source column and have saasapi read only facts the sprout
    itself wrote.
  - Separately, stop splicing prop values into recipe text before YAML
    parsing. Quote or escape them, or pass them as data.
- **Mark:** CONFIRMED from the JWT grant through to item success, and into
  the template. Whether a given recipe or cohort is exploitable depends on
  its content.

### H3. Sealed messages don't bind the tenant, and adopted-legacy tenants share a private key (J)

- **Where:**
  - `internal/payloadbox/payloadbox.go:135-147`: `Message` binds version,
    purpose, `sid`, id, reply-to and `iat`, but no tenant and no key id.
  - `payloadbox.go:226-229`: `Expect` checks only purpose and sprout id.
  - `internal/pki/tenantbox.go:417-431`: `initialKeypair` gives every
    tenant that has pinned sprouts the legacy shared keypair (origin
    `adopted-legacy`).
  - The box public key submitted at enrollment needs no proof of possession
    (`enroll.go:272,428`), and `pub` is not unique across tenants
    (`boxkeys.go:46-51`).
  - The bus can learn any sprout's new box public key: it sends the
    unauthenticated `boxkey.rotate`, and the sprout logs the new key at
    Notice (`cmd/sprout/boxkey.go:73`), which log shipping publishes.
- **Scenario:**
  1. Tenants A and B are both `adopted-legacy`.
  2. The bus triggers a rotate on A's `web01` and reads its new public key
     P from the shipped log.
  3. Tenant B enrols its own `web01` (ids are unique only per tenant) with
     `sprout_pub = P`.
  4. B runs `cmd.run` on its `web01`. Farmer seals it with the shared
     legacy private key to P, purpose `f2s.cmd.run`, `sid` `web01`.
  5. The bus delivers it into A's account. A's sprout opens it with its
     pending key, purpose and `sid` match, and it runs the command. Its
     sealed reply opens at B's farmer.
- **Fix:**
  - Bind `tenant_id`, and the recipient key, into `Message` and `Expect`;
    the sprout pins its tenant at enrollment.
  - Rotate every adopted-legacy tenant now, and until then treat them as
    one trust domain.
  - Require proof of possession of `sprout_pub` at enrollment.
- **Mark:** CONFIRMED as a code path; not run. Exposure exists only where a
  legacy shared keypair existed when tenants were created. No deployment
  has been released, so this may be latent; check before any release that
  migrates an existing install.

### H4. Opened cook envelopes are logged at Trace and shipped on the bus (J)

- **Where:**
  - `internal/cook/sproutcook.go:34`: `log.Tracef("received new envelope:
    %v", envelope)`, called after the sealed envelope is opened
    (`cmd/sprout/nats.go:86-99`). The envelope includes each step's
    rendered properties.
  - `internal/log/log.go:43-44,84-85`: the NATS logger receives every
    level.
  - The library does not filter by level either: `log-nats` v2.1.2
    `createLog` publishes every entry (`log/log.go:73-101`).
  - Shipping is switched on at `cmd/sprout/main.go:292`.
- **Scenario:** Every cook dispatch arrives sealed and is then republished
  in plaintext on `imas.logs.sprouts.<id>.TRACE`. A compromised bus reads
  the steps and any values farmer templated into them.
  - `sdb://` refs are resolved on the sprout, so secret values themselves
    are not in the envelope. Everything else the recipe carries is.
  - This undoes cook sealing on every sprout.
- **Fix:**
  - Log only the job id and step count.
  - Stop shipping Trace and Debug over NATS, or ship from a minimum level.
  - Add a test that no opened body reaches a log sink.
- **Mark:** CONFIRMED, including the library source.

## Medium

### M1. The signed manifest's version is not bound to the package it names (FU.0, FU.2)

- **Where:**
  - The downgrade check compares manifest versions only
    (`internal/ingredients/selfupdate/selfupdate.go:182-188`).
  - The package is found by checksum anywhere in the index
    (`repo.go:283-348`; `aptFilenameFor` matches any stanza whose `SHA256`
    equals the signed sum).
  - dpkg is run as `--force-confdef --force-confold -i` (`install.go:106`).
    dpkg's `downgrade` force option is on by default.
  - fleetreleaser signs any valid manifest above the floor without seeing
    the package (`cmd/fleetreleaser/server.go:143-168`).
- **Scenario:** Someone with the operator token, or code execution in
  saasapi (which holds fleetreleaser's caller token):
  1. registers `v3.0.0` deb with the checksum of the genuine old
     `imas-sprout_2.0.0_amd64.deb`, which apt repos keep;
  2. gets it approved; a compromised saasapi writes the approval row
     itself.
  - A v2.5.0 sprout accepts it (3.0.0 > 2.5.0), downloads the 2.0.0 file
    (hash matches), and `dpkg -i` downgrades it to vulnerable code and its
    old keyring, as root.
  - On a general-purpose customer mirror, the checksum can name *any*
    package in it.
  - `rpm -U` refuses older packages, and the MSI has
    `DowngradeErrorMessage`. zypper was not checked.
- **Fix:**
  - Before installing, read the package's own metadata and require name
    `imas-sprout` and version equal to the manifest's (`dpkg-deb -f`,
    `rpm -qp --qf`, the MSI's ProductVersion).
  - Pass `--refuse-downgrade` to dpkg.
  - Optionally have fleetreleaser check the checksum against the tag's
    signed `checksums.txt`.
- **Mark:** CONFIRMED for deb; zypper UNCONFIRMED.

### M2. Replay of sealed `cmd.run` or `cook` after a sprout restart (J)

- **Where:**
  - `internal/pki/sproutbox.go:156`: the replay guard lives only in process
    memory.
  - The reasoning in `internal/payloadbox/replay.go:30-34` ("re-runs at
    most what the restart interrupted") does not hold: every message
    answered within the ±5-minute window can be replayed once memory is
    empty.
  - The cook push path cooks without checking the persisted handled-jobs
    list (`cmd/sprout/nats.go:86-99`, `internal/cook/sealed.go:206`); only
    the staged-pull path checks it.
- **Scenario:** An admin runs `cmd.run shutdown -r now`. The VM is back in
  a minute, the bus replays the captured request (its `iat` is still in the
  window), and the host reboots again, in a loop until 5 minutes after the
  original was issued. Any non-idempotent command or recipe can be replayed
  the same way.
- **Fix:**
  - Either persist the guard (ids with expiry, atomic 0600 file), or refuse
    any message whose `iat` is earlier than process start plus the skew
    allowance.
  - Make `RespondCook` refuse a job id already in the handled-jobs file.
- **Mark:** CONFIRMED.

### M3. A box key submission sealed under a grace key is accepted (J)

- **Where:**
  - `internal/natsapi/boxkeys.go:115` opens the submission through
    `pki.OpenFromSprout`, which tries the active key *and* every grace key
    (`internal/pki/farmerbox.go:74-86`).
  - `boxkeys.go:129` then installs the named key as active.
  - The farmer grace period defaults to 24 h; the sprout deletes its own
    previous key after 15 minutes.
- **Scenario:** An old box private key leaks, for example from a VM
  snapshot. The operator rotates. Within 24 h the attacker, with a
  compromised bus, submits a fresh request sealed under the old key naming
  its own public key. Farmer now seals every `cmd.run` and `cook` for that
  sprout to the attacker, and accepts its forged results.
- **Fix:** For submissions, accept only the active key. A grace key may
  only re-assert the key that is already active.
- **Mark:** CONFIRMED.

### M4. Dotted sprout IDs overlap other sprouts' grants (CL.1)

- **Where:**
  - `internal/pki/pki.go:39` allows `.` in sprout IDs.
  - `resolveEnrollSproutID` (`enroll.go:563-571`) keeps the
    client-supplied hostname apart from lowercasing.
  - The minted grant is `Sub imas.sprouts.<id>.>`
    (`internal/pki/jwtusers.go:60-62`), and the sprout may also publish
    `_INBOX.>`.
- **Scenario:** The victim is `ip-10-0-0-5.ec2.internal`. Anyone with a
  join token for the tenant enrols as `ip-10-0-0-5`. Its JWT then receives
  the victim's `cmd.run`, `cook`, `shell.start`, `test.ping`,
  `boxkey.rotate` and `recipe.nudge` subjects, and it can answer first:
  - an error-header refusal kills sealed commands
    (`internal/ingredients/cmd/sealed.go:93-95`);
  - forged ping replies are accepted;
  - a `shell.start` reply hands back session subjects it chose.
  - Sealed bodies stay confidential.
  - An id of `announce` subscribes to every announcement.
  - Dotted ids are already broken elsewhere (`imas.sprouts.*.facts` and
    `imas.sprouts.*.boxkey.pub` never match them, and
    `handleBoxKeySubmit` takes `parts[2]`), so box key rotation never
    completes for them.
- **Fix:**
  - Map `.` to `-` at enrollment and reject it in `IsValidSproutID`.
  - Reserve control tokens such as `announce`.
- **Mark:** CONFIRMED (follows from NATS subject matching on the minted
  grants).

### M5. One tenant can starve every tenant's dispatch (FU.6, CL.3)

- **Where:**
  - saasapi has one 64-slot pool per process
    (`internal/saasapi/sprout_actions.go:97,693`). Each item holds a slot
    until its reply or timeout, which is up to about 10m45s for a `cmd.run`
    with `timeout_seconds: 600` (`:825-836`).
  - Rollout waves take slots from the same pool
    (`fleet_update_dispatch.go:932`).
  - Farmer has a 64-slot pool per replica whose callback blocks when it is
    full (`internal/natsapi/sprout_action.go:107,153-165`).
  - The rate limit is per tenant; the slots are not.
- **Scenario:** A tenant posts 100 long `cmd.run` items and repeats. Other
  tenants' items and update waves wait.
  - Requests queued behind farmer's full pool miss saasapi's 45 s reply
    timeout and are recorded `dispatch_outcome_unknown`.
  - A rollout wave then halts, while farmer may still run the request
    later.
- **Fix:**
  - Per-tenant concurrency caps well below the pool size, in both services.
  - A reserved pool for `self_update`.
- **Mark:** CONFIRMED by trace; not load-tested.

### M6. A same-second tie lets a stale Account JWT spread cluster-wide (SCALE.2)

- **Where:**
  - Only lockouts wait for a fresh `iat`
    (`internal/pki/tenant.go:516`). Ordinary re-signs do not
    (`tenant.go:728-735`, `jwtusers.go:230-238`, `saasapi_user.go:233`).
  - `claimRank.beats` (`cmd/farmerbus/fence.go:477-485`) breaks equal
    `iat` by `a.raw > b.raw`.
  - `merge` saves the winner locally (`fence.go:530`), including when
    healthy nodes pull from a rejoining peer.
- **Scenario:** A bulk deny of X then Y in one second signs JWT1 {X} and
  JWT2 {X, Y} with the same `iat`. Node C misses JWT2 (the recorded ~4 s
  window). When C rejoins, every node pulls. If JWT1 sorts higher as a
  string, healthy nodes replace JWT2 with it, and Y is re-admitted
  everywhere until the account next changes.
- **Fix:**
  - Give every Account re-sign a strictly newer `iat` (call
    `waitPastIssuedAt`, or use `max(now, prev+1)`).
  - In `beats`, on equal `iat` with different content, keep the local copy
    or prefer the superset of revocations.
- **Mark:** CONFIRMED in code. That the two JWTs share a `jti` comes from
  the repo's own comments (`tenant.go:657-663`, `fence.go:523-527`), not
  from re-reading nats-server.

### M7. Server-side OpenBao errors can carry an echoed token to a tenant (CL.2a)

- **Where:**
  - `openbao/api/v2` v2.7.1 `response.go:63-66` stores a non-JSON body
    verbatim in `ResponseError.Errors` (with `RawError = true`).
  - `internal/openbao/openbao.go:396-401` (`statusError`) copies `Errors`
    without checking `RawError`, and `openbao_test.go:383` pins this
    behaviour.
  - `pki.RotateTenantX25519Keypair` returns that error to
    `handlePKIRotateTenantBoxKey` (`internal/natsapi/boxkeys.go:67-75`),
    whose error text goes back to the caller (`internal/natsapi/router.go:139`).
  - fleetreleaser logs it (`cmd/fleetreleaser/server.go:161`).
- **Scenario:** A tenant admin calls `pki.rotatetenantbox` while a load
  balancer, ingress or WAF in front of the platform OpenBao answers 502
  with a page that echoes request headers. The tenant receives the
  tenant-box identity's `X-Vault-Token`, and that identity can read every
  tenant's box private key. During a Kubernetes login the echoed body is
  the service account JWT.
  - CL.2b hardened the sprout against exactly this; the server side
    regressed from the hand-rolled client, which dropped such bodies.
- **Fix:** In `statusError`, keep `Errors` only when `!re.RawError`, and
  change the test to assert that the body is absent.
- **Mark:** CONFIRMED as a code path. It needs an echoing intermediary,
  which depends on the deployment.

### M8. Recipe templates can read farmer's environment (outside the flagged scope)

- **Where:**
  - `internal/cook/farmercook.go:68`: `v["env"] = os.Getenv` in the
    recipe template function map.
  - The farmer chart puts `IMAS_PXC_DSN` and the S3 access keys in farmer's
    environment (`deploy/helm/farmer/templates/farmer-deployment.yaml:89-119`).
- **Scenario:** A recipe containing `{{ env "IMAS_PXC_DSN" }}` renders the
  platform database credential (every tenant's farmer data) into the recipe
  sent to, and staged for, the cooking sprout.
  - No API lets a tenant upload recipes: they come from the one
    platform-wide `config.RecipeDir` prefix. So this is reachable by
    whoever can write that bucket prefix, and the result lands on every
    tenant's sprout that cooks the recipe.
  - Recipe names cannot escape the prefix, because `.` becomes `/` and the
    `.imas` suffix is forced (`farmercook.go:330-345`).
- **Fix:**
  - Remove `env` from the farmer-side function map, or allow-list a
    non-secret prefix.
  - Decide whether a shared recipe tree is intended in a multi-tenant
    deployment.
- **Mark:** CONFIRMED in code. Severity depends on who may write recipes.
  Found in passing; it predates the flagged work (merge `d997fbb`).

## Low

Each entry gives where, the scenario, the fix and the mark.

**FU.0, FU.2, FU.3, FU.4**

- **L1. The dispatch switch exists only in saasapi.**
  - Where: farmer accepts `self_update` whenever asked
    (`internal/natsapi/sprout_action.go:219-251`). `checkSelfUpdateRelease`
    checks approval, registration, revocation and signatures, but not the
    rollout window and not any enable flag (`:440-489`).
    `PATCH .../update-policy` is registered with the flag off
    (`internal/saasapi/router.go:141`).
  - Scenario: with the flag off, a forged `internal.sprout.action`
    `self_update` installs the approved version, bypassing waves, the
    window and the selection.
  - Fix: a farmer-side `IMAS_SELF_UPDATE_ENABLED` (default false), and have
    farmer enforce the rollout window too.
  - Mark: CONFIRMED.
- **L2. Repository redirect URLs, with their query strings, reach job
  errors.**
  - Where: `internal/ingredients/selfupdate/download.go:73,101` wrap
    `url.Error`, which carries the redirected URL; `Redacted()` keeps the
    query.
  - Scenario: a presigned CDN URL (`X-Amz-Signature`) lands in the step
    error, on the bus and in job results. The repo token itself does not
    leak.
  - Fix: replace `url.Error.URL` with `redact(...)` and strip the query.
  - Mark: CONFIRMED.
- **L3. Staging directory and keyring are checked by mode, not owner.**
  - Where: `internal/fleetsign/keyring.go:96-101` (no uid or parent check;
    Windows skips it). `selfupdate.go:244-250`: `RemoveAll`, then
    `MkdirAll` succeeds on a directory that already exists with any owner.
  - Scenario: only with a non-default `cachedir` under a world-writable
    directory. A local user swaps the staged file between the hash check
    and `dpkg`/`msiexec` (msiexec starts 10 s later), which gives root or
    SYSTEM.
  - Fix: `Lstat` and require owner = euid, mode 0700, not a symlink, on the
    directory and its parent; require the same of the keyring.
  - Mark: CONFIRMED as a code path; depends on configuration.
- **L4. Revocation and the version floor are not enforced on the sprout,
  and signatures never expire.**
  - Where: `internal/saasapi/model.go:174-179`: `Revoked` is outside the
    signature. `selfupdate.go:200-219` checks only the keyring.
  - Scenario: whoever controls farmer or the `revoked` column can serve a
    revoked but signed, higher version.
  - Fix: accept and document it, or ship a deny-list or minimum version
    with the keyring.
  - Mark: CONFIRMED.
- **L5. The `{}` placeholder keyring can ship.**
  - Where: `packaging/etc/fleet-signing-keys.json` is `{}`. It is packaged
    by `.goreleaser.yaml:327-330` and `imas-sprout.wxs:176-183`, and no
    release hook checks it.
  - Scenario: a fleet built with it fails closed and can never self-update
    without a reinstall.
  - Fix: a release hook runs `fleetsign.ParseKeyring` on the file and
    compares it with Transit's public keys.
  - Mark: CONFIRMED.
- **L6. One tenant can empty the shared manifest cache.**
  - Where: `internal/api/handlers/update_manifest.go:333-341` calls
    `clear()` on everything at 4096 entries; negative results are cached.
  - Scenario: a large tenant forces other tenants' waves to read through to
    PXC.
  - Fix: per-tenant caps, or don't cache "not found".
  - Mark: CONFIRMED; modest impact.
- **L7. The signer and saasapi split is documented as stronger than it is.**
  - Where: `cmd/fleetreleaser/main.go:17-24` and
    `deploy/fleetreleaser/README.md:82` call tenant approval a barrier
    against a compromised saasapi. But saasapi holds the caller token
    (`fleet_releases.go:126,640-665`) and writes `tenant_update_policy`,
    which farmer trusts (`internal/natsapi/sprout_action.go:457-462`).
  - Scenario: reviewers rely on a barrier that does not exist against a
    compromised saasapi.
  - Fix: correct both documents; consider an independent second factor
    (the signed `checksums.txt`, as in M1).
  - Mark: CONFIRMED.

**FU.6, FU.6b, FU.7, CL.3**

- **L8. A live rollout never re-checks that the tenant is active.**
  - Where: `preWaveCheck` returns early unless `r.resumed`
    (`internal/saasapi/fleet_update_dispatch.go:897`). `DeleteTenant`
    keeps the policy row (`tenants.go:184-195`).
  - Scenario: after DELETE, waves keep going until farmer's deprovision
    lands. If deprovisioning exhausts its retries, they keep going for the
    whole rollout.
  - Fix: call `tenantIsActive` before every wave.
  - Mark: CONFIRMED.
- **L9. `cmd.run` output crosses the unsealed `internal.*` bus for
  nothing.**
  - Where: farmer fills `CmdRunResult.Stdout`/`Stderr`
    (`internal/natsapi/sprout_action.go:319-325`); saasapi reads only
    `ExitCode` (`internal/saasapi/sprout_actions.go:941-946`).
  - Scenario: output sealed end to end from the sprout is re-sent in
    plaintext.
  - Fix: leave both fields empty on this subject.
  - Mark: CONFIRMED. Whether large output exceeds `max_payload` and turns a
    completed command into `dispatch_outcome_unknown` is UNCONFIRMED.

**CL.1, PKI.1, SCALE.2**

- **L10. A deprovisioned tenant's sprouts keep getting gateway JWTs.**
  - Where: no deleted-tenant check in `SproutIDAndTenantForNKey`
    (`internal/pki/store.go:161-168`), `reissueExistingIdentity`
    (`enroll.go:479-501`), `RefreshSprout` (`refresh.go:75-86`) or the
    file middleware (`internal/api/handlers/middleware.go:104-167`).
    `acceptEnrolledNKey` swallows the `ReloadNKeysForTenant` error
    (`enroll.go:592-596`).
  - Scenario: offboarded hosts keep refreshing and reading their staged
    files and the update manifest.
  - Fix: check `pki_tenants.deleted` (fail closed on a DB error) on these
    paths, and propagate the reload error.
  - Mark: CONFIRMED.
- **L11. PKI.1: a failed re-check leaves a deprovisioned tenant live.**
  - Where: `pushLiveTenantAccount` (`tenant.go:593-595`) returns an error
    after the live push. A redelivered provision hits the deleted branch
    (`tenant.go:318-319`) and returns without pushing a lockout.
  - Scenario: the race plus a database error at that moment leaves the
    tenant admitted until core's next SYS reconnect.
  - Fix: retry the re-check; whenever any path sees `Deleted`, push a fresh
    lockout; run a periodic relock.
  - Mark: CONFIRMED.
- **L12. Unauthenticated legacy `PUT /pki/putnkey` can revoke any
  legacy-tenant sprout.**
  - Where: `internal/api/routers.go:44`, `handlers/pki.go:25-99` (no proof
    of possession). The revoke wins in `syncNatsAuth`
    (`jwtusers.go:200-226`).
  - Scenario: anyone who can reach farmer's API and knows a public NKey
    files it as `rejected`. In the Helm deployment only Envoy reaches
    farmer and Envoy does not route this path, so it is Medium only for
    standalone installs.
  - Fix: disable it when enrollment is on, or require proof of possession;
    never revoke an NKey accepted under another row.
  - Mark: CONFIRMED; exposure depends on the deployment.
- **L13. The bus logs payloads at debug.**
  - Where: `internal/pki/nats.go:64-65` (`Trace: true, Debug: true`);
    `cmd/farmerbus/main.go:183` (`SetLogger(..., true, true)`);
    `internal/log/charm.go:20` maps Trace to Debug.
  - Scenario: with `loglevel: debug`, CLI tokens, shell keystrokes,
    `internal.*` bodies and every unsealed payload, for every tenant, reach
    the bus log.
  - Fix: `Trace: false` unless a separate, explicit flag is set.
  - Mark: CONFIRMED in the repo. That nats-server's trace includes payloads
    was not re-read.
- **L14. A single-node bus on an empty volume serves before core's SYS JWT
  arrives.**
  - Where: the SYS bootstrap has no revocations
    (`internal/pki/busauth.go:119-121`); with no cluster there is no fence
    (`cmd/farmerbus/main.go:167-177`). The SaaS API user JWT has no `exp`
    (`saasapi_user.go:213-218`).
  - Scenario: a rotated-out SaaS API key works for the seconds before
    core's push.
  - Fix: give the SaaS API user JWT an expiry, or gate the listener until a
    newer SYS JWT lands.
  - Mark: CONFIRMED; short window.
- **L15. The fence counts any routed peer and takes cluster size from local
  configuration.**
  - Where: `cmd/farmerbus/fence.go:210-222,233`.
  - Scenario: during a 3-to-5 scale-up, an old pod partitioned with one new
    pod sees 2 of 3 and keeps serving. That is split-brain, failing open.
  - Fix: count only peers in the configured `Routes`; fence on a peer
    reporting a different size.
  - Mark: code CONFIRMED; the rollout ordering is UNCONFIRMED.
- **L16. A compromised bus node can plant future-dated Account JWTs that
  survive cleanup.**
  - Where: the bus holds the operator, operator-signing and SYS seeds
    (`busauth.go:80-103`); `fence.rank` (`fence.go:487-499`) puts no upper
    bound on `iat`.
  - Scenario: a JWT with `iat` in year 3000 is re-merged from any PVC and
    beats every later core push.
  - Fix: reject `iat > now + skew`. Better, ship the bus pre-signed JWTs so
    it holds no signing seed at all.
  - Mark: CONFIRMED.

**CL.2a, CL.2b**

- **L17. A redirect carries token, body and client certificate to any HTTPS
  host.**
  - Where: `openbao/api/v2` `client.go:1595-1612` follows one 301, 302 or
    307 with no host check, re-adding `X-Vault-Token` (`request.go:125-135`)
    and re-sending the body. The sprout's `GetClientCertificate` is
    transport-wide (`internal/ingredients/sdb/openbao/provider.go:131`).
  - Scenario: a node or ingress redirects to a host the operator does not
    control. That host receives the platform token, Kubernetes login JWTs,
    or tenant box private keys being written (`tenantbox.go:293-303`).
  - Fix: a RoundTripper that refuses any host other than the configured
    one, or `DisableRedirects`; add tests. The recorded decision to keep
    one redirect did not consider a host change.
  - Mark: CONFIRMED.
- **L18. The Kubernetes login client picks up ambient
  `BAO_NAMESPACE`/`VAULT_NAMESPACE`.**
  - Where: `internal/openbao/openbao.go:223` uses `client.Clone()`, which
    re-reads the environment (`client.go:820-826`); only `<prefix>NAMESPACE`
    overrides it (`:228-230`).
  - Scenario: an `envFrom` with `VAULT_NAMESPACE` sends logins to the wrong
    namespace. A malformed `BAO_*` variable stops startup.
  - Fix: always `ClearNamespace()`, or build the login client with
    `DisableEnvironment`; add the Kubernetes variant of the ambient test.
  - Mark: CONFIRMED.
- **L19. An unfollowed 3xx counts as success.**
  - Where: `response.go:34`; `openbao.go:367-377`; an empty body parses as
    `(nil, nil)`; `tenantbox.go:304-309` reports `written=true`.
  - Scenario: an empty 308 to a key write reports success, and farmer uses
    a tenant keypair that was never stored.
  - Fix: treat anything outside 200-299 as `*StatusError`, as the sprout
    does.
  - Mark: CONFIRMED.
- **L20. The sprout's cached OpenBao token survives a certificate
  rotation.**
  - Where: `internal/ingredients/sdb/certwatch.go:62-74,104-111` has no
    reload hook; the only invalidation is on a 403 (`provider.go:268-270`).
  - Scenario: a rotation meant to drop a distrusted identity does not take
    effect until 90% of the old lease (weeks by default).
  - Fix: invalidate the cache on reload.
  - Mark: CONFIRMED.
- **L21. An `sdb://openbao` ref can reach any path on the customer
  server.**
  - Where: `provider.go:276-283,300-301`: no segment validation; the
    client's `path.Join` resolves `..`.
  - Scenario: `sdb://openbao/secret/a/../../auth/token/lookup-self#id`
    reaches `/v1/auth/token/lookup-self` on the KV v1 fallback.
  - Fix: reject `.`, `..`, empty segments and reserved first segments, as
    `internal/openbaokv/client.go:122-131` does.
  - Mark: path construction CONFIRMED; exploitation depends on the
    customer's policy. Info where recipe authors already have `cmd.run`.

**J follow-ups**

- **L22. Deleting a severing tenant-key version re-joins the chain to
  compromised versions.**
  - Where: `internal/pki/tenantbox.go:400-410`: a missing version is
    skipped, and the `severed` marker lives in the deleted version's own
    data.
  - Scenario: v1 leaks; v2 is written with `--sever`; v3 is a normal
    rotation; the operator deletes v2. v1 gets continuity proofs again and
    sits in `previous`.
  - Fix: record the sever boundary somewhere deletion cannot erase (the
    current version's data or KV `custom_metadata`), or stop at any gap.
  - Mark: CONFIRMED; depends on operator action.
- **L23. Continuity proofs have no freshness check.**
  - Where: `internal/pki/sproutbox.go:472-485` checks `body.To` but not
    `IssuedAt` or the replay guard. The comment at `:111-112` saying the
    proof "carries no IssuedAt" is wrong.
  - Scenario: an old K1-to-K2 proof replayed after K2 leaked and was
    severed re-pins an offline sprout to K2.
  - Fix: check `iat` against the skew window.
  - Mark: code CONFIRMED; the delivery path (MITM of the refresh response)
    is UNCONFIRMED.
- **L24. The tenant pin is trust-on-first-use against the DMZ Envoy.**
  - Where: Envoy terminates TLS; `enrollclient.go:368-370,454-461` pins
    whatever `tenant_x25519_pub` comes back.
  - Scenario: a compromised Envoy at enrollment substitutes its own key.
  - Fix: farmer signs the response's identity fields with a key provisioned
    with the sprout (like `sproutrootca`), or the tenant key is
    pre-provisioned with the join token.
  - Mark: CONFIRMED; design level.
- **L25. "Box-ready" is decided by key files existing.**
  - Where: `sproutbox.go:161-171`; plaintext is accepted when not ready
    (`internal/ingredients/cmd/sealed.go:122-131`,
    `internal/cook/sealed.go:141-142`). `ErrTenantKeyNotPinned` is raised
    only at refresh (`enrollclient.go:609-611`).
  - Scenario: a lost pin file makes a J-enrolled sprout accept plaintext
    `cmd.run` until its next refresh.
  - Fix: persist an "enrolled with J" marker, and treat a missing pin as
    fatal at startup.
  - Mark: CONFIRMED; needs local state loss.

## Info

- **I1.** The rollout lease is advisory and compared in the application's
  clock (`internal/saasapi/outbox_lease.go:128-138`), and a non-UTC `loc`
  in the DSN is only warned about (`db.go:63-65`). The per-item status
  claim still prevents double sends. Compare in SQL (`NOW(3)`) and refuse a
  non-UTC `loc`.
- **I2.** `http://` OpenBao addresses are accepted on both sides
  (`openbao.go:150-194`, `provider.go:163-172`). Refuse them unless an
  explicit test override is set.
- **I3.** With an `https://` proxy, the OpenBao TLS config (its CA, and the
  sprout's client certificate) is used for the TLS session to the proxy.
  Document it next to the NO_PROXY guidance already listed in Open item 10.
- **I4.** Bounds on a hostile repository are loose: a 256 MiB index
  (`repo.go:59`), a 512 MiB `.nupkg` read with `zip.OpenReader`
  (`download.go:41`), and a 15-minute timeout per request that can hold
  the update lock for about 45 minutes. Memory figures were not measured
  (UNCONFIRMED).
- **I5.** Stale text:
  - `deploy/fleetreleaser/policies/imas-fleet-signer.hcl:8` still names
    `artifact_url`;
  - `.goreleaser.yaml:20,33-34,305` says packaged sprouts are built
    "without self-update" (`no_self_update`), but no Go file uses that tag
    and `cmd/sprout/include.go:15` always links `selfupdate`.
- **I6.** Removed CLI admin keys are never revoked (`jwtusers.go:185-198`).
  Latent, because the CLI connects with a bare NKey.
- **I7.** `SproutIDAndTenantForNKey` looks up by NKey alone over a
  non-unique index (`store.go:40,161-168`), and maps database errors to
  not-found, so a transient error spends a join-token use. Add uniqueness
  and fail on more than one match.
- **I8.** `ensureTenantAccountMaterial` (`tenant.go:171-193`) and
  `ensureNatsAuth` (`jwtauth.go:194-212,254-275`) re-mint a revocation-free
  Account or SYS JWT if the file is missing or undecodable. That fails open
  on file loss.
- **I9.** After a core PVC restore, `PushAllAccounts` pushes older JWTs
  without re-syncing revocations first. Run `syncTenantSprouts` per tenant
  before pushing.
- **I10.** `JobRef{SproutID, JID}` (`internal/saasapi/sprout_actions.go:958-961`)
  has no tenant. It is used only inside tenant-scoped calls today, but it
  is the one tenant-less key found outside H2, and it is fragile.
- **I11.** Route mTLS uses the general root CA rather than a dedicated one.
  This is mitigated by the SAN and route-password checks
  (`cmd/farmerbus/cluster.go:191-201,279-307`).
- **I12.** Minor:
  - no body limit on the enroll handler (`handlers/enroll.go:94`);
  - `writeFileAtomic` does not fsync the directory
    (`enrollclient.go:751-783`);
  - stale comment at `pushall.go:177-180`.

## What held up

Recorded so the human review can see what was examined, not only what
failed.

- **Manifest crypto (FU.0).**
  - Domain-tagged, `|`-joined fields; no field may contain `|` or control
    characters, and each has a strict pattern (`fleetsign/manifest.go:97-159`).
  - Strict JSON: no duplicate, unknown or case-folded keys (`:170-248`).
  - Ed25519 only, canonical `vN` key ids, small-order keys refused, at most
    32 keys (`keyring.go:59-80,160-181`).
  - An empty or malformed keyring fails closed.
  - OS and arch are signed and checked; `min_sprout_version` is enforced
    (`selfupdate.go:212`); pseudo-versions are refused (`version.go:52-63`).
- **Install path (FU.2).**
  - The hash is computed over the exact file installed (`O_EXCL`, 0600, in
    a 0700 directory: `download.go:192-217`).
  - The local file name is the signed one.
  - Installers come from fixed paths and are given argument lists, with no
    shell (`platform.go:211-226`, `install.go:106-115`).
  - The repo token stays on the repo host, and only https is followed
    (`download.go:68-98`).
  - The farmer client is pinned to the sprout root CA and follows no
    redirects (`selfupdate/manifest.go:58-77`).
- **fleetreleaser (FU.3).**
  - Constant-time bearer token comparison, current and previous tokens,
    at least 32 characters (`server.go:96-116`).
  - Signs only a validated manifest above the floor, and verifies Transit's
    signature against Transit's key set before returning it.
- **Registration (FU.4).**
  - Operator listener only, with a distinct token
    (`fleet_releases.go:134-144,165-170`).
  - Immutable rows; unique on (version, os, arch, package type); every
    signature verified before it is stored.
- **Tenant scoping (FU.6, CL.3).** Every saasapi query, lease key and
  sweeper join examined is scoped by tenant:
  - `asset_links.go:302-305`
  - `sprout_actions.go:361,375,841`
  - `outbox_lease.go:239`
  - `sweeper.go:233`
  - `rollout_resume.go:245`
  - `fleet_update_dispatch.go:619`

  One rollout per tenant holds (`:565-599`). Revoked versions are refused at
  PATCH, POST, claim, every wave, and by farmer.
- **No double sends found (CL.3).**
  - Only `queued` items are re-sent.
  - `self_update` is excluded from the §1.5 sweep.
  - `dispatching` items are failed, not re-sent.
- **Fail-closed checks on the gate.**
  - A missing fact never counts as success.
  - A reader error halts the wave.
  - Facts dated in the future give `facts_clock_skew`.
- **Enrollment (CL.1).**
  - Constant-time, tenant-bound, single-use join tokens (`enroll.go:118-129,317-400`).
  - Proof of possession is checked before redemption.
  - Separate signature domains for enroll and refresh.
  - The Valkey replay cache fails closed when Valkey is unavailable.
  - No path traversal from `tenant_id` or `sprout_id`.
- **PKI.1.**
  - Tombstones are insert-if-absent and never un-deleted.
  - A deprovision marks the row before signing and gets a strictly newer
    `iat`.
- **SCALE.2 routes.**
  - mTLS, a SAN matching a configured host, and a constant-time password
    read from a file.
  - The fence starts fenced and needs a strict majority.
  - Pulled JWTs have signature and issuer verified.
- **OpenBao (CL.2a, CL.2b).**
  - TLS verification is never disabled, and `BAO_SKIP_VERIFY` is ignored.
  - A CA bundle that fails to load is fatal.
  - Ambient tokens are cleared on the API clients.
  - Sprout errors drop raw bodies.
  - Every `sdb` value is registered as sensitive.
  - The certificate watcher keeps the last good pair on a failed reload.
- **Sealing (J).**
  - NaCl box with both static keys and `crypto/rand` nonces.
  - Purposes carry a direction prefix.
  - Farmer accepts a reply only if its `ReplyTo` names the request it just
    sent.
  - A seal error is never silently downgraded to plaintext.
  - A box-ready sprout refuses plaintext.
  - Every box and tenant key lookup is keyed on `(tenant_id, sprout_id)`
    or on `tenant_id`.
  - Re-pinning needs a continuity proof under the pinned key.
- **Malicious update repository.**
  - It cannot get unsigned bytes installed; its reach is M1, L2 and I4.
  - Nothing outside FU.2 reads repository content.

## Known gaps, ranked

These are already recorded in BUILD-STATUS. They are ranked here against the
findings above and not restated.

1. **Critical: Open item 11, control plane forgeable by a compromised bus.**
   Unbounded CLI token lifetime gives the bus permanent admin. The bus can
   refresh as any sprout and read its staged recipe. It can forge
   `internal.*` actions. This outranks every finding above. The 5-minute
   token stopgap should ship before dispatch is turned on.
2. **High: Open item 2, `shell.*` unsealed.** A compromised bus gets an
   interactive shell on any Unix sprout. M4 adds a second route to
   intercept `shell.start` inside a tenant.
3. **High (raise from "lower severity by design"): facts sent in
   plaintext.** Facts now drive the rollout gate (H2) and are templated
   into recipes, so a forged fact is an integrity problem, not just
   disclosure.
4. **Medium (raise): `/v1/refresh` hands out the on-disk JWT, and old JWTs
   have no expiry.** This is what keeps a deleted host live in H1.
5. **Medium: SCALE.2, core pushes to one node and doesn't wait for all of
   them.** Combined with M6, a missed push can become a permanent revert
   across the cluster rather than a temporary one. PKI.1's ordering
   argument relies on the same delivery order.
6. **Low (unchanged): cook step events, `test.ping`, `cancel`, the rotate
   trigger and log shipping in plaintext.** Log shipping is the exception:
   it carries H4 and H3's key discovery, so treat it as High until H4 is
   fixed.
7. **Low (unchanged): `natsapi` tenant-facing subjects don't validate
   `msg.Reply`.**
8. **Low (unchanged): pre-CL.1 sprouts keep an unused `fleetsigningkeys`
   grant.**

## Open questions for the human review

1. **Recipe authorship (M8, H2).** Is the recipe tree meant to be shared
   across tenants? Who may write it?
2. **Legacy keypairs (H3).** Does any existing install have a legacy shared
   tenant keypair that would be adopted on upgrade? If not, can the
   adoption path be deleted rather than fixed?
3. **Revocation on the sprout (L4).** Should a revoked release be enforced
   on the sprout itself (a signed deny-list), or is farmer's check enough?
4. **Dispatch switch (L1).** Should the farmer-side switch be added before
   dispatch is enabled, as this review recommends?
