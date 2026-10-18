# Fixes before the Azure run (T1 to T6)

Read `docs/briefs/ORCHESTRATOR.md` first: its session prompt (zero open items,
repo-wide search, brief errors decided by a fixed order) applies to every unit.
The units close the open review findings and test gaps that can be fixed in
code before the Azure run (P1). Source: `docs/BUILD-STATUS.md` (P4, P8, P12,
P14, P17, P18), `docs/security-review-2026-10.md` (L3 to L21, I4, I5, I7) and
`docs/security-review-2026-10-b.md` (B8). Line numbers in those reviews are
from 2026-10 and have drifted: find each place by name, and check on main that
the finding still holds before fixing it. A finding that no longer holds gets a
test that pins the good behaviour and a line under "Brief corrections".

The six units touch different packages and can run at the same time. They
all end with a status fragment, so none edits another unit's file.

Owner decisions (2026-10-17, final):

- **T1.** The release is not allowed to ship an empty fleet keyring; the
  development tree may keep `{}` until the release GPG public key is added.
- **T2.** The three BSD/ISC/0BSD licence families are recorded as allowed
  (permissive, no copyleft), not dropped.
- **T3.** A DISCONNECT may only remove the presence of the connection it
  belongs to.
- **T4.** A deprovisioned tenant fails closed everywhere an identity is issued
  or read, including on a database error.
- **T5.** The OpenBao client talks to the configured host only.
- **T6.** Legacy unauthenticated endpoints are off when enrolment is on.
- Findings L15, L22, L23, L24 and I6 are not in this batch: they change a
  trust or design decision and need an owner decision first. Do not touch them.

## T1: sprout update safety (L3, L5, L6, L7, I4, I5, B8)

Scope: `internal/fleetsign`, `internal/ingredients/selfupdate`,
`internal/api/handlers/update_manifest.go`, `packaging/`, `.goreleaser.yaml`,
`.github/workflows` (release), `docs/`. (`cmd/fleetreleaser` and
`deploy/fleetreleaser` were removed with P22, PR #205.)

- **L3.** The staging directory, its parent and the keyring file are checked
  with `Lstat`: owner is the effective uid, mode no looser than 0700 for the
  directory (0600 for the file), and not a symlink. A failed check refuses the
  update with a distinct error code that is documented. The staging directory is
  created fresh (never reused when it exists with another owner). Windows: the
  equivalent check (owner is SYSTEM or Administrators, no inherited write for
  Users), tested with a fake ACL reader so the test runs on Linux.
- **L5.** `fleetsign.ParseArmoredKeyring` runs on the packaged keyring
  (`gpg-public-key.asc`, which every package installs as
  `/etc/imas/fleet-signing-keys.asc`) in `packaging/test` (it parses and has
  the shape the sprout expects). The release workflow fails when the keyring
  has no keys, and also when the release's `checksums.txt.sig` does not verify
  against the keyring (a `go test` of `packaging/test` that runs the existing
  verify code, `fleetsign.VerifyChecksums`, not a new tool). The test on `{}`
  for the development tree passes; the release step is what fails. Document
  the owner step (put the GPG public key in the file) in `docs/RELEASING.md`
  or the file the release process lives in.
- **L6.** The manifest cache is capped per tenant (default 256 entries per
  tenant, total cap kept) and "not found" is not cached. One tenant filling its
  share must not evict another's entries: test it with two tenants.
- **L7.** The documentation and the `cmd/fleetreleaser` comment stop calling
  tenant approval a barrier against a compromised saasapi; they say what it is.
  If `fleetreleaser` no longer exists on main, fix the remaining docs only.
- **I4.** Bound a hostile repository: index at most 16 MiB, a package at most
  the size the repository's index declares for it (and never above 512 MiB),
  a request timeout of 2 minutes with a total budget per update of 10 minutes
  that releases the update lock when it runs out. All overridable by sprout
  config.
- **I5.** Remove the `artifact_url` mention in the signer policy, and either
  make `-tags no_self_update` do what it says (a file with that build tag that
  makes `selfupdate` unavailable) or remove the tag from CI and packaging and
  correct the `.goreleaser.yaml` comments. Decide by what `packaging` needs:
  sprouts in packages DO self-update, so remove the tag and fix the text.
- **B8.** An MSI `ProductVersion` carries no prerelease. The binding of package
  to manifest on Windows compares the full version string (including `-rc.N`)
  taken from the manifest with the one the sprout derives from the file name,
  and refuses when they differ. Add a test with an rc and the final of the same
  MAJOR.MINOR.PATCH. zypper's downgrade skip: test it with a fake `zypper`.

Brief corrections (T1, decided by the code on main):

- L5: there is no `fleetsign.ParseKeyring` and no `{}` JSON keyring on main.
  P22 replaced `packaging/etc/fleet-signing-keys.json` with the armored GPG
  keyring built from `gpg-public-key.asc`, parsed by `ParseArmoredKeyring`;
  main already ships the release key in it. An empty keyring (`{}`, nothing,
  or no key that can sign) is `ErrNoKeys`, which the development-tree test
  allows and the release gate refuses. There is no verify `main` to `go run`,
  so the release steps run the verify code as `go test ./packaging/test`.
- L3: the keyring's 0600 needs the packages to install it 0600 (they
  installed it 0644): `.goreleaser.yaml`, the Molecule and self-update e2e
  nfpm specs, and `packaging/check-package-contents.sh`, which now checks
  the mode. "The staging directory and its parent" are the per-update
  directory and the staging root (`<cachedir>/selfupdate`), both 0700; the
  cache directory above them, which the packages make 0755, must be the
  sprout user's and not writable by group or others.
- I4: the update manifest declares no package size (P22's seven-key wire
  contract), so the package is bounded by the size the repository's index
  declares (apt `Size`, rpm `size package`, the MSI's zip entry in the
  NuGet package) and `sproutupdatemaxpackagebytes`. The budget covers the
  update up to the installer; the installer keeps its own 10-minute timeout,
  so the budget never kills `dpkg` or `rpm` part way.
- I5 and L7: `cmd/fleetreleaser`, `deploy/fleetreleaser` and the signer
  policy `imas-fleet-signer.hcl` were removed with P22, so there is no
  `artifact_url` left to remove there. The standalone builds' `self_update`
  tag was as unused as `no_self_update` and is removed too. L7's remaining
  text was in the signing and payload-encryption designs, the SaaS API docs
  and the `internal/natsapi` dispatch comment.
- B8: a prerelease is still refused on Windows (owner decision, PR #86); the
  file-name comparison runs first, so an rc and a final of one
  MAJOR.MINOR.PATCH are told apart either way.

## T2: #139, test gaps, licence record (P14, P17, P8, P4)

Scope: `cmd/imas`, `internal/saasapi/sweeper_actions_test.go`, `packaging/test`,
`internal/cook` tests, `docs/design/requirements.md`, `DEPENDENCIES.md`.

- **#139.** The CLI creates its config file with mode 0600 from the first
  byte (`OpenFile` with `O_CREATE|O_EXCL` and 0600 in a 0700 directory, then
  atomic rename), so the private key is never in a world-readable file, not
  even for an instant. Test it by creating the file under a permissive umask and
  checking mode at every step with a hook. Close issue #139 in the PR body.
- **P17 test gaps.** `TestItemErrorCodesDocumented` must fail for a code that
  the sweeper returns and `actionErrorMessages` lacks (derive the list of
  returned codes from the code, for example from a set of constants, and compare
  both ways). Add the missing tests for the farmer redial after the NATS client
  gives up, and the other re-signs that can tie on `iat` (P4 B5/M6): make every
  Account re-sign wait for a strictly newer `iat` as the tenant lock-out does, or
  prove with a test that it cannot tie. Tests that pin behaviour now fixed by
  T1, T4, T5 or T6 are not changed here; those units own them.
- **P8.** Record BSD-2-Clause, BSD-3-Clause, ISC and 0BSD under
  `requirements.md` item 21 as allowed permissive licences, and make
  `DEPENDENCIES.md` match. If a module has another licence, flag it in the PR.
- **P4.** Recheck B4, B5/M6, B6 (accepted) and B8 (T1) on main and update the
  P4 text through the status fragment: what is closed, with the commit.

Brief corrections (applied by T2, 2026-10-17, decided by the code on main):

- **#139.** The loader (`config.LoadConfig`, `internal/config`) still
  creates a missing file with `os.Create`; T2 only makes it close that file
  (an open handle blocks the rename below on Windows). The CLI
  creates the file 0600 (in a 0700 directory) before the loader runs
  (`ensureConfigFile`, `cmd/imas/cmd/configperm.go`; installed with a hard
  link, or created in place with O_EXCL where hard links are missing, so a
  file another process created meanwhile is kept), so the loader only
  ever finds the file and truncating it keeps 0600; `imas init` writes the
  config through a 0600 temporary file renamed into place
  (`writeConfigFile`). The private key itself is written by
  `internal/auth` with jety's in-place write, into that 0600 file.
- **P17, re-signs.** B5/M6 is already closed on main: every Account re-sign
  waits for a strictly newer `iat` (`waitPastIssuedAt`, C2 `5f4858b` and E6
  `aa1dd69`), with a source guard
  (`TestEveryAccountResignWaitsPastIssuedAt`) and a behaviour test
  (`TestEveryResignAdvancesIat`). The one re-sign the guard excepts, the
  purge's minimal lock-out (`scrubTombstoneLocked`, S6, minted from fresh
  claims), had no behaviour test; T2 adds it as a subtest. The tests are in
  `internal/pki`, not in the scope list.
- **P17, redial.** Farmer's redial lives in `cmd/farmer`
  (`newTenantRegistry`, `connectTenantWithRetry`), not in the scope list;
  the test is `cmd/farmer/tenantredial_test.go`, and `newTenantRegistry`
  takes its dialer as an argument so the test can pass one.
- **`internal/cook` and `packaging/test`.** Nothing is left for T2 there:
  `maxRecipeIncludes` is tested since S4 (`cook_budget_test.go`), and the
  packaged keyring check (L5) and `-tags no_self_update` (I5) are T1's.
- **P8.** No module has a licence outside Apache-2.0, MIT, BSD-2-Clause,
  BSD-3-Clause, ISC, 0BSD and MPL-2.0 (`go-licenses report`, v2.0.1, for the
  three targets of `.github/workflows/go-licenses.yml`), so nothing is
  flagged; the module list in `DEPENDENCIES.md` matches the report.

## T3: heartbeat presence (P12)

Scope: `internal/heartbeat`, `tools/loadtest`, `uat` heartbeat checks, CI
workflow for a Valkey service container, docs.

- **Race.** A presence entry carries the connection id (CID) of the connection
  that wrote it. DISCONNECT deletes it only when the stored CID is its own, in
  one atomic script (compare-and-delete). CONNECT is a plain write of the new CID.
  Test the interleaving with both orders, with CONNECT processed before the old
  DISCONNECT (the failing order today). (Correction, T3: a client ID is unique
  on one bus node only, so the stored ID is the node's server ID and the client
  ID, `heartbeat.ConnID`, both in every CONNECT/DISCONNECT event. The heartbeat
  refresh wrote `1` over the key, which would defeat the compare; it now extends
  an existing key and keeps its owner, and writes a missing one with the
  connection ID the sprout sends as the heartbeat body.)
- **Valkey.** The two-key refresh script and the compare-and-delete script use
  keys that share a hash slot (the `{tenant:sprout}` tag), and a test proves it
  against a real Valkey (standalone) and a real Valkey Cluster of 3 shards, run in
  CI from service containers. Tests read the address from an environment variable;
  CI sets it; a local run without Docker is the only case a test may report "not
  configured", and CI fails if the variable is missing. (Correction, T3: the
  compare-and-delete script names one key. The standalone address is the
  existing `SAASAPI_TEST_VALKEY_ADDR`, the cluster's `IMAS_TEST_VALKEY_CLUSTER_ADDR`;
  CI sets `IMAS_REQUIRE_VALKEY=1`, which makes a missing one a failure. A service
  container takes no command, so the three nodes get cluster mode through the
  image's `VALKEY_EXTRA_FLAGS` and a CI step joins them.)
- **Load test.** `tools/loadtest/fixture.go` takes the sprout permissions from
  the one shared definition in `internal/` (no second copy); load-test sprouts
  send heartbeats; a test fails if the two lists differ.
- **JWT change.** A sprout uses a JWT that a later refresh changes without a
  restart: reconnect with the new JWT at the next heartbeat. UAT.13 checks the
  full grant (heartbeat and the other subjects), not only the heartbeat one. (Correction,
  T3: this needs `internal/pki`'s `SproutBus` to present the JWT through a
  callback, and `cmd/sprout`; both changed here. UAT.13's check is
  `cmd/sprout`'s `refreshStaleUserJWT`, now against `pki.SproutUserJWTHasFullGrant`.)

## T4: deprovision and identity (L10, L11, I7)

Scope: `internal/pki`, `internal/api/handlers/middleware.go`, `internal/saasapi`
provisioning, docs.

- **L10.** `SproutIDAndTenantForNKey`, `reissueExistingIdentity`, `RefreshSprout`,
  the sealed refresh path and the `/files/` middleware all refuse a tenant that is
  deprovisioned (`pki_tenants.deleted`), with the same error, and also refuse
  when the database check fails (fail closed). `acceptEnrolledNKey` returns the
  `ReloadNKeysForTenant` error instead of swallowing it. One test per path.
- **L11.** The re-check after the live push is retried (3 attempts, jittered
  backoff); whenever any path sees a deleted tenant it pushes a fresh lockout;
  and a periodic relock (default every 10 minutes, `IMAS_TENANT_RELOCK_INTERVAL`,
  1m to 24h) pushes lockouts for every deleted tenant that still has a live
  Account on the bus. Tests: redelivered provision after a failed re-check; the
  periodic relock; no push storm with 1000 deleted tenants (batched, rate limited).
- **I7.** `SproutIDAndTenantForNKey` is keyed on `(tenant_id, nkey)` where the
  tenant is known; a database error is an error, never "not found", so it does
  not spend a join-token use. Add the unique index in a migration if the data
  allows (check for duplicates first and fail the migration loudly with a message
  that names them if there are any).

Brief corrections (found while building T4; decided by the order in
`ORCHESTRATOR.md` rule 6):

- The `/files/` middleware already refused a deprovisioned tenant on main
  (SEC.7c, `pki.VerifyGatewaySubject`, which the update manifest shares).
  Kept; it now uses the same check and error as the other paths
  (`ErrTenantDeprovisioned`, where it returned `ErrTenantNotFound`), and a
  router test pins both routes.
- "The same error" is the internal one, `ErrTenantDeprovisioned`. On the
  wire nothing changes: `/v1/enroll` and `/v1/refresh` keep their one
  generic refusal and the gateway routes their `403` (design §3.4, no
  oracle).
- `acceptEnrolledNKey` no longer calls `ReloadNKeysForTenant` on main (P21
  slice 3 replaced it with `grantEnrolledSprout`). What it swallowed was
  `errAccountPushFailed`, which also covered a failed re-check after the
  push. It now returns that re-check failure (`errTenantRecheckFailed`) and a
  deprovisioned tenant. A plain push failure after a re-check that found the
  tenant live is still logged and not returned: returning it strands the
  host (its NKey is accepted with no box key, which the replay path refuses
  for good), and with the accounts bucket installed a bus that only missed
  the push is no error anyway.
- I7: neither caller of `SproutIDAndTenantForNKey` knows the tenant (the
  enrollment replay and the sealed refresh carry only `nkey_pub`), so it stays
  the one cross-tenant lookup and refuses more than one accepted match. The
  lookups where the tenant is known are `SproutIDForNKey` and the new
  `findNKeyRowByNKeyInTenant` (used by `resolveEnrollSproutID`). The unique
  index is `(tenant_id, nkey)`, never `nkey` alone (CLAUDE.md, tenant
  safety); the duplicate check that names them is a preflight in `migrate up`
  (`internal/migrations/preflight.go`), since a MySQL migration file cannot
  raise an error that long.
- L11: "still has a live Account on the bus" is read from every bus node
  (`CLAIMS.LOOKUP`) and from the accounts bucket the bus loaders apply.
- Files outside the stated scope that the unit needed: `cmd/farmer`
  (starting the relocker), `deploy/helm/farmer` (`farmer.tenantRelockInterval`),
  `internal/migrations` (migration farmer 00006 and its preflight).

## T5: OpenBao client (L17 to L21, I2)

Scope: `internal/openbao`, `internal/openbaokv`, `internal/ingredients/sdb`
and its `openbao` provider, farmer chart notes, docs.

- **L17.** No redirect is followed to another host: a RoundTripper (or the
  client's redirect policy) refuses a different host, scheme or port, and a
  redirect on the same host keeps at most one hop. The platform token and body
  are never re-sent to another host. Tests with an `httptest` server that
  redirects to a second server that records what it received (nothing).
- **L18.** Login clients ignore `BAO_NAMESPACE` and `VAULT_NAMESPACE` and every
  other ambient `BAO_*`/`VAULT_*` variable unless the config asks for it; add the
  Kubernetes-login variant of the ambient test, and a malformed `BAO_*` variable
  no longer stops startup.
- **L19.** Farmer's `send` treats any status outside 200 to 299 as `*StatusError`,
  as the sprout does; `tenantbox` reports `written=true` only after a 2xx.
- **L20.** The sprout's cached OpenBao token is dropped when the client
  certificate reloads (a reload hook in `certwatch.go`). Test it with a rotation.
  The test that pins the old behaviour (`rotation_test.go`) changes with this.
- **L21.** `sdb://openbao` refs are validated segment by segment: reject `.`,
  `..`, empty segments, a leading `auth`, `sys` or `identity` segment, and
  percent-encoded forms of those. (Correction: `internal/openbaokv/client.go`
  rejected only `.`, `..` and empty segments, not the encoded forms or the
  reserved first segment; T5 moved the check to `internal/openbao`
  (`ValidatePath`, `ValidateMountPath`) and both use it.)
- **I2.** An `http://` OpenBao address is refused unless `allowInsecure` is set,
  in every client (farmer, sprout, loader); the refusal message names the key.
  (Correction: the bus loader has no OpenBao client. "Every client" is every
  `internal/openbao` identity, farmer's, the Jobs' and the bus's
  `IMAS_CERTS_OPENBAO_*`, plus the sprout's `sdb://openbao` provider. The key
  is `<prefix>OPENBAO_ALLOW_INSECURE` / `IMAS_SDB_OPENBAO_ALLOW_INSECURE`,
  set by the chart values `openbaoClient.allowInsecure` and
  `bus.tls.openbao.allowInsecure`; the farmer chart implies it for its
  bundled dev-mode OpenBao, which serves http only, so the eval install
  still renders and runs.)

## T6: bus logging and legacy endpoints (L12, L13, L14)

Scope: `internal/pki/nats.go`, `cmd/farmerbus`, `internal/api` (`routers.go`,
`handlers/pki.go`), `internal/pki/jwtusers.go`, deploy values, docs.

- **L12.** `PUT /pki/putnkey` is not registered when enrolment is on (the Helm
  default); in a standalone install it needs proof of possession of the NKey
  (a signature over a server nonce), and the revoke-by-rejection of an NKey that
  another row accepted never happens (`syncNatsAuth` skips it and logs). The test
  that pins the current behaviour (`pki_test.go`) changes with this.
  Correction (2026-10-18, fix/main-ci): T4's I7 makes `(tenant_id, nkey)`
  unique, so the store refuses the second row before any sync sees it; the
  sync's skip stays as a second guard, tested on its own
  (`TestRevokeUnlessAccepted`).
- **L13.** The bus does not log at Trace or Debug unless `IMAS_BUS_LOG_LEVEL`
  says so (`info` default; `debug` and `trace` accepted), and the chart does not
  set them. Prove with a test that, at the default level, a published payload
  does not appear in the log.
- **L14.** A single-node bus does not serve before its SYS JWT is loaded (it
  reports not ready and refuses clients); the SaaS API user JWT gets an `exp`
  (default 24h, refreshed before it runs out by the same path as other JWTs; test the
  refresh).

Corrections from the T6 build (2026-10-17):

- **L12.** No enrolment setting existed: `POST /v1/enroll` and
  `PUT /pki/putnkey` were both always registered. Farmer now has
  `enrollment` (default `true`; the Helm chart always renders `true`, which
  `farmer.extraConfig` cannot override). With it on, `PUT /pki/putnkey` is
  not registered; with it off (standalone), `POST /v1/enroll` is not, and
  `PUT /pki/putnkey` needs a signature over a nonce from the new
  `GET /pki/nkeynonce`. The tests that pinned the old behaviour were the
  sprout client's in `internal/pki/pki_test.go`, as the brief says, and
  also the handler's in `internal/api/handlers/pki_test.go` and the
  router's in `internal/api/routers_test.go`. The sprout client
  (`pki.PutNKey`) had no caller; it now signs the nonce, so the legacy
  protocol keeps a client that matches it. The rebuild in `syncTenantSprouts`
  (`internal/pki/tenant.go`) had the same revoke-by-rejection as
  `syncNatsAuth` and is fixed the same way.
- **L14, single node.** The bus cannot tell "its SYS JWT is loaded" from its
  own resolver: when core has never re-signed the SYS account, the loaded
  JWT is the bootstrap one. The signal is the account loader's readiness
  (it is ready only once the node holds the bucket's SYS account):
  `IMAS_BUS_LOADER_READY_URL`, set by the nats chart for a single node.
  Until it answers 200 the node refuses every client handshake not from
  the pod's loopback address (the loader's), every websocket handshake,
  and reports not ready.
- **L14, SaaS API JWT.** No scheduled path re-published it: the publisher
  ran only as a post-deploy hook. The refresh path is that publisher, now
  also a CronJob (`credentialPublisher.refresh.everyHours`, every 4 hours);
  it writes a new JWT once a third of the lifetime
  (`IMAS_SAASAPI_USER_JWT_TTL`, `credentialPublisher.userJWTTTL`, 24h) is
  left, the gateway JWT's two-thirds rule. saasapi read its JWT once from an
  env var, so a refreshed JWT would reach it only through Reloader; it now
  takes `SAASAPI_NATS_USER_JWT_FILE` (the chart mounts the JWT), re-reads
  it at every reconnect and reconnects when it changes.
- **L13.** The chart never set debug or trace; a chart test now pins that
  it does not. `tools/loadtest`'s `-bus-trace` said it matched
  `cmd/farmerbus`'s always-on trace; it now defaults to off, as farmerbus.
