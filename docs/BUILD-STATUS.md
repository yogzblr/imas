# Build Status

Tracks Wave 0 (the nine workstreams from `docs/claude-code-parallel-build-plan.md`
section 1, task briefs 1.1–1.9), Wave 1 (section 2), Wave 2 (section 3), the
"ongoing" Windows/Linux ingredient batch (section 4), and everything merged
since — the repo rebrand, CI setup, the Helm charts, and workstream M
(Windows packaging + Ansible). Refreshed 2026-09-27 against `git log` on
`main`; see "Notes" at the bottom for what changed in this pass. Refreshed
again later the same day by the docs-refresh pass (architecture diagram,
SaaS API reference, `INSTALL.md`), which closed the Envoy/EdDSA gap and
recorded two payload-encryption gaps it found; see "Docs-refresh pass" in
the Notes.

**Repository-history note, read before trusting a PR number below:** this
repo (`yogzblr/imas`) was created by detaching from `yogzblr/grlx` while
keeping full commit history (see the `Rebrand: grlx -> imas` commit,
`b4a0195`, 2026-09-26). GitHub PR numbers are per-repo counters, so every PR
number cited for work merged **before** `b4a0195` (all of Wave 0, Wave 1,
Wave 2, and the ongoing ingredient batch below) refers to a PR on the old,
superseded `yogzblr/grlx` repo — those numbers do not resolve on
`yogzblr/imas` and may collide with an unrelated, real PR number here (e.g.
old "#20"/"#21"/"#22" below are different PRs from the current, real
`yogzblr/imas` #20/#21/#22 in the Workstream M section). The commit hashes
in backticks are stable across the rename and are the reliable way to find
this work; PR numbers for anything merged **after** `b4a0195` are real,
live `yogzblr/imas` links.

## Wave 0

Six of the nine were already implemented and merged in this repo before the
Wave 0 dispatch ran — verified against the tree and skipped rather than
re-dispatched. The other three (F, L, SaaS-API-scaffold) were dispatched as
new cloud sessions and have since been merged (PRs #12–#14).

| Workstream | Description | Cloud session ID | Status | Needs security review |
|---|---|---|---|---|
| B | Replace custom NKey allow-list with NATS decentralized JWT auth (Operator → Account-per-tenant → User-per-sprout) in `internal/pki/` | already merged — PR #3 (`d1c66a6`, `ccddc1d`) + PR #8 (`2e8788d`, `3dd7247`); not dispatched this run, no session ID recorded | merged | y |
| D | Queue-group fix: `nc.Subscribe` → `nc.QueueSubscribe(subject, "imas-core", ...)` in `internal/natsapi/router.go`, plus reviewed `internal/jobs/listener.go` / `internal/facts/listener.go` fan-out | already merged — PR #2 (`26c8c05`); not dispatched this run, no session ID recorded | merged | n |
| F | Replace `internal/certs/tls.go`'s self-signed local CA (`genCACert`, `GenCert`, `RotateTLSCerts`, `forceRegenCert`) with OpenBao's PKI secrets engine + lease-renewal rotation | session_01SP3JBj5AYgDn2rh5hND3t1 | merged — PR #13 (`6be145d`, `5b76626`) | y |
| G.1+G.3 | Windows SCM-backed service provider (`golang.org/x/sys/windows/svc/mgr`) + new registry ingredient (`golang.org/x/sys/windows/registry`) | already merged — PR #5 (`7e537ee`); not dispatched this run, no session ID recorded | merged | n |
| G.5+G.8+G.9 | Windows SMBIOS hardware/BIOS facts, PowerShell-module batch (win_servermanager, win_dsc, win_psget, win_iis, win_pki, win_snmp, win_smtp_server, win_appx), CLI-tool batch (win_firewall/netsh, win_dns_client, win_auditpol, win_powercfg, win_certutil) | already merged — PR #7 (`940368b`); not dispatched this run, no session ID recorded | merged | n |
| H.4+H.5 | Linux mount/fstab ingredient (`golang.org/x/sys/unix` + `/etc/fstab` parser, cmd fallback for NFS/CIFS) + per-user crontab ingredient | already merged — PR #4 (`d47e429`, `0f5479a`); not dispatched this run, no session ID recorded | merged | n |
| L | Sprout atomic ingredients (`probe.http`, `probe.database`, `wait`, `file.sync`, `file.line`, `file.copy` enrichment) + cook-engine primitives (`cond`, `on_exit`, variable registration/passing with `sensitive:true`, runtime context vars) | session_01USpHZSU9DKecaet3HpxduN | merged — PR #14 (`9fc3f12`, `0a211b1`, `c8bad91`, `851099c`) | y (redaction path only) |
| K | Sprout-side `SecretProvider` v1 tier behind `sdb://` (OpenBao/customer Vault via client cert, Azure/AWS/GCP via managed identity) | already merged — PR #6 (`ebe3be3`); not dispatched this run, no session ID recorded | merged | n |
| SaaS-API-scaffold | New SaaS API service: `/tenants` CRUD + status, `/tenants/{tenant_id}/enrollment-keys` (key_id/key_hash split), GORM against the `saas` schema | session_01QrtzRidQPugaJ8HgWRfoEC | merged — PR #12 (`7613b67`, `6646798`) | y (enrollment-key hashing/lookup) |

Workstream A (PXC/Valkey/object storage — not part of Wave 0, but a Wave 1
gate) is also confirmed merged: `20eb7cd` on `master`.

## Wave 1

Dispatched once B and A were confirmed merged to `master`; both are now
merged themselves (C via PR #20, H via PR #21, plus a review follow-up
PR #22/#23 that split sprout identity into a paired NATS User JWT + gateway
JWT and updated the design docs).

| Workstream | Description | Cloud session ID | Status | Needs security review |
|---|---|---|---|---|
| C | Split `cmd/farmer/main.go` into two deployables — DMZ bus process (`farmerbus`, `RunNATSServer()`) and non-DMZ core process (`farmer`, `ConnectFarmer()`), wired to workstream B's JWT push mechanism | session_01JLfTEGP4UW6hZpPADc8ftD | merged — PR #20 (`629e4bc`) | n |
| H | Envoy JWT-gated gateway (`deploy/envoy/`) in front of NATS + recipe-download route, plus the enrollment endpoint (`POST /v1/enroll`, token redemption against `saas.enrollment_keys`, issuing JWT + NKey + tenant X25519 pubkey + gateway JWT) | session_01CGL1nDaq9RrXK2nAttjwf3 | merged — PR #21 (`373c844`, `f2a6fe7`, `1b81abc`, `de0958a`) | y — literal front door of the trust chain |

**Verification gap left by H's merge: closed (2026-09-27).** H's sandbox
had no network, so `jwt_authn`'s EdDSA support was first checked only
against `jwx`'s library-level round-trip. It has since been checked against
real Envoy three times:

1. **In this docs-refresh session**, against the official Envoy **v1.35.3**
   release binary (`envoy-1.35.3-linux-x86_64` from the GitHub release,
   sha256 `241c1702f0ed1c0dba31339abaab422906a4295cc92640f5b832c131ee385767`,
   `envoy --version`: `ff3fe7f0…/1.35.3/Clean/RELEASE/BoringSSL`), which
   is the version `deploy/helm/nats/values.yaml` pins:
   `IMAS_TEST_ENVOY_BIN=<that binary> go test ./internal/pki/ ./internal/api/ -run ThroughRealEnvoy -v`.
   Both suites passed: `TestSproutLifecycle_ThroughRealEnvoy` (5/5
   subtests) and `TestSproutDownloadsStagedRecipe_ThroughRealEnvoy` (4/4).
   They run the shipped `deploy/envoy/envoy.yaml` and cover a real
   `POST /v1/enroll` through Envoy (NKey proof of possession), the `wss://`
   upgrade accepted with a valid EdDSA gateway JWT and refused with a
   missing, expired or forged one, `/v1/refresh`, and `/files/`. OpenBao
   Transit is stubbed in these suites; the Ed25519 signatures and JWKS are
   real.
2. `deploy/envoy/testing/README.md` records the same suites passing on
   v1.34.1 and v1.35.3.
3. `deploy/helm/nats/README.md` ("Verification status") records the real
   `cmd/sprout` binary enrolling through the chart's `envoyproxy/envoy:v1.35.3`
   with **real** OpenBao signing the EdDSA gateway JWT: 1 websocket upgrade
   and 3 `jwt_authn` allows, 0 denies.

What this does **not** cover: `deploy/envoy/testing/docker-compose.keycloak.yml`
is not an Envoy test. It's a separate harness that checks farmer's JWKS
against Keycloak as a second, independent JOSE consumer, and it has still
never been run. The docs-refresh session has the Docker CLI but no running
daemon, and starting one there wasn't permitted, so it couldn't run it
either. The Envoy question is settled without it; the Keycloak cross-check
remains open as a nice-to-have (see Notes).

## Wave 2

Dispatched now that A and H are confirmed merged to `master`. J's brief was
updated post-H-merge to close a real gap H's enrollment endpoint left open
(no `sprout_pub` field yet) — verified against `internal/pki/enroll.go` and
`internal/api/handlers/enroll.go` before dispatching, confirmed accurate. All
three are now merged; J landed first, then E needed a follow-up commit to
resolve merge fallout against J's box-key tenant scoping.

| Workstream | Description | Cloud session ID | Status | Needs security review |
|---|---|---|---|---|
| E | Multi-tenancy: NATS Account-per-tenant (subjects unchanged), re-key `internal/pki/pki.go` by `(tenant_id, sprout_id)`, tenant field on `internal/rbac` cohort/role maps, dynamic `FarmerOrganization` | session_01SwBEMgMkSFan2X3fUC3pkz | merged — PR #28 (`c13d290`, `aeec2b8`) | y — tenant isolation correctness |
| I | Finish recipe storage migration: confirm A's recipe HTTP endpoint is served behind H's Envoy JWT-gated route, remove `internal/natsapi/recipes.go`'s old NATS-based delivery | session_01QKGaTno21cXoZGp7hrbjbM | merged — PR #25 (`e59eb65`) | n |
| J | Payload encryption + rotation: NaCl `box` (X25519), tenant keypair via OpenBao (replacing `internal/pki/tenantbox.go`'s interim local-disk custody), sprout keypair generated at enrollment. Must first add a `sprout_pub` field to the enrollment request/`Enroll()` (confirmed missing) | session_01AivbiHCYGgL1ywzyTViaK2 | merged — PR #27 (`f5a947d`); the three gaps below are closed by the J follow-up on `claude/tender-cerf-kudmy3` (**in review**), which leaves the open items listed under it | y — cryptographic code defending against a compromised DMZ bus |

**Gaps in J as merged (found by the docs-refresh pass, 2026-09-27, by
reading the code):** no payload was encrypted (`PublishEncryptedTo` /
`DecryptEncryptedFrom` had no callers, and the sprout had no NaCl-box
code); the "tenant" keypair was one per deployment (`tenantbox.go` read a
single KV path and `pki.Enroll` handed every tenant the same
`tenant_x25519_pub`); and there was no tenant key rotation tooling, the
design's accepted mitigation for having no forward secrecy.

**J follow-up (branch `claude/tender-cerf-kudmy3`, in review, FLAG FOR
SECURITY REVIEW).** What it changes:

- **One keypair per tenant.** `internal/pki/tenantbox.go` keeps each
  tenant's keypair in its own KV v2 secret,
  `<IMAS_TENANTBOX_OPENBAO_KV_PATH>/tenants/<tenant_id>`, and each
  rotation is a new KV version of it. Migration: the first time a tenant's
  secret is needed, it *adopts* the legacy shared keypair (still at
  `<KV_PATH>` itself, now read-only) if the tenant already has sprout box
  keys on record, i.e. sprouts pinned to the shared key; every other
  tenant gets a fresh keypair. `Enroll` reads the tenant key before
  recording the enrolling sprout's box key, so a new tenant's first sprout
  never counts. The Helm policy grants `…/tenants/+` (one segment) and
  read-only on the legacy path.
- **Rotation with authenticated re-pin.** `imas keys rotate-tenant-key
  [--sever]` (NATS `pki.rotatetenantbox`, RBAC `pki`, the caller's own
  tenant only) writes a new version. `/v1/refresh` and `/v1/enroll` now
  carry `tenant_x25519_continuity`: the new public key sealed to the
  sprout's box key under each retained earlier tenant key. A sprout whose
  pin differs re-pins only if that proof opens under its pinned key and
  names exactly the new key; otherwise `ErrTenantKeyMismatch`, fatal as
  before. The previous key keeps sealing and opening for
  `max(boxkeygraceduration, gatewayjwtttl)`. `--sever` (suspected
  exposure) gives no grace and no proof, so the tenant's sprouts must be
  re-enrolled.
- **`cmd.run` sealed end to end**, both directions
  (`internal/ingredients/cmd/sealed.go`, `internal/payloadbox`). Each
  message has a purpose (so a reflected message is refused), a sprout ID,
  a random ID and a timestamp. Replies name their request; the sprout
  refuses replays and stale messages, and refuses plaintext `cmd.run` once
  it has keys. Farmer refuses a plaintext reply to a sealed request (no
  downgrade). Only a sprout with no box key on record, i.e. enrolled
  before J, still gets plaintext, with a warning.
- **Box key substitution closed.** `imas.sprouts.*.boxkey.pub` used to
  accept a plaintext new key from anything on the bus, which would have let
  a compromised bus swap in its own key and read everything farmer sealed
  for that sprout. Farmer now only accepts a submission sealed under one of
  the sprout's current keys, and fresh; a superseded key is never made
  active again.

**Still open in J after the follow-up:**

- **`cook` is sealed end to end** (`internal/cook/sealed.go`): the
  dispatch on `imas.sprouts.<id>.cook` and its Ack, and the resync nudge
  and its Ack, with the same rules as `cmd.run` (own purpose pairs,
  ReplyTo binding, box-ready sprouts refuse plaintext, plaintext only for
  a sprout with no box key on record). A compromised bus can no longer
  inject a cook envelope into a box-ready sprout. Farmer's job-creation
  record, which `internal/jobs` used to read off the plaintext dispatch,
  is now written by the dispatching replica (`cook.SetDispatchRecorder`).
  The `fleetsigningkeys` reply was sealed earlier, in PR #31
  (`internal/fleetkeys`).
- **Every other boundary is still plaintext inside TLS**: cook's step
  events (`imas.cook.<id>.<jid>`), `test.ping`, `shell.*`, facts,
  `cancel`, the `boxkey.rotate` trigger, and sprout log shipping
  (`imas.sprouts.<id>.logs`). **`shell.*` now matters most**:
  `imas.sprouts.<id>.shell.start` spawns a PTY running the request's
  `shell` (default `/bin/sh`) from a plaintext request
  (`internal/shell/sprout.go`), so a compromised bus can still get an
  interactive shell on any Unix sprout. Sealing `cmd.run` and `cook`
  doesn't close command injection until it is sealed too. Cook's step
  events carry results, not commands, but
  they include each step's change notes and errors (secrets registered
  `sensitive` are already redacted). They are fire-and-forget publishes,
  not request/reply, and they are read in plaintext by
  `internal/jobs/listener.go` and `clilistener.go`,
  `internal/serve/logstream.go` and the imas CLI
  (`cmd/imas/cmd/cook.go`), which holds no tenant key. So sealing them
  needs its own design, e.g. farmer opening each event and re-publishing
  it for the CLI.
- **Adopted tenants still share the legacy private key** until each is
  rotated. Rotate them once their sprouts run this build; the `origin`
  field in each tenant's secret (`adopted-legacy`) shows which. Then the
  legacy secret can be deleted.
- **No scheduled rotation** in farmer itself; run
  `imas keys rotate-tenant-key` from a scheduler (e.g. a CronJob).
- ~~**Sprout-initiated box key rotation** has a farmer side but no sprout
  side, so a sprout's own box key never rotates yet.~~ **Closed, PR #34.**
  See "Post-rebrand work" below and `docs/design/imas-payload-encryption-design.md`'s
  "Sprout-side rotation, farmer-triggered only."
- **Rollout order:** upgrade farmer before sprouts. Sprouts built between
  J and this follow-up can't open sealed `cmd.run` (farmer reports
  `ErrReplyNotSealed`) and exit on any tenant key rotation. Upgrade them
  before rotating. A new sprout against an old farmer has its `cmd.run`
  refused, because the old farmer sends plaintext. Sealed `cook` behaves
  the same way: a box-ready sprout built before it can't read a sealed
  dispatch (farmer reports `ErrReplyNotSealed` and the sprout cooks
  nothing), and a sprout built with it refuses an old farmer's plaintext
  dispatch and nudge. Until both sides are upgraded, those sprouts still
  catch up on reconnect by pulling their staged recipe over HTTPS.
- **Live `cmd.run` output streaming** (`stream_topic`) is dropped for
  sealed requests: it publishes in plaintext to a subject the CLI reads
  directly without a tenant key. The full output still comes back in the
  sealed reply.
- `tenant_priv` is still read into farmer's memory (OpenBao Transit has
  no X25519 DH), as before.

## Ongoing / fully parallel (no gating)

| Item | Description | Cloud session ID | Status | Needs security review |
|---|---|---|---|---|
| D (facts listener) | `internal/facts/listener.go`'s `RegisterFarmerListener` still used plain fan-out `Subscribe`, justified by a stale comment from before workstream A removed `props/store.go`'s in-memory cache; queue-grouped it under `imas-core` to stop every replica double-writing the same PXC row on every fact update | not dispatched by this coordinator — found already merged | merged — PR #24, old-repo numbering (`e9aa2ea`) | n |
| G.2 | Windows user/group provider using `deploymenttheory/go-bindings-win32`'s netmanagement package | session_01ArigyXKLB5a2gV449zBGZB | **merged** — PR #32, old-repo numbering (`20a6ac5`) | y — user/group creation, and the dependency is young (v0.2.x) |
| G.4 | Windows DACL/ACL ingredient using `hectane/go-acl` for file ACLs, extended to registry-key ACLs (`SE_REGISTRY_KEY`) | session_01BVU6xoX7h7tzkscFYUTY8U | **merged** — `internal/ingredients/windacl/`, `hectane/go-acl` in `go.mod` | y — propagation/inheritance semantics are a security-relevant bug class |
| G.6 | Task Scheduler, Windows Update, and Shortcut COM ingredients using `go-ole/go-ole`, starting with Shortcut (IShellLink) to prove the COM lifecycle pattern | session_01GXJ5vf5Fdo9fMxdoFAe5rE | **merged** — `internal/ingredients/wintaskscheduler/`, `winupdate/`, `winshortcut/`, `go-ole/go-ole` in `go.mod` (`a49361a`, `cbd1fe0`) | y — COM lifecycle bugs (missed Release, wrong apartment threading) |
| G.7 | v1 subset of LGPO — parse `registry.pol` (`encoding/binary`) and ADMX/ADML (`encoding/xml`); PR proposes which policy subset to cover for a first pass | session_01XYVPKvrCssvaGQTd9MbEs3 | **merged** — `internal/ingredients/lgpo/` | n |
| H.1 | Linux network/route management using `vishvananda/netlink`, with a verify-connectivity-or-roll-back pattern in the ingredient itself | session_01Q9NMvFaiFykjHmvCpqSn36 | **merged** — `internal/ingredients/network/`, `vishvananda/netlink` in `go.mod` | n |
| H.2 | nftables firewall ingredient using `google/nftables` | session_015pQ7NBWmSxJFht6DQyrrbs | **merged** — `internal/ingredients/firewall/` (build-tagged `linux`, doc comment confirms this is the H.2 nftables ingredient, distinct from G.9's `winfirewall`), `google/nftables` in `go.mod` | y — a firewall ingredient can lock out or expose a host |
| H.3 | SELinux ingredient using `opencontainers/selinux` | session_012DtUVSVbEHb11Uz4KzW4Tt | **merged** — `internal/ingredients/selinux/`, `opencontainers/selinux` in `go.mod` | y — CERT-In/DPDP-relevant: silently degrading to permissive is compliance-visible |

Before dispatching, validated against `master` that none of the seven were
already implemented: no ACL/DACL, Task Scheduler/WUA/Shortcut, LGPO,
netlink/route, nftables, or SELinux ingredient existed, and none of their
named dependencies (`go-bindings-win32`, `hectane/go-acl`, `go-ole/go-ole`,
`vishvananda/netlink`, `google/nftables`, `opencontainers/selinux`) were in
`go.mod`. The existing `winfirewall` ingredient is G.9's already-merged
`netsh advfirewall` wrapper, not H.2's Linux nftables ingredient — confirmed
by reading its imports before ruling H.2 not done. **All seven are now
confirmed merged** (re-verified 2026-09-27: every listed package/ingredient
directory and `go.mod` dependency is present on `main`) — the "dispatched"
status this table originally recorded was stale.

## Post-rebrand work (not part of the original Wave 0–2 plan)

Everything below merged to `main` after `b4a0195` (the `grlx` → `imas`
rebrand), on real, current `yogzblr/imas` PR numbers. None of it was
dispatched from `claude-code-parallel-build-plan.md` — it was tracked
directly in this session instead.

| Item | Description | Status |
|---|---|---|
| Rebrand + CI setup | `Rebrand: grlx -> imas` (`b4a0195`); added `build.yml` (Linux/Windows cross-compile + farmer Docker); made `snapshot.yml`/`release.yml` manual-only until publish secrets exist on the new repo; `govulncheck`/`go-licenses` CI fixes | merged (`b4a0195`, `e7c8860`, `65e59e1`, `0d1b975`) |
| Helm charts | Chart for farmer (core) and saasapi, with optional PXC/OpenBao/Valkey subcharts | merged — PR #17 (`b5a418d`) |
| Farmer bus/CLI separation | Separated farmer's bus address from its API interface address (`farmerinterface`); `imas` CLI now reads `farmerbusurl` and verifies the bus via `BusTLSServerName` instead of assuming they're the same host | merged — PR #18 (`f30b9dd`), PR #19 (`01b4013`) |
| **Workstream M.1** — Windows SCM service wrapper for the sprout binary | `golang.org/x/sys/windows/svc` lifecycle hooks so `imas-sprout.exe` itself runs under the Windows SCM (install/uninstall/start/stop/status via `svc/mgr`, no SIGINT/SIGTERM handling under the SCM, rotating file log) — distinct from G.1's *ingredient* for managing other Windows services | merged — PR #22 (`cfdb73f`, `54d70f4`, `f2fa7fa`, `8b9b388`, `718928e`) |
| **Workstream M.2** — MSI installer + winget package | MSI via `wixl`/`msitools`, winget NuGet package published to the public `imasnget` Buildkite feed on release, sprout starts itself post-upgrade | merged — PR #21 (`1c6a2a5`, `65bc985`) |
| **Workstream M.3** — SUSE rpm validation | `zypper`-specific check on the existing `nfpm`-built rpm packaging | merged — folded into PR #21 (`1c6a2a5`'s "SUSE RPM check") |
| **Workstream M.4** — customer-run Ansible playbooks | `ansible/roles/imas_sprout` (adds the Buildkite apt/yum/zypper repo or does `win_package`, merges enrollment settings into the sprout's existing config file via drift-detection rather than overwriting it — the sprout itself writes back `sproutid` and empties `jointoken` post-enroll — `no_log` + mode `0600` on the join token) + `ansible/roles/imas_verify` (polls a custom `imas_sprout_bus_status` module for connected state, fails clearly on timeout). Molecule scenario (`ansible/molecule/default/`, a stub farmer + Rocky/Debian/openSUSE Leap 15.6 containers) wired into CI (`.github/workflows/molecule.yml`: `ansible-lint`, `pytest`, `molecule test`). Along the way, caught and fixed two real packaging bugs found while building the playbooks: `packaging/etc/imas-sprout.conf` had `farmerapiport` misspelled `farmeripoprt` (silently ignored, masked by the value matching the default), and `packaging/etc/imas-farmer.conf` had a tab-indented `pubkeys` list (invalid YAML, `LoadConfig` would panic) plus a stale `organization:` key (farmer reads `farmerorganization`) — a new regression test, `internal/config/config_files_test.go`, now statically checks every packaged/testing config's keys against what the code actually reads via `jety`. | **merged** — PR #24 (`0ea6384`), PR #25 (`7377ba9`, `ef36998`, `6c630b7`, `7d3a70e`, `930f191`, `7356668`), PR #26 (`edca7ac`), PR #28 |
| **New: Terraform UAT gate** | Provision per-OS VMs, install a tagged release's actual Buildkite-published packages via the M.4 playbooks, smoke-test enrollment/recipe-run/reboot survival. Not in the original roadmap; added as a release-quality gate. Task brief drafted in `docs/claude-code-parallel-build-plan.md` §4a (item 5), including an explicit flag that its default compute-provider choice (libvirt/KVM) needs a human sign-off, not just green tests. | **open, unblocked** — M.4 (its dependency) is now merged; not yet dispatched |
| J follow-up: per-tenant tenant keypairs, tenant key rotation with authenticated re-pin, `cmd.run` sealed end to end, box key submissions sealed | See "J follow-up" under Wave 2. FLAG FOR SECURITY REVIEW | **in review** (`claude/tender-cerf-kudmy3`) |
| Docs refresh (architecture diagram, SaaS API reference, `INSTALL.md`, this file, `packaging/systemd/*.service` vs `docs/*.service` dedup) | Done on branch `claude/sweet-sagan-yklpu8`: `docs/diagrams/imas-architecture.svg` replaces `grlx-arch-light.png`; `docs/api/saasapi.md` + `docs/api/saasapi-openapi.yaml` (all 18 `NewRouter` routes, the 2 dispatch routes marked off by default); `INSTALL.md` rewritten for tenants, enrollment keys, the SaaS API and Envoy; `docs/imas-{farmer,sprout}.service` removed in favour of `packaging/systemd/` | merged — PR #23 |
| J: seal `cook` dispatch and resync nudge end to end | See "As built (J follow-up)" under Wave 2. Closes the highest-priority item on the "still plaintext" list: a compromised bus can no longer inject either a command (`cmd.run`) or a recipe (`cook`) onto a box-ready sprout. Also moved farmer's job-creation recording off the (now sealed) plaintext dispatch onto an explicit hook (`cook.SetDispatchRecorder`). FLAG FOR SECURITY REVIEW | merged — PR #32 (`d2692c8`, `6f1ac36`, `bf5956c`) |
| H: sprout outbound proxy support for the bus connection (requirements.md item 8) | New sprout config key `busproxyurl` (`http://` HTTP CONNECT or `socks5://`); `pki.LoadSproutBus` wires it as nats.go's `CustomDialer`, covering `wss://`, `tls://` and `nats://` alike, with `nats.SkipHostLookup` so the proxy resolves the bus host. The sprout's HTTP clients already covered this via `ProxyFromEnvironment`; this closes the one real gap (the bus connection itself) | merged — PR #33 (`924e9dc`, `ac523c1`) |
| J: sprout side of farmer-triggered box key rotation (requirements.md item 15) | Closes "sprout-initiated box key rotation has a farmer side but no sprout side." Farmer-triggered only, no sprout-side scheduling. New key held `pending` until confirmed by the first farmer payload that opens under it; replaced key kept `previous` for `sproutboxkeyprevgrace` (default 15m, floored at `2×DefaultMaxSkew`). Along the way, found and fixed a real gap: `sproutPermissions` never granted the `boxkey.pub` publish subject at all, so every submission was refused as a Permissions Violation until this PR added it (existing sprouts pick it up via JWT re-mint on next refresh). See `docs/design/imas-payload-encryption-design.md`'s "Sprout-side rotation, farmer-triggered only." FLAG FOR SECURITY REVIEW | merged — PR #34 (`8eb23da`, `8384084`, `7b9d80d`) |
| Ansible + packaging: expose `busproxyurl` and `sproutboxkeyprevgrace` | `ansible/roles/imas_sprout` variables `imas_sprout_bus_proxy_url` / `imas_sprout_boxkey_prev_grace` (drift-managed the same way as `busurls`), `packaging/etc/imas-sprout.conf` commented examples, `ansible/README.md` variable table | **done, this pass** (docs/ansible only, no application code) |

## Notes

- "Needs security review" reflects only workstreams whose task brief in
  `claude-code-parallel-build-plan.md` includes the literal line
  "FLAG FOR SECURITY REVIEW." Per `CLAUDE.md`, none of the flagged
  workstreams should be treated as "done" or "safe to merge" even after
  their tests pass — only as "ready for review."
- The six pre-existing Wave 0 workstreams were confirmed directly against the
  repo (code present, tests present, commits/PRs identified in `git log`)
  rather than re-run, per instruction to skip work already done.
- All of Wave 0, Wave 1, Wave 2, and the "ongoing" G.2/G.4/G.6/G.7/H.1/H.2/H.3
  batch are now confirmed **merged** — every workstream from
  `docs/claude-code-parallel-build-plan.md` sections 1–4 is merged. The
  Envoy/EdDSA verification gap noted under Wave 1 is now closed (see
  there). "Merged" isn't "complete" for J, though: see its open gaps
  under Wave 2.
- **2026-09-27 refresh:** this file had drifted since the `grlx` → `imas`
  rebrand (`b4a0195`) — it hadn't been touched since the ongoing batch was
  *dispatched*, and never recorded that batch actually landing, nor any of
  the post-rebrand work (CI setup, Helm charts, the farmer bus/CLI split,
  or workstream M's Windows packaging). This pass: (1) re-verified all seven
  ongoing-batch items against `go.mod` and `internal/ingredients/` and
  flipped them from "dispatched" to "merged"; (2) added the
  repository-history note at the top, since PR numbers before the rebrand
  are on the old, superseded `yogzblr/grlx` repo and can numerically collide
  with real, current `yogzblr/imas` PR numbers; (3) added the "Post-rebrand
  work" section above documenting the rebrand/CI setup, the Helm charts, the
  farmer bus/CLI split, and workstream M (M.1–M.3 merged, M.4 and the new
  Terraform UAT gate still open); (4) recorded the docs-refresh task
  (architecture diagram, SaaS API reference, `INSTALL.md` rewrite, this
  file, `*.service` dedup) as drafted but not yet dispatched.
- ~~Still genuinely open, in priority order: the Envoy/EdDSA-against-real-Envoy
  verification (Wave 1, needs Docker), workstream M.4 (Ansible playbooks),
  the Terraform UAT gate, and the docs refresh.~~ Superseded by the
  docs-refresh pass below.
- **Docs-refresh pass (2026-09-27).** Closed: the Envoy/EdDSA verification
  (see Wave 1; run against the real v1.35.3 binary, which needed no
  Docker), and the docs refresh itself (in review). Newly recorded as open,
  from reading the code while documenting it: J's two gaps (payloads not
  yet encrypted; one tenant keypair per deployment). Minor inconsistencies
  it found and left alone, since they're outside a docs change:
  - `packaging/systemd/imas-{farmer,sprout}.service` set
    `Environment=IMAS_CONFIG=…`, which no code reads: the config paths are
    fixed (`internal/config.LoadConfig`).
  - `packaging/etc/imas-farmer.conf` uses `organization:`, but farmer reads
    `farmerorganization`. *(Fixed in yogzblr/imas#25, along with a tab that
    made the file invalid YAML; `internal/config` now tests that every key
    in `packaging/etc/*.conf` is one the code reads; the docker-compose
    fixtures under `testing/` are covered too.)*
  - `packaging/systemd/imas-{farmer,sprout}-standalone.service` aren't
    referenced by `.goreleaser.yaml` or anything else.
  - `router.go` and `fleet_update_dispatch.go` cite `yogzblr/imas#286` for
    the disabled sprout self-update path. That number predates the rename
    and returns 404 on `yogzblr/imas`; the underlying blocker (design doc
    §2.3 backup/restore) is still open, and dispatch stays off by default.
  - farmerbus and saasapi have no OS package, systemd unit or published
    image; `INSTALL.md` says so.
  - `README.md`'s "Architecture" and "Batteries Included" prose still
    describe a farmer with an embedded bus. Only its diagram link was fixed.
- **2026-09-27, later same day: M.4 merged.** Workstream M.4 (customer-run
  Ansible playbooks) landed across PR #24, #25, #26, and #28, after the
  docs-refresh pass above had already run — that's why the "Post-rebrand
  work" table's M.4 row above and the two "still open" lists elsewhere in
  this file were briefly stale. Spot-checked directly (not just taken on
  faith): `ansible/roles/imas_sprout`'s config-merge task does drift
  detection against the sprout's own live config rather than overwriting it
  wholesale (the sprout writes back `sproutid` and empties `jointoken` after
  enrolling), keeps the join token out of logs and behind file mode `0600`,
  and PR #25's fixes were real bugs (a misspelled `farmerapiport` key and
  invalid-YAML tab indentation in the shipped packaging configs, both now
  covered by a new static regression test). The Molecule scenario is wired
  into CI (`.github/workflows/molecule.yml`) rather than left as a
  local-only check. `go test ./internal/config/...` was **not** run in this
  validation pass — this sandbox's Go toolchain can't fetch `go1.26.6`
  (`go.mod` requires it) because `proxy.golang.org` isn't on the egress
  allowlist here — so the new config-key test is verified by reading it,
  not by executing it.
- **2026-09-27, later same day: `cook` sealing, sprout bus proxy support,
  and farmer-triggered sprout box key rotation merged (PRs #32–#34)**, plus
  the ansible/packaging follow-up exposing the two new sprout config keys
  (`busproxyurl`, `sproutboxkeyprevgrace`) as role variables. Requirements
  RAG (requirements.md; tracked in chat, not yet a doc in this repo):
  item 8 (sprout proxy support) and item 15 (sprout key rotation) both
  close out; item 14 (payload encryption) narrows to `shell.*` as the
  highest-remaining-priority plaintext boundary (an interactive PTY from a
  plaintext request), everything else on the "still plaintext" list above
  being lower severity by design (read by the UI/CLI, which hold no
  tenant key) or already accepted (the `boxkey.rotate` trigger itself).
- **Still genuinely open, in priority order:** `shell.*` sealing (now the
  most security-relevant remaining payload-encryption gap), the Terraform
  UAT gate (M.4, its one dependency, is now merged — this can be
  dispatched), scale/latency validation against `imas-1m-scale-plan.md`
  and the master plan's <300ms SLA (requirements.md items 1 and 10 — no
  load test has ever run), and, as a nice-to-have, running the Keycloak
  JWKS harness somewhere with a Docker daemon.
