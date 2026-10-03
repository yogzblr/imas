# Build Status

Tracks every workstream against the numbered requirements in
`docs/design/requirements.md`: Wave 0, Wave 1, Wave 2, the "ongoing"
Windows/Linux ingredient batch, the post-rebrand work (CI, Helm charts,
workstream M), and Wave 4 (fleet updates and DB migrations). Refreshed
2026-10-02 against `main` at `1098b47` (PR #59): every item that was
"designed, not built" on 2026-09-29 has since merged except the Terraform UAT
gate, which has not been started. See "Requirements traceability" for the
requirement-by-requirement view and "Notes" for what changed in this pass.

**How this was verified.** By reading the code on `main` (packages, routes,
migrations, Helm templates, tests) and the merge history, and by CI results:
CI, Build, govulncheck, Docs, CodeQL and Gitleaks all passed on `1098b47`.
The Go toolchain this was written from can't fetch `go1.26.6`, so no test was
run locally; "merged" means reviewed and green in CI, not exercised on real
hosts. Nothing here has run against production-shaped infrastructure: that is
what the Terraform UAT gate and the load tests below are for.

**No release has ever been cut.** `yogzblr/imas` has no tag and no GitHub
release, and neither `release.yml` nor `publish-packages.yml` has run once.
Everything that depends on a published artifact (the Buildkite registries the
Ansible role installs from, the signed GHCR images, the Helm charts in
`imashelm`, the stamped sprout release) is written and reviewed but untried.

## Requirements traceability

Status against `docs/design/requirements.md`. "Built" means the code is on
`main` and its tests pass in CI; "validated" means exercised somewhere
beyond unit tests (real Envoy, Molecule containers, real OpenBao).

| # | Requirement | Status | Evidence / gap |
|---|---|---|---|
| 1 | 1M endpoints | **Not validated; two scale-plan items not built** | Storage (PXC, Valkey, object storage) and queue-grouped core are built. Not built: (a) **reconnect jitter**: the sprout still uses a fixed `ReconnectWait(15s)` with unlimited retries (`cmd/sprout/main.go`), and `nats.CustomReconnectDelay` appears nowhere; at 1M sprouts a bus restart is a thundering herd, which Phase 2 of the scale plan called out; (b) **a clustered bus**: `cmd/farmerbus` does not read cluster routes, so the nats chart refuses `bus.replicaCount > 1` unless `bus.cluster.routesSupported` is set, and nothing sets it truthfully yet. No load or chaos test has ever run and no harness is in the repo. |
| 2 | DMZ / non-DMZ split | Built | `cmd/farmerbus` (DMZ) vs `cmd/farmer` (core, outbound only); Helm charts `deploy/helm/nats` and `deploy/helm/farmer`, with NetworkPolicies. |
| 3 | Windows and Unix | Built, **not validated on Windows hosts** | Full G.1–G.9 ingredient set, SCM service wrapper, MSI. Windows paths are cross-compiled and unit-tested; the self-update MSI path is tested with `msiexec` mocked. The Terraform UAT gate would be the first real-host run. |
| 4 | Deployment automation with Ansible | Built, validated | `ansible/roles/imas_sprout` and `imas_verify`, Molecule CI on Rocky, Debian and openSUSE Leap. |
| 5 | JWT auth to the NATS websocket; enrollment key only to bootstrap | Built, validated | NATS User JWT plus gateway EdDSA JWT; `POST /v1/enroll`; run through real Envoy v1.35.3. |
| 6 | Per-sprout JWT | Built, validated | Paired JWTs minted at enrollment and refresh. |
| 7 | Farmer horizontally scalable | Built, not load-tested | Core is stateless: `QueueSubscribe` on `imas-core`, PXC read-through, Valkey heartbeat, object-store recipes. The bus tier is single-node until farmerbus supports routes (see 1). |
| 8 | Sprout via proxies | Built | `busproxyurl` (HTTP CONNECT / SOCKS5) for the bus connection; HTTP clients use `ProxyFromEnvironment`. Ansible variable exposed. |
| 9 | Recipe download from a configured HTTP endpoint | Built, validated | `/files/` behind Envoy; `TestSproutDownloadsStagedRecipe_ThroughRealEnvoy`. |
| 10 | NATS response under 300 ms | **Not validated** | Design removes the synchronous probe loop; no latency measurement has been taken. |
| 11 | Recipe download uses the same JWT | Built, validated | Same gateway JWT, same Envoy gate. |
| 12 | Envoy with JWT validation in front of NATS | Built, validated | `deploy/envoy/envoy.yaml`, `jwt_authn` with remote JWKS; checked against real Envoy. Keycloak JWKS cross-check harness has never been run (nice-to-have). |
| 13 | Backend on Kubernetes (NATS, Valkey, farmer, Percona) | Built | Helm charts with optional PXC/OpenBao/Valkey subcharts; single migration hook Job; sprout-release hook Job. Chart tests render them; no gate has installed them on a real cluster. **No Terraform exists yet** (see the UAT gate row). |
| 14 | Payload encryption, key pair per sprout and per tenant | **Partly built** | Per-tenant and per-sprout X25519 keys; `cmd.run`, `cook` and box-key submissions are sealed end to end. **`shell.*` (interactive PTY) is still plaintext inside TLS**, as are cook step events, `test.ping`, facts, `cancel`, the rotate trigger and log shipping. `shell.*` is the one that matters: a compromised bus can still open a shell on a Unix sprout. |
| 15 | Key rotation for sprout keys | Built, **deliberately differs from the wording** | The requirement text says the new private key is sent encrypted over NATS. The built design never transmits a private key: the sprout generates the new pair and submits only the public key, farmer-triggered. See `imas-payload-encryption-design.md`. `requirements.md` should be reworded to match (see "Open items"). |
| 16 | SDB-equivalent secrets in the sprout | Built (v1 tier) | `internal/ingredients/sdb`: OpenBao/Vault (hot-reloaded client cert), Azure Key Vault, AWS Secrets Manager, GCP Secret Manager. CyberArk and Delinea (Tier 2) not built, by design. |
| 17 | Probe capability (database, HTTP) as a sprout task | Built | `probe.http`, `probe.database`, plus `wait`, `cond`, `on_exit`, registered variables with `sensitive` redaction. |
| 18 | Installers: yum, apt, zypper, MSI | Built, **never published** | nfpm deb/rpm/apk, SUSE rpm check, MSI and winget package, and the workflow that uploads them to the Buildkite registries. No release has ever been cut (see "Release flow" below), so the registries hold no imas packages and nothing has exercised the upload. |
| 19 | Ansible with one-time key | Built, validated | Join token handled `no_log`, mode `0600`, removed by the sprout after enrollment. |
| 20 | Fleet updates from the sprout's configured repo | Built, **dispatch off by default** | FU.0–FU.7, FU.6b merged (below). `SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED` stays `false`, in the Helm chart too, until security review and the UAT gate. Linux path has an end-to-end test against a real repository (Nexus); Windows is mock-tested only. |
| 21 | Licensing | Built | Apache/MIT default; PXC and MPL-2.0 exceptions recorded; goose (MIT) added; dependency licence files refreshed by the `go-licenses` workflow. |

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
| J | Payload encryption + rotation: NaCl `box` (X25519), tenant keypair via OpenBao (replacing `internal/pki/tenantbox.go`'s interim local-disk custody), sprout keypair generated at enrollment. Must first add a `sprout_pub` field to the enrollment request/`Enroll()` (confirmed missing) | session_01AivbiHCYGgL1ywzyTViaK2 | merged — PR #27 (`f5a947d`); the three gaps below are closed by the J follow-up on `claude/tender-cerf-kudmy3` (merged, PR #30, `60c39a2`), which leaves the open items listed under it | y — cryptographic code defending against a compromised DMZ bus |

**Gaps in J as merged (found by the docs-refresh pass, 2026-09-27, by
reading the code):** no payload was encrypted (`PublishEncryptedTo` /
`DecryptEncryptedFrom` had no callers, and the sprout had no NaCl-box
code); the "tenant" keypair was one per deployment (`tenantbox.go` read a
single KV path and `pki.Enroll` handed every tenant the same
`tenant_x25519_pub`); and there was no tenant key rotation tooling, the
design's accepted mitigation for having no forward secrecy.

**J follow-up (branch `claude/tender-cerf-kudmy3`, merged as PR #30, FLAG FOR
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
  (`internal/fleetkeys`); CL.1 has since removed that subject and package.
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
| **New: Terraform UAT gate** | Provision per-OS VMs, install a tagged release's actual Buildkite-published packages via the M.4 playbooks, smoke-test enrollment/recipe-run/reboot survival, and now also one self-update cycle (FU.2) per OS. Task brief is in `docs/claude-code-parallel-build-plan.md` §4a (item 5), including a flag that the default compute-provider choice (libvirt/KVM) needs a human sign-off. | **not started — no `.tf` files, modules or workflow exist in the repo.** Every dependency (M.4, the release flow, FU.2) is now merged, so it is unblocked and is the main remaining delivery item |
| J follow-up: per-tenant tenant keypairs, tenant key rotation with authenticated re-pin, `cmd.run` sealed end to end, box key submissions sealed | See "J follow-up" under Wave 2. FLAG FOR SECURITY REVIEW | merged — PR #30 (`60c39a2`); still flagged for security review |
| Docs refresh (architecture diagram, SaaS API reference, `INSTALL.md`, this file, `packaging/systemd/*.service` vs `docs/*.service` dedup) | Done on branch `claude/sweet-sagan-yklpu8`: `docs/diagrams/imas-architecture.svg` replaces `grlx-arch-light.png`; `docs/api/saasapi.md` + `docs/api/saasapi-openapi.yaml` (all 18 `NewRouter` routes, the 2 dispatch routes marked off by default); `INSTALL.md` rewritten for tenants, enrollment keys, the SaaS API and Envoy; `docs/imas-{farmer,sprout}.service` removed in favour of `packaging/systemd/` | merged — PR #23 |
| J: seal `cook` dispatch and resync nudge end to end | See "As built (J follow-up)" under Wave 2. Closes the highest-priority item on the "still plaintext" list: a compromised bus can no longer inject either a command (`cmd.run`) or a recipe (`cook`) onto a box-ready sprout. Also moved farmer's job-creation recording off the (now sealed) plaintext dispatch onto an explicit hook (`cook.SetDispatchRecorder`). FLAG FOR SECURITY REVIEW | merged — PR #32 (`d2692c8`, `6f1ac36`, `bf5956c`) |
| H: sprout outbound proxy support for the bus connection (requirements.md item 8) | New sprout config key `busproxyurl` (`http://` HTTP CONNECT or `socks5://`); `pki.LoadSproutBus` wires it as nats.go's `CustomDialer`, covering `wss://`, `tls://` and `nats://` alike, with `nats.SkipHostLookup` so the proxy resolves the bus host. The sprout's HTTP clients already covered this via `ProxyFromEnvironment`; this closes the one real gap (the bus connection itself) | merged — PR #33 (`924e9dc`, `ac523c1`) |
| J: sprout side of farmer-triggered box key rotation (requirements.md item 15) | Closes "sprout-initiated box key rotation has a farmer side but no sprout side." Farmer-triggered only, no sprout-side scheduling. New key held `pending` until confirmed by the first farmer payload that opens under it; replaced key kept `previous` for `sproutboxkeyprevgrace` (default 15m, floored at `2×DefaultMaxSkew`). Along the way, found and fixed a real gap: `sproutPermissions` never granted the `boxkey.pub` publish subject at all, so every submission was refused as a Permissions Violation until this PR added it (existing sprouts pick it up via JWT re-mint on next refresh). See `docs/design/imas-payload-encryption-design.md`'s "Sprout-side rotation, farmer-triggered only." FLAG FOR SECURITY REVIEW | merged — PR #34 (`8eb23da`, `8384084`, `7b9d80d`) |
| Ansible + packaging: expose `busproxyurl` and `sproutboxkeyprevgrace` | `ansible/roles/imas_sprout` variables `imas_sprout_bus_proxy_url` (drift-managed the same way as `busurls`: set when non-empty, removed when emptied) and `imas_sprout_boxkey_prev_grace` (set when non-empty, but deliberately never removed — see below), `packaging/etc/imas-sprout.conf` commented examples, `ansible/README.md` variable table. Found and fixed a Molecule idempotence failure along the way: `sproutboxkeyprevgrace` is the only one of the two with a `jety.SetDefault` in `internal/config/config.go`, so the sprout rewrites it into the config file with a concrete default value on any other save (enrolling, clearing its join token). Managing it the same "remove when empty" way as `busurls`/`busproxyurl` fought that write-back every run — molecule's idempotence check caught it: `imas_sprout : Write the enrollment settings...` and the restart handler both fired non-idempotently on all three containers. Fixed by only ever adding an explicit override for this key and never trying to force it absent. | **done, this pass** (docs/ansible only, no application code) |

## Fleet updates and DB migrations (Wave 4, merged 2026-10-01 to 2026-10-02)

Decisions recorded in `docs/design/requirements.md` (items 20, 21) and
`docs/design/cloudxp-machine-manager-api-design.md` (§1.8, §2.2, §2.3,
§2.5, §2.6, §4.1a). Sprout updates install from the repository configured
**in the sprout**, the same per-OS repos the Ansible role `imas_sprout` sets
up; imas controls only a signed manifest (version, OS/arch, file name,
checksum, `min_sprout_version`). This **replaced** the earlier
signed-row-with-artifact-URL flow: `internal/update` (the disabled upstream
skeleton) is deleted, `fleetreleaser` no longer touches the database, and the
manifest is verified against a keyring shipped in the sprout package, not a
key set fetched over the bus. Release/rollout flow: see `docs/RELEASING.md`.

| Item | What shipped | Status |
|---|---|---|
| Release flow (`docs/RELEASING.md`), **never run** | One `vMAJOR.MINOR.PATCH` tag releases everything: five GHCR images (keyless cosign), binaries and checksums on GitHub releases, rpm/deb/winget to the Buildkite registries, `farmer` and `nats` charts to `imashelm`. Stale upstream publishers (Docker Hub, Cloudsmith, S3, AUR) removed. `release.yml` is manual-only until the repo secrets `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE` and `GORELEASER_KEY` (goreleaser-pro, a paid licence; brief REL.1 in plan §4c replaces it with GoReleaser OSS and a `wixl` build hook, after which the key is not needed) exist, and `publish-packages.yml` needs the Buildkite organisation variable and token. No tag exists and neither workflow has a run. | merged — PR #43 (`c3f6f65`), #44 |
| DB.1 goose migrations | `cmd/migrate` and `internal/migrations` (goose, embedded SQL, no CGO): baseline per schema, row-based run lock (not `GET_LOCK`, which is node-local on Galera), `up` and `check`; GORM `AutoMigrate` removed from `internal/pxc` and saasapi; services check the schema version at startup. `saas` migrations 00001–00005 and `farmer` 00001 are on `main`. | merged — PR #46 (`1e56315`) |
| DB.2 Migration hook Job | `db-migrate-job.yaml` replaces `db-bootstrap-job.yaml`: one pod, `pre-upgrade`/`pre-rollback`, `post-install` with the bundled PXC; `imas-migrate` image shipped; chart tests extended | merged — PR #48 (`691a1bc`) |
| FU.0 Signed manifest | URL-free manifest (`imas-fleet-manifest-v1|version|os|arch|file_name|checksum_sha256|min_sprout_version`) signed with the Transit key, verified against a keyring; `selfupdate` and `sprout_action` reworked. FLAG FOR SECURITY REVIEW | merged — PR #45 (`c5ecebe`) |
| FU.3 + FU.4 Release registration and signing | `fleetreleaser` is a stateless TLS signing service with no DB access and is the sole signer; saasapi's operator plane validates and stores signed rows (one per OS/arch/package type, idempotent on identical checksums, revoke call), migrations 00003–00004. FLAG FOR SECURITY REVIEW | merged — PR #49 (`08b6982`), operator plane served by `cmd/saasapi` in PR #56 (`e79a3d4`) |
| FU.1 Manifest endpoint | Farmer serves `GET /v1/sprout/update-manifest` (sprout JWT), read-only from the release catalog; routed through Envoy and tested against real Envoy | merged — PR #51 (`e44b1a6`), #52 (`c23fce5`) |
| FU.2 Sprout fetch, verify, install | Sprout reads its repository's own index (apt, rpm incl. zstd, NuGet flat container), verifies signature and SHA-256, installs with `dpkg -i`, `rpm -U`, `zypper` or `msiexec`, refuses downgrades; keyring shipped in deb/rpm/MSI; Ansible variables for repo URL and token; `testing/selfupdate-e2e` drives a real cycle against Nexus on Debian and Rocky. FLAG FOR SECURITY REVIEW | merged — PR #53 (`f3d035d`) |
| FU.7 Farmer dispatch | Farmer dispatches `self_update` as `{version}` only and re-verifies it against the catalog (`internal/fleetcatalog`) before sending | merged — PR #53 |
| CL.1 Remove the dead live fleet-key path | Deleted `internal/fleetkeys` and its farmer wiring, `payloadbox.PurposeFleetSigningResponse`, the `imas.sprouts.<id>.fleetsigningkeys` grant in sprout JWTs, `fleet_signing_jwks` in `POST /v1/enroll` (farmer and sprout client), `GET /v1/.well-known/fleet-signing-jwks.json`, the sprout's enrollment pin (`internal/pki/fleetkey.go`) and the `sproutfleetsigningjwks` setting. Enrollment no longer needs the fleet key source. A sprout built before this refuses to enrol against a farmer built after it: upgrade sprouts first, or re-enrol. FLAG FOR SECURITY REVIEW | ready for review — PR #62 |
| CL.3 Outbox sweeper | `internal/saasapi/sweeper.go`, on every saasapi replica (`SAASAPI_OUTBOX_*`, Helm `saasapi.outboxSweeper.*`). Row leases (`lease_owner`/`lease_until`, claimed by one conditional `UPDATE` that must affect the row; not `GET_LOCK`), migration `saas/00006`, which also adds `provisioning_jobs.last_dispatched_at`, `asset_action_items.dispatched_at` and `planned_at_target` (what a resumed rollout needs and wasn't stored) and an index on `asset_action_items.status`. Re-publishes pending provisioning jobs with exponential backoff, failing them after `SAASAPI_OUTBOX_MAX_ATTEMPTS`; re-sends §1.5 items still `queued`, never ones in `dispatching`; with dispatch enabled, takes over an update rollout whose lease lapsed and resumes it from the database, gating already-sent items on deadlines from their dispatch time and re-checking approval, revocation, registration and the tenant before every wave. Farmer's handling of a repeated `job_id` checked: harmless on its own; the one race (a late provision copy against a deprovision) is mitigated in saasapi by `DELETE` waiting out a re-published provision job, with the `internal/pki` fix left open (out of scope). Tested with sqlite and against MySQL 8. FLAG FOR SECURITY REVIEW | ready for review — this branch (`claude/gallant-rubin-o9pnyo`) |
| FU.5 Helm release hook | `sprout-release-register-job.yaml` (post-install/post-upgrade) runs `farmer register-sprout-release`; `min_sprout_version` stamped at release time (`packaging/helm/`) | merged — PR #55 (`6815306`) |
| FU.6 Rollout gates | Health-gated waves (a sprout counts when it reports the new version), one rollout per tenant, per-sprout OS/arch/package-type resolution, sprouts report their release as the `sprout_version` fact | merged — PR #57 (`ec21992`) |
| FU.6b Gate freshness | Gate counts only reports written after dispatch; dedicated `rollout_claimed_at` column (migration 00005). FLAG FOR SECURITY REVIEW | merged — PR #58 (`507554d`) |

**Fleet update dispatch is still off by default.**
`SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED` stays `false`: the code path is
complete and unit/e2e tested on Linux, but it has not had its security review
and has never run on real hosts, and the Windows install path has only been
tested with `msiexec` mocked. Turn it on after review and after the Terraform
UAT gate has run the published packages. Known leftovers from this work:

- **Dead live-key-set path: removed by CL.1** (see the table above).
  Sprouts enrolled before CL.1 keep the unused
  `imas.sprouts.<id>.fleetsigningkeys` Publish grant until their User JWT is
  next re-minted; nothing subscribes to it any more. `fleetsign`'s JWKS
  encoding and `JWKSHandler` now have no production caller and are left
  for a follow-up.
- **Farmer's real dispatch path in the e2e test.** `testing/selfupdate-e2e`
  uses the Molecule stub farmer, not `internal/natsapi`.
- FU.6 open question 1 (targets created before FU.6) is not needed
  pre-production; question 4 (`facts.request`) is deferred.
- **Outbox sweeper: built by CL.3** (see the table above). Open from it:
  an item a dead pod left in `dispatching` is never re-sent and keeps an
  update rollout's tenant slot taken; `internal/pki`'s provision/deprovision
  race on a re-published request (mitigated in saasapi); no maximum age for
  a queued §1.5 item. See `docs/design/imas-internal-api-account.md`.

Decided 2026-09-29: `helm rollback` leaves the sprout release registered
(withdrawn only by explicit revoke); one `cmd/migrate` binary; sprout
private-repo token is Linux only for now, as in the Ansible role. Atlas was
considered; goose chosen (MIT).

**Licensing follow-through.** MPL-2.0 is accepted generally (requirement 21)
and `CLAUDE.md` now says so (PR #41). The decision to replace imas's
hand-rolled OpenBao HTTP clients with the official Go client has **not** been
acted on: `go.mod` has no OpenBao client, and `internal/openbaokv`,
`internal/fleetsign`, `internal/gatewayjwt` and `internal/certs` still speak
HTTP directly.

## Docs, CI and tooling merged alongside

| Item | Status |
|---|---|
| GitHub Pages site (`docs-site/`, mdBook): per-ingredient reference generated from source by `tools/gendocs`, architecture and SaaS API chapters; `docs.yml` deploys on push to `main` | merged — PR #36, #37 |
| Requirements, API design, BUILD-STATUS and `CLAUDE.md` rewritten for sprout repo updates and the MPL-2.0 exception | merged — PR #38–#42 |
| CI: goimports check skips `dependencies/`; dependency licence files refreshed | merged — PR #47 |
| J follow-up: box-key round-trip test no longer deadlocks on sqlite | merged — PR #50 |

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
    and returns 404 on `yogzblr/imas`. Superseded 2026-09-29: the upstream
    dependency no longer applies; the sprout-side install is imas's own work
    (FU.2 above) and dispatch stays off by default until it lands.
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
  RAG (`docs/design/requirements.md`, updated 2026-09-29):
  item 8 (sprout proxy support) and item 15 (sprout key rotation) both
  close out; item 14 (payload encryption) narrows to `shell.*` as the
  highest-remaining-priority plaintext boundary (an interactive PTY from a
  plaintext request), everything else on the "still plaintext" list above
  being lower severity by design (read by the UI/CLI, which hold no
  tenant key) or already accepted (the `boxkey.rotate` trigger itself).
- ~~Still genuinely open, in priority order: `shell.*` sealing, Terraform UAT, scale/latency validation, Keycloak harness.~~ Superseded by the 2026-10-02 list below.
- **2026-09-29: fleet updates and migrations re-scoped.** Doc-by-doc
  review (requirements, design, this file, `CLAUDE.md`), each approved
  before changing. Recorded above: updates from the sprout-configured repo,
  manifest signed by `fleetreleaser` and registered from the farmer Helm
  release, goose migrations in a single hook Job, MPL-2.0 accepted. No code
  changed in this pass; FU.1–FU.6 and DB.1–DB.2 are the new open work and
  join the "still genuinely open" list above, ahead of the Terraform UAT
  gate for anything that touches updates.
  **Update 2026-10-02:** every item from that note has since merged (see
  "Fleet updates and DB migrations").

## Open items (as of 2026-10-02, in priority order)

1. **Terraform UAT gate: not started.** No Terraform exists in the repo. It
   is the release-quality gate (provision VMs per OS, install the published
   packages with the Ansible role, smoke-test enrollment, a recipe run,
   reboot survival, one self-update cycle) and the first thing that would run
   the Windows paths, the Helm charts and the Buildkite packages on real
   infrastructure. Brief: `docs/claude-code-parallel-build-plan.md` §4a.
   Needs a human decision on the compute provider before dispatch.
   **Prerequisite: a first release.** The gate installs *published*
   packages, and none exist. Someone must set the release secrets, tag a
   pre-release (for example `v0.1.0-rc.1`), run **Release** on that tag, review
   the draft and publish it, and fix whatever the first real run of the
   pipeline turns up (cosign verification, the Buildkite uploads, the chart
   stamp). Dispatch brief REL.1 (plan §4c) first so the paid
   GoReleaser Pro key is not one of the secrets. Do this before dispatching the UAT brief.
2. **`shell.*` is not sealed** (requirement 14). An interactive PTY is started
   from a plaintext request on `imas.sprouts.<id>.shell.start`; a compromised
   bus can still get a shell on any Unix sprout, which undoes the value of
   sealing `cmd.run` and `cook`.
3. **Scale and latency (requirements 1, 7, 10):** no load or chaos test has
   ever run. Two scale-plan items are also unbuilt: jittered sprout reconnect
   (still a fixed 15 s `ReconnectWait`) and a clustered bus (`cmd/farmerbus`
   has no route support, so the chart blocks more than one bus replica).
4. **Security review of the flagged work**, including FU.0/FU.2/FU.3/FU.4/
   FU.6b, CL.3 and the J follow-ups, before `SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED`
   is turned on anywhere.
5. **Clean-ups left by Wave 4** (briefs CL.2a and CL.2b are in
   `docs/claude-code-parallel-build-plan.md` §4c, not yet dispatched; CL.1,
   removing `internal/fleetkeys` and its permission, is ready for review in PR #62;
   CL.3, the outbox sweeper that resumes batches and rollouts after a pod
   restart, is ready for review on `claude/gallant-rubin-o9pnyo`):
   replace the hand-rolled OpenBao HTTP clients with the official Go client
   as decided on 2026-09-29. CL.3 leaves three open questions (stuck
   `dispatching` items, the `internal/pki` provision/deprovision race, no
   maximum age for queued items); see "Deferred / open questions" in
   `docs/design/imas-internal-api-account.md`.
6. **SaaS API §1.7** (caller API keys, teams, webhooks, billing/metering) has
   never been designed or started.
7. **Docs:** `requirements.md` item 15 still says the new private key is sent
   encrypted over NATS, which the built (and designed) behaviour deliberately
   does not do; `README.md`'s "Batteries Included" still describes an
   embedded bus.
8. **Nice-to-haves:** run the Keycloak JWKS harness somewhere with a Docker
   daemon; tenant key rotation has no scheduler inside farmer (run
   `imas keys rotate-tenant-key` from a CronJob); CERT-In/DPDP/data
   sovereignty review is still unowned.

Known accepted gaps, unchanged: JWT permission re-mint does not apply to
already-enrolled sprouts (harmless pre-production), and
`internal/natsapi/router.go`'s tenant-facing subjects do not validate
`msg.Reply` (inherited from upstream grlx).

## Re-evaluation, 2026-10-03

A second pass over the 2026-10-02 refresh, checking its claims against `main`
(no code had changed in between). Corrected: the release flow and installers
were described as published when nothing has ever been released; a note on
requirement 5 about "original wording" that could not be supported was removed;
`README.md` said message payloads are encrypted with per-tenant and per-sprout
keys without saying only `cmd.run`, `cook` and box-key submissions are;
`deploy/helm/farmer/values.yaml` still cited the dead `imas#286`;
`docs-site/src/architecture.md` omitted `fleetreleaser` and the migration Job. Confirmed as written: no AutoMigrate on production paths
(`migrateSchema` in `internal/saasapi/db.go` is used only by tests, though it
sits in a non-test file); dispatch defaults off in the chart; all 18 `saasapi`
routes (16 unconditional, 2 behind the flag); Envoy uses remote JWKS; key
rotation never transmits a private key; the sdb Tier 2 gap is by design; the
scale plan did call out reconnect-storm hardening.
