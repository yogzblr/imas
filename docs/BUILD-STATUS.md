# Build Status

Tracks Wave 0 (the nine workstreams from `docs/claude-code-parallel-build-plan.md`
section 1, task briefs 1.1–1.9) and Wave 1 (section 2, dispatched once B and A
were confirmed merged to `master`).

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

**Open verification gap left by H's merge (not a code task, and not gated on
anything):** the sandbox H was built in had no network access to run a live
Envoy instance, so `jwt_authn`'s EdDSA/Ed25519 support was only checked
against `jwx`'s library-level round-trip, never against real Envoy. Someone
with normal network access (and a Docker daemon) needs to pin an Envoy image
version confirmed to support EdDSA in `jwt_authn` and run one real enrollment
against `deploy/envoy/testing/docker-compose.keycloak.yml` before relying on
`deploy/envoy/` in any real environment. **I attempted this myself and could
not** — this coordinator session has network access but no Docker daemon
(`/var/run/docker.sock` doesn't exist here). This still needs to happen
somewhere before Wave 1/2's Envoy config is trusted in production, but it
does not block Wave 2's code being written, since E/I/J don't depend on the
JWT signing algorithm choice itself.

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
| J | Payload encryption + rotation: NaCl `box` (X25519), tenant keypair via OpenBao (replacing `internal/pki/tenantbox.go`'s interim local-disk custody), sprout keypair generated at enrollment. Must first add a `sprout_pub` field to the enrollment request/`Enroll()` (confirmed missing) | session_01AivbiHCYGgL1ywzyTViaK2 | merged — PR #27 (`f5a947d`) | y — cryptographic code defending against a compromised DMZ bus |

## Ongoing / fully parallel (no gating)

| Item | Description | Cloud session ID | Status | Needs security review |
|---|---|---|---|---|
| D (facts listener) | `internal/facts/listener.go`'s `RegisterFarmerListener` still used plain fan-out `Subscribe`, justified by a stale comment from before workstream A removed `props/store.go`'s in-memory cache; queue-grouped it under `imas-core` to stop every replica double-writing the same PXC row on every fact update | not dispatched by this coordinator — found already merged | merged — PR #24 (`e9aa2ea`) | n |
| G.2 | Windows user/group provider using `deploymenttheory/go-bindings-win32`'s netmanagement package | session_01ArigyXKLB5a2gV449zBGZB | dispatched | y — user/group creation, and the dependency is young (v0.2.x) |
| G.4 | Windows DACL/ACL ingredient using `hectane/go-acl` for file ACLs, extended to registry-key ACLs (`SE_REGISTRY_KEY`) | session_01BVU6xoX7h7tzkscFYUTY8U | dispatched | y — propagation/inheritance semantics are a security-relevant bug class |
| G.6 | Task Scheduler, Windows Update, and Shortcut COM ingredients using `go-ole/go-ole`, starting with Shortcut (IShellLink) to prove the COM lifecycle pattern | session_01GXJ5vf5Fdo9fMxdoFAe5rE | dispatched | y — COM lifecycle bugs (missed Release, wrong apartment threading) |
| G.7 | v1 subset of LGPO — parse `registry.pol` (`encoding/binary`) and ADMX/ADML (`encoding/xml`); PR proposes which policy subset to cover for a first pass | session_01XYVPKvrCssvaGQTd9MbEs3 | dispatched | n |
| H.1 | Linux network/route management using `vishvananda/netlink`, with a verify-connectivity-or-roll-back pattern in the ingredient itself | session_01Q9NMvFaiFykjHmvCpqSn36 | dispatched | n |
| H.2 | nftables firewall ingredient using `google/nftables` | session_015pQ7NBWmSxJFht6DQyrrbs | dispatched | y — a firewall ingredient can lock out or expose a host |
| H.3 | SELinux ingredient using `opencontainers/selinux` | session_012DtUVSVbEHb11Uz4KzW4Tt | dispatched | y — CERT-In/DPDP-relevant: silently degrading to permissive is compliance-visible |

Before dispatching, validated against `master` that none of the seven were
already implemented: no ACL/DACL, Task Scheduler/WUA/Shortcut, LGPO,
netlink/route, nftables, or SELinux ingredient existed, and none of their
named dependencies (`go-bindings-win32`, `hectane/go-acl`, `go-ole/go-ole`,
`vishvananda/netlink`, `google/nftables`, `opencontainers/selinux`) were in
`go.mod`. The existing `winfirewall` ingredient is G.9's already-merged
`netsh advfirewall` wrapper, not H.2's Linux nftables ingredient — confirmed
by reading its imports before ruling H.2 not done.

## Notes

- "Needs security review" reflects only workstreams whose task brief in
  `claude-code-parallel-build-plan.md` includes the literal line
  "FLAG FOR SECURITY REVIEW." Per `CLAUDE.md`, none of the flagged
  workstreams should be treated as "done" or "safe to merge" even after
  their tests pass — only as "ready for review."
- The six pre-existing Wave 0 workstreams were confirmed directly against the
  repo (code present, tests present, commits/PRs identified in `git log`)
  rather than re-run, per instruction to skip work already done.
- All of Wave 0, Wave 1, and Wave 2 are now merged. Everything in
  `docs/claude-code-parallel-build-plan.md` sections 1–3 is done. The
  Envoy/EdDSA verification gap noted above under Wave 1 is still open and
  needs a human or a docker-capable environment — it was never gated on
  Wave 2 and remains the one unresolved item from the plan as dispatched.
  Section 4's remaining "ongoing / fully parallel" Windows/Linux ingredient
  workstreams (G.2, G.4, G.6, G.7, H.1, H.2, H.3) have now been dispatched
  as well, since they have no dependency on anything else in the plan.
