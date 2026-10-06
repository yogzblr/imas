# imas SaaS Machine Manager — Claude Code Parallel Build Plan

This is a working playbook for building the CloudXP machine-manager fork of
`yogzblr/imas` using Claude Code cloud agents (`claude --cloud`), running
workstreams in parallel where the roadmap allows it and gating the rest on
the dependencies already identified in the design docs.

---

## 0. Prerequisites (do this once)

1. **Repo on GitHub**, public (open source). Install the Claude GitHub App
   on it, or run `/web-setup` from a terminal with `gh` already
   authenticated against it.
2. **Commit the design docs into the repo** under `docs/design/` — cloud
   sessions only see what's in git, not this chat. Copy in:
   - `imas-master-plan.md`
   - `imas-fork-roadmap.md`
   - `imas-nats-jwt-auth-design.md`
   - `imas-envoy-enrollment-design.md`
   - `imas-payload-encryption-design.md`
   - `imas-sdb-secrets-design.md`
   - `imas-1m-scale-plan.md`
   - `imas-windows-parity-addendum.md`
   - `imas-linux-parity-addendum.md`
   - `imas-tls-entropy-caution.md`
   - `cloudxp-machine-manager-api-design.md`
   - `requirements.md` (the original numbered requirements list)
3. **Add a root `CLAUDE.md`** (template below) so every cloud session
   inherits the same ground rules without you repeating them in every
   prompt.
4. If your org account: confirm `allow_remote_sessions` is enabled
   (Owner sets this at claude.ai/admin-settings/claude-code).
5. Decide now whether this repo runs on Anthropic-hosted cloud sessions or
   a self-hosted environment — revisit if CERT-In/DPDP scope ever pulls
   this fork inside CloudXP proper rather than staying upstream OSS.

### Root `CLAUDE.md` template

```markdown
# imas SaaS Machine Manager — repo conventions

Fork of yogzblr/imas (github.com/yogzblr/imas). See docs/design/ for the
full architecture — read imas-master-plan.md and imas-fork-roadmap.md
first, then the specific design doc named in your task.

## Constraints (non-negotiable)
- Licensing: Apache-2.0 / MIT dependencies only. Flag anything else
  before adding it as a dependency, don't just add it.
- Go, existing module layout. Don't introduce a second language/runtime
  without flagging it first.
- No CGO (blocks a CGO-free build target elsewhere in the plan).
- Follow the existing self-registering ingredient plugin pattern
  (see internal/ingredients/*) for any new ingredient.

## Workflow
- Work only within the file scope stated in your task brief. If you need
  to touch a file outside that scope, stop and say why instead of doing it.
- Write unit tests for new logic. `go test ./...` must pass before you
  consider the task done.
- Commit messages: `<workstream-id>: <what>` (e.g. `B: mint sprout JWT
  via nats-io/jwt/v2`).
- Open a PR when done. In the PR description, state what you built,
  what you deliberately left out or deferred, and any open question.

## Security review flag
If your task brief includes the line "FLAG FOR SECURITY REVIEW", say so
explicitly at the top of the PR description, and do not describe the
work as "done" or "safe to merge" — only as "ready for review."
```

---

## 1. Wave 0 — launch immediately, no dependencies

Run each of these as its own `claude --cloud "..."` call (or paste them
into a Claude Code **Project** so one lead conversation dispatches and
tracks all nine).

**1. Workstream B — NATS JWT auth**
```
claude --cloud "Implement workstream B from docs/design/imas-fork-roadmap.md:
replace imas's custom NKey allow-list with NATS decentralized JWT auth
(Operator -> Account-per-tenant -> User-per-sprout). Full design in
docs/design/imas-nats-jwt-auth-design.md. Build: Operator/SystemAccount
keypair bootstrap, 'full' resolver config, JWT minting via nats-io/jwt/v2
+ the existing nkeys dependency, and a push-to-resolver mechanism over a
NATS system-account connection that replaces pki.ReloadNKeys()'s
in-process ReloadOptions() call. Preserve today's accept/deny/reject
sprout lifecycle, remapped onto JWT issuance/revocation. Scope: internal/pki/
only. Do not touch internal/natsapi/subjects.go. Write tests against a
local nats-server. FLAG FOR SECURITY REVIEW in the PR description — this
is the trust-chain root."
```

**2. Workstream D — queue-group fix**
```
claude --cloud "Implement workstream D from docs/design/imas-fork-roadmap.md:
change nc.Subscribe(...) to nc.QueueSubscribe(subject, \"imas-core\", ...)
in internal/natsapi/router.go. Also review internal/jobs/listener.go and
internal/facts/listener.go (currently plain Subscribe) and decide, with
reasoning in the PR, whether they should be queue-grouped too or whether
their fan-out is intentional. Small, mechanical change; add/adjust tests
covering the subscription pattern."
```

**3. Workstream F — OpenBao TLS**
```
claude --cloud "Implement workstream F from docs/design/imas-fork-roadmap.md:
replace internal/certs/tls.go's self-signed local CA (genCACert, GenCert,
RotateTLSCerts, forceRegenCert) with calls to OpenBao's PKI secrets
engine, writing results to the same CertFile/KeyFile/RootCA paths that
internal/pki/nats.go and the API server already consume. Rotation should
use OpenBao lease renewal instead of a self-managed timer. Scope:
internal/certs/ only. Write tests against a local OpenBao dev server.
FLAG FOR SECURITY REVIEW — this is certificate/key-handling code."
```

**4. Workstream G.1 + G.3 — Windows service provider + registry ingredient**
```
claude --cloud "Implement G.1 and G.3 from docs/design/imas-windows-parity-addendum.md:
(1) a Windows SCM-backed service provider matching the create/start/
stop/delete/status surface of the existing systemd/openrc/rcd providers
in internal/ingredients/service/, using golang.org/x/sys/windows/svc/mgr.
(2) a new registry ingredient from scratch using
golang.org/x/sys/windows/registry, following the self-registering
ingredient pattern used elsewhere in internal/ingredients/. Cross-compile
with GOOS=windows to confirm it builds; note in the PR that this cannot
be runtime-validated outside a real Windows host."
```

**5. Workstream G.5 + G.8 + G.9 — Windows facts + PowerShell/CLI module batch**
```
claude --cloud "Implement G.5, G.8, and G.9 from docs/design/imas-windows-parity-addendum.md:
(1) hardware/BIOS facts via the SMBIOS route described (prefer
digitalocean/go-smbios or jaypipes/ghw's SMBIOS reader over WMI/COM for
this subset), wired into the existing facts collection path. (2) the
PowerShell-only module batch (win_servermanager, win_dsc, win_psget,
win_iis, win_pki, win_snmp, win_smtp_server, win_appx) as
exec.Command('powershell.exe', ...) wrappers with ConvertTo-Json output
parsing, reusing the existing cmd ingredient execution path — build the
first one, get the pattern right, then repeat it for the rest. (3) the
CLI-tool-only batch (win_firewall via netsh, win_dns_client, win_auditpol,
win_powercfg, win_certutil) as plain-text-parsing wrappers. Cross-compile
GOOS=windows; flag that none of this is runtime-verified."
```

**6. Workstream H.4 + H.5 — Linux mount/fstab + cron ingredients**
```
claude --cloud "Implement H.4 and H.5 from docs/design/imas-linux-parity-addendum.md:
(1) a mount/fstab ingredient using golang.org/x/sys/unix's Mount/Unmount
syscalls plus a plain parser/writer for /etc/fstab — keep a cmd-based
fallback path for NFS/CIFS mount types, since raw mount(2) doesn't
dispatch to mount.nfs/mount.cifs the way the mount binary does. (2) a
per-user crontab ingredient (list/set/remove, idempotent add/remove-by-
identifier) reading/writing the crontab format directly or shelling to
the crontab binary. Follow the self-registering ingredient pattern.
Write tests."
```

**7. Workstream L — sprout ingredients + cook-engine primitives**
```
claude --cloud "Implement workstream L from docs/design/imas-sprout-orchestration.md:
new atomic ingredients probe.http, probe.database, wait, file.sync,
file.line (check existing file ingredient coverage first before treating
these as net-new), and a file.copy enrichment (bidirectional push/pull,
glob, exclude, mkdir, chmod+x). Separately, cook-engine orchestration
primitives that apply to any ingredient: conditional step execution
(cond, with negation — confirm nothing equivalent exists first),
deferred/on_exit actions, variable registration/passing between steps
with a sensitive:true flag, and runtime context variables
({IMAS_SPROUT_ID}, {IMAS_TENANT_ID}). Do not build a probe-internal
workflow engine or a separate probe-only secrets mechanism — probe is
atomic ingredients only, and secret injection should reference the
sdb:// interface by name (stub the interface if workstream K isn't
merged yet). Everything sensitive-marked must be redacted from the
persisted job log AND from verbose/debug output, never just the log —
write a test that specifically exercises the debug-output path. FLAG
FOR SECURITY REVIEW on the sensitive-value redaction path only."
```

**8. Workstream K — SDB secret resolution (v1 tier)**
```
claude --cloud "Implement the v1 tier of docs/design/imas-sdb-secrets-design.md:
a sprout-side SecretProvider interface (Get(ctx, ref) (value, error))
behind the sdb:// URI scheme, with self-registering implementations for
OpenBao/customer Vault (certificate-based auth, file-watched/hot-reloaded
so a rotated customer cert doesn't need a sprout restart), and Azure/
AWS/GCP via managed identity only (no JWT federation in this pass).
Follow the same self-registering plugin pattern as other ingredients.
Write tests with a mocked OpenBao client at minimum."
```

**9. SaaS API scaffold — tenants, enrollment-keys, schema**
```
claude --cloud "Scaffold the new SaaS API service described in
docs/design/cloudxp-machine-manager-api-design.md, sections 1.1, 1.2,
and 5. Standard Go REST service with GORM against the 'saas' schema in
the shared PXC cluster (do not touch the 'farmer' schema). Implement:
POST/GET/PATCH/DELETE /tenants and GET /tenants/{tenant_id}/status
(async provisioning per the doc's pending/active/failed states, backed
by a provisioning_jobs outbox table), and POST/GET/DELETE
/tenants/{tenant_id}/enrollment-keys per section 1.2/3.1's key_id.secret
split (key_id plaintext indexed lookup, secret's SHA-256 stored as
key_hash, never the raw secret). Do not implement the actual farmer-side
NATS calls yet (internal.tenant.provision etc.) — stub them with a TODO
referencing section 2.2, since that depends on workstream B/H landing
first. Write tests. FLAG FOR SECURITY REVIEW on the enrollment-key
hashing/lookup logic specifically."
```

---

## 2. Wave 1 — hold until B (and ideally A) are merged to `main`

**Workstream A — PXC/Valkey/object storage** (can actually start in Wave 0
in parallel with B, since it touches different files — include it there if
you have capacity):
```
claude --cloud "Implement workstream A from docs/design/imas-fork-roadmap.md
and imas-master-plan.md Phase 1: move PKI, props/facts, and RBAC to
Percona XtraDB Cluster with read-through and no in-memory cache (fixes
the cross-replica divergence bug in props/store.go directly). Move
connection-state/heartbeat to Valkey TTL keys driven by NATS's own
$SYS.ACCOUNT.*.CONNECT/DISCONNECT events, not an app-level heartbeat.
Move recipe storage off farmer's local-disk basepath
(internal/cook/farmercook.go's ResolveRecipeFilePath/os.ReadFile) to
object storage (S3/MinIO), git remaining the source of truth synced on
merge, with a new authenticated HTTP endpoint serving the read path
(reuse the pattern in internal/ingredients/file/http/provider.go). Every
query against the PXC-backed tables must scope by tenant_id in the same
WHERE clause. FLAG FOR SECURITY REVIEW on the tenant-scoping discipline
specifically (workstream A.1)."
```

**Workstream C — DMZ split** (needs B settled):
```
claude --cloud "Implement workstream C from docs/design/imas-fork-roadmap.md:
split cmd/farmer/main.go into two deployables — a bus process
(RunNATSServer() + TLS/NKey config) for the DMZ, and a core process
(ConnectFarmer() + all registered subscribers) for non-DMZ, outbound-only
to the bus. Wire however workstream B's JWT push mechanism delivers
updates to the DMZ-side bus. Separate lifecycle/shutdown handling for
each binary."
```

**Workstream H — Envoy gateway + enrollment subsystem** (needs B):
```
claude --cloud "Implement workstream H from docs/design/imas-fork-roadmap.md
and docs/design/imas-envoy-enrollment-design.md: Envoy config in front of
NATS's websocket listener validating each sprout's JWT via a jwt_authn
filter against JWKS before the connection reaches nats-server, plus a
second Envoy route proxying authenticated recipe-download requests to
non-DMZ. Build the enrollment endpoint per section 3 of
cloudxp-machine-manager-api-design.md: token format {key_id}.{secret},
constant-time hash comparison against saas.enrollment_keys, atomic
redemption via the UPDATE ... WHERE used_count < max_uses guard shown in
that doc, idempotency check on nkey_pub first, generic
'enrollment_failed' response for every failure case (never distinguish
unknown/expired/revoked/exhausted in the response). Response returns the
sprout's JWT + NKey identity + tenant X25519 public key in one round
trip. FLAG FOR SECURITY REVIEW — this is the literal front door of the
trust chain."
```

---

## 3. Wave 2 — hold until A + H are merged

Before dispatching Wave 2 — one verification task, not a build task, that
H's merge left genuinely open: the sandboxed environment H was built in had
no network access to run a live Envoy instance, so `jwt_authn`'s
Ed25519/EdDSA support was only checked against `jwx`'s own library-level
round-trip, never against real Envoy. Confirm this somewhere with normal
network access before relying on `deploy/envoy/` in any real environment —
pin an Envoy image version confirmed to support EdDSA in `jwt_authn`, and
run one real enrollment against it (the
`deploy/envoy/testing/docker-compose.keycloak.yml` setup already checked in
gives a ready-made way to do this). This isn't gated on anything and
doesn't need a `claude --cloud` session — it's a local verification step.

**Workstream E — multi-tenancy:**
```
claude --cloud "Implement workstream E from docs/design/imas-fork-roadmap.md,
using the simplification from imas-nats-jwt-auth-design.md: one NATS
Account per tenant means internal/natsapi/subjects.go's subject strings
can stay unchanged, since isolation is enforced by which Account a
connection authenticated into. Re-key internal/pki/pki.go's storage by
(tenant_id, sprout_id) instead of sprout_id alone. Add a tenant field to
internal/rbac's cohort/role maps. Make FarmerOrganization dynamic —
one Account created/pushed per tenant at onboarding instead of one
static config-loaded string. FLAG FOR SECURITY REVIEW — tenant isolation
correctness."
```

**Workstream I — recipe storage migration** (mostly done as part of A above
if you sequenced it that way; otherwise the HTTP endpoint half, gated on H's
Envoy route):
```
claude --cloud "Finish workstream I: confirm the recipe HTTP endpoint from
workstream A is served behind workstream H's Envoy JWT-gated route, and
that internal/natsapi/recipes.go's old NATS-based recipe delivery is
removed in favor of it."
```

**Workstream J — payload encryption + rotation** (H is merged; note the gap
its enrollment work left open — see below):
```
claude --cloud "Implement workstream J from docs/design/imas-fork-roadmap.md
and docs/design/imas-payload-encryption-design.md: NaCl box (X25519)
encryption of NATS payloads. One tenant keypair (farmer-side,
OpenBao-custodied private key via internal/certs's existing hand-rolled
OpenBao client pattern — do not add the OpenBao/Vault SDK, it's MPL-2.0
and conflicts with this repo's Apache/MIT constraint, see
internal/certs/tls.go and internal/gatewayjwt/obtransit.go for the
established pattern), one sprout keypair (generated locally at
enrollment, private key never transmitted — not even encrypted).

Known gap to close first: internal/pki/enroll.go's Enroll() and
internal/api/handlers/enroll.go's enrollRequest do NOT yet accept the
sprout's X25519 public key — only nkey_pub. Add a sprout_pub field to
the enrollment request, thread it through Enroll(), and persist it
(sprout_pub -> PXC, per the design doc's 'Storage' section) before
building anything else. internal/pki/tenantbox.go is today's interim,
locally-disk-held placeholder for the tenant keypair specifically so the
enrollment response has *a* real tenant_x25519_pub — replace its local-
disk custody with real OpenBao custody as part of this workstream, per
its own doc comment.

Build a shared encrypt/decrypt request/response helper in
internal/natsapi so this is transparent to individual handlers rather
than opt-in per handler. Key rotation is sprout-initiated only: sprout
generates a new keypair locally, sends only the new public key, farmer
may trigger rotation but never generates or holds a sprout's private
key. Grace-period overlap reusing the existing PKI accept/deny/revoke
lifecycle. FLAG FOR SECURITY REVIEW — this is cryptographic code
defending against a compromised DMZ bus."
```

---

## 4. Ongoing / fully parallel, no gating — launch whenever you have capacity

```
claude --cloud "Fix a stale correctness assumption in internal/facts/listener.go:
RegisterFarmerListener still uses plain nc.Subscribe (fan-out), justified by
a comment claiming props.SetProp writes into an in-process, in-memory cache.
That's no longer true — internal/props/store.go's own header comment
confirms the in-memory propCache was removed when props moved to PXC-backed
storage (workstream A): 'now reads and writes straight through to the
shared farmer schema in PXC on every call, with no in-memory cache layered
on top.' Confirm this yourself by reading internal/props/props.go's
setProp/getStringProp — every call goes straight to db.Where(...), no map,
no mutex anywhere in the package.

With shared PXC storage already in place, fan-out here means every farmer
replica independently processes and UPSERTs every fact update into the
same PXC row — pure duplicate work, and worse, N replicas racing to write
the same row on every single fact update, which is exactly the kind of
write race workstream A's PXC migration was meant to eliminate at the
storage layer, not reintroduce at the listener layer.

Change RegisterFarmerListener to nc.QueueSubscribe(subject,
natsCoreQueueGroup, ...) under the same 'imas-core' queue group
internal/natsapi/router.go already uses for its route handlers, matching
that package's existing queue-grouping pattern. Update the function's
doc comment to explain the correction (not just delete the old reasoning —
a future reader should understand why this changed, the same way
internal/props/store.go's own header documents its own transition).

internal/jobs/listener.go's plain Subscribe is correct and NOT in scope
here — verify its own justification still holds (job data genuinely still
writes to local disk via config.JobLogDir, confirmed by reading
internal/jobs/listener.go directly) rather than assuming it does, but do
not change that file.

Update internal/facts/listener_test.go's
TestRegisterFarmerListener_FanOutNotQueueGrouped, which currently asserts
the old (now-wrong) fan-out behavior and will fail once this is fixed.
Replace it with a test verifying queue-group load balancing, mirroring
internal/natsapi/router_test.go's TestSubscribe_UsesQueueGroup pattern:
simulate a second farmer replica via a second QueueSubscribe on the same
subject and 'imas-core' group, publish a batch of facts events, and assert
the simulated replica receives some but not all of them (not zero, not
every one — if it receives all of them, the fix didn't take; if the real
listener were queue-grouped incorrectly against a different group name,
the simulated replica would receive none).

Run go test ./internal/facts/... and go vet ./... before considering this
done. Small, isolated, mechanical change — no dependency on Wave 2's
E/I/J work, safe to land independently and immediately."
```

```
claude --cloud "Implement G.2 (Windows user/group provider) from
docs/design/imas-windows-parity-addendum.md using
deploymenttheory/go-bindings-win32's netmanagement package. FLAG FOR
SECURITY REVIEW — user/group creation, and the dependency itself is
young (v0.2.x) so note that in the PR."

claude --cloud "Implement G.4 (Windows DACL/ACL ingredient) from
docs/design/imas-windows-parity-addendum.md using hectane/go-acl for
file ACLs first, then extend to registry-key ACLs (SE_REGISTRY_KEY).
FLAG FOR SECURITY REVIEW — propagation/inheritance semantics are a
security-relevant bug class, not just functional."

claude --cloud "Implement G.6 (Task Scheduler, Windows Update, Shortcut
COM ingredients) from docs/design/imas-windows-parity-addendum.md using
go-ole/go-ole. Start with the Shortcut ingredient (IShellLink, smallest
scope) to prove the COM lifecycle pattern before Task Scheduler and WUA.
FLAG FOR SECURITY REVIEW — COM lifecycle bugs (missed Release, wrong
apartment threading) are easy to miss in review."

claude --cloud "Scope and implement a v1 subset of G.7 (LGPO) from
docs/design/imas-windows-parity-addendum.md — parse registry.pol
(encoding/binary) and ADMX/ADML (encoding/xml), and propose in the PR
description which policy subset to cover for a first pass rather than
attempting full Salt win_lgpo parity."

claude --cloud "Implement H.1 (network/route management) from
docs/design/imas-linux-parity-addendum.md using vishvananda/netlink.
Include a 'verify connectivity survives the change, or roll back'
pattern in the ingredient itself, since a bad route/interface change can
cut off the sprout's own connectivity to farmer."

claude --cloud "Implement H.2 (nftables firewall ingredient) from
docs/design/imas-linux-parity-addendum.md using google/nftables.
FLAG FOR SECURITY REVIEW — a firewall ingredient can lock out or expose
a host; treat with the same discipline as the auth workstreams."

claude --cloud "Implement H.3 (SELinux ingredient) from
docs/design/imas-linux-parity-addendum.md using opencontainers/selinux.
FLAG FOR SECURITY REVIEW — CERT-In/DPDP-relevant: silently degrading to
permissive is a compliance-visible failure, not just a bug."
```

---

## 4a. Wave 3 — workstream M follow-through (Ansible + release UAT gate)

**Status (2026-10-02):** M.4 (Ansible) is merged. The Terraform UAT gate
(item 5) is **not started**: there are no `.tf` files in the repo. Its
dependencies are all merged, and it should now also cover one self-update
cycle per OS (FU.2).

Sub-items M.1–M.3 (Windows SCM service wrapper, MSI+winget installer,
zypper/SUSE rpm validation) are merged — see `packaging/windows/`,
`packaging/buildkite/publish-packages.sh`, and `.github/workflows/
publish-packages.yml`. What's left in M is M.4 (customer-run Ansible
playbooks), plus a new gate the roadmap didn't originally call out: a
Terraform-provisioned UAT pass that actually installs a tagged release
from the Buildkite registries and exercises it end to end before anyone
calls that release verified. M.4 gates the UAT item below, since UAT
drives the same playbooks a customer would run.

**4. Workstream M.4 — customer-run Ansible playbooks**
```
claude --cloud "Implement M.4 from docs/design/imas-fork-roadmap.md and
imas-windows-parity-addendum.md: Ansible playbooks a customer runs to
bootstrap a host onto imas, consuming workstream H's one-time enrollment
key ({key_id}.{secret}, per docs/design/imas-envoy-enrollment-design.md
§3 and cloudxp-machine-manager-api-design.md §3.1).

Add under ansible/ (new top-level dir, alongside deploy/):
- roles/imas_sprout: installs the imas-sprout package for the target OS
  and enrolls it.
  - Linux: add the Buildkite-hosted apt/yum/zypper repo (imasdeb/imasrpm,
    per publish-packages.yml's registry names) via the distro's native
    repo module (apt_repository / yum_repositoryzypper_repository), then
    install imas-sprout through the normal package module — do not
    download .deb/.rpm files directly, the point is customers get repo-
    managed updates.
  - Windows: install via win_package pointing at the release's MSI (the
    URL Buildkite's NuGet flat-container serves, same one
    packaging/windows/winget/build-winget-nupkg.sh resolves) — check
    whether community.windows.win_winget against the public imasnget
    feed is a cleaner fit than a direct win_package URL and justify
    whichever you pick in the PR.
  - After install, write the enrollment key and farmer bus URL to
    whatever config path imas-sprout already reads on each OS (check
    packaging/ for the installed config location — don't invent a new
    one), then start the service via the OS-native service module
    (systemd/win_service, matching the providers workstream G/M.1
    built) and idempotently detect 'already enrolled' by checking the
    sprout's own local state before re-running enrollment, since re-
    enrolling a healthy sprout should not happen on every playbook run.
  - roles/imas_verify (or a post_task in imas_sprout): poll the sprout's
    local status until it reports connected to farmer, fail the play
    with a clear message if it doesn't within a timeout.
- An inventory-driven playbook (site.yml or similar) applying
  imas_sprout to a `sprouts` group, with per-host or per-group vars for
  the enrollment key and farmer bus URL (document that the key is
  meant to be supplied via ansible-vault or the runner's secret store,
  never committed).
- A README under ansible/ walking a customer through: get an enrollment
  key from the SaaS API (POST /tenants/{tenant_id}/enrollment-keys, per
  cloudxp-machine-manager-api-design.md §1.2), put it in inventory
  (vaulted), run the playbook.

Test what you can with Molecule against Docker for the Linux path (a
local nats-server + the enrollment endpoint stubbed or run for real if
workstream H is merged). Flag in the PR that the Windows path can't be
molecule-tested from this sandbox the same way workstreams G/M's other
Windows pieces couldn't."
```

**5. New workstream — Terraform UAT gate for published releases**
```
claude --cloud "Add a Terraform-driven UAT (user-acceptance test) pass
that runs against a real tagged release after publish-packages.yml has
pushed its packages to the Buildkite registries (imasrpm/imasdeb/
imasnget), to catch what a green `go test ./...` can't: that the actual
published packages install and enroll cleanly on real target OSes.

Scope:
- New terraform/uat/ directory. Provision one VM per target OS this
  project claims to support today per the packaging matrix
  (.goreleaser.yaml's nfpm targets plus the MSI): at minimum an apt-
  based distro, an rpm-based distro, SUSE (zypper), and Windows.
- Make the compute provider swappable via a Terraform variable/module
  boundary rather than hard-wiring one cloud — default to a libvirt/KVM
  provider (dmacvicar/terraform-provider-libvirt or similar) so the UAT
  can run on a self-hosted runner without requiring new cloud
  credentials as a prerequisite, and leave clearly-marked module stubs
  for AWS/Azure/GCP equivalents. This default-provider choice is an
  infra decision with real cost/ownership implications beyond what an
  agent should decide unattended — say explicitly in the PR that it's a
  first draft default, not a final decision, and flag it for a human
  call on which provider(s) this actually runs against in production
  CI.
- After the VMs are up, run the Wave-3 M.4 Ansible playbooks
  (ansible/site.yml) against them using a real enrollment key obtained
  from a UAT tenant (stub/mock the SaaS API call if it isn't reachable
  from CI yet; say so in the PR rather than hand-waving it), pinning the
  package version/repo channel to the release tag under test rather
  than 'latest'.
- Smoke-test assertions after enrollment: the sprout shows as connected
  from farmer's side (a facts/status query over the imas CLI or API),
  a trivial recipe runs successfully on it (e.g. a fileManaged +
  cmd.run round trip), and the service survives a host reboot (systemd/
  win_service auto-start). Fail the run clearly naming which OS/step
  failed.
- Wire this as a new .github/workflows/uat.yml, modeled on
  publish-packages.yml's structure (a 'check secrets up front' step
  naming what's missing, a concurrency group per tag): trigger on
  workflow_dispatch with a required release-tag input, and optionally
  on release published as a follow-on to publish-packages.yml — but
  make that second trigger opt-in behind a repo variable for now, since
  it needs real provider credentials that don't exist on this repo yet
  (same posture as release.yml's 'manual-only until secrets exist').
- Always terraform destroy at the end of the job (including on
  failure), and say in the PR whether teardown-on-failure was actually
  verified or just written.

Do not change publish-packages.yml or release.yml's existing gating —
this is a new, separate pass that runs after a release is already
published, not a precondition for publishing it."
```

---

## 4b. Wave 4 — fleet updates and DB migrations

**Status (2026-10-02): every brief in this wave is merged** (DB.1, DB.2, FU.0,
FU.1, FU.2, FU.3/FU.4, FU.5, FU.6, FU.6b, plus FU.7 and the release flow), as
recorded in `docs/BUILD-STATUS.md`. The briefs below are kept as the record of
what was asked; do not re-dispatch them. The only brief in this file still to
dispatch is the Terraform UAT gate in §4a.

Re-scoped 2026-09-29 (requirements 20–21; API design §1.8, §2.2, §2.3, §2.5,
§2.6, §4.1a; `docs/BUILD-STATUS.md`, "Fleet updates and DB migrations").
Sprout updates install from the repo configured in the sprout, like the
Ansible role; imas controls a signed manifest, registered from the farmer
Helm release. The farmer and sprout ship under one tag (`docs/RELEASING.md`).

Sub-waves, each held until the one before is merged to `main`:

| Wave | Briefs (run in parallel) | Why this order |
|---|---|---|
| 4A | DB.1, FU.0 | Disjoint scopes. DB.1 owns schema, FU.0 owns the signed-manifest format. |
| 4B | DB.2, FU.34 | FU.34 adds the `fleet_versions` columns as a goose migration, so it needs DB.1. DB.2 needs DB.1. |
| 4C | FU.1, FU.2, FU.5 | FU.1 and FU.2 code against FU.0's manifest and FU.34's table. FU.5 needs DB.2 and FU.34. |
| 4D | FU.6, then the Terraform UAT gate | Gates and floors sit on the finished path; UAT proves it on real hosts. |

Every brief below inherits `CLAUDE.md`. IDs match BUILD-STATUS (FU.3 and
FU.4 are one brief, FU.34, because they share one signing contract).

**DB.1 — goose migrations (Go side)**
```
claude --cloud "Implement DB.1 from docs/BUILD-STATUS.md ('Fleet updates and
DB migrations') per docs/design/cloudxp-machine-manager-api-design.md §4.1a.
Add cmd/migrate: a CGO-free binary using pressly/goose (MIT) as a library
with embedded SQL (embed.FS), one migration set for the farmer schema and
one for the saas schema, each run with that schema owner's own DSN (single
writer per schema must hold). It also does the root-credential step first,
idempotently: create the two schemas and users and apply the schema-level
grants in §4.1; after both migration sets, apply farmer's column grant
UPDATE (used_count, last_used_at) on saas.enrollment_keys. Read the root
password from a file or env, never argv; never log DSNs or passwords.
Baseline migration 00001 per schema is CREATE TABLE IF NOT EXISTS generated
from the current GORM models, so existing installs are a no-op. Migrations
are forward-only, idempotent (MySQL DDL is not transactional) and written
backward compatible for one version; no automatic down. Subcommands:
migrate up, migrate check (exit non-zero unless the schema version is within
the range this binary supports, without changing anything; this is what a
helm rollback runs). Guard against two concurrent runs with a row-based
lock (GET_LOCK is node-local on Galera, do not use it). Then remove GORM
AutoMigrate from internal/pxc/db.go OpenDB and internal/saasapi/db.go, and
make cmd/farmer and cmd/saasapi check at startup that the schema version
they need is present, retrying with backoff until it is. Scope: cmd/migrate/,
internal/migrations/ (new), internal/pxc/, internal/saasapi/db.go,
cmd/farmer/main.go, cmd/saasapi/main.go, go.mod/go.sum. Do not touch Helm
or .goreleaser.yaml (that is DB.2). Tests: run the migrations against a
real MySQL-compatible server where the repo already does so, plus unit tests
for the version check and lock. Confirm goose and its dependencies are
MIT/Apache and say so in the PR. FLAG FOR SECURITY REVIEW: this binary
holds PXC root credentials and defines the single-writer grants."
```

**FU.0 — signed manifest format (fleetsign)**
```
claude --cloud "Implement FU.0 from docs/BUILD-STATUS.md per API design §2.5
and §2.6. In internal/fleetsign, move the signed message from
version|artifact_url|checksum_sha256 to the canonical
version|os|arch|file_name|checksum_sha256 (no URL anywhere). Define the
Manifest type served to sprouts (version, os, arch, file_name,
checksum_sha256, min_sprout_version, signature) and a strict canonical
encoder shared by signer and verifiers (reject separators and control
characters in fields). Add a Keyring type: a set of Ed25519 public keys by
key id, loaded from a file shipped with the sprout package, and Verify(
manifest) that accepts any key in the ring; no network fetch and no JWKS.
Keep the 'v<key version>:<base64>' signature form. Keep the Transit signer
and verifier code that fleetreleaser and saasapi use compiling, adapted to
the new message. Scope: internal/fleetsign/ only, plus the minimum edits to
callers so the repo builds (list them in the PR); do not change behaviour
of those callers beyond the new message. Tests: round-trip, tamper of every
field, wrong key, key-id rotation (two keys in the ring), downgrade of
min_sprout_version. FLAG FOR SECURITY REVIEW: this is the release trust
root."
```

**DB.2 — migration hook Job (Helm and release wiring)**
```
claude --cloud "Implement DB.2 from docs/BUILD-STATUS.md per API design
§4.1a. In deploy/helm/farmer replace templates/db-bootstrap-job.yaml with one
Helm-hook Job running cmd/migrate (image ghcr.io/yogzblr/imas-migrate, tag =
appVersion): hooks pre-upgrade and pre-rollback, post-install when
pxc.enabled (the bundled PXC does not exist at pre-install), pre-install when
the database is external; hook-delete-policy before-hook-creation,
hook-succeeded; backoffLimit and activeDeadlineSeconds from values; the PXC
root Secret mounted only in this pod; NetworkPolicy to PXC and DNS only;
restricted securityContext like the existing Job. pre-rollback runs
'migrate check', everything else 'migrate up'. Farmer and saasapi
Deployments must not need the root Secret. Update chart_test.go, values.yaml,
the README (drop the wait-for-saasapi text). Also add the cmd/migrate build,
a distroless docker/goreleaser.migrate.dockerfile, and the image to
.goreleaser.yaml (dockers, docker_manifests, services archive ids) and to
the image list in .github/workflows/publish-packages.yml, following the
other four services. Scope: deploy/helm/farmer/, .goreleaser.yaml, docker/,
.github/workflows/publish-packages.yml. Needs DB.1 merged. FLAG FOR
SECURITY REVIEW: root-credential Job."
```

**FU.34 — release registration and signing API (saasapi + fleetreleaser)**
```
claude --cloud "Implement FU.3 and FU.4 from docs/BUILD-STATUS.md per API
design §2.5 (needs DB.1 and FU.0 merged). (1) cmd/fleetreleaser becomes a
stateless HTTP signing service: POST /v1/sign takes one manifest entry,
validates it with internal/fleetsign, signs with the Transit key
imas-fleet-signing and returns {signature}. It has no database access: remove
its direct write to saas.fleet_versions and its DB grant and config. Callers
authenticate with mTLS or a bearer token from a mounted Secret (pick one,
justify in the PR); only saasapi may call it; it refuses a version at or below
the current floor it is configured with. (2) saasapi gets an operator-plane
endpoint POST /v1/operator/fleet-releases (not tenant-facing; separate
credential, not the tenant API-key or BFF path) taking {version, channel,
min_sprout_version, packages:[{os, arch, package_type, file_name,
checksum_sha256}]}. It validates, calls fleetreleaser per package, and
upserts saas.fleet_versions rows in one transaction. Idempotent: same
version and same checksums is a 200 no-op; same version with different
checksums is 409. POST /v1/operator/fleet-releases/{version}/revoke marks
rows revoked. (3) A goose migration (from DB.1) gives fleet_versions the
columns os, arch, package_type, file_name, min_sprout_version, revoked and
UNIQUE(version, os, arch), and drops artifact_url. (4) Update the OpenBao
policies and deploy/fleetreleaser/README.md for the service shape.
Scope: cmd/fleetreleaser/, internal/saasapi/ (fleet registration, model,
router, tests), internal/migrations/ (new migration only),
deploy/fleetreleaser/, docs/api/. Do not touch the Helm hook (FU.5) or the
farmer manifest endpoint (FU.1). Tests: idempotence, 409, revoke, no DB
access in fleetreleaser, auth refusal, and the existing OpenBao read-only
test must still pass. FLAG FOR SECURITY REVIEW: sole signer and the
registration trust boundary."
```

**FU.1 — farmer manifest endpoint**
```
claude --cloud "Implement FU.1 from docs/BUILD-STATUS.md per API design §2.6.
In farmer add GET /v1/sprout/update-manifest?os=&arch=&version= on the
existing recipe HTTP endpoint, behind the same sprout JWT Auth as
/v1/recipes (internal/api/routers.go, internal/api/handlers/). It reads
saas.fleet_versions and saas.tenant_update_policy through farmer's existing
read-only saas grant and returns the internal/fleetsign Manifest for the
caller's own tenant, os and arch, only for a version that tenant has
approved and that is not revoked; anything else is 404 with a generic body
(do not distinguish unapproved, revoked and unknown). The tenant comes from
the verified JWT, never from a query parameter. Rate-limit per sprout and
cache briefly per (tenant_id, os, arch, version) — key every cache and map on
(tenant_id, sprout_id/tenant_id), never sprout_id alone. Scope:
internal/api/ and internal/api/handlers/, tests, docs/api/. Tests: cross-
tenant isolation, unapproved and revoked versions, missing arch, bad JWT,
no URL ever in the response. Needs FU.0 and FU.34 merged."
```

**FU.2 — sprout fetch, verify, install**
```
claude --cloud "Implement FU.2 from docs/BUILD-STATUS.md per API design
§1.8 and §2.3. Rewrite internal/ingredients/selfupdate: the self_update
action carries only target_version (internal/saasapi and the sealed cmd are
unchanged). The sprout (1) GETs its manifest from the farmer recipe endpoint
with its JWT (SproutRootCA-pinned) for its own os/arch and target_version;
(2) verifies it with internal/fleetsign.Keyring loaded from a keyring file
shipped in the package (packaging/etc/fleet-signing-keys.json: key id to
base64 Ed25519 public key; ship it in the nfpm contents and the MSI, and
document that rotation adds a key in a release signed by the old one);
(3) refuses any version lower than the running one, and any manifest whose
min_sprout_version is above the running version; (4) builds the download URL
from the repo already configured in the sprout (the same per-OS repo the
Ansible role sets: apt/rpm base URL or the Windows feed/MSI URL, plus
file_name; add the config key(s) if missing and expose them in ansible/ and
packaging/etc), downloads over HTTPS with the OS trust store, the sprout's
proxy settings and the optional repo token, and NO sprout JWT and NOT
SproutRootCA; (5) checks the SHA-256 against the signed manifest before
anything else; (6) installs from that local file: dpkg -i, rpm -U (zypper
on SUSE), msiexec /i /qn on Windows, run so the service restarts onto the new
version, and reports the outcome. Remove ErrInstallNotImplemented and retire
internal/update's backup/rename scaffolding if nothing else uses it (say what
you removed). Scope: internal/ingredients/selfupdate/, internal/update/,
internal/config/, packaging/etc/, packaging/windows/, .goreleaser.yaml
(nfpm contents only), ansible/roles/imas_sprout/ (new variables only).
Tests: table tests for every refusal above, a local HTTPS server standing in
for the repo, hash mismatch, downgrade, Windows install path mocked. Needs
FU.0 and FU.34 merged and FU.1's contract. FLAG FOR SECURITY REVIEW: this
installs code as root/SYSTEM."
```

**FU.5 — Helm release registration hook**
```
claude --cloud "Implement FU.5 from docs/BUILD-STATUS.md per API design §2.5.
In deploy/helm/farmer add a post-install/post-upgrade hook Job that reads
files/sprout-release.json (written at release time by
packaging/helm/stamp-sprout-release.sh) and POSTs it, with the chart's
min_sprout_version value, to saasapi's operator-plane
/v1/operator/fleet-releases using a dedicated operator credential from a
Secret (new ServiceAccount, no other access). It runs after the app
rollout, retries with backoff, treats 200 (idempotent re-run) as success and
409 as a hard failure that fails the release and prints the mismatch. If
files/sprout-release.json is absent (a dev install from source) the hook is
skipped with a NOTES.txt line. Add a revoke runbook to the README. Scope:
deploy/helm/farmer/ and the stamp script's output shape if the Job needs a
field (packaging/helm/). Tests in chart_test.go: hook annotations and
weights, skipped without the file, Secret wiring, NetworkPolicy to saasapi
only. Needs DB.2 and FU.34 merged. FLAG FOR SECURITY REVIEW: operator
credential."
```

**FU.6 — rollout gates and floors**
```
claude --cloud "Implement FU.6 from docs/BUILD-STATUS.md per API design
§2.3. In internal/saasapi/fleet_update_dispatch.go and fleet_updates.go: a
wave completes only when each sprout reconnects and reports the NEW version
(from facts), not when the command is acked; unresponsive_after_update stays
its own status; target_version must equal the tenant's approved version and a
non-revoked registered version; per-tenant concurrency of one in-progress
update (close the check-then-act race with a transactional claim); mixed
os/arch in one batch resolves per sprout; the probe gate stays rejected. Keep
SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED default off. Scope: internal/saasapi/
fleet_*.go and tests, docs/api/. Needs FU.1, FU.2, FU.5 merged. Do not enable
the flag by default; the Terraform UAT gate decides that."
```

**FU.6b — gate freshness and the rollout claim column**

Follow-up to FU.6's open PR questions 2 and 3. Question 1 (a target built
before FU.6 cannot report its version) is not addressed: no sprout is in
production. Question 4 (on-demand `facts.request`) is deferred: an update
restarts the sprout, which republishes its facts on connect, and saasapi has
no path to the tenant bus connections.
```
claude --cloud "Implement FU.6b from docs/BUILD-STATUS.md, answering two open
questions left on FU.6 (internal/saasapi/fleet_update_dispatch.go,
fleet_sprout_facts.go, model.go). Rebase on main first.

(A) Gate freshness. SproutFacts deliberately ignores farmer.props.expiry,
which is right for planning (a sprout's last report is what planUpdateItems
needs). For the rollout GATE a row only counts as proof if it was written
after the item's dispatch: otherwise a leftover row naming the target version
(an earlier attempt, or a package reinstalled by an administrator) would pass
the wave without evidence. A prop's write time is expiry minus
props.DefaultPropTTL; do not add a column or a second query, and import the
constant rather than copying 5 minutes (TestFarmerSproutFactsColumnContract-
style tests must pin that the expiry column and the TTL relationship still
hold, so a props change breaks a test instead of silently loosening the
gate). Extend the facts reader with a second method that also returns each
fact's write time (keep SproutFacts' signature and its ignore-expiry
behaviour for planning), and make the wave check treat a sprout as
succeeded only when its sprout_version equals the target AND the
sprout_version row's write time is after that item's dispatch time (record
the dispatch time per item in the rollout state; use the saasapi clock, and
allow a small documented clock-skew margin, 30s, between saasapi and the
farmer node that wrote the row). A sprout that reports the target version
only with an older write time stays running until the wave deadline, then
unresponsive_after_update as today. Items that were 'already running' at
planning are unchanged.

(B) Dedicated rollout claim column. claimRollout currently writes
tenant_update_policy.updated_at to make Galera certification refuse one of
two claims committed on different nodes, so updated_at moves when a rollout
starts and GET update-policy reports a policy change that never happened.
Add column rollout_claimed_at (nullable, millisecond precision like
updated_at) to saas.tenant_update_policy with a goose migration in
internal/migrations/saas (next number; forward-only, idempotent, backward
compatible for one version: the old binary ignores the column) and the model
field. claimRollout writes rollout_claimed_at instead, with the same
always-later-than-stored rule (claimTimestamp) so the write is never a no-op
MySQL would skip, and no longer touches updated_at. PATCH update-policy and
GET keep their meaning: updated_at changes only when the policy does. Do not
expose rollout_claimed_at in the API unless a test or doc already needs it.
Update the comments on claimRollout, the fleet_update_dispatch.go header and
docs/api to say so.

Scope: internal/saasapi/ (fleet_update_dispatch.go, fleet_sprout_facts.go,
model.go, tests), internal/migrations/saas/ (one new migration and its
test), docs/api/. Do not change farmer, the sprout, props, or the update
flag. Tests: a stale row naming the target version does not pass the gate;
a fresh one does; skew margin boundaries; two concurrent claims on one
tenant still produce exactly one rollout (reuse the existing concurrency
test against the new column); updated_at is unchanged by a rollout start
and still changes on PATCH; the migration is a no-op on a re-run and the
old model still loads with the column present. State in the PR what you
deferred and any open question. FLAG FOR SECURITY REVIEW: the gate is what
decides a fleet update succeeded."
```

---

## 4c. Wave 5: Wave 4 clean-ups

Added 2026-10-03 from the "Open items" list in `docs/BUILD-STATUS.md`
(item 5), plus REL.1 (replace GoReleaser Pro with a wixl build hook, a
first-release prerequisite). These were the leftovers Wave 4 knowingly left behind. None of
them blocked the Terraform UAT gate, but CL.1 removed attack surface and CL.3
closed the restart gap that kept a tenant's one rollout slot taken. Not in
this wave: `shell.*` sealing, sprout reconnect jitter and a clustered bus
(separate, larger items), and the `requirements.md` item 15 wording (a
separate docs change, DOC.1).

Sub-waves, each held until the one before is merged to `main`:

| Wave | Briefs (run in parallel) | Why this order |
|---|---|---|
| 5A | CL.1, CL.3 | Disjoint scopes: CL.1 is farmer, pki and the sprout enrollment client; CL.3 is `internal/saasapi`. |
| 5A | REL.1 | Independent of CL.1 and CL.3: scope is `.goreleaser.yaml`, the workflows and `packaging/`. It only shares the two release rows of `docs/BUILD-STATUS.md`, so merge whichever finishes first and rebase the other. Run it first if the first release is the priority, because the Terraform UAT gate needs published packages. |
| 5B | CL.2a, then CL.2b | CL.2a touches `cmd/farmer/main.go` and files CL.1 edits, so it waits for CL.1. CL.2b follows CL.2a so it reuses the shared package CL.2a creates. |

**Status, 2026-10-03:** CL.1 (PR #62), CL.3 (PR #63), REL.1 (PR #64, #65),
CL.2a (PR #66) and CL.2b (PR #67) are all merged; the briefs below are kept
as the record of what was asked, do not re-dispatch them. Follow-ups they
left are in `docs/BUILD-STATUS.md` Open items 5, 6 and 10.

Every brief below inherits `CLAUDE.md`. The prompts avoid backticks, double
quotes and dollar signs so they survive being pasted inside a shell string.

**CL.1: remove the dead live fleet-key-set path**
```
claude --cloud "Implement CL.1 from docs/BUILD-STATUS.md ('Open items',
item 5, first clean-up). FLAG FOR SECURITY REVIEW.
Background: since FU.2 the sprout verifies fleet manifests against the
keyring shipped in its package (internal/fleetsign keyring, packaging/etc/
fleet-signing-keys.json). The design (docs/design/cloudxp-machine-manager-
api-design.md section 2.5, Key rotation) drops the live key-set fetch on
imas.sprouts.<id>.fleetsigningkeys and the enrollment-time pin. The code
was never removed. Verified on main: nothing outside tests calls
pki.LoadPinnedFleetSigningKeys, and no sprout code calls the fleetkeys
request function, but farmer still subscribes to the subject, still grants
it in each sprout JWT, still returns fleet_signing_jwks from POST /v1/enroll,
and the sprout still requires and pins that field.
Remove, in this order, one commit each: (1) farmer side: delete
internal/fleetkeys, its wiring in cmd/farmer/main.go (the fleetkeys.
SetKeySource call and RegisterFarmerListener call; keep the rest of
initFleetKeySource, because farmer still serves the signed manifest and
re-verifies a release before dispatching a self_update from the same
read-only key source), payloadbox.PurposeFleetSigningResponse and its entry
in payloadbox_test.go; (2) the NATS grant for imas.sprouts.<id>.
fleetsigningkeys and its reply subjects in internal/pki/jwtusers.go, and
internal/pki/fleetsigningkeys_integration_test.go (keep a test proving a
sprout JWT still cannot publish or subscribe to other sprouts subjects);
(3) enrollment: stop returning fleet_signing_jwks from handlers/enroll.go,
delete handlers/fleetjwks.go and the GET /v1/.well-known/fleet-signing-
jwks.json route in internal/api/routers.go with its test, and drop the
field from the sprout enrollment client (internal/pki/enrollclient.go: the
struct field, the ParseJWKS validation, the PinFleetSigningKeys call);
delete internal/pki/fleetkey.go and its tests; (4) config: remove
SproutFleetSigningJWKS and the sproutfleetsigningjwks key from
internal/config (config.go, paths_windows_test.go), packaging/etc and the
ansible role if present, and the Molecule stub farmer
(ansible/molecule/stubfarmer main.go and main_test.go); config_files_test.go
must still pass; (5) docs: deploy/fleetreleaser/README.md, the API design
doc (sections 2.5 and 3, and the section 6 open item), docs/api, and
docs/design/imas-payload-encryption-design.md (its Boundaries sealed so far
paragraph mentions the fleetsigningkeys reply), then BUILD-STATUS.
Do not remove anything fleetsign still uses for the shipped keyring, the
manifest endpoint or FU.7 re-verification; if the Envoy config or the
Helm NetworkPolicies mention the removed route or subject, remove that too
and say so. Wire compatibility: a sprout built before this change refuses to
enrol against a farmer built after it (it requires the field). That is
acceptable pre-production; state it in the PR with the upgrade order
(sprouts first, then farmer, or re-enrol). Enrolled sprouts keep the unused
JWT grant until their next re-mint; that is harmless, say so in the PR.
Scope: cmd/farmer/main.go, internal/fleetkeys/, internal/pki/, internal/
payloadbox/, internal/api/, internal/config/, internal/fleetsign (comments
only), packaging/etc/, ansible/ (role and molecule stub), deploy/envoy/
and deploy/helm/ only if they reference the removed route or subject, and
the docs named above. Tests: go test ./... must pass, and the real-Envoy
suites (IMAS_TEST_ENVOY_BIN, see docs/BUILD-STATUS.md) must still pass if
you can run them. PR: list every symbol and file removed, the wire
compatibility note, and anything you left because something still uses it."
```

**CL.3: outbox sweeper**
```
claude --cloud "Implement CL.3 from docs/BUILD-STATUS.md ('Open items',
item 5, outbox sweeper) per docs/design/imas-internal-api-account.md
('Outbox re-dispatch sweeper', currently deferred) and the comments in
internal/saasapi/provisioning.go, sprout_actions.go and
fleet_update_dispatch.go. FLAG FOR SECURITY REVIEW.
Problem: provisioning, action-batch and update-rollout dispatch run in
goroutines of the process that accepted the request. If that pod restarts or
has no bus connection, tenant provisioning jobs stay pending, queued batch
items are never sent, and an update rollout stops with its tenant's one
rollout slot (rollout_claimed_at) held forever.
Add a sweeper to saasapi, safe with several replicas. Use a row-based lease,
not GET_LOCK (node-local on Galera): new columns on the rows it sweeps (for
example lease_owner and lease_until, plus the last-dispatch time it needs
to back off), added by a new goose migration in internal/migrations/saas
(next number after 00005; forward-only, idempotent, backward compatible for
one version), claimed with a conditional UPDATE that checks rows affected.
Never run two sweepers on the same row. Key everything on (tenant_id,
sprout_id) or the existing composite keys, never sprout_id alone.
Three jobs, each its own commit with tests: (1) provisioning_jobs: re-publish
jobs still pending after a threshold, bounded by the existing attempts
column with exponential backoff, then mark the job failed with a clear
error; first read farmer's handler for internal.tenant.provision and
deprovision and confirm a repeated job_id is harmless, and fix farmer if
it is not; (2) action batch items that are still queued (a queued item has
provably never reached farmer): re-dispatch from the batch action_params.
Items in dispatching must NEVER be re-sent, because cmd.run is not
idempotent (see the comment on AssetActionItemStatus). Do not change what
happens to a stuck dispatching item; list it as an open question in the PR;
(3) self_update rollouts: resume a rollout whose process died. Rebuild
wave state from the database, take over the tenant's claim only after its
lease expires, continue with the unsent queued items using the batch's
original wave size and gate, and judge items already sent with the gate's
deadline measured from their recorded dispatch time. Before every resumed
wave re-check that the version is still approved by the tenant, registered
and not revoked (the same checks CreateFleetUpdateBatch and farmer's FU.7
re-verification make), and halt with rollout_halted if not. If wave state
cannot be rebuilt from existing columns, add what is missing in the same
migration and explain it in the PR. Resume only runs when
SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED is true.
Configuration: SAASAPI_OUTBOX_SWEEPER_ENABLED (default true),
SAASAPI_OUTBOX_SWEEP_INTERVAL, the staleness thresholds and attempt limit,
documented in docs/api/saasapi.md and read in internal/saasapi/config.go.
Never log command lines, action params or tokens. Skip a sweep cleanly when
there is no bus connection. Tests: simulate a crash (dispatch with a nil bus,
then sweep with a bus and check exactly one send per item); two sweepers on
one database never double-send; a dispatching item is never re-sent; a
revoked version halts a resumed rollout; an expired lease is taken over and a
live one is not. Include a MySQL-backed test where the existing migration
tests already have one. Update docs/design/imas-internal-api-account.md,
the API design doc open items, and BUILD-STATUS. Scope: internal/saasapi/,
internal/migrations/saas/, cmd/saasapi/, internal/natsapi/ and
internal/controlplane/ only if farmer's idempotency needs a fix, deploy/
helm/farmer/ for the new environment variables, docs/. PR: state the lease
design, what is and is not re-sent, and the open question on stuck
dispatching items."
```

**CL.2a: official OpenBao Go client (farmer, fleetreleaser, certs, tenant keys)**
```
claude --cloud "Implement CL.2a from docs/BUILD-STATUS.md ('Open items',
item 5, OpenBao client). Decision of 2026-09-29, now in docs/design/
requirements.md item 21: MPL-2.0 dependencies are accepted, including the
OpenBao Go client, so imas's hand-rolled OpenBao HTTP code is to be replaced
by it. Verify the module path and licence first (it should be
github.com/openbao/openbao/api/v2, MPL-2.0; read its go.mod and licence on
GitHub). If any dependency it pulls in is not Apache-2.0, MIT, BSD, ISC or
MPL-2.0, or if it needs CGO, stop and report instead of adding it.
Hand-rolled call sites on main today (all use X-Vault-Token over net/http):
internal/openbaokv/client.go, internal/fleetsign/obtransit.go, internal/
gatewayjwt/obtransit.go, internal/certs/tls.go, internal/pki/tenantbox.go,
cmd/fleetreleaser/obtransit.go, and the test helpers internal/gatewayjwt/
transittest and internal/pki/tenantboxtest. Do NOT touch internal/
ingredients/sdb/openbao (that is CL.2b, it runs on customer sprouts).
Design: first add one small internal package (for example internal/openbao)
that builds the client from the existing IMAS_*_OPENBAO_* environment
variables and owns auth (static token, and the kubernetes login that
internal/openbaokv does today), token renewal or re-login before expiry, the
optional CA certificate, timeouts and the namespace header if one is set.
Then migrate each call site in its own commit. Keep every environment
variable name, default and failure mode as it is today (farmer must still
start without the Transit keys and fail closed on POST /v1/enroll). Keep the
regression tests that encode past bugs: internal/fleetsign/openbao_response_
test.go and internal/gatewayjwt/openbao_response_test.go (the PEM and base64
public key format mismatch against real OpenBao responses), and
TestOpenBaoEnforcesReadOnlyFleetKey, which proves fleetreleaser alone can
sign and farmer and saasapi cannot. The existing httptest stubs should keep
working by pointing the client at them; if a stub has to change, say why.
fleetreleaser must stay a stateless signer with no database access. No new
long-lived goroutines without a shutdown path. After migrating, delete the
duplicated request, header and error-handling code, and confirm nothing in
the repo still sets X-Vault-Token outside the shared package and the sdb
provider. Run go-licenses (the go-licenses workflow) and report new
dependencies and their licences in the PR; update DEPENDENCIES.md and the
dependencies directory the way that workflow does. Scope: the files above,
go.mod and go.sum, DEPENDENCIES.md, dependencies/, docs. Tests: go test
./... must pass, plus the real-OpenBao tests if you can run them. FLAG FOR
SECURITY REVIEW. PR: list each call site migrated, the behaviour kept, the
dependency and licence diff, and the resulting binary size change for
farmer, saasapi and fleetreleaser."
```

**CL.2b: OpenBao client in the sprout sdb provider**
```
claude --cloud "Implement CL.2b from docs/BUILD-STATUS.md ('Open items',
item 5, OpenBao client), after CL.2a is merged. Read CL.2a's shared package
and PR first. Migrate internal/ingredients/sdb/openbao/provider.go (the
sprout-side sdb:// provider for OpenBao and customer Vault) to it, or to the
official client directly if the shared package carries server-only
assumptions.
This code runs on every customer sprout against the customer's own server,
so check what a server-side swap would not: (1) binary size: build cmd/sprout
for linux amd64 and windows amd64 before and after (no CGO) and report both
sizes; if the sprout grows by more than 5 MB, stop before merging the
change and report the numbers; (2) the provider authenticates with a client
certificate that internal/ingredients/sdb/certwatch.go reloads when the file
changes, and with a token cache (tokencache.go): keep both behaviours,
including no restart after a certificate rotation; (3) the customer server
may be HashiCorp Vault, not OpenBao: keep working against KV v2 and the
cert auth method on both, and say in the PR which you tested; (4) the
sprout proxy settings (ProxyFromEnvironment) and the sdb:// path syntax stay
as they are; (5) secrets must never appear in logs or error strings, and
sensitive registered variables stay redacted. Keep the existing tests
passing and add a test that rotates the client certificate while the provider
is running. If the official client cannot meet (2) or (3) cleanly, do not
force it: leave the provider as it is, and write up why in the PR and in
BUILD-STATUS (Open items, item 5). Scope: internal/ingredients/sdb/, go.mod,
go.sum, DEPENDENCIES.md, dependencies/, docs. FLAG FOR SECURITY REVIEW."
```

**REL.1: replace GoReleaser Pro with GoReleaser OSS and a wixl build hook**
```
claude --cloud "Implement REL.1 from docs/BUILD-STATUS.md ('Open items',
item 1, first-release prerequisite) and docs/RELEASING.md: stop depending on
GoReleaser Pro. FLAG FOR SECURITY REVIEW.
Background: GoReleaser itself is MIT licensed; only the Pro edition needs
GORELEASER_KEY. The only Pro-only feature in .goreleaser.yaml is the
top-level msi pipe (the GoReleaser docs say it is exclusively Pro). If you
can install the OSS goreleaser binary, run goreleaser check with it and
report anything else it rejects; if you cannot, say so. release.yml and
snapshot.yml pin distribution goreleaser-pro and fail without the key.
Goal: the same MSI, built by wixl from a script that GoReleaser OSS runs as a
post-build hook, with the MSI still listed in the signed checksums.txt and
still a release asset, so .github/workflows/publish-packages.yml, packaging/
windows/winget/build-winget-nupkg.sh and the Ansible role keep working
unchanged.
Do, one commit each: (1) packaging/windows/build-msi.sh (new). Arguments:
--binary, --version (GoReleaser Version, no leading v, may carry a
prerelease such as 1.2.3-rc.1), --out directory, optional --timestamp.
Promote the Python stand-in that packaging/test/test-windows-packaging.sh
already uses to render the .wxs template fields (Major, Minor, Patch,
Version, MsiArch as x64, Binary, and dropping the else branch and the
Runtime.Goos windows blocks) so there is one renderer, and fail on any
unhandled template action. Stage a temp directory holding imas-sprout.exe,
packaging/etc/imas-sprout.conf and packaging/etc/fleet-signing-keys.json at
those relative paths next to the rendered wxs (what the msi pipe did), run
wixl -a x64, run packaging/windows/msi-postprocess.sh on the result, and
write imas-sprout-VERSION-windows-x64.msi into the out directory (the name the
msi pipe produced). Use set -euo pipefail, give clear errors when wixl,
msibuild or msiinfo are missing, and never leave a partial MSI behind. Keep
the output reproducible for the same inputs where wixl allows (fixed file
modification times from the timestamp argument) and say in the PR whether it
is.
(2) .goreleaser.yaml: delete the msi block. Add a post hook to the build with
id sprout-windows-pkg that calls the script with the built binary path, the
Version and the dist directory as output (build hook templates provide Path
and Version). Add checksum.extra_files and release.extra_files entries that
glob the MSI in dist; checksums are written after builds, so the file exists
by then, but confirm that in a snapshot run rather than assuming it. Remove
imas-sprout-msi from release.ids (that artifact no longer exists). Keep the
checksum file name checksums.txt and both signs entries (gpg and cosign)
unchanged, so the MSI hash stays covered by both signatures. Update the
comments, including the note about msi.ids.
(3) Workflows: release.yml and snapshot.yml use the OSS distribution and drop
GORELEASER_KEY from the environment, the secret check list and the header
comments. Keep GPG_PRIVATE_KEY and GPG_PASSPHRASE. Fix snapshot.yml's stale
comment about S3 and Docker Hub.
(4) packaging/test/test-windows-packaging.sh: call build-msi.sh instead of its
own stand-in, and keep every assertion.
(5) CI proof that needs no secrets: a job or workflow, on pull requests that
touch .goreleaser.yaml, packaging/ or the workflows, that installs goreleaser
OSS, wixl and msitools, runs goreleaser check, then a snapshot with publish,
signing and docker skipped (read goreleaser release --help for the valid skip
values), then asserts that dist holds exactly one MSI, that checksums.txt
lists it, and that sha256sum --check passes on it. It also runs
test-windows-packaging.sh.
(6) Docs: packaging/README.md (the table row, the paragraphs about the msi
pipe, the msi.ids note), the header comment in packaging/windows/
imas-sprout.wxs, docs/RELEASING.md (remove GORELEASER_KEY from the status
banner and say GoReleaser OSS is used), docs/BUILD-STATUS.md (the release flow
row and the first-release prerequisite).
The oldest supported Windows is Windows Server 2016 (decided 2026-10-03; no
client Windows). Do not add anything to the MSI that needs a newer Windows
Installer than 5.0, say in packaging/README.md that 2016 is the floor and
that winget is not present on it (Ansible win_package installs the MSI there),
and note in the PR that no 2016 host has installed it yet.
Do not change what the MSI contains or does. Compare the table dumps of the
old build (the msi pipe, or the existing test script's build at the parent
commit) and the new one: msiinfo export of Property, Component, File,
Directory, ServiceInstall, ServiceControl, MsiLockPermissionsEx and
MsiServiceConfigFailureActions, and state that they match or list the
differences. Do not touch the Linux packages, the container images or Helm
publishing. Out of scope: go-msi, MSIX, and installing the MSI on Windows;
say in the PR that nothing has installed this MSI on a Windows host yet and
that the first real tag is still the real test of the whole pipeline.
Scope: .goreleaser.yaml, .github/workflows/, packaging/windows/, packaging/
test/, packaging/README.md, docs/RELEASING.md, docs/BUILD-STATUS.md. Tests:
go test ./... and packaging/test/test-windows-packaging.sh must pass. PR:
state exactly what was run and what was not."
```

## 4e. Wave 7: security fixes and sealing, before the UAT gate

Added 2026-10-04 from `docs/security-review-2026-10.md` (PR #81) and the two
designs in `docs/design/imas-payload-encryption-design.md` ("Sealing
`shell.*`", "Sealing the control plane"). Owner decisions, 2026-10-04:

- The legacy shared tenant keypair adoption path is deleted (review H3).
- Revocation is enforced on farmer, not on the sprout (review L4).
- Tenants write recipes and upload them through the SaaS API, so recipe
  templates are untrusted input (review M8 becomes a blocker).
- Sealing is built before the Terraform UAT gate.
- Nothing is deployed, so there is no compatibility window: the sealing
  briefs end in sealed-only. No bearer-token fallback, no plaintext fallback,
  none of the design's rollout flags or ratchets, and a sprout with no box
  key is refused rather than downgraded.

Sub-waves, each held until the one before is merged to `main`:

| Wave | Briefs (run in parallel) | Why this order |
|---|---|---|
| 7A | SEC.0, SEC.3a, SEC.3b, SEC.4, SEC.5 | Fixes on today's code. Disjoint areas: SEC.0 is `internal/auth` and `internal/openbao`; SEC.3a and SEC.3b are `internal/pki`, `internal/payloadbox` and the sprout (different files, rebase on each other); SEC.4 is facts, props and recipes; SEC.5 is self-update and dispatch. SEC.0 is tiny and should merge first. |
| 7A+ | REC.1 | SaaS API recipe upload, needed for the UAT. Needs SEC.4 merged (it uses SEC.4's per-tenant key prefix and restricted template functions). Touches saasapi and objectstore only, so it runs in parallel with the J chain. |
| 7A+ | SEC.5b | Added 2026-10-04 at the owner's request: farmer reads each tenant's rollout window (`internal/fleetcatalog`), so the self_update check SEC.5 added can pass; until it lands farmer refuses every self_update. Needs SEC.5 merged. Touches `internal/fleetcatalog` and `internal/natsapi/sprout_action.go`, so it runs in parallel with REC.1 and J.1 to J.3; merge it before J.4, which also works in `internal/natsapi`. |
| 7B | J.1 | The sealing building blocks touch `internal/pki` and `internal/payloadbox`, so they wait for SEC.3a and SEC.3b. |
| 7C | J.2, J.3 | Sealed refresh (pki, api handlers, sprout) and sealed `imas.api.*` (natsapi, auth, CLI) share only J.1's helpers. |
| 7D | J.4, J.5 | Sealed `internal.*` and sealed shell both need J.3 (the natsapi wrapper and the CLI box keys). |
| 7E | SEC.6 | A read-only re-review of the final state. Then the first release and the UAT gate. |

Not in this wave, after the UAT gate: review M6 (same-second `iat` tie in the
bus fence), the other Low findings, sealing the streams to the CLI (Decision D)
and the cook step events, (REC.1, the SaaS API recipe upload, is in 7A+ because the UAT needs it). Every brief inherits `CLAUDE.md`; the prompts
avoid backticks, double quotes and dollar signs.

**SEC.0: token lifetime cap and the OpenBao echo fix**
```
claude --cloud "Implement SEC.0 from docs/design/imas-payload-encryption-design.md
('Stopgaps that can ship before the design is built', stopgap 1) and
docs/security-review-2026-10.md (M7). Two small fixes and nothing else.
FLAG FOR SECURITY REVIEW.
(1) The CLI API token is an NKey signature over an expiry time, and
UserAuth.IsValid in internal/auth sets no upper bound on it, so a compromised
bus can mint a token valid until 2099 from a crafted nonce. Make IsValid refuse
an expiry more than 5 minutes plus the existing clock skew allowance in the
future. Check every place that creates or validates these tokens
(internal/auth, internal/api/client, cmd/imas, the natsapi middleware) so no
legitimate caller asks for a longer one. Keep the error generic. Tests: a
regression that runs a fake server sending a nonce of 2099-01-01T00:00:00Z,
captures the signature the client makes at connect, and shows IsValid refuses
it; boundary tests just inside and just outside the limit; an expired token.
(2) internal/openbao statusError copies a non-JSON response body into the error
(the official client sets ResponseError.RawError), and pki.rotatetenantbox
returns that text to the tenant. Keep Errors only when RawError is false,
otherwise report the status code alone. Change the test that pins the old
behaviour to assert the body is absent, and add one for the kubernetes login
path.
Scope: internal/auth, internal/api/client (only if needed), internal/openbao,
docs/BUILD-STATUS.md (Open item 11 stopgap line only). Tests: go test ./...
must pass. PR: state what you built, what you deferred, and any open question."
```

**SEC.3a: deleted sprouts, box keys, sprout IDs, legacy keypair**
```
claude --cloud "Implement SEC.3a from docs/security-review-2026-10.md (H1, M3,
M4 and the legacy keypair part of H3). Owner decisions, 2026-10-04: nothing is
deployed, so no existing install needs migrating; the legacy shared tenant
keypair adoption path is DELETED; schema and wire changes are fine now. FLAG
FOR SECURITY REVIEW.
(1) H1: deleting or replacing a sprout must end its bus credential and its box
key. Record a revocation for the removed NKey in a per-tenant revoked-keys list
(a revocation set derived only from rows in unaccepted, denied or rejected
cannot remember deleted rows) and apply it in DeleteNKey, on the AcceptNKey
replace path, and in the rebuilt Account JWT revocations. In the same
transaction revoke every pki_sprout_box_keys row for the tenant and sprout. Make
upsertSproutBoxKeyActive demote other active rows; add a goose migration (see
internal/migrations) with a unique constraint of one active key per
(tenant_id, sprout_id); make ValidSproutBoxKeys fail closed if more than one row
is active. A freed sprout_id may enrol again with a fresh key; say so in the
docs. (2) M3: accept a box key submission only under the ACTIVE key
(internal/natsapi/boxkeys.go, pki.OpenFromSprout); a grace key may only
re-assert the key that is already active. (3) M4: reject dots in sprout IDs
(IsValidSproutID), map dots to dashes in resolveEnrollSproutID, and reserve
control tokens such as announce. Check every subject pattern that takes a token
by position (facts, boxkey.pub, shell, logs) against the new rule. (4) H3,
legacy part: delete the adopted-legacy path in internal/pki/tenantbox.go so
every tenant gets its own fresh keypair, and delete the legacy read-only KV
path from the Helm policy and values.
Tests: delete a sprout and show its JWT is refused on reconnect and its box key
no longer opens or seals; replace by accept; enrol a reused id and check exactly
one active key; a submission under a grace key refused and under the active key
accepted; dotted and reserved ids; the migration up and down on sqlite and
MySQL like the existing migration tests. Keep every table and map keyed on
tenant_id and sprout_id together.
Scope: internal/pki, internal/natsapi/boxkeys.go, internal/migrations,
deploy/helm/farmer (policy and values only), docs/design/imas-payload-encryption-design.md,
docs/BUILD-STATUS.md (Open item 10 and the requirement 14 row only). SEC.3b edits
the same package in other files: rebase if it merges first. Tests: go test ./...
must pass. PR: state what you built, what you deferred, and any open question."
```

**SEC.3b: tenant binding in sealed messages, replay after restart, cook logging**
```
claude --cloud "Implement SEC.3b from docs/security-review-2026-10.md (H3
tenant binding and proof of possession, M2, H4). Wire format changes are fine:
nothing is deployed. FLAG FOR SECURITY REVIEW.
(1) H3: bind the tenant and the recipient key into every sealed message.
payloadbox.Message gains tenant_id and a recipient key identifier (a hash of the
recipient box public key); Expect checks both; the sprout pins its tenant at
enrollment (it already pins the tenant box public key) and refuses a message for
another tenant; farmer checks the tenant on everything it opens. Update cmd.run,
cook and the box key submission to the new Message. Require proof of possession
of sprout_pub at enrollment (for example the sprout opens a farmer-sealed
challenge): say what you chose and why. (2) M2: after a sprout restarts, a
sealed cmd.run or cook from the last 5 minutes can be replayed because the
replay guard is only in memory. Persist the guard (ids with expiry, atomic 0600
file) or refuse any message whose iat is earlier than process start plus the
skew allowance, and make RespondCook refuse a job id already in the handled jobs
file. Say which you chose, and what happens after a clock jump. (3) H4: the
sprout logs every opened cook envelope at Trace (internal/cook/sproutcook.go)
and log shipping publishes every level on the bus. Log only the job id and step
count; stop shipping Trace and Debug over NATS (a configurable minimum level,
default info); stop logging a new box public key at Notice in
cmd/sprout/boxkey.go. Add a test that no opened body reaches any log sink,
including the NATS sink, and search farmer for the same pattern (opened
envelopes, props, secrets in logs) and fix what you find.
Tests: a sealed message for tenant B opened by tenant A's sprout is refused even
under a shared key; an enrollment without proof of possession is refused; a
replay after a simulated restart is refused for cmd.run and cook; the log sink
test.
Scope: internal/payloadbox, internal/pki (sproutbox.go, farmerbox.go, enroll.go),
internal/cook, internal/ingredients/cmd, cmd/sprout, internal/log,
internal/natsapi/boxkeys.go (only where the Message changes),
docs/design/imas-payload-encryption-design.md, docs/BUILD-STATUS.md (Open item
10 and the requirement 14 row only). SEC.3a edits the same package in other
files: rebase if it merges first. Tests: go test ./... must pass. PR: state what
you built, what you deferred, and any open question."
```

**SEC.4: forged facts, recipe templates, per-tenant recipes**
```
claude --cloud "Implement SEC.4 from docs/security-review-2026-10.md (H2, M8).
Owner decision, 2026-10-04: tenants write recipes and upload them through the
SaaS API, so recipe templates are untrusted input. FLAG FOR SECURITY REVIEW.
(1) H2: farmer stores facts under the sprout_id in the message body
(internal/facts/listener.go). Take the sprout id from subject token 2, drop a
message whose body id differs, validate the id, and key the store on tenant_id
and sprout_id together. Reserve the names that drive decisions (os, arch,
sprout_version, hostname, ip_addresses and the hardware keys) in props.set and
props.delete (internal/natsapi/props.go), or record a source column and make
saasapi read only facts the sprout wrote itself
(internal/saasapi/fleet_sprout_facts.go): say which you chose. (2) Stop splicing
prop and fact values into recipe text before YAML parsing
(internal/cook/helpers.go): quote or escape them, or pass them as data, so a
value containing a newline cannot add steps. (3) M8: remove env from the
farmer-side template function map (internal/cook/farmercook.go populateFuncMap);
audit every other function for file, network, process or secret access and for
unbounded work; cap template output size and execution time; keep props and
hostname, which are already tenant-scoped. (4) Per-tenant recipes: resolve a
recipe name under a per-tenant prefix first and then under a platform-wide
read-only prefix, never under another tenant's. Check how recipes are staged for
sprouts and served at /files/ (internal/api/handlers/recipes.go, internal/cook/store.go,
internal/objectstore, deploy/envoy; the old internal/natsapi/recipes.go no longer exists) and make sure a sprout of tenant A can never fetch tenant B's
staged or source recipe, with a test through the real handler. Do NOT build the
upload endpoints here: in docs/design/cloudxp-machine-manager-api-design.md
section 1.6 write down what they need (PUT and DELETE on
tenants/{tenant_id}/recipes/{name}, size and count limits, validation on upload,
RBAC, audit) so the follow-up brief can be written.
Tests: a forged fact body is ignored; reserved names are refused; a prop value
with a newline stays one value; env and every removed function fail to render;
template time and size limits; a cross-tenant recipe read is refused at every
layer.
Scope: internal/facts, internal/natsapi (props.go), internal/api/handlers (recipes.go),
internal/objectstore, internal/cook (store.go, farmercook.go, helpers.go), internal/saasapi/fleet_sprout_facts.go,
internal/api, deploy/envoy (only if a route needs it),
docs/design/cloudxp-machine-manager-api-design.md, docs/BUILD-STATUS.md (Open
items 10 and the requirement 9 row only). Tests: go test ./... must pass. PR:
state what you built, what you deferred, and any open question."
```

**SEC.5: pre-dispatch fixes (self-update and rollouts)**
```
claude --cloud "Implement SEC.5 from docs/security-review-2026-10.md (M1, L1,
L2, L8, M5): the fixes the review asks for before
SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED is turned on anywhere. Owner decision,
2026-10-04: revocation stays enforced on farmer, not on the sprout (L4): add no
sprout-side deny list. FLAG FOR SECURITY REVIEW.
(1) M1: the signed manifest version is not bound to the package it names. Before
installing, read the package's own metadata and require the name imas-sprout and
a version equal to the manifest's (dpkg-deb -f, rpm -qp --qf, the MSI
ProductVersion). The packages carry a +git version suffix (version_metadata in
.goreleaser.yaml), so compare the canonical version and say how. Pass
--refuse-downgrade to dpkg. Check what zypper does on a downgrade and report. Say
whether fleetreleaser could check the checksum against the tag's signed
checksums.txt; do not build that. (2) L1: add a farmer-side switch
IMAS_SELF_UPDATE_ENABLED, default false, checked in
internal/natsapi/sprout_action.go before any self_update, make farmer enforce the
rollout window as well, and expose the switch in the farmer chart (default
false). (3) L2: in internal/ingredients/selfupdate/download.go replace the
url.Error URL with the redacted form and strip the query, so a presigned URL
never reaches a job error. (4) L8: a live rollout re-checks that the tenant is
active before every wave and every item, as the resumed path does, and stops
with the same code. (5) M5: per-tenant concurrency caps well below the pool size
in saasapi (internal/saasapi/sprout_actions.go) and farmer
(internal/natsapi/sprout_action.go), and a reserved pool for self_update so
rollouts cannot be starved, with Helm values and documented defaults. Farmer must
not block its subscription callback when its pool is full: refuse with a clear
code instead.
Tests for each, including a hostile tenant filling its cap while another tenant
and a rollout wave still proceed, and a downgrade attempt that names an older
genuine package.
Scope: internal/ingredients/selfupdate, internal/natsapi/sprout_action.go,
internal/saasapi, cmd/fleetreleaser (report only), deploy/helm/farmer (values and
env), docs/BUILD-STATUS.md (Open items 4 and 10 and the requirement 20 row only).
Tests: go test ./... must pass. PR: state what you built, what you deferred, and
any open question."
```

**SEC.5b: farmer reads tenant rollout windows (after SEC.5)**
```
claude --cloud "Implement SEC.5b: farmer reads each tenant's rollout window, so
the self_update check SEC.5 added can pass. Today internal/natsapi/sprout_action.go
checkRolloutWindow type-asserts the release catalog to a rolloutWindowCatalog
interface (RolloutWindow(ctx, tenantID) returning start, end, ok, err), and the
SQL catalog in internal/fleetcatalog does not implement it, so farmer refuses
every self_update with internal_error even with IMAS_SELF_UPDATE_ENABLED on.
That fail-closed default stays until this lands. FLAG FOR SECURITY REVIEW.
Build: (1) Add RolloutWindow to the Catalog interface in internal/fleetcatalog
and implement it on SQL: read rollout_window_start and rollout_window_end from
saas.tenant_update_policy WHERE tenant_id = ?, one query, scoped by tenant_id
(CLAUDE.md tenant safety); ok is false when the tenant has no policy row; both
columns NULL means no window; exactly one NULL is a corrupt row and must fail
closed, not be read as no window. Return times in UTC. (2) Drop the type
assertion in checkRolloutWindow now that every Catalog has the method, and
remove the failing-closed message that names the missing method; keep the
rule identical to saasapi policyRefusal (internal/saasapi/fleet_update_dispatch.go):
refused when now is before start or at or after end. Use one shared clock
helper or test both against the same table of cases so the two cannot drift.
(3) Update the fleetcatalogtest fixture and the windowedCatalog stand-in in
internal/natsapi/sprout_action_selfupdate_test.go to use the real
implementation where they can. (4) Check farmer's read-only saas grant covers
the two columns (design doc section 4.1, deploy/helm/farmer README PXC
section); if it is column-scoped and misses them, say so and stop rather than
widen it.
Tests: no row, no window, inside, before start, exactly at start, exactly at
end, after end, one-NULL corrupt row refused, another tenant's window never
read (two tenants with different windows), a failed read is internal_error;
the farmer and saasapi rules agree on the same cases; an end-to-end
self_update through checkSelfUpdateRelease passes inside the window with the
switch on and is refused with rollout_window_closed outside it.
Scope: internal/fleetcatalog (including fleetcatalogtest),
internal/natsapi/sprout_action.go and its tests, internal/saasapi
(fleet_update_dispatch.go, only to share the window rule), docs/BUILD-STATUS.md
(Open item 4 and the requirement 20 row only). Needs SEC.5 merged. Tests: go
test ./... must pass. PR: state what you built, what you deferred, and any
open question."
```

**REC.1: SaaS API recipe upload (after SEC.4)**
```
claude --cloud "Implement REC.1: tenants upload, list, read and delete their own
recipes through the SaaS API. Owner decision, 2026-10-04: tenants write recipes
and upload them through the SaaS API, and the UAT cannot run without it. Today
recipes only arrive in the recipe bucket by a git sync outside this repo, the
SaaS API has no object store client, and farmer reads recipes through
internal/cook/store.go and internal/api/handlers/recipes.go. Recipe templates are
untrusted input. FLAG FOR SECURITY REVIEW.
Read first: docs/security-review-2026-10.md (M8, H2), the SEC.4 PR (the per-tenant
key prefix, the restricted template function map, the section 1.6 notes in
docs/design/cloudxp-machine-manager-api-design.md) and internal/objectstore. Use
the key layout SEC.4 merged; if it did not settle one, use
tenants/<tenant_id>/recipes/<name> and say so.
Build: (1) Routes in internal/saasapi, in the section 1.6 style, every one behind
Auth and tenant-scoped like the others: GET /v1/tenants/{tenant_id}/recipes (list,
paged), GET .../recipes/{name} (content, sha256, size, updated time), PUT
.../recipes/{name} (create or replace), DELETE .../recipes/{name}. Names are
dot-notation like the existing recipes: validate strictly (lowercase letters,
digits, dot, dash and underscore, no empty or dot-only segment, a length cap, no
slash or traversal, nothing that collides with a reserved prefix) and map to the
key in one function that every route uses. (2) Writer: the SaaS API writes to the
recipe bucket directly with its own object store credential limited to the
tenants/ prefix (never sprouts/, jobs or the platform prefix); add the config and
the Helm values and a MinIO or S3 policy example, and say in the PR why this beats
routing through farmer (farmer needs sealed internal.* first, J.4). Reads of the
platform-wide prefix are allowed, writes are not. (3) Validation on PUT, before
anything is stored: body size cap, per-tenant recipe count and total size caps,
UTF-8 text only, the YAML parses, and the template parses and executes against dummy
props with SEC.4's restricted function map under its time and output limits; reject
anything that fails with a clear 4xx and never echo the body in an error or a log.
(4) Concurrency and integrity: a conditional write (If-Match on the stored
checksum or an expected sha256 header) so two editors do not silently overwrite each
other; return the new sha256. (5) RBAC and audit: say which Keycloak role or scope may
write versus read (follow the existing middleware model, least privilege), rate limit
PUT and DELETE like the other mutating routes, and write an audit row for every
write and delete with the tenant, caller, name, sha256 and size, never the content.
(6) Freshness: confirm that farmer and the sprout pick up an uploaded recipe on the
next cook without a restart or a cache to clear (internal/cook/store.go,
the staged recipe path); if there is a cache, add an invalidation or a short TTL and
test it. (7) Update docs/design/cloudxp-machine-manager-api-design.md section 1.6
(replace the stale text that says these proxy farmer recipes.* subjects, which no
longer exist), add the routes to docs/api, and write a short tenant-facing howto for
uploading a recipe with curl in docs/INSTALL.md or a new docs page.
Tests: a tenant cannot read, list, write or delete another tenant's recipes under any
name or encoded path; invalid names, oversize bodies, over-quota, bad YAML, bad
template and a template using a removed function are refused; a conditional write
conflict returns 412; a recipe uploaded through the API cooks on a sprout of the same
tenant and is not visible to a sprout of another tenant (use the embedded
farmer and an in-memory or MinIO test store as the existing tests do); audit rows
carry no content.
Scope: internal/saasapi, internal/objectstore (only if a conditional put or a paged
list is missing), internal/cook (store.go, only for the freshness fix),
deploy/helm (saasapi values, secret and env), docs/design/cloudxp-machine-manager-api-design.md,
docs/api, docs/INSTALL.md, docs/BUILD-STATUS.md (Open items 1 and 10 only). Needs SEC.4
merged. Tests: go test ./... must pass. PR: state what you built, what you deferred,
and any open question."
```

**J.1: sealing building blocks (after SEC.3a and SEC.3b)**
```
claude --cloud "Implement J.1 from docs/design/imas-payload-encryption-design.md
('Sealing the control plane': Decisions A, B and C, and Rollout step 2):
building blocks, with no change in behaviour yet. Owner decisions, 2026-10-04:
sealing is built BEFORE the UAT gate; nothing is deployed, so there is no
compatibility window: no plaintext fallback, no bearer token fallback, no
apiallowbearertoken or internalallowplaintext flags and no per-user or
per-sprout ratchets; the end state in J.3 and J.4 is sealed only; a sprout with
no box key is refused rather than downgraded; method names stay visible in
subjects (open question 9); control traffic uses static keys (open question 8);
the Valkey claim for mutating methods fails closed (open question 7). FLAG FOR
SECURITY REVIEW.
Build: (1) payloadbox purposes and fields for c2f.api, f2c.api, the SaaS API to
farmer pair, and s2f.refresh, bound to the method, the subject and the principal
header, as the design says. (2) The CLI box key store: a table keyed on
(tenant_id, user_id) with the registered public key, status and created and
rotated times, in a new goose migration (farmer schema); admin registration and
rotation on farmer; imas auth keygen and imas auth rotate-key in cmd/imas. (3)
The platform key and the SaaS API box key: generated by a Helm hook job into an
OpenBao path or a Secret (say which), private half readable only by its owner,
and how farmer and saasapi pin each other's public keys. (4) Sealed request and
reply helpers for both ends, the per-replica ReplayGuard use, and the Valkey
claim helper (SET NX on tenant_id, user_id and message id with a 10 minute TTL,
fail closed for mutating methods; use the design's explicit read-only list and
treat cohorts.refresh as mutating; say if you disagree with any entry). (5) The
users store: auth.users.add writes farmer's local config file
(jety.WriteConfig). Find out whether that is consistent across several farmer
replicas and report it; if it is not, move user registration and CLI box keys to
the farmer database in this brief, or stop and say why.
Tests: a round trip for every purpose; wrong key, wrong principal, wrong method,
wrong subject, stale, replayed on one replica, replayed on another replica
(Valkey), Valkey down (mutating refused, reads allowed).
Scope: internal/payloadbox, internal/pki, internal/auth (store only),
internal/migrations, internal/natsapi (helpers only, no router change), cmd/imas
(auth subcommands), deploy/helm/farmer (hook job, values, policy), docs/design,
docs/BUILD-STATUS.md (Open item 11 only). Needs SEC.3a and SEC.3b merged. Tests:
go test ./... must pass. PR: state what you built, what you deferred, and any
open question."
```

**J.2: sealed sprout refresh (after J.1)**
```
claude --cloud "Implement J.2 from docs/design/imas-payload-encryption-design.md
(Decision C): sealed sprout refresh. Today the sprout NKey signs both the
CONNECT nonce and its /v1/refresh proof, so a compromised bus can refresh as
any sprout and read its staged rendered recipe from /files/. Same owner
decisions as J.1: no fallback and no ratchet; a sprout with no box key must
re-enrol. FLAG FOR SECURITY REVIEW.
Build: the sprout sends s2f.refresh (a payloadbox message under its box key to
the tenant key, with the freshness, replay and ReplyTo rules) instead of the
NKey-signed proof; farmer verifies it under the sprout's active box key and the
tenant, returns the new gateway JWT sealed to the sprout, and refuses NKey-only
refresh for every sprout; do the same for any other follow-up call that uses the
NKey proof. Check the Envoy path (deploy/envoy) and the refresh handler in
internal/api/handlers, and keep the jwt_authn behaviour. Think through and test:
a sprout box key rotation during refresh, an expired gateway JWT at reconnect
(the SCALE.1 reconnect path must still recover), clock skew, and the tenant pin.
Tests: the fake-server regression from SEC.0 extended so a signature captured at
CONNECT cannot authorise a refresh; refresh under a rotated key; a stale tenant
pin; a replayed refresh. Run the through-real-Envoy tests
(IMAS_TEST_ENVOY_BIN, see BUILD-STATUS Wave 1) if you can get the binary; say if
you cannot.
Scope: internal/pki (enrollment client, refresh), internal/api/handlers,
cmd/sprout, internal/payloadbox (use only), deploy/envoy (only if needed),
docs/BUILD-STATUS.md (Open item 11 only). Needs J.1 merged. Tests: go test ./...
must pass. PR: state what you built, what you deferred, and any open question."
```

**J.3: sealed CLI to farmer API (after J.1)**
```
claude --cloud "Implement J.3 from docs/design/imas-payload-encryption-design.md
(Decision A): sealed CLI to farmer API. Remove bearer tokens; the CLI NKey signs
only the bus nonce. Same owner decisions as J.1: sealed only, no fallback, no
ratchet. FLAG FOR SECURITY REVIEW.
Build: every imas.api.* request is a payloadbox c2f.api message from the CLI box
key to the tenant key and every reply is f2c.api back, with the method bound to
the subject, a principal header, the per-replica replay guard and the Valkey
claim for mutating methods (J.1 helpers). A router wrapper in internal/natsapi
opens the request, derives the user from the verified key (never from a field in
the body), runs checkScopedAccess for that user and seals the reply. Remove
token creation and validation from internal/auth and the token from the client
(internal/api/client/nats.go) entirely, and update every caller in cmd/imas,
tools and testing. The CLI refuses a plaintext reply. Make auth.users.* work
with the J.1 key store, and make the first admin bootstrappable (a config or Helm
value) without a bus token. Check what the CLI still reads in plaintext (cook
--follow, imas serve) and write down in the design what stays plaintext until
Decision D.
Tests: the forged-token regression (no token can be minted or replayed any
more); wrong key, wrong user, replay on two replicas, a revoked key, a method not
granted; an end-to-end CLI test against an embedded farmer and bus.
Scope: internal/natsapi, internal/auth, internal/api/client, cmd/imas,
internal/pki (CLI key lookups), deploy/helm/farmer (bootstrap admin value),
docs/api, docs/INSTALL.md, docs/BUILD-STATUS.md. Needs J.1 merged. Tests: go test
./... must pass. PR: state what you built, what you deferred, and any open
question."
```

**J.4: sealed SaaS API to farmer (after J.3)**
```
claude --cloud "Implement J.4 from docs/design/imas-payload-encryption-design.md
(Decision B): sealed SaaS API to farmer traffic. internal.* trusts the bus
account's permissions, so a compromised bus can forge provisioning,
deprovisioning, internal.sprout.action and their results. Same owner decisions as
J.1: sealed only, no fallback. FLAG FOR SECURITY REVIEW.
Build: every internal.* request and reply is a payloadbox message between the SaaS
API box key and the platform key (J.1), bound to the method, the subject and the
tenant, with replay protection. Farmer opens only under the registered SaaS API
key and refuses plaintext; the SaaS API refuses plaintext replies and results.
Point-of-effect checks (tenant active, release approval, signatures, rollout
window) keep running on farmer as FU.7 and CL.3 do. The outbox sweeper's re-sends
must produce fresh sealed messages (new id and iat) while idempotency by job id
stays as CL.3 built it. Do not move internal.* onto a core-only transport (design
open question 5): write down in the design what that would take.
Tests: forged and replayed provision, deprovision and sprout_action requests are
refused; forged results are refused; a sweeper re-send; the PKI.1 interleaving
tests still pass; go test -race on internal/saasapi and internal/natsapi.
Scope: internal/saasapi, internal/natsapi (tenant provisioning, sprout_action),
internal/pki (platform key use), docs/design, docs/api, docs/BUILD-STATUS.md.
Needs J.3 merged (it shares the natsapi wrapper). Tests: go test ./... must pass.
PR: state what you built, what you deferred, and any open question."
```

**J.5: sealed shell (after J.3)**
```
claude --cloud "Implement J.5 from docs/design/imas-payload-encryption-design.md
('Sealing shell.*'). Read the whole section first. Where it proposes a default,
take it, as the owner agreed on 2026-10-04: farmer relays with both legs sealed;
leg 1 authenticates with the CLI box key (J.3); idle timeout 15 minutes by
default and 60 at most, maximum session 8 hours; sprout disableshell defaults to
false and is exposed in the Ansible role; the shell allow-list is /etc/shells,
overridable in sprout config; the operator role loses shell unless granted;
keystroke timing leakage is a recorded residual risk; the CLI pins tenantboxpub
from explicit config only; sessions die with their farmer replica and v1 has no
cross-replica shell list; no plaintext fallback and no shellallowplaintextsprouts
flag; Windows sprouts keep refusing shell (ConPTY needs Server 2019 and the
supported floor is Server 2016); no transcripts in v1, only audit entries when a
session opens and ends (ask the owner in the PR whether CERT-In or DPDP need
recording); no browser or SaaS API shell. FLAG FOR SECURITY REVIEW.
Also fix what the design found: sproutPermissions grants no imas.shell.> subject,
so shell does not work for a per-sprout JWT today.
Build: the payloadbox stream codec (HKDF from ephemeral X25519, ChaCha20-Poly1305
with the sequence number as nonce, fail closed on replay, reorder or gap, flow
control, heartbeats); internal/shell on the sprout; the relay in
internal/natsapi/shell.go with the 60 second RBAC re-check and --sever closing
running sessions; the grant in internal/pki/jwtusers.go; cmd/imas/cmd/ssh.go. Mind
the Molecule idempotence note in BUILD-STATUS (Ansible and packaging row) when you
add the role variable.
Tests: integration tests on an embedded nats-server with real per-sprout JWT
permissions and a hostile bus publisher that tries to open, inject, replay,
reorder, drop and read; a sprout refuses a plaintext shell.start; a cross-tenant
open is refused.
Scope: internal/payloadbox, internal/shell, internal/natsapi, internal/pki (the
grant), cmd/sprout, cmd/imas, ansible/roles/imas_sprout, packaging/etc,
docs/design, docs/BUILD-STATUS.md (Open item 2 and the requirement 14 row). Needs
J.3 merged. Tests: go test ./... must pass. PR: state what you built, what you
deferred, and any open question."
```

**SEC.6: read-only re-review of the final state (last)**
```
claude --cloud "Do a read-only security review of everything merged since
eacdc79 and record the findings. Change no code. This is input for the human
security review, not a replacement. FLAG FOR SECURITY REVIEW.
Method: the same as docs/security-review-2026-10.md (read it first): for each
area answer what is trusted, what a compromised bus can do, what a hostile
tenant can do, what a malicious update repository can do, whether everything is
keyed on tenant_id and sprout_id together, whether secrets reach logs, errors or
job results, and where a failure opens instead of closing. Mark every finding
CONFIRMED or UNCONFIRMED and say which link is unverified. Areas, in order: (1)
every High and Medium finding of that review: confirm each is fixed with a test
and say if the fix is incomplete; (2) SEC.0 to SEC.5; (3) J.1 to J.5: the sealed
refresh, CLI API, internal.* and shell. For the sealed designs, test the table
'What a compromised bus can still do' in docs/design/imas-payload-encryption-design.md
claim by claim against the code, and write a throwaway hostile-bus test for each
claim you can, run it, delete it, and report the result; (4) recipes: a hostile
tenant uploading a recipe, templates, staged files and /files/. Write
docs/security-review-2026-10-b.md: findings ranked, each with file and line, a
concrete failure scenario and a proposed fix. Scope: docs/security-review-2026-10-b.md
(new) and docs/BUILD-STATUS.md (Open items 4 only). PR: describe the findings as
ready for review, not as a clean bill of health."
```

## 4f. Post-SEC.6 follow-ups

Added 2026-10-04 at the owner's request after SEC.6 (PR #100,
`docs/security-review-2026-10-b.md`). The owner chose to run these after
SEC.6, including the review's three High findings. They run in parallel, each
in its own session, from `main` at `43e716a`; none gates another, but SEC.7b
and SEC.7c both edit `internal/pki` and most of them touch
`docs/BUILD-STATUS.md`, so later ones merge `main` in. The stub farmer's old
refresh contract stays as it is (owner decision). Every brief inherits
`CLAUDE.md`; the prompts avoid backticks, double quotes and dollar signs.

**SEC.7a: staged recipe envelope authenticated end to end (review B1, B9)**
```
claude --cloud "Implement SEC.7a from docs/security-review-2026-10-b.md (B1, and B9 which
folds into it). The sprout cooks a staged recipe pulled over GET /files/ with no
proof farmer produced it: internal/cook/stagedfetch.go only decodes the body and
internal/cook/stagedsync.go accepts it on non-cryptographic checks, and the DMZ
terminates that TLS. Owner decisions so far: sealed only, no fallback, no
compatibility window (nothing is deployed). FLAG FOR SECURITY REVIEW.
Build: farmer seals or signs every staged envelope it writes for a sprout under
the tenant key, bound to tenant_id, sprout_id, the job id and DispatchedAt,
using internal/payloadbox the way the sealed cook push does (add a purpose such
as f2s.staged to payloadbox's purpose list). The sprout opens or verifies it
against its pinned tenant key before decoding and refuses anything else,
including today's plain JSON, with no fallback. Keep the existing push-race,
handled-job and max-age checks after verification, and take the job id and
freshness only from inside the verified envelope, never from the object key or
headers. Say how an envelope written before a tenant key rotation is handled
(grace keys). Find every farmer writer of the staged envelope and every sprout
reader.
Tests: reproduce the review's throwaway test first (a forged envelope served at
/files/ is cooked) and show it is now refused and not cooked; an envelope for
another sprout or tenant is refused; a replayed old envelope is refused; a
genuine one still cooks; tenant key rotation; go test -race on internal/cook and
internal/pki.
Scope: internal/cook, internal/payloadbox (the new purpose only), internal/pki
(tenant key helpers only), internal/api/handlers (staging only, if needed),
cmd/sprout (wiring only), docs/design/imas-payload-encryption-design.md,
docs/security-review-2026-10-b.md (mark B1 and B9 addressed),
docs/BUILD-STATUS.md (requirement 14 row and Open item 10 only). Other
post-SEC.6 briefs run in parallel: merge main with a merge commit if it moves.
Tests: go test ./... must pass. PR: state what you built, what you deferred, and
any open question."
```

**SEC.7b: no first box key outside the identity-issuing exchange (review B2)**
```
claude --cloud "Implement SEC.7b from docs/security-review-2026-10-b.md (B2). An accepted
sprout with no active box key accepts an attacker-chosen box key at enrollment
and is handed a gateway JWT: openEnrollProof in internal/pki/farmerbox.go opens
the proof against the sprout_pub from the request, recordProvenSproutBoxKey in
internal/pki/enroll.go records it when no key is active, and the idempotency
replay path mints a gateway JWT. A compromised bus can obtain the NKey signature
it needs from an enrollment-shaped CONNECT nonce. Owner decisions so far:
nothing is deployed, no compatibility window, a sprout with no box key is
refused rather than downgraded. FLAG FOR SECURITY REVIEW.
Build: make an accepted-but-keyless sprout a closed state, not a standing
window. Accept a first box key only on the identity-issuing exchange, never on
the replay path for an already accepted sprout: for example bind the proof of
possession to the step 1 response with a farmer-issued one-time nonce that the
step 2 proof must contain, stored with a short TTL and consumed once. A sprout
that is accepted with no active key (revoked keys, pre-J, an abandoned step 1)
must re-enrol with a fresh join token. Say what you chose and why. Keep J.2's
rule that a gateway JWT is issued only after a verified proof, and SEC.3a's
one-active-key and revoked-NKey rules.
Tests: reproduce the review's throwaway test first (keyless sprout, proof sealed
under an attacker key, replay path, key recorded and gateway JWT minted) and
show it now records no key and mints no JWT; the real sprout's step 2 still
succeeds; a step 2 without the step 1 binding is refused; a replayed step 2 is
refused; extend TestConnectNonceCannotEarnAGatewayJWTByEnrolling to the keyless
case; update the stub farmer only if the enrollment contract changes.
Scope: internal/pki (enroll.go, farmerbox.go, enrollclient.go and their tests),
internal/api/handlers (enroll.go and its tests), ansible/molecule/stubfarmer
(only if the contract changes), docs/design, docs/security-review-2026-10-b.md
(mark B2 addressed), docs/BUILD-STATUS.md (requirement 14 row and Open item 10
only). SEC.7c also edits internal/pki in other files: merge main with a merge
commit if it lands first. Tests: go test ./... must pass. PR: state what you
built, what you deferred, and any open question."
```

**SEC.7c: revoked or superseded NKeys lose /files/ at once (review B3)**
```
claude --cloud "Implement SEC.7c from docs/security-review-2026-10-b.md (B3). SEC.3a revokes
a deleted or replaced host's NATS User JWT and box keys but not its gateway JWT:
the /files/ checks (internal/gatewayjwt/verify.go, and sproutFileAccess and
sproutIdentityAuth in internal/api/middleware.go) look only at the signature,
issuer, expiry and the tenant_id and sprout_id claims, gatewayjwtttl defaults to
24 hours, and after a replace the old host reads the new host's staged recipe.
FLAG FOR SECURITY REVIEW.
Build: every gateway JWT check fails closed for a revoked or superseded NKey.
In both sproutFileAccess and sproutIdentityAuth, refuse a token whose sub (the
NKey) is on the tenant's pki_revoked_nkeys list, and require that sub is the
NKey currently accepted for that (tenant_id, sprout_id), so a replace cuts the
old host off at once. Key every lookup on tenant_id together with the NKey or
sprout_id, and fail closed on a database error. Cache only if needed, with a
short TTL and invalidation on delete and accept. Say whether the default
gatewayjwtttl should drop; do not change it without saying why.
Tests: reproduce the review's throwaway test first (accept web-01, delete it,
re-accept under a new NKey, the old host's gateway JWT still reads the file)
and show it is now refused; a deleted sprout's token is refused; a live
sprout's token still works; a database error refuses; cross-tenant is still
refused; the update-manifest route is covered too.
Scope: internal/gatewayjwt, internal/api (middleware.go and its tests),
internal/pki (revoked-NKey and accepted-NKey lookups only), docs/design,
docs/security-review-2026-10-b.md (mark B3 addressed), docs/BUILD-STATUS.md
(requirement 14 row and Open item 10 only). SEC.7b also edits internal/pki in
other files: merge main with a merge commit if it lands first. Tests: go test
./... must pass. PR: state what you built, what you deferred, and any open
question."
```

**SH.1: shell follow-ups from J.5**
```
claude --cloud "Implement SH.1: the three shell follow-ups the owner deferred from J.5 (PR 98).
Read As built: J.5 in docs/design/imas-payload-encryption-design.md and
docs/BUILD-STATUS.md Open item 2 first. FLAG FOR SECURITY REVIEW.
Build: (1) the built-in operator role in internal/rbac/config.go loses the
shell action, as the owner agreed for J.5; shell is granted only by a role that
names it. Update every test, doc or default that assumes operator can open a
shell, and say in the PR what an existing operator user now needs. (2) farmer
calls natsapi.CloseShellSessions() during shutdown in cmd/farmer, before the bus
connection closes, so open sessions end with farmer-shutdown instead of
peer-lost. (3) Update the user docs that still describe shell as plaintext
(docs/INSTALL.md, docs/api/farmer-cli-api.md, README.md, ansible/README.md) to
the sealed shell as built: imas ssh, the tenantboxpub pin, disableshell and
imas_sprout_disable_shell, the idle and session limits, audit entries only, and
Windows refusing shell.
Tests: an operator without an explicit shell grant is refused shell.open; a
role that grants shell still works; farmer shutdown ends open sessions with
farmer-shutdown.
Scope: internal/rbac, cmd/farmer, internal/natsapi (only if the shutdown wiring
needs it), docs/INSTALL.md, docs/api/farmer-cli-api.md, README.md,
ansible/README.md, docs/BUILD-STATUS.md (Open item 2 only). Other post-SEC.6
briefs run in parallel: merge main with a merge commit if it moves. Tests: go
test ./... must pass. PR: state what you built, what you deferred, and any open
question."
```

**CL.4: J.3 cleanup**
```
claude --cloud "Implement CL.4: the J.3 cleanup the owner deferred (PRs 95 and 96). Since J.3
the CLI token is gone and the HTTP recipe routes refuse every request. FLAG FOR
SECURITY REVIEW.
Build: (1) remove the dead HTTP recipe routes GET /v1/recipes and GET
/v1/recipes/{name...} from internal/api/routers.go, their handlers ListRecipes
and GetRecipe in internal/api/handlers/recipes.go, and every stale comment, doc
and Envoy route for them (deploy/envoy, the Envoy config in deploy/helm/nats).
The sealed recipes.list and recipes.get on NATS stay. (2) Remove internal/audit's
unused identity resolver (extractIdentity, identityResolver and its setter in
internal/audit/middleware.go) and anything that only fed it; audit entries must
keep the verified user from the sealed router. (3) imas serve: add boxpub to
POST /api/v1/auth/users in internal/serve/openapi.yaml and in whatever
internal/serve forwards, so it matches farmer's auth.users.add. The web UI
source is the grlx-web-ui git submodule (github.com/gogrlx/grlx-web-ui),
outside this repo, and internal/serve/dist is its built bundle: do not edit the
bundle by hand and do not add a Node toolchain. Write in the PR exactly what the
UI's add-user form must change so the owner can raise it there.
Tests: the removed routes return 404; audit entries still carry the user; the
serve OpenAPI still validates and the add-user path passes boxpub through.
Scope: internal/api, internal/audit, internal/serve (not dist), deploy/envoy and
deploy/helm/nats (route removal only), docs/api, docs/BUILD-STATUS.md (Open item
11 only). Other post-SEC.6 briefs run in parallel: merge main with a merge
commit if it moves. Tests: go test ./... must pass. PR: state what you built,
what you deferred, and any open question."
```

**OPS.1: saasapi NetworkPolicy and PDB after J.4**
```
claude --cloud "Implement OPS.1: answer the question left open on PR 99 (J.4 Helm wiring):
does saasapi's NetworkPolicy or PodDisruptionBudget in deploy/helm/farmer need
to change now that saasapi holds the SaaS API box key, reaches farmer over the
sealed internal.* path (J.4) and writes recipes to the object store (REC.1)?
FLAG FOR SECURITY REVIEW.
Build: read the chart's NetworkPolicy, PDB and the saasapi and farmer
deployments, and list every connection saasapi makes and receives (bus, PXC,
Valkey, Keycloak, object store, OpenBao via External Secrets, farmer). Where the
policy is missing an allowed path saasapi needs, or allows more than it needs,
fix it with least privilege and chart tests; where the PDB is wrong for the
replica count, fix it. If nothing needs to change, change no templates and
write the reasoning into deploy/helm/farmer/README.md. Put any judgement call
in the PR as an open question rather than deciding it.
Tests: chart tests (helm on PATH, so they run rather than skip) for every
policy or PDB change, including a negative case.
Scope: deploy/helm/farmer, docs/BUILD-STATUS.md (one line under the J.4 entry).
Other post-SEC.6 briefs run in parallel: merge main with a merge commit if it
moves. Tests: go test ./... must pass. PR: state what you built, what you
deferred, and any open question."
```

**T.1: fix the flaky J.2 sealed-refresh test**
```
claude --cloud "Implement T.1: fix the flaky test TestRefresh_AnswersOnlySealed in
internal/api/handlers (refresh_test.go), from J.2. It fails in about 1.5
percent of runs (6 in 460) because it searches the sealed reply body for the
substring eyJ, and the random base64 ciphertext sometimes contains it. It is a
test bug, not a leak.
Build: change the assertion to what it means: the response body is exactly the
sealed reply shape, the sealed field opens only under the sprout key, and no
plaintext field of the response is or contains a JWT (three dot-separated
base64url parts whose first part decodes to a JSON header). Do not weaken the
check that no gateway JWT is in the clear. Search the repo's tests for the same
substring pattern and fix those the same way.
Tests: show the old assertion failing on a crafted ciphertext that contains
eyJ, and the new test passing with go test -count=2000 -run
TestRefresh_AnswersOnlySealed ./internal/api/handlers/.
Scope: test files only, in internal/api and internal/pki. Other post-SEC.6
briefs run in parallel: merge main with a merge commit if it moves. Tests: go
test ./... must pass. PR: state what you built, what you deferred, and any open
question."
```

## 4g. Wave 7 validation fixes (FIX.1 to FIX.4)

Added 2026-10-05 after validating `main` at `b78c9e7` (all of PRs 81 to 108
merged, CI green). The validation found a plaintext downgrade left in cmd.run
and cook, job-log keys with no tenant, three Helm gaps on a fresh install, and a
BUILD-STATUS that stops at PR 67. FIX.1, FIX.2 and FIX.3 run in parallel from
`main`; each edits only its own BUILD-STATUS rows, so merge `main` in if it moves.
FIX.4 runs last, after the other three are merged. Every brief inherits
`CLAUDE.md`; the prompts avoid backticks, double quotes and dollar signs.

**FIX.1: remove the plaintext cmd.run and cook path for sprouts with no box key**
```
claude --cloud "Implement FIX.1: delete the last plaintext downgrade in the sealed
command path. Owner decision, 2026-10-04: sealing is sealed-only, with no fallback
and no compatibility window; a sprout with no box key re-enrolls and is refused in
the meantime. Today farmer still sends cmd.run and cook in plaintext to a sprout
with no box key on record (internal/ingredients/cmd/sealed.go, internal/cook/sealed.go,
the boundary request helper), and a sprout with no keys still accepts plaintext from
anyone on the bus (the not-sealed-and-not-ready branches in the sprout side
handlers and in RespondCook). The design doc says these are refused, not downgraded,
so the docs and the code disagree. FLAG FOR SECURITY REVIEW.
Build: (1) Farmer: when pki.SealToSprout returns ErrNoActiveBoxKey, do not send.
Return a clear error naming the sprout and telling the operator to re-enroll it, with
a stable error code, for cmd.run, cook and any other caller of the same boundary
helper; the batch and sprout action paths must record that sprout as failed with the
code, not hang. (2) Sprout: a sprout with no box keys refuses BOTH plaintext and
sealed cmd.run and cook with the existing no-keys refusal; delete the plaintext
execution branches. Check every other handler that has a similar enrolled-before-J
branch (grep for the comment text and for SproutBoxReady) and report each. (3) Delete
dead code this exposes (for example internal/api/handlers/ingredients/cmd/run.go if it
is no longer reached from any route; say what you removed and confirm with grep and
the build). (4) Fix the docs: the table row in docs/design/imas-payload-encryption-design.md
('Attacks sprouts with no box key') becomes true; remove the stale statements in
docs/BUILD-STATUS.md about the plaintext path (Open item 10 and the requirement 14 row
only) and add the plaintext residuals that ARE still real and documented nowhere:
the imas.sprouts.announce join event (farmer only logs it) and the fact that cancel has
no sprout handler. List them as known residuals.
Tests: farmer refuses to send to a keyless sprout and the action records the code;
a keyless sprout refuses a plaintext and a sealed cmd.run and cook; a sprout with keys
still runs a sealed one; the real-bus tests from J.1 to J.3 still pass; go test -race on
internal/cook, internal/ingredients/cmd and internal/natsapi.
Scope: internal/ingredients/cmd, internal/cook, internal/natsapi (error mapping only),
internal/saasapi (only where a send error is classified), internal/api/handlers/ingredients
(dead code only), docs/design/imas-payload-encryption-design.md, docs/BUILD-STATUS.md
(Open item 10 and the requirement 14 row only). Tests: go test ./... must pass. PR: state
what you built, what you deferred, and any open question; call it ready for review, not
done."
```

**FIX.2: tenant-prefix the job object keys (review item I4)**
```
claude --cloud "Implement FIX.2: key job objects on tenant and sprout together. The job
store writes jobs/<sprout_id>/<jid>/... in one global bucket (internal/jobs/store.go,
jobKeyPrefix and the key helpers, plus internal/jobs/clistore.go, jobtypes.go,
internal/serve, internal/saasapi/job_status.go, internal/saasapi/recipes.go and
internal/rbac/config.go where they read or list job keys). sprout_id is unique per
tenant only, so two tenants with the same sprout_id share job logs: a cross-tenant
collision and a read leak. CLAUDE.md requires every table, index, cache and map to be
keyed on (tenant_id, sprout_id). Review item I4 in docs/security-review-2026-10-b.md.
FLAG FOR SECURITY REVIEW.
Build: (1) Change the layout to jobs/<tenant_id>/<sprout_id>/<jid>/... and thread the
tenant id through every writer, reader, lister, expiry sweep, the reconcile window and
the cook step event listener; derive the tenant from the verified principal or the
subject, never from a body field. Reject a tenant_id or sprout_id containing a slash,
dot-dot or control characters before building a key; build every key in one function.
(2) ListAllJobs and any whole-prefix scan must be per tenant, or if a platform-wide scan
is needed (reconcile, expiry), it parses the tenant from the key and applies the
tenant's own rules; no code path may return a job to a caller of another tenant. (3) No
migration: nothing is deployed. Say so in the PR, and say what happens to an old-layout
object (ignored), and make the code refuse to read one. (4) The saasapi job status
read path (internal/saasapi/job_status.go) and the CLI job commands must pass the
tenant and check it against the caller's tenant. (5) Check the object store policy
examples in deploy/helm for the jobs bucket and update them to the new prefix. (6)
Update docs and mark I4 addressed in docs/security-review-2026-10-b.md.
Tests: two tenants with the same sprout_id and the same jid-shaped value write, list,
read, expire and reconcile without ever seeing each other's objects, including through
the saasapi route and the farmer HTTP and NATS read paths; a key with a hostile
tenant_id or sprout_id (slash, dot-dot) is refused; the old layout is not read; the
existing jobs, serve and saasapi tests are updated, not deleted.
Scope: internal/jobs, internal/serve, internal/saasapi (job_status.go and recipes.go only
where they read job keys), internal/rbac (only if it names job keys), cmd/farmer (wiring),
cmd/imas (job commands only), deploy/helm/farmer (bucket policy examples only),
docs/security-review-2026-10-b.md, docs/BUILD-STATUS.md (Open item 10 only). Tests: go
test ./... must pass. PR: state what you built, what you deferred, and any open question."
```

**FIX.3: Helm gaps on a fresh install**
```
claude --cloud "Implement FIX.3: close three gaps that would make a fresh install of
deploy/helm/farmer fail or be unsafe. FLAG FOR SECURITY REVIEW.
(1) Farmer's object store egress. networkPolicy.farmerExtraEgress defaults to empty and
the farmer NetworkPolicy has no rule for objectStore.endpoint, so recipes, staged recipes
and job logs fail by default. Add a dedicated farmer egress rule for the object store
port, the way saasapi has networkPolicy.saasapiEgress.objectStore (see
templates/networkpolicy.yaml and values.yaml near line 803), restricted by the same
destination setting, and keep farmerExtraEgress as an addition. (2) Bootstrap admin.
farmer.bootstrapAdmin.pubkey defaults to empty and nothing complains, but with J.3 the
CLI cannot add a user over the bus, so the install is unusable. Make render fail with a
clear message when it is empty, unless an explicit value (for example
farmer.bootstrapAdmin.skip: true with a documented reason such as users already exist in
the database) is set; check how _helpers.tpl validates it today (around line 547) and
keep the existing username and boxpub checks. (3) The SaaS API recipe credential. Today
only an example policy (files/objectstore-policies/saasapi-recipes.json) limits it to
tenants/*/recipes/*, and the chart only checks the Secret differs from farmer's. Add a
chart-level control that makes the limit real and not documentation: for example a
required, rendered policy name or an optional bucket-policy Job for MinIO that creates
the policy and the user, or at minimum a startup self-check in saasapi that tries a
write outside tenants/ and a read of sprouts/ and refuses to start with a clear error if
either succeeds. Say which you chose and why. If the self-check needs code, it lives in
internal/saasapi and internal/objectstore and is covered by a test with a fake store.
Also: pods waiting on the imas-saasapi-box Secret with externalSecrets disabled should
fail with a clear NOTES warning at install time (it is documented; confirm and test).
Tests: extend chart_test.go and saasapinetpol_test.go: default values render the farmer
object store egress; bootstrapAdmin empty fails render and skip passes; the policy
control behaves as designed; existing tests still pass. helm template and lint on both
charts with the default values, the values used in the UAT (docs) and a minimal override.
Scope: deploy/helm/farmer (templates, values, tests, policy files, NOTES),
deploy/helm/nats (only if a value is shared), internal/saasapi and internal/objectstore
(only for the self-check), docs/INSTALL.md, docs/BUILD-STATUS.md (Open item 10 and the
requirement 13 row only). Tests: go test ./... must pass. PR: state what you built, what you
deferred, and any open question."
```

**FIX.4: refresh BUILD-STATUS to match main (after FIX.1, FIX.2 and FIX.3 merge)**
```
claude --cloud "Implement FIX.4: bring docs/BUILD-STATUS.md up to date with main. Docs
only. Change no code and no other file. The file stops at PR 67 in its header, its
requirements RAG table, its build plan table and its PR ledger, and many sections still say
in review for PRs that merged. Work from the merged PR list (gh api repos/yogzblr/imas/pulls
with state closed, PRs 68 onward; gh GraphQL is blocked here, so use REST), each PR's
description, the code on main, docs/security-review-2026-10.md and
docs/security-review-2026-10-b.md.
Do: (1) update the header date and commit, the RAG summary (legend, counts, requirements
table, build plan table, open items table) with a judgement from the code and CI on main,
not from PR titles; keep the legend meaning; requirement 14 should reflect what is really
sealed and what is documented residual. (2) Add every PR from 68 to the latest to the PR
ledger with its brief id and one line. (3) Add a Wave 7 row (SEC.0 to SEC.6, REC.1, J.1 to
J.5, SEC.5b, SEC.7a to SEC.7c, SH.1, CL.4, OPS.1, T.1, FIX.1 to FIX.3) to the build plan table.
(4) Rewrite Open items 1, 2, 4, 10 and 11 so each states what is true on main: item 4 now
records both security reviews, which findings are addressed and which are open (B4, B5, B6,
B8 and the Info items), and what must be done before SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED
is turned on. Change every in review that is now merged. (5) Resolve the contradictions the
validation found: requirements 1 and 7 rows versus the SCALE.1 and SCALE.2 sections.
(6) Add a short Validation 2026-10-05 note: what was verified, what could not be run
(tests need the Go toolchain, so CI is the evidence), and the first release prerequisites
still owed by the owner (GPG public key committed and the SECURITY.md fingerprint,
Buildkite registries and variable, tag v0.1.0-rc.1, release run, publish by
workflow_dispatch, verify the Buildkite index layout and the +git version against the
manifest, re-enable the release.yml tag trigger). Do not invent a status you cannot check:
mark it UNCONFIRMED and say what would confirm it. Needs FIX.1, FIX.2 and FIX.3 merged so
the file describes the final state. Scope: docs/BUILD-STATUS.md only. Tests: none to run;
check every PR number, file path and open item cross reference you write. PR: state what you
changed, what you could not verify, and any open question."
```

**FIX.5: release blockers found in the 2026-10-05 re-validation**
```
claude --cloud "Implement FIX.5: fix what the re-validation of main at cefa9ca found
before the first release candidate. Two items are release blockers and are listed first.
FLAG FOR SECURITY REVIEW (items 4 and 5 touch security behaviour).
(1) BLOCKER, helm lint in the publish workflow. .github/workflows/publish-packages.yml
runs helm lint on deploy/helm/farmer and deploy/helm/nats with default values. The farmer
chart now fails render on defaults (bus.serviceName and the other required values, and since
FIX.3 an empty farmer.bootstrapAdmin), so the first publish would fail. Check by running
helm lint and helm template locally (install helm in the session) with defaults and with
-f deploy/helm/farmer/ci/default-values.yaml and the other ci values files; make the
workflow lint each chart with the values file that CI uses (add one for the nats chart if
it needs it), and keep helm package unchanged. Do not touch the tag trigger of release.yml.
(2) BLOCKER, chart tests are skipped in CI. deploy/helm/farmer/chart_test.go skips when helm
is not on PATH and when charts/ is not populated, and .github/workflows/ci.yml installs
neither, so FIX.3 and every other chart render test may never have run. Install helm with
azure/setup-helm pinned to a version, run helm dependency build for the farmer and nats
charts in the Test job (or a new Chart job), and make the tests fail, not skip, when
they are run in CI (for example require an environment variable such as IMAS_REQUIRE_HELM=1
and set it in the workflow). Then run them. If any test now fails, fix the chart or the
test as appropriate and list each such fix in the PR; do not delete or weaken a test to make
it pass. If the Helm dependency build needs network registries the CI cannot reach, say so
and choose the least bad option.
(3) FIX.1 gap: the batch item for a keyless sprout is recorded as internal_error
(internal/saasapi/sprout_actions.go around line 1020, pinned by dispatch_limits_test.go).
Record sprout_reenroll_required instead, add the code to the API docs and the OpenAPI enum
in docs/api and to the CLI messages, and update the tests that pin the old behaviour. Also
fix docs/design/imas-payload-encryption-design.md around line 219, which still says cmd.run
falls back to plaintext and mentions shellallowplaintextsprouts, a flag that no longer
exists; make it agree with line 85 of the same file.
(4) FIX.3 gap: the SaaS API recipe credential self-check (internal/saasapi/recipes_credcheck.go,
internal/objectstore/probe.go) never probes the platform recipe prefix or the jobs bucket, yet
its error text says it protects them. Add probes: a write and a delete under the platform
recipe prefix must be refused, and any access to the jobs bucket must be refused. Keep the
check fail-closed and covered by a fake-store test for each new probe, and say in the PR what
the AWS read-probe gap is and whether it can be closed.
(5) Documentation drift: in docs/security-review-2026-10-b.md update the status of B2
(addressed by SEC.7b, merged in PR 108) and I4 (addressed by FIX.2, merged in PR 111) and any
other mark that main contradicts; in docs/BUILD-STATUS.md remove the leftover done-this-pass
wording around line 419, correct the line near 413 that calls the UAT gate unblocked (it still
needs a release and a compute-provider decision), make the older sections that describe the
plaintext fallback, unsealed shell and adopted tenants carry a visible Superseded banner at the
top of each section, note that requirement 14 at Amber and requirement 4 at Green are judgement
calls with the reason, and mention FIX.5 in the PR ledger. Do not edit any other status claim
without checking it against main.
Tests: helm lint and helm template for both charts with defaults-plus-ci-values and with the
UAT values from the docs; go test ./... must pass, including the chart tests now running;
new tests for items 3 and 4.
Scope: .github/workflows/publish-packages.yml and ci.yml (the helm steps only),
deploy/helm/farmer and deploy/helm/nats (values, templates and tests, only as needed to make
the tests pass), internal/saasapi, internal/objectstore, docs/api, docs/design/imas-payload-encryption-design.md,
docs/security-review-2026-10-b.md, docs/BUILD-STATUS.md. Do not touch release.yml. PR: state
what you built, what you deferred, which tests newly ran and which of them failed before your
fixes, and any open question; call the security items ready for review, not done."
```

## 4h. Azure UAT gate (UAT.1 to UAT.7)

Added 2026-10-06. **Supersedes the Terraform UAT brief in section 4a (item 5):** the
owner chose Azure over the libvirt/KVM default, OpenTofu over Terraform (Terraform is
BUSL-1.1; OpenTofu and the azurerm provider are MPL-2.0, covered by the recorded MPL
exception), and a production-shaped layout instead of one VM per OS. SUSE (zypper) is out
of scope for this gate; add it later as one more tenant VM.

Owner decisions, 2026-10-06: Keycloak is validated by saasapi, as built (the Envoy
gateway keeps validating farmer-minted gateway JWTs; Envoy-side Keycloak validation is a
possible later design change, not part of this gate). MinIO is accepted as a UAT-only
object store (AGPL-3.0; never shipped, never a dependency of a released artifact; the
repo already avoids its mc image). Existing paid Azure subscription, so no free tier.

### The shape

Eight VMs in one resource group per run, three subnets, torn down after the run.

| Subnet | VM | Runs |
|---|---|---|
| dmz 10.60.1.0/24 | uat-dmz (single-node k0s) | deploy/helm/nats: farmerbus StatefulSet and the Envoy gateway |
| core 10.60.2.0/24 | uat-core (single-node k0s) | deploy/helm/farmer: farmer, saasapi, PXC (one node), Valkey, OpenBao; plus MinIO and Keycloak |
| tenants 10.60.3.0/24 | t1-ubuntu, t1-alma, t1-win, t2-ubuntu, t2-alma, t2-win | one sprout each, tenant 1 and tenant 2 |

Two clusters, not one: the DMZ is a separate trust zone, as in the design. Production is
Kubernetes, so the hubs run the real Helm charts from the published release. Ubuntu 24.04,
AlmaLinux 9 (stands in for RHEL, which needs a subscription to fetch; say so in the
report) and Windows Server 2022 Core. The two tenants' sprouts of one OS get the SAME
sproutid, so the run also proves sprout_id is unique per tenant only (CLAUDE.md).

### Scenario catalogue

What the gate tests, with the ids the tests and reports use. Tiers decide what a run does: smoke
(about 10 minutes), core, resilience, ingredients, lifecycle, or all. Test functions are named
with their tier as a prefix (TestSmoke, TestCore, TestResilience, TestIngredients,
TestLifecycle) so a tier can be chosen with go test -run.

| Id | Scenario | Tier |
|---|---|---|
| T1 | Create a tenant (POST /v1/tenants, 202), poll status until active | smoke, core |
| T2 | Validation: a missing name is refused | core |
| T3 | Status shows last_error or warning when set | core |
| T4 | Delete: offboarding then offboarded; 409 provisioning_in_progress while provisioning | core |
| T5 | After offboarding the tenant's keys, sprouts and bus account are cut off | core |
| T6 | Two tenants stay separate for tenants, keys, sprouts, recipes and job logs | core |
| K1 | Mint an enrolment key with expiry and max_uses | smoke, core |
| K2 | A key at max_uses is refused for the next enrolment | core |
| K3 | A revoked key is refused; sprouts already enrolled stay | core |
| K4 | Minting is rate limited (1 per second, burst 5) | core |
| S1 | Install the published package, enrol through Envoy, sprout connected under its own tenant | smoke, core |
| S2 | The same sproutid in both tenants resolves to different machines | core |
| S3 | Asset link: new 201, repeat 200, collision 409 asset_link_conflict | core |
| S4 | Lookup by asset_ids; another tenant's ids come back unresolved without saying why | core |
| S5 | A sprout with no box key is refused (sprout_reenroll_required); nothing is sent in plaintext | core |
| S6 | Uninstall and reinstall on the same host re-enrols cleanly | core |
| C1 | cmd.run succeeds on every sprout, all three OS | smoke, core |
| C2 | A non zero exit gives command_failed with the exit code | core |
| C3 | timeout_seconds is honoured | core |
| C4 | Shell syntax is rejected; args, cwd and run_as work | core |
| C5 | An unknown asset id comes back unresolved | core |
| C6 | A stopped sprout gives sprout_unreachable | core |
| C7 | A batch over several sprouts reports per item results | core |
| C8 | The per tenant rate limit applies | core |
| R1 | Recipe upload, list, fetch, delete through the API | core |
| R2 | Read and write roles are enforced (a read only user cannot write) | core |
| R3 | Recipes are tenant scoped | core |
| R4 | Cook a recipe by name on a sprout | core |
| R5 | Cook in test mode reports pending changes, then none after a real run | core |
| R6 | Recipes with properties, templates and OS conditions over a mixed OS batch | core |
| I.name.method | Ingredient conformance: one case per registered ingredient method (below) | ingredients |
| L1 | Each sprout survives a reboot, reconnects and runs a job | resilience |
| L2 | Restarting farmer: sprouts stay connected or reconnect, jobs run | resilience |
| L3 | Restarting farmerbus and Envoy: sprouts reconnect | resilience |
| L4 | Package upgrade from the previous release to this one keeps /etc/imas/sprout and the sproutid | lifecycle |
| L5 | One self update cycle with the dispatch flags on (opt in, UAT only) | lifecycle |
| X1 | No token, expired token, wrong audience, read only token on a write route: refused as documented | core |
| X2 | A sprout presenting no gateway JWT is refused at Envoy | core |
| X3 | A sprout cannot open a connection to core | core |
| X4 | Cross tenant access by a tenant admin token is denied everywhere | core |
| X5 | Sealing: plaintext cmd.run and cook are refused by a sprout | core |

Ingredient conformance (UAT.7). Every ingredient package under internal/ingredients has one case
file per method, with the OS it applies to. A case is one cycle: cook in test mode and see a pending
change; cook for real; cook in test mode again and see none (idempotent); verify out of band with
a cmd.run on the sprout (id, stat, systemctl or the Windows equivalent); revert. A coverage test
fails if a registered method has neither a case nor a written reason to skip, so a new ingredient
cannot slip in untested. Risky ingredients (firewall, network, mount, selinux, lgpo and the Windows
update, DSC and server manager ones) use harmless changes and never touch the sprout's own
connection. Windows Server Core may lack some features (appx, shortcuts and others): a case that
cannot run there is skipped with the reason, and the report lists them so the owner can decide on a
Desktop Experience image for those.

Not covered by this gate: key expiry (the minimum is one hour; unit tests cover it), the web UI,
high availability, real RHEL, scale and load.

### Shared contract (every UAT brief reads this; do not change it without the owner)

- Layout of the work, one directory per brief, no overlap: uat/tofu (UAT.1), uat/k0s
  (UAT.2), uat/hub/dmz (UAT.3a), uat/hub/core (UAT.3b), uat/enroll (UAT.4), uat/tests
  (UAT.5, except uat/tests/ingredients), uat/cases and uat/tests/ingredients (UAT.7), and for UAT.6 the workflow .github/workflows/uat.yml, .github/workflows/
  uat-janitor.yml and uat/scripts. uat/README.md is written by UAT.6 from the others.
- Inputs: run_id (lowercase letters and digits, 6 to 10), release_tag (a vX.Y.Z or
  vX.Y.Z-rc.N tag; the chart, images and packages all come from this release, never
  latest), region (default centralindia, a variable; the owner confirms size and quota
  there), runner_cidr (one /32, the only source allowed in from the internet), keep_hours
  (default 0; above 0 skips the final destroy and the janitor deletes it after that time).
- Names: resource group imas-uat-<run_id>; every resource tagged purpose=imas-uat,
  run_id, expires_at (RFC 3339, UTC). Public DNS labels uat<run_id>-dmz and uat<run_id>-core
  under <region>.cloudapp.azure.com. Sizes are variables: dmz Standard_D2s_v5, core
  Standard_D8s_v5, Linux sprouts Standard_B1ms, Windows sprouts Standard_B2s.
- Image URNs are variables, verified by the owner with az vm image list (agents cannot
  reach Azure): Canonical ubuntu-24_04-lts server; almalinux almalinux-x86_64 9-gen2
  (marketplace terms accepted once per subscription); MicrosoftWindowsServer WindowsServer
  2022-datacenter-core-smalldisk-g2.
- tofu output uat (JSON) is the interface to everything else: run_id, region,
  resource_group, dmz and core (each: name, private_ip, public_ip, fqdn, admin_user),
  sprouts (a map keyed by VM name: tenant 1 or 2, os ubuntu|alma|windows, private_ip,
  public_ip, admin_user), subnets. Credentials are never outputs: SSH keys are generated
  per run and WinRM passwords are random, both held as sensitive values only.
- Network rules (UAT.1 derives the exact ports from the Network section of
  deploy/helm/nats/README.md and the NetworkPolicy section of deploy/helm/farmer/README.md,
  and documents them): sprouts reach only Envoy in the DMZ; the DMZ reaches only the farmer
  API port on core; core reaches only the bus websocket port on the DMZ; the internet
  (runner_cidr only) reaches SSH or WinRM on every VM, and 443 plus Envoy's port on the two
  hubs. Nothing else is open. A sprout must not be able to open a connection to core.
- Hostnames and issuer: the Keycloak issuer URL, saasapi's SAASAPI_KEYCLOAK_JWKS_URL value
  and the token iss claim must be the same string, built on the core FQDN, and resolve to
  the core private IP from inside the cluster (CoreDNS rewrite or hostAliases) so a pod
  never dials its own node public IP.
- TLS: one throwaway UAT CA per run, created by the run (cert-manager on each hub),
  sprouts pin it through sproutrootca with sproutrootcatofu false, as the Envoy design
  requires. No real certificates, no secrets in git.
- Auth to Azure is GitHub OIDC only, from the GitHub environment named uat. No client
  secrets anywhere. Subscription, tenant and client ids are GitHub environment variables,
  not committed.
- The agents' sandboxes cannot reach Azure, Docker Hub, GHCR, quay.io or Buildkite.
  Every UAT brief therefore ends with static checks only (tofu fmt and validate if tofu can
  be installed, helm template and lint, shellcheck, go vet with the uat tag, yamllint) and
  its PR says plainly which checks ran and which could not. Nothing is proven until the
  owner runs UAT.6 for real; expect fix rounds after the first runs.
- New third-party pieces and their licences, to name in each PR that adds one: azurerm
  provider and OpenTofu (MPL-2.0), k0s and k0sctl, cert-manager, local-path-provisioner
  and Keycloak (Apache-2.0), PXC (GPLv2, recorded exception), OpenBao (MPL-2.0, recorded),
  MinIO (AGPL-3.0, accepted for UAT only, see above). Flag anything else.

### Owner prerequisites (do these once, before the first run)

Not agent work. Run in Azure Cloud Shell as the subscription Owner; the values below are
placeholders, the subscription id is the one in the Azure portal.

```sh
SUB=<subscription id>
az account set --subscription "$SUB"
for ns in Microsoft.Compute Microsoft.Network Microsoft.Storage Microsoft.Authorization Microsoft.Consumption; do
  az provider register --namespace "$ns"
done

# GitHub OIDC identity for the uat environment (no secret is created)
APP=$(az ad app create --display-name imas-uat-github --query appId -o tsv)
az ad sp create --id "$APP"
az role assignment create --assignee "$APP" --role Contributor --scope "/subscriptions/$SUB"
az ad app federated-credential create --id "$APP" --parameters '{
  "name": "imas-uat-env",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:yogzblr/imas:environment:uat",
  "audiences": ["api://AzureADTokenExchange"]}'
echo "AZURE_CLIENT_ID=$APP  AZURE_TENANT_ID=$(az account show --query tenantId -o tsv)  AZURE_SUBSCRIPTION_ID=$SUB"

# AlmaLinux marketplace terms, once (confirm the URN first with az vm image list)
az vm image terms accept --publisher almalinux --offer almalinux-x86_64 --plan 9-gen2
```

Then: in the repo create the GitHub environment uat with a required reviewer (you), a
deployment rule for the branch main, and the three variables above. Check in your region
that Standard_D2s_v5, Standard_D8s_v5, Standard_B1ms and Standard_B2s are available and
that the quotas cover 18 vCPUs in total (D2s 2 + D8s 8 in the Dsv5 family, 4 B1ms + 2 B2s x 2
in the B family; quotas are per family as well as per region), and request more if not. Run uat/tofu/bootstrap once by hand when UAT.1 has merged: it
creates the small persistent resource group (state storage account, budget alert), the
only thing that stays up between runs. The Contributor role is subscription wide: keep this
subscription for UAT only, and keep the uat environment's required reviewer on.

Cost, guessed and unchecked: the two hubs dominate, roughly a dollar an hour together;
the six sprouts add a few cents an hour. A run of 60 to 90 minutes should be a few dollars.
The janitor and the budget alert exist so a stuck run cannot run for days.

**UAT.1: Azure infrastructure module (OpenTofu)**
```
claude --cloud "Implement UAT.1: the OpenTofu module that builds and destroys the Azure
side of the UAT gate. Read section 4h of docs/claude-code-parallel-build-plan.md first, in
full, including the Shared contract; follow it exactly, it is the interface the other UAT
briefs are written against. FLAG FOR SECURITY REVIEW (cloud credentials, network rules and
destroy semantics).
Build under uat/tofu: (1) A main module taking the inputs in the contract (run_id,
release_tag, region, runner_cidr, keep_hours, sizes, image URNs) that creates: the resource
group imas-uat-run_id with the tags in the contract; one VNet 10.60.0.0/16 with the three
subnets; one network security group per subnet implementing the Network rules in the
contract (derive the exact ports from the Network section of deploy/helm/nats/README.md and
the NetworkPolicy section of deploy/helm/farmer/README.md, write them in uat/tofu/README.md
as a table with a reason for each rule, and say which you could not derive); the two hub VMs
(Ubuntu 24.04, Standard SSD OS disk of 64 GB and 128 GB, Standard public IP with the DNS
label from the contract); the six sprout VMs (t1 and t2, ubuntu, alma, windows) each with
its own Standard public IP, small OS disks, no data disks. Windows uses the Server 2022 Core
smalldisk image and enables WinRM over HTTPS through a custom script extension or user data;
the Linux VMs take a per-run generated SSH key. Every NIC, public IP and OS disk is created
with delete_option or equivalent set to delete so destroy leaves nothing; use ephemeral OS
disks only where the size supports it. Outputs: the uat JSON object from the contract, with
secrets marked sensitive and never printed. (2) A bootstrap stack under uat/tofu/bootstrap for
the persistent pieces: one small resource group, a storage account and container for tofu
state (the main module uses it as its azurerm backend, key per run_id, so a keep_hours run can
be destroyed later by another job), and a subscription budget alert at a monthly amount given
by a variable with a sensible default and an email variable. It must not create the GitHub
OIDC application; that is an owner prerequisite listed in section 4h. (3) A teardown helper
script uat/tofu/destroy.sh that runs tofu destroy and then checks the resource group is gone,
falling back to az group delete for imas-uat-run_id, and exits non zero if anything tagged
with the run_id remains. (4) uat/tofu/README.md: inputs, outputs, the network table, how the
owner runs the bootstrap once, how to destroy by hand, and the resource list with a rough
size per VM. Do not hard code the subscription, tenant or client ids. Do not create any
credential that is committed. Do not add any provider other than azurerm and random/tls.
Tests: tofu fmt -check and tofu validate for both stacks if tofu can be installed here (say
if not); a shell test with bash that runs destroy.sh against stubbed az and tofu commands to
check its three branches; shellcheck on the scripts. You cannot reach Azure: state that the
module has never been applied. Scope: uat/tofu only, plus a row in docs/BUILD-STATUS.md for
this brief. PR: state what you built, what you deferred, any open question, and call it ready
for review, not done."
```

**UAT.2: k0s on both hubs**
```
claude --cloud "Implement UAT.2: install a single-node k0s cluster on each hub VM and the
cluster add-ons the charts need. Read section 4h of docs/claude-code-parallel-build-plan.md
first, in full, including the Shared contract. The VMs and the tofu output uat come from
UAT.1, which is being written in parallel: code against the contract, not against UAT.1's
files.
Build under uat/k0s: (1) A k0sctl configuration template and a script
uat/k0s/bootstrap.sh that, given the uat JSON from tofu output, installs k0s with k0sctl on
uat-dmz and on uat-core as two separate single-node clusters (controller and worker on the
one node), pins the k0s version in one place, fetches a kubeconfig for each cluster to a
path the caller gives, and waits until each node is Ready. (2) The add-ons, installed by the
same script with versions pinned in one file: local-path-provisioner as the default storage
class, cert-manager, and a way to reach services from outside without a cloud load balancer
(NodePort or host ports; state which and why). For the DMZ the exposed port is Envoy's, and
the bus websocket port toward core; for core it is 443 for saasapi and Keycloak and the farmer
API port toward the DMZ. Use the ports the nats and farmer chart READMEs give. (3) The UAT CA:
a self signed root created per run, set up as a cert-manager ClusterIssuer on each hub, with
the CA certificate written to a file the caller can fetch (sprouts pin it). (4) The DNS part of
the contract: a CoreDNS rewrite or hostAliases so the core FQDN resolves to the core private
IP inside the core cluster, and the DMZ cluster resolves the core FQDN the same way. (5) A
check script that prints the state of both clusters and fails if a node is not Ready, the
default storage class is missing or cert-manager is not available.
Do not install any application chart here; the hub briefs do that. Tests: shellcheck, yamllint
on the templates, a bash test of the script's argument handling and of how it builds the
k0sctl file from a sample uat JSON file you add under uat/k0s/testdata. You cannot reach
Azure: state that nothing was run against a real node. Scope: uat/k0s only, plus a row in
docs/BUILD-STATUS.md. PR: state what you built, what you deferred, and any open question; call
it ready for review, not done."
```

**UAT.3a: the DMZ hub (nats chart and Envoy)**
```
claude --cloud "Implement UAT.3a: install the published DMZ chart on the uat-dmz cluster and
prove it comes up. Read section 4h of docs/claude-code-parallel-build-plan.md first, in full,
including the Shared contract, then deploy/helm/nats/README.md and deploy/envoy/README.md.
The clusters come from UAT.2 and the core hub from UAT.3b, both being written in parallel: code
against the contract.
Build under uat/hub/dmz: (1) A values file for deploy/helm/nats for this layout: the Envoy
downstream certificate issued by the UAT ClusterIssuer for the DMZ FQDN, the upstream address
of farmer on the core private IP and the farmer API port, the bus settings the farmer chart
expects, replica counts of one, resource requests small enough for a D2s_v5. (2) A script
uat/hub/dmz/install.sh that installs the chart from the published release named by release_tag
(the chart version and the image tag both equal the tag without the leading v; never latest;
pull the chart from the Buildkite imashelm registry the release publishes to, and say which URL
you used and how a pre-release chart version is selected), waits for farmerbus and Envoy to be
Ready, and exposes Envoy as the contract says. (3) A check script that, from the runner,
confirms the Envoy listener answers TLS with the UAT CA, that an unauthenticated request to the
files route and to the websocket route is refused (the jwt_authn gate), and that the enroll
route is reachable and rate limited, using only curl and openssl. Write the exact checks
against the behaviour documented in deploy/envoy/envoy.yaml's header. (4) uat/hub/dmz/README.md
with what was assumed about the core side.
You cannot reach the cluster, GHCR or Buildkite: run helm template and helm lint on the chart
with your values file (add the chart repositories first, as the chart README says) and say
what could not be run. Tests: shellcheck, yamllint, helm template output checked for the
Envoy certificate, ports and upstream address. Scope: uat/hub/dmz only, plus a row in
docs/BUILD-STATUS.md. PR: state what you built, what you deferred, and any open question;
call it ready for review, not done."
```

**UAT.3b: the core hub (farmer chart, OpenBao, MinIO, Keycloak)**
```
claude --cloud "Implement UAT.3b: install the core side on the uat-core cluster, and bootstrap
the pieces the chart expects to exist. Read section 4h of docs/claude-code-parallel-build-plan.md
first, in full, including the Shared contract, then deploy/helm/farmer/README.md (all of
Install, Bootstrap admin, Seeds, the OpenBao and gateway JWT parts, the objectStore and saasapi
values) and docs/api/saasapi.md for how saasapi reads a Keycloak token (issuer, audience, roles,
and how the tenant is derived). FLAG FOR SECURITY REVIEW (secret generation, OpenBao bootstrap,
UAT identity provider). The clusters come from UAT.2, being written in parallel: code against
the contract.
Build under uat/hub/core: (1) MinIO as a UAT only object store (one pod, a pinned image, a
generated root credential held in a Kubernetes Secret, the recipes bucket and the jobs bucket
named by objectStore.bucket and objectStore.jobBucket, credentials for the chart in the secret
the chart names) and a short note in uat/hub/core/README.md that it is AGPL-3.0, test only and
never shipped. (2) Keycloak (Apache-2.0, pinned image, dev style single replica with its own
small database or the embedded one; state which) with a realm import file for a realm named
imas-uat: a client for saasapi's audience, the recipe read and write roles with the exact
names saasapi expects (read them from the chart values and docs), and two tenants each with
an admin user holding both roles and a read only user, whose tokens saasapi will map to tenant
1 and tenant 2 the way docs/api/saasapi.md describes (if tenant comes from a claim, add the
claim mapper). The issuer must be the Keycloak URL on the core FQDN from the contract.
Passwords are generated per run and never committed. (3) An OpenBao bootstrap script for the
chart's OpenBao subchart: initialise, unseal, enable the Transit engine and create the Ed25519
key the gateway JWT needs under the name the chart expects, and create the seed Secret the
chart requires (imas-farmer-nats-seeds or the configured name) using the repo's own tooling to
generate seeds, not hand written keys; read the README for how. For UAT only, the unseal keys
go into a Kubernetes Secret and a file the run keeps as a sensitive artifact: say so loudly in
the README and the PR. (4) A values file for deploy/helm/farmer for this layout: PXC and Valkey
and OpenBao subcharts on with one replica each, the DMZ bus address from the contract, saasapi.jwt
pointing at Keycloak, the object store pointing at MinIO, and a bootstrap admin whose keys the
script generates with the imas CLI (imas auth privkey, pubkey and keygen) from the same release
and prints the admin material to a sensitive output for the tests. (5) install.sh that does it
all in order from the published release named by release_tag (chart and images equal to the tag
without the leading v, never latest), waits for each workload, and a check script that confirms
farmer, saasapi, PXC, Valkey and OpenBao are Ready, that the migration job finished, that saasapi
answers with a Keycloak token from each tenant admin and refuses a request with no token.
You cannot reach the cluster, GHCR or quay.io: run helm template and helm lint with your values
(add the chart repositories first) and say what could not be run. Tests: shellcheck, yamllint,
a JSON schema or jq check of the realm file for the roles and the issuer, helm template output
checked for the values that matter. Scope: uat/hub/core only, plus a row in docs/BUILD-STATUS.md.
PR: state what you built, what you deferred, and any open question; call it ready for review,
not done."
```

**UAT.4: tenant bootstrap and sprout enrolment**
```
claude --cloud "Implement UAT.4: create the two UAT tenants through saasapi and enrol the six
sprouts with the published packages. Read section 4h of docs/claude-code-parallel-build-plan.md
first, in full, including the Shared contract, then ansible/README.md, ansible/site.yml and the
imas_sprout and imas_verify roles, docs/api/saasapi.md (tenant creation, enrolment keys, update
policy) and docs/INSTALL.md. The infrastructure and hubs are written in parallel by other
briefs: code against the contract.
Build under uat/enroll: (1) A script that, given the uat JSON and a Keycloak admin token for
each tenant, creates tenant 1 and tenant 2 through the saasapi API and one enrolment key per
sprout (one time keys, the tenant's own), and prints nothing secret. (2) An Ansible inventory
generator that turns the uat JSON and the keys into an inventory for ansible/site.yml: Linux
sprouts over SSH with the per run key, Windows sprouts over WinRM HTTPS, group variables
pinning the package source to the release named by release_tag (the version of imas-sprout, the
Buildkite registries the role already uses, never latest), the Envoy address as farmerinterface,
the UAT CA file for sproutrootca with sproutrootcatofu false, and the same sproutid for the t1
and t2 sprout of each OS (ubuntu-01, alma-01, win-01) if the role or the config can set it; if
it cannot, report exactly where sproutid comes from and what the tests should assume. (3) A
wrapper that runs the existing playbook and imas_verify, then waits until every sprout is
connected from farmer's side. Do not change the roles; if they need a change for this, list it
as a finding and the owner decides. Check how the Windows install works for a pre-release tag
(the MSI ProductVersion carries no rc suffix, and PR 88 refuses pre-release package updates on
Windows) and say plainly in the PR whether UAT can enrol Windows with a pre-release tag, and
what to do if not. State how AlmaLinux differs from RHEL for the role.
Tests: ansible-lint and yamllint if installable, shellcheck, a bash or Python test of the
inventory generator against a sample uat JSON file you add under uat/enroll/testdata, including
the case that both tenants get the same sproutid. You cannot reach Azure or the registries.
Scope: uat/enroll only (read, do not edit, ansible/), plus a row in docs/BUILD-STATUS.md. PR:
state what you built, what you deferred, and any open question; call it ready for review, not
done."
```

**UAT.5: the acceptance test suite**
```
claude --cloud "Implement UAT.5: the Go acceptance tests that run against the deployed stack.
Read section 4h of docs/claude-code-parallel-build-plan.md first, in full, including the Shared
contract, then docs/api/saasapi.md, docs/design/imas-payload-encryption-design.md,
docs/design/imas-envoy-enrollment-design.md and the existing testing/ and internal/saasapi client
code you can reuse. The deployment is built by other briefs in parallel; you test against the
contract.
Build under uat/tests, a Go package with the build tag uat so go test ./... never runs it. It reads
the uat JSON file and the admin and Keycloak material from a directory named by an environment
variable. Keep it in the existing Go module and add no new dependency without flagging its licence.
Implement the scenarios of the Scenario catalogue in section 4h with the ids T1 to T6, K1 to K4, S1 to
S6, C1 to C8, R1 to R6, X1 to X5 (tier core, with the smoke ones named TestSmoke) and L1 to L3 (tier
resilience); name every test function with the tier prefix and the scenario id so a tier or one
scenario can be chosen with go test -run, and report each failure with the id, the OS, the tenant and
the step. Do not implement the I scenarios or L4 and L5: UAT.7 does, in uat/tests/ingredients and
uat/cases, and will reuse your helper package, so put the API client, token, sprout lookup, batch and
cook helpers, and the sprout command helper in a package of its own (uat/tests/harness) with a small
documented interface, and write it for reuse. Where a scenario cannot be asserted from the outside, say
so in the test file instead of faking it, and where the API lacks what a scenario needs (for example
revoking a sprout), record the gap in the PR. The reboot and service restart helpers use a command the
harness is given by the workflow, not Azure calls from the tests. Add uat/tests/run.sh that builds the
test binary, takes a tier name (smoke, core, resilience, ingredients, lifecycle or all) and an optional
list of ids, runs all packages under uat/tests with the uat tag, prints a JUnit style summary with one
line per scenario id, OS and tenant, and exits non zero on failure.
You cannot run these against a stack: run go vet and go build with the uat tag, unit tests for the
helpers with fake servers, and say that the suite has never run against a real deployment. Scope:
uat/tests only (not uat/tests/ingredients), plus a row in docs/BUILD-STATUS.md. Tests: go vet and go
test ./... must pass, and go vet -tags uat ./uat/tests/... . PR: state what you built, what you
deferred, and any open question; call it ready for review, not done."
```

**UAT.6: the workflow, janitor and README (last)**
```
claude --cloud "Implement UAT.6: assemble the UAT gate into a workflow and write its README. Read
section 4h of docs/claude-code-parallel-build-plan.md first, in full, then read what UAT.1 to UAT.5
actually merged under uat/ (they are on main), and .github/workflows/publish-packages.yml and
release.yml for the house style (secrets check up front, concurrency per tag, the environment
gate). FLAG FOR SECURITY REVIEW (a workflow that holds cloud credentials).
Build: (1) .github/workflows/uat.yml, workflow_dispatch only, inputs release_tag (required),
region, keep_hours (default 0), tier (smoke, core, resilience, ingredients, lifecycle or all, default
all), upgrade_from_tag (optional, for scenario L4) and an optional list of scenario ids, passed to
uat/tests/run.sh; it runs in the GitHub environment
uat (required reviewer), permission id-token write, logs in with azure/login by OIDC using the three
environment variables, finds the runner's public address and passes it as runner_cidr, generates
run_id, and runs in order: tofu apply (uat/tofu), k0s bootstrap, DMZ install, core install, enrolment,
the tests, and a final destroy step with if always() unless keep_hours is above zero; it uploads the
test report and the sensitive-free outputs as artifacts and never the unseal keys or kubeconfigs. It
checks up front that the three Azure variables exist and that release_tag is a tag that exists and has
a published release, and fails naming what is missing. Concurrency group per release_tag. (2) After
destroy it verifies teardown: the resource group is gone and nothing tagged with the run_id remains,
and the job fails if not. (3) .github/workflows/uat-janitor.yml, on a schedule every hour and by hand:
deletes every resource group tagged purpose=imas-uat whose expires_at has passed, and lists what it
deleted; it must never touch a group without that tag. (4) uat/README.md for the owner: what the gate
proves and does not prove (the Helm charts run on k0s, enrolment through Envoy, tenant isolation, auth;
not HA, not PXC clustering, not RHEL itself, not SUSE, not the internet path), the prerequisites from
section 4h, how to run it, how to keep an environment for debugging and how it is cleaned up, how to
read a failure by OS and tenant, and a cost note with the caveat that the numbers are guesses. Do not
change publish-packages.yml or release.yml. Do not add a trigger on release published or on schedule
for the gate itself; the owner turns that on after it is green. Tests: actionlint if installable,
yamllint, and a shell test of the logic you put in scripts (run id generation, runner address
handling, the janitor's tag and expiry filter against a sample listing). You cannot run Azure: say the
workflow has never run, and say whether the teardown on failure was exercised or only written. Scope:
the two workflow files, uat/scripts, uat/README.md, and the Wave rows in docs/BUILD-STATUS.md (the
Terraform UAT gate row becomes the Azure UAT gate row). PR: state what you built, what you deferred, and
any open question; call it ready for review, not done."
```

**UAT.7: ingredient conformance suite and lifecycle tests (after UAT.5)**
```
claude --cloud "Implement UAT.7: the ingredient conformance suite and the two lifecycle scenarios of the
UAT gate. Read section 4h of docs/claude-code-parallel-build-plan.md first, in full, including the
Scenario catalogue and the Shared contract, then what UAT.5 merged under uat/tests (the harness package
is yours to reuse; extend it only by adding, and list any change as a finding), the ingredient registry
in internal/ingredients and every package under it, internal/cook for how a recipe, test mode and the
results work, docs-site and testing/recipes for recipe syntax, and docs/design/imas-linux-parity-addendum.md
and imas-windows-parity-addendum.md if present.
Build: (1) Enumerate, from the code and not from memory, every registered ingredient method on every
platform (all packages under internal/ingredients, Linux and Windows) and write the list to
uat/cases/INVENTORY.md with the OS each applies to and its properties. (2) uat/cases: one case file per
ingredient method, in a simple data format of your choice documented in uat/cases/README.md, with: id
(I.name.method), the OS list, the recipe text, the out of band checks (a command to run on the sprout with
the output or exit code expected), the revert recipe or command, and any need (reboot, network access,
OpenBao, a Windows feature) with a written reason when a case is skipped. Cases follow the one cycle in the
catalogue: test mode shows a pending change, a real cook, test mode shows none, a check, a revert. Use
harmless changes for the risky ingredients (firewall, network, mount, selinux, lgpo, the Windows update,
DSC, IIS and server manager ones): never alter the sprout's own connection, the default firewall policy, or
anything that needs a reboot unless the case is marked and ordered last. Cover the sdb ingredient against the
OpenBao on the core hub if the harness can reach it, otherwise mark it skipped with the reason. (3)
uat/tests/ingredients: a runner under the uat build tag that turns every case into one subtest per sprout of a
matching OS in tenant 1 (named TestIngredients with the id, OS and sprout), runs them in parallel across
sprouts but in order on one sprout, and in tenant 2 repeats a small marked subset to show tenant scoping holds
for ingredients too. Also a coverage test that fails when a registered method has neither a case nor a
documented skip, and lists the skips with their reasons in the report. (4) Lifecycle scenarios L4 and L5
under TestLifecycle: L4 installs the package of an earlier release (an input upgrade_from_tag; skip with a
clear message if it is empty), enrols, then upgrades to the release under test with the package manager and
asserts the config file and the sproutid are kept, the service is running and a job runs; L5 runs one self
update cycle and only when an environment variable says the dispatch flags are on. Report, never fix, what an
ingredient does wrongly: a failing case is a finding for the owner, so each failure message names the case,
the sprout and what differed.
You cannot run these against a real stack: run go vet and go build with the uat tag, unit tests for the case
loader and the coverage test against a fake registry and fake sprout, and say that no case has been run on a
real sprout and that Windows Server Core may not support some of them. Scope: uat/cases and
uat/tests/ingredients only, plus a row in docs/BUILD-STATUS.md. Tests: go vet and go test ./... must pass, and
go vet -tags uat ./uat/... . PR: state what you built, what you deferred, how many methods and how many cases
and skips, and any open question; call it ready for review, not done."
```

---

## 5. Orchestrator prompt: Wave 7 to the UAT gate (Claude Code app, hosted agents)

Paste into one session in the Claude Code app, with the yogzblr/imas repo
attached. The orchestrator starts each brief as a hosted (remote) agent from
inside that session instead of running claude --cloud by hand. It dispatches and
tracks; it never merges and never edits code. The Wave 0 version of this prompt is
retired: Waves 0 to 6 are merged.

```
You are the dispatcher for the remaining imas work before the UAT gate: Wave 7
(section 4e of docs/claude-code-parallel-build-plan.md). You start hosted agents,
track them and report. You do not write code, review code, merge, or approve
anything yourself. Read CLAUDE.md, docs/BUILD-STATUS.md and section 4e of the plan
first.

How to start a brief. Each brief in section 4e is a code block of the form
claude --cloud "TEXT". Take TEXT, the part between the outer quotes, exactly as
written, and start ONE hosted agent per brief with the Agent tool, passing TEXT as
the prompt and isolation set to remote so it runs in its own cloud environment
with its own copy of yogzblr/imas. Do not paraphrase, shorten, reorder or add to
TEXT, and do not include the claude --cloud wrapper. Give each agent a short
description equal to the brief id (for example SEC.4). Start agents that are
eligible together in a single message so they run concurrently. Read the plan from
origin/main each time you dispatch; never dispatch from memory. If an agent cannot
reach the repo, add it with the add_repo tool for yogzblr/imas with push access and
retry once; if that fails, stop and tell me.

Briefs: SEC.0, SEC.3a, SEC.3b, SEC.4, SEC.5, SEC.5b, REC.1, J.1, J.2, J.3, J.4,
J.5, SEC.6.

Gates. A gate is satisfied only when its PR is MERGED into main, not merely open
or green.
- Preconditions, checked once at the start: PR 81 (security review) and PR 82
  (Wave 7 briefs) are merged. If not, stop and tell me.
- 7A, no further gate: SEC.0, SEC.3a, SEC.3b, SEC.4, SEC.5. Start all five
  together. SEC.3a and SEC.3b touch the same package: tell me if they conflict;
  do not resolve it yourself.
- REC.1: gate SEC.4.
- SEC.5b: gate SEC.5.
- J.1: gates SEC.3a and SEC.3b (SEC.0 should already be merged).
- J.2 and J.3: gate J.1. Start together.
- J.4 and J.5: gate J.3. Start together.
- SEC.6: gates every brief above.
After SEC.6 merges, stop and hand back to me: the first release and the UAT are
mine to schedule.

Tracking. Use the task list as the ledger, one task per brief, with the agent id,
the PR number once it exists, and its state (not started, running, PR open, CI red,
merged, blocked). Use ListAgents to see which agents are running and SendMessage to
continue an agent that needs a nudge or an answer I gave. When an agent finishes,
find its PR with the REST API (gh api repos/yogzblr/imas/pulls and
.../commits/SHA/check-runs); gh GraphQL is blocked in this environment, so do not
use gh pr. Its PR title should start with the brief id, as CLAUDE.md requires. Do not
poll in a loop: call ReadNotifications when the app says notifications are pending,
and when I message you, and otherwise schedule at most one check-in with send_later
about 30 minutes out while agents are running. Subscribe nothing else.

Rules.
- A brief whose text has FLAG FOR SECURITY REVIEW is never described by you as done
  or safe to merge, only as ready for review, even when CI is green.
- When an agent or PR lists open questions or decisions for me, copy them to me
  verbatim with the PR number. Do not answer them and do not tell an agent an answer
  I have not given.
- If an agent fails, stalls or its PR conflicts, say so and propose a retry;
  start a new agent only after I say yes, with the same verbatim TEXT.
- If a PR touches files outside its brief's Scope line, flag it to me.
- Start nothing that is not in section 4e. Do not start Terraform or the UAT.
- Status report format, whenever I ask: the task list as a table, then what is
  blocked and on whom, then the briefs now eligible.

Start now: verify the preconditions, then start 7A and report the five agent ids.
```

## 5b. Dispatcher prompt: validation fixes FIX.1 to FIX.4 (Claude Code app, hosted agents)

Paste into one session in the Claude Code app with the yogzblr/imas repo attached.
Same mechanism as section 5: each brief runs as a hosted (remote) agent started from
this session. The dispatcher never merges and never edits code.

```
You are the dispatcher for four fix briefs, FIX.1 to FIX.4, in section 4g of
docs/claude-code-parallel-build-plan.md. You start hosted agents, track them and
report. You do not write code, review code, merge, or approve anything yourself. Read
CLAUDE.md and section 4g of the plan first.

Precondition, checked once at the start: the PR that added section 4g is merged into
main (read the plan from origin/main; if section 4g is not there, stop and tell me).

How to start a brief. Each brief in section 4g is a code block of the form
claude --cloud "TEXT". Take TEXT, the part between the outer quotes, exactly as
written, and start ONE hosted agent per brief with the Agent tool, passing TEXT as the
prompt and isolation set to remote so it runs in its own cloud environment with its
own copy of yogzblr/imas. Do not paraphrase, shorten, reorder or add to TEXT, and do
not include the claude --cloud wrapper. Give each agent a description equal to the brief
id. Start eligible briefs together in one message so they run concurrently. If an agent
cannot reach the repo, add it with the add_repo tool for yogzblr/imas with push access and
retry once; if that fails, stop and tell me.

Gates. A gate is satisfied only when its PR is MERGED into main, not merely open or green.
- FIX.1, FIX.2 and FIX.3: no gate. Start all three together.
- FIX.4: gates FIX.1, FIX.2 and FIX.3. Start it only after all three are merged.
After FIX.4 merges, stop and hand back to me.

Tracking. Use the task list as the ledger, one task per brief, with the agent id, the PR
number once it exists, and its state (not started, running, PR open, CI red, merged,
blocked). Use ListAgents to see running agents and SendMessage to continue an agent that
needs a nudge or an answer I gave. When an agent finishes, find its PR with the REST API
(gh api repos/yogzblr/imas/pulls and .../commits/SHA/check-runs); gh GraphQL is blocked
here, so do not use gh pr. Its PR title should start with the brief id. Do not poll in a
loop: call ReadNotifications when the app says notifications are pending, and when I
message you, and otherwise schedule at most one check-in with send_later about 30 minutes
out while agents are running.

Rules.
- FIX.1, FIX.2 and FIX.3 carry FLAG FOR SECURITY REVIEW: never describe them as done or
  safe to merge, only as ready for review, even when CI is green.
- When an agent or PR lists open questions or decisions for me, copy them to me verbatim
  with the PR number. Do not answer them and do not tell an agent an answer I have not
  given.
- If an agent fails, stalls or its PR conflicts, say so and propose a retry; start a new
  agent only after I say yes, with the same verbatim TEXT. FIX.1 to FIX.3 may touch the
  same docs and BUILD-STATUS rows: if their PRs conflict, report it and do not resolve it.
- If a PR touches files outside its brief's Scope line, flag it to me.
- Start nothing that is not in section 4g. Do not start the release or the UAT.
- Status report format, whenever I ask: the task list as a table, then what is blocked and
  on whom, then the briefs now eligible.

Start now: verify the precondition, then start FIX.1, FIX.2 and FIX.3 and report the three
agent ids.
```

---

## 5c. Dispatcher prompt: Azure UAT gate UAT.1 to UAT.7 (Claude Code app, hosted agents)

Paste into one session in the Claude Code app with the yogzblr/imas repo attached. Same
mechanism as sections 5 and 5b. The dispatcher never merges and never edits code. Do the owner
prerequisites in section 4h while the agents work; the briefs do not need them, the first real
run does.

```
You are the dispatcher for the UAT briefs in section 4h of docs/claude-code-parallel-build-plan.md:
UAT.1, UAT.2, UAT.3a, UAT.3b, UAT.4, UAT.5, UAT.6 and UAT.7, eight briefs in all. You start hosted agents,
track them and report. You do not write code, review code, merge, run anything in Azure, or approve
anything yourself. Read CLAUDE.md and section 4h of the plan first, including the Shared contract.

Precondition, checked once at the start: the PR that added section 4h is merged into main (read the
plan from origin/main; if section 4h is not there, stop and tell me).

How to start a brief. Each brief in section 4h is a code block of the form claude --cloud "TEXT". Take
TEXT, the part between the outer quotes, exactly as written, and start ONE hosted agent per brief with
the Agent tool, passing TEXT as the prompt and isolation set to remote so it runs in its own cloud
environment with its own copy of yogzblr/imas. Do not paraphrase, shorten, reorder or add to TEXT, and
do not include the claude --cloud wrapper. Give each agent a description equal to the brief id. Start
eligible briefs together in one message so they run concurrently. If an agent cannot reach the repo, add
it with the add_repo tool for yogzblr/imas with push access and retry once; if that fails, stop and tell
me.

Gates. A gate is satisfied only when its PR is MERGED into main, not merely open or green.
- Round A, no gate: UAT.1, UAT.2, UAT.3a, UAT.3b, UAT.4 and UAT.5. They write to separate directories
  against the Shared contract, so start all six together.
- Round B: UAT.6 and UAT.7 each gate all six of round A (UAT.7 reuses UAT.5's harness package). Start
  both together, only after every brief of round A is merged.
After UAT.6 and UAT.7 are both merged, stop and hand back to me. Do not run the gate and do not touch Azure.

Tracking. Use the task list as the ledger, one task per brief, with the agent id, the PR number once it
exists, and its state (not started, running, PR open, CI red, merged, blocked). Use ListAgents to see
running agents and SendMessage to continue an agent that needs a nudge or an answer I gave. When an
agent finishes, find its PR with the REST API (gh api repos/yogzblr/imas/pulls and
.../commits/SHA/check-runs); gh GraphQL is blocked here, so do not use gh pr. Its PR title should start
with the brief id. Do not poll in a loop: call ReadNotifications when the app says notifications are
pending, and when I message you, and otherwise schedule at most one check-in with send_later about 30
minutes out while agents are running.

Rules.
- UAT.1, UAT.3b and UAT.6 carry FLAG FOR SECURITY REVIEW: never describe them as done or safe to merge,
  only as ready for review, even when CI is green.
- None of these agents can reach Azure, so none of the work is proven. When reporting, repeat what each PR
  says it could not run. Never describe the gate as working.
- When an agent or PR lists open questions or decisions for me, copy them to me verbatim with the PR
  number. Do not answer them and do not tell an agent an answer I have not given.
- Each brief adds its own row to docs/BUILD-STATUS.md, so their PRs may conflict there. Report a conflict
  and do not resolve it. If an agent fails, stalls or its PR conflicts, say so and propose a retry; start
  a new agent only after I say yes, with the same verbatim TEXT.
- If a PR touches files outside its brief's Scope line, flag it to me. If two PRs disagree about the
  Shared contract, stop and tell me which two and where.
- Start nothing that is not in section 4h.
- Status report format, whenever I ask: the task list as a table, then what is blocked and on whom, then
  the briefs now eligible.

Start now: verify the precondition, then start UAT.1, UAT.2, UAT.3a, UAT.3b, UAT.4 and UAT.5 and report
the six agent ids.
```

---

## 6. Recap of the gating logic (why the waves are ordered this way)

- **B gates C and H** — both touch the auth/trust-chain plumbing B builds.
- **A gates E and I, and effectively D's "real" horizontal scaling** —
  tenant-scoping and recipe storage both assume shared PXC/object storage
  exists first.
- **H gates J** — payload encryption bootstraps its keys through H's
  enrollment response.
- **G (Windows), H.1–H.5 (Linux ingredients), L, K, and the SaaS API
  scaffold** have no dependency on the messaging/storage/auth work and are
  safe to run in Wave 0 regardless of what else is in flight.
- Workstreams flagged 🔴/🟡 in the roadmap docs (auth, crypto, tenant
  isolation, firewall, SELinux, user/group creation) are fine as
  unattended first drafts but should never be treated as merge-ready on
  green tests alone — that's what the "FLAG FOR SECURITY REVIEW" line in
  each prompt is for.
