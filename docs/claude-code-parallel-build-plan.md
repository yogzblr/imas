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

## 5. Orchestrator prompt — paste into one lead Claude Code session

Use this if you'd rather have Claude dispatch and track Wave 0 for you
instead of running the nine commands above by hand. Run it as a **local**
`claude` session at the repo root (it needs Bash to shell out to
`claude --cloud`), or as a Claude Code **Project**.

```
You are coordinating the Wave 0 buildout of the imas SaaS Machine Manager
fork. Read docs/design/imas-master-plan.md and
docs/design/imas-fork-roadmap.md for context first.

Create docs/BUILD-STATUS.md with a table of these nine workstreams:
B, D, F, G.1+G.3, G.5+G.8+G.9, H.4+H.5, L, K, SaaS-API-scaffold.
Columns: workstream | one-line description | cloud session ID | status
(dispatched / in review / merged) | needs security review (y/n).

For each workstream, run `claude --cloud "<task brief>"` using the exact
task briefs from claude-code-parallel-build-plan.md sections 1.1 through
1.9 in this repo (copy them verbatim — do not paraphrase or shorten
them). Record each returned session ID into BUILD-STATUS.md.

Do not dispatch Wave 1 or Wave 2 workstreams (A, C, H, E, I, J) yourself
— those depend on B and A being merged first. Stop after dispatching
Wave 0 and tell me to review the nine PRs. When I tell you B (and A, if
you've also started it) are merged, come back and I'll ask you to
dispatch Wave 1.

For any workstream whose brief says "FLAG FOR SECURITY REVIEW," mark
that in BUILD-STATUS.md and do not represent it as ready to merge, only
ready for review, even after its tests pass.
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
