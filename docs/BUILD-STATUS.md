# Build Status

Tracks every workstream against the numbered requirements in
`docs/design/requirements.md`: Wave 0, Wave 1, Wave 2, the "ongoing"
Windows/Linux ingredient batch, the post-rebrand work (CI, Helm charts,
workstream M), Wave 4 (fleet updates and DB migrations), Wave 5 (the Wave 4
clean-ups and REL.1), the open-item briefs of 2026-10-03 and 2026-10-04
(DOC.1, the first CL.4, SCALE.1 to SCALE.3, LIC.1, REL.2, PKI.1, PKI.2 and the
SEC.1 review) and Wave 7 (security fixes and sealing, the SEC.6 review, the
post-SEC.6 follow-ups and the FIX.1 to FIX.3 validation fixes). Refreshed
2026-10-05 against `main` at `7fb527a` (PR #112, the last of FIX.1 to FIX.3 to
merge): everything in the build plan has merged except the Terraform UAT gate,
which has not been started; no release has been cut; and this file records no
human security review of the flagged work. Start with the "RAG summary" below;
"Requirements traceability" has the evidence behind each requirement's colour,
"Validation, 2026-10-05" (at the end) records what this refresh checked and
what it could not, and "Notes" records what changed in earlier passes.

**How this was verified.** By reading the code on `main` (packages, routes,
migrations, Helm templates, workflows, tests), the merged pull request list and
each PR's description (PRs #68 to #113 through the REST API: all merged, none
open, none closed unmerged), `docs/security-review-2026-10.md`,
`docs/security-review-2026-10-b.md`, and CI results. On `7fb527a` every
workflow that runs on a push to `main` passed: CI (Test on Go 1.26.x, and
Lint), Build, CodeQL, CodeQL Advanced, govulncheck, Docs, Gitleaks and
go-licenses (both its check and its save job). CI, Build, CodeQL,
govulncheck, Docs and Gitleaks passed on every `main` commit from `b78c9e7`
(PR #104) on, and go-licenses, which runs only when Go files change, passed
each time it ran. The path-filtered workflows did not run on these pushes;
their last runs passed: Ansible (Molecule) and GoReleaser
check on PR #110, Load test smoke on PR #80, and sdb OpenBao real server on
`main` at `5896eb8` (PR #71). No test was run for this refresh, which is docs
only; CI is the evidence. "Merged" means reviewed and green in CI, not
exercised on real hosts. Nothing here has run against production-shaped
infrastructure: that is what the Terraform UAT gate and the load tests below
are for.

**Releases (updated 2026-10-05).** Pre-releases `v0.1.0-rc.1` to `-rc.4` have
been cut. rc.1 failed in GoReleaser (`.IsPrerelease` template, fixed in
PR #124/#125), rc.2 was tagged from a broken `main` and skipped, and rc.3
shipped deb/rpm/apk packages with a versioned binary name and none of the
config, signing keys or state directories (fixed in PR #127). **rc.4 is the
first good one**: checksums, GPG and keyless cosign signatures and the six
multi-arch images verified for rc.3's pipeline, and rc.4's packages passed
the new contents check and installed from the `imasdeb` Buildkite registry on
Ubuntu (WSL2), where the service started and, with a placeholder config,
retried the root CA fetch as expected. `publish-packages.yml` has run to the
end (rpm, deb, NuGet, Helm). Still untried: the Windows MSI on a host, the
rpm and apk installs, and enrolment through Envoy against a real backend.

**No human security review is recorded.** Every PR that carries "FLAG FOR
SECURITY REVIEW" has been merged by the owner. Two read-only reviews were
written as input to the human review (Open item 4); neither replaces it. Per
`CLAUDE.md`, the flagged work is "ready for review", not "done" or "safe to
merge", until that review is recorded here.

## RAG summary

**Legend.** **Green**: built, merged, and its tests pass in CI, with no known
gap against the requirement. **Amber**: built, but not yet validated beyond
unit tests, off by default, or with a gap that doesn't defeat the requirement.
**Red**: not built, or a known gap that defeats what the requirement is for.
This is a delivery judgement made from the code and CI on `main` at `7fb527a`;
none of it has run on real hosts or a real cluster, so Green does not mean
"proven in production", and no colour here stands in for the human security
review.

**Overall: 21 requirements: 12 Green, 9 Amber, 0 Red.** Changed since the
2026-10-03 pass: requirement 1 Red to Amber (jitter, the clustered bus and the
load harness are built, none of it measured at scale), requirement 14 Red to
Amber (every boundary the sealing designs named is sealed, sealed only;
residuals below), requirement 15 Amber to Green (DOC.1 reworded
`requirements.md` item 15 to match the build). Everything in the build plan
has merged except the Terraform UAT gate, and nothing has been released.

### Requirements (`docs/design/requirements.md`)

| # | Requirement | RAG | What it would take to turn it Green |
|---|---|---|---|
| 1 | 1M endpoints | **Amber** | Jitter (SCALE.1), the clustered bus (SCALE.2) and the load harness (SCALE.3) are built; the harness has only made its 200-sprout smoke run. Run it at 10k and 100k on a real cluster (`docs/loadtest.md`), add the PXC and Valkey failure tests the scale plan's Phase 3 asks for (not in the harness), close SCALE.2's one-node push and the same-second `iat` tie (B5), and decide the resolver mode. See Open item 3. |
| 2 | DMZ / non-DMZ split | **Green** | |
| 3 | Windows and Unix | **Amber** | A real Windows Server host run (UAT gate). Server 2016 is the stated floor and nothing has installed the MSI. |
| 4 | Ansible deployment | **Green** | (Linux is validated by Molecule; the Windows `win_package` path is not.) **Judgement call:** Green although the Windows path has never run, because the role is built for both, Linux is exercised end to end in CI, and the Windows gap is carried by requirement 3 (Amber, UAT gate) rather than counted twice; a stricter reading of the legend would make this Amber. |
| 5 | JWT auth to the NATS websocket | **Green** | |
| 6 | Per-sprout JWT | **Green** | |
| 7 | Horizontally scalable farmer | **Amber** | A load test. Core is queue-grouped and stateless; the bus tier can run as 3 or more meshed nodes since SCALE.2 (chart default `bus.replicaCount: 1`), never run on a real cluster or under load. |
| 8 | Sprout via proxies | **Green** | |
| 9 | Recipe download from an HTTP endpoint | **Green** | |
| 10 | NATS response under 300 ms | **Amber** | A latency measurement. SCALE.3 reports `test.ping` p50/p95/p99 against 300 ms, but its only run is the smoke run (200 sprouts, local bus, p99 threshold 1 s), which is not a latency result. |
| 11 | Recipe download uses the same JWT | **Green** | |
| 12 | Envoy with JWT validation | **Green** | |
| 13 | Backend on Kubernetes | **Amber** | Install the charts on a real cluster (UAT gate). No Terraform exists. FIX.3 (merged, PR #112) fixed three things a fresh install would have hit: no farmer object store egress, no required bootstrap admin, and an unchecked recipe credential. |
| 14 | Payload encryption | **Amber** | The human security review of the sealing work, then the residuals: facts, cook step events, `test.ping`, the rotate trigger, log shipping and the join event are still plaintext inside TLS, facts being the one review 2026-10 ranked High (they feed the rollout gate and recipe templates); the forged "no responders" re-run (B6) is an accepted residual. Sealed only, as built: `cmd.run`, `cook` and its nudge, box-key submissions, `shell.*` (J.5), the staged recipe on `/files/` (SEC.7a), sprout refresh (J.2), the CLI API (J.3) and `internal.*` (J.4); a sprout with no box key is refused, never downgraded (FIX.1). **Judgement call:** Amber, not Red, although facts stay plaintext inside TLS and review 2026-10 ranked that High: every boundary that carries a command, a recipe, a key or a credential is sealed only, and the facts gap lets a compromised bus forge data, not run anything. A reader who weighs the rollout gate and templates fed by forgeable facts as defeating the requirement would call it Red. |
| 15 | Key rotation for sprout keys | **Green** | (`requirements.md` item 15 now describes the built design, DOC.1, PR #69.) |
| 16 | SDB-equivalent secrets | **Green** | |
| 17 | Probe capability | **Green** | |
| 18 | Installers: yum, apt, zypper, MSI | **Amber** | Cut a first release so the packages are published and installed once. |
| 19 | Ansible with one-time key | **Green** | |
| 20 | Fleet updates from the sprout's repo | **Amber** | Both switches stay off. The fixes both reviews asked for before dispatch are merged (H2 in SEC.4; M1, L1, L2, L8, M5 in SEC.5; the rollout window in SEC.5b; B1 to B3 in SEC.7a to SEC.7c). Left: the human review, the UAT gate's self-update cycle on published packages, and a decision on B8 (MSI version binding) and B4 (per-cook render budget). See Open item 4. |
| 21 | Licensing | **Amber** | Decide on BSD-2-Clause, BSD-3-Clause, ISC and 0BSD and record them under item 21 (every such module and the binaries that link it are in `DEPENDENCIES.md`; questions in PR #73). The `go-licenses` workflow passes on `main`. |

### Build plan (`docs/claude-code-parallel-build-plan.md`)

| Wave / item | RAG | Status |
|---|---|---|
| Wave 0 (B, D, F, G.1/G.3, G.5/G.8/G.9, H.4/H.5, L, K, SaaS-API scaffold) | **Green** | All merged. |
| Wave 1 (C, H) | **Green** | Merged; checked against real Envoy v1.35.3. |
| Wave 2 (E, I, J) | **Green** | Merged. J's sealing, which stopped at `cmd.run` and `cook`, was completed by Wave 7 (see that row). |
| Ongoing batch (G.2, G.4, G.6, G.7, H.1, H.2, H.3) | **Green** | All merged. |
| Post-rebrand work (M.1 to M.4, Helm charts, proxy support, box-key rotation) | **Green** | Merged. Windows paths are unit-tested only. |
| Wave 4 (DB.1, DB.2, FU.0 to FU.7, FU.6b) | **Amber** | Merged. Dispatch is off by default and the Windows install is mock-tested only. |
| Wave 5: CL.1, CL.2a, CL.2b, CL.3 (PR #62, #66, #67, #63) | **Green** | Merged. Follow-ups are in Open items (5, 6, 10). |
| Wave 5: REL.1 (PR #64, #65) | **Green** | Merged: GoReleaser OSS, MSI from `build-msi.sh`, secret-free `goreleaser-check.yml`. No real tag has exercised it. |
| Open-item briefs, 2026-10-03/04, not in the plan document: DOC.1, the J sealing designs, CL.4 (PR #71), SCALE.1 to SCALE.3, LIC.1, REL.2, PKI.1, PKI.2, SEC.1 (PR #69 to #81) | **Amber** | All merged. The scale work is unmeasured (Open item 3) and SCALE.2, PKI.1 and PKI.2 are flagged for a security review not yet held. See "Open-item briefs and Wave 7". |
| Wave 7 (plan §4e to §4g): SEC.0, SEC.3a, SEC.3b, SEC.4, SEC.5, SEC.5b, SEC.6, REC.1, J.1 to J.5, SEC.7a to SEC.7d, SH.1, CL.4 (PR #103), OPS.1, T.1, FIX.1 to FIX.3 (PR #83 to #113) | **Amber** | All merged, CI green on `main`. Every brief but T.1 is flagged for security review and none has had the human one; SEC.6 is a read-only review. Open residuals in Open items 4, 10 and 11. SEC.1 (the first review, PR #81) ran before this wave; there is no SEC.2. See "Open-item briefs and Wave 7". |
| First release (`release.yml`, `publish-packages.yml`) | **Amber** | `v0.1.0-rc.4` (2026-10-05) is released and published; rc.3 and earlier are not usable. Tag trigger in `release.yml` re-enabled. Untried: MSI on Windows, rpm/apk installs, enrolment against a backend. |
| Azure UAT gate (was: Terraform UAT gate) | **Red** | Not started. Decided 2026-10-06: Azure (existing paid subscription), OpenTofu, two single-node k0s hubs (DMZ and core) plus six tenant VMs (Ubuntu, AlmaLinux, Windows x 2 tenants), Keycloak validated by saasapi, MinIO for UAT only. Briefs UAT.1 to UAT.8 (UAT.7: every ingredient method, plus package upgrade and self update; UAT.8: a local rig to validate the suite without Azure; access to the VMs is through Azure Bastion tunnels) and the owner prerequisites are in the plan, section 4h; the first release it needs exists (rc.4). Nothing has run in Azure. |
| Azure UAT gate: UAT.1, Azure infrastructure and access (`uat/tofu`, `uat/access`) | **Amber** | Ready for review (FLAG FOR SECURITY REVIEW), never applied. OpenTofu module for one run (resource group `imas-uat-<run_id>`, VNet with dmz, core, tenants and AzureBastionSubnet, one NSG per subnet, Standard Bastion with native tunnelling that fails closed on its NSG, two hubs and six sprouts, a private DNS zone with `dmz.` and `core.` names, per-run SSH key and Windows password as sensitive outputs, `tofu output uat` with exactly the contract keys), a bootstrap stack (state storage with Entra-only access, CanNotDelete lock, subscription budget), `destroy.sh` (tofu destroy, tag-checked `az group delete` fallback, fails if anything tagged with the run_id remains), and `tunnels.sh`/`vmctl.sh`. Network per the owner (2026-10-06): sprouts reach only Envoy, node port 8443, on the DMZ private address by private DNS name; core reaches only the bus node port 8442; no load balancer. Owner: the names `dmz.`/`core.uat.imas.internal` go in the Shared contract, used by the Envoy and bus certificate SANs, `farmerinterface` and `farmerbusurl` (UAT.3a, UAT.3b, UAT.4); the Bastion NSG stays fail-closed. Tests: tofu fmt, validate and test (mocked providers), shell tests with stubbed `az`/`tofu`, shellcheck. |
| Azure UAT gate: UAT.3a, the DMZ hub (`uat/hub/dmz`) | **Amber** | PR #133 open, ready for review. `install.sh` pulls the `nats` chart of `release_tag` from the public `imashelm` (exact version, pre-releases included, no token), installs farmerbus and Envoy with one replica each, and creates the two exposure Services with pinned node ports: Envoy on 8443 (NodePort, or LoadBalancer as the alternative) and the bus on 8442. Certificates carry the private name `dmz.uat.imas.internal`, which sprouts (`farmerinterface`) and farmer (`farmerbusurl`) use (owner's decisions, 2026-10-06; install order core first, then DMZ). `check.sh` checks TLS with the UAT CA for the public and private names, the `jwt_authn` refusals, and that `/v1/enroll` reaches farmer and is rate limited. Static checks and offline tests only; never run against a cluster. The Services stay `install.sh`'s own manifests (owner's decision; a `deploy/helm/nats` change for node port values is a later follow-up). Open: `farmerbusurl` on the private name needs `deploy/helm/farmer` support (UAT.3b); section 4h still lists the DMZ install first. |
| Azure UAT gate: UAT.4, tenants and enrolment (`uat/enroll`) | **Amber** | Ready for review, not run against any stack. Creates tenants 1 and 2 through saasapi, mints one one-time key per sprout in its own tenant, writes the Ansible inventory (SSH and WinRM through the Bastion tunnels, docker for the local rig, the package pinned to the release tag), runs `ansible/site.yml` and `imas_verify` unchanged, and waits for farmer to report every sprout connected (asset links and the saasapi lookup). Both tenants get the same sprout IDs (`ubuntu-01`, `alma-01`, `win-01`) through a seed play, because the role has no `sproutid` variable (a finding). Owner decisions 2026-10-06 applied: each new tenant is bound once with UAT.3b's `uat/hub/core/bind-tenant.sh`, and tokens come from the core hub's `core.json` and `credentials.json` (`core-token.sh`, tested against stand-ins only); `community.docker` is dropped and the local rig connects over SSH to containers running sshd (no docker connection); UAT.4 binds tenants 1 and 2, the harness only run-created tenants not in `core.json`; `farmerinterface` is the DMZ's private name `dmz.uat.imas.internal`, so Envoy's certificate must carry it as a SAN. Windows enrols with a pre-release tag when it is pinned and on `imasnget`, but self update to a pre-release is refused on Windows by design. Tests: generator unit tests, script tests against a fake saasapi, Keycloak token endpoint and `bind-tenant.sh`, the two playbooks run on localhost, shellcheck, yamllint, ansible-lint. |

### Open items (numbered as in "Open items" below)

| # | Item | RAG | Next step |
|---|---|---|---|
| 1 | Azure UAT gate | **Red** | The first release exists (`v0.1.0-rc.4`, 2026-10-05) and the provider is chosen (Azure, OpenTofu; see the Azure UAT gate row). Owner: the prerequisites in plan section 4h (OIDC identity, `uat` environment, quota, image terms), then dispatch UAT.1 to UAT.8 with the section 5c prompt. Its other prerequisites are merged: recipe upload (REC.1) and the Helm fresh-install fixes (FIX.3). |
| 2 | `shell.*` sealed (J.5) and its follow-ups (SH.1) | **Amber** | Built and merged (PR #98, #102); human security review not held. No session recording (owner, PR #98). |
| 3 | Scale and latency (jitter, clustered bus, load tests) | **Red** | SCALE.1, SCALE.2 and SCALE.3 are built. The open action is the run: the harness at 10k and 100k on a real cluster (`docs/loadtest.md`). No load result exists yet. |
| 4 | Security review of the flagged work | **Amber** | Both read-only reviews done (`docs/security-review-2026-10.md`, `docs/security-review-2026-10-b.md`); every finding they asked to fix before dispatch has a merged fix. Open: B4, B5, B6 (accepted), B8, the Info items, the first review's deferred Lows, and the human review itself, to be recorded here before `SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED` is turned on. |
| 5 | `go-licenses` workflow and licence record (LIC.1) | **Amber** | Workflow fixed by LIC.1 (PR #73) and green on `main`, `save` included. Left: record BSD-2-Clause, BSD-3-Clause, ISC and 0BSD under requirement 21, or drop the modules (questions in PR #73). |
| 6 | `internal/pki` provision/deprovision race | **Amber** | Fixed by PKI.1 (PR #74, #77), with PKI.2's atomic writes (PR #79); merged, human security review not held. |
| 7 | SaaS API section 1.7 (API keys, teams, webhooks, billing) | **Red** | Never designed; needs a design pass. |
| 8 | Docs wording (requirement 15, README embedded bus) | **Green** | Closed by DOC.1 (PR #69). |
| 9 | Nice-to-haves (Keycloak harness, rotation scheduler, CERT-In/DPDP review) | **Amber** | Unowned. |
| 10 | Leftovers and follow-ups from PR #62 to #113 | **Amber** | None blocks the first release. Fold them into clean-up briefs after the first release shows what the pipeline needs; the API docs for the new item codes and variable, the web UI's `boxpub`, and REC.1's audit and deprovision follow-ups are the larger ones. |
| 11 | Control plane forgeable by a compromised bus (CLI tokens, sprout refresh, `internal.*`) | **Amber** | Sealed only, merged: J.1 to J.4 and J.4's Helm wiring (PR #93 to #97, #99). Human security review not held. Accepted residual: forged "no responders" on `internal.sprout.action` (B6, owner, PR #97). |

## Requirements traceability

Status against `docs/design/requirements.md`. "Built" means the code is on
`main` and its tests pass in CI; "validated" means exercised somewhere
beyond unit tests (real Envoy, Molecule containers, real OpenBao).

| # | Requirement | RAG | Status | Evidence / gap |
|---|---|---|---|---|
| 1 | 1M endpoints | **Amber** | **Built, not validated at any scale** | Storage (PXC, Valkey, object storage) and queue-grouped core are built. **Reconnect jitter: built (SCALE.1, PR #72).** `cmd/sprout` reconnects with full-jitter exponential backoff (`internal/natsretry`, `nats.CustomReconnectDelay`; `busreconnectbase` 2 s and `busreconnectcap` 5 min by default) instead of the fixed 15 s wait, and its first-connect loop uses the same backoff. **Clustered bus: built (SCALE.2, PR #76, #78), not load-tested.** `cmd/farmerbus` meshes on authenticated routes (mutual TLS + route password) and fences a node that lacks a majority, sits on a partial mesh, or hasn't synced its resolver; in-process 3-node tests cover cross-node delivery, failover, and lock-out while a node is down or partitioned (`cmd/farmerbus/cluster_integration_test.go`). The nats chart allows `bus.replicaCount` of 1 or an odd number of 3 or more (default 1) and `bus.maxConnections` (default 65,536 per node). **Load harness: built (SCALE.3, PR #80).** `tools/loadtest` (`docs/loadtest.md`); its only runs are the CI smoke runs on PR #80 (200 sprouts, one local bus node). Known gaps: core pushes an Account JWT to one bus node and doesn't wait for every node, and a same-second `iat` tie can still revert a revocation cluster-wide (review B5, M6 carried); farmer's per-tenant bus connection gives up after 30 reconnects (about 7.5 min of outage) and nothing redials it (`cmd/farmer/main.go`, reported in PR #72); the default 512Mi bus memory limit is reached at a few thousand connections. No connection, throughput or failure figure is claimed. |
| 2 | DMZ / non-DMZ split | **Green** | Built | `cmd/farmerbus` (DMZ) vs `cmd/farmer` (core, outbound only); Helm charts `deploy/helm/nats` and `deploy/helm/farmer`, with NetworkPolicies. |
| 3 | Windows and Unix | **Amber** | Built, **not validated on Windows hosts** | Full G.1–G.9 ingredient set, SCM service wrapper, MSI. Windows paths are cross-compiled and unit-tested; the self-update MSI path is tested with `msiexec` mocked. The Terraform UAT gate would be the first real-host run. |
| 4 | Deployment automation with Ansible | **Green** | Built, validated | `ansible/roles/imas_sprout` and `imas_verify`, Molecule CI on Rocky, Debian and openSUSE Leap. |
| 5 | JWT auth to the NATS websocket; enrollment key only to bootstrap | **Green** | Built, validated | NATS User JWT plus gateway EdDSA JWT; `POST /v1/enroll`; run through real Envoy v1.35.3. |
| 6 | Per-sprout JWT | **Green** | Built, validated | Paired JWTs minted at enrollment and refresh. |
| 7 | Farmer horizontally scalable | **Amber** | Built, not load-tested | Core is stateless: `QueueSubscribe` on `imas-core`, PXC read-through, Valkey heartbeat, object-store recipes. The bus tier can run as 3 or more meshed nodes (SCALE.2, see 1); it has not been run on a real Kubernetes cluster or under load. |
| 8 | Sprout via proxies | **Green** | Built | `busproxyurl` (HTTP CONNECT / SOCKS5) for the bus connection; HTTP clients use `ProxyFromEnvironment` (the `sdb://openbao` provider only since CL.2b: before it, it connected directly). Ansible variable exposed. |
| 9 | Recipe download from a configured HTTP endpoint | **Green** | Built, validated | `/files/` behind Envoy; `TestSproutDownloadsStagedRecipe_ThroughRealEnvoy`. A sprout reads only its own staged recipe; since SEC.7a (PR #107) that copy is sealed by farmer and refused unless it opens under the sprout's own keys, and since SEC.7c (PR #104) a revoked or superseded NKey's gateway JWT is refused on `/files/`. SEC.4 added per-tenant source recipes (`tenants/<tenant_id>/recipes/`, then the platform prefix, never another tenant's) and tests the cross-tenant refusal at every layer (`TestTenantRecipes_CrossTenantRefusedAtEveryLayer`). Tenants upload recipes through the SaaS API (REC.1, PR #90). |
| 10 | NATS response under 300 ms | **Amber** | **Not validated** | Design removes the synchronous probe loop. SCALE.3's harness measures the `test.ping` round trip at p50/p95/p99 against 300 ms; its only runs are the 200-sprout CI smoke runs (PR #80, threshold p99 1 s), which show the harness works, not a latency figure. |
| 11 | Recipe download uses the same JWT | **Green** | Built, validated | Same gateway JWT, same Envoy gate. |
| 12 | Envoy with JWT validation in front of NATS | **Green** | Built, validated | `deploy/envoy/envoy.yaml`, `jwt_authn` with remote JWKS; checked against real Envoy, again for J.2's sealed refresh (v1.35.3). Envoy can't see revocation: farmer refuses a revoked NKey's gateway JWT behind it (SEC.7c) and the bus refuses its User JWT. Keycloak JWKS cross-check harness has never been run (nice-to-have). |
| 13 | Backend on Kubernetes (NATS, Valkey, farmer, Percona) | **Amber** | Built | Helm charts with optional PXC/OpenBao/Valkey subcharts; single migration hook Job; sprout-release hook Job; the control-plane box keygen hook Job, on by default since J.4's Helm wiring (PR #99). Chart tests render them; no gate has installed them on a real cluster. FIX.3 (merged, PR #112; flagged for security review): farmer's NetworkPolicy reaches `objectStore.endpoint` whenever one is set, the render refuses an install with no bootstrap admin (or an explicit `farmer.bootstrapAdmin.skip`), saasapi refuses to start with a recipe credential the object store lets outside `tenants/` or onto `sprouts/` (on by default in the chart and the binary), and NOTES warns when saasapi's two Secrets must be created by hand (Open items, 10). FIX.3 ran `helm template` and `helm lint`, but not the subchart render test (`TestSubchartsRender`). **No Terraform exists yet** (see the UAT gate row). |
| 14 | Payload encryption, key pair per sprout and per tenant | **Amber** | **Built, sealed only; not human-reviewed; documented residuals** | Per-tenant and per-sprout X25519 keys; every tenant has its own fresh keypair (SEC.3a deleted the shared legacy keypair). **Sealed end to end, with no plaintext fallback:** `cmd.run`; `cook` dispatch, its Ack and the resync nudge; box-key submissions; `shell.*` (J.5, PR #98: farmer relays with both legs sealed under per-session ephemeral keys; Windows refuses shell); the staged recipe a sprout pulls over `/files/` (SEC.7a, PR #107: `f2s.staged`, bound to tenant, sprout, job ID and dispatch time; a copy stamped more than `stagedrecipeclockskew` before the newest handled job is refused, SEC.7d, PR #110); sprout refresh (J.2, PR #94); the CLI API, bearer tokens deleted (J.3, PR #95, #96); and `internal.*` between the SaaS API and farmer (J.4, PR #97, #99). Every sealed message names its tenant and recipient key (SEC.3b). A sprout with no box key gets nothing: farmer refuses with `sprout_reenroll_required` and a keyless sprout refuses everything with `no-keys` (FIX.1, PR #113). A sprout's first box key is accepted only with the single-use, 5-minute `enroll_binding` from the request that issued its identity (SEC.7b, PR #108). Deleting or replacing a sprout revokes its NKey (`pki_revoked_nkeys`), its box keys and, on farmer's routes, its gateway JWT (SEC.3a, PR #85; SEC.7c, PR #104). The sprout's replay guard survives restarts; opened bodies are never logged and log shipping sends Info and above only (`natslogminlevel`). **Still plaintext inside TLS:** facts (forgeable by a compromised bus on the sprout's own subject; review 2026-10 ranked this High because facts feed the rollout gate and recipe templates; not addressed), cook step events (Decision D, after the UAT gate), `test.ping`, the empty `boxkey.rotate` trigger, log shipping, the sprout's `imas.sprouts.announce.<id>` join event (farmer only logs it) and `cancel` (no sprout subscribes, so a cancel does nothing on the sprout). **Accepted residual:** a forged "no responders" re-runs an `internal.sprout.action` up to `SAASAPI_OUTBOX_MAX_ATTEMPTS` times (review 2026-10-b B6, owner, PR #97). All of it is flagged for security review; neither read-only review is the human one. |
| 15 | Key rotation for sprout keys | **Green** | Built, matches the requirement | DOC.1 (PR #69) reworded `requirements.md` item 15 to the built design: farmer-triggered, the trigger carries no key material, the sprout generates the new pair and submits only the public key, sealed under its current key. See `imas-payload-encryption-design.md`, "Sprout-side rotation, farmer-triggered only". |
| 16 | SDB-equivalent secrets in the sprout | **Green** | Built (v1 tier) | `internal/ingredients/sdb`: OpenBao/Vault (hot-reloaded client cert, official OpenBao client since CL.2b, tested against OpenBao 2.4.1 and Vault 1.20.4), Azure Key Vault, AWS Secrets Manager, GCP Secret Manager. CyberArk and Delinea (Tier 2) not built, by design. |
| 17 | Probe capability (database, HTTP) as a sprout task | **Green** | Built | `probe.http`, `probe.database`, plus `wait`, `cond`, `on_exit`, registered variables with `sensitive` redaction. |
| 18 | Installers: yum, apt, zypper, MSI | **Amber** | Built, **published (rc.4)** | nfpm deb/rpm/apk, SUSE rpm check, MSI and winget package, and the workflow that uploads them to the Buildkite registries. `v0.1.0-rc.4` went through it on 2026-10-05; the deb installed from `imasdeb` on Ubuntu (WSL2) and the service started. The rpm and apk installs and the MSI on Windows are untried; rc.3's packages in the registries are broken. |
| 19 | Ansible with one-time key | **Green** | Built, validated | Join token handled `no_log`, mode `0600`, removed by the sprout after enrollment. |
| 20 | Fleet updates from the sprout's configured repo | **Amber** | Built, **dispatch off by default** | FU.0 to FU.7, FU.6b merged (below). `SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED` stays `false`, in the Helm chart too (`saasapi.fleetUpdateDispatch.enabled`); farmer has its own switch since SEC.5, `IMAS_SELF_UPDATE_ENABLED` (Helm `farmer.selfUpdate.enabled`), also `false`, and a rollout needs both on. Since SEC.5 the sprout installs only a package whose own metadata names `imas-sprout` at the signed version, dpkg runs with `--refuse-downgrade`, and the installed version is read back; a pre-release is refused on Windows (PR #88), because an MSI ProductVersion can't carry it (review B8). Since SEC.5b farmer enforces the tenant's rollout window, and since SEC.4 facts are stored under the subject's sprout (review H2). Linux path has an end-to-end test against a real repository (Nexus), not against the Buildkite registries; Windows is mock-tested only, and its MSI metadata read (`msi.dll`) is compiled but not run; zypper's downgrade skip was read from source, not run. See Open item 4 for what is left before dispatch. |
| 21 | Licensing | **Amber** | Built, **BSD/ISC/0BSD not recorded** | Apache/MIT default; PXC and MPL-2.0 exceptions recorded; goose (MIT) added. LIC.1 (PR #73) fixed the `go-licenses` workflow: pinned to v2.0.1, whose classifier identifies `modernc.org/mathutil`'s LICENSE as the BSD-3-Clause it is (v1.6.0, what `@latest` gave, could not); the check now also fails on an unidentified licence and runs on pull requests; `dependencies/` is regenerated for Linux, the Windows sprout and the darwin CLI. Both jobs have passed on every `main` push that ran them since (`7fb527a` included). `DEPENDENCIES.md` lists every module that is not Apache-2.0 or MIT and which binaries link it. BSD-2-Clause, BSD-3-Clause, ISC and 0BSD (Go's own `x/*` modules among them) are not yet recorded under item 21. Open question from PR #73: the MPL-2.0 OpenBao client is linked into the imas CLI too. |

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

> **Superseded (2026-10-05). Historical record of PR #30, not the current
> state.** The plaintext `cmd.run` fallback for a sprout with no box key
> described below is deleted (FIX.1, PR #113: farmer sends nothing to such a
> sprout and refuses with `sprout_reenroll_required`; a keyless sprout
> refuses everything with `no-keys`). Adopted tenants and the legacy shared
> keypair are gone (SEC.3a, PR #85: every tenant has its own fresh keypair).
> For what is sealed today, see requirement 14 in "Requirements
> traceability".

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

> **Superseded (2026-10-05). Historical record as of PR #30 to #34, not
> the current state.** The plaintext fallback for a sprout with no box key
> (the `cook` bullet below) is deleted (FIX.1, PR #113); `shell.*` is
> sealed end to end, so the "`shell.*` now matters most" bullet no longer
> holds (J.5, PR #98, and SH.1, PR #102); adopted tenants and the legacy
> shared keypair are gone (SEC.3a, PR #85); and live `cmd.run` streaming is
> removed with the plaintext path (FIX.1). For what is sealed today, see
> requirement 14 in "Requirements traceability"; for what is left, Open
> items 10 and 11.

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
| **New: Terraform UAT gate** | Provision per-OS VMs, install a tagged release's actual Buildkite-published packages via the M.4 playbooks, smoke-test enrollment/recipe-run/reboot survival, and now also one self-update cycle (FU.2) per OS. Task brief is in `docs/claude-code-parallel-build-plan.md` §4a (item 5), including a flag that the default compute-provider choice (libvirt/KVM) needs a human sign-off. | **not started — no `.tf` files, modules or workflow exist in the repo.** Its code dependencies (M.4, the release flow, FU.2) are merged, but it is **not unblocked**: it still needs a first release (none has been cut; see "Validation, 2026-10-05") and a decision on the compute provider. It is the main remaining delivery item (Open item 1) |
| J follow-up: per-tenant tenant keypairs, tenant key rotation with authenticated re-pin, `cmd.run` sealed end to end, box key submissions sealed | See "J follow-up" under Wave 2. FLAG FOR SECURITY REVIEW | merged — PR #30 (`60c39a2`); still flagged for security review |
| Docs refresh (architecture diagram, SaaS API reference, `INSTALL.md`, this file, `packaging/systemd/*.service` vs `docs/*.service` dedup) | Done on branch `claude/sweet-sagan-yklpu8`: `docs/diagrams/imas-architecture.svg` replaces `grlx-arch-light.png`; `docs/api/saasapi.md` + `docs/api/saasapi-openapi.yaml` (all 18 `NewRouter` routes, the 2 dispatch routes marked off by default); `INSTALL.md` rewritten for tenants, enrollment keys, the SaaS API and Envoy; `docs/imas-{farmer,sprout}.service` removed in favour of `packaging/systemd/` | merged — PR #23 |
| J: seal `cook` dispatch and resync nudge end to end | See "As built (J follow-up)" under Wave 2. Closes the highest-priority item on the "still plaintext" list: a compromised bus can no longer inject either a command (`cmd.run`) or a recipe (`cook`) onto a box-ready sprout. Also moved farmer's job-creation recording off the (now sealed) plaintext dispatch onto an explicit hook (`cook.SetDispatchRecorder`). FLAG FOR SECURITY REVIEW | merged — PR #32 (`d2692c8`, `6f1ac36`, `bf5956c`) |
| H: sprout outbound proxy support for the bus connection (requirements.md item 8) | New sprout config key `busproxyurl` (`http://` HTTP CONNECT or `socks5://`); `pki.LoadSproutBus` wires it as nats.go's `CustomDialer`, covering `wss://`, `tls://` and `nats://` alike, with `nats.SkipHostLookup` so the proxy resolves the bus host. The sprout's HTTP clients already covered this via `ProxyFromEnvironment`; this closes the one real gap (the bus connection itself) | merged — PR #33 (`924e9dc`, `ac523c1`) |
| J: sprout side of farmer-triggered box key rotation (requirements.md item 15) | Closes "sprout-initiated box key rotation has a farmer side but no sprout side." Farmer-triggered only, no sprout-side scheduling. New key held `pending` until confirmed by the first farmer payload that opens under it; replaced key kept `previous` for `sproutboxkeyprevgrace` (default 15m, floored at `2×DefaultMaxSkew`). Along the way, found and fixed a real gap: `sproutPermissions` never granted the `boxkey.pub` publish subject at all, so every submission was refused as a Permissions Violation until this PR added it (existing sprouts pick it up via JWT re-mint on next refresh). See `docs/design/imas-payload-encryption-design.md`'s "Sprout-side rotation, farmer-triggered only." FLAG FOR SECURITY REVIEW | merged — PR #34 (`8eb23da`, `8384084`, `7b9d80d`) |
| Ansible + packaging: expose `busproxyurl` and `sproutboxkeyprevgrace` | `ansible/roles/imas_sprout` variables `imas_sprout_bus_proxy_url` (drift-managed the same way as `busurls`: set when non-empty, removed when emptied) and `imas_sprout_boxkey_prev_grace` (set when non-empty, but deliberately never removed — see below), `packaging/etc/imas-sprout.conf` commented examples, `ansible/README.md` variable table. Found and fixed a Molecule idempotence failure along the way: `sproutboxkeyprevgrace` is the only one of the two with a `jety.SetDefault` in `internal/config/config.go`, so the sprout rewrites it into the config file with a concrete default value on any other save (enrolling, clearing its join token). Managing it the same "remove when empty" way as `busurls`/`busproxyurl` fought that write-back every run — molecule's idempotence check caught it: `imas_sprout : Write the enrollment settings...` and the restart handler both fired non-idempotently on all three containers. Fixed by only ever adding an explicit override for this key and never trying to force it absent. | merged — PR #35 (`aa51688`, `73ecaf2`; docs and Ansible only, no application code) |

## Fleet updates and DB migrations (Wave 4, merged 2026-10-01 to 2026-10-02) and the Wave 5 clean-ups (merged 2026-10-03)

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
| Release flow (`docs/RELEASING.md`), **run to the end with rc.4** | One `vMAJOR.MINOR.PATCH` tag releases everything: five GHCR images (keyless cosign), binaries and checksums on GitHub releases, rpm/deb/winget to the Buildkite registries, `farmer` and `nats` charts to `imashelm`. Stale upstream publishers (Docker Hub, Cloudsmith, S3, AUR) removed. `release.yml` is manual-only until the repo secrets `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE` exist (set 2026-10-03), and `publish-packages.yml` needs the Buildkite organisation variable and token. GoReleaser OSS since brief REL.1: the Windows MSI comes from `packaging/windows/build-msi.sh` (`wixl`) as a build hook instead of goreleaser-pro's `msi` pipe, so no `GORELEASER_KEY`; `goreleaser-check.yml` runs a secret-free snapshot on pull requests and checks the MSI is in `checksums.txt`. rc.1 to rc.3 failed or were broken (see "Releases" above); rc.4 is the first good one, and the tag trigger in `release.yml` is on again. | merged — PR #43 (`c3f6f65`), #44; REL.1 merged — PR #64, #65 |
| DB.1 goose migrations | `cmd/migrate` and `internal/migrations` (goose, embedded SQL, no CGO): baseline per schema, row-based run lock (not `GET_LOCK`, which is node-local on Galera), `up` and `check`; GORM `AutoMigrate` removed from `internal/pxc` and saasapi; services check the schema version at startup. `saas` migrations 00001–00005 and `farmer` 00001 are on `main`. | merged — PR #46 (`1e56315`) |
| DB.2 Migration hook Job | `db-migrate-job.yaml` replaces `db-bootstrap-job.yaml`: one pod, `pre-upgrade`/`pre-rollback`, `post-install` with the bundled PXC; `imas-migrate` image shipped; chart tests extended | merged — PR #48 (`691a1bc`) |
| FU.0 Signed manifest | URL-free manifest (`imas-fleet-manifest-v1|version|os|arch|file_name|checksum_sha256|min_sprout_version`) signed with the Transit key, verified against a keyring; `selfupdate` and `sprout_action` reworked. FLAG FOR SECURITY REVIEW | merged — PR #45 (`c5ecebe`) |
| FU.3 + FU.4 Release registration and signing | `fleetreleaser` is a stateless TLS signing service with no DB access and is the sole signer; saasapi's operator plane validates and stores signed rows (one per OS/arch/package type, idempotent on identical checksums, revoke call), migrations 00003–00004. FLAG FOR SECURITY REVIEW | merged — PR #49 (`08b6982`), operator plane served by `cmd/saasapi` in PR #56 (`e79a3d4`) |
| FU.1 Manifest endpoint | Farmer serves `GET /v1/sprout/update-manifest` (sprout JWT), read-only from the release catalog; routed through Envoy and tested against real Envoy | merged — PR #51 (`e44b1a6`), #52 (`c23fce5`) |
| FU.2 Sprout fetch, verify, install | Sprout reads its repository's own index (apt, rpm incl. zstd, NuGet flat container), verifies signature and SHA-256, installs with `dpkg -i`, `rpm -U`, `zypper` or `msiexec`, refuses downgrades; keyring shipped in deb/rpm/MSI; Ansible variables for repo URL and token; `testing/selfupdate-e2e` drives a real cycle against Nexus on Debian and Rocky. FLAG FOR SECURITY REVIEW | merged — PR #53 (`f3d035d`) |
| FU.7 Farmer dispatch | Farmer dispatches `self_update` as `{version}` only and re-verifies it against the catalog (`internal/fleetcatalog`) before sending | merged — PR #53 |
| CL.1 Remove the dead live fleet-key path | Deleted `internal/fleetkeys` and its farmer wiring, `payloadbox.PurposeFleetSigningResponse`, the `imas.sprouts.<id>.fleetsigningkeys` grant in sprout JWTs, `fleet_signing_jwks` in `POST /v1/enroll` (farmer and sprout client), `GET /v1/.well-known/fleet-signing-jwks.json`, the sprout's enrollment pin (`internal/pki/fleetkey.go`) and the `sproutfleetsigningjwks` setting. Enrollment no longer needs the fleet key source. A sprout built before this refuses to enrol against a farmer built after it: upgrade sprouts first, or re-enrol. `POST /v1/enroll` no longer reads the fleet signing key, so a farmer without `IMAS_FLEETSIGN_OPENBAO_*` now enrols sprouts instead of failing closed (the manifest endpoint and `self_update` dispatch still fail closed without it). FLAG FOR SECURITY REVIEW | merged — PR #62 (`ec4f10d`) |
| CL.3 Outbox sweeper | `internal/saasapi/sweeper.go`, on every saasapi replica (`SAASAPI_OUTBOX_*`, Helm `saasapi.outboxSweeper.*`). Row leases (`lease_owner`/`lease_until`, claimed by one conditional `UPDATE` that must affect the row; not `GET_LOCK`), migration `saas/00006`, which also adds `provisioning_jobs.last_dispatched_at`, `asset_action_items.dispatched_at` and `planned_at_target` (what a resumed rollout needs and wasn't stored) and an index on `asset_action_items.status`. Re-publishes pending provisioning jobs with exponential backoff, failing them after `SAASAPI_OUTBOX_MAX_ATTEMPTS`; re-sends §1.5 items still `queued` (failing them `expired_not_sent` past `SAASAPI_OUTBOX_ACTION_MAX_AGE`, 15m), never ones in `dispatching`, which it fails `dispatch_outcome_unknown` once their dead dispatcher would have given up (nothing downstream deduplicates a re-send, and nothing downstream rejects an old command: the envelope's ±5m window counts from farmer's seal time); with dispatch enabled, takes over an update rollout whose lease lapsed and resumes it from the database, gating already-sent items on deadlines from their dispatch time and re-checking approval, revocation, registration and the tenant before every wave, reporting the same item codes as a live rollout; a stuck `dispatching` item halts it and frees the tenant's rollout slot. Farmer's handling of a repeated `job_id` checked: harmless on its own; the one race (a late provision copy against a deprovision) is mitigated in saasapi by `DELETE` waiting out a re-published provision job, with the `internal/pki` fix left open (out of scope; Open items, 6). Tested with sqlite and against MySQL 8. FLAG FOR SECURITY REVIEW | merged — PR #63 (`abca45d`) |
| REL.1 GoReleaser OSS and a `wixl` MSI hook | The release no longer needs GoReleaser Pro or `GORELEASER_KEY`. `packaging/windows/build-msi.sh` (version, binary and tool checks; refuses to leave a partial MSI) renders the `.wxs`, runs `wixl -a x64` and `msi-postprocess.sh`; a post hook on the `sprout-windows-pkg` build calls it; the MSI is in `checksum.extra_files` and `release.extra_files`, so both signatures (gpg and keyless cosign) cover it. Added `checksum.name_template: checksums.txt` (GoReleaser's default name is `imas_<version>_checksums.txt`, which `publish-packages.yml` would not have found). New secret-free `goreleaser-check.yml` runs a snapshot on pull requests and checks that `dist` has exactly one MSI that `checksums.txt` lists once. The MSI's tables match a build from the parent commit apart from the always-new ProductCode and PackageCode; it is not byte-reproducible (those GUIDs and a wixl build timestamp), though the cabinet is. `test-windows-packaging.sh` had been failing on `main` since FU.2 added `fleet-signing-keys.json` and now passes through `build-msi.sh`. Oldest supported Windows is Server 2016 (Windows Installer 5.0; no winget there, Ansible `win_package` installs the MSI). Not compared against a real Pro `msi` build, and no Windows host has installed the MSI. FLAG FOR SECURITY REVIEW | merged — PR #64 (`579c830`) |
| REL.1 follow-up: `snapshot.yml` keyless signing | `snapshot.yml` gets `id-token: write`, `cosign-installer`, QEMU and Buildx so the snapshot's cosign `signs` entry can run (it signs under snapshot.yml's own identity, which `publish-packages.yml` rejects, and writes a public Rekor entry). The workflow has never run: the OIDC-to-Rekor path and the image builds are untested. FLAG FOR SECURITY REVIEW | merged — PR #65 (`ecc18f3`) |
| CL.2a Official OpenBao client, server side | New `internal/openbao` on `github.com/openbao/openbao/api/v2` v2.7.1 (MPL-2.0, unmodified): static-token and kubernetes auth, re-login at 80% of the lease, CA bundle, 30 s timeout, no retries, optional `<prefix>NAMESPACE`, never `BAO_*`/`VAULT_*`. `internal/openbaokv`, `fleetsign`, `gatewayjwt`, `certs`, `pki` (tenant box keys) and `cmd/fleetreleaser` now use it, with their variables, defaults, methods and errors unchanged; six copies of the HTTP code removed. Deliberate differences: the environment proxy is honoured even with a CA bundle, at most one redirect (never https to http), HTTP/2 always, an extra `X-Vault-Request` header, a malformed address fails at construction (fleetreleaser exits 2, not 1). Two bugs found and fixed on the way (a refused login's status read as the request's; HTTP/2 lost with a CA bundle). Also fixed, outside the brief's scope and at the owner's request: a flaky `TestUpdateManifestRoute_NoURLInResponse` (its check matched random signature bytes) and both CodeQL workflows now build Go by hand so the third-party copies under `dependencies/` stay out of the scan. FLAG FOR SECURITY REVIEW | merged — PR #66 (`7cd586d`) |
| CL.2b Official OpenBao client, sprout side | `internal/ingredients/sdb/openbao` calls the same client directly (customer client certificate, hot-reloaded; cached login token renewed at 90%; `sdb://openbao/<mount>/<path>[#field]` and the KV v2 then v1 read unchanged). Changed: the environment proxy now applies, error strings no longer quote non-JSON bodies, a 403 drops the cached token, numbers read back as written, one redirect at most. Tested against OpenBao 2.4.1 and Vault 1.20.4 (cert rotation under a running provider over HTTP/1.1 and HTTP/2) with `TestRealServer`, which CI does not run. The sprout grew by 1.74 MiB (linux/amd64) and 1.78 MiB (windows/amd64), not the little expected. FLAG FOR SECURITY REVIEW | merged — PR #67 (`1419c18`) |
| FU.5 Helm release hook | `sprout-release-register-job.yaml` (post-install/post-upgrade) runs `farmer register-sprout-release`; `min_sprout_version` stamped at release time (`packaging/helm/`) | merged — PR #55 (`6815306`) |
| FU.6 Rollout gates | Health-gated waves (a sprout counts when it reports the new version), one rollout per tenant, per-sprout OS/arch/package-type resolution, sprouts report their release as the `sprout_version` fact | merged — PR #57 (`ec21992`) |
| FU.6b Gate freshness | Gate counts only reports written after dispatch; dedicated `rollout_claimed_at` column (migration 00005). FLAG FOR SECURITY REVIEW | merged — PR #58 (`507554d`) |

**Fleet update dispatch is still off by default.**
`SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED` stays `false`, and since SEC.5 so does
farmer's own `IMAS_SELF_UPDATE_ENABLED`: the code path is complete and
unit/e2e tested on Linux, and the fixes both read-only reviews asked for
before dispatch are merged, but no human security review is recorded, it has
never run on real hosts, and the Windows install path has only been tested
with `msiexec` mocked. Turn both on only after the steps in Open item 4. Known
leftovers from this work:

- **Dead live-key-set path: removed by CL.1** (see the table above), and
  `fleetsign`'s JWKS encoding and `JWKSHandler` deleted by CL.4 (PR #71).
  Sprouts enrolled before CL.1 keep the unused
  `imas.sprouts.<id>.fleetsigningkeys` Publish grant until their User JWT is
  next re-minted; nothing subscribes to it any more (Open item 10).
- **Farmer's real dispatch path in the e2e test.** `testing/selfupdate-e2e`
  uses the Molecule stub farmer, not `internal/natsapi`.
- FU.6 open question 1 (targets created before FU.6) is not needed
  pre-production; question 4 (`facts.request`) is deferred.
- **Outbox sweeper: built by CL.3** (see the table above). The
  `internal/pki` provision/deprovision race it exposed is fixed by PKI.1
  (PR #74, #77), and saasapi's `DELETE` no longer waits it out (Open items,
  6). The CL.3 row above is the record as merged. See
  `docs/design/imas-internal-api-account.md`.

Decided 2026-09-29: `helm rollback` leaves the sprout release registered
(withdrawn only by explicit revoke); one `cmd/migrate` binary; sprout
private-repo token is Linux only for now, as in the Ansible role. Atlas was
considered; goose chosen (MIT).

**Licensing follow-through.** MPL-2.0 is accepted generally (requirement 21)
and `CLAUDE.md` now says so (PR #41). CL.2a (merged, PR #66, FLAG FOR
SECURITY REVIEW) acts on the decision to use the official OpenBao Go client
for every server-side identity: `internal/openbao` builds
`github.com/openbao/openbao/api/v2` (MPL-2.0) from each identity's own
`IMAS_*_OPENBAO_*` block (never `BAO_*`/`VAULT_*`) and owns static-token and
kubernetes auth, re-login before 80% of the lease, the CA bundle, the 30 s
timeout with no retries, and an optional `<prefix>NAMESPACE`.
`internal/openbaokv`, `internal/fleetsign`, `internal/gatewayjwt`,
`internal/certs`, `internal/pki` (tenant box keys) and `cmd/fleetreleaser`
use it; their variable names, defaults, HTTP methods and errors are
unchanged. CL.2b (merged, PR #67, FLAG FOR SECURITY REVIEW) moves
`internal/ingredients/sdb/openbao`, the sprout's `sdb://openbao` provider,
onto the same client directly rather than through `internal/openbao`, whose
identities are configured from `IMAS_*_OPENBAO_*` blocks and authenticate
with a static token or kubernetes auth; the sprout's provider uses the
customer's client certificate against the customer's own server. Kept: the
`IMAS_SDB_OPENBAO_*` variables, the `sdb://openbao/<mount>/<path>[#field]`
syntax with its KV v2 then KV v1 read, the hot-reloaded client certificate
(`sdb.CertWatcher`, keep-alives off) and a cached login token (now
`sdb.TokenCache`, renewed at 90% of the lease as before), no retries, a 30 s
timeout, and no `BAO_*`/`VAULT_*` variable read. Changed: the provider now
honours `HTTP(S)_PROXY`/`NO_PROXY` (`ProxyFromEnvironment`), which it did
not before; errors no longer quote a response body that isn't OpenBao's JSON
(a proxy error page could echo the request and its token); a 403 drops the
cached token so the next read logs in again; a number in a secret reads back
as written (`1.0` stays `1.0`); the client follows one redirect, never
https to http, where `net/http` had followed up to ten. Decided on review
(2026-10-03): the environment proxy is always respected and is assumed to
allow every URL a sprout needs (cloud metadata included); `busproxyurl` is
for the bus connection only; the single redirect stays, as the Vault CLI
does. Tested against OpenBao 2.4.1 and HashiCorp
Vault 1.20.4 dev servers on TLS (cert auth, KV v2 and v1, a client
certificate rotated under the running provider);
`TestRealServer` in that package runs it when `IMAS_TEST_SDB_OPENBAO_*` is
set. The sprout grows by 1.74 MiB (linux/amd64, 30,990,943 → 32,812,111
bytes) and 1.78 MiB (windows/amd64, 25,717,760 → 27,588,096), within the
5 MB limit: before CL.2b the sprout linked little of the client, and the
request path brings `golang.org/x/net/http2`, `go-retryablehttp` and both
`mapstructure` modules into the binary (no new modules). More MPL-2.0 code
now ships in the customer-distributed sprout binary than before; the
obligations are the same as for the part that already shipped
(`DEPENDENCIES.md`).

## Open-item briefs and Wave 7 (merged 2026-10-03 to 2026-10-05)

The open-item briefs were dispatched from this file's Open items on
2026-10-03 and 2026-10-04 and are not written up in
`docs/claude-code-parallel-build-plan.md`. Wave 7 is plan §4e (security fixes
and sealing, from `docs/security-review-2026-10.md` and the two sealing
designs), §4f (follow-ups to `docs/security-review-2026-10-b.md`) and §4g
(validation fixes). Every item below is merged and green in CI on `main`.
"Flagged" means the PR carries "FLAG FOR SECURITY REVIEW"; none of them has had
the human review this file asks for (Open item 4), so each stays "ready for
review". Two different briefs were both named CL.4: PR #71 (OpenBao and
fleetsign clean-up) and PR #103 (the J.3 clean-up); this file names each with
its PR.

| Item | What shipped | Status |
|---|---|---|
| DOC.1 | `requirements.md` item 15 reworded to the built design; README Quick Start and Architecture; `docs/INSTALL.md` "Proxies and `NO_PROXY`"; OpenBao `*_NAMESPACE` variables in the chart READMEs; `fleet_signing_jwks` out of the architecture diagram | merged, PR #69 |
| J designs | "Sealing `shell.*`" and "Sealing the control plane" in `docs/design/imas-payload-encryption-design.md`; flagged | merged, PR #70; built by J.1 to J.5 |
| CL.4 (PR #71) | `fleetsign`'s dead JWKS code deleted; `sdb://openbao` read errors name every path tried; `.github/workflows/sdb-openbao-realserver.yml` runs `TestRealServer` against OpenBao v2.7.1 | merged, PR #71 |
| SCALE.1 | Full-jitter exponential backoff for sprout bus reconnects (`internal/natsretry`, `busreconnectbase`, `busreconnectcap`, Ansible variables) | merged, PR #72 |
| LIC.1 | `go-licenses` v2.0.1 with a PR check and a push-only save; `dependencies/` regenerated; `DEPENDENCIES.md` lists every non-Apache/MIT module | merged, PR #73 |
| PKI.1 | Provision/deprovision race closed in `internal/pki` (post-push re-check, mark before lockout, tombstones; then the Account re-read after the mark); saasapi's 409 wait removed; flagged | merged, PR #74, #77 |
| REL.2 | Release before hook checks tidiness instead of tidying; `snapshot.yml` unsigned and secret-free; release assets and `GORELEASER_CURRENT_TAG` fixed; First release checklist in `docs/RELEASING.md` | merged, PR #75 |
| SCALE.2 | Clustered `farmerbus` with authenticated routes and a fail-closed fence; then the bus mints no Account JWTs and core pushes them all on connect (`pki.ConfigureBusNats`, `pki.PushAllAccounts`); flagged | merged, PR #76, #78 |
| PKI.2 | Every JWT and seed written atomically, so a mid-write read can't re-mint an Account without its revocations; flagged | merged, PR #79 |
| SCALE.3 | Load and latency harness `tools/loadtest`, `docs/loadtest.md`, CI smoke run (`loadtest-smoke.yml`); `busmaxconnections` / chart `bus.maxConnections` | merged, PR #80 |
| SEC.1 | First read-only security review, `docs/security-review-2026-10.md` (4 High, 8 Medium, 25 Low, 12 Info) | merged, PR #81 |
| SEC.0 | CLI token expiry cap and raw OpenBao error bodies dropped (review M7); the token cap was superseded by J.3, which deleted tokens; flagged | merged, PR #83 |
| SEC.4 | Facts stored under the subject's sprout (H2); recipe templates sandboxed and values substituted as data (M8); per-tenant recipes; flagged | merged, PR #84 |
| SEC.3a | Deleted or replaced sprouts revoked (`pki_revoked_nkeys`, farmer migration 00002), one active box key per sprout, no dotted sprout IDs, the legacy shared tenant keypair deleted (H1, M3, M4, H3 in part); flagged | merged, PR #85 |
| SEC.5 | Package bound to the signed version, `--refuse-downgrade`, farmer's `IMAS_SELF_UPDATE_ENABLED`, redacted redirect URLs, rollout re-checks the tenant, per-tenant dispatch pools (M1, L1, L2, L8, M5); pre-release refused on Windows; flagged | merged, PR #86, #88 |
| SEC.3b | Tenant and recipient key in every sealed message, proof of possession of `sprout_pub`, replay guard across restarts, no opened bodies in logs (H3, M2, H4); flagged | merged, PR #87 |
| REC.1 | Tenant recipe upload, list, read and delete in saasapi (`internal/saasapi/recipes.go`) with its own object-store credential; unclean request paths refused with 400 (`RejectUncleanPaths`); flagged | merged, PR #89, #90 |
| SEC.5b | Farmer reads each tenant's rollout window (`fleetcatalog.RolloutWindow`, one rule `RolloutWindowClosed` shared with saasapi); flagged | merged, PR #92 |
| J.1 | Control-plane sealing building blocks; users store moved to the farmer database (`auth_users`, `auth_cli_box_keys`, migration `farmer/00003`); platform and SaaS API box keys; flagged | merged, PR #93 |
| J.2 | Sealed sprout refresh (`s2f.refresh`/`f2s.refresh`); no gateway JWT for an NKey proof alone; flagged | merged, PR #94 |
| J.3 | Sealed CLI to farmer API (`c2f.api`/`f2c.api`), bearer tokens deleted; then the `dangerously_allow_root` bypass removed from HTTP too; flagged | merged, PR #95, #96 |
| J.4 | Sealed `internal.*` between the SaaS API and farmer (`a2f`/`f2a`); then the Helm wiring for saasapi's box key (`imas-saasapi-box`, keygen Job on by default); flagged | merged, PR #97, #99 |
| J.5 | `shell.*` sealed end to end, farmer relaying both legs; flagged | merged, PR #98 |
| SEC.6 | Second read-only security review, `docs/security-review-2026-10-b.md` (3 High, 3 Medium, 3 Low, 6 Info) | merged, PR #100 |
| SH.1 | Built-in `operator` role loses `shell` (B7); farmer ends shell sessions with `farmer-shutdown` on stop; sealed-shell user docs; flagged | merged, PR #102 |
| CL.4 (PR #103) | Dead HTTP recipe routes and `internal/audit`'s token resolver removed; `imas serve`'s add-user requires `boxpub`; flagged | merged, PR #103 |
| SEC.7c | `/files/` and `/v1/sprout/update-manifest` refuse a revoked or superseded NKey's gateway JWT (`pki.VerifyGatewaySubject`, B3); flagged | merged, PR #104 |
| OPS.1 | saasapi NetworkPolicy and PDB re-checked after J.4 and REC.1: a saasapi object-store egress rule (`networkPolicy.external.objectStore`), nothing else needed; flagged | merged, PR #105 |
| T.1 | Flaky `TestRefresh_AnswersOnlySealed` fixed (it matched `eyJ` in random ciphertext) | merged, PR #106 |
| SEC.7a | Staged recipe sealed by farmer (`f2s.staged`) and verified by the sprout before cooking (B1, B9); flagged | merged, PR #107 |
| SEC.7b | A first box key only with the `enroll_binding` from the identity-issuing request; a keyless accepted sprout is closed and must re-enroll (B2); flagged | merged, PR #108 |
| SEC.7d | Staged recipe clock skew tolerance, `stagedrecipeclockskew` (default 1m, cap 5m); the 5-minute enroll binding kept (owner decisions, 2026-10-05); flagged | merged, PR #110 |
| FIX.2 | Job objects keyed `jobs/<tenant_id>/<sprout_id>/<jid>/...` (review B, I4); flagged | merged, PR #111 |
| FIX.3 | Helm fresh-install gaps: farmer object store egress, required bootstrap admin, saasapi's recipe credential self-check (`SAASAPI_RECIPES_CREDENTIAL_CHECK`, on by default); flagged | merged, PR #112 |
| FIX.1 | Plaintext `cmd.run` and `cook` path deleted: farmer refuses a keyless sprout with `sprout_reenroll_required`, a keyless sprout refuses with `no-keys`; flagged | merged, PR #113 |

Docs-only PRs in the same window: #68 (this file's RAG summary), #82 (plan
§4e, Wave 7 briefs), #91 (the SEC.5b brief), #101 (plan §4f) and #109 (plan
§4g and the dispatcher prompt).

## Azure UAT gate briefs (plan §4h)

| Item | What shipped | Status |
|---|---|---|
| UAT.3b | `uat/hub/core`: installs the published `farmer` chart of a `release_tag` on the uat-core cluster (PXC, Valkey and standalone OpenBao, one replica each) plus UAT-only MinIO (AGPL-3.0, test only), Keycloak (dev mode, embedded H2) with the `imas-uat` realm (two tenants, admin and read-only users, `organization.id` from a user attribute set by `bind-tenant.sh`), an Envoy edge on the core FQDN, the cross-cluster bus Service and NetworkPolicies; generated secrets, `nk` seeds, the release CLI's bootstrap admin, OpenBao init/unseal with the ed25519 gateway key (**UAT only: unseal keys in a Secret and a sensitive artifact**); `check.sh`. Owner decisions 2026-10-06 applied: the DMZ bus on node port 8442, hostPorts 443 and 5405 on core, a sensitive `keycloak.json` (with `tenant_attribute`) next to `core.json` and `credentials.json`, a `bind-tenant.sh --scratch-user` mode for tenants created during a run (no admin API on the edge), the bus reached by the private name `dmz.uat.imas.internal` and `core.uat.imas.internal` on farmer's certificate, and no core node port mode; flagged | ready for review, PR #132; never run against a cluster (static checks, chart renders, and the OpenBao bootstrap against a local OpenBao only) |
| UAT.2 | `uat/k0s`. `bootstrap.sh` renders one k0sctl file per hub from the uat JSON and `access.json`: role `single`, SSH through the Bastion tunnel on 127.0.0.1 with a per-run `known_hosts`, `127.0.0.1` in the API certificate's SANs, and a CoreDNS `hosts` block (a k0s component patch) mapping the core and DMZ FQDNs to their private IPs. It then installs k0s on both hubs, fetches each kubeconfig with the tunnel's address, and waits for the node to be Ready. It adds local-path-provisioner as the default StorageClass and cert-manager, from checksum-pinned manifests. It creates one per-run self-signed UAT CA on both hubs as ClusterIssuer `imas-uat-ca` and writes `uat-ca.crt` and `endpoints.json`. All versions are in `versions.env`. Exposure follows the owner decisions of 2026-10-06: the DMZ's Envoy (node port 8443, NodePort or LoadBalancer) and bus (node port 8442) Services belong to UAT.3a, with the DMZ NodePort range 8442-8443 only; core 443 and 5405 are hostPorts on UAT.3b's edge, with no core node ports and the core range 30000-32767. uat/k0s creates no exposure Service. `check.sh` reports and fails on an unready node, no default StorageClass, cert-manager unavailable, the issuer not Ready, a missing CoreDNS line, or a node port or hostPort the hub does not expose. Ran: shellcheck, yamllint, and 212 stubbed bash tests (`uat/k0s/tests/run.sh`); `k0s config validate` and k0sctl's config parser on the rendered files, by hand. Never run against a node. busybox (local-path's helper image, GPL-2.0) is recorded as a UAT-only exception pending owner confirmation. Open: the bus node port 8442 in farmer's `farmerbusurl` (UAT.3b). | ready for review |
| UAT.5 | Acceptance suite under `uat/tests` (build tag `uat`): T1 to T6, K1 to K4, S1 to S6, C1 to C8, R1 to R6, X1 to X5 (core, smoke ones `TestSmoke*`), L1 to L3 (resilience); `uat/tests/harness` (API client, Keycloak tokens and scratch users, `vmctl.sh` wrapper, synthetic sprouts for `/v1/enroll`, batches, cooks, host checks), reused by UAT.7; `run.sh` with a per id/OS/tenant summary, JUnit and the no silent green rule (`uatreport`, `catalogue.tsv` kept equal to the plan's table by a test); an in-memory fake stack the whole catalogue runs green against (plumbing only). Reads uat/hub/core's `core.json`, `credentials.json` and `keycloak.json` and checks tenants 1 and 2 are bound (UAT.4 binds them), per the owner's decisions of 2026-10-06; T1, T4 and T5 make users for their own tenants with `bind-tenant.sh --scratch-user` (PR #132). Never run against a deployment. Written skips: T3, part of T4/T5/T6, S6 on Windows and after a purge, X5. API gap: no saasapi route to delete or revoke a sprout; no scratch-user delete, accepted by the owner | PR #134, ready for review |
| UAT.7 | Ingredient conformance and lifecycle (`uat/cases`, `uat/tests/ingredients`). The registry is read from the source per GOOS (cmd/sprout's imports, `RegisterAllMethods`, `Methods()`, `PropertiesForMethod()`), and `uat/cases/INVENTORY.md` is generated from it: 100 methods in 32 ingredients (46 on both platforms, 22 Linux only, 32 Windows only). There are 108 case files (100 methods, plus 4 `win_dacl` and 4 `sdb` backends): 178 of 214 (method, OS) pairs run, and 36 are written skips. `TestCoverage` in `go test ./...` fails on a registered method with neither a case nor a skip. `TestIngredients` gives one subtest per case and sprout: test mode, a real cook, test mode again, a second real cook (changes and idempotency read from the sprout's job log), an out of band check and a revert. Sprouts run in parallel and each runs its cases in order. A tenant 2 subset of 4 cases also checks the change didn't reach tenant 1's same-sproutid host. L4 is a package downgrade to `upgrade_from_tag` followed by an upgrade, keeping the config and sproutid. L5 is one self update, opt in through `IMAS_UAT_DISPATCH_FLAGS`. Findings from the code: `win_dacl` isn't imported by `cmd/sprout`; no `database/sql` driver is linked into the sprout; test mode results drop `Changed`; `file.PropertiesForMethod` switches on the receiver. Unit tests use a fake registry and a fake sprout. No case has run on a real sprout | ready for review |

## Docs, CI and tooling merged alongside

| Item | Status |
|---|---|
| GitHub Pages site (`docs-site/`, mdBook): per-ingredient reference generated from source by `tools/gendocs`, architecture and SaaS API chapters; `docs.yml` deploys on push to `main` | merged — PR #36, #37 |
| Requirements, API design, BUILD-STATUS and `CLAUDE.md` rewritten for sprout repo updates and the MPL-2.0 exception | merged — PR #38–#42 |
| CI: goimports check skips `dependencies/`; dependency licence files refreshed | merged — PR #47 |
| J follow-up: box-key round-trip test no longer deadlocks on sqlite | merged — PR #50 |
| `go-licenses.yml`: a check job on pull requests and pushes, a save job on push only, v2.0.1 pinned, three build targets | merged — PR #73 (LIC.1) |
| CI lint checks `go.mod` and `go.sum` are tidy, as the release's before hook now does | merged — PR #75 (REL.2) |
| `sdb-openbao-realserver.yml`: `TestRealServer` against an OpenBao v2.7.1 dev server on TLS, on changes to `internal/ingredients/sdb/**` | merged — PR #71 (CL.4) |
| `loadtest-smoke.yml`: the load harness's smoke mode on changes to `tools/loadtest/**` | merged — PR #80 (SCALE.3) |
| `.gitleaks.toml`: one allowlist entry for a test object path in FIX.3's history (`2569cbe`) | merged — PR #112 (FIX.3) |

## Merged pull requests, 2026-09-28 to 2026-10-05

Every PR merged to `main` in this window (#36 to #122; #54 and #119 were not
merged, and #119 was reopened as #120), so this file can be checked against
the repository's history. From #68 on, each
row starts with its brief ID ("docs" for a docs-only PR).

| PR | Merged | What | Recorded in |
|---|---|---|---|
| #36, #37 | 09-28, 09-29 | Ingredient reference generator, mdBook site, architecture and SaaS API chapters | Docs, CI and tooling |
| #38 to #42 | 09-29 | Requirements 20 and 21, sprout updates from the configured repo, `CLAUDE.md` licensing exceptions, confirmed decisions | Docs, CI and tooling; Fleet updates |
| #43, #44 | 10-01 | Release flow (GHCR-only signed images, Buildkite packages and charts), Wave 4 briefs, `RELEASING.md` | Release flow row |
| #45 | 10-02 | FU.0 signed URL-free manifest | FU.0 |
| #46, #48 | 10-02 | DB.1 goose migrations, DB.2 hook Job and `imas-migrate` image | DB.1, DB.2 |
| #47 | 10-02 | CI: goimports check skips `dependencies/` | Docs, CI and tooling |
| #49, #56 | 10-02 | FU.3/FU.4 release signing and registration; operator plane in `cmd/saasapi` | FU.3 + FU.4 |
| #50 | 10-02 | Box-key round-trip test deadlock on sqlite | Docs, CI and tooling |
| #51, #52 | 10-02 | FU.1 farmer manifest endpoint, routed through Envoy | FU.1 |
| #53 | 10-02 | FU.2 sprout self-update and FU.7 farmer dispatch | FU.2, FU.7 |
| #55 | 10-02 | FU.5 Helm release hook | FU.5 |
| #57, #58 | 10-02 | FU.6 rollout waves, FU.6b gate freshness | FU.6, FU.6b |
| #59 | 10-02 | FU.6b brief | (docs only) |
| #60, #61 | 10-03 | BUILD-STATUS and design-doc refresh and re-evaluation | Notes; Re-evaluation |
| #62 | 10-03 | CL.1 remove the dead live fleet-key path | CL.1 |
| #63 | 10-03 | CL.3 outbox sweeper | CL.3 |
| #64, #65 | 10-03 | REL.1 GoReleaser OSS, `wixl` MSI hook; `snapshot.yml` keyless signing | REL.1 rows |
| #66 | 10-03 | CL.2a official OpenBao client, server side (plus the flaky-test and CodeQL fixes) | CL.2a; Licensing follow-through |
| #67 | 10-03 | CL.2b official OpenBao client in the sprout's `sdb://` provider | CL.2b; Licensing follow-through |
| #68 | 10-03 | **docs**: RAG summary for requirements, build plan and open items; ledger to #67 | RAG summary |
| #69 | 10-04 | **DOC.1**: Requirement 15 wording, README split, `NO_PROXY`, OpenBao namespaces, diagram | Open-item briefs and Wave 7; Open item 8 |
| #70 | 10-04 | **J designs**: Designs for sealing `shell.*` and the control plane | Open-item briefs and Wave 7; Open items 2, 11 |
| #71 | 10-04 | **CL.4 (first)**: Dead `fleetsign` JWKS code removed, clearer `sdb://openbao` read errors, `TestRealServer` in CI | Open-item briefs and Wave 7; Open item 10 |
| #72 | 10-04 | **SCALE.1**: Jittered exponential backoff for sprout bus reconnects | Open-item briefs and Wave 7; requirement 1; Open item 3 |
| #73 | 10-04 | **LIC.1**: `go-licenses` workflow fixed, `dependencies/` regenerated, non-Apache/MIT licences listed | Open-item briefs and Wave 7; requirement 21; Open item 5 |
| #74 | 10-04 | **PKI.1**: Provision/deprovision race closed in `internal/pki` | Open-item briefs and Wave 7; Open item 6 |
| #75 | 10-04 | **REL.2**: Release pipeline fixes from the REL.1 reviews, First release checklist | Open-item briefs and Wave 7; Open item 10 |
| #76 | 10-04 | **SCALE.2**: Clustered `farmerbus`, authenticated routes, fail-closed fence | Open-item briefs and Wave 7; requirement 1; Open item 3 |
| #77 | 10-04 | **PKI.1 follow-up**: Re-read the tenant row after marking it deleted | Open-item briefs and Wave 7; Open item 6 |
| #78 | 10-04 | **SCALE.2 follow-up**: The bus mints no Account JWTs; core pushes them all on connect | Open-item briefs and Wave 7; Open item 3 |
| #79 | 10-04 | **PKI.2**: Every JWT and seed written atomically | Open-item briefs and Wave 7; Open item 6 |
| #80 | 10-04 | **SCALE.3**: Load and latency harness `tools/loadtest` | Open-item briefs and Wave 7; requirements 1, 10; Open item 3 |
| #81 | 10-04 | **SEC.1**: First read-only security review (`docs/security-review-2026-10.md`) | Open-item briefs and Wave 7; Open item 4 |
| #82 | 10-04 | **docs**: Plan §4e: Wave 7 briefs, owner decisions of 2026-10-04 | Open items (decisions) |
| #83 | 10-04 | **SEC.0**: CLI token expiry cap, raw OpenBao error bodies dropped (M7) | Open-item briefs and Wave 7; Open items 4, 11 |
| #84 | 10-04 | **SEC.4**: Forged facts (H2), sandboxed recipe templates (M8), per-tenant recipes | Open-item briefs and Wave 7; Open items 4, 10 |
| #85 | 10-04 | **SEC.3a**: Deleted sprouts revoked, one active box key, no dotted sprout IDs, no shared tenant keypair | Open-item briefs and Wave 7; requirement 14; Open items 4, 10 |
| #86 | 10-04 | **SEC.5**: Fixes before fleet update dispatch (M1, L1, L2, L8, M5) | Open-item briefs and Wave 7; requirement 20; Open item 4 |
| #87 | 10-04 | **SEC.3b**: Tenant binding in sealed messages, replay after restart, cook logging (H3, M2, H4) | Open-item briefs and Wave 7; requirement 14; Open items 4, 10 |
| #88 | 10-04 | **SEC.5 follow-up**: Pre-release self-updates refused on Windows | Open-item briefs and Wave 7; requirement 20; Open item 4 |
| #89 | 10-04 | **REC.1 (split)**: Unclean request paths refused with 400 instead of a redirect | Open-item briefs and Wave 7; Open item 10 |
| #90 | 10-04 | **REC.1**: Tenant recipe upload, list, read and delete through the SaaS API | Open-item briefs and Wave 7; Open items 1, 10 |
| #91 | 10-04 | **docs**: The SEC.5b brief added to plan §4e | (docs only) |
| #92 | 10-04 | **SEC.5b**: Farmer reads each tenant's rollout window | Open-item briefs and Wave 7; requirement 20; Open item 4 |
| #93 | 10-04 | **J.1**: Control-plane sealing building blocks; users store in the farmer database | Open-item briefs and Wave 7; Open item 11 |
| #94 | 10-04 | **J.2**: Sealed sprout refresh; no gateway JWT for an NKey proof alone | Open-item briefs and Wave 7; Open item 11 |
| #95 | 10-04 | **J.3**: Sealed CLI to farmer API, bearer tokens removed | Open-item briefs and Wave 7; Open item 11 |
| #96 | 10-04 | **J.3 follow-up**: `dangerously_allow_root` HTTP bypass and the flag removed | Open-item briefs and Wave 7; Open item 11 |
| #97 | 10-04 | **J.4**: Sealed SaaS API to farmer `internal.*` | Open-item briefs and Wave 7; Open item 11 |
| #98 | 10-04 | **J.5**: `shell.*` sealed end to end, farmer relaying both legs | Open-item briefs and Wave 7; requirement 14; Open item 2 |
| #99 | 10-04 | **J.4 follow-up**: Helm wiring for the SaaS API box key | Open-item briefs and Wave 7; Open item 11 |
| #100 | 10-04 | **SEC.6**: Second read-only security review (`docs/security-review-2026-10-b.md`) | Open-item briefs and Wave 7; Open item 4 |
| #101 | 10-05 | **docs**: Plan §4f: post-SEC.6 follow-up briefs | (docs only) |
| #102 | 10-05 | **SH.1**: `operator` loses `shell`, `farmer-shutdown` on stop, sealed-shell user docs | Open-item briefs and Wave 7; Open item 2 |
| #103 | 10-05 | **CL.4 (second)**: Dead HTTP recipe routes and audit token resolver removed; `boxpub` in `imas serve` add-user | Open-item briefs and Wave 7; Open items 10, 11 |
| #104 | 10-05 | **SEC.7c**: Revoked or superseded NKeys' gateway JWTs refused (B3) | Open-item briefs and Wave 7; requirement 14; Open items 4, 10 |
| #105 | 10-05 | **OPS.1**: saasapi NetworkPolicy and PDB after J.4 and REC.1 | Open-item briefs and Wave 7; Open item 11 |
| #106 | 10-05 | **T.1**: Flaky `TestRefresh_AnswersOnlySealed` fixed | Open-item briefs and Wave 7 |
| #107 | 10-05 | **SEC.7a**: Staged recipe sealed and verified before cooking (B1, B9) | Open-item briefs and Wave 7; requirement 14; Open items 4, 10 |
| #108 | 10-05 | **SEC.7b**: First box key bound to the identity-issuing enrollment (B2) | Open-item briefs and Wave 7; requirement 14; Open items 4, 10 |
| #109 | 10-05 | **docs**: Plan §4g: validation fix briefs FIX.1 to FIX.4, dispatcher prompt | Validation, 2026-10-05 |
| #110 | 10-05 | **SEC.7d**: Staged recipe clock skew tolerance; 5-minute enroll binding kept | Open-item briefs and Wave 7; Open item 10 |
| #111 | 10-05 | **FIX.2**: Job objects keyed on `(tenant_id, sprout_id)` (I4) | Open-item briefs and Wave 7; Open items 4, 10 |
| #112 | 10-05 | **FIX.3**: Helm fresh-install gaps: farmer object store egress, required bootstrap admin, recipe credential self-check | Open-item briefs and Wave 7; requirement 13; Open item 10 |
| #113 | 10-05 | **FIX.1**: `cmd.run` and `cook` refused to sprouts with no box key; plaintext path deleted | Open-item briefs and Wave 7; requirement 14; Open item 10 |
| #114 | 10-05 | **FIX.4**: This file brought up to `main` at `7fb527a` (PRs #68 to #113) | Validation, 2026-10-05 |
| #115 | 10-05 | **docs**: Release GPG public key committed; `SECURITY.md` fingerprint fixed | Validation, 2026-10-05 (first release prerequisite 1) |
| #116 | 10-05 | **docs**: Plan §4g: the FIX.5 brief (release blockers from the 2026-10-05 re-validation) | this ledger |
| #117 | 10-05 | **FIX.5**: Helm lint with CI values and Chart.lock repositories in the publish workflow; chart tests required to run in CI (`IMAS_REQUIRE_HELM=1`); keyless sprout items recorded as `sprout_reenroll_required`; recipe credential check probes the platform recipe prefix and the job bucket; security review and this file's marks updated. Flagged for security review | Validation, 2026-10-05; Open items 4, 10 |
| #118 | 10-05 | **FIX.1** follow-up: `cmd.run` errors carried as text, so the CLI shows farmer's refusal; `imas cmd run` exits 1 when the command failed on any target. Flagged for security review | Open item 10 |
| #120 | 10-05 | **FIX.5 follow-up**: saasapi refuses to start without `SAASAPI_RECIPES_JOB_BUCKET` while `SAASAPI_RECIPES_CREDENTIAL_CHECK` is on (owner decision: strictly fail closed); chart README and `INSTALL.md` list the new probes and add `helm repo add` before `helm dependency build`. Flagged for security review | Validation, 2026-10-05; Open item 10 |
| #121 | 10-05 | **FIX.1** follow-up, docs: this file records #118's `cmd.run` error fix and what it left, including `Inline.Error` printing `"error":{}` in the CLI's `--output json` errors; #120 marked merged | Open item 10 |
| #122 | 10-05 | **FIX.1** follow-up: `apitypes.Inline` and `PingPong` errors carried as text, as #118 did for `CmdRun`, so the CLI's `--output json` errors (e.g. `imas keys`) print `"error":"<text>"` instead of `"error":{}` | Open item 10 |

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
  Docker), and the docs refresh itself (then in review, since merged as
  PR #23). Newly recorded as open,
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
- *Superseded: the unsealed `shell.*` this note describes was sealed by
  J.5 (PR #98).* **2026-09-27, later same day: `cook` sealing, sprout bus proxy support,
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
- **2026-10-05 refresh (FIX.4):** header, RAG summary, requirements rows,
  build plan, PR ledger (#68 to #113) and Open items brought up to `main` at
  `7fb527a`; the new "Open-item briefs and Wave 7" section lists every brief
  merged since PR #67. See "Validation, 2026-10-05" at the end.

## Open items (as of 2026-10-05, in priority order)

**Decisions, 2026-10-04.** The legacy shared tenant keypair adoption path is
deleted (review H3); revocation is enforced on farmer, not on the sprout (L4);
tenants write recipes and upload them through the SaaS API, so recipe
templates are untrusted input (M8 is a blocker); sealing (items 2 and 11) is
built before the Terraform UAT gate, sealed-only with no compatibility window
because nothing is deployed. Briefs: `docs/claude-code-parallel-build-plan.md`
§4e (Wave 7), §4f (post-SEC.6 follow-ups) and §4g (validation fixes); every
one has merged, FIX.5 last (PR #117) ("Open-item briefs and Wave 7").
**Decisions, 2026-10-05:** a staged recipe copy may be up to
`stagedrecipeclockskew` older than the newest handled job (SEC.7d, PR #110);
the enrollment binding stays at 5 minutes (SEC.7d); saasapi records FIX.1's
`sprout_reenroll_required` as `internal_error` for now (PR #113; since
FIX.5, PR #117, saasapi records and documents the code itself); the saasapi
binary defaults the recipe credential check to on, as the chart does (FIX.3,
PR #112).

1. **Terraform UAT gate: not started; the first release it needs has not
   been cut.** No Terraform exists in the repo (no `.tf` file on `main`). The
   gate is the release-quality check: provision VMs per OS, install the
   published packages with the Ansible role, smoke-test enrollment, a recipe
   run, reboot survival and one self-update cycle. It is the first thing that
   would run the Windows paths, the Helm charts and the Buildkite packages on
   real infrastructure. Brief: `docs/claude-code-parallel-build-plan.md` §4a.
   It needs a human decision on the compute provider before dispatch.
   - **Prerequisite: a first release.** The gate installs *published*
     packages, and none exist: no tag, no GitHub release, and neither
     `release.yml` nor `publish-packages.yml` has run. The pipeline is
     written and reviewed (REL.1, PR #64, #65; REL.2, PR #75) and
     `docs/RELEASING.md` has an 11-step First release checklist for
     `v0.1.0-rc.1`. The steps the owner still owes are listed in
     "Validation, 2026-10-05". A pre-release is skipped by
     `publish-packages.yml`, so it is published to Buildkite deliberately
     with `workflow_dispatch`. Nothing has installed the MSI on a Windows
     host yet (oldest supported: Windows Server 2016).
   - **Recipe upload (REC.1): merged (PR #90, #89; flagged).**
     `GET/PUT/DELETE /v1/tenants/{tenant_id}/recipes[/{name}]` (design doc
     §1.6, `docs/api/saasapi.md` "Recipes", `docs/INSTALL.md` "Upload a
     recipe"). For the gate to upload a recipe, the deployment needs
     saasapi's own object-store credential (`saasapi.recipes.*`, policy in
     `deploy/helm/farmer/files/objectstore-policies/saasapi-recipes.json`),
     which saasapi now checks at startup (FIX.3), and the Keycloak roles
     `imas-recipes-read` and `imas-recipes-write`.
   - **A fresh Helm install (FIX.3, merged, PR #112; flagged)** now needs a
     bootstrap admin (`farmer.bootstrapAdmin.pubkey` and `boxpub`, made
     offline with `imas auth pubkey` and `imas auth keygen`) or an explicit
     `farmer.bootstrapAdmin.skip`; farmer reaches the object store without
     `networkPolicy.farmerExtraEgress`; and NOTES warns when
     `imas-saasapi-nats` and `imas-saasapi-box` must be created by hand. The
     gate's values must set these.
2. **`shell.*` sealed: J.5 merged (PR #98), its follow-ups merged in SH.1
   (PR #102)** (requirement 14; both flagged, human review not held). Farmer
   relays with both legs sealed, as designed in "Sealing `shell.*`" in
   `docs/design/imas-payload-encryption-design.md`; "As built: J.5" there
   records what was built and where it departs from the text.
   - `imas ssh` seals `c2f.shell.open` with the CLI box key (J.3) to the
     tenant key it pins from explicit config.
   - Each leg is a `payloadbox` handshake, then a stream of numbered
     ChaCha20-Poly1305 frames under keys derived from ephemeral X25519
     (`internal/payloadbox/stream.go`). Every frame is accepted only in
     sequence, so a replayed, reordered, dropped or altered frame ends the
     session (`integrity`).
   - A sprout refuses a plaintext start, keys or not. A sprout with no box
     key is refused, never downgraded. Windows keeps refusing. There is no
     plaintext fallback anywhere. `sproutPermissions` grants
     `imas.shell.sprout.<id>.>`, tested on a live operator-mode bus.
   - Farmer re-checks the user's `shell` permission every 60 s, and
     `--sever` ends running sessions. The owner's answers (2026-10-04) are
     built: 15/60 min idle, 8 h maximum, `disableshell` default `false` in
     the Ansible role (`imas_sprout_disable_shell`), the `/etc/shells`
     allow-list, explicit pinning, no transcripts and no browser shell.
   - **SH.1:** the built-in `operator` role no longer grants `shell`
     (`internal/rbac/config.go`; review 2026-10-b B7); shell comes only from
     a role that names it, and `admin` keeps it (`docs/INSTALL.md`,
     "Interactive shell", says how to give an operator shell back). Farmer
     ends its sessions with `farmer-shutdown` when it stops
     (`natsapi.CloseShellSessions`, bounded at 5 s, before the tenant bus
     connections close; a session opened between the two still sees
     `peer-lost`). The user docs describe the sealed shell
     (`docs/INSTALL.md`, `docs/api/farmer-cli-api.md`, `README.md`,
     `ansible/README.md`).
   - **Owner decision, 2026-10-04 (PR #98):** no session recording; CERT-In
     and DPDP don't call for it, so v1 keeps only the audit entries at
     session start and end.
   - **Residuals (the design's Decision 3 table, checked by review 2026-10-b,
     I2):** denial of service, metadata and keystroke timing; farmer itself
     sees plaintext keystrokes (Decision 1). A sprout on a build older than
     J.5 would accept a plaintext start injected by the bus; nothing is
     deployed, so no such sprout exists.
3. **Scale and latency (requirements 1, 7, 10):** built, not measured. No
   load or chaos test has run beyond the harness's own smoke run.
   - **SCALE.1, jittered sprout reconnect (PR #72):** `cmd/sprout`
     reconnects with full-jitter exponential backoff (`internal/natsretry`,
     `busreconnectbase` 2 s and `busreconnectcap` 5 min by default) instead
     of a fixed 15 s wait. Reported in PR #72, not changed: farmer's
     per-tenant bus connection (`cmd/farmer/main.go`, `MaxReconnects(30)`,
     a fixed 15 s wait) is closed by nats.go after 30 failed reconnects
     (about 7.5 min of bus outage) and nothing redials it, so that tenant is
     unreachable from that replica until farmer restarts; and a sprout whose
     User JWT is refused twice stays offline until restarted.
   - **SCALE.3, the load and latency harness (PR #80):** `tools/loadtest`,
     manual in `docs/loadtest.md`. It opens N simulated sprout connections
     to a local one-node bus or to deployed nodes, and reports the connect
     rate and failures, the `test.ping` round trip at p50/p95/p99 against
     300 ms, the time to full reconnect and peak reconnect rate after a bus
     node restart, and bus and local process memory and CPU. Sprouts get
     fixture credentials minted from the operator signing and SYS account
     seeds in `internal/pki`'s shape, not enrollment; the docs list what that
     leaves untested (enrollment, Envoy and the websocket path, core). Its
     smoke mode (200 sprouts, local bus, one restart, generous thresholds)
     runs in CI on pull requests that touch the tool (`loadtest-smoke.yml`).
     Its first CI run (PR #80) passed in about 50 s: all 200 sprouts
     connected, every `test.ping` was answered before and after the
     restart, and all 200 reconnected after the bus was stopped for 2 s.
     That shows the harness and the reconnect path work; it is not a scale
     or latency result, and no run at 10k, 100k or 1M has been made. The
     harness does not kill PXC or Valkey nodes, which the scale plan's
     Phase 3 asks for. Writing it found that a bus node refused clients
     above 65,536 (nats-server's default `max_connections`); the limit is
     now `busmaxconnections`, the nats chart's `bus.maxConnections`
     (default 65,536). Raising it needs memory to match: the chart's default
     512Mi bus memory limit is reached at a few thousand connections.
   - **SCALE.2, the clustered bus (PR #76, #78; flagged, not yet reviewed
     by a human):** `cmd/farmerbus` reads `IMAS_BUS_CLUSTER_*`, routes need
     mutual TLS plus a route password and are confined to bus pods by their
     own NetworkPolicy, and a fence keeps a node that may hold stale claims
     from serving anyone. The chart sets `routesSupported` true, keeps
     `replicaCount: 1` by default and refuses 2. Tested in process only
     (three nodes, failover, lock-out while a node is down, partitioned, or
     on a partial mesh); never on a real cluster. The bus no longer mints
     its own legacy-tenant and SYS Account JWTs, and core pushes every
     Account whenever its SYS connection connects (PR #78). Left open (the
     first two in the chart README's "Clustering"): a push in the ~4 s before a partition
     is detected can miss a node until its next pull; core still pushes to
     one node, never waiting for every node to confirm; and the same-second
     `iat` tie (review M6, carried as 2026-10-b B5) is deferred past the UAT
     gate.
4. **Security review of the flagged work.** Two read-only code reviews have
   been written as input to the human security review. Neither replaces it,
   neither is a clean bill of health, and no human review is recorded here.
   **The human review is the first thing owed before
   `SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED` is turned on anywhere**, and its
   outcome (who, when, what it covered, what it accepted) belongs in this
   item.
   - **`docs/security-review-2026-10.md`** (SEC.1, PR #81), at `eacdc79`,
     covering FU.0, FU.2 to FU.4, FU.6, FU.6b, FU.7, CL.1 to CL.3, the J
     follow-ups, PKI.1 and SCALE.2: 4 High, 8 Medium, 25 Low, 12 Info. No
     code changed and no exploit was run.
   - **`docs/security-review-2026-10-b.md`** (SEC.6, PR #100), at `f645a93`,
     over everything merged since `eacdc79` (SEC.0 to SEC.5b, REC.1, J.1 to
     J.5): 3 High, 3 Medium, 3 Low, 6 Info. It re-checked the first
     review's findings and ran throwaway hostile-bus tests (deleted); `go
     test ./...` passed at that commit.

   **Where each finding stands on `main` at `7fb527a`** (fix merged and
   tested in CI; none human-reviewed). H, M and L are review 2026-10's IDs,
   B are review 2026-10-b's:

   | Finding | Status |
   |---|---|
   | H1 deleted or replaced sprout keeps its credentials | Fixed by SEC.3a (PR #85); its gateway JWT residue (B3) fixed by SEC.7c (PR #104) |
   | H2 facts stored under the body's `sprout_id` | Fixed by SEC.4 (PR #84); review B found the fix complete |
   | H3 no tenant binding; shared legacy keypair | Fixed by SEC.3a (keypair deleted) and SEC.3b (PR #87, `tid` and `rk` in every message); its enrollment residue (B2) fixed by SEC.7b (PR #108) |
   | H4 opened cook envelopes logged and shipped | Fixed by SEC.3b; review B found the fix complete |
   | M1 manifest version not bound to the package | Fixed by SEC.5 (PR #86) and PR #88 for deb and rpm; MSI residual open (B8) |
   | M2 replay after a sprout restart | Fixed by SEC.3b |
   | M3 box key submission under a grace key | Fixed by SEC.3a |
   | M4 dotted sprout IDs | Fixed by SEC.3a |
   | M5 one tenant starves the dispatch pools | Fixed by SEC.5 with a documented residual: several tenants together can still fill the `cmd.run`/`cook` pool |
   | M6 same-second Account JWT `iat` tie | **Open**, deferred past the UAT gate (plan §4e); carried as B5 |
   | M7 raw OpenBao bodies in errors | Fixed by SEC.0 (PR #83); confirmed by review B, I5 |
   | M8 recipe templates read farmer's environment | Fixed by SEC.4 (sandboxed templates, values as data) |
   | L1, L2, L8 | Fixed by SEC.5 (farmer's own switch; redacted redirect URLs; a live rollout re-checks the tenant) |
   | L4 revocation not enforced on the sprout | Decided (owner, 2026-10-04): stays on farmer, no sprout-side deny list |
   | L3, L5 to L7, L9 to L25, and review 2026-10's I1 to I12 | Deferred past the UAT gate by plan §4e. Some were touched by later work (L9's `cmd.run` output on `internal.*` is sealed since J.4, PR #97), but no review has re-checked them: status **UNCONFIRMED**. A pass over each against `main` would confirm it. |
   | B1 staged recipe cooked with no proof farmer made it | Fixed by SEC.7a (PR #107), with SEC.7d's skew tolerance (PR #110); the throwaway test is kept as `TestStagedSealed_ForgedPlainEnvelopeIsRefused` |
   | B2 keyless sprout accepts an attacker's box key | Fixed by SEC.7b (PR #108); residual: an attacker holding the join token who submits step 1 before the real sprout binds its own key (a visible failed enrollment, not a silent takeover) |
   | B3 old host's gateway JWT still reads `/files/` | Fixed by SEC.7c (PR #104); residual: Envoy can't see revocation, so the token still passes `jwt_authn` and costs farmer a lookup before the 403 |
   | B4 recipe render cost scales with the include count (Medium) | **Open.** No per-cook render budget; upload validation doesn't resolve includes. The review asks whether a budget is wanted before dispatch |
   | B5 same-second `iat` tie (Medium, M6 carried) | **Open**, deferred past the UAT gate |
   | B6 forged "no responders" re-runs an action (Medium) | **Open, accepted** residual (owner, PR #97); the fix would be at-most-once per action item on farmer |
   | B7 `operator` keeps `shell` | Fixed by SH.1 (PR #102) |
   | B8 MSI version binding is MAJOR.MINOR.PATCH only (Low) | **Open.** Mitigated by refusing pre-releases on Windows (PR #88); two release builds of one version are still indistinguishable by MSI metadata, and zypper's downgrade skip was read, not run |
   | B9 staleness was the only bound on a forged pull | Fixed with B1 by SEC.7a |
   | Review 2026-10-b I1 (sprout clock more than 5 min off refuses every farmer message), I2 (shell keystroke timing), I6 (an exotic error string could carry a URL past the redaction) | **Open** as notes; I1 and I2 are by design and recorded |
   | Review 2026-10-b I3, I5 | Confirmations that H2 and M7 are fixed |
   | Review 2026-10-b I4, job store keyed without the tenant | Fixed by FIX.2 (PR #111) |

   **Before `SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED` (and farmer's
   `IMAS_SELF_UPDATE_ENABLED`) is turned on:**
   1. Hold the human security review of the flagged work and record it
      here, including its answers to the reviews' open questions (B4's
      per-cook budget; confirming the B5 and B6 deferrals; `/files/` as a
      trust boundary now that SEC.7a seals it).
   2. Cut the first release and run the Terraform UAT gate's self-update
      cycle per OS against the published packages. That is also the first
      check of FU.2's index reader against the Buildkite registries (it was
      tested against Nexus), of the `+git` package version against the
      signed manifest, of zypper's downgrade skip, and of the MSI path on a
      real Windows host.
   3. Decide B8: carry the full version in an MSI property, or record the
      residual as accepted.
   4. Smaller, not blocking: move `self_update_disabled`,
      `rollout_window_closed` and `farmer_busy` into `internal/controlplane`
      and add `self_update_disabled` and `sprout_reenroll_required` to
      `docs/api/saasapi.md` and the OpenAPI item enum. FIX.5 (merged,
      PR #117) did this for `sprout_reenroll_required`;
      `self_update_disabled` is left, and saasapi still records it as
      `internal_error`.
5. **Licences (LIC.1, merged, PR #73).** CL.2a found the `go-licenses`
   workflow's `save` step failing on `main` (`modernc.org/mathutil` reported
   an unknown licence), so `dependencies/` was not refreshed after
   glebarez/sqlite arrived. LIC.1 pinned go-licenses v2.0.1, split the
   workflow into a check (pull requests and pushes) and a save (push only),
   and regenerated `dependencies/`. Both jobs have passed on every `main`
   push that ran them since, `7fb527a` included; the save found nothing to
   commit. Still open: recording BSD-2-Clause, BSD-3-Clause, ISC and 0BSD
   under requirement 21 (or dropping the modules), and PR #73's question
   whether the MPL-2.0 OpenBao client should be linked into the imas CLI.
   CL.2b added 1.74 MiB (linux/amd64) and 1.78 MiB (windows/amd64) to the
   sprout, not the "little" expected (see "Licensing follow-through").
6. **`internal/pki` provision/deprovision race (follow-up to CL.3): fixed by
   PKI.1 (PR #74, #77) and hardened by PKI.2 (PR #79); merged, flagged, human
   review not held.** With the outbox sweeper re-publishing a lost provision
   request, a late copy could still be running on one farmer replica while a
   deprovision of the same tenant ran on another, and push the tenant's live
   Account JWT after the locked-out one (the bus applies pushes in arrival
   order, whatever their `iat`). `ProvisionTenant` and
   `ReloadNKeysForTenant` now re-read the tenant's deleted state from the
   database after their push and push the lockout again if a deprovision
   won; `DeprovisionTenant` marks the row before signing the lockout, decides
   from the row re-read after the mark (PR #77), pushes a fresh lockout even
   when the row is already deleted, so a retry repairs the bus, and leaves a
   deleted tombstone for a tenant it finds no row for. Across replicas this
   needs no clock agreement, only that the re-check sees committed writes
   (one database, PXC through one node, or `wsrep_sync_wait`). Proven by
   hook-driven interleaving tests against a real bus
   (`internal/pki/tenant_race_test.go`), including one with the provision in
   a second process sharing the database. saasapi's `409
   provisioning_in_progress` wait is removed
   (`SAASAPI_OUTBOX_PROVISIONING_STALE_AFTER` stays, as the sweeper's
   backoff). PKI.2 writes every JWT and seed atomically, so a read during a
   rewrite can no longer re-mint an Account JWT without its revocations.
   Open questions from the PRs: set `wsrep_sync_wait=1` in farmer's DSN as
   hardening; require agreeing farmer clocks for a clustered bus; whether a
   failed post-push re-check should fail closed; refuse or warn on
   `clientFoundRows=true` in the DSN. See "Outbox re-dispatch sweeper" in
   `docs/design/imas-internal-api-account.md`.
7. **SaaS API §1.7** (caller API keys, teams, webhooks, billing/metering) has
   never been designed or started.
8. **Docs wording: closed by DOC.1 (PR #69).** `requirements.md` item 15 now
   says the sprout generates the new key pair and submits only the public
   key; `README.md`'s Quick Start and Architecture describe the DMZ and core
   split ("Batteries Included" already did).
9. **Nice-to-haves:** run the Keycloak JWKS harness somewhere with a Docker
   daemon; tenant key rotation has no scheduler inside farmer (run
   `imas keys rotate-tenant-key` from a CronJob); CERT-In/DPDP/data
   sovereignty review is still unowned.
10. **Leftovers and follow-ups from PR #62 to #113.** None blocks the first
    release. All the briefs named here are merged; what each left open:
    - **Release pipeline (REL.1, PR #64, #65; REL.2, PR #75):** REL.2 made
      the before hook fail on an untidy `go.mod`/`go.sum` instead of
      tidying (CI checks the same), made `snapshot.yml` build with
      `--skip=sign` and no secrets (owner's decision, 2026-10-03: signing is
      first exercised by the rc release), and fixed two first-release
      blockers: `release.ids` left the CLI archives and both
      `checksums.txt` signatures off the release, and a final tagged on its
      rc's commit would have been built as the rc (now pinned with
      `GORELEASER_CURRENT_TAG`; `release.yml` also refuses a non-tag ref).
      Still open: everything in the First release checklist (see
      "Validation, 2026-10-05"), including re-enabling `release.yml`'s tag
      trigger and the committed GPG public key; the nfpm packages carry a
      literal `+git` version suffix (`version_metadata: git`), which the
      sprout maps back to semver since SEC.5; fleetreleaser could check each
      row's checksum against the tag's signed `checksums.txt` (review M1,
      L7), which needs the committed key (or cosign verification) and either
      egress to the release or the operator uploading `checksums.txt` with
      the registration: not built. The OIDC-to-Rekor path, the image builds
      and `sha256sum --check` on a real release are untested; the MSI is not
      byte-reproducible. `docs/RELEASING.md` checklist step 4 still calls the
      `go-licenses` save a known failure on `main`; it passes since LIC.1.
    - **Enrollment and the stale grant (#62; CL.4, PR #71):** DOC.1 removed
      `fleet_signing_jwks` and `fleetsigningkeys` from
      `docs/diagrams/imas-architecture.svg`; CL.4 deleted `fleetsign`'s JWKS
      encoding and `JWKSHandler`. Sprouts enrolled before CL.1 keep the
      unused `fleetsigningkeys` Publish grant (nothing subscribes to that
      subject). Farmer re-mints a sprout's User JWT whenever its permissions
      differ from `sproutPermissions`, but only when a sync runs: for the
      legacy tenant every farmer start or SIGHUP, for a per-tenant Account
      only an enrollment, accept, unaccept, deny, reject, delete or
      provisioning in that tenant. The sprout uses a changed JWT only after
      a restart, and the old JWT stays valid (no expiry, not revoked). CL.4's
      suggestion, not built: run `syncTenantSprouts` for every provisioned
      tenant at farmer start.
    - **Deleted and replaced sprouts (SEC.3a, PR #85; SEC.7c, PR #104):**
      the old NKey goes on the tenant's revoked list (`pki_revoked_nkeys`,
      farmer migration 00002), its box keys are revoked in the same
      transaction, and farmer refuses its gateway JWT on `/files/` and
      `/v1/sprout/update-manifest` (`pki.VerifyGatewaySubject`, no cache,
      failing closed on a database error). Still open: User JWTs have no
      `exp`, so the revoked list (and each Account JWT's revocations) only
      grows; a deleted sprout's JWT file stays on farmer's disk (never
      served: refresh needs an accepted row); Envoy can't see revocation, so
      a retired host's unexpired gateway JWT still passes `jwt_authn` and
      costs farmer the lookup before the 403 (`gatewayjwtttl` stays 24h).
    - **Sealed payloads after FIX.1 (SEC.3b, PR #87; SEC.7a, PR #107;
      SEC.7b, PR #108; SEC.7d, PR #110; FIX.1, PRs #113, #118 and #122):** sealed only
      everywhere farmer talks to a sprout's commands. Farmer sends nothing
      to a sprout with no box key on record and fails `cmd.run`, the cook
      dispatch and the nudge with `sprout_reenroll_required` (saasapi stores
      the code itself since FIX.5, PR #117; before that it stored
      `internal_error`, owner decision); a sprout with no keys refuses
      everything with `no-keys`. A first box key needs the 5-minute
      `enroll_binding` (owner decision 2026-10-05 kept 5 minutes); after it
      a keyless accepted sprout is closed and must be deleted (`imas keys
      delete`) and enrolled again under a new NKey with a fresh join token.
      Nothing deletes closed sprouts automatically, and nothing regenerates
      a sprout's NKey. A staged copy is sealed (`f2s.staged`), and a sprout
      with no box key gets none, so a pull can't catch up its missed
      dispatches; not caught up either: a copy staged before a tenant key
      rotation, pulled after the sprout re-pinned (no previous pin is kept;
      PR #107 open question 1), or before a box key rotation, pulled more
      than `sproutboxkeyprevgrace` after it. Since SEC.7d a copy stamped up
      to `stagedrecipeclockskew` (default 1m, cap 5m) before the newest job
      handled is still cooked; accepted cost: an older captured job the
      sprout never ran can be cooked after a newer one within that window.
      The staged copy's size and key stay visible to anything that can read
      `/files/` for that sprout. Known plaintext residuals on the sprout's
      bus: the join event on `imas.sprouts.announce.<id>` (farmer only logs
      it), and `jobs.cancel`'s `{"jid"}` on `imas.sprouts.<id>.cancel`,
      which no sprout subscribes to, so cancel does nothing on the sprout
      although farmer answers `cancel request published`. Since PR #118
      (FIX.1 follow-up, flagged for security review), `apitypes.CmdRun` and
      `CmdCook` carry their errors as message text, or `null` for none
      (`internal/api/types/wireerror.go`). So `imas cmd run` shows farmer's
      `[sprout_reenroll_required]` refusal instead of `returned an invalid
      message!`, and farmer decodes a sprout's sealed reply that carries an
      error. A sprout-side error now travels as text inside the sealed
      `cmd.run` reply. On `internal.sprout.action` it reaches farmer's log
      and `auditTenantAction`, and it can name the command the caller sent.
      The object form older farmers and sprouts wrote decodes as an error
      whose message was lost. `imas cmd run` prints every target's result,
      then exits 1 if the command failed on any target (a non-zero exit
      code, an error from farmer or the sprout, or a result it can't read).
      Left by #118: an older CLI against a new farmer still prints
      `invalid message` for a result with an error (it never could decode
      one); other multi-target commands
      such as `imas cook` keep their exit status; open question whether a
      remote failure should exit 2 rather than 1. #118 also left
      `apitypes.PingPong.Error` and `Inline.Error` holding an `error`
      encoding/json wrote as `{}`; #118 said nothing sets them, but the CLI
      sets `Inline.Error` in `util.WriteJSONErr`, so `--output json` errors
      from `imas keys` printed `"error":{}`. Closed by PR #122: both now
      travel as their message text (`"error":"<text>"`), with the same
      legacy-object decoding. Deferred by FIX.1:
      a multi-sprout CLI cook only logs a keyless sprout's refusal on farmer
      (the CLI times out for it); `cmd.RegisterNatsConn` and its
      unused connection, and the routeless `HTestPing` handler, remain;
      `docs/design/imas-sprout-orchestration.md` ("As built: cook's wire
      format") still describes the removed plaintext fallback. Open from
      SEC.7b: the exported test seam `pki.UseInMemoryJoinToken`, and
      whether the proof should also carry the binding ID. Open from SEC.7d:
      whether an out-of-range `stagedrecipeclockskew` should stop the sprout
      instead of falling back to the default.
    - **Job store keys (FIX.2, PR #111; review 2026-10-b I4):** job objects
      are `jobs/<tenant_id>/<sprout_id>/<jid>/...`, built by one function
      (`jobKey` in `internal/jobs/store.go`) that refuses unsafe IDs; every
      read and list is per tenant (the tenant from the event's connection or
      the verified CLI caller, never a body field); `jobs.get` now needs view
      scope on the job's sprout; the CLI's local job store is per pinned
      tenant. Still open: looking a job up by JID alone lists the tenant's
      whole prefix (no JID index); the reaper still lists the whole bucket
      once an hour per replica; old-layout objects, if any exist, are never
      read or swept.
    - **Facts, recipe templates, per-tenant recipes (SEC.4, PR #84):** facts
      are stored under the subject's sprout and a body naming another is
      dropped; `props.set`/`props.delete` refuse the fact names; prop and fact
      values are substituted into parsed YAML, not spliced into recipe text;
      `env`, `call`, `html`, `js` and `template`/`define`/`block` are gone
      from recipes, which render under size, time and range limits
      (`farmer.recipes.templateLimits`); recipes resolve per tenant, a tenant
      recipe shadowing a platform one of the same name. Still open: static
      props from farmer's config (`props.static`) can still set reserved
      names, and saasapi still reads them for planning (not for the wave
      gate); `hostname` in a recipe is the sprout's reported hostname fact,
      kept 10 minutes, then the sprout ID; `props.GetHostnameFuncForTenant`
      has no caller; a deprovisioned tenant's `tenants/<tenant_id>/recipes/`
      is not deleted; the render budget is per render, not per cook (review
      B4, Open item 4).
    - **Recipe upload (REC.1, PR #90, #89):** the four §1.6 routes in
      `internal/saasapi/recipes.go`; saasapi writes the recipe bucket with
      its own credential, limited by policy to `tenants/*/recipes/*` plus
      append-only `tenants/*/recipe-audit/*` and checked at startup since
      FIX.3; uploads validated under farmer's `IMAS_RECIPE_*` limits (one set
      of limits for upload and cook, owner, 2026-10-04); tenant caps 500
      recipes and 20 MiB; compare-and-swap writes (412); separate Keycloak
      read and write roles; PUT and DELETE rate-limited; every write audited
      without its content, failing closed. `RejectUncleanPaths` answers 400
      to a path with `.` or `..` segments instead of ServeMux's 307 (PR #89).
      Still open: audit records are bucket objects, not a `saas` table;
      tenant deprovisioning deletes neither `recipes/` nor `recipe-audit/`;
      §1.5's `cook` action has no role check, so the read role alone can't
      stop someone without the write role cooking an existing recipe; a
      DELETE `If-Match` is a check then a delete; validation renders with
      empty props; PR #90's questions on retention and defaults.
    - **Helm fresh-install gaps (FIX.3, PR #112):** farmer's NetworkPolicy
      gets its own rule on `objectStore.endpoint`'s port whenever an
      endpoint is set (narrowed by `networkPolicy.external.objectStore`);
      the render fails without a bootstrap admin unless
      `farmer.bootstrapAdmin.skip=true` (the `ci/` files carry an all-zero
      placeholder farmer refuses to import); saasapi refuses to start if the
      object store lets its recipe credential create outside `tenants/`,
      write, read or list under `sprouts/`, or gives no classifiable answer
      within about 30 s (`internal/saasapi/recipes_credcheck.go`,
      `internal/objectstore/probe.go`), on by default in the chart and the
      binary; NOTES warns when `imas-saasapi-nats` and `imas-saasapi-box`
      must be created by hand. Chosen over a MinIO policy Job, which would
      need the AGPL-3.0 `mc` image and a MinIO admin credential. Still open:
      on AWS the read probe can't catch a key that may read `sprouts/*` but
      can't list the bucket (it answers `AccessDenied` for a missing key,
      and the same holds for job bucket keys); PR #112's questions
      (render farmer's rule with no endpoint; a required `skipReason`).
      FIX.5 (merged, PR #117) closed the rest: `docs/api/saasapi.md` lists
      `SAASAPI_RECIPES_CREDENTIAL_CHECK`, CI builds the real subcharts and
      fails rather than skips the chart tests (`IMAS_REQUIRE_HELM=1`), and
      the check also probes the platform recipe prefix and the job bucket.
      With the check on, the job bucket is required: the chart refuses to
      render without `objectStore.jobBucket` (FIX.5, PR #117), and the
      saasapi binary refuses to start without `SAASAPI_RECIPES_JOB_BUCKET`
      instead of warning that it didn't probe it (PR #120, merged; owner
      decision).
    - **saasapi NetworkPolicy and PDB (OPS.1, PR #105):** nothing stops
      `saasapi.pdb.maxUnavailable` being 0 (blocks every drain) or at least
      `replicaCount` (protects nothing); neither is the default.
    - **OpenBao client (CL.2a, PR #66; CL.2b, PR #67; CL.4, PR #71;
      DOC.1, PR #69):** `.github/workflows/sdb-openbao-realserver.yml` runs
      `TestRealServer` against OpenBao v2.7.1 only (no HashiCorp Vault job,
      for licensing reasons), checking the tarball against a pinned sha256
      but not its cosign bundle. An absent KV v2 secret still falls back to
      KV v1, and the error now names each path tried. DOC.1 documented the
      optional `*_NAMESPACE` variables and `NO_PROXY`. Still open: Vault
      Enterprise namespaces are not supported on the sprout side; the
      credential publish Job has no `extraEnv`, so the chart can't set
      `IMAS_SAASAPI_CRED_OPENBAO_NAMESPACE` or a proxy for it; the `bao` CLI
      steps (the bootstrap Job and saasapi's `fetch-bus-ca` init container)
      set no namespace; no test has run against a namespaced server.
    - **CLI and web UI (J.3 clean-up, CL.4, PR #103):** `imas serve`'s
      add-user requires `boxpub`. The web UI (the `grlx-web-ui` submodule,
      outside this repo) must send it; the built bundle in
      `internal/serve/dist` has no add-user form at all, so either its source
      has one not yet rebuilt or it still has to be written. After a tenant
      key rotation the CLI re-pins `tenantboxpub` by hand
      (`f2c.tenantkey.continuity` not built).
    - **Tests (T.1, PR #106):** the JWT-detector helpers are copied into
      `internal/api/handlers` and `internal/pki`; other in-memory test
      databases keyed on `t.Name()` may have the same `-count` problem.
11. **The control plane, which a compromised bus could forge (requirement
    14): sealed only, merged (J.1 to J.4, PR #93 to #97, and J.4's Helm
    wiring, PR #99); all flagged, human review not held.** Sealing farmer ↔
    sprout stopped the bus injecting commands *into a sprout*, but not asking
    *farmer* to send them. Verified on `main` before J (throwaway tests, PR
    #70): the CLI's NKey signed the bus's `CONNECT` nonce and an API token
    was only a signature over an expiry time, so one CLI connection let the
    bus mint a token valid until 2099; the sprout's NKey signed both its
    `CONNECT` nonce and its `/v1/refresh` proof, so the bus could refresh as
    any sprout and read its staged recipe from `/files/`, and `/v1/enroll`'s
    replay path had the same hole; captured tokens could be replayed for 5
    minutes; and `internal.*` trusted the bus's account permissions, so a
    compromised bus could forge provisioning, deprovisioning, sprout actions
    and their results. Design: "Sealing the control plane" in
    `docs/design/imas-payload-encryption-design.md`, with an "As built"
    section per brief. Owner decisions, 2026-10-04: no compatibility window
    (no bearer-token or plaintext fallback, no `apiallowbearertoken` or
    `internalallowplaintext`, no ratchets), sealed only, and a sprout with no
    box key is refused, not downgraded.
    - **J.1, building blocks (PR #93):** `payloadbox` purposes for
      `c2f.api`/`f2c.api`, `c2f.userkey.pub`, the `a2f`/`f2a` set and
      `s2f.refresh`, bound to the method, the subject and the
      `Imas-Principal` header; sealed request and reply helpers, a
      per-replica replay guard and a Valkey claim (10-minute TTL, fail closed
      for mutating methods). The users store, which was each replica's own
      config file, moved to the farmer database (`auth_users`, CLI box keys
      in `auth_cli_box_keys` keyed on `(tenant_id, user_id)`, migration
      `farmer/00003`); `imas auth keygen` and `imas auth rotate-key`; the
      platform key and the SaaS API box key, written to OpenBao by a keygen
      hook Job that `cmd/farmer` runs before loading config. The first
      admin's CLI box key comes from `boxpub` in farmer's config. Accepted
      limitation (owner): no per-user rate limit on the replay guard.
    - **J.2, sealed sprout refresh (PR #94):** `POST /v1/refresh` takes only
      `{nkey_pub, sealed}`, an `s2f.refresh` message sealed with the
      sprout's box key to its pinned tenant key, naming its pinned tenant and
      sprout ID; the reply is a sealed `f2s.refresh` carrying the gateway
      JWT, so nothing in the HTTP exchange, Envoy included, carries one in
      the clear. `/v1/enroll` issues a gateway JWT only for a verified box
      key proof. The through-real-Envoy suites pass on v1.35.3. Owner
      decisions (PR #94): a sprout cut off by a severing rotation gets a
      retried refusal until an operator re-enrolls it; the gateway JWT in
      enrollment step 2's response stays plaintext inside TLS. Known gap:
      `ansible/molecule/stubfarmer` still speaks the old refresh contract
      (owner decision: leave it).
    - **J.3, sealed CLI ↔ farmer (PR #95, #96):** bearer tokens are deleted
      everywhere (`TestForgedTokenRegression`); every `imas.api.*` request
      is a sealed `c2f.api` message from the user's CLI box key and every
      reply a sealed `f2c.api`, through one router
      (`internal/natsapi/sealedrouter.go`) that derives the user from the key
      that opened it; only an unsealed `health`/`version` gets a plaintext
      answer. `auth.users.add` carries the new user's box key;
      `auth.users.resetkey` stays (admin only). The cook trigger is sealed;
      recipe browsing moved to sealed `recipes.list`/`recipes.get`
      (read-only). There is no `dangerously_allow_root` bypass on either the
      NATS or the HTTP path (PR #96); farmer warns if the key is still set.
      The dead HTTP recipe routes and the audit token resolver were removed
      by CL.4 (PR #103).
    - **J.4, sealed SaaS API ↔ farmer (PR #97):** every
      `internal.tenant.provision`, `internal.tenant.deprovision` and
      `internal.sprout.action` request is a sealed `a2f` message from the
      SaaS API box key to the platform key, bound to its method, subject and
      tenant; results and replies are sealed `f2a`; both ends refuse
      plaintext, stale and replayed messages (per replica and through
      Valkey); the point-of-effect checks still run behind the seal. Every
      send, the sweeper's re-sends included, seals a new message.
      saasapi needs `SAASAPI_BOX_PRIV_FILE` and `SAASAPI_PLATFORM_BOX_PUB`.
    - **J.4 Helm wiring (PR #99) and OPS.1 (PR #105):** saasapi's box key
      is the Secret `imas-saasapi-box`, mounted only in saasapi's pods (the
      private key as a read-only file, the platform public key it pins as an
      env value); `controlPlaneBoxKeys.enabled` defaults to `true`, so the
      keygen hook Job runs on every install and upgrade (with an external
      OpenBao, its role and policy must exist first). Chart tests prove
      farmer never gets the SaaS API's private key and saasapi never gets
      the platform's. On a fresh install saasapi's pods wait until the
      Secret exists; `--wait` on a first install deadlocks, as before. OPS.1
      found that J.4 needs no new saasapi network path (`internal.*` rides
      the bus, ESO delivers the key) and that the PDB is right.
    - **Stopgap SEC.0 (PR #83), superseded:** it capped a token's expiry at
      15 minutes ahead; J.3 deleted the tokens.
    - **Residuals:** a compromised bus can still deny service, delay a
      request inside the 5-minute window, and see method names, principals,
      sizes and timing. It can deliver an `internal.sprout.action` request,
      answer "no responders", and have the SaaS API send it again as a new
      sealed message farmer accepts, so the action can run up to
      `SAASAPI_OUTBOX_MAX_ATTEMPTS` times: **accepted, known residual risk**
      (owner decision, 2026-10-04, PR #97, "accept no-responders for now";
      review 2026-10-b B6). Not built: at-most-once per action item on
      farmer, a core-only transport for `internal.*` (design B2a/B2b),
      platform key rotation tooling and `f2a.platformkey.continuity`,
      `f2c.tenantkey.continuity` for the CLI, and sealed streams to the CLI
      (Decision D): the step events `imas cook`, `imas jobs watch` and `imas
      serve`'s log stream read stay plaintext, which a compromised bus can
      read and forge (the job store, through sealed `jobs.get`, is
      authoritative).

Known accepted gaps, not re-checked in this pass: JWT permission re-mint
reaches an already-enrolled sprout only when a sync runs and the sprout
restarts (Open item 10, "Enrollment and the stale grant"; harmless
pre-production), and `internal/natsapi/router.go`'s tenant-facing subjects do
not validate `msg.Reply` (inherited from upstream grlx).

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

## Re-evaluation, 2026-10-03 (evening): RAG pass

> **Superseded (2026-10-05).** The Red for unsealed `shell.*` (requirement
> 14) recorded here no longer holds: `shell.*` is sealed (J.5, PR #98), and
> requirement 14 is Amber in the RAG summary above.

After PR #62 to #67 merged (CL.1, CL.3, REL.1, CL.2a, CL.2b), this file got a
RAG summary and the rows that still said "ready for review" were corrected.
Colours were assigned from the code on `main` and CI at the time: the
two Reds in the requirements are the unbuilt scale items (1) and unsealed
`shell.*` (14); the first release and the Terraform UAT gate are Red because
neither has started. CI was still running on `1419c18` when this was written.

## Validation, 2026-10-05

FIX.4 (plan §4g) brought this file up to `main` at `7fb527a`, after FIX.1 to
FIX.3 merged. The validation behind §4g (of `main` at `b78c9e7`) found that
this file stopped at PR #67, still said "in review" for merged work, and
contradicted itself on requirements 1 and 7.

**Verified.**
- The PR list through the REST API (GraphQL is blocked here): PRs #68 to
  #113 are all merged, none is open and none was closed unmerged. Each has a
  row in the ledger with its brief ID, and each brief is in "Open-item briefs
  and Wave 7".
- Each PR's description, against the code on `main` for the claims this file
  makes: SCALE.1's `nats.CustomReconnectDelay` in `cmd/sprout/main.go` and
  `internal/natsretry`; SCALE.2's `cmd/farmerbus/cluster.go` and
  `fence.go`; `tools/loadtest`; `payloadbox.PurposeStagedRecipe`
  (`f2s.staged`); `internal/cook/reenroll.go` and `sprout_reenroll_required`
  in `internal/natsapi` and `internal/saasapi`; `pki.VerifyGatewaySubject`;
  `jobKey` in `internal/jobs/store.go`; `natsapi.CloseShellSessions` called
  from `cmd/farmer`; the plaintext `announce`, `test.ping` and `cancel`
  subjects; the Helm defaults (`controlPlaneBoxKeys.enabled: true`,
  `farmer.selfUpdate.enabled: false`, `saasapi.fleetUpdateDispatch.enabled:
  false`, `saasapi.recipes.credentialCheck: true`, nats `replicaCount: 1`);
  `requirements.md` item 15's new wording; no `.tf` file in the repo.
- CI on `7fb527a`: every push workflow passed (see the top of this file).
  No tag, no GitHub release, and no run of `release.yml` or
  `publish-packages.yml`. `snapshot.yml` last ran on 2026-09-26 and failed,
  before REL.1 and REL.2 rewrote it.
- Both security reviews' findings, mapped to the merged fixes (Open item 4).

**Resolved contradictions.** Requirement 1's row said reconnect jitter was
not built, with a fixed `ReconnectWait(15s)` in `cmd/sprout/main.go` and no
harness in the repo, while Open item 3 said SCALE.1 and SCALE.3 were built;
the RAG row for requirement 7 said the bus stayed single-node "until
requirement 1's routes land", while SCALE.2 had built them. The code agrees
with the SCALE sections, and both rows now say so.

**Could not be run or checked here.**
- No test was run: the change is docs only and its brief asks for none, so
  CI on `main` is the evidence for "tests pass".
- The repository's Actions secrets, variables and environments: the API
  refuses them from this environment. Whether `GPG_PRIVATE_KEY`,
  `GPG_PASSPHRASE`, `BUILDKITE_PACKAGES_TOKEN` and
  `BUILDKITE_ORGANIZATION_SLUG` exist, on the repository or the
  `goreleaser` environment, is **UNCONFIRMED** (the GPG pair was reported set
  on 2026-10-03); checklist step 1 in `docs/RELEASING.md`, or a Release run
  passing `Check release secrets`, would confirm it. Whether the four
  Buildkite registries exist (`imasnget` public) is **UNCONFIRMED** for the
  same reason.
- Whether the owner's merge of each flagged PR was meant as its security
  review: nothing records it, so this file treats the human review as not
  held (**UNCONFIRMED**). A record in Open item 4 (who, when, what scope)
  would settle it.
- The first review's deferred Lows and Info items, one by one (Open item 4).

**First release prerequisites still owed by the owner** (in the order of
`docs/RELEASING.md`'s First release checklist):
1. ~~Commit the GPG public key and make `SECURITY.md` match it.~~ Done by
   PR #115: `gpg-public-key.asc` is at the repo root, and `SECURITY.md`'s
   fingerprint (`84F4 5E90 … 41F0 41EB`) and its `main` download link
   match it (checked 2026-10-05, FIX.5).
2. Create the Buildkite registries `imasrpm`, `imasdeb`, `imasnget`
   (public) and `imashelm`, and set `BUILDKITE_ORGANIZATION_SLUG` and
   `BUILDKITE_PACKAGES_TOKEN`; check the `goreleaser` environment's rules
   allow `v*` tags and `main`.
3. Tag `v0.1.0-rc.1` on a green `main` commit.
4. Run Release on the tag (Actions, Release, Use workflow from the tag),
   then check and publish the draft as a pre-release.
5. Publish it to Buildkite by `workflow_dispatch` of Publish packages: a
   pre-release is skipped automatically.
6. Verify on a scratch host that the Buildkite index layout is the one
   FU.2's reader expects (it was tested against Nexus, never Buildkite), and
   that the published package's `+git` version (`0.1.0~rc.1+git`) maps back
   to the signed manifest's version as SEC.5's check requires.
7. Re-enable the `push: tags` trigger in `release.yml` by PR, and record the
   run in this file.

Then the Terraform UAT gate (Open item 1), which also needs the
compute-provider decision.

**FIX.5 (2026-10-05, merged, PR #117; flagged for security review).** The re-validation of
`main` at `cefa9ca` found two release blockers. `publish-packages.yml` ran
`helm dependency build` on the farmer chart without adding its `Chart.lock`
repositories, which Helm refuses ("no repository definition"), and linted
both charts with their default values only; it now adds the repositories,
pins Helm (`v4.3.0`), and lints and renders each chart with its
`ci/default-values.yaml`. And CI never installed Helm, so every chart render
test skipped; the Test job now installs the same Helm, builds both charts'
dependencies and sets `IMAS_REQUIRE_HELM=1`, which turns every chart-test
skip into a failure.

**FIX.5 follow-up (2026-10-05, merged, PR #120; flagged for security review).**
The job bucket is now required while the recipe credential check is on.
FIX.5 (PR #117) had left `SAASAPI_RECIPES_JOB_BUCKET` optional in the binary: unset,
saasapi probed the recipe bucket only and logged a warning. The owner chose
to fail closed. `RecipeSettings.validate` refuses an unset job bucket while
`SAASAPI_RECIPES_CREDENTIAL_CHECK` is on, and the check itself refuses a
missing job store. With the check off nothing changes. The chart already
required `objectStore.jobBucket` in that case (FIX.5). An operator running
the binary outside the chart, with recipes and the check on but no job
bucket, must now set `SAASAPI_RECIPES_JOB_BUCKET` (farmer's
`IMAS_S3_JOB_BUCKET`) or saasapi won't start. The same PR documents the
probes in the chart README and `docs/INSTALL.md`, and adds the
`helm repo add` lines the README's install steps were missing.
