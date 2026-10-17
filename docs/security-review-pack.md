# Review pack for P3: the human security review

**FLAG FOR SECURITY REVIEW.** This pack is for the person doing the review. It
is a map and a checklist, not a review and not a clean bill of health. Nothing
in it says any work is done or safe to merge; every item is **ready for
review** until the sign-off at the end is filled in.

Prepared 2026-10-13 against `main`. It covers the scope of the P3 row in
`docs/BUILD-STATUS.md`: 124 merged PRs whose description carries FLAG FOR
SECURITY REVIEW (index in section 6).

## 1. What the review gates

- `SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED` and `IMAS_SELF_UPDATE_ENABLED` stay
  off everywhere except the UAT until the sign-off in section 7 exists.
- P21 (signing keys in OpenBao, stateless farmer/saasapi/bus) and P22 (GPG
  fleet-update trust) stay Amber until it exists.
- It does not block the Azure Run 2 or Run 3 (`uat/RUNBOOK.md`); a green run is
  evidence for the review, not a substitute for it.

## 2. Suggested order and time

Review in this order: what an attacker reaches first, then what the stateless
build changed, then the tooling. Reading the tests named below is faster than
reading the whole diff; each claim has a test, and a claim without one is
itself a finding.

| Step | Area | Why this order | Read first |
|---|---|---|---|
| 1 | Fleet update trust (section 3.1) | It runs code as root on every sprout; the dispatch flags exist for it | `docs/design/imas-openbao-signing-design.md` D9, D12, D19 to D21; `internal/ingredients/selfupdate/`; `internal/sproutrelease/` |
| 2 | Signing keys in OpenBao (3.2) | Whoever holds a signing key mints identities for every tenant | same design, D1 to D8, D22; `internal/pki/natskeys/`; `internal/natsbootstrap/`; `deploy/helm/farmer/openbao_policy_test.go` |
| 3 | Stateless bus and farmer (3.3) | Moves trust from local disk to an object store the DMZ can read | design D10, D11, D13; `internal/accountloader/`, `internal/lease/`, `internal/pki/accountpublisher.go`, `cmd/farmerbus-loader/` |
| 4 | Sealing and the staged channel (3.4) | The one farmer to sprout channel that is plaintext inside TLS, and the DMZ ends that TLS | `docs/design/imas-payload-encryption-design.md`; `internal/payloadbox/`; `internal/cook/` |
| 5 | Enrolment and gateway JWT (3.5) | Where a sprout first gets an identity | `internal/pki/enroll.go`; `docs/design/imas-envoy-enrollment-design.md` |
| 6 | Tenant isolation (3.6) | A cross-tenant bug is the worst outcome for a multi-tenant product | `docs/design/imas-tenant-context-threading.md`; `internal/rbac/`, `internal/jobs/`, `internal/tenantconn/` |
| 7 | UAT and Azure credentials (3.7) | Cloud credentials and a root-policy bootstrap token | `.github/workflows/uat.yml`, `uat/` |

Steps 1 to 3 are the new work and need the most attention. Allow a day for
them, half a day each for 4 to 6, and two hours for 7. Earlier written
reviews are inputs: `docs/security-review-2026-10.md` and
`docs/security-review-2026-10-b.md` (their findings B1 to B3 and H1 to H4 were
addressed by SEC.7a to SEC.7d and others; check the fixes, not the findings).

How to look at a PR: `gh pr view N` for its description (each states what was
verified) and `gh pr diff N`. To see a file as it is now, read `main`.

## 3. Checklists

Each question is answerable from the code and its named test. Mark each
Accepted, Fix needed (with a note) or Not applicable.

### 3.1 Fleet update trust (P22, FU.*, SEC.5)

1. The sprout is the only verifier (D20). Confirm no path installs a package
   without the GPG check of `checksums.txt` against `/etc/imas/fleet-signing-keys.asc`,
   including the dispatch path from farmer. Test: `TestPrepare_GPGChecksums`,
   `TestApply_ThroughFarmerManifestRoute` (a release signed by another key is
   refused before any download).
2. The sprout derives the file name itself and takes the hash for that name;
   a manifest cannot choose another file's hash. Read `manifest.go`, `download.go`.
3. `min_sprout_version` is unsigned (D19). Is that acceptable given an
   attacker who can alter the manifest can only block updates, not choose a
   package? Say yes or no.
4. The keyring file is built from the repo's `gpg-public-key.asc` (D21) and
   ships root-owned and not writable by the sprout user. Check the package
   scripts for the three platforms.
5. Windows and prerelease handling (SEC.5, #88): an rc cannot replace a final
   by version confusion; the MSI `ProductVersion` carries no prerelease
   (finding B8 of review B). Accept or fix.
6. The operator plane registers a release only with a stored signed pair
   (`fleet_release_checksums`, saas migration 00007); the registration hook
   Job uses an operator bearer token and TLS Secret. Who can call it?
7. The release GPG key lives only in the `goreleaser` environment (owner
   action in `uat/RUNBOOK.md`). Confirm before accepting.
8. Dispatch switch: farmer refuses to dispatch when the flag is off
   (finding L1 of review 1). Test it off and on.

### 3.2 Signing keys in OpenBao (P21 slice 1)

1. Farmer can create a Transit key of any name on the transit mount and
   soft-delete any key there that an exact deny does not cover, including keys
   other clients keep on a shared mount (owner decision 2, accepted as a
   known residual and recorded in `deploy/helm/farmer/README.md`). Re-affirm
   or require a dedicated mount. `TestOpenBaoFarmerPolicyKeySet` pins what
   a farmer token may do per key name; read it as the contract.
2. No key material leaves OpenBao: the operator and account signing keys are
   Transit keys (D3, D5) and the Go side holds only a signer. Check
   `internal/pki/natskeys/` for any export, log or error that prints a seed.
3. The bootstrap (`farmer bootstrap-nats-trust`, `internal/natsbootstrap`) leaves no standing
   admin (D22) and the operator/account public keys land in the trust
   ConfigMap only. Check the Job's RBAC.
4. Recovery keys: 3 shares, threshold 2, held by people (D2). Confirm the
   operator runbook (`docs/OPENBAO-RUNBOOK.md`) exists and a real custody plan
   is assigned. This is a process item, not a code item.
5. Seals: Azure Key Vault in production (D17); the image also carries AWS KMS,
   GCP KMS and KMIP (D14). Confirm unused seals cannot be enabled by a values
   file without review.
6. UAT only: bootstrap uses a short-lived root-policy token per run (B8). Confirm
   it is revoked at the end of the run and never printed to the job log.

### 3.3 Stateless bus and farmer (P21 slices 2 and 3)

1. The DMZ bus loader reads the accounts bucket with a read-only credential
   (D22). In OpenBao TLS mode it could read the bus TLS private key (C6);
   owner decision 2026-10-14: not accepted, fixed by unit S1, where the
   loader reads the CA from a public ConfigMap (`loader.caConfigMap`,
   written by the core bootstrap Job) and never mounts the bus TLS volume
   in either mode (`deploy/helm/nats/chart_test.go`, `TestLoaderMounts`).
   Confirm the credential cannot list or read any other bucket
   (`validate-object-store.sh`).
2. A compromised bus node cannot publish an Account JWT: accounts are
   verified against the operator key before use and the rank rule
   (`internal/accountrank`) refuses an older JWT. A forged "newer" JWT must
   fail signature. Read `accountloader/loader.go` and `node.go`.
3. The loader is ready only after loading every account (test:
   `TestLoaderEmptyNodeReadyOnlyAfterLoadingEverything`), and revocation is not lost
   when the object store is unreachable (decision: keep serving with last
   state; accept the staleness window or set a limit).
4. Row leases (`internal/lease`) prevent two farmers writing one Account JWT or
   minting two sprout JWTs. Check the lease expiry cannot be extended by a
   stale holder.
5. Object-store layout: JWT bucket, accounts bucket, recipes, jobs, and their
   per-component users (D22). Confirm each user's policy in
   `deploy/helm/farmer` and the Versity IAM file.
6. No local state: farmer, saasapi and bus carry no PVC and write no key or
   JWT file (E3, D9 of slice 3). Confirm nothing sensitive reaches stdout
   (audit goes to stdout by decision; confirm tokens and seeds are redacted).

### 3.4 Sealing and the staged channel (J.*, SEC.7a/7d, SH.1, FIX.1)

1. The staged recipe is sealed end to end (`f2s.staged`, bound to tenant,
   sprout, job ID and `DispatchedAt`); the sprout refuses plain JSON. Test:
   `TestStagedSealed_ForgedPlainEnvelopeIsRefused`.
2. "What a compromised bus can still do" in
   `docs/design/imas-payload-encryption-design.md`: test each row against the
   code. This is the central table of requirement 14.
3. `cmd.run` and cook to a sprout with no box key are refused, and the
   plaintext path is deleted (FIX.1). Search for any leftover.
4. The built-in `operator` role has no `shell` (SH.1); farmer-shutdown on
   stop. Confirm the default roles in `internal/rbac/config.go`.
5. Residuals the owner has accepted: forged "no responders" can re-run an
   action up to `SAASAPI_OUTBOX_MAX_ATTEMPTS` times (B6); same-second Account
   JWT `iat` tie (B5, M6). Confirm both are still accepted.
6. Recipe render cost per cook (B4): a total per-cook render budget was asked
   for before dispatch is enabled. Decide.

### 3.5 Enrolment and gateway JWT (H:*, SEC.7b/7c)

1. A first box key is accepted only on the identity-issuing exchange, never
   the replay path, and an accepted-but-keyless sprout is a closed state (B2,
   SEC.7b). The enroll binding window is 5 minutes (SEC.7d).
2. A gateway JWT of a deleted or replaced host is refused (B3, SEC.7c).
3. Proof of possession signatures are single-use (Valkey replay cache). Check
   the cache TTL covers the signature validity and that a Valkey failover
   fails closed. Owner decision 2026-10-17, fixed by unit S5: the clients
   connected with no password and no TLS, so anyone who could reach Valkey
   could delete claims (a replay) or pre-claim keys (lock a sprout out).
   Now farmer and saasapi authenticate as Valkey's `default` user with a
   password the OpenBao bootstrap Job generates (`valkey_password` of the
   seed path; generated once, never overwritten), delivered by ESO as
   Secret `imas-valkey-auth` and mounted as a file only, never an
   environment variable, Helm value or ConfigMap; the bundled Valkey and
   its replicas use the same password; `valkey.auth.enabled=false` renders
   only with `valkey.auth.allowInsecure=true`. The clients can use TLS
   (1.2 or later, a CA from a ConfigMap, never the system roots or
   `InsecureSkipVerify`), expected of the production Valkey, which is
   external. The bundled Valkey runs `maxmemory-policy noeviction`, and
   both clients warn at startup if Valkey may evict (`internal/valkeyconn`;
   `deploy/helm/farmer/README.md`, "Valkey"; `valkey_test.go`). Accepted
   residual: Valkey replication is asynchronous, so a failover can lose the
   most recent claims. The impact is bounded to the 6-minute claim window
   and to the replay path: no gateway JWT is issued without a separately
   claimed box-key proof. Confirm the residual is still accepted.
4. The box-key write retry (PR #171, decided 2026-10-09: whole-transaction
   retry, six attempts, check the error number, release the enroll binding on
   final failure). Still open from #171: the gap-locking revoke and the same
   retry elsewhere in `internal/pki`. Look at both.
5. Envoy terminates sprout TLS in the DMZ and requires the right requirement
   map per route (#6). Walk `deploy/envoy/envoy.yaml`: every gated route
   needs a requirement.

### 3.6 Tenant isolation (PKI.*, SCALE.2, SEC.3a/4, REC.*, FIX.2)

1. Every table, index, cache and map is keyed `(tenant_id, sprout_id)`; a
   `sprout_id` alone is a bug (`CLAUDE.md`). Search `internal/` for maps and
   queries keyed on `sprout_id` alone.
2. Tenant recipe upload and read are scoped per tenant; templates are
   sandboxed; paths are refused when unclean (REC.1).
3. Deleting a tenant or sprout revokes its keys and JWTs; the provision and
   deprovision race is closed (PKI.1, PKI.2).
4. The fence in the clustered bus fails closed (SCALE.2).

### 3.7 UAT and Azure credentials (UAT.1, UAT.6, UAT.12, UAT.13, R1, H1 to H6)

1. The workflow uses OIDC to Azure, no stored secret; the `uat` and
   `uat-janitor` environments have reviewers (UAT.6). The janitor can only
   delete resources tagged for the UAT.
2. The sprout publish permission (UAT.12) and the startup path that refreshes
   a stale User JWT (UAT.13): what can a sprout publish, and can it publish
   for another tenant?
3. The UAT core RustFS is reachable from the DMZ private address on 9000 for
   the loader's read-only credential (E1); the loader seed is in the run's
   sensitive state and is copied to the DMZ only.
4. `dispatch_flags` turns the two update flags on in UAT only; confirm the
   production chart defaults are off.
5. Bastion tunnels and NSG rules added for the HA run (H1, H2) open only
   what the node-to-node ports need.

## 4. Decisions already made: do not reopen unless you disagree

D1 to D22 in `docs/design/imas-openbao-signing-design.md`, and these owner
decisions (2026-10-09 to 2026-10-12): PR #171 questions 1 to 4; farmer may
soft-delete any Transit key on its mount (accepted; recorded); bootstrap leaves
no standing admin; audit goes to stdout; idle bus connections close but active
ones stay; object store outage keeps serving the last state; DMZ and core share
one object store with scoped users; soft-delete with a purge window for
tenants. If you reverse one, write it in the sign-off as a required change.

## 5. Commands that help

```sh
# a PR's description and diff
gh pr view 205 ; gh pr diff 205 --name-only
# the policy contract for farmer on Transit
go test ./deploy/helm/farmer -run TestOpenBaoFarmerPolicyKeySet -v
# the update-trust tests
go test ./internal/ingredients/selfupdate -run 'TestPrepare_GPGChecksums|TestApply_ThroughFarmerManifestRoute' -v
# bus loader readiness
go test ./cmd/farmerbus -run TestLoaderEmptyNodeReadyOnlyAfterLoadingEverything -v
# anything keyed on sprout_id alone (read the hits)
grep -rn 'sprout_id' --include=*.go internal | grep -v tenant_id | head -80
```

## 6. Index of flagged PRs (124)

Grouped by the checklist area they mainly belong to. A PR can touch more than
one area; the group is the first place to look.

### 1. Enrolment, gateway JWT and the DMZ path (Envoy, bus connect) (10 PRs)

| PR | Merged | Title |
|---|---|---|
| #4 | 2026-09-27 | C+H: Helm chart for the farmerbus DMZ bus + Envoy gateway (deploy/helm/nats) |
| #6 | 2026-09-26 | H: fix envoy.yaml requirement_map (403 on every gated route); test the sprout path through real Envoy |
| #7 | 2026-09-26 | H: require NKey proof of possession on POST /v1/enroll |
| #8 | 2026-09-26 | H: enroll sprouts via POST /v1/enroll and connect with the User JWT |
| #9 | 2026-09-26 | H: route sprout recipe downloads to /files/ and accept scoped gateway JWTs there |
| #13 | 2026-09-26 | H: single-use proof-of-possession signatures (Valkey replay cache) |
| #14 | 2026-09-27 | H: root CA bootstrap: never pin a bad /auth/cert/ response; DMZ sprouts use a pre-provisioned CA |
| #15 | 2026-09-27 | H: connect sprouts to the enrolled nats_urls instead of FarmerBusURL |
| #16 | 2026-09-27 | H: ship bus logs over the authenticated bus connection |
| #33 | 2026-09-27 | H: dial the sprout bus through an optional busproxyurl |

### 2. Sealing: payload encryption, staged recipes, box keys, shell (J.*, SEC.7*, FIX.1, SH.1) (21 PRs)

| PR | Merged | Title |
|---|---|---|
| #27 | 2026-09-27 | J: per-tenant tenant keypairs, authenticated key rotation, cmd.run sealed end to end |
| #30 | 2026-09-27 | J: per-tenant tenant keypairs, authenticated key rotation, cmd.run sealed end to end |
| #31 | 2026-09-27 | J: seal the fleetsigningkeys reply to the sprout |
| #32 | 2026-09-27 | J: seal cook dispatch and resync nudge end to end |
| #34 | 2026-09-27 | J: sprout side of farmer-triggered box key rotation |
| #70 | 2026-10-04 | J: designs for sealing shell.* and the control plane (requirement 14) |
| #87 | 2026-10-04 | SEC.3b: tenant binding in sealed messages, replay after restart, cook logging |
| #93 | 2026-10-04 | J.1: control-plane sealing building blocks (FLAG FOR SECURITY REVIEW) |
| #94 | 2026-10-04 | J.2: sealed sprout refresh; no gateway JWT for an NKey proof alone |
| #95 | 2026-10-04 | J.3: sealed CLI to farmer API, bearer tokens removed (FLAG FOR SECURITY REVIEW) |
| #96 | 2026-10-04 | J.3 follow-up: remove the dangerously_allow_root HTTP bypass and the flag (FLAG FOR SECURITY REVIEW) |
| #97 | 2026-10-04 | J.4: sealed SaaS API <-> farmer internal.* (FLAG FOR SECURITY REVIEW) |
| #98 | 2026-10-04 | J.5: seal shell.* end to end, farmer relaying both legs |
| #99 | 2026-10-04 | J.4 follow-up: Helm wiring for the SaaS API box key (FLAG FOR SECURITY REVIEW) |
| #102 | 2026-10-05 | SH.1: operator loses shell, farmer-shutdown on stop, sealed-shell user docs |
| #104 | 2026-10-05 | SEC.7c: refuse revoked or superseded NKeys' gateway JWTs (B3) |
| #107 | 2026-10-05 | SEC.7a: seal the staged recipe and verify it before cooking (B1, B9) |
| #108 | 2026-10-05 | SEC.7b: bind a sprout's first box key to the identity-issuing enrollment (B2) |
| #110 | 2026-10-05 | SEC.7d: staged recipe clock skew tolerance; keep the 5-minute enroll binding |
| #113 | 2026-10-05 | FIX.1: refuse cmd.run and cook to sprouts with no box key; delete the plaintext path |
| #118 | 2026-10-05 | FIX.1: carry cmd.run errors as text; imas cmd run exits 1 on failure |

### 3. Tenant isolation, PKI races, recipes (PKI.*, SCALE.2, SEC.3a/4, REC.*, FIX.2) (10 PRs)

| PR | Merged | Title |
|---|---|---|
| #74 | 2026-10-04 | PKI.1: close the provision/deprovision race in internal/pki |
| #76 | 2026-10-04 | SCALE.2: clustered farmerbus with authenticated routes and a fail-closed fence |
| #77 | 2026-10-04 | PKI.1: re-read the tenant's Account after marking it deleted |
| #78 | 2026-10-04 | SCALE.2 follow-up: the bus mints no Account JWTs; core pushes them all on connect |
| #79 | 2026-10-04 | PKI.2: write every JWT and seed atomically, so a mid-write read can't drop revocations |
| #84 | 2026-10-04 | SEC.4: forged facts, sandboxed recipe templates, per-tenant recipes |
| #85 | 2026-10-04 | SEC.3a: revoke deleted sprouts, one active box key, no dotted sprout IDs, no shared tenant keypair |
| #89 | 2026-10-04 | REC.1: refuse unclean request paths with 400 instead of redirecting |
| #90 | 2026-10-04 | REC.1: tenant recipe upload, list, read and delete through the SaaS API |
| #111 | 2026-10-05 | FIX.2: key job objects on (tenant_id, sprout_id) [FLAG FOR SECURITY REVIEW] |

### 4. P21: OpenBao-held signing keys, stateless farmer/saasapi/bus (B*, C*, D*, E*, F1, Z) (34 PRs)

| PR | Merged | Title |
|---|---|---|
| #198 | 2026-10-11 | C1: extract Account JWT rank into internal/accountrank (P21 slice 2 PR 1) |
| #199 | 2026-10-11 | D1: P21 slice 3 PR 1 — internal/lease row lease and report-only file-write guard |
| #200 | 2026-10-11 | D2: P21 slice 3 PR2 — state migrations (farmer 00004-00005, saas 00008) |
| #202 | 2026-10-11 | B1: natskeys Transit-backed NATS key store and signer (P21 slice 1 PR1) |
| #204 | 2026-10-11 | B2: P21 slice 1 PR2 — NATS trust model and pkitest |
| #206 | 2026-10-11 | D3: audit to stdout JSON, JSON log format, no farmer config writes (P21 slice 3 PR 3) |
| #207 | 2026-10-11 | B3: farmer bootstrap-nats-trust subcommand (P21 slice 1 PR3) |
| #208 | 2026-10-11 | C3: account loader (internal/accountloader) and farmerbus-loader binary |
| #209 | 2026-10-11 | B4: P21 slice 1 PR4a — key pair provider seam in pki |
| #210 | 2026-10-11 | B5: Transit cut-over in pki (P21 slice 1 PR4b) |
| #211 | 2026-10-12 | B6: P21 slice 1 PR5: bus reads only the NATS trust directory |
| #212 | 2026-10-12 | D5: sprout JWT store and lease (P21 slice 3 PR 5) |
| #213 | 2026-10-12 | D6: SaaS API credential state in PXC (P21 slice 3 PR 6) |
| #214 | 2026-10-12 | C4: P21 slice 2 PR 4 — fence size source and loader SYS user |
| #215 | 2026-10-12 | B7: charts wired to the Transit NATS signer and the trust ConfigMap (P21 slice 1 PR6) |
| #216 | 2026-10-12 | D6: saasapi records its NATS key in the credential state at boot |
| #217 | 2026-10-12 | C5: P21 slice 2 PR 5 — integration tests for the five loader scenarios |
| #219 | 2026-10-12 | D7: job leases, optimistic recipe writes, one-call SaaS API cook (P21 slice 3 PR 7) |
| #221 | 2026-10-12 | C6: bus chart drops its PVC and runs the account loader sidecar |
| #222 | 2026-10-12 | C7: P21 slice 2 PR 7 — drop leftover bus persistence references |
| #223 | 2026-10-12 | D8: tenant bus lazy connect, reconnect forever, idle close |
| #224 | 2026-10-12 | B8: P21 slice 1 PR7 — UAT scripts, values and docs on the Transit signer; T4/T5 real-cluster checks |
| #225 | 2026-10-12 | D9: stateless farmer chart (no PVC, 2 replicas, RollingUpdate, PDB, spread); file-write guard enforcing |
| #227 | 2026-10-12 | F1: 503 with Retry-After for a busy sprout JWT lease |
| #228 | 2026-10-12 | D4: farmer NKey from a shared Secret (P21 slice 3 PR 4) |
| #229 | 2026-10-12 | C2: farmer accounts publisher, all-node push, ReconcileAll, farmer chart values (P21 slice 2 PR 2) |
| #232 | 2026-10-12 | E6: finish C2, the farmer account publisher |
| #233 | 2026-10-12 | E2: every package gets tenant connections from the registry (P27.1) |
| #234 | 2026-10-12 | E1: make the UAT work after the stateless build (P26) |
| #235 | 2026-10-12 | E4: loadtest without trust seeds; sprout honours Retry-After (P27.3, P27.4) |
| #236 | 2026-10-12 | E2: accountloader ready ordering; slash-key test records its answer |
| #237 | 2026-10-12 | E3: no local JWT or key files in farmer (P27.2) |
| #238 | 2026-10-12 | E5: docs, CI MySQL tests, natsapi flake and earlier reports (P28) |
| #240 | 2026-10-13 | Z: final gate for P26 to P28 (end-to-end tests, every gated test in CI, stale docs) |

### 5. Fleet update trust: self-update, manifests, release registration, P22 (FU.*, SEC.5, CL.1, A1, A2) (12 PRs)

| PR | Merged | Title |
|---|---|---|
| #45 | 2026-10-02 | FU.0: sign a URL-free fleet manifest and verify it against a shipped keyring |
| #49 | 2026-10-02 | FU.3/FU.4: fleetreleaser signing service and saasapi release registration |
| #52 | 2026-10-02 | FU.1: route /v1/sprout/update-manifest through Envoy to farmer |
| #53 | 2026-10-02 | FU.2 + FU.7: sprout self-update from its configured repo; farmer dispatches {version} re-verified against the catalog |
| #55 | 2026-10-02 | FU.5: register the chart's sprout release from a Helm hook Job |
| #58 | 2026-10-02 | FU.6b: fresh-report wave gate; dedicated rollout claim column |
| #62 | 2026-10-03 | CL.1: remove the dead live fleet-signing-key path |
| #86 | 2026-10-04 | SEC.5: fixes before fleet update dispatch (M1, L1, L2, L8, M5) — FLAG FOR SECURITY REVIEW |
| #88 | 2026-10-04 | SEC.5: refuse pre-release self-updates on Windows (follow-up to #86) |
| #92 | 2026-10-04 | SEC.5b: farmer reads each tenant's rollout window |
| #203 | 2026-10-11 | A1: P22 slice 1 — sprout verifies GPG-signed checksums.txt |
| #205 | 2026-10-11 | A2: P22 slice 2 — server side, release stamping, retire fleetreleaser |

### 6. UAT and Azure: credentials, workflow, hub scripts, HA run (UAT.*, R1, H1 to H6) (16 PRs)

| PR | Merged | Title |
|---|---|---|
| #132 | 2026-10-06 | UAT.3b: core hub install (farmer chart, OpenBao bootstrap, MinIO, Keycloak) |
| #135 | 2026-10-06 | UAT.1: Azure UAT infrastructure (OpenTofu) and Bastion access scripts |
| #143 | 2026-10-06 | UAT.6: workflow, janitor and README for the Azure UAT gate |
| #147 | 2026-10-07 | UAT.1: write each az stub log line in one write (fix tunnel test race) |
| #148 | 2026-10-07 | UAT.9: pre-Azure fixes |
| #149 | 2026-10-07 | UAT.10: publish and pull Helm charts from GHCR (OCI) |
| #154 | 2026-10-08 | UAT.12: sprout heartbeat keeps `connected` true |
| #160 | 2026-10-09 | UAT.13: refresh a stale User JWT before the sprout connects |
| #163 | 2026-10-09 | UAT: defer farmer/saasapi wait and release registration until after the DMZ install |
| #244 | 2026-10-13 | H3: Versity Gateway as an optional farmer chart component (P25 first half) |
| #245 | 2026-10-13 | H1: tofu for 3 + 3 nodes (P24 item 1) |
| #246 | 2026-10-13 | R1: UAT registers the sprout release and turns the update path on (P20, P13) |
| #247 | 2026-10-13 | H2: k0s with 3 controller+worker nodes on etcd (P24 item 2) |
| #248 | 2026-10-13 | H4: HA hub values and scripts (P24 items 3 and 4) |
| #249 | 2026-10-13 | H5: the ha test tier (P24 item 6, P23) |
| #250 | 2026-10-13 | H6: final gate for the next Azure runs; runbook uat/RUNBOOK.md |

### 7. Supporting: charts, migrations, release pipeline, OpenBao client, earlier reviews (21 PRs)

| PR | Merged | Title |
|---|---|---|
| #17 | 2026-09-27 | C+SAAS: Helm chart for farmer (core) and saasapi, with optional PXC/OpenBao/Valkey subcharts |
| #18 | 2026-09-27 | C: separate farmer's bus address and bus TLS ServerName from farmerinterface |
| #19 | 2026-09-27 | C: imas CLI reads farmerbusurl and verifies the bus via BusTLSServerName |
| #20 | 2026-09-27 | C: re-land #19 on main (imas CLI reads farmerbusurl, verifies the bus via BusTLSServerName) |
| #22 | 2026-09-27 | M: run the sprout under the Windows SCM, default to %ProgramData%\imas |
| #46 | 2026-10-02 | DB.1: cmd/migrate with goose migrations; drop GORM AutoMigrate |
| #48 | 2026-10-02 | DB.2: run cmd/migrate as Helm hook Jobs; ship the imas-migrate image |
| #63 | 2026-10-03 | CL.3: outbox sweeper for provisioning jobs, action batches and update rollouts |
| #64 | 2026-10-03 | REL.1: release with GoReleaser OSS, build the MSI from a wixl build hook |
| #65 | 2026-10-03 | REL.1: give snapshot.yml what keyless cosign signing needs |
| #66 | 2026-10-03 | CL.2a: official OpenBao Go client for every server-side OpenBao identity |
| #67 | 2026-10-03 | CL.2b: official OpenBao client in the sprout's sdb:// provider |
| #71 | 2026-10-04 | CL.4: remove dead fleetsign JWKS code, clearer sdb OpenBao read errors, TestRealServer in CI |
| #81 | 2026-10-04 | SEC.1: read-only security review of the flagged work |
| #83 | 2026-10-04 | SEC.0: cap CLI token expiry and drop raw OpenBao error bodies |
| #100 | 2026-10-04 | SEC.6: read-only security review of Wave 7 (since eacdc79) |
| #103 | 2026-10-05 | CL.4: remove dead HTTP recipe routes and audit token resolver; boxpub in serve add-user |
| #105 | 2026-10-05 | OPS.1: saasapi NetworkPolicy/PDB after J.4 and REC.1 (FLAG FOR SECURITY REVIEW) |
| #112 | 2026-10-05 | FIX.3: Helm fresh-install gaps (farmer object store egress, required bootstrap admin, recipe credential self-check) |
| #117 | 2026-10-05 | FIX.5: release blockers and gaps from the 2026-10-05 re-validation |
| #120 | 2026-10-05 | FIX.5 follow-up: require the job bucket for the recipe credential check; document the new probes and helm repo add |
## 7. Sign-off record

Copy this block into a status fragment (below) when the review is finished.
Fill every field; "Fix needed" items become briefs or PRs before the flags go on.

```
Reviewer:
Date:
Scope reviewed (sections 3.1 to 3.7; list any left out and why):
Commit reviewed (main SHA):
Accepted (item numbers):
Fix needed (item, what, who):
Decisions reversed (D number or owner decision, new decision):
Residuals accepted (B5, B6, farmer Transit key deletion, others):
Dispatch and self-update flags may be turned on in: (UAT only | staging | production | not yet)
```

Status fragment, `docs/status/days/YYYY-MM-DD/p3-review.md` (the nightly roll-up
applies it; do not edit `docs/BUILD-STATUS.md`):

```
change: P3 human security review recorded: <reviewer>, <scope>, <result>.
item: P3
action: update
rag: Green
next-append: **Recorded <date>:** reviewer <name>; scope <sections>; accepted <list>; fixes owed <list>; flags may be enabled in <where>.
---
item: P21
action: update
next-append: **P3 (<date>):** security review recorded; <result>.
---
item: P22
action: update
next-append: **P3 (<date>):** security review recorded; <result>.
```

Set `rag: Green` for P3 only when there are no "Fix needed" items. Otherwise
leave P3 Amber, list the fixes in `next-append`, and have each one briefed
and built before the flags are enabled.
