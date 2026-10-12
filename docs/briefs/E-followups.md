# Follow-up units E1 to E5 and Z (P26, P27, P28)

These close every open point left by the P21 and P22 build (status items P26, P27,
P28). Read `docs/briefs/ORCHESTRATOR.md` first: the session prompt there (zero open
items, repo-wide search, no deferral) applies to every unit. Nothing here is left for
the owner to decide, except the security review (P3), which stays with the owner.

Facts below come from the unit PRs of the build (B8 #224, C6 #221, D2 #200, D4 #228,
D5 #212, D6 #213, D7 #219, D8 #223, D9 #225, F1 #227). A unit checks each fact against
main before using it; if one is wrong, the brief-correction rule applies.

## E1: make the UAT work after the stateless build (P26)

Scope: `uat/`, `deploy/farmer/`, `.github/workflows/uat.yml`, UAT docs.

1. UAT core OpenBao rejects the `file` storage backend (2.7.1). Replace it with
   single-node `raft` storage (path on the existing data volume, `node_id` fixed,
   `api_addr` and `cluster_addr` set to the pod's service addresses). Prove it by
   rendering the config and parsing it with the 2.7.1 image (`bao operator diagnose
   -config` or a 5-second `bao server -config` run in a container); if no container
   runtime is available in the session, state which static check you ran instead.
2. `uat/hub/core/values/farmer-uat.yaml`: set `objectStore.sproutJWTBucket` to the
   chart's default name for that bucket (read it from `deploy/helm/farmer/values.yaml`),
   make `minio-setup` (RustFS) create that bucket, and remove `farmer.persistence.size`.
3. Farmer NKey: `uat/hub/core/seeds.sh` creates Secret `imas-farmer-nkey` with key
   `farmer.nk` (a user seed generated the same way the script generates the other
   seeds); the chart reads it through `farmer.nkeySecret` (D4). Add the same Secret to
   `deploy/farmer/externalsecrets.yaml` and `deploy/farmer/farmer-deployment-nats-seeds.patch.yaml`.
4. Loader, core side: `seeds.sh` generates the loader user NKey; `natsTrust.busLoaderUserPub`
   is set from it in the UAT values; RustFS is reachable from the DMZ on its S3 port
   (design D22: the DMZ reads the core object store with a read-only credential scoped to the
   accounts bucket; open exactly that one NSG/NetworkPolicy path and no other DMZ-to-core
   path); `.github/workflows/uat.yml` passes `--loader-seed` and `--accounts-reader-dir`.
5. Recurrence guard: a CI step (or Go test) that renders both UAT hub values files with
   the farmer and nats charts and fails on any `fail` or missing required value. If one
   already exists, extend it to cover items 2 to 4.

Done when: both hubs render with their UAT values, the guard passes, and a search for
`file` storage, `farmer.persistence`, `farmer.nk`, `busLoaderUserPub`, `loader-seed`,
`accounts-reader-dir` finds no stale or missing use across `uat/`, `deploy/`, `docs/`
and workflows.

## E2: every package gets tenant connections from the registry (P27.1)

Scope: `cmd/farmer`, `internal/natsapi`, `internal/tenantconn`, and any other package
a search finds.

Decision: there is one source of tenant connections, `tenantconn.Registry.Get(ctx,
tenantID)`, which dials lazily. No package keeps its own `map[string]*nats.Conn` (or a
struct holding per-tenant connections). Replace each with a small interface
`type ConnGetter interface { Get(ctx context.Context, tenantID string) (*nats.Conn, error) }`
injected where the connection is needed (cook, sprout actions, audit, anything the
search finds), and call it on every use; never cache the returned connection across
requests. The error "not connected" must only come from a failed dial, never from a
missing map entry.

Search gate: `map[string]*nats.Conn`, `map[string]*natsConn`, `not connected`,
`tenantConns`, `connFor`, `getConn` across the repo; every hit is either removed or
justified in "Consumers updated".

Tests: with a fake `ConnGetter` that closes a tenant's connection (as the idle sweeper
does), a cook dispatch, a sprout action and an audit call for that tenant succeed by
redialing; a dial failure returns the dial error; two concurrent calls share one dial.

## E3: no local JWT or key files in farmer (P27.2)

Needs E2 and E6 merged. Scope: `internal/pki`, `cmd/farmer`,
`internal/config`, the file-write guard test.

Decision: farmer writes no file outside the process's temp directory for anything it must
find again. Per-tenant sprout JWT files written by `tenant.go`, account JWT copies and
the farmer's own user JWTs under `/tmp/farmer/pki` are removed: sprout JWTs live in the
object store (D5), account JWTs go through the publisher to the accounts bucket (C2),
and the farmer's own user JWT is signed at start-up and held in memory. Where a library
needs a file path, use a file created at start-up in `os.MkdirTemp` and rebuilt on every
start; nothing reads a file written by an earlier process.

Search gate: `/tmp/farmer`, `farmerpki`, `writeFileAtomic`, `FarmerPKI`, `os.WriteFile`,
`.jwt` across `internal/pki`, `cmd/farmer`, `internal/config`, charts and docs. Extend
the existing enforcing file-write guard (D9) so that any write under `/tmp/farmer/pki`
fails the test, and update the chart's `emptyDir` mounts that existed only for this.

Tests: two farmer replicas (two test processes with separate temp directories) mint,
re-sign and revoke for one tenant; each serves the other's results; killing one loses
nothing.

## E4: loadtest without trust seeds; sprout honours Retry-After (P27.3, P27.4)

Scope: `tools/loadtest`, `internal/pki/enrollclient.go`, the Envoy config in
`deploy/helm/nats` (the DMZ chart; the farmer chart has no Envoy config) and
the reference `deploy/envoy/`, the UAT DMZ render that uses the nats chart
(`uat/hub/dmz`), their tests and docs.

1. `tools/loadtest -servers` must run against a deployed bus with no private trust key.
   Replace the use of operator-signing and SYS seeds with the real enrolment path
   (one-time enrolment keys through the SaaS API, then the sprouts connect with the JWTs
   they receive). Remove the seed flags and update `docs/loadtest.md` and any UAT
   script that passes them.
2. `enrollclient.go`: on a 503, wait the `Retry-After` seconds (default 5 when absent or
   invalid, cap 60), with jitter of up to 20 percent, retry up to the existing attempt
   limit, and log "server busy (lease held), retrying in Ns" instead of the token or
   clock message.
3. Envoy: on the enrolment and sprout-JWT routes, do not retry 503 at the proxy
   (`retry_on` must not include `5xx` or `retriable-status-codes` for 503 there), so the
   client sees `Retry-After`. Change the Envoy config in the chart and in `uat/`; add a
   chart test that asserts it.

Tests: a fake enrol server returning 503 with and without `Retry-After`; chart test for
the Envoy route; loadtest builds and its unit tests pass without seed flags.

As built (corrections, E4): the Envoy routes are in the nats chart
(`templates/envoy-configmap.yaml`, `_helpers.tpl`) and `deploy/envoy/`; the UAT
has no Envoy config of its own for these routes (the DMZ hub renders the nats
chart; the core edge proxies farmer's API over TCP, which never retries an HTTP
answer), so the UAT check is a test on the DMZ render. Both routes carry an
explicit `retry_on: connect-failure,refused-stream` (one retry of a request that
never reached farmer). "The existing attempt limit" is `enrollStep2Attempts` (5).
"One-time enrolment keys" is the default (`-enroll-key-uses 1`); a larger value
is allowed because key minting is rate-limited per tenant. Without a trust key
the harness has no User that may send `test.ping` to a sprout, so against a
deployed bus its latency probe is the sprouts' own bus round trip (NATS
PING/PONG), and it reads no bus varz (no SYS user); `docs/loadtest.md` says so.

## E5: docs, CI, the flake and earlier reports (P28)

Needs E1 (both edit `uat.yml`). Scope: docs, workflows, `internal/natsapi` tests,
`internal/migrations`.

1. Add `409 recipe_write_conflict` (when it is returned, the body) to
   `docs/api/saasapi.md` and `saasapi-openapi.yaml`.
2. Fix the stale comments in `.github/workflows/uat.yml` (around lines 13 and 306),
   `uat/lite/README.md` (around line 230) and the Seeds section of
   `deploy/helm/nats/README.md` so they describe the current trust and seed model.
3. CI runs the MySQL-gated migration and lease tests: add a MySQL-compatible service to the
   CI workflow (use the Percona image already used elsewhere in this repo's workflows or
   charts; if none, `percona/percona-xtradb-cluster:8.0`), set `IMAS_TEST_MYSQL_ROOT_DSN`
   for the test job, and make the gated tests fail, not skip, when the variable is set but
   the database is unreachable.
4. Fix the `internal/natsapi` flake (`TestSealedShellReplayedHandshakes` and the tests that
   fail with it). Find the cause (shared state, ordering, a port, a timing assumption),
   fix it in the test or the code, and prove it with `go test -race -count=20 ./internal/natsapi`
   passing; do not add skips or retries.
5. Earlier reports: open PR #203 (A1) and PR #205 (A2) descriptions; for the `.json`
   breakage A1 reported and the out-of-scope files A2 listed, confirm on main that each
   is fixed, and fix any that are not. For D2 (#200) decide whether `compatibleFrom` in
   `internal/migrations` must change: it must if an older binary cannot run against the
   new schema (farmer 00004 to 00005 and saas 00008); write the reasoning in the PR and
   the code comment next to `compatibleFrom`, and change it if required.

6. Farmer Transit policy test. OpenBao 2.7.1 cannot deny under the tenant-key glob, so
   the merged policy (decision 2, #215) lets a farmer token create and soft-delete any key
   on the transit mount that an exact deny does not cover, including keys other clients keep
   there. That is an accepted cost and goes to the security review (P3). Make it
   visible and fixed in place: add a real-OpenBao policy test that lists the key names a farmer
   token can create, soft-delete and sign with, asserts the exact set the merged policy allows
   (signing only `nats-tsign-*`; no rotate, no config, no export, no hard delete; exact denies on
   the platform and gateway keys), and fails if the policy changes that set. Put the accepted
   cross-client soft-delete behaviour in `deploy/helm/farmer/README.md` next to the policy.

## E6: finish C2, the farmer account publisher (P21)

C2 (PR 229) merged with five things left open. Close each one. Scope: `internal/pki`,
`cmd/farmer`, `internal/inventory`, `deploy/helm/farmer`, `internal/config`, docs.

1. Same-second re-sign in `internal/pki/enroll.go`: `grantEnrolledSprout` re-signs the
   Account JWT without waiting for a strictly newer iat, so a re-sign in the same second
   has the same jti, and the loader can treat the new JWT as the one it already holds
   (the grant is not applied). Call `waitPastIssuedAt` on the JWT being replaced before
   its `Encode`, as the other re-signs do. Search every `Encode(` of an Account JWT in
   `internal/pki` (`jwtauth.go`, `jwtusers.go`, `tenant.go`, `saasapi_user.go`, `enroll.go`,
   `nats.go`) and make every one wait; add a test that fails for any that does not
   (`TestEveryResignAdvancesIat` already exists: extend it to cover `enroll.go`).
2. No write hook (brief 7.2). The brief's `persistAccountJWT` hook is not built, because
   farmer mints a minimal Account JWT at boot and publishing it would put an un-revoked
   JWT in the bucket. Decision: the publish point stays `pushAccountUpdate` (every
   JWT that reaches the bus passes through it), and the invariant is made explicit and tested:
   `TestNoAccountJWTReachesBusWithoutPublisher` fails if any code path calls the NATS claims
   update directly instead of `pushAccountUpdate` (search gate: `CLAIMS.UPDATE`). Correct
   brief 7.2 in `docs/briefs/P21-slice2-bus-loader.md` to describe what was built, and say
   in a code comment on `pushAccountUpdate` why minimal boot mints are not published.
3. No silent fallback. With the bus stateless, a farmer with no accounts bucket loses
   every account when a bus node restarts. Decision: farmer refuses to start (exit with a clear
   error) when the bus URLs are configured and the accounts store is not, except in the
   existing in-process test/dev seam; the farmer chart fails to render when `accountStore.bucket`
   or its endpoint (own or `objectStore.endpoint`) is empty. Update the chart README, the UAT
   and CI values that relied on the fallback (search `accountStore`, `IMAS_ACCOUNTS_`).
4. Metrics. Decision: no new metrics system in this phase. Keep `farmer_account_push_missing_nodes`
   as a structured log field and add the same for `farmer_account_bucket_write_failed`; document
   both log fields in `deploy/helm/farmer/README.md` so the log platform can alert on them
   (Fluent Bit ships them, D16). Remove "Prometheus metrics" from any brief or doc that
   promises them for the publisher.
5. `internal/pki/nats.go`: `seedResolverFromCore` still uses `resolverStoreDir()`, a per-process
   directory used only by the test bus. Replace it with a directory from `os.MkdirTemp` created
   per call and removed on close, add the single allow-list entry in
   `internal/inventory/nofilewrites_test.go` that the guard needs, and delete the C7 leftover
   comment.
6. Objects have no Content-Type (`objectstore.Put` takes none and the loader never reads it).
   Decision: leave as is and say so in the `accountpublisher.go` doc comment; nothing else.

Done when: the search gates above are clean, the new and extended tests pass under `-race`,
both chart renders and the UAT render pass, and the brief and docs match the code.

## Z: final gate, nothing left open

Needs every other unit merged. Do not write features. On main:

1. `go build ./...`, `go vet ./...`, `go test -race ./...`, `CGO_ENABLED=0 go build ./...`
   all pass; `helm template` passes for every chart with every ci and uat values file;
   `scripts/status/rollup.py --check` passes.
2. Search the repo for `TODO`, `FIXME`, `not yet implemented`, `follow-up`, `deferred`,
   `report-only`, `persistence`, `volumeClaimTemplates`, `seeds` in the P21 and P22
   areas; fix or remove every hit that is stale.
3. Check the end-to-end claims the build made, with tests or rendered output: a bus node
   started empty loads every account from the object store; farmer writes the account
   object that the loader reads; sprouts enrol through two farmer replicas without
   duplicate JWTs; a fleet update verifies through the GPG checksums path.
4. Write the status fragment that closes P26, P27, P28 and sets P21 and P22 to the state
   the evidence supports (Green only with passing evidence).
5. PR body: Verified lists every command and its result. Anything that cannot be verified
   here is not a defect to list; if a check could not run, find another way to run it.
