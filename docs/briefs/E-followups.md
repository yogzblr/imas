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

Needs C2 (the account publisher) and E2 merged. Scope: `internal/pki`, `cmd/farmer`,
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
`deploy/helm/farmer` and `uat/`, their tests and docs.

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
