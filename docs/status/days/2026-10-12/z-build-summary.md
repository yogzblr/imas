change: P22 and P21 built by hosted sessions: 25 of 26 units merged (tracking issue 197); C2, the farmer account publisher, is still building. Open points from the build are recorded as P26 to P28.
---
item: P22
action: update
rag: Amber
next-append: **Built (2026-10-12): A1 #203 and A2 #205 merged.** Waiting on the security review (P3) and on the first release signed and registered end to end.
---
item: P21
action: update
rag: Amber
next-append: **Built (2026-10-12), tracking issue 197: 25 of 26 units merged (B1 to B8, C1 and C3 to C7, D1 to D9, plus follow-ups F1 and #216, #218, #220, #226).** Left: C2, the farmer account publisher (not yet a PR). Until C2 merges the bus loader reads the accounts bucket but farmer does not write it, so bus account delivery does not work end to end. Owner decisions made during the build: decision 2 farmer Transit policy as merged in #215 (accepted cost: farmer can create a Transit key of any name; it signs only with `nats-tsign-*`); the loader SYS user also gets publish on the claims lookup subject; the trust ConfigMap is `imas-nats-trust`; the bus keeps the fence user; the trust bootstrap mints the loader SYS user JWT; the farmer NKey is its own Secret `imas-farmer-nkey`. Follow-up work is P26 to P28.
---
item: P23
action: update
next-append: **Unblocked by the P21 build (2026-10-12) except for C2.** The validation tests can be written against main once C2 merges; P27 lists code gaps they will hit.
---
item: P3
action: update
next-append: **Added to the review scope (2026-10-12):** the P21 build as merged (no unit PR was described as safe to merge). Specific points: farmer can create a Transit key of any name on the transit mount (B7, decision 2); the bus loader can read the bus TLS private key in OpenBao TLS mode (C6); the UAT bootstrap uses a short-lived root-policy token per run instead of a quorum root token (B8, UAT only).
---
item: P26
action: add
section: S1
sub: S1a
title: **UAT does not work after the stateless build**
rag: Red
next: Fix in one UAT follow-up. (1) UAT core OpenBao 2.7.1 rejects the `file` storage backend and will not start; use single-node raft (reported by B8). (2) `uat/hub/core/values/farmer-uat.yaml` sets no `objectStore.sproutJWTBucket`, so enrolment fails, and it still sets the ignored `farmer.persistence.size` (D9). (3) No farmer NKey Secret: create `imas-farmer-nkey` with key `farmer.nk` in `uat/hub/core/seeds.sh`, and add it to the reference manifests in `deploy/farmer/` (`externalsecrets.yaml`, `farmer-deployment-nats-seeds.patch.yaml`) (D4). (4) Core side of the loader: generate the loader NKey, set `natsTrust.busLoaderUserPub`, expose RustFS to the DMZ (ClusterIP today), pass `--loader-seed` and `--accounts-reader-dir` in `.github/workflows/uat.yml` (C6, B8).
---
item: P27
action: add
section: S1
sub: S1c
title: **Stateless build leftovers that break scale-out or operation**
rag: Amber
next: (1) Dispatch to an idle-closed tenant: packages with their own per-tenant connection maps (`natsapi`, cook, `cmd`) do not call `Registry.Get` when a connection is missing, so dispatch fails with "not connected" until a client reconnects or a heartbeat arrives (D8). (2) Local JWT writes: `tenant.go` still writes per-tenant sprout JWT files, and farmer still writes account JWT copies and its own user JWTs under `/tmp/farmer/pki`; these are per replica and lost on restart (D5, D9). (3) `tools/loadtest -servers` still needs operator-signing and SYS seeds that a deployed bus no longer has (B8). (4) The sprout client ignores `Retry-After` on a 503 from the sprout JWT lease and logs a misleading token or clock message (`internal/pki/enrollclient.go`); check Envoy's 5xx retry policy on those routes (F1).
---
item: P28
action: add
section: S3
title: **Docs, CI and hygiene after the P21 and P22 build**
rag: Amber
next: (1) `409 recipe_write_conflict` is missing from `docs/api/saasapi.md` and `saasapi-openapi.yaml` (D7). (2) Stale comments: `.github/workflows/uat.yml` lines 13 and 306, `uat/lite/README.md` line 230, and the Seeds section of `deploy/helm/nats/README.md` (B8). (3) CI does not run the MySQL-gated migration and lease tests; no workflow sets `IMAS_TEST_MYSQL_ROOT_DSN` (D2, D6). (4) Recurring flake in `internal/natsapi` (`TestSealedShellReplayedHandshakes` and similar): one failure in a full `go test ./...`, passes alone. (5) Earlier reports with no follow-up: A1's out-of-scope `.json` breakage, A2's large out-of-scope file list, and D2 did not bump `compatibleFrom`.
