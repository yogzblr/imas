change: E1 (P26): the UAT works with the stateless build. Core OpenBao uses single-node raft (2.7.1 has no `file` backend; checked with the 2.7.1 image); `farmer-uat.yaml` sets `objectStore.sproutJWTBucket` (`imas-sprout-jwts`, created by `minio-setup.sh`) and drops `farmer.persistence`; `seeds.sh` creates Secret `imas-farmer-nkey` (`farmer.nk`) and the DMZ bus loader's seed, whose public key becomes `natsTrust.busLoaderUserPub`; RustFS is a hostPort (9000) open to the DMZ private address only (NetworkPolicy, NSG `accounts_store_port`, k0s host port list); `uat.yml` and the lite rig pass `--loader-seed` and `--accounts-reader-dir`; `deploy/farmer/` references carry `imas-farmer-nkey`. Guard: Go tests render both UAT hubs' values and fail on a stale or unknown key, a missing bucket, a non-raft OpenBao config or a NOTES warning. Flagged for security review.
pr: 234
---
item: P26
action: update
rag: Amber
next-append: **Built in E1 (2026-10-12):** all four points fixed; the stale comments P28 (2) names in `uat.yml` (lines 13 and 306) and `uat/lite/README.md` (line 230) were rewritten with it. Closes when E1 merges and the UAT gate runs.
---
item: P3
action: update
next-append: **E1 adds to the review scope:** the UAT core RustFS is reachable from the DMZ private address on 9000 (hostPort, NetworkPolicy, NSG), for the bus loader's read-only accounts credential (design D22); the loader's seed is a file in the run's sensitive state, copied to the DMZ only.
