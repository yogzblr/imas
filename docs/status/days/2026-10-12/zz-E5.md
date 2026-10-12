change: E5 (P28): docs, CI, the natsapi flake and earlier reports. The 409 `recipe_write_conflict` body is in `docs/api/saasapi.md` and the OpenAPI spec, tied to the code by a test; the nats chart README's Seeds section names both DMZ seeds (the loader's always, the fence user's when clustered); CI's test job runs a PXC 8.4.8-8.1 service and sets `IMAS_TEST_MYSQL_ROOT_DSN`, and the MySQL tests (now through `internal/migrations/mysqltest`) fail instead of skipping when it is set but unreachable, and take a lease row so packages do not abort each other's DDL on PXC; `TestSealedShellReplayedHandshakes` waited too little (the sprout sends CLOSE before it drops the session from its count) and now waits for both ends, then checks the count after every replay (issue #142; `-race -count=20` passes); A1's `.json` path and A2's file list are clean on main; `compatibleFrom` stays (P21 slice 3's migrations only add tables; a MySQL test runs the previous releases' schema checks on the latest schema); a real-OpenBao test pins farmer's Transit capabilities per key name, and the farmer README records the accepted cross-client soft delete. Flagged for security review.
item: P28
action: update
next-append: **Built in E5 (2026-10-12), ready for review:** all five points closed (see the day's record); also the farmer Transit policy key-set test.
---
item: P14
action: update
next-append: **#142 (E5):** the cause is the test, not the replay guard: the sprout sends CLOSE before it drops the session from its count, so the count was read too early; the test now waits for both ends and checks the count after every replay. Closes when E5 merges.
---
item: P3
action: update
next-append: **E5 adds to the review scope:** `TestOpenBaoFarmerPolicyKeySet` pins what a farmer token may do on the Transit mount per key name; a farmer token can soft-delete any key on that mount without an exact deny (accepted, owner decision 2), recorded in `deploy/helm/farmer/README.md`.
