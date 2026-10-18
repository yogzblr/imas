change: T2: the imas CLI creates its config file (it holds the NKey private key) 0600 in a 0700 directory from the first byte: `O_CREATE\|O_EXCL` 0600 under a temporary name, then an atomic rename, before the loader runs; `imas init` rewrites it the same way (issue #139, `cmd/imas/cmd/configperm.go`). `TestItemErrorCodesDocumented` derives the stored item error codes from saasapi's source and compares them both ways with `actionErrorMessages`, the OpenAPI enum and `docs/api/saasapi.md`. New tests: farmer redials a tenant after the NATS client gives up on its connection; the purge's minimal lock-out is issued after the lock-out it replaces. BSD-2-Clause, BSD-3-Clause, ISC and 0BSD recorded as allowed under `requirements.md` item 21, `DEPENDENCIES.md` matches. Ready for security review.
pr: 272
item: P14
action: update
next-append: **#139 (T2, 2026-10-17):** the CLI creates the file 0600 in a 0700 directory before the loader runs (`ensureConfigFile`: `O_CREATE\|O_EXCL` 0600, atomic rename) and `imas init` rewrites it through a 0600 temporary file (`writeConfigFile`); tested under umask 0 with a hook that checks the mode at every step. The issue closes when T2 merges.
---
item: P17
action: update
next-append: **T2 (2026-10-17):** `TestItemErrorCodesDocumented` derives the codes saasapi stores from its source (every `errCode*` constant and what `farmerErrorCode` passes through) and compares them both ways with `actionErrorMessages`, the OpenAPI enum and the saasapi.md section; farmer's redial after the NATS client gives up is tested (`cmd/farmer/tenantredial_test.go`); the iat re-sign gap is closed (below, P4). Left with other units: L5, I5 (T1), the heartbeat race and Valkey Cluster (T3), and the tests pinning L12 (T6) and L20 (T5).
---
item: P8
action: close
---
item: P4
action: update
next-append: **Recheck (T2, 2026-10-17):** B4 closed by S4 (`f26f854`, PR 266: per-cook render budget and include cap). B5/M6 closed: every Account re-sign waits for a strictly newer `iat` since C2 (`5f4858b`, PR 229) and E6 (`aa1dd69`, PR 232), guarded by `TestEveryAccountResignWaitsPastIssuedAt` and tested by `TestEveryResignAdvancesIat`, which T2 extends to the purge's minimal lock-out (S6). B6 accepted (owner, PR #97). B8 is T1's.
