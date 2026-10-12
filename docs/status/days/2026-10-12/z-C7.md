change: P21 slice 2 PR 7 (C7): leftover sweep. `dropSelfMintedClaims` was already gone (slice 1 removed it); three stale comments that still described the bus resolver directory as a volume now say it is an emptyDir refilled by the loader (`internal/pki/busauth.go`, `cmd/farmerbus/cluster_integration_test.go`, `docs/loadtest.md`). No behaviour change. Flagged for security review.
pr: 222
item: P21
action: update
next-append: **Slice 2 PR 7 (C7), ready for review:** leftover persistence references on the bus side removed; the farmer side's remaining ones belong to C2 (slice 2 PR 2) and D9 (slice 3 PR 9).
