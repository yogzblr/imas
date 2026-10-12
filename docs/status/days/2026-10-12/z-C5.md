change: P21 slice 2 PR 5 (C5): integration tests for the five account loader scenarios (`cmd/farmerbus/loader_integration_test.go`): real bus nodes with real loaders over the fake S3 bucket, the loader connecting as the bootstrap-shaped SYS user (exactly `pki.BusLoaderUserPermissions`). Covers readiness only after a full load, a missed event repaired by the timer, a stale object never applied, a revoked sprout refused on every node, and all nodes restarting on empty resolvers with farmer down. Flagged for security review.
pr: 217
item: P21
action: update
next-append: **Slice 2 PR 5 (C5), ready for review:** loader integration tests for the five scenarios (`go test ./cmd/farmerbus -run Loader`); the test plays farmer because the publisher (PR 2) is not merged yet.
