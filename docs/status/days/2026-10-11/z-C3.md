change: P21 slice 2 PR 3 (C3): account loader `internal/accountloader` and the `farmerbus-loader` sidecar binary (start-up load gated readiness, event plus timer reconcile, newest-wins push with re-read, read-only credential self-check), shipped in the farmerbus image by goreleaser. Flagged for security review.
pr: 208
item: P21
action: update
next-append: **Slice 2 PR 3 (C3), ready for review:** `internal/accountloader` and `cmd/farmerbus-loader` built and packaged in the farmerbus image; nothing runs it yet (PR 6 adds the sidecar to the chart).
