change: P21 slice 1 PR2 (unit B2): NATS trust model in `internal/pki/natstrust.go` (parse, load from the trust dir, bootstrap without replacing an anchor, verify against Transit) and the `internal/pki/pkitest` test helper. Flagged for security review.
pr: 204
item: P21
action: update
next-append: **Slice 1 PR2 (B2), ready for review:** trust model and `pkitest` built; nothing uses them yet (PR3 bootstrap subcommand, PR4b farmer cut-over).
