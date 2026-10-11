change: P21 slice 1 PR4b (unit B5): Transit cut-over in `internal/pki`: the farmer signs every NATS account and user JWT through OpenBao Transit (`natskeys`), reads the operator and SYS account JWTs from the trust directory, writes no operator, operator-signing, SYS account, tenant or tenant-signing seed, creates tenant keys only at provisioning and soft-deletes them after the offboarding lockout push; `farmer` checks trust and Transit at start-up (`pki.CheckNATSAuth`). Tests across pki, api, facts, heartbeat, natsapi, saasapi and saasapicred moved to the fake Transit (`pkitest.Farmer`). Flagged for security review.
pr: 210
item: P21
action: update
next-append: **Slice 1 PR4b (B5), ready for review:** farmer pki on Transit; the bus (PR5) and the charts (PR6) still use seeds until their PRs.
