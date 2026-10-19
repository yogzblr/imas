change: W1: UAT acceptance cases for the S, T and U fixes in the core tier (`uat/tests/hardening_test.go`): B1 (S3 backlog cap), E1 (S6 purge by the operator route and the sweeper), D1 (U4 retention, with Fluent Bit shipping now on in the UAT core hub), U1 (U3 sealed facts and step events), N1 (T6/L12, standalone only: skips on the hosted stack) and RB1 (S4 render budget). `uat/hub/core/acceptance.sh` is their view inside the hub, tested against real PXC, Valkey, RustFS and OpenBao containers; the core hub's values set the short settings (backlog 20, purge after 1h, 24h terminal rows, one day of recipe audit and logs), the chart defaults stay as shipped. All six pass against the fake stack; their first real run is the owner's next rig run. RB1 found a product bug (P29). `uat/lite/README.md` refreshed (status of the rc.14 rig run, `<latest rc>`, 304 checks); the kind node image pinned by digest.
pr: 293
---
item: P29
action: add
section: S3
title: **A cook refused before it reaches the sprout leaves its batch item `running` for ever** (found by W1's RB1)
rag: Amber
next: `internal/natsapi/cook.go` answers saasapi's `cook` with `dispatched` and a jid, then dispatches in the background, where a refusal (the per-cook render budget, S4; a missing include; a staging failure) is only logged. No `farmer.job_status` row is ever written, so saasapi keeps the item `running` and the batch `in_progress` for ever (docs/api/saasapi.md promises every item ends terminal). Decide the fix (resolve and stage before answering, or record a failed job row on a dispatch error), then UAT case RB1 passes on a deployed stack.
---
item: P13
action: update
next-append: **W1 (2026-10-19):** the UAT gate now has acceptance cases for S3, S4, S6, T6, U3 and U4 (B1, RB1, E1, N1, U1, D1; `uat/tests/README.md`, "The W1 cases"), green against the fake stack; the rig's next run is their first. The kind node image is pinned by digest.
---
item: P3
action: update
next-append: **W1 adds to the review scope (2026-10-19):** `uat/hub/core/acceptance.sh` (UAT only) reads the PXC root password, Valkey's password, the OpenBao root token and the RustFS root credential of a UAT hub over stdin and changes rows and objects the W1 cases made; the UAT core hub now ships logs with Fluent Bit (logShipping on in `uat/hub/core/values/farmer-uat.yaml`).
