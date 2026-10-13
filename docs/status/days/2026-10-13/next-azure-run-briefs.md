change: Briefs written for the next Azure runs: R1 (Run 2, single-node re-run with the fleet-update path on) and H1 to H6 (Run 3, HA on 3 + 3 nodes with Versity over Azure Blob). Owner decisions recorded in the brief.
---
item: P24
action: update
next-append: **Brief (2026-10-13):** `docs/briefs/H-azure-next-runs.md` units H1, H2, H4. HA run uses Versity over Azure Blob; error windows decided (pod kill: 3 retries, sprouts back in 30 s; node stop: served within 60 s). Core nodes D4s_v5, DMZ D2s_v5; request 18 Dsv5 vCPU plus the 12 B2ls_v2 vCPU.
---
item: P23
action: update
next-append: **Brief (2026-10-13):** unit H5, the `ha` test tier (HA1 to HA5, T1 to T8 mapped).
---
item: P25
action: update
next-append: **Split (2026-10-13):** the Versity Gateway chart component (unit H3) comes first because the HA run needs it; Fluent Bit shipping stays open.
---
item: P20
action: update
next-append: **Brief (2026-10-13):** unit R1 (operator plane on in UAT, no `fleetreleaser`, release registered and verified, `dispatch_flags` turns the flags on).
