change: Local rig on v0.1.0-rc.15 after W2: E1 passes (81s) and RB1 passes on Ubuntu and AlmaLinux; resilience L1 to L3 pass on all four Linux sprouts (12 pass, 0 fail). With the first rc.15 core run (65 pass, 4 skip), every core case is green except the written skips: T3, X5, N1 (standalone only), S6 clean re-enrol (no sprout delete route). Still not run: Windows, X3, HA, lifecycle, ingredients (Azure).
---
item: P13
action: update
rag: Green
next-append: **Rig rc.15 green (2026-10-20):** core and resilience pass on the local rig, W1 cases included (B1, E1, D1, U1, RB1; N1 skips by design). Remaining for the gate: Azure Run 2 (update path with dispatch and self-update flags on, Windows, X3) and Run 3 (HA).
