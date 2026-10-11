change: Owner decision: horizontal scale validation (P23) is a showstopper for production; validating 1M endpoints is not possible and not a showstopper (P5 moved to Medium). P21 moved into the new S1c section.
---
item: P5
action: close
---
item: P5
action: add
section: S3
title: **1M-endpoint and latency numbers** (not a showstopper)
rag: Amber
next: The 1M figure and the 300 ms target cannot be measured on the rig (a few hundred to about two thousand simulated sprouts) or on the six-VM Azure gate, so they are not planned (owner, 2026-10-11). Instead: measure the per-node cost (connections per bus node, enrolment rate, request latency) at the rig's scale, size the 1M deployment from those figures and the scale plan (about 100k connections per bus node), and write down what is extrapolated. Add the PXC and Valkey failure tests only as far as our code's handling goes (design D7). A real large-scale run is left to a separate scale environment if one is ever built. The code gaps that used to sit here moved to P23.
---
item: P23
action: add
section: S1
sub: S1c
title: **Horizontal scale validation** (showstopper for production)
rag: Red
next: Show that the code we build scales out. Run several replicas of farmer (at least 3), the bus (add and remove nodes) and the SaaS API on the rig (kind, on WSL2 or Linux), with PXC, Valkey, OpenBao and the object store treated as external services that behave as their documentation says (design D7). Prove: no divergence or duplicate keys between farmer replicas (per-tenant lock, mint-or-reuse), every bus node holds every Account JWT, sprouts reconnect through jitter without a storm when a node is added or removed, a rolling restart keeps enrolled sprouts connected, and nothing is lost when one replica dies mid-enrolment. Includes the code fixes from the old P5: core pushes Accounts to every bus node and waits, farmer's per-tenant bus connection reconnects after 30 failures (`maxFarmerReconnect`, `ClosedHandler`), a sprout whose User JWT is refused twice recovers, and the resolver mode is decided. Depends on P21 (state off the PVC, `replicaCount` 1 rule removed). Tests T1 to T8 in `docs/design/imas-openbao-signing-design.md` §11.
