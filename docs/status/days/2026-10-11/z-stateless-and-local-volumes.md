change: Owner decision: farmer, saasapi and the bus must be stateless (no PVC; state only in the replicated external services); stateful external services keep local volumes and rely on their own replication (P21, P24, design D10).
---
item: P21
action: update
next-append: **Stateless rule (owner, 2026-10-11, design D10): farmer, saasapi and the bus carry no PVC. The bus's Account JWT store (`NewDirAccResolver`, `/var/lib/imas/farmerbus`) must be rebuilt at start from the source of truth; decide the resolver mode (P23).**
---
item: P24
action: update
next-append: **Storage decided (owner, 2026-10-11): local volumes. Everything stateful (PXC, OpenBao, Valkey, object store) is replicated on its own; farmer, saasapi and the bus are stateless and carry no volume, so they reschedule to any node.**
