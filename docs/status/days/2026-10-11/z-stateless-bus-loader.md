change: Owner decision: the bus is made stateless by a per-node account loader that reads Account JWTs from the object store (design D11, section 9.1); state inventory for the bus, farmer and SaaS API added (section 9.2); per-tenant locks use a row lease, not GET_LOCK.
---
item: P21
action: update
next-append: **Stateless bus (owner, 2026-10-11, design D11): per-node account loader from the object store, `emptyDir` resolver directory, readiness gated on the load; see design §9.1 and the state inventory in §9.2 (farmer: `localCooks`, hourly jobs, audit logs, rotation state; saasapi: `recipeTenantLocks`). Locks are row leases (`outbox_lease.go`), not `GET_LOCK` (node-local on PXC).**
---
item: P23
action: update
next-append: **Also prove (design §9.1 and §9.2): a bus node started empty becomes ready only after loading every account, a missed event is repaired by the timer, all bus nodes restarted with farmer down, `localCooks` survives a replica change, and the hourly jobs do not run twice.**
