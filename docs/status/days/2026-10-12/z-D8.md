change: D8 (P21 slice 3 PR 8): farmer's per-tenant bus connections are lazy, reconnect forever and close when idle. A tenant connects on first need (boot only for tenants with accepted sprouts, a client CONNECT into its Account on every replica, provisioning, or its connection closing), once per tenant under concurrent callers; `MaxReconnects(-1)` replaces the 30-attempt limit; a connection unused for `IMAS_TENANT_CONN_IDLE_TTL` (10m) with no sprout heartbeat for `IMAS_TENANT_CONN_HEARTBEAT_WINDOW` (15m, owner decision 3) is closed. The legacy tenant stays open. Chart values for the two env vars are left to D9. Flagged for security review.
pr: 223
item: P21
action: update
next-append: **Slice 3 PR 8 (D8), ready for review:** tenant bus lazy connect, reconnect forever, idle close.
