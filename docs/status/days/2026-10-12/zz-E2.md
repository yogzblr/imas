change: E2 (P27.1): every package gets tenant connections from the registry. `natsapi`, `cook` and the `cmd` and `test` ingredients keep no per-tenant connection map; cmd/farmer hands them the `tenantconn.Registry` as a `tenantconn.ConnGetter` and each calls `Get` on every use, so a tenant whose connection the idle sweeper closed is dialled again by its next cook, sprout action or API call. "Not connected" now only comes from a failed dial. The registry's `OnDrop` hook is gone. Flagged for security review.
pr: 233
item: P27
action: update
next-append: **(1) built by E2, ready for review:** dispatch to an idle-closed tenant redials through `tenantconn.Registry.Get`; no package keeps its own connection map.
