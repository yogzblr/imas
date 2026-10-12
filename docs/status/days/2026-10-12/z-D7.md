change: D7 (P21 slice 3 PR 7): farmer's background jobs run under `farmer.job_leases` row leases (`lease.Run`): the job reaper (`jobs_expiry`) and cohort refresher (`cohort_refresher`) run once per interval across replicas, and `PushAllAccounts` pushes each tenant under `pushall:<tenant_id>` with a 60s minimum interval. saasapi's `recipeTenantLocks` is gone: recipe PUTs are optimistic (re-read and retry a lost compare-and-swap 3 times, then 409 `recipe_write_conflict`). The SaaS API cook prepares and dispatches in one call; `localCooks` is gone. Flagged for security review.
pr: 219
item: P21
action: update
next-append: **Slice 3 PR 7 (D7), ready for review:** job leases, optimistic recipe writes, one-call SaaS API cook.
