change: P21 slice 3 PR 2 (D2): farmer migrations 00004 (`job_leases`, seeded `jobs_expiry` and `cohort_refresher`) and 00005 (`sprout_user_jwt`, keyed on `(tenant_id, sprout_id)`), saas migration 00008 (`saasapi_credential_state`, one row); no `prepared_cooks` migration (owner decision 2). Expand only; compatibility floors unchanged.
---
item: P21
action: update
next-append: Slice 3 state tables migrated (D2): farmer 00004 and 00005, saas 00008. Saas 00007 (P22 slice 2) must be applied before 00008 reaches any install, or goose refuses it as out of order.
