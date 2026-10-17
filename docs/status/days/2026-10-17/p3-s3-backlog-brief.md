change: Briefs S3 and S4 written (docs/briefs/S-hardening.md). S3: higher dispatch defaults and a `backlog_full` refusal when a tenant's pending action items exceed a cap. S4: a per-cook render budget (review finding B4). P3 section 3.4 walked through with the owner.
item: P3
action: update
next-append: **Walkthrough (2026-10-17, owner):** 3.4 confirmed against the code (items 1 to 4 hold; item 5 residuals accepted: "no responders" re-run up to the attempt limit, same-second Account JWT iat tie; the staged-recipe replay residual, a compromised DMZ serving an older genuine recipe within the one-hour window, is recorded). The action backlog finding became brief S3; the per-cook render budget (item 6, B4) became brief S4, which starts after S3. 3.5 to 3.7 are open.
