change: Brief S6 written (docs/briefs/S6-tenant-erasure.md): automatic and operator-triggered erasure of an offboarded tenant's data after a retention delay, keeping a tombstone. P3 section 3.6 walked through with the owner.
item: P3
action: update
next-append: **Walkthrough (2026-10-17, owner):** 3.6 confirmed against the code (tenant keying, recipe scoping and sandbox, deprovision race and the fence hold). The finding that offboarding erased no tenant data became brief S6 (default 30 days retention, operator purge route, tombstone kept). 3.7 is open.
