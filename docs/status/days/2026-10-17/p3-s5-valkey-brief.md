change: Brief S5 written (docs/briefs/S5-valkey-hardening.md): a Valkey password from OpenBao through ESO, TLS in the farmer and saasapi clients, no eviction. P3 section 3.5 walked through with the owner.
item: P3
action: update
next-append: **Walkthrough (2026-10-17, owner):** 3.5 confirmed against the code (enrol binding, revoked gateway JWTs, Envoy routes hold; replay cache TTL covers the window and fails closed on Valkey errors). Item 4 accepted as is: the deadlock retry covers the first-key write, the rotation, replace and delete transactions fail closed without it. The unauthenticated Valkey became brief S5; the async-replication failover residual is recorded. 3.6 and 3.7 are open.
