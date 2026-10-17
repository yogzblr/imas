change: S5: farmer and saasapi authenticate to Valkey as user `default` with a password the OpenBao bootstrap Job generates once (property `valkey_password` of the seed path, check-and-set, never overwritten), delivered by ESO as Secret `imas-valkey-auth` and mounted as a file only (`IMAS_VALKEY_PASSWORD_FILE`, `SAASAPI_VALKEY_PASSWORD_FILE`); the bundled Valkey and its replicas use the same Secret; `valkey.auth.enabled=false` renders only with `valkey.auth.allowInsecure=true`. The clients can use TLS (`*_VALKEY_TLS`, a CA from a ConfigMap, TLS 1.2 or later, never the system roots), the bundled Valkey runs `maxmemory-policy noeviction`, and both clients warn at startup when Valkey may evict (`internal/valkeyconn`). The UAT runs with the password (`saasapi-secrets.sh` delivers the Secret; `check.sh` checks NOAUTH without it). Ready for security review.
pr: 267
item: P3
action: update
next-append: **S5 built (2026-10-17):** Valkey password from OpenBao through ESO as a file, TLS in both clients, no eviction (`internal/valkeyconn`, farmer README "Valkey", `docs/OPENBAO-RUNBOOK.md` 5.6); item 3 of 3.5 updated with the accepted failover residual; flagged for security review.
---
item: P12
action: update
next-append: Since S5 (2026-10-17) the heartbeat keys sit behind Valkey's password and the bundled Valkey never evicts them; farmer and saasapi warn if a Valkey may.
