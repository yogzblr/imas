change: T6 (security review 2026-10 L12, L13, L14): farmer's new `enrollment` setting (default true, always true in the Helm chart) keeps the legacy unauthenticated `PUT /pki/putnkey` unregistered; with it off (standalone) the route needs the NKey's signature over a single-use nonce (`GET /pki/nkeynonce`), and no Account rebuild revokes an NKey another row of the tenant has accepted. The bus logs no nats-server debug or trace (payloads) unless `IMAS_BUS_LOG_LEVEL` is `debug` or `trace` (default `info`; the chart never sets it). A single-node bus refuses every client but its account loader, and reports not ready, until the loader has loaded the SYS account (`IMAS_BUS_LOADER_READY_URL`). The SaaS API User JWT expires after 24h (`IMAS_SAASAPI_USER_JWT_TTL`, Helm `credentialPublisher.userJWTTTL`) and a new refresh CronJob re-publishes it once a third is left. Ready for security review.
item: P4
action: update
next-append: **T6 built (2026-10-17):** L12, L13 and L14 fixed in code with tests (`internal/api`, `internal/pki/nkeynonce.go`, `cmd/farmerbus` `loglevel.go` and `sysgate.go`, the publisher's refresh CronJob); flagged for security review.
---
item: P3
action: update
next-append: **T6 adds to the review scope (2026-10-17):** the proof of possession on the legacy `PUT /pki/putnkey` (standalone installs only); the single-node bus gate admits loopback clients (its account loader) before the SYS account is loaded; the SaaS API credential publisher now also runs as a CronJob under the same ServiceAccount and OpenBao roles, every 4 hours.
