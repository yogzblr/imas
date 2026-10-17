change: T5: the OpenBao clients talk to the configured host only. Every request, a followed redirect included, goes to the scheme, host and port of the address or is refused before anything is sent (`openbao.PinTransport`; at most one redirect, same host), on farmer, saasapi's Jobs, the bus and the sprout (L17); the kubernetes login client is built without the environment, so `BAO_NAMESPACE`/`VAULT_NAMESPACE` never reach a login and a malformed `BAO_*` no longer stops startup (L18); only a 2xx is success, so an unfollowed 3xx is a `*StatusError` and `tenantbox` writes only on a 2xx (L19); the sprout drops its cached OpenBao token when the client certificate reloads (`CertWatcher.OnReload`, L20); `sdb://openbao` refs and the KV writer's paths are checked segment by segment (no `.`, `..`, empty segment, leading `auth`/`sys`/`identity`, percent-encoded or not; `openbao.ValidatePath`, L21); an `http://` address is refused unless `<prefix>OPENBAO_ALLOW_INSECURE` / `IMAS_SDB_OPENBAO_ALLOW_INSECURE` is true, set by `openbaoClient.allowInsecure` (implied for the bundled dev-mode OpenBao) and `bus.tls.openbao.allowInsecure`; the UAT sets it (I2). Ready for security review.
item: P4
action: update
next-append: **T5 built (2026-10-17):** OpenBao client findings L17, L18, L19, L20, L21 and I2 fixed with tests (redirect to a recording second server, the kubernetes ambient-variable test, an unfollowed 308 on a tenant box write, a certificate rotation under a running provider, encoded `..` and reserved refs, `http://` refused naming the key).
---
item: P3
action: update
next-append: **T5 adds to the review scope (2026-10-17):** the OpenBao host pin and path checks shared by farmer and the sprout (`internal/openbao/guard.go`), the `*_OPENBAO_ALLOW_INSECURE` override and when the farmer chart sets it (the bundled dev-mode OpenBao implies it), and the sprout's token drop on a certificate reload.
---
item: P17
action: update
next-append: **T5 (2026-10-17):** the L20 test (`rotation_test.go`) now rotates with no manual token drop and fails unless the reload drops the token; the I2 tests that pinned `http://` being accepted set `*_OPENBAO_ALLOW_INSECURE=true`, and new tests pin the refusal.
