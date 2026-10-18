change: U2 (P3, P4): L24 fixed with tests. A join token is now `{key_id}.{secret}.{tenant_key_fingerprint}` (`internal/jointoken`; the fingerprint is the lowercase hex SHA-256 of the tenant box public key). saasapi reads the key from farmer over a new sealed request-reply subject, `internal.tenant.boxkey` (`a2f.tenant.boxkey`/`f2a.tenant.boxkey`, added to the SaaS API User's publish list), and mints no key without farmer's sealed answer (`503 farmer_unavailable`, `409 tenant_deprovisioned`); the response also carries `tenant_key_fingerprint`. The sprout checks the tenant key its first enrollment response names against the fingerprint before sealing its proof to it or pinning it (`ErrTenantKeyFingerprintMismatch`, not retried), and refuses a token without one unless `enrollpinrequired: false` (default true; the `imas_sprout_enroll_pin_required` role variable and `packaging/etc/imas-sprout.conf` match), which then warns at every enrollment. Farmer refuses a token whose fingerprint isn't the tenant's current key before redeeming it. Rotation is unaffected (a token is for a first enrollment; continuity proofs carry later keys). The loadtest, the UAT fake stack, harness and K1/K2, `uat/enroll`, the Molecule stub farmer and scenario and the self-update e2e mint or read the new token. Ready for security review.
pr: 282
item: P4
action: update
next-append: **U2 built (2026-10-18):** L24 fixed with tests (`internal/jointoken`, `internal/pki/enrollclient.go`, `enroll.go`, `internal/saasapi/tenant_boxkey.go`, `internal/natsapi/tenant_boxkey.go`): the join token carries the tenant key fingerprint and the sprout refuses a substituted key; its row in "Review findings re-checked" below is superseded.
---
pr: 282
item: P17
action: update
next-append: **U2 (2026-10-18):** L24 has tests: a substituted tenant key and a token without a fingerprint are refused before anything is pinned (`internal/pki/enrollpin_test.go`), farmer refuses a stale fingerprint without spending the token, `internal.tenant.boxkey` is sealed and bound both ways (`internal/natsapi/tenant_boxkey_test.go`, `internal/saasapi/tenant_boxkey_test.go`), the loadtest reports a substituted key, and the UAT K1/K2 scenarios check the token's fingerprint against the key enrolment names.
---
pr: 282
item: P3
action: update
next-append: **U2 adds to the review scope (2026-10-18):** the join token's tenant key fingerprint and the sprout's check of it (`internal/jointoken`, `internal/pki/enrollclient.go`), the new sealed subject `internal.tenant.boxkey` and its place in the SaaS API User's permissions (`internal/pki/saasapi_user.go`, `internal/natsapi/tenant_boxkey.go`), saasapi minting no key without farmer's sealed answer (`internal/saasapi/tenant_boxkey.go`), and the `enrollpinrequired` setting (`docs/security-review-pack.md` 3.5 item 6).
