change: S2: the audit log redacts in `audit.Logger.Log`: free-form methods (`cmd.run`, `cook`, `props.set`, `shell.open`, `auth.users.add`, `auth.users.resetkey`, `auth.rotatekey`) log only size, SHA-256 and key names; other params and the error text have secrets masked (key words at any depth; JWT, PEM private key, NATS seed, AKIA, bearer, URL userinfo, name=value via masq); params not JSON or over 1 MiB log size and hash only. Ready for security review.
pr: 262
item: P3
action: update
next-append: **S2 built (2026-10-17):** no secrets or passwords in the audit log (`internal/audit` redact.go; `deploy/helm/farmer/README.md` "What the audit log never contains"); flagged for security review, item 6 of 3.3 stays open until reviewed.
