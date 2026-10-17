# S5: Valkey authentication, TLS in the clients, no eviction

Read `docs/briefs/ORCHESTRATOR.md` first: its session prompt (zero open items,
repo-wide search, brief errors decided by a fixed order) applies. Source: P3
walkthrough 3.5 item 3 (`docs/security-review-pack.md`), owner decision
2026-10-17. Needs: S4 (S3 and S4 also edit `deploy/helm/farmer` values, README
and `chart_test.go`; S5 starts after S4 is merged to avoid conflicts).

Owner decisions (2026-10-17), final:

- Farmer and saasapi authenticate to Valkey with a password the platform
  generates and keeps in OpenBao; it reaches the pods as a file through the
  External Secrets Operator (ESO), the same way farmer's NKey seed does. It is
  never an environment variable, a Helm value or a ConfigMap.
- The clients can use TLS to Valkey and verify the server with a CA from a
  ConfigMap (public data, like S1). The bundled Valkey gets TLS only if its
  chart supports it; the production Valkey is external and is expected to use
  TLS.
- Valkey must not evict keys: the replay cache and the heartbeat keys are
  security state.
- Accepted residual, to be documented: Valkey replication is asynchronous, so a
  failover can lose the most recent claims. Impact is bounded to the 6-minute
  claim window and to the replay path (no gateway JWT without a separately
  claimed box-key proof).

## Why

The replay cache (`internal/pki/replaycache.go`, `sealedclaim.go`) is what makes
enrolment, refresh and sealed messages single-use, and the heartbeat keys say
which sprouts are online. Today the clients connect with no password and no TLS
(`valkey.ClientOption{InitAddress: ...}` in `cmd/farmer/main.go` and
`cmd/saasapi/main.go`), so anyone who can reach Valkey on the network can delete
claims (a replay) or pre-claim keys (lock a sprout out). The farmer README says
"Neither client does auth or TLS yet".

Scope: `cmd/farmer/main.go`, `cmd/saasapi/main.go`, `internal/config`,
`internal/saasapi/config.go`, `deploy/helm/farmer` (templates, values, README,
ESO templates, bootstrap Job, `chart_test.go`, network policy), `deploy/saasapi`,
`uat/` (hub scripts and values), `docs/`.

Facts on main (2026-10-17), verify first:

- Two clients: `initValkeyClient` (farmer; client-side caching on) and saasapi
  (`DisableCache: true`, only when `SAASAPI_VALKEY_ADDRS` is set). Addresses come
  from `IMAS_VALKEY_ADDRS` and `SAASAPI_VALKEY_ADDRS`.
- The chart has `valkey.enabled` (bundled `valkey-io/valkey-helm` 0.12.0,
  standalone) and `valkey.addrs` (external). The UAT HA values use the chart's
  replicated mode. `uat/tests/harness/ha.go` already passes `VALKEY_PASSWORD` to
  `valkey-cli` when set.
- Farmer's NKey seed is the pattern to copy: an `ExternalSecret`
  (`deploy/helm/farmer/templates/externalsecrets.yaml`), its Secret mounted in
  farmer's pods only, read by file path (`IMAS_FARMER_NKEY_SEED_FILE`).
- The OpenBao bootstrap Job (`deploy/helm/farmer/templates/openbao-bootstrap-job.yaml`,
  `uat/hub/core/openbao-bootstrap.sh`) already writes platform material into
  OpenBao.

## Decisions

1. **The password.** The OpenBao bootstrap Job generates a random password of 32
   bytes (base64, no padding) if the KV property is absent and never overwrites
   an existing one, in the same KV path and mount as the NKey seeds, property
   `valkey_password`. One new `ExternalSecret` writes Secret
   `imas-valkey-auth` (key `password`), name and key settable in values
   (`valkey.auth.secretName`, `valkey.auth.key`). The Secret is mounted as a file at
   `/var/run/secrets/imas/valkey/password` in farmer and saasapi pods, and in the
   bundled Valkey if it is enabled. The ACL user is `default`.
2. **Chart switch.** `valkey.auth.enabled`, default `true`. Setting it to
   `false` makes the render fail unless `valkey.auth.allowInsecure` is `true`
   (same style as the chart's other safety `fail` checks), and the NOTES and
   README say it is for throwaway installs. The UAT follows the production path:
   auth on.
3. **Bundled Valkey.** Read the subchart's values (`helm show values
   valkey/valkey --version 0.12.0`) and use its own authentication feature with
   the Secret above. If the subchart cannot take the password from a Secret by
   reference, or cannot read it from a mounted file, the session must find the
   smallest way to do it that keeps the password out of values and out of
   environment variables (an init step that renders the config from the mounted
   file is acceptable) and records it in the README. The bundled replicated mode
   used in the UAT HA run gets the same treatment, including replica-to-primary
   authentication.
4. **Clients.** New settings, farmer then saasapi:
   - `IMAS_VALKEY_PASSWORD_FILE` / `SAASAPI_VALKEY_PASSWORD_FILE`: path of the
     password file; read once at startup, trailing newline trimmed; if set and
     unreadable or empty, the process refuses to start. Rotation is a pod
     restart (say so in the README).
   - `IMAS_VALKEY_TLS` / `SAASAPI_VALKEY_TLS` (`true`/`false`, default `false`),
     `IMAS_VALKEY_TLS_CA_FILE` / `SAASAPI_VALKEY_TLS_CA_FILE` (PEM; required when
     TLS is on, no system-roots fallback), and `IMAS_VALKEY_TLS_SERVER_NAME` /
     `SAASAPI_VALKEY_TLS_SERVER_NAME` (optional). Minimum TLS 1.2. Never
     `InsecureSkipVerify`.
   - Helm: `valkey.tls.enabled`, `valkey.tls.caConfigMap` (name),
     `valkey.tls.caKey` (default `ca.crt`), `valkey.tls.serverName`; the CA is
     mounted from the ConfigMap as a file. Bundled Valkey: TLS only if the
     subchart supports it, else the chart refuses `valkey.enabled=true` with
     `valkey.tls.enabled=true` and says to use an external Valkey.
   - Network policy: unchanged ports; if TLS uses another port, the policy and
     `valkeyPort` follow it.
5. **No eviction.**
   - Bundled: set `maxmemory-policy noeviction` through the subchart's config
     hook and say it in the README.
   - Both clients, after connecting, read `INFO memory`. If `maxmemory` is above
     0 and `maxmemory_policy` is not `noeviction`, log one warning that names the
     replay cache and heartbeats as security state. Warn only: a managed Valkey
     may not allow changing the policy, and an unreadable `INFO` is also only
     logged.
6. **Docs.** `deploy/helm/farmer/README.md` (replace "Neither client does auth
   or TLS yet"), `docs/INSTALL.md`, `docs/OPENBAO-RUNBOOK.md` (the new KV
   property, who generates it, how to rotate: write a new value, restart farmer,
   saasapi and Valkey), `docs/security-review-pack.md` item 3.5.3 (what is now
   closed and the accepted failover residual), `deploy/saasapi/README.md`.
7. **UAT.** `uat/` values and scripts set `valkey.auth.enabled` true, let the
   bootstrap generate the password, and pass `VALKEY_PASSWORD` where the harness
   or check scripts call `valkey-cli` or connect to Valkey. The HA node-stop test
   keeps working.

## Tests

- Config: password file read, trimmed, missing file / empty file refuse startup;
  TLS on without a CA file refuses startup; a bad PEM refuses; settings parse
  for both farmer and saasapi.
- A client built from the settings connects to a test Valkey (or a test server
  that speaks enough RESP, whichever the repo's tests already use) with the
  password, and is refused with a wrong password; with TLS, a server certificate
  from another CA is refused, a matching server name passes.
- `INFO memory` check: warns for `allkeys-lru` with `maxmemory` above 0, silent
  for `noeviction`, silent when `maxmemory` is 0, only logs when `INFO` fails.
- Helm (`chart_test.go`): the `ExternalSecret` renders; the Secret is mounted as a
  file in farmer and saasapi and never appears in `env`; `valkey.auth.enabled=false`
  fails to render without `allowInsecure`; TLS on mounts the CA ConfigMap and sets
  the TLS variables; bundled Valkey with TLS on fails with the message; the
  bootstrap Job script generates once and never overwrites (assert on the script
  text and run it against a fake as the neighbouring bootstrap tests do).
- No password, no secret value in any rendered ConfigMap, env var or log line
  (search the rendered chart and the new log statements).

Search gate: `IMAS_VALKEY_ADDRS`, `SAASAPI_VALKEY_ADDRS`, `valkey.NewClient`,
`ClientOption`, `VALKEY_PASSWORD`, `valkey-cli`, `valkey.enabled`, `valkey.addrs`,
`SetReplayCacheClient`, `SetReadinessValkey`, `heartbeat.SetClient`, `no auth or
TLS`, `Neither client` across `cmd/`, `internal/`, `deploy/`, `uat/`, `docs/`.

## Brief corrections (build, 2026-10-17)

Decided by the order in `ORCHESTRATOR.md` rule 6; none conflicts with a
numbered owner decision.

1. **Bundled Valkey and TLS.** The subchart (`valkey-io/valkey-helm`
   0.12.0) supports TLS (`tls.enabled`, `tls.existingSecret` with
   `server.crt`, `server.key`, `ca.crt`; it then serves TLS on 6379), so by
   decision 4 the bundled Valkey gets TLS. The chart does not refuse
   `valkey.enabled` with `valkey.tls.enabled`; it refuses it without
   `valkey.tls.existingSecret`, with a message that also points to an
   external Valkey. The test "bundled Valkey with TLS on fails with the
   message" is that test. The port stays 6379, so the NetworkPolicies and
   `valkeyPort` don't change.
2. **Where the bundled Valkey reads the password.** The subchart's own
   authentication takes it by reference (`auth.usersExistingSecret`,
   templated to `valkey.auth.secretName`, user `default`, `passwordKey`
   `valkey.auth.key`): its init step mounts the Secret at
   `/valkey-users-secret` and writes the password's SHA-256 into the ACL
   file, and replicas get `masteruser default`/`masterauth` from it. It is
   not mounted at `/var/run/secrets/imas/valkey/password` in Valkey's pods;
   that path is farmer's and saasapi's.
3. **The KV mount.** The seed path had no mount in values; the bootstrap
   Job writes `valkey_password` to the new `externalSecrets.seedMount`
   (default `secret`, the KV v2 mount the SecretStore reads). The Job runs
   only with the bundled OpenBao; with an external OpenBao, ops writes the
   property (`docs/OPENBAO-RUNBOOK.md` 5.6). The write is a check-and-set
   `kv patch` (or `kv put -cas=0` for a new path), so the seeds in the same
   path are kept.
4. **The harness did not pass a password.** `uat/tests/harness/ha.go` used
   `VALKEY_PASSWORD` from the Valkey pod's environment, which nothing sets.
   It now reads Secret `imas-valkey-auth` and passes the password on stdin
   into `VALKEYCLI_AUTH`, with `valkey-cli -e`, never on a command line.
5. **The UAT has no ESO.** `uat/hub/core/saasapi-secrets.sh` delivers
   `imas-valkey-auth` from the bootstrap Job's `valkey_password` (as it
   does saasapi's Secrets), and `check.sh` checks that Valkey refuses a
   client without the password.
6. **The subchart's metrics exporter** takes the password as an env var
   (`REDIS_PASSWORD`), which the owner decision forbids, so the chart
   refuses `valkey.metrics.enabled` with `valkey.auth.enabled`.
