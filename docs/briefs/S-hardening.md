# Hardening units from the P3 review walkthrough (S1, S2)

Read `docs/briefs/ORCHESTRATOR.md` first: its session prompt (zero open items,
repo-wide search, brief errors decided by a fixed order) applies to both
units. Both come from the owner's walkthrough of `docs/security-review-pack.md`
sections 3.3 (items 1 and 6) on 2026-10-14. Decisions below are final.

Owner decisions (2026-10-14):

- **S1.** The bus loader gets the CA certificate from a ConfigMap and never
  mounts the bus's TLS volume, in every TLS mode. The CA is public data; a
  ConfigMap is configuration, not pod state, so the loader and the bus stay
  stateless. The bus keeps issuing its own key in memory (`openbao` mode);
  no key is stored in a Secret for this.
- **S2.** Secrets and passwords must not reach the audit log (stdout, then
  Fluent Bit, kept 30 days). Use the `masq` library where it fits (Apache-2.0,
  allowed by `CLAUDE.md`), and a small in-repo walker where it does not.
  Free-form content (command text, recipes, property values) is not logged;
  its hash is.

## S1: the loader mounts the CA from a ConfigMap, never the bus TLS volume

Scope: `deploy/helm/nats` (templates, values, README, `chart_test.go`),
`deploy/helm/farmer` (the OpenBao bootstrap Job, trust RBAC, values, README),
`uat/hub` scripts that copy the NATS trust, docs.

Facts on main (2026-10-14), verify first:

- `deploy/helm/nats/templates/bus-statefulset.yaml`: in `bus.tls.mode` `secret`
  the loader mounts volume `loader-ca`, a Secret projection of `ca.crt` alone
  (`IMAS_LOADER_CA_FILE=/var/run/imas/loader-ca/ca.crt`). In `openbao` mode it
  mounts the whole in-memory `tls` volume (`$tlsDir`) read-only, which holds the
  bus key, and reads `$tlsDir/tls-rootca.pem`.
- In `openbao` mode the bus writes the issuing CA of the certificate OpenBao
  issued (`internal/certs/tls.go`, `issuing_ca`) to `tls-rootca.pem`.
- The core bootstrap Job writes the public trust ConfigMap
  (`natsTrust.configMapName`, default `imas-nats-trust`); its RBAC
  (`deploy/helm/farmer/templates/nats-trust-rbac.yaml`) allows `create` on
  ConfigMaps and `get, update, patch` on that one name. The ConfigMap is copied
  into the bus namespace (and to the DMZ hub) by hand or pipeline
  (`uat/hub/dmz/lib.sh`, `DMZ_TRUST_CONFIGMAP`).

Build:

1. **New value** `bus.loader.caConfigMap` (nats chart), default `imas-bus-ca`:
   the ConfigMap, in the bus's namespace, with key `ca.crt`. Used only in
   `openbao` mode. In `secret` mode nothing changes: the loader already
   mounts only `ca.crt` of the TLS Secret.
2. **nats chart, `openbao` mode:** the loader's `loader-ca` volume is a
   `configMap` volume of `bus.loader.caConfigMap`, projecting only `ca.crt`,
   mounted read-only as a directory (never `subPath`, which would not receive
   a CA rotation) at `/var/run/imas/loader-ca`; `IMAS_LOADER_CA_FILE` is
   `/var/run/imas/loader-ca/ca.crt` in both modes. The loader container no
   longer mounts `tls`. The bus pod waits for the ConfigMap the way it waits
   for `nats-trust` (same init pattern; the message names the ConfigMap).
3. **farmer chart, bootstrap Job:** when OpenBao PKI is in use
   (`openbao.enabled` and the PKI mount the bus role issues from), the Job
   writes the ConfigMap named by a new value `natsTrust.busCAConfigMapName`
   (default `imas-bus-ca`) in the core namespace, with `ca.crt` set to the PEM
   OpenBao returns as `issuing_ca` for the bus role's issuer (read the
   issuer certificate from `pki/cert/ca`, or `pki/cert/ca_chain` when the
   mount's issuer is an intermediate; the test below pins which bytes equal
   what an issued certificate's `issuing_ca` carries; if they differ, use the
   one that equals it). The Job creates it when absent and updates it when
   the PEM changed. Add `resourceNames` for the new name to the trust RBAC
   (`get`, `update`, `patch`); `create` is already allowed. Nothing else
   changes in the Job's token handling.
4. **Copy step:** wherever the NATS trust ConfigMap is copied to the bus
   namespace or the DMZ hub (`uat/hub` scripts, `deploy/helm/nats/README.md`,
   `deploy/helm/farmer/README.md` "NATS trust"), copy `imas-bus-ca` as well
   when the bus runs in `openbao` mode, with the same wording ("public data
   only"). The UAT uses `secret` mode today, so only the copy code and its
   script tests change there; do not switch the UAT's mode.
5. **Docs:** the nats README describes the loader's mounts exactly (CA
   ConfigMap, SYS user seed, accounts-reader credential, trust ConfigMap; no
   bus key in either mode) and says a CA rotation is a ConfigMap update with
   the new PEM (the loader re-reads it on restart; the runbook,
   `docs/OPENBAO-RUNBOOK.md` section 6, lists it).

Tests (the repo's chart test pattern):

- `deploy/helm/nats/chart_test.go`: for both modes, the loader container
  mounts none of `tls`, `data`, `nats-seeds`; in `openbao` mode `loader-ca`
  is a `configMap` volume named `imas-bus-ca`, projecting only `ca.crt`, no
  `subPath`, and `farmerbus` does not mount it; `IMAS_LOADER_CA_FILE` is
  `/var/run/imas/loader-ca/ca.crt` in both. Extend the existing test that
  covers `secret` mode so that `openbao` mode is no longer untested.
- farmer chart: the bootstrap Job renders the ConfigMap step and the RBAC rule
  with the new name; with OpenBao PKI off the step is absent.
- A Job-script test (the repo's script-test pattern, fake `bao` and `kubectl`)
  that the step writes the PEM, updates on change, and does nothing on no
  change.
- A Go test that the PEM the step reads equals the `issuing_ca` a certificate
  issued from the same mount carries (use `internal/certs`'s test server or
  `openbaotest`; if neither can answer both calls, extend the fake).

Search gate: `loader-ca`, `tls-rootca.pem`, `IMAS_LOADER_CA_FILE`,
`imas-nats-trust`, `DMZ_TRUST_CONFIGMAP`, `busCAConfigMapName`,
`caConfigMap` across `deploy/`, `uat/`, `docs/`, `.github/`.

## S2: no secrets or passwords in the audit log

Scope: `internal/audit`, the two audit write sites in `internal/natsapi`
(`sealedrouter.go` `auditCall`, `shell.go` around line 812), the tenant
provisioning call (`LogAction`), `DEPENDENCIES.md`, `go.mod`, docs.

Facts on main (2026-10-14), verify first:

- `internal/natsapi/sealedrouter.go` `auditCall` sets `entry.Parameters = params`
  for every method that is not in `audit.readOnlyActions`, with no redaction.
  `audit.LogAction` calls `redactToken`, which removes only a top-level
  `token` key. `internal/natsapi/shell.go` writes its own entry.
- Write methods that carry user content include `cmd.run`, `cook`,
  `props.set`, `shell.open`, `deploy.app`, `deploy.recipe`, `multi.recipe`,
  `test.recipe`, `test.sls`, `nginx.harden`, `webserver.nginx`, and
  `auth.users.add`/`resetkey` (public keys). Confirm the list from the router
  and add every other method whose params are free-form.
- `audit.Entry` has `Error`, which can quote a value. `Logger.Log` is the one
  function every audit line goes through.

Build:

1. **One choke point.** Redaction runs inside `Logger.Log`, on a copy of the
   entry, so every writer is covered, now and later: `auditCall`, `shell.go`,
   `LogAction`, and any other `audit.Entry{` writer you find (search; route
   it through `Log`). Callers do not redact.
2. **Free-form methods: log shape, not content.** A fixed set
   `freeFormMethods` (the list above plus every method you add after the
   router check) never logs its parameters. Its `params` becomes
   `{"redacted":"free-form","bytes":N,"sha256":"<hex of the original bytes>","keys":[the sorted top-level key names]}`.
   Targets stay as the entry already carries them. A method not in the set
   and not read-only gets rule 3.
3. **Every other logged parameter object.** Decode to `any` (numbers kept as
   `json.Number`), walk objects and arrays to any depth, and:
   - replace the value of any object key whose lower-cased name matches
     `pass(word|wd|phrase)?`, `secret`, `token`, `api[_-]?key`, `private`,
     `seed`, `credential`, `authorization`, `bearer`, `cookie`, `otp`,
     `sdb` or `key_material` (a substring match on those words) with the
     string `[REDACTED]`;
   - on every string leaf, replace what matches these patterns with
     `[REDACTED]`: a JWT (three base64url parts, the first starting `eyJ`),
     a PEM private key block (`-----BEGIN [A-Z ]*PRIVATE KEY-----` to its END
     line), an NATS seed (`S[UAON][A-Z2-7]{55}`), `AKIA[0-9A-Z]{16}`,
     `Bearer\s+\S+`, URL userinfo (`://user:pass@`), and `name=value` or
     `name: value` where name is one of the key words above.
   - Use **`github.com/m-mizutani/masq`** for the string-leaf patterns:
     build one `masq.New(masq.WithRegex(...))` per pattern and apply it to
     each string leaf as a `slog.Attr`. Its documentation covers `slog`
     attributes and struct fields only, so the key-name rule and the
     free-form rule are the in-repo walker, not masq. First write the test
     that applies masq to a string leaf holding each pattern. If it does
     not replace all of them, use `regexp` for the string leaves instead
     and say so in the PR; do not leave both in.
   - Parameters that do not parse as JSON, or that exceed 1 MiB, are not
     logged: `{"redacted":"unparseable","bytes":N,"sha256":"..."}`.
4. **`Entry.Error`.** Apply rule 3's string patterns to it (an error that
   quotes a secret is redacted). Do not change the other fields.
5. **Dependency.** If masq is kept: `go get` the latest release, record it in
   `DEPENDENCIES.md` with its licence (Apache-2.0), confirm
   `CGO_ENABLED=0 go build ./...` still passes. A license other than
   Apache-2.0 or MIT in the module's own tree is flagged and the dependency
   not added (use `regexp`).
6. **Docs.** `docs/design/imas-payload-encryption-design.md` (the router step
   that audits "a write's params") and the audit paragraph in
   `internal/audit/audit.go` say what is logged: parameters of ordinary
   write methods with secrets masked, the shape and hash of free-form
   methods. Add a short "What the audit log never contains" list to
   `docs/INSTALL.md` or the saasapi/farmer README where audit is described.

Tests:

- Table test per rule: each key word (any case, at depth 3, inside an array);
  each string pattern; a JWT in a command-looking string; a PEM block; an NATS
  seed; invalid JSON; a 2 MiB body.
- Per free-form method: the logged line has the shape in rule 2 and the
  original text appears nowhere in the line (assert on the raw bytes written).
- A test through `auditCall` and through the shell writer and `LogAction`
  that a fixture containing `password`, `X-Api-Key`, an NATS seed and a JWT
  never appears in the bytes written to the writer.
- The existing audit tests still pass; a read-only method is unchanged.

Search gate: `audit.Entry{`, `Parameters`, `redactToken`, `LogAction`,
`readOnlyActions` across `internal/`, `cmd/`, `docs/`.
