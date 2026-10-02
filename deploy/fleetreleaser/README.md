# fleetreleaser: the release signing service (reference deploy config)

**FLAG FOR SECURITY REVIEW.** fleetreleaser is the only signer of sprout
releases, and saasapi's operator plane is the only way a signed release
gets into `saas.fleet_versions`. This directory holds the OpenBao policies
that decide who can sign. If they are misconfigured, the Go code will not
catch it: farmer and saasapi would sign releases just fine. Review the
policies, the caller-token custody and the checks below more carefully
than the Go code.

Design: `docs/design/cloudxp-machine-manager-api-design.md` §2.5.

These are reviewed reference files, as in `deploy/farmer/`.

- `deploy/helm/farmer` carries byte copies of both policies, and
  `TestPoliciesMatchReference` fails if they drift. Its eval-only OpenBao
  bootstrap writes them to the bundled OpenBao and binds `imas-fleet-verify`
  to farmer's role (and to saasapi's, with fleet update dispatch on).
- It deploys no fleetreleaser, so no role binds `imas-fleet-signer`.
- For a production OpenBao, the roles and the fleetreleaser Deployment are
  set up outside imas, as described below.

| File | What it is |
|---|---|
| `policies/imas-fleet-signer.hcl` | Policy for `cmd/fleetreleaser` only: sign with `imas-fleet-signing`, and read its public keys |
| `policies/imas-fleet-verify.hcl` | Policy for farmer and saasapi: read the public keys and call Transit verify. Nothing else |

The service shape (FU.4) changes no capability in either policy:
fleetreleaser still needs exactly sign and read on the one key, and farmer
and saasapi exactly read and verify. One comment in
`imas-fleet-signer.hcl` still describes the pre-FU.0 message
(`version|artifact_url|checksum_sha256`); it is left as is here because
the chart's byte copy has to change with it (see the PR).

## How a release gets signed and registered

```
farmer Helm hook Job ──operator token──▶ saasapi operator plane ──caller token──▶ fleetreleaser ──sign──▶ OpenBao Transit
                                            │  validate, verify signature                (no DB)
                                            ▼
                                     saas.fleet_versions (saasapi is the only writer)
```

1. The farmer chart's post-install/post-upgrade hook Job (FU.5) calls
   saasapi's `POST /v1/operator/fleet-releases` with the release: version,
   channel, `min_sprout_version`, and per OS/arch the package type, file
   name and SHA-256.
2. saasapi validates it and compares it with what is registered. Same
   contents: a no-op, fleetreleaser isn't called. A different build under
   the same version: 409.
3. For each new OS/arch, saasapi calls fleetreleaser's `POST /v1/sign`.
   fleetreleaser validates the entry with `internal/fleetsign`, refuses a
   version at or below its floor, has Transit sign the canonical message,
   checks the signature against Transit's own key set, logs it, and
   returns it.
4. saasapi verifies each signature against its own read-only view of the
   key and writes the rows in one transaction.

A bad version is withdrawn with saasapi's
`POST /v1/operator/fleet-releases/{version}/revoke`. `helm rollback` does
not withdraw anything.

## Who holds what

| Identity | OpenBao (Transit key `imas-fleet-signing`) | PXC `saas.fleet_versions` | Holds |
|---|---|---|---|
| `cmd/fleetreleaser` (Deployment) | `imas-fleet-signer`: **sign**, read | **none** | the caller token (to check it), its TLS key |
| saasapi | `imas-fleet-verify`: read, verify | `saas_svc`: `ALL ON saas.*` (sole writer) | the caller token (to present it), the operator token (to check it) |
| farmer | `imas-fleet-verify`: read, verify | `farmer_svc`: `SELECT ON saas.*` | — |
| farmer Helm hook Job | none | none | the operator token |
| sprout | none. It gets the live key set from farmer over its own NATS connection; the enrollment-time key is a bootstrap fallback only | none | — |

The rule this table enforces is that **no identity holds both Transit
sign on `imas-fleet-signing` and a way to write `saas.fleet_versions`.**
fleetreleaser can sign but writes nothing; saasapi writes the table but
can only ask fleetreleaser to sign, through fleetreleaser's own format and
version-floor checks.

**What the split does not stop.** Anyone who controls saasapi (or holds
the operator token) can get any well-formed release above the floor signed
and registered: that is what registration is for. What still stands
between such a release and a fleet: a tenant has to approve the version;
the sprout downloads `file_name` from the repository configured in the
sprout itself, not from anything imas controls, and installs it only if
its SHA-256 matches the signed checksum; and fleetreleaser's log records
every signature it made.

## The signing service

`cmd/fleetreleaser` is a stateless HTTPS service. Run it as a small
Deployment (one or two replicas) in the control-plane namespace.

| Method | Path | Auth | |
|---|---|---|---|
| POST | `/v1/sign` | caller token | Body: exactly `version`, `os`, `arch`, `file_name`, `checksum_sha256`, `min_sprout_version`, all strings. 200 `{"signature": "v<N>:<base64>"}`. 400 `invalid_request` / `invalid_manifest`, 422 `version_not_above_floor`, 401, 502 `signing_failed` |
| GET | `/healthz` | none | liveness; touches nothing |

It never stores anything, so signing the same entry twice simply signs it
twice; deduplication is saasapi's, against the table.

Configuration, all read once at startup (Reloader rolls the Deployment on
a change):

| Variable | |
|---|---|
| `IMAS_FLEETRELEASER_LISTEN_ADDR` | default `:8443` |
| `IMAS_FLEETRELEASER_TLS_CERT_FILE`, `IMAS_FLEETRELEASER_TLS_KEY_FILE` | required; there is no plain-HTTP mode |
| `IMAS_FLEETRELEASER_CALLER_TOKEN_FILE` | required; mounted Secret file holding the token saasapi presents (at least 32 characters, no whitespace) |
| `IMAS_FLEETRELEASER_CALLER_TOKEN_PREVIOUS_FILE` | optional; the previous token, accepted during a rotation |
| `IMAS_FLEETRELEASER_VERSION_FLOOR` | required; canonical semver. Nothing at or below it is signed. `v0.0.0` allows everything |
| `IMAS_FLEETRELEASER_OPENBAO_*`, `IMAS_FLEETRELEASER_TRANSIT_KEY` | its own OpenBao identity (see Roles) |

It refuses to start (exit 2) without any of the required settings, and
exits 1 if it can't read the Transit key or the key isn't Ed25519.

**Version floor.** Raise `IMAS_FLEETRELEASER_VERSION_FLOOR` to the last
released version when you want to make sure nothing older can be signed
again (for example a version line with a known vulnerability). A
re-registration of an already registered release doesn't reach
fleetreleaser, so raising the floor never breaks `helm upgrade` for the
current release.

**NetworkPolicy.** Allow ingress to fleetreleaser's port from saasapi's
pods only, and egress only to OpenBao. The caller token is the
authentication; the NetworkPolicy keeps everyone else from even trying.

### Caller authentication: a bearer token, not mTLS

The brief allowed either. fleetreleaser uses a bearer token from a mounted
Secret, over TLS, because:

- **It is saasapi's existing pattern.** saasapi's other secrets (the BFF
  secret, its NATS seed) are Kubernetes Secrets kept in sync with OpenBao
  by External Secrets Operator, mounted as files, read at startup, rotated
  with a current/previous pair and a Reloader restart. The caller token
  uses exactly that path on both ends.
- **mTLS would need client-certificate issuance this deployment doesn't
  have.** The repo runs no cert-manager or internal issuer for service
  identities; adding one for a single caller is more moving parts than
  the threat warrants.
- **It protects the same thing.** The caller credential only has to tell
  saasapi apart from everything else that can reach the port. A
  compromised saasapi can use a client certificate exactly as it can use a
  token. Against everyone else, the token is as good as a certificate as
  long as it stays secret: it is a file, not an env var; it travels only
  over TLS (fleetreleaser has no plain-HTTP mode, and saasapi only accepts
  an `https://` URL and doesn't follow redirects); it is compared in
  constant time; and the NetworkPolicy limits who can present it.
- What mTLS would add, a credential that can't be replayed if copied, is
  noted as a possible follow-up, not built.

Generate the token with at least 32 random bytes, e.g.
`openssl rand -base64 48 | tr -d '\n=+/'`, and store it once in OpenBao;
both sides read the same value. To rotate: put the new value in
fleetreleaser's `..._CALLER_TOKEN_FILE` and the old in
`..._CALLER_TOKEN_PREVIOUS_FILE`, roll fleetreleaser, then update saasapi's
`SAASAPI_FLEETRELEASER_TOKEN_FILE` and roll saasapi, then drop the previous
token.

## The Transit key

```sh
bao secrets enable transit   # if not already enabled
bao write -f transit/keys/imas-fleet-signing type=ed25519 exportable=false allow_plaintext_backup=false
```

- Use a new key. Do not reuse `imas-gateway-jwt`.
- Never set `exportable=true` or `allow_plaintext_backup=true`.
### Rotating the key

**The rotation step itself is safe.** Run
`bao write -f transit/keys/imas-fleet-signing/rotate`.

- fleetreleaser signs new releases with the new version.
- Sprouts pick it up without re-enrolling. They verify against the key
  set farmer serves live on `imas.sprouts.<id>.fleetsigningkeys`. That
  set holds every version at or above `min_decryption_version`: every
  version Transit's own `/verify` still accepts.
- Sprouts cache that set for 5 minutes. A signature by a version missing
  from the cache triggers an immediate refetch.

**The two floors do different things.**

- `min_encryption_version` only limits which versions may make **new**
  signatures. Raising it (for example to the newest version right after
  a rotation) starts a grace period. Older versions stop signing but
  still verify everywhere, so already-approved releases keep working.
- `min_decryption_version` is what verifiers honor.

**Retiring a version is not automated, on purpose, and has a hard
constraint.** You retire version N for verification by raising
`min_decryption_version` past it (`bao write
transit/keys/imas-fleet-signing/config min_decryption_version=N+1`).
Transit requires `min_encryption_version` >= `min_decryption_version`,
so raise that first if needed.

- That removes N from the live set, so every sprout stops accepting
  signatures made with N within about 5 minutes. Farmer's pre-dispatch
  check and saasapi's rollout check stop accepting them too.
- **Never raise `min_decryption_version` past a version that signed a
  release still named as `approved_version` in any tenant's
  `saas.tenant_update_policy`.** That tenant's approved release would
  stop verifying fleet-wide, and its rollouts would fail.
- Before raising it, check that every approved version was signed at or
  above the new floor. The key version is the `v<N>:` prefix of
  `saas.fleet_versions.signature`.
- **Nothing re-signs a registered release.** Registering it again is a
  no-op, and registered rows are never rewritten. So the only way to move
  an approved release onto a newer key version is to register it as a new
  version, have tenants approve that, and only then retire the old key
  version.
- This is an operator decision. Nothing in imas raises either floor,
  trims key versions or retires them automatically.

Note that `internal/gatewayjwt`'s JWKS floors on `min_encryption_version`.
That's a different key with different semantics; don't copy it here.

## Roles

Create one Kubernetes auth role per identity. Don't share a role or a
token between identities.

- `auth/kubernetes/role/imas-fleetreleaser`: bound only to the
  fleetreleaser Deployment's ServiceAccount.
  `token_policies=imas-fleet-signer`. Keep `token_ttl` short, for example
  `15m`: the client logs in again at 80% of the lease, so a short TTL costs
  nothing and limits a leaked token.
- `auth/kubernetes/role/imas-farmer-fleet-verify`: bound to farmer's
  ServiceAccount. `token_policies=imas-fleet-verify`.
- `auth/kubernetes/role/imas-saasapi-fleet-verify`: bound to saasapi's
  ServiceAccount. `token_policies=imas-fleet-verify`. saasapi needs it
  whenever the operator plane is on (it verifies every signature before
  storing it), not only with fleet update dispatch.

Environment variables:

- farmer and saasapi read `IMAS_FLEETSIGN_OPENBAO_*`, which is
  `internal/fleetsign`'s read-only client.
- fleetreleaser reads `IMAS_FLEETRELEASER_*`. It has no database setting.
- saasapi reads `SAASAPI_FLEETRELEASER_URL`,
  `SAASAPI_FLEETRELEASER_TOKEN_FILE` and `SAASAPI_FLEETRELEASER_CA_FILE` to
  call it.
- Never put a `IMAS_FLEETRELEASER_*` variable in farmer's or saasapi's
  Deployment.

## Check it; don't assume it

**Wildcards on other policies.** farmer's existing gateway Transit
policy must name `transit/sign/imas-gateway-jwt` exactly. A
`transit/sign/*` or `transit/sign/+` grant on farmer's gateway role
quietly gives farmer sign on `imas-fleet-signing` too, and this design is
gone. Audit **every** policy attached to farmer's and saasapi's roles,
including `default` and any policy inherited through identity groups.

**Log in as each role and ask OpenBao.** Use a token issued to each role:

```sh
# farmer's and saasapi's tokens: every one of these must print "deny"
for p in transit/sign/imas-fleet-signing \
         transit/sign/imas-fleet-signing/sha2-256 \
         transit/keys/imas-fleet-signing/rotate \
         transit/keys/imas-fleet-signing/config \
         transit/export/signing-key/imas-fleet-signing \
         transit/backup/imas-fleet-signing; do
  bao token capabilities "$TOKEN" "$p"
done
bao token capabilities "$TOKEN" transit/keys/imas-fleet-signing     # read
bao token capabilities "$TOKEN" transit/verify/imas-fleet-signing   # update

# and the direct attempt must fail with 403 permission denied:
VAULT_TOKEN="$TOKEN" bao write transit/sign/imas-fleet-signing input=aGk=
```

**Run the automated version against a real OpenBao.** The same checks,
plus a live refusal through fleetreleaser's own sign client and through the
signing service running on a read-only token, using the policy files in
this directory:

```sh
bao server -dev -dev-root-token-id=root &
IMAS_TEST_OPENBAO_ADDR=http://127.0.0.1:8200 IMAS_TEST_OPENBAO_TOKEN=root \
  go test ./cmd/fleetreleaser -run TestOpenBaoEnforcesReadOnlyFleetKey -v
```

Without those variables the test is skipped. CI doesn't run it yet (see
the PR).

## Removing fleetreleaser's old database access

Before FU.4, fleetreleaser was a CLI that wrote `saas.fleet_versions` over
its own database user. That access must go:

```sql
DROP USER IF EXISTS 'fleetreleaser_svc'@'%';
```

- Remove `IMAS_FLEETRELEASER_DSN` and its Secret from wherever the old
  release Job ran. Nothing reads it any more.
- The saas migration `00003_fleet_versions_per_os_arch` drops
  `artifact_url`, so the old CLI's insert would fail anyway; the grant
  should still not outlive it.
- Rows the old CLI wrote are deleted by that migration: they were signed
  over the pre-FU.0 message and have no OS, arch or file name, so nothing
  could verify or serve them. Register the release again through the
  operator plane. A tenant whose `approved_version` named one of them
  keeps the policy row; the version is unknown until it is registered
  again.
