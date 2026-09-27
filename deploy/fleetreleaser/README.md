# fleetreleaser: release signing split (reference deploy config)

**FLAG FOR SECURITY REVIEW.** This directory holds the OpenBao policies
that decide who can sign sprout releases. The whole design rests on
them. If these policies are misconfigured, the Go code will not catch it:
farmer and saasapi would sign releases just fine. Review the policies
and the checks below more carefully than the Go code.

Design: `docs/design/cloudxp-machine-manager-api-design.md` §2.5.

These are reviewed reference files, as in `deploy/farmer/`.

- `deploy/helm/farmer` carries byte copies of both policies, and
  `TestPoliciesMatchReference` fails if they drift. Its eval-only OpenBao
  bootstrap writes them to the bundled OpenBao and binds `imas-fleet-verify`
  to farmer's role (and to saasapi's, with fleet update dispatch on).
- It deploys no fleetreleaser, so no role binds `imas-fleet-signer`.
- For a production OpenBao, the roles, the fleetreleaser Job and its
  database user are set up outside imas, as described below.

| File | What it is |
|---|---|
| `policies/imas-fleet-signer.hcl` | Policy for `cmd/fleetreleaser` only: sign with `imas-fleet-signing`, and read its public keys |
| `policies/imas-fleet-verify.hcl` | Policy for farmer and saasapi: read the public keys and call Transit verify. Nothing else |

## Who holds what

| Identity | OpenBao (Transit key `imas-fleet-signing`) | PXC `saas.fleet_versions` |
|---|---|---|
| `cmd/fleetreleaser` (release pipeline Job) | `imas-fleet-signer`: **sign**, read | its own user: `SELECT`, `INSERT`, `UPDATE (signature)` |
| saasapi | `imas-fleet-verify`: read, verify | `saas_svc`: `ALL ON saas.*` (unchanged) |
| farmer | `imas-fleet-verify`: read, verify | `farmer_svc`: `SELECT ON saas.*` (unchanged) |
| sprout | none. It gets the live key set from farmer over its own NATS connection; the enrollment-time key is a bootstrap fallback only | none |

The rule this table enforces is that **no identity holds both Transit
sign on `imas-fleet-signing` and a way to change what
`saas.fleet_versions` says outside fleetreleaser.** saasapi already
writes that table, so it gets verify-only access. fleetreleaser writes
rows, but only rows it has just signed.

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
- **fleetreleaser has no re-sign path today.** A row whose signature
  still verifies is left `unchanged`, and one that doesn't verify is
  refused. So the only way to move an approved release onto a newer key
  version is to publish it as a new version, have tenants approve that,
  and only then retire the old key version.
- This is an operator decision. Nothing in imas raises either floor,
  trims key versions or retires them automatically.

Note that `internal/gatewayjwt`'s JWKS floors on `min_encryption_version`.
That's a different key with different semantics; don't copy it here.

## Roles

Create one Kubernetes auth role per identity. Don't share a role or a
token between identities.

- `auth/kubernetes/role/imas-fleetreleaser`: bound only to the release
  Job's ServiceAccount. `token_policies=imas-fleet-signer`. Give it a
  short `token_ttl`, for example `5m`, because a run makes about three
  Transit calls.
- `auth/kubernetes/role/imas-farmer-fleet-verify`: bound to farmer's
  ServiceAccount. `token_policies=imas-fleet-verify`.
- `auth/kubernetes/role/imas-saasapi-fleet-verify`: bound to saasapi's
  ServiceAccount. `token_policies=imas-fleet-verify`.

Environment variables:

- farmer and saasapi read `IMAS_FLEETSIGN_OPENBAO_*`, which is
  `internal/fleetsign`'s read-only client.
- fleetreleaser reads `IMAS_FLEETRELEASER_OPENBAO_*` and
  `IMAS_FLEETRELEASER_DSN`.
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
plus a live refusal through fleetreleaser's own sign client, using the
policy files in this directory:

```sh
bao server -dev -dev-root-token-id=root &
IMAS_TEST_OPENBAO_ADDR=http://127.0.0.1:8200 IMAS_TEST_OPENBAO_TOKEN=root \
  go test ./cmd/fleetreleaser -run TestOpenBaoEnforcesReadOnlyFleetKey -v
```

Without those variables the test is skipped. CI doesn't run it yet (see
the PR).

## Database user for fleetreleaser

```sql
CREATE USER 'fleetreleaser_svc'@'%' IDENTIFIED BY '...';
GRANT SELECT, INSERT ON saas.fleet_versions TO 'fleetreleaser_svc'@'%';
GRANT UPDATE (signature) ON saas.fleet_versions TO 'fleetreleaser_svc'@'%';
```

- Grant nothing else in `saas` or `farmer`.
- `UPDATE (signature)` exists only to backfill rows written before the
  column existed. fleetreleaser signs such a row only when its version,
  URL and checksum exactly match what the pipeline passed.
- Once no unsigned rows remain, drop the `UPDATE` grant.
- saasapi owns the schema. Its AutoMigrate adds the `signature` column,
  so deploy saasapi before the first fleetreleaser run.

## Running it

The release pipeline runs it after it publishes the artifact:

```sh
fleetreleaser -version v2.4.1 \
  -artifact-url https://<recipe-endpoint>/artifacts/sprout-v2.4.1-linux-amd64 \
  -checksum-sha256 <hex>
```

Exit codes:

- 0: the release is in the catalog, signed. This covers `inserted`,
  `backfilled` and `unchanged`.
- 1: signing or writing failed.
- 2: a usage or configuration error.

A version already published with different contents is an error.
Releases are immutable.
