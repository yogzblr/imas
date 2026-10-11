# P21 slice 1 build specification: Transit-backed NATS signer and bootstrap

Repo: /home/claude/yogzblr/imas (module github.com/yogzblr/imas). Design basis: docs/design/imas-openbao-signing-design.md (decisions D1-D21 in section 2; key inventory section 4; bootstrap section 5; policies section 6; tenant provisioning section 7; code changes section 9; tests T1-T8 section 11). Repo rules: CLAUDE.md:33-43 (go test ./... green, status fragment under docs/status/days/YYYY-MM-DD/, commit message `<workstream-id>: <what>`, "FLAG FOR SECURITY REVIEW" wording in PRs, CLAUDE.md:44-47).

Owner decisions applied: D3 (operator identity key is a Transit key), D6 (no production: no migration, no compat shims, old seeds simply stop being read), D7 (do not test OpenBao beyond its docs; unit tests use an httptest fake Transit; real-server tests follow the pattern of cmd/fleetreleaser/openbao_integration_test.go with IMAS_TEST_OPENBAO_ADDR / IMAS_TEST_OPENBAO_TOKEN).

Conventions in this document: "file:line" cites current behaviour as read in this session. Items marked UNVERIFIED could not be confirmed from sources reachable here (openbao.org and GitHub releases were blocked; Go module cache is absent; I fetched upstream sources at pinned tags from raw.githubusercontent.com: nkeys v0.4.16, jwt/v2 v2.8.2, OpenBao v2.7.1 website/content/docs/api/secret/transit.mdx and concepts/policies.mdx). Those copies are in the scratchpad under src/.

---------------------------------------------------------------------
## 0. What exists today (facts the spec builds on)

Seeds: six seeds in one Secret (OPERATOR, OPERATOR_SIGNING, SYS_ACCOUNT, TENANT, TENANT_SIGNING, SAASAPI_USER): deploy/helm/farmer/values.yaml:73-92; deploy/helm/farmer/templates/farmer-deployment.yaml:76-86 (env), 219-221 (mount), 248-257 (volume); deploy/helm/farmer/templates/_helpers.tpl:223-228 (seeds helper), 639-653 (validation). Bus chart: deploy/helm/nats/values.yaml:25-41, templates/_helpers.tpl:102-108 and 153-168, templates/bus-statefulset.yaml:113-118 (env), 207-209 (mount), 240-250 (volume).

Farmer-side use of private seeds:
- internal/pki/jwtauth.go: struct natsAuthMaterial 42-62; ensureNatsAuth 100-278; seed loads 118-157; operator JWT `oc.Encode(mat.operatorKP)` 165-191; SYS account JWT `ac.Encode(operatorSigningKP)` 193-212; SYS user (SYS_USER seed, JWT signed by sysAccountKP) 218-248; legacy tenant JWT 254-275; loadExternalSeed 295; loadOrCreateSeed 318.
- internal/pki/busauth.go: loadBusAuth 75-151 (builds operator JWT in memory line 110; SYS bootstrap JWT via signAccountClaimsAt at iat=1, line 121; fence SYS user signed by sysAccountKP 138-141); signAccountClaimsAt 159-196 (also used by busauth_test.go:113); ConfigureBusNats 202-224; dropSelfMintedClaims 232-253.
- internal/pki/tenant.go: tenantAccountMaterial 60-65; paths 80-84; externalSeedNameForTenant 120-122; ensureTenantAccountMaterial 141-195 (seeds 153 and 161; `ac.Encode(mat.operatorSigningKP)` 183); loadTenantAccountMaterial 205-217; ensureTenantAccount 227; ensureTenantAccountLocked 290; ProvisionTenant 355-379; DeprovisionTenant 393-428 (deletes no key material, comment 384-385); signLockedOutTenantJWT 507-526; syncTenantSprouts 676-752 (tam.signingKP at 696 and 720; operatorSigningKP at 742); tenantIDsProvisionedOnDisk 824-843.
- internal/pki/jwtusers.go: mintOrReuseUserJWT 201-225; syncNatsAuth 233-324 (tenantSigningKP at 249, 263, 290; operatorSigningKP at 314).
- internal/pki/nats.go: seedResolverFromCore 134-188; ReloadNKeys 212.
- internal/pki/pushall.go: PushAllAccounts 48-127 (ensureNatsAuth 52, loadTenantAccountMaterial 89, relockForPushAll 111/217).
- internal/pki/saasapi_user.go: seed load 161; `uc.Encode(mat.sysAccountKP)` 218; `sysClaims.Encode(mat.operatorSigningKP)` 233.
- internal/pki/saasapi_publish.go: requireSaaSAPIKeyMaterial 60-78 (checks SYS_ACCOUNT and SAASAPI_USER seeds).
- internal/pki/resolver.go: connectSystemAccount 84-103 (sysUserJWT + sysUserSeed).
- internal/pki/store.go: tenantID() 147; ensureNatsAuth callers 451 and 498.
- cmd/farmer/main.go: runPreConfigSubcommand 118; pki.SetupPKIFarmer 147; pki.ReloadNKeys 164; pki.EnsureSaaSAPICredential 174; PushAllAccounts 559 and 925; ResyncProvisionedTenants 950. cmd/farmer/subcommands.go registers sproutrelease.Command and pki.ControlPlaneBoxKeysCommand.
- cmd/farmerbus/main.go: ConfigureBusNats 114; startBus 167-196. cmd/farmerbus/fence.go:157-164 (nats.InProcessServer with UserJWTAndSeed(sysUser)).
- tools/loadtest/fixture.go:82, tools/loadtest/localbus.go:196, cmd/farmerbus/cluster_integration_test.go:60-100 mint with seeds.

OpenBao client: internal/openbao/openbao.go: NewFromEnv(Env, Errors); Client.Token(ctx) re-logs in via Kubernetes auth when under 20% of the lease remains (250-290); Read/Post/Put; StatusError/StatusCode/IsNotFound; 30s timeout, 0 retries; there is no way to drop the cached token. Existing Transit clients to copy: internal/gatewayjwt/obtransit.go:128-203 (sign, readKey), internal/fleetsign/obtransit.go. Fake-server pattern: internal/gatewayjwt/transittest/transittest.go. Admin helper: internal/openbao/openbaotest/admin.go. Real captured Transit responses verified with ed25519.Verify: internal/gatewayjwt/testdata/openbao-v2.7.0/*.json, internal/gatewayjwt/openbao_response_test.go:122-138.

Chart: deploy/helm/farmer/templates/openbao-bootstrap-job.yaml (250 lines; shell using `bao`; creates imas-gateway-jwt and imas-fleet-signing keys at 111-115; role() function 153-178; token from a Secret or dev root token; never writes NATS seeds; image openbaoTools tag 2.6.3 in values.yaml:139-144 while server pinned 2.7.1). Policies: templates/openbao-policies-configmap.yaml, files/openbao-policies/*.hcl, _helpers.tpl:491-503 (policy.farmerGateway), openbaoEnv helper 253-277. Existing hook Job patterns: templates/controlplane-box-keys-job.yaml (weight 5, farmer image, subcommand ensure-controlplane-box-keys), saasapi-credential-publish-job.yaml (weight 10, seed refs 85-88 and 106-127), bootstrap Job weight 0. Chart tests: chart_test.go TestSeedsAreReferencesOnly 809-845, TestFarmerPoliciesAreExact 671 (forbids `*` and `+` except tenantbox), TestBootstrapRoles 738 (parses `role` lines of container `bootstrap`), TestFarmerMatchesSeedPatch 438, TestPublishJobMatchesReference 486, TestExternalSecretsMatchReference 589, TestContractWithNatsChart 1877; container() helper only inspects `containers`, not `initContainers`. No kube-API NetworkPolicy egress exists in the chart.

nkeys/jwt facts confirmed from upstream sources:
- jwt/v2 v2.8.2 doEncode builds toSign = base64url(header) + "." + base64url(payload), calls kp.PublicKey() for the issuer (checks the prefix), then kp.Sign([]byte(toSign)); the signature is the raw 64-byte Ed25519 value, base64url-encoded (RawURL). Verification: nkeys.FromPublicKey(issuer).Verify([]byte(payload), sig), which is ed25519.Verify.
- nkeys.KeyPair interface (v0.4.16): Seed, PublicKey, PrivateKey, Sign, Verify, Wipe, Seal, SealWithRand, Open. A public-only pair returns ErrPublicKeyOnly / ErrCannotSign / ErrInvalidNKeyOperation.
- NKey public string = nkeys.Encode(prefix, raw32) = base32(prefix byte + 32 bytes + crc16).
- Required prefixes: operator identity and operator signing key: Operator (O); SYS account, tenant account and tenant signing key: Account (A).

Transit facts confirmed from OpenBao v2.7.1 docs:
- POST transit/sign/:name with `input` (base64), `key_version`, `batch_input`. For ed25519, hash_algorithm is not applicable and prehashed defaults to false: the signature is pure Ed25519 over the message bytes.
- Result: `signature` = `vault:v<N>:<std-base64 of 64 bytes>`; batch result `batch_results[]` with `signature`, `error`, `reference`, in input order.
- GET transit/keys/:name returns `keys.<ver>.public_key` as std base64 of 32 raw bytes for ed25519 (not PEM), plus latest_version, exportable, allow_plaintext_backup, deletion_allowed, derived, imported_key, soft_deleted, min_encryption_version, type.
- Key creation parameters (type, exportable, allow_plaintext_backup) cannot be changed after creation.
- Hard delete needs deletion_allowed=true via keys/:name/config. OpenBao soft delete: DELETE keys/:name/soft-delete does not require deletion_allowed, leaves the key readable but not usable to sign; soft-delete-restore reverses it.

UNVERIFIED (stated honestly, spec has a contingency for each):
1. Whether slashes are accepted in Transit key names. Decision: flat names (section 3) with name builders in one function so a switch is a one-file change. Step 1 of the build contains a real-server check (section 6.3).
2. Whether `+` matches a partial path segment in policies. Decision: use `*` suffix globs (valid: last character prefix match, policies.mdx) and never `+`.
3. Behaviour of POST transit/keys/:name on an existing key. Decision: EnsureKeyPair always reads first, creates on 404, and on any create error (including 403 race) re-reads; it never relies on the POST outcome.
4. Whether the batch response includes key_version. Decision: parse the `vault:vN:` prefix from each signature.

---------------------------------------------------------------------
## 1. The Transit-backed nkeys.KeyPair

### 1.1 Package and files

New package `internal/pki/natskeys` (not inside package pki, so test helpers and the bootstrap subcommand can import it without an import cycle). Files:
- natskeys.go: KeyStore interface, TransitKeyStore, Config, errors.
- keypair.go: transitKeyPair implementing nkeys.KeyPair.
- batch.go: sign dispatcher.
- names.go: key-name builders.
- env.go: Config from environment.
- natskeystest/fake.go: fake Transit (httptest) with counters, fault injection and Rotate. Internal pki tests that cannot import a pki-dependent helper use this directly; external packages use `internal/pki/pkitest` (new, thin: builds a KeyStore over the fake and pre-creates platform keys).

### 1.2 API

```go
type Prefix = nkeys.PrefixByte

type KeyStore interface {
    // KeyPair returns a signing pair for an existing Transit key. It reads the key,
    // validates hardening, pins key_version to latest_version, caches the public key.
    KeyPair(ctx context.Context, name string, prefix Prefix) (nkeys.KeyPair, error)
    // EnsureKeyPair reads; on 404 creates with hardened parameters; then KeyPair.
    EnsureKeyPair(ctx context.Context, name string, prefix Prefix) (nkeys.KeyPair, error)
    // RetireKey soft-deletes (DELETE keys/<name>/soft-delete). 404 and already
    // soft-deleted are success.
    RetireKey(ctx context.Context, name string) error
    Close() error  // stops workers; pending signs get ErrClosed
}
func NewTransitKeyStore(cfg Config) (*TransitKeyStore, error)
func ConfigFromEnv(prefix string, getenv func(string) string) (Config, error)
```

transitKeyPair methods:
- PublicKey(): returns the cached NKey public string. Built as nkeys.Encode(prefix, raw32) where raw32 is the base64-decoded `keys[latest_version].public_key` (must be exactly 32 bytes, else ErrKeyType).
- Sign(input): submits to the dispatcher with the pair's context-free default (store timeout, section 1.4); returns raw 64 bytes. This is what jwt/v2 doEncode calls (kp.Sign of the "header.payload" string), so the JWT signature is already exactly what nats-server verifies.
- Verify(input, sig): local ed25519.Verify against the cached 32 bytes. No network.
- Seed(), PrivateKey(): return nil, nkeys.ErrPublicKeyOnly. Seal/SealWithRand/Open: nkeys.ErrInvalidNKeyOperation. Wipe(): no-op.
- Additional: `SignContext(ctx, input)` on the concrete type for callers with deadlines.

Every caller that today uses a seed-derived pair changes only where the pair comes from; claims.Encode(kp) call shapes stay.

### 1.3 Getting the public key and hardening checks

On KeyPair(): GET `<mount>/keys/<name>`. Require: type == "ed25519"; exportable == false; allow_plaintext_backup == false; imported_key == false; derived == false; soft_deleted == false. Otherwise error (ErrKeyType, ErrKeyNotHardened, ErrKeyRetired). 404 maps to ErrKeyNotFound (wrapping openbao.IsNotFound). Pin version = latest_version at load; the pair keeps signing with the pinned version even if the key is rotated later (a rotate cannot silently change the issuer identity of already-built trust); a new process picks up the new latest version only through an explicit operator action (rotation is out of scope for slice 1).

Public key to NKey string: `nkeys.Encode(prefix, raw32)`; check with `nkeys.IsValidPublicOperatorKey` / `IsValidPublicAccountKey` as appropriate.

Creation (EnsureKeyPair): POST `<mount>/keys/<name>` body `{"type":"ed25519","exportable":false,"allow_plaintext_backup":false}`. Never sets deletion_allowed (soft delete does not need it; hard delete is an operator action).

### 1.4 Signing

- Request: POST `<mount>/sign/<name>` with `key_version` always set to the pinned version. Single caller: plain `input` (std base64 of the message). Two or more concurrent callers for the same (key, version): `batch_input: [{"input": b64, "reference": "<index>"}...]`.
- Response parse: `signature` must match `vault:v<N>:<b64>`; N must equal the pinned version, else ErrBadSignature; base64-decode must be exactly 64 bytes. The result is verified locally with ed25519.Verify against the cached public key before returning (catches a wrong key, a rotated mapping or a tampering proxy); failure is ErrBadSignature.
- Batching: one shared dispatcher per store, Workers (default 4) goroutines, each draining up to BatchMax (default 64) queued jobs and grouping them by (key, version). A batch item error fails only that caller (batch_results[i].error non-empty becomes ErrSignFailed carrying the message). An HTTP-level failure fails every caller in the batch.
- Timeout: Config.Timeout default 15s per request; callers' ctx cancel returns early. ErrSignTimeout wraps context.DeadlineExceeded.
- Retry: up to 3 attempts with 100ms/300ms jittered backoff on network errors, 429 and 5xx. 400 and 404 never retried. 403: if auth method is kubernetes, call `Client.ResetToken()` once, re-login and retry that request once; a second 403 returns ErrSignFailed (permission) with no further retries.
- Token renewal: reuse internal/openbao.Client unchanged for Token(ctx) (20% remaining threshold, openbao.go:250-290). Add one method `ResetToken()` that clears the cached token and lease so the next Token() re-logs in. This is the only change to internal/openbao.

### 1.5 Errors (exported sentinel values, wrapped with %w)
ErrKeyNotFound, ErrKeyRetired, ErrKeyNotHardened, ErrKeyType, ErrSignFailed, ErrSignTimeout, ErrBadSignature, ErrNotConfigured, ErrClosed.

### 1.6 Env block (identity "natssign"; follows the per-identity pattern of IMAS_GATEWAY_OPENBAO_* and IMAS_FLEETSIGN_OPENBAO_*)
`IMAS_NATSSIGN_OPENBAO_{ADDR,CACERT,AUTH_METHOD,TOKEN,K8S_ROLE,K8S_MOUNT,K8S_JWT_PATH,NAMESPACE,TRANSIT_MOUNT}` (TRANSIT_MOUNT default `transit`), plus `IMAS_NATSSIGN_TIMEOUT` (15s), `IMAS_NATSSIGN_BATCH_MAX` (64), `IMAS_NATSSIGN_WORKERS` (4). ConfigFromEnv returns ErrNotConfigured when ADDR is empty. The bootstrap subcommand uses prefix `IMAS_NATSBOOT_OPENBAO_*` with the same suffixes (auth method token); the publish Job uses `IMAS_NATSSIGN_*` with its own role.

---------------------------------------------------------------------
## 2. Call sites: exactly what each becomes

Rule: operator, operator-signing, sys-account, tenant and tenant-signing seeds and their `*.nk` files cease to exist. Public keys are read from the trust ConfigMap (platform) or from the Transit key (tenant). Key pairs for signing come from the KeyStore. Remaining files/Secrets: SYS_USER and SAASAPI_USER user seeds (these are user-kind keys, not CA keys; they stay as Secret seeds, SYS_USER becomes a required Secret seed instead of a generated file), and the bus fence user seed.

### 2.1 Trust model (new, internal/pki/natstrust.go)
```go
type NATSTrust struct { OperatorJWT, OperatorPub, OperatorSigningPub, SysAccountPub, SysAccountJWT, BusFenceUserJWT string }
func ParseNATSTrust(files map[string][]byte) (*NATSTrust, error)   // validates each JWT, issuers and prefixes
func LoadNATSTrustDir(dir string) (*NATSTrust, error)               // IMAS_NATS_TRUST_DIR, default /var/run/imas/nats-trust
func BootstrapNATSTrust(ctx context.Context, ks natskeys.KeyStore, in BootstrapInput) (*NATSTrust, error)
func (t *NATSTrust) VerifyAgainst(ctx context.Context, ks natskeys.KeyStore) error // compare pubs with Transit
```
ConfigMap `imas-nats-trust` (release namespace; name overridable by `natsTrust.configMapName`), keys: `operator.jwt`, `operator.pub`, `operator-signing.pub`, `sys-account.pub`, `sys-account.jwt`, optional `bus-fence-user.jwt`. Only public data. Mounted at /var/run/imas/nats-trust, env IMAS_NATS_TRUST_DIR.

Operator JWT: claims with Subject=operator pub, SigningKeys=[operator-signing pub], SystemAccount=sys pub, signed by `nats-operator` (kp.PublicKey() issuer). SYS account JWT: Subject=sys pub, signed by `nats-operator-signing` (issuer_account not set; operator signing key is listed in the operator JWT). Fence user JWT: signed by `nats-sys-account`.

Idempotence: BootstrapNATSTrust reuses existing JWTs that parse, validate, and match the Transit public keys; mints only what is missing. If existing operator/operator-signing/sys pubs differ from Transit it returns ErrTrustWouldChange and writes nothing (never silently replaces the trust anchor).

### 2.2 internal/pki/jwtauth.go
- natsAuthMaterial (42-62): drop operatorKP and tenantKP; keep public strings, operatorSigningKP and sysAccountKP as natskeys pairs, plus the legacy tenant signing pair; SYS_USER seed and JWT stay.
- ensureNatsAuth (100-278) is split: `ensurePlatformAuth` loads the trust (LoadNATSTrustDir), calls KeyPair (not Ensure) for `nats-operator-signing` and `nats-sys-account`, cross-checks pubs, and writes nothing for operator/sys JWTs except seeding `sys-account.jwt` into the farmer PVC when missing (the farmer then keeps its own revisions, jwtauth.go:193-212 behaviour). The publish Job calls only this. The remainder (sys user from the SYS_USER Secret seed, legacy tenant) stays in ensureNatsAuth.
- Operator JWT creation (165-191) and SYS JWT creation (193-212) are deleted from the farmer; the bootstrap Job owns them.
- Legacy tenant (254-275): keys `nats-tsign-<currentTenantID()>` and `nats-tacct-<currentTenantID()>` via EnsureKeyPair on first creation only (provisioning path), via KeyPair otherwise.
- loadExternalSeed (295) and loadOrCreateSeed (318) remain only for user-kind seeds (SYS_USER, SAASAPI_USER). Calls for OPERATOR, OPERATOR_SIGNING, SYS_ACCOUNT, TENANT, TENANT_SIGNING (118-157) are removed.
- pki.CheckNATSAuth(ctx): called from cmd/farmer/main.go before SetupPKIFarmer (147) so the farmer fails fast if trust is missing or Transit is unreachable or pubs mismatch.

### 2.3 internal/pki/tenant.go
- tenantAccountMaterial (60-65): drop `kp`; keep accountPub, signingKP (natskeys pair), signingPub.
- Paths (80-84): remove `.nk` paths; externalSeedNameForTenant (120-122) deleted.
- ensureTenantAccountMaterial (141-195) gets a `create bool` argument. Only ensureTenantAccountLocked (290) -> provisioning passes true: EnsureKeyPair(`nats-tsign-<id>`, Account) and EnsureKeyPair(`nats-tacct-<id>`, Account); the account JWT at 183 is `ac.Encode(operatorSigningKP)` unchanged in shape (signed via Transit). loadTenantAccountMaterial (205-217), PushAllAccounts (pushall.go:89) and seedResolverFromCore (nats.go:134-188) pass false: a missing key returns ErrKeyNotFound, never creates.
- ProvisionTenant (355-379): creates keys then JWT as above.
- DeprovisionTenant (393-428): after the lockout push and post-hook, RetireKey on both tenant keys; error returned if retire fails (non-404); idempotent. Update comment 384-385.
- signLockedOutTenantJWT (507-526): no tenant key needed; read the existing account JWT file or build minimal claims from `row.AccountPub`, and sign with operator-signing.
- syncTenantSprouts (676-752): tam.signingKP (696, 720) and operatorSigningKP (742) now Transit pairs; unchanged call shapes. Sign calls are concurrent-safe and batched.
- tenantIDsProvisionedOnDisk (824-843): unchanged (file-based JWT discovery).

### 2.4 internal/pki/jwtusers.go
mintOrReuseUserJWT (201-225), syncNatsAuth (233-324): tenantSigningKP at 249, 263, 290 and operatorSigningKP at 314 come from the Transit pairs; no code change except the construction site.

### 2.5 internal/pki/saasapi_user.go, saasapi_publish.go
- saasapi_user.go:161 (seed load) keeps SAASAPI_USER from the Secret; `uc.Encode(mat.sysAccountKP)` (218) and `sysClaims.Encode(mat.operatorSigningKP)` (233) sign via Transit pairs.
- requireSaaSAPIKeyMaterial (saasapi_publish.go:60-78): now checks trust dir present and SAASAPI_USER seed; the SYS_ACCOUNT seed check is removed.
- resolver.go connectSystemAccount (84-103): sysUserJWT/sysUserSeed unchanged (SYS_USER Secret seed + JWT from `sys-account` Transit signing).

### 2.6 Bus (cmd/farmerbus, internal/pki/busauth.go)
- loadBusAuth (75-151), signAccountClaimsAt (159-196), dropSelfMintedClaims (232-253), busBootstrapIssuedAt constant: deleted.
- ConfigureBusNats (202-224) reads operator JWT, SYS pub and SYS account JWT from the trust dir. No private keys, no Transit access from the bus.
- Fence user: seed from `IMAS_NATS_BUS_FENCE_USER_SEED_FILE` (Secret key BUS_FENCE_USER) and `bus-fence-user.jwt` from the trust dir. startBus (cmd/farmerbus/main.go:167-196) returns an error if clustered and no fence user is configured. The fence (fence.go:157-164) continues to use UserJWTAndSeed.
- The bus resolver directory stays on its PVC (D10/D11 are slice 2).
- Tests using signAccountClaimsAt (busauth_test.go:113) switch to the fake Transit.

### 2.7 Other consumers that change only in test/tooling
tools/loadtest/fixture.go:82 and localbus.go:196 build an in-process fake Transit via pkitest. cmd/farmerbus/cluster_integration_test.go:60-100 likewise. internal/saasapi/provisioning_e2e_test.go:530 corrupted operator.nk: replace with corrupting the fake's key (or removing the trust ConfigMap file). Other packages whose tests mint through pki (internal/natsapi, internal/facts, internal/heartbeat, internal/cook, internal/api, internal/api/handlers, internal/saasapicred/run_test.go, internal/pki/*_test.go: jwtauth_test, busauth_test, saasapi_*_test, tenant*_test, pushall_test, jwt_integration_test, envoy_e2e_test) move to pkitest.

---------------------------------------------------------------------
## 3. Transit keys, paths and policies

### 3.1 Key names (mount `transit`, TRANSIT_MOUNT overridable), flat
| Purpose | Transit key | NKey prefix |
|---|---|---|
| operator identity (D3) | nats-operator | O |
| operator signing | nats-operator-signing | O |
| SYS account | nats-sys-account | A |
| tenant signing | nats-tsign-<tenantID> | A |
| tenant account | nats-tacct-<tenantID> | A |

All type ed25519, exportable=false, allow_plaintext_backup=false. Names live in natskeys/names.go (functions OperatorKey(), OperatorSigningKey(), SysAccountKey(), TenantSigningKey(id), TenantAccountKey(id)). If Step 1's real-server check shows slashes are accepted, the design's slash names (nats/operator ...) are adopted by editing names.go and the policies only.

### 3.2 Policies (HCL; files under deploy/helm/farmer/files/openbao-policies/, listed in the policies ConfigMap)

imas-farmer-natssign (farmer runtime; chart role `imas-farmer-natssign`, bound to the farmer ServiceAccount):
```hcl
path "transit/keys/nats-operator"         { capabilities = ["read"] }
path "transit/keys/nats-operator-signing" { capabilities = ["read"] }
path "transit/keys/nats-sys-account"      { capabilities = ["read"] }
path "transit/sign/nats-operator-signing" { capabilities = ["update"] }
path "transit/sign/nats-sys-account"      { capabilities = ["update"] }
# per-tenant keys: create at provisioning, read, soft/hard delete at offboarding. No "update":
# update on keys/<name>/config or /rotate is thereby not granted.
path "transit/keys/nats-tsign-*"          { capabilities = ["create", "read", "delete"] }
path "transit/keys/nats-tacct-*"          { capabilities = ["create", "read", "delete"] }
path "transit/sign/nats-tsign-*"          { capabilities = ["update"] }
```
Deliberately absent: sign on nats-operator (D3 and design section 6: operator identity signs only during bootstrap), sign on nats-tacct-* (the tenant account JWT is signed by operator-signing; the tacct key is never needed to sign), export/backup/restore, rotate, config. `delete` on transit/keys/<name>/soft-delete: the glob `transit/keys/nats-tsign-*` is a prefix match and covers sub-paths such as `/soft-delete`; soft-delete is invoked as a DELETE on that sub-path, which `delete` capability covers. UNVERIFIED: that soft-delete uses DELETE (docs say `DELETE keys/:name/soft-delete`; real-server test in Step 1 confirms).

imas-nats-sys-signer (publish Job; role `imas-natssign-publisher`): read on the three platform keys, `update` on transit/sign/nats-sys-account only.

imas-nats-bootstrap (ephemeral, written and deleted by the Job): read and create on the three platform keys, `update` on transit/sign/nats-operator, nats-operator-signing, nats-sys-account; `auth/token/revoke-self` update; `auth/token/lookup-self` read; optional KV `secret/data/platform/imas/nats-trust` create/update/read when natsTrust.kvCopy.enabled.

TestFarmerPoliciesAreExact (chart_test.go:671) is amended to allow exactly the `nats-tsign-*` and `nats-tacct-*` globs for imas-farmer-natssign and still forbids `+` and other `*`.

### 3.3 Tenant key lifecycle
- Creation: only at provisioning (ProvisionTenant -> ensureTenantAccountLocked, tenant.go:290/355-379) via EnsureKeyPair. Enrollment of an already-provisioned tenant, resync, push-all and resolver seeding never create keys.
- Offboarding: DeprovisionTenant retires (soft-deletes) both keys after the lockout JWT push (section 2.3). Retained material can be restored by an operator (`soft-delete-restore`); purge (hard delete: set deletion_allowed, delete) is an operator action, not farmer (OWNER DECISION b).

---------------------------------------------------------------------
## 4. Rewritten bootstrap Job

Single Job `{{fullname}}-openbao-bootstrap` (hook weight 0, unchanged position). Structure:

### 4.1 Init container `prepare` (image openbaoTools, `bao` shell, root token from the Secret/dev root token)
1. Existing steps: mounts, PKI, Kubernetes auth config, policies from /policies/*.hcl (including `imas-farmer-natssign`, `imas-nats-sys-signer`, plus the ephemeral `imas-nats-bootstrap` written from the same ConfigMap).
2. If the NATS platform keys all exist and the trust ConfigMap is complete (checked in step 3 of the next container), no token is minted: when the root token Secret is absent (optional ref) the container exits 0.
3. Otherwise mint an orphan, non-renewable, 10-minute token with policy `imas-nats-bootstrap` only: `bao token create -orphan -no-default-policy -policy=imas-nats-bootstrap -ttl=10m -renewable=false -field=token > /handoff/token` and the accessor to /handoff/accessor (`-field=` because no jq in the image). /handoff is a memory-backed emptyDir (medium Memory), mounted only in `prepare` and `nats-trust`.

### 4.2 Init container `nats-trust` (farmer image, command `farmer bootstrap-nats-trust`, new package internal/natsbootstrap, registered in cmd/farmer/subcommands.go next to ControlPlaneBoxKeysCommand, pattern internal/saasapicred/run.go and pki/controlplanekeys.go)
Env `IMAS_NATSBOOT_*` (token read from /handoff/token via IMAS_NATSBOOT_OPENBAO_TOKEN_FILE). Steps, all idempotent:
1. If no token file: read the ConfigMap; exit 0 if complete (all required keys, JWTs valid, pubs match Transit via VerifyAgainst), else exit 1 with a clear message.
2. EnsureKeyPair for nats-operator (O), nats-operator-signing (O), nats-sys-account (A) with hardened params.
3. Read ConfigMap `imas-nats-trust` (get; 404 means create). BootstrapNATSTrust(existing) per section 2.1: reuse valid JWTs, mint missing ones (operator JWT via nats-operator, SYS JWT via nats-operator-signing, optional fence user JWT via nats-sys-account when `BusFenceUserPub` is given from `IMAS_NATSBOOT_BUS_FENCE_USER_PUB`).
4. Write the ConfigMap through a minimal REST kube client (in-cluster, projected SA token at the standard path, namespace from the pod): POST create, PUT update with resourceVersion; retry on 409 conflict (3 times, re-read and re-merge).
5. Optional: copy public data to KV `secret/platform/imas/nats-trust` (default off).
6. Self-revoke the handoff token (`auth/token/revoke-self`). Remove /handoff/token.
Exit non-zero on any failure; the Job fails (backoffLimit as today).

### 4.3 Main container `bootstrap` (shell, `bao`)
1. The existing `role` lines plus `role imas-farmer-natssign ...` and `role imas-natssign-publisher ...` (TestBootstrapRoles parses these).
2. If /handoff/accessor exists: `bao token revoke -accessor $(cat /handoff/accessor)` (tolerating already revoked).
3. `bao policy delete imas-nats-bootstrap` (removes operator-identity signing permission from anything).
4. Revoke the root/bootstrap token last: `bao token revoke -self`, unless dev mode or `openbaoBootstrap.revokeToken: false`. Default true.

### 4.4 Job plumbing
- ServiceAccount for the Job (name `{{fullname}}-openbao-bootstrap`), projected token mounted only into `nats-trust`.
- Role/RoleBinding: `configmaps` verbs `create` (no resourceNames possible for create) and `get,update,patch` restricted by resourceNames [imas-nats-trust].
- NetworkPolicy egress to kube API: new `networkPolicy.external.kubeApi` value (CIDRs/ports), absent today.
- Bump `openbaoTools.tag` 2.6.3 to 2.7.1 (values.yaml:139-144).
- Token Secret reference becomes `optional: true`.
- chart_test.go container() helper only looks at `containers`; add an initContainers-aware helper for assertions.

---------------------------------------------------------------------
## 5. Env vars, chart values and every file to touch

### 5.1 Env
Farmer: IMAS_NATSSIGN_OPENBAO_* (section 1.6), IMAS_NATS_TRUST_DIR. Bus: IMAS_NATS_TRUST_DIR, IMAS_NATS_BUS_FENCE_USER_SEED_FILE. Publish Job: IMAS_NATSSIGN_* with role imas-natssign-publisher and IMAS_NATS_TRUST_DIR. Bootstrap: IMAS_NATSBOOT_*.

### 5.2 Values
Farmer chart (deploy/helm/farmer/values.yaml): `natsSeeds.seeds` reduced to SYS_USER and SAASAPI_USER (was lines 73-92); new `natsTrust: {configMapName: imas-nats-trust, kvCopy: {enabled: false}}`; new `farmer.openbao.natsSign: {role: imas-farmer-natssign, transitMount: transit, timeout: 15s, batchMax: 64, workers: 4}` (next to farmer.openbao 319-339); `openbaoBootstrap.revokeToken: true` (784-805); `networkPolicy.external.kubeApi`; `openbaoTools.tag: 2.7.1`.
Nats chart (deploy/helm/nats/values.yaml:25-41): `natsSeeds` reduced to `BUS_FENCE_USER` (required when replicaCount > 1); new `natsTrust.configMapName`.

### 5.3 Files (Go)
New: internal/pki/natskeys/{natskeys,keypair,batch,names,env}.go, natskeys/natskeystest/fake.go, internal/pki/pkitest/pkitest.go, internal/pki/natstrust.go, internal/natsbootstrap/{run,kube}.go.
Modified: internal/openbao/openbao.go (ResetToken), internal/pki/{jwtauth,busauth,tenant,jwtusers,nats,pushall,saasapi_user,saasapi_publish,resolver,store}.go, cmd/farmer/{main,subcommands}.go, cmd/farmerbus/{main,fence}.go, tools/loadtest/{fixture,localbus}.go, and tests listed in 2.7.

### 5.4 Files (chart/UAT/docs)
Farmer chart: values.yaml; templates/{farmer-deployment,openbao-bootstrap-job,saasapi-credential-publish-job,externalsecrets,openbao-policies-configmap,_helpers.tpl (seeds helper 223-228, openbaoEnv 253-277, policy 491-503, validation 639-653, name-collision lists at 817 and 894)}; new templates/{nats-trust-rbac.yaml}; files/openbao-policies/{imas-farmer-natssign,imas-nats-sys-signer,imas-nats-bootstrap}.hcl; chart_test.go; README.md (Seeds 284-309, OpenBao client table 437-498, replica note 898-911). deploy/farmer/{README.md,externalsecrets.yaml (properties become sys_user and saasapi_user),farmer-deployment-nats-seeds.patch.yaml,saasapi-credential-publish-job.yaml}. Nats chart: values.yaml, templates/{_helpers.tpl,bus-statefulset.yaml,bus-configmap.yaml}, chart_test.go (195-244). UAT: uat/hub/core/{seeds.sh,lib/common.sh,values/farmer-uat.yaml,test/run.sh,core_test.go,saasapi-secrets.sh}, uat/hub/dmz/{lib.sh:19-21,install.sh:215-250,values-uat.yaml:25-35,dmz_test.go:1001}. Docs: docs/design/imas-internal-api-account.md, docs/loadtest.md, docs/claude-code-parallel-build-plan.md, status fragment docs/status/days/2026-10-11/z-p21-slice1-transit-signer.md (item P21, action update; format per docs/status/README.md, check with scripts/status/rollup.py --check).

---------------------------------------------------------------------
## 6. Tests (named)

### 6.1 Unit, internal/pki/natskeys (fake Transit)
- TestKeyPairImplementsNKeys: PublicKey prefix, Verify local, Seed/PrivateKey return ErrPublicKeyOnly.
- TestPublicKeyEncodingMatchesLocalNKey: raw32 from the fake produces the same string as nkeys.Encode from the same ed25519 key.
- TestSignIsRawEd25519OverJWTInput: jwt Encode, then ed25519.Verify of the base64url-decoded signature over "header.payload" (T1 core; also verifies against the captured fixtures in internal/gatewayjwt/testdata/openbao-v2.7.0).
- TestT1_NatsServerAcceptsTransitSignedJWTs: in-process nats-server with a Transit-signed operator JWT, SYS and tenant account JWTs and a user JWT; a client connects and publishes (design T1).
- TestKeyVersionPinned: rotate on the fake; pair keeps signing with the pinned version; mismatched `vault:vN:` prefix is ErrBadSignature.
- TestBatchingGroupsByKey: N concurrent signs result in fewer requests; per-item error isolated.
- TestRetryOnTransient / TestRetryNever400and404 / TestReloginOn403Once.
- TestRejectsBadSignature: fake returns a signature of another key.
- TestRejectsUnhardenedKeys: exportable, allow_plaintext_backup, imported, derived, wrong type, soft-deleted.
- TestEnsureKeyPairRace: concurrent create gets 400/403, re-read succeeds.
- TestRetireKeyIdempotent.
- TestConfigFromEnv, TestKeyNames.
- TestSignTimeout.

### 6.2 pki, bootstrap, bus
- internal/pki: TestBootstrapNATSTrustFirstRun, TestBootstrapNATSTrustIdempotent (T4: second run writes nothing, JWTs byte-identical), TestBootstrapNATSTrustRefusesChangedAnchor (ErrTrustWouldChange), TestVerifyAgainstDetectsMismatch, TestEnsureNatsAuthWritesNoRemovedSeedFiles (no operator/operator-signing/sys-account/tenant/tenant-signing `.nk` files), TestProvisionCreatesTenantKeys, TestEnrollExistingTenantCreatesNoKeys, TestDeprovisionRetiresKeysAfterPush, TestLockoutWithoutTenantKeys, TestResolverSeedingWithoutTransit.
- Bus (T5): TestConfigureBusNatsFromTrustOnly (no network, no Transit), TestBusFenceUserRequiredWhenClustered, TestBusFenceUserFromSeedAndTrust.
- internal/natsbootstrap: TestRunFirstCreatesConfigMap, TestRunIdempotent, TestRunNoTokenCompleteConfigMap, TestRunNoTokenIncompleteFails, TestRunSelfRevokesToken, TestConfigMapConflictRetry (httptest kube API).
- Chart: TestBootstrapJobStructure (init containers prepare and nats-trust, revoke steps), TestBootstrapRoles (extended), TestFarmerPoliciesAreExact (amended), TestSeedsAreReferencesOnly (two seeds), TestNatsTrustMounts, TestNatssignEnv, TestKubeApiEgress, TestContractWithNatsChart (updated), TestExternalSecretsMatchReference and TestPublishJobMatchesReference (updated references).

### 6.3 Integration against real OpenBao (skipped unless IMAS_TEST_OPENBAO_ADDR and IMAS_TEST_OPENBAO_TOKEN are set; pattern cmd/fleetreleaser/openbao_integration_test.go; admin helper internal/openbao/openbaotest/admin.go)
- TestOpenBaoSlashKeyNames (records the UNVERIFIED answer; non-failing log plus t.Skip branch).
- TestOpenBaoSignerWithNatsServer: EnsureKeyPair, sign JWTs, nats-server accepts (T1 against the real server).
- TestOpenBaoPolicyEnforcement: farmer policy cannot sign with nats-operator, cannot create `other-*` keys, cannot rotate or export; bootstrap policy gone after cleanup.
- TestOpenBaoSoftDeleteBlocksSigning.
CI: no IMAS_TEST_OPENBAO wiring exists today (searched .github/workflows; the only OpenBao real-server workflow is sdb-openbao-realserver.yml, which pins OpenBao 2.7.1 with a SHA256 and starts a TLS dev server). Add a sibling workflow `.github/workflows/natskeys-openbao-realserver.yml` modelled on it (paths: internal/pki/natskeys/**, go.mod, go.sum), in Step 1.

---------------------------------------------------------------------
## 7. Ordered implementation, one PR each (each PR: go build ./..., go vet ./..., go test ./... green, helm chart tests green; real-OpenBao tests skipped locally and run in the new workflow)

1. PR1 natskeys: package, fake, env, ResetToken, real-server tests and workflow. Green: all section 6.1 and 6.3.
2. PR2 trust model (natstrust.go, pkitest). Green: T4 tests.
3. PR3 natsbootstrap subcommand plus registration. Green: natsbootstrap tests.
4. PR4a pki seam: introduce interfaces for key pair providers in pki, no behaviour change. Green: existing tests untouched.
5. PR4b cut-over: Transit everywhere in pki, removal of seed paths, test migration across all affected packages (section 2.7). Green: full go test ./...
6. PR5 bus side (ConfigureBusNats from trust, fence user), loadtest and cluster test. Green: T5 tests, loadtest smoke.
7. PR6 charts (farmer and nats together because TestContractWithNatsChart:1877 couples them): Job, RBAC, policies, values, references. Green: all chart tests.
8. PR7 UAT scripts/values/docs, status fragment, T4/T5 real-cluster checks.
Every PR carries "FLAG FOR SECURITY REVIEW" wording (CLAUDE.md:44-47: "ready for review", never "done").

---------------------------------------------------------------------
## OWNER DECISIONS NEEDED

(a) Bootstrap token lifecycle after first install.
 - Option 1: no standing admin; policy or role changes re-run the Job with a fresh root token produced from the recovery quorum (2-of-3). Option 2: a standing admin role kept for the Job (effectively root-equivalent).
 - Recommendation: Option 1.

(b) Offboarding key retention.
 - Option 1: farmer soft-deletes tenant keys; an operator purges after a retention window (recommend 30 days; owner sets the window and names who purges). Option 2: farmer hard-deletes (irreversible).
 - Recommendation: Option 1, subject to DPDP/offboarding retention requirements.

(c) How the trust ConfigMap reaches a DMZ bus in another cluster.
 - Option 1: manual or pipeline copy of the public ConfigMap. Option 2: KV copy plus ESO in the DMZ (requires DMZ-to-core OpenBao reachability).
 - Recommendation: Option 1.

## Owner decisions (2026-10-11) - these settle "OWNER DECISIONS NEEDED" above; do not ask again
- (a) No standing admin after first install. Policy or role changes re-run the bootstrap Job with a fresh root token generated from the recovery quorum.
- (b) Tenant keys are soft-deleted by farmer at offboarding; an operator purges after a retention window. Default window 30 days, configurable by a chart value; purge is a documented operator runbook step in the chart README.
- (c) The public trust ConfigMap reaches a DMZ bus in another cluster by copying it (by hand or pipeline). It holds public data only. Document the copy step in the chart README.
