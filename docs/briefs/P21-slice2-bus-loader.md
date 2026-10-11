# Slice 2 build specification: stateless bus with an S3 account loader

Repo: /home/claude/yogzblr/imas (module github.com/yogzblr/imas), branch docs/horizontal-scale-gate.
Status: specification only. No code was written or run. The Go toolchain in this sandbox is go1.24.7 (the repo needs a newer one and the download was blocked), so nothing here was compiled or tested; every statement about current behaviour comes from reading source. Items I could not read are listed in section 14.

Citations are file:line against the current tree. nats-server citations are to v2.14.5 source (fetched from the tag; dependencies/ in the repo holds licences only).

---------------------------------------------------------------------
## 0. Decisions already taken (inputs, not open)

- Bus is stateless: no PVC. Resolver directory is an emptyDir.
- Each bus node runs an account LOADER. Form chosen here: a sidecar container (section 3).
- Storage is S3 protocol only. UAT RustFS, production Versity Gateway over Azure Blob.
- Farmer writes `accounts/<account pub>.jwt` and bumps `accounts/index`. Farmer holds the write credential; loader holds a read-only credential.
- Loader keeps the JWT with the highest iat per account and never pushes an older one.
- Plain (non-queue) subscription for the farmer broadcast event; plus a timer.
- Slice 1 delivers the bus trust ConfigMap (operator JWT, SYS public key). Section 11 pins its keys.
- No production exists: no migration, no compatibility shims.
- Tests follow D7: test our code with fakes.

---------------------------------------------------------------------
## 1. Current behaviour this slice depends on (verified)

1.1 Resolver. `ConfigureBusNats` builds `NewDirAccResolver(resolverStoreDir(), ...)` and seeds only the SYS bootstrap JWT (internal/pki/busauth.go:202-224). `resolverStoreDir()` is `FarmerPKI/nats-auth/resolver` (internal/pki/jwtauth.go:72-74). In nats-server, `NewDirAccResolver(dir, 0, 0, HardDelete)` defaults the sync interval to 1 minute (server/accounts.go:4611-4628).

1.2 Claims update. The `$SYS.REQ.CLAIMS.UPDATE` handler calls `dr.save` (an UNCONDITIONAL write) and then fires the changed callback (accounts.go:4456-4470, dirstore.go:481-507). `Store()` is the compare-and-keep path (same jti skip; existing larger iat skip) (accounts.go:4585, dirstore.go:509-555). Inter-node pack/merge sync is newest-iat-wins.

1.3 Fan-out. Every node subscribes to the claims subjects in the SYS account with sysSubscribe, so one push reaches every directly routed peer (cmd/farmerbus/fence.go:6-17; deploy/helm/nats/README.md:285-291). Replies carry server info, so a reply is attributable to a node. `$SYS.REQ.CLAIMS.LIST` replies carry `Server.ID` plus account IDs (fence.go listReply). LOOKUP replies are raw JWT without a server id. `ACCOUNTZ` lists only in-memory accounts, so it cannot prove a stored JWT.

1.4 HAZARD (new finding). Because the push is an unconditional save AND fans out, a loader that pushes a stale JWT can overwrite a newer one on every peer. Mitigation is in section 5.6 (re-read after push). A fallback is in section 13.

1.5 Fence (cmd/farmerbus/fence.go). Gate on TLS handshakes (VerifyConnection), majority / partial-mesh / pull checks, `claimRank` (newest iat; locked-out wins a tie; then raw string; fence.go:467-485), `rank()` validates subject and trusted issuer (fence.go:487-499). Health: `serveHealth` with /healthz and /readyz (fence.go:533-556). Cluster size: `newFence(cl.Size(), ...)` (cmd/farmerbus/main.go:173); `Size()` is `len(IMAS_BUS_CLUSTER_ROUTES)` (cmd/farmerbus/cluster.go:75-76). The chart renders routes from replicaCount (deploy/helm/nats/templates/_helpers.tpl:138-146).

1.6 Bus node readiness. `busNode.Ready` = server running AND (fence nil OR not Fenced) (cmd/farmerbus/main.go:140-145). `RunNATSServer` is main.go:113-131; `startBus` main.go:167-197. main.go:1-9 states farmerbus embeds no object storage.

1.7 SYS user today. `BusSysUser` is minted inside the bus from the SYS seed (internal/pki/busauth.go:126-149). After slice 1 the bus holds no seeds, so the loader and fence need a provided SYS user credential (section 11).

1.8 Operator / bootstrap. `loadBusAuth` mints operator claims in memory and the SYS bootstrap JWT at iat=1 (busauth.go:75-151). `dropSelfMintedClaims` (busauth.go:232-253) is an old-bus migration shim: REMOVE (no migration).

1.9 Account JWT iat. Lock-outs use `waitPastIssuedAt` so iat is strictly newer (internal/pki/tenant.go:664-668). Deprovision is a lock-out JWT, never a delete (tenant.go:381-428). A tombstone for a never-provisioned tenant has no Account.

1.10 Where Account JWTs are written today (all `writeFileAtomic` on farmer disk):
- internal/pki/jwtauth.go:208 (sys-account.jwt), :271 (tenant.jwt, legacy tenant)
- internal/pki/jwtusers.go:318 (syncNatsAuth / tenantJWTPath)
- internal/pki/tenant.go:187 (ensureTenantAccountMaterial), :522 (signLockedOutTenantJWT), :746 (syncTenantSprouts)
- internal/pki/saasapi_user.go:237 (SYS JWT re-sign on SaaS API key rotation; push at :149)

1.11 Where pushes happen today:
- internal/pki/resolver.go:521-528 `pushAccountUpdate` (fresh connection per push via connectSystemAccount to config.FarmerBusURL, i.e. the Service, so it lands on ONE node); :551-564 `publishClaimsUpdate` (nc.Request, 10 s timeout).
- internal/pki/pushall.go:48-127 `PushAllAccounts`; :150-173 `pushUntilCurrent` (push, re-read, repeat until current).
- internal/pki/tenant.go: `pushLiveTenantAccount` 585-608, `ProvisionTenant` 355-379, `DeprovisionTenant` 393-428, `ReloadNKeysForTenant` 763-783, `ResyncProvisionedTenants`.
- internal/pki/nats.go: `ReloadNKeys` 465-485.
- cmd/farmer/main.go: start-up 120-230; `initSystemAccountListeners` ~477-535 (Connect/Reconnect handlers call pushAllAccounts); `pushAccountsUntilAccepted` 539-553; `pushAllAccounts` 559-565; `ConnectFarmer` push loop ~900-925; `handleSIGHUP` ~660-700.
The old backlog text recorded in git history: "core still pushes Accounts to one bus node without waiting for all; farmer's per-tenant bus connection gives up after 30 failed attempts ... a sprout whose User JWT is refused twice stays offline until restarted".

1.12 Object store package (internal/objectstore). Wraps minio-go v7.3.0 (already in go.mod). API: `Open(Config{Endpoint,AccessKeyID,SecretAccessKey,UseSSL,Bucket})`, `Get`, `GetLimited`, `GetLimitedWithInfo` (conditional.go:94-125, returns ETag), `Put`, `PutConditional` (conditional.go:66-88), `Delete`, `List`, `ListPage(prefix,startAfter,max)` (conditional.go:133-153, max 10000), `Ping`, `WaitReady(RetryPolicy)` with jitter, `IsNotExist`, `TryAccess`/`ExpectDenied` probes (probe.go:107-272; ExpectDenied fails closed, line 226-232). Fake S3: internal/objectstore/objectstoretest (NewServer, NewStore, NewSharedStores, FailNext(n,status,code), BeforePut, Deny(fn(op,key)), Set, Keys, Object, Seed; single bucket "test-bucket"; supports GET/PUT/HEAD/DELETE, ListObjectsV2 with start-after, If-Match/If-None-Match).

1.13 Chart (deploy/helm/nats). StatefulSet has a persistence volumeClaimTemplate (templates/bus-statefulset.yaml:299-321); validation forces persistence when clustered (templates/_helpers.tpl:196-198) with a test case "cluster without persistence" in chart_test.go. Bus NetworkPolicy egress is DNS only plus OpenBao in openbao mode (templates/networkpolicy.yaml:429-449). README.md:490 says "The bus never opens a connection into the core network". Readiness is HTTP /readyz on 8080. PDB maxUnavailable 1, rendered only when replicaCount>1. podManagementPolicy Parallel, RollingUpdate.

1.14 Config loading. `config.LoadConfig` folds every env var into config and calls jety.WriteConfig; /etc/imas/farmer is mounted read-only for that reason. The loader binary therefore must NOT call config.LoadConfig.

1.15 Farmer S3 config today: IMAS_S3_ENDPOINT, IMAS_S3_ACCESS_KEY_ID, IMAS_S3_SECRET_ACCESS_KEY, IMAS_S3_BUCKET, IMAS_S3_JOB_BUCKET, S3UseSSL default true (internal/config/config.go:574-621, 851-856). Farmer chart values: `objectStore.{endpoint,useSSL,bucket,jobBucket,credentialsSecret,accessKeyIdKey,secretAccessKeyKey}` (deploy/helm/farmer/values.yaml ~210-221); farmer.replicaCount held at 1 (values.yaml:235).

1.16 Release. Build id farmerbus (.goreleaser.yaml:167-178); images farmerbus-amd64/arm64 (.goreleaser.yaml:558-585); Dockerfile is distroless static with `COPY imas-farmerbus /farmerbus`.

---------------------------------------------------------------------
## 2. S3 client choice

Use the existing internal/objectstore package (minio-go v7.3.0, Apache-2.0). No new dependency, no licence change (DEPENDENCIES.md untouched). It speaks plain S3 (path-style capable), which is what RustFS and Versity Gateway expose. Do not rely on conditional PUT (D13); the design below needs only GET, PUT, LIST, HEAD. Ordinary PUT overwrites; ListObjectsV2 is used for discovery and ETag change detection. ETag is treated as opaque and compared only for equality with the last value seen.

Versity/Azure note: listing and ETag semantics on Versity are not verified in this repo. Section 12 tests only against the fake; section 14 flags a manual check on the Versity gateway before production.

---------------------------------------------------------------------
## 3. Loader form

A new Go binary `cmd/farmerbus-loader`, shipped in the SAME image as farmerbus (second binary), run as a regular sidecar container in the bus pod.

Why not an init container: it must push through the running server; an init container finishes before the server starts. Why not a native sidecar (restartable init container): it starts before the main container, so the server is not there yet. A normal second container retries until the server answers.

Why not inside farmerbus: main.go:1-9 forbids object storage in farmerbus, and the loader needs a credential farmerbus must not hold.

Pod readiness: pod Ready = farmerbus container ready (/readyz, fence.go:533-556) AND loader container ready (its own /readyz). Kubernetes ANDs container readiness, so the pod is not Ready until everything is loaded. farmerbus stays S3-free.

The loader does not import internal/config. It parses its own env (section 4.5) in `cmd/farmerbus-loader/main.go`.

---------------------------------------------------------------------
## 4. Contracts

### 4.1 Bucket and key layout
Bucket name: value `accountStore.bucket` (default `imas-accounts`). Private; no public policy.
- `accounts/<account public key>.jwt` : body is the raw Account JWT text (one line, no trailing newline required, trailing whitespace trimmed on read), Content-Type text/plain. `<account public key>` is the nkey public key starting `A` (the JWT `sub`). The SYS account is stored here too under its own public key.
- `accounts/index` : JSON object, Content-Type application/json:
  `{"v":1,"token":"<26-char random base32>","written":"<RFC3339>"}`
  The token is random per bump, NOT a counter: farmer has no CAS, and two concurrent bumps must both be visible as "changed".
Objects are never deleted. Deprovision is a lock-out JWT (tenant.go:381-428), which is a newer-iat object under the same key. If an object vanishes, the loader keeps its held copy and logs a warning (metric `loader_object_missing_total`).

### 4.2 JWT object validity (loader enforces on every fetch)
Decode with nats-io/jwt/v2 `DecodeAccountClaims`; reject (log, count, skip, keep held copy) unless: signature valid; `Subject` equals the key name; issuer is one of the trusted operator signing keys; `IssuedAt > 0`. Reuse the fence's `rank()` logic (fence.go:487-499) by extracting it, with `claimRank` (fence.go:467-485), into a new package `internal/accountrank` imported by both fence.go and the loader. Size cap 1 MiB per object (GetLimitedWithInfo).

### 4.3 Event
Subject `imas.bus.accounts.changed`, published by farmer in the SYS account (needs `pub imas.bus.accounts.changed` in farmer's SYS-account user; loader's SYS user gets `sub imas.bus.accounts.changed`). Loader uses a plain `nc.Subscribe` (NOT QueueSubscribe), so every node's loader receives it. Core NATS delivery is at-most-once and not replayed; it is a hint.
Payload JSON: `{"v":1,"token":"<index token>","accounts":{"<pub>":<iat>,...}}`. `accounts` omitted or empty means "full reconcile". Max 64 KiB; farmer sends omitted-accounts when more than 500 entries.

### 4.4 Timer
Loader polls `accounts/index` every `IMAS_LOADER_RECONCILE_INTERVAL` (default 30s, jitter +-20%). Token changed since last applied: list and diff (5.4). Independently, a full resync (list accounts/, diff by ETag) every `IMAS_LOADER_FULL_RESYNC_INTERVAL` (default 5m), which covers a farmer crash between the object PUT and the index bump.

### 4.5 Loader environment (all required unless a default is shown)
- IMAS_LOADER_S3_ENDPOINT (host:port, no scheme)
- IMAS_LOADER_S3_USE_SSL (default true)
- IMAS_LOADER_S3_BUCKET
- IMAS_LOADER_S3_ACCESS_KEY_ID_FILE, IMAS_LOADER_S3_SECRET_ACCESS_KEY_FILE (file paths; read once at start, re-read on each reconnect so a rotated Secret is picked up)
- IMAS_LOADER_NATS_URL (default tls://127.0.0.1:4222)
- IMAS_LOADER_NATS_SERVER_NAME (TLS ServerName = the bus Service FQDN)
- IMAS_LOADER_CA_FILE
- IMAS_LOADER_SYS_USER_JWT_FILE, IMAS_LOADER_SYS_USER_SEED_FILE
- IMAS_LOADER_EVENT_SUBJECT (default imas.bus.accounts.changed)
- IMAS_LOADER_RECONCILE_INTERVAL (30s), IMAS_LOADER_FULL_RESYNC_INTERVAL (5m)
- IMAS_LOADER_PUSH_CONCURRENCY (8), IMAS_LOADER_PUSH_RATE (200/s)
- IMAS_LOADER_HEALTH_PORT (8081)
Farmer side (internal/config/config.go, new fields, env names `IMAS_ACCOUNTS_S3_ENDPOINT` (defaults to IMAS_S3_ENDPOINT), `IMAS_ACCOUNTS_S3_USE_SSL` (defaults to S3UseSSL), `IMAS_ACCOUNTS_S3_BUCKET`, `IMAS_ACCOUNTS_S3_ACCESS_KEY_ID`, `IMAS_ACCOUNTS_S3_SECRET_ACCESS_KEY`, `IMAS_ACCOUNTS_EVENT_SUBJECT`, `IMAS_BUS_EXPECTED_NODES`). A separate credential and bucket from IMAS_S3_BUCKET; farmer's existing credential must not be able to write the accounts bucket (and vice versa).

### 4.6 Helm values and Secret names
Bus chart (deploy/helm/nats/values.yaml), new block replacing `bus.persistence` (currently lines 165-178, to be deleted):
```
accountStore:
  endpoint: ""            # required
  useSSL: true
  bucket: imas-accounts
  credentialsSecret: imas-bus-accounts-reader   # keys: access-key-id, secret-access-key
  reconcileInterval: 30s
  fullResyncInterval: 5m
  eventSubject: imas.bus.accounts.changed
loader:
  image: {}               # defaults to the bus image
  healthPort: 8081
  resources: {requests: {cpu: 50m, memory: 64Mi}, limits: {memory: 256Mi}}
  sysUserSecret: imas-bus-loader-sys-user      # keys: user.jwt, user.nk
trust:
  configMap: imas-bus-trust                    # section 11
networkPolicy:
  accountStoreEgress: {cidr: "", port: 443}    # required when networkPolicy.enabled
```
Farmer chart (deploy/helm/farmer/values.yaml): `accountStore.{endpoint,useSSL,bucket,credentialsSecret(imas-farmer-accounts-writer),accessKeyIdKey,secretAccessKeyKey}` and `bus.expectedNodes`. Rendered into farmer-deployment.yaml env next to the existing S3 block (~lines 99-120).

---------------------------------------------------------------------
## 5. Loader algorithm (internal/accountloader)

### 5.1 Packages and interfaces
- `internal/accountloader` (all logic, no main):
  - `type ObjectSource interface { Index(ctx) (token string, err error); List(ctx) ([]ObjInfo, error); Get(ctx, key) (jwt []byte, info ObjInfo, err error) }` implemented by `objectstoreSource` wrapping internal/objectstore (ListPage prefix "accounts/", GetLimitedWithInfo).
  - `type NodeClient interface { Push(ctx, accountPub string, jwt []byte) error; ListIDs(ctx) (serverID string, accounts []string, err error); ConnectedServerID() string }` implemented by `natsNodeClient` (SYS user, localhost).
  - `type Loader struct{...}` with `Run(ctx)`, `Ready() bool`, `Status() Status`.
  - state: `applied map[pub]appliedEntry{iat int64, etag string, jti string}` guarded by a mutex.
- `cmd/farmerbus-loader/main.go`: env parse, wiring, HTTP health server, signal handling (SIGTERM cancels ctx; exit 0).
- `internal/accountrank` extracted from fence.go (section 7).

### 5.2 Connecting to its node
`natsNodeClient` dials `IMAS_LOADER_NATS_URL` with `nats.Secure(tls.Config{RootCAs: CA, ServerName: ...})` and `nats.UserJWT(jwtCB, sigCB)` from the SYS user files. Retries forever with exponential backoff (500ms to 10s, jitter), `nats.RetryOnFailedConnect(true)`, MaxReconnects(-1). Not-connected is not-ready. The loader talks ONLY to its own node over localhost; it never uses the Service.
The SYS user's permissions (minted by slice 1, section 11): publish `$SYS.REQ.CLAIMS.UPDATE`, `$SYS.REQ.CLAIMS.LIST`; subscribe `_INBOX.>` and `imas.bus.accounts.changed`. Nothing else.

### 5.3 Start-up load and readiness
Ready is false at process start. Algorithm `loadAll(ctx)`:
1. Wait for the node connection and for S3 (`objectstore.WaitReady` semantics, but loop forever; section 5.7).
2. List `accounts/` (paged, 1000). Target set T = all `*.jwt` keys. If the SYS account key (from trust ConfigMap `sys-account.pub`) is not in T: stay not-ready, status "bucket not initialised", retry after backoff. (The fence and the server need the SYS account; with a missing SYS object the cluster cannot form trust.)
3. For each key in T not yet applied at that ETag, with concurrency IMAS_LOADER_PUSH_CONCURRENCY and rate IMAS_LOADER_PUSH_RATE: Get; validate (4.2); compare iat with `applied` (5.5); if newer, push (5.6).
4. Re-list. If any key is new or has a changed ETag versus what this pass processed, repeat from step 3 (tenants added during start-up are picked up here, bounded by pass count 20 per run, after which it proceeds and leaves the rest to the timer/event).
5. Own-node check: `ListIDs` (one `$SYS.REQ.CLAIMS.LIST` request, taking the reply whose server id equals `nc.ConnectedServerId()`) and verify every pub in T that the loader applied is present. A missing one is re-pushed once; still missing: not ready.
6. Ready := true when step 4 finds no unprocessed or changed keys AND step 5 passes. "Loaded count matches" therefore means: every key in the final listing T has been fetched and validated, applied-or-held-at-equal-or-newer iat, pushed where needed, and confirmed present in the own node's CLAIMS.LIST reply. Keys that failed validation are excluded from T but are listed in /status and counted; if the SYS key is invalid, not ready.
Once Ready, it stays Ready (section 5.7 for S3 outages). Ready is NOT cleared by new tenants; those are applied by event/timer.

### 5.4 Steady state
- Event handler: for each `accounts` entry whose iat is greater than `applied[pub].iat`, fetch `accounts/<pub>.jwt`; if fetched iat < event iat, retry with backoff for up to 30s (object store lag), then give up and leave it to the timer. Omitted `accounts`: run a full reconcile.
- Timer: GET index; if token differs from `lastToken` run `reconcile()` = list, diff by ETag against applied, fetch+validate+push the diffs, then set lastToken. Full resync ignores the token.
- Handlers and the timer run on one worker goroutine fed by a channel (coalescing), so passes never run concurrently.

### 5.5 iat comparison and deletes
For a fetched, valid JWT with iat I and jti J for account A:
- applied[A] absent: push.
- I > applied.iat: push.
- I == applied.iat and J == applied.jti: skip (same object; refresh ETag).
- I == applied.iat and J differs: use `claimRank` (locked-out wins, then raw string) to choose; push only if the fetched one outranks.
- I < applied.iat: never push; log `stale` and count `loader_stale_skipped_total`.
Objects are not deleted by farmer, so there is no delete handling; a disappearing object is ignored (section 4.1). Revocation of a tenant is a lock-out JWT with strictly greater iat (tenant.go:664-668), handled by the same path. Revocation of a single sprout is a User-JWT / revocation entry inside the Account JWT (re-signed Account, strictly greater iat) and travels as an ordinary Account update.

### 5.6 Pushing safely (fan-out hazard, 1.4)
`Push` publishes the raw JWT to `$SYS.REQ.CLAIMS.UPDATE` as a request and waits for the own-node reply (timeout 10s; retried up to 5 times, backoff 200ms to 5s). Because the handler saves unconditionally and fans out (1.2, 1.3), after each successful push the loader RE-READS `accounts/<pub>.jwt` (GetLimitedWithInfo). If the object's iat is now greater than what it pushed, it pushes the newer one and repeats (the repo's `pushUntilCurrent` pattern, pushall.go:150-173; cap 5 rounds). This relies on the farmer invariant "bucket write happens before any push", so a newer object is already visible when any stale push lands, and on same-publisher message ordering over routes. A residual window remains if two different loaders publish a stale and a newer JWT for the same account at nearly the same time; the next event/timer pass of the loader holding the newer JWT repairs it, because that loader's `applied` is newer than... (see 14: this repair requires the check below). To make repair real, each reconcile also checks, for a sample of N=50 applied accounts per pass, the node's stored JWT via `$SYS.REQ.ACCOUNT.<pub>.CLAIMS.LOOKUP` and re-pushes if the stored iat is lower than `applied`. Note LOOKUP replies are raw JWT with no server id (1.3), so the check is only meaningful for the own node via a direct subscription on that node; if that cannot be made reliable, adopt the fallback in section 13.
The loader never pushes an account it cannot decode and never pushes a JWT with iat lower than `applied`.

### 5.7 Retries, backoff, S3 outages
- Backoff: exponential from 500ms to 30s with full jitter, reusing `objectstore.RetryPolicy` jitter; per-request timeout 15s.
- S3 down at start: not ready, retry forever. No timeout-based give-up (kubelet's startupProbe failureThreshold set high, section 6). The pod then never becomes Ready and a rollout halts, which is intended (section 6.4).
- S3 down while running: stay Ready, keep serving the node, log at warn once per minute, expose `loader_last_success_timestamp_seconds` and `loader_s3_errors_total`. No staleness cut-off by default (owner decision D-2).
- Node connection lost: Ready false only if loadAll has not completed; after that, on reconnect the loader re-checks (ListIDs) and re-pushes anything missing before reporting any change.
- Rate limiting: because each push fans out to N-1 peers, every loader's start-up multiplies load by N; the concurrency and rate caps bound it. A fully restarted 3-node cluster with 10k tenants pushes up to 30k messages' worth of saves; the default 200/s makes that about 50s per node. Tune via IMAS_LOADER_PUSH_RATE.

### 5.8 Health and metrics
HTTP on IMAS_LOADER_HEALTH_PORT: `/healthz` 200 while the process runs; `/readyz` 200 iff Ready; `/status` JSON `{ready, applied, target, invalid[], lastIndexToken, lastSuccess}` (no JWTs). Prometheus text on `/metrics` if the repo already has a metrics helper (not verified, section 14); otherwise only /status.

---------------------------------------------------------------------
## 6. cmd/farmerbus and chart changes

### 6.1 cmd/farmerbus (Go)
- cmd/farmerbus/main.go: remove use of the resolver directory as persistent; `RunNATSServer` (113-131) unchanged except resolver dir is the emptyDir path. Remove the file-system reload assumptions. `startBus` (167-197): replace `newFence(cl.Size(), ...)` with `newFence(sizeSource, ...)` (6.2).
- internal/pki/busauth.go: `ConfigureBusNats` (202-224) takes the trust ConfigMap files (operator JWT, SYS pub, SYS JWT) instead of minting; delete `dropSelfMintedClaims` (232-253). (Overlap with slice 1: slice 1 owns the removal of seeds from the bus; slice 2 owns only the resolver directory and the shim. If slice 1 has not removed `loadBusAuth`'s minting, this slice's PR 3 depends on it.)
- internal/pki/busauth.go:126-149 `BusSysUser`: replace with a user loaded from `IMAS_BUS_SYS_USER_JWT_FILE`/`IMAS_BUS_SYS_USER_SEED_FILE` (Secret `imas-bus-fence-sys-user`, same shape as the loader's).

### 6.2 Fence cluster size follows the real replica count
- `fence.go`: `newFence(size func() int, ...)`; each tick calls `size()`.
- Source: file named by `IMAS_BUS_CLUSTER_SIZE_FILE`, the key `replicas` of a chart-rendered ConfigMap `<fullname>-bus-topology`, mounted as a DIRECTORY (no subPath) so kubelet updates it.
- Rule: size = max(value in file, len(IMAS_BUS_CLUSTER_ROUTES), number of distinct servers observed). Missing or unparsable file: keep the last good value; before any good value, use len(routes). Each failure direction rounds the size UP (fails closed).
- Helm scaling still rolls pods because IMAS_BUS_CLUSTER_ROUTES is in the pod template; `kubectl scale`/HPA is unsupported (documented) but safe.
- The topology ConfigMap is excluded from the pod checksum annotation.
- Chart test: ConfigMap `replicas` == StatefulSet replicas == number of routes.

### 6.3 StatefulSet (templates/bus-statefulset.yaml)
- Delete the `data` volumeClaimTemplate and persistentVolumeClaimRetentionPolicy (lines 299-321 region). Add emptyDir volume `data` mounted at /var/lib/imas/farmerbus (workingDir stays). bus-configmap.yaml farmerpki stays "/var/lib/imas/farmerbus/pki/".
- Add container `loader`: image = bus image, command `/farmerbus-loader`, env per 4.5, ports health 8081, `readinessProbe` GET /readyz (period 5s, failureThreshold 3), `startupProbe` GET /healthz (period 5s, failureThreshold 120), `livenessProbe` GET /healthz, `securityContext` readOnlyRootFilesystem true, runAsNonRoot, drop ALL, mounts: trust ConfigMap (ro), loader SYS user Secret (ro), S3 reader Secret (ro), TLS CA (ro).
- Existing farmerbus probes unchanged.
- PDB (bus-pdb.yaml): unchanged maxUnavailable 1. Interplay: a replacement node is not Ready until loaded, so the next eviction and the rolling update wait; if S3 is down during a rollout the first replaced pod never becomes Ready and the rollout halts while the other pods keep serving.

### 6.4 Other chart files
- _helpers.tpl: delete persistence validation at 196-198; add: fail if `accountStore.endpoint` empty, if `accountStore.bucket` empty, if `trust.configMap` empty; keep replica/route consistency checks.
- networkpolicy.yaml: add egress to `networkPolicy.accountStoreEgress.cidr` port; update test TestNetworkPolicyPorts expectation (currently DNS-only [53,53], networkpolicy.yaml:429-449).
- chart_test.go: remove case "cluster without persistence"; add cases in section 12.
- ci/*.yaml values, README.md (persistence section; "How an Account JWT reaches every node"; security note at line 490), NOTES.txt.
- uat/hub/dmz/values-uat.yaml (persistence.enabled ~60-65 removed; add accountStore), uat/hub/dmz/install.sh (create the Secrets).
- uat/hub/core/minio-setup.sh: create bucket `imas-accounts`, writer user (put/get/list on the bucket), reader user (get/list only).
- deploy/helm/farmer: values.yaml, templates/farmer-deployment.yaml, _helpers.tpl.
- .goreleaser.yaml: add build id `farmerbus-loader` (copy of 167-178) and include it in the farmerbus docker image entries (558-585); docker/goreleaser.farmerbus.dockerfile: add `COPY imas-farmerbus-loader /farmerbus-loader`.

---------------------------------------------------------------------
## 7. Farmer side

### 7.1 New component: internal/pki/accountpublisher.go
`type AccountPublisher interface { Publish(ctx, accountPub string, jwt string) error; ReconcileAll(ctx) error }` with implementation `s3AccountPublisher` (objectstore.Store for the accounts bucket with the WRITE credential, a NATS system connection, config).

### 7.2 Single choke point
Introduce `func persistAccountJWT(path, accountPub, jwt string) error` in internal/pki, which does the existing `writeFileAtomic` and then calls the publisher. Replace the write at each site in 1.10 (jwtauth.go:208, :271; jwtusers.go:318; tenant.go:187, :522, :746; saasapi_user.go:237) with it. The publisher is a package-level injectable (`SetAccountPublisher`) set in cmd/farmer/main.go; nil in tests that do not care (no-op).

### 7.3 Order on every change
1. Sign (iat made strictly greater via `waitPastIssuedAt` on EVERY re-sign, not only lock-outs; extend tenant.go:664-668's use to the other signers).
2. Persist locally (the PVC copy stays until slice 3 removes it).
3. PUT `accounts/<pub>.jwt` (refuse to regress: before writing, read the existing object; if its iat is greater, do not overwrite, log, return an error).
4. PUT `accounts/index` with a fresh token.
5. Push to all nodes and wait (7.4).
6. Publish the event (4.3).
The bucket write precedes the push so loaders can always find the latest object (supports 5.6).

### 7.4 Push to every node and wait
New `pushToAllNodes(ctx, jwt)` in internal/pki/resolver.go replacing the single-node `pushAccountUpdate` use (resolver.go:521-528): (a) discover nodes with a `$SYS.REQ.SERVER.PING` gather; (b) PublishRequest to `$SYS.REQ.CLAIMS.UPDATE` and collect replies attributable by ServerInfo.ID; (c) retry for missing nodes with bounded backoff (3 rounds, 200ms to 2s). Expected node count: `IMAS_BUS_EXPECTED_NODES` if set, else the number discovered. `PushAllAccounts` (pushall.go:48-127) keeps its role as a speed-up and uses this function; it waits for all expected nodes. Nodes still missing after the retries are NON-fatal: the loader repairs them because the bucket is already written.

### 7.5 Failure policy
- Bucket write fails (step 3 or 4): for lock-outs/revocations still push live (security first), then return an error to the caller so the API call reports failure and the operation is retried; for ordinary updates return the error without pushing. In both cases the periodic `ReconcileAll` repairs.
- Push fails or partial: log, return nil (the bucket has it), set metric `farmer_account_push_missing_nodes`.
- Event publish fails: log only.
- `ReconcileAll` runs at farmer start-up (after ReloadNKeys, cmd/farmer/main.go:120-230) and inside every PushAllAccounts: it lists the bucket and PUTs any farmer-state account whose object is missing or whose iat differs (farmer state wins, since it is the signer). This also repairs a bucket rollback or lost write.

### 7.6 Files
internal/pki/{accountpublisher.go,resolver.go,pushall.go,tenant.go,jwtauth.go,jwtusers.go,saasapi_user.go}, internal/config/config.go, cmd/farmer/main.go (wire publisher; initSystemAccountListeners ~477-535 push calls stay), deploy/helm/farmer/*.

---------------------------------------------------------------------
## 8. Shared code extraction
`internal/accountrank/rank.go`: `Rank(jwt string, trusted []string, wantSub string) (iat int64, jti string, lockedOut bool, err error)` and `Better(a, b Claim) bool` moved from fence.go:467-499; fence.go imports them (behaviour unchanged, its existing tests must stay green).

---------------------------------------------------------------------
## 9. Config and name summary
Env: section 4.5. Secrets: `imas-bus-accounts-reader`, `imas-bus-loader-sys-user`, `imas-bus-fence-sys-user`, `imas-farmer-accounts-writer`. ConfigMaps: `imas-bus-trust` (section 11), `<fullname>-bus-topology`. Subject: `imas.bus.accounts.changed`. Keys: `accounts/<pub>.jwt`, `accounts/index`.

---------------------------------------------------------------------
## 10. Security notes (FLAG FOR SECURITY REVIEW)
- The reader credential must be get/list on the accounts bucket only; farmer's recipe/job credential must not reach it. Add a start-up self-check in the loader using `objectstore.ExpectDenied` (probe.go:233) with put and delete probes on a fresh key; fail closed (refuse to start) if the store allows them, retrying inconclusive answers.
- The loader's SYS user is a SYS-account credential: scope strictly as 5.2.
- All JWTs are validated before push, so a tampered bucket cannot install an Account not signed by a trusted operator key; it can still replay an OLDER valid JWT (rollback). Mitigation: a loader never goes backward versus what it has applied; a node restarted from scratch with an old-only bucket cannot detect rollback. Farmer's `ReconcileAll` repairs the bucket; fence `claimRank` prefers newest across nodes.
- Bus network policy gains S3 egress; README.md:490 must be reworded.

---------------------------------------------------------------------
## 11. Contract with slice 1 (assumed, not read)
I did not read slice 1's spec (its agent was still running). Assumed deliverables, keys to pin:
ConfigMap `imas-bus-trust` with keys:
- `operator.jwt` (operator claims JWT)
- `operator-signing-keys` (optional, newline-separated trusted signing public keys; if absent, only the operator key in operator.jwt is trusted)
- `sys-account.pub` (SYS account public key)
- `sys-account.jwt` (SYS account JWT, needed by the server at start so it can accept the loader; the bucket copy supersedes it)
Secrets `imas-bus-loader-sys-user` and `imas-bus-fence-sys-user`, each keys `user.jwt` and `user.nk`, minted by slice 1's bootstrap. If slice 1 does not mint them, slice 2 must add a farmer subcommand `farmer publish-bus-sys-users` (pattern: internal/saasapicred/run.go:1-45).

---------------------------------------------------------------------
## 12. Tests (D7: our code, with fakes)

Use internal/objectstore/objectstoretest for S3 and in-memory fakes for NodeClient. Use the existing embedded-nats pattern (cmd/farmerbus/cluster_integration_test.go: trust, newTrust, tr.push, newTestCluster with per-pair TCP proxies, startBus, waitFor, c.stop/start, dialSprout, accountJWT lock-out helper, per-node pkiDirs) only for scenarios that need real nats-server behaviour.

### Unit: internal/accountloader (accountloader_test.go)
- `TestLoadAllReadyOnlyAfterEveryKeyPushed`: fake NodeClient, seed 5 accounts + SYS; hold the 4th Get on a channel; assert Ready()==false until released, then true; assert pushes==6.
- `TestLoadAllWaitsForSysAccountObject`: no SYS object -> Ready false, Status "bucket not initialised"; add it -> ready.
- `TestTenantAddedDuringStartupIsLoaded`: BeforePut/hook adds an object after first list; assert second pass pushes it and Ready only after.
- `TestOlderJWTNotPushed`: applied iat 200; bucket holds iat 100 -> zero pushes, `stale` counter 1.
- `TestEqualIatDifferentJtiLockoutWins`.
- `TestInvalidJWTSkipped`: wrong subject, bad signature, untrusted issuer -> not pushed, counted, held copy kept.
- `TestObjectDisappearingKeepsHeldCopy`.
- `TestS3DownAtStartNotReady` using FailNext(n,503,"SlowDown") then recovery; backoff injected clock; Ready only after recovery.
- `TestS3DownWhileRunningStaysReady`.
- `TestEventFetchRetriesUntilIatCurrent`.
- `TestPushRereadsAndRepushesNewer`: bucket changes during push -> second push with the newer JWT.
- `TestEventIsPlainSubscription` (checks natsNodeClient uses Subscribe, via embedded server with two loaders both receiving).
- `TestReadOnlyCredential` (loader self-check): objectstoretest.Deny denies put/delete -> starts; allows put -> refuses.

### Unit: farmer side (internal/pki/accountpublisher_test.go)
- `TestPublishOrderBucketThenIndexThenPushThenEvent` (recording fakes with a shared sequence).
- `TestPublishRefusesToRegress`.
- `TestBucketFailureStillPushesLockout` / `TestBucketFailureNoPushForOrdinaryUpdate`.
- `TestPushToAllNodesWaitsForEveryNode` (embedded 3-node or fake gather) and `TestPushToAllNodesMissingNodeNonFatal`.
- `TestReconcileAllRepairsMissingAndRolledBackObjects`.
- `TestFarmerWriteCredentialCannotBeUsedByLoader`/Deny test showing writer put allowed, reader put denied.
- `TestEveryResignAdvancesIat` for each site in 1.10.

### Unit: fence size
- `TestFenceSizeFollowsFile`, `TestFenceSizeNeverBelowRoutes`, `TestFenceSizeBadFileKeepsLast`.

### Integration (cmd/farmerbus/loader_integration_test.go)
The five required scenarios:
1. `TestEmptyNodeReadyOnlyAfterLoadingEverything`: start a node with an empty emptyDir and a bucket holding 25 accounts; run the real loader against it with /readyz sampled each 10ms; assert /readyz is never 200 before the node's `$SYS.REQ.CLAIMS.LIST` reply contains all 26 ids, and is 200 afterwards; a sprout of each tenant can connect.
2. `TestMissedEventRepairedByTimer`: 3 nodes + loaders (reconcile 200ms); write a new tenant object and bump the index but publish NO event; assert every node accepts the tenant's sprout within 5 reconcile intervals.
3. `TestOlderJWTNotApplied`: put iat 200 then overwrite the bucket object with an older iat 100 and bump the index; assert the node keeps iat 200 (query LOOKUP) and the stale counter increments.
4. `TestRevokedSproutRefusedOnEveryNode`: 3 nodes; a sprout connected to each; farmer-side publisher writes a revoking Account JWT (greater iat) and publishes the event while the proxy for node 3 drops it; assert nodes 1 and 2 refuse/disconnect the sprout promptly and node 3 does after the timer, and a new connection attempt is refused on all three.
5. `TestAllNodesRestartWithFarmerDown`: start 3 nodes, populate, stop all nodes (fresh emptyDirs), no farmer process; start nodes again; assert each becomes Ready from the bucket alone, sprouts reconnect, and the fence forms the mesh.

### Chart tests (deploy/helm/nats/chart_test.go)
- `TestNoPersistentVolumeClaim`: no volumeClaimTemplates, `data` is emptyDir.
- `TestLoaderSidecarRendered`: container, probes, mounts, readOnlyRootFilesystem, env names.
- `TestTopologyConfigMapReplicasMatch`.
- `TestAccountStoreEgress`: egress rule to the cidr/port present; DNS still present.
- `TestValidationAccountStoreRequired`; remove "cluster without persistence".
- Farmer chart: `TestAccountStoreEnvRendered`.
Also required green: scripts/status/rollup.py --check with a fragment under docs/status/days/<date>/ (CLAUDE.md workflow).

---------------------------------------------------------------------
## 13. Fallback if the residual stale-overwrite window (5.6) is judged unacceptable
Run the loader logic in-process in a separate small process that uses the nats-server resolver's local save (SaveAcc/LoadAcc), which does not fan out, as the fence already does (fence.go:523-530). Rejected as the default because main.go:1-9 forbids object storage in farmerbus and the owner chose a sidecar. Keep as plan B; it removes the hazard entirely.

---------------------------------------------------------------------
## 14. What I could not read or verify
- Slice 1 spec (contract in section 11 is an assumption).
- pki test helper names startTestBus / setupPKITest / dialAsSprout: seen in the summary of earlier reading but not re-verified in this pass.
- natsapi tenant provisioning call sites, farmer /files handlers.
- Whether the repo has a Prometheus helper (affects 5.8).
- Versity Gateway listing and ETag behaviour; RustFS ListObjectsV2 start-after is covered by the fake only.
- The exact lines of the farmer chart env block (given as ~99-120).
- Nothing was compiled or run (toolchain mismatch).

---------------------------------------------------------------------
## 15. Implementation order (one PR each)

PR 1: `internal/accountrank` extraction + fence unit tests unchanged. Green: go test ./cmd/farmerbus ./internal/accountrank.
PR 2: farmer publisher (7.1-7.5), config fields, all-node push, ReconcileAll, farmer chart values. Green: go test ./internal/pki ./internal/config ./cmd/farmer; farmer chart tests. Behaviour: bucket is now written; nothing reads it yet (PVC still in place).
PR 3: `internal/accountloader` + `cmd/farmerbus-loader` + unit tests + goreleaser/Dockerfile. Green: go test ./internal/accountloader ./cmd/farmerbus-loader; goreleaser check.
PR 4: fence size source + SYS user files in farmerbus (6.1, 6.2). Green: fence tests, cluster integration tests.
PR 5: integration tests for the five scenarios (needs PRs 3 and 4). Green: go test ./cmd/farmerbus -run Loader.
PR 6: chart: remove PVC, add loader sidecar, topology ConfigMap, NetworkPolicy, validation, README, UAT values and scripts, minio-setup. Green: go test ./deploy/helm/...; helm lint with ci/*.yaml.
PR 7: delete dropSelfMintedClaims and any leftover persistence references (grep "persistence", "volumeClaimTemplates", "resolverStoreDir"); status fragments. Green: go test ./... and scripts/status/rollup.py --check.

---------------------------------------------------------------------
## OWNER DECISIONS NEEDED

D-1. Which S3 endpoint the DMZ bus reaches. This ends the rule "the bus never opens a connection into the core network" (README.md:490).
- (a) The same store as core, DMZ egress allowed to that one endpoint, reader credential scoped to the accounts bucket.
- (b) A dedicated gateway/replica in the DMZ fed from core.
Recommendation: (a) for UAT and production, with the single-endpoint firewall rule.

D-2. If S3 is unreachable for a long time while running, should a node keep serving with the JWTs it holds, or fail closed after a cut-off?
- (a) Keep serving (no cut-off).
- (b) Mark not-ready after a configurable age (for example 1 hour).
Recommendation: (a). A cut-off would turn an object-store outage into a full bus outage, and a revocation can already not be delivered during an outage either way.

## Owner decisions (2026-10-11) - these settle "OWNER DECISIONS NEEDED" above; do not ask again
- D-1 (a): the DMZ bus reads the same object store as core. Add DMZ egress to that single endpoint and a read-only credential scoped to the accounts bucket. Update the README rule that the bus never opens a connection into core to say this one exception.
- D-2 (a): a running node keeps serving with the JWTs it holds when S3 is down; it never goes not-ready for that reason. Startup still waits, not-ready, until the first load succeeds.
