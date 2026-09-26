# farmer: SaaS API credential hand-off (reference deploy config)

This covers the last open item in
`docs/design/imas-internal-api-account.md`: getting the SaaS API's NATS
User JWT from where farmer mints it into OpenBao, so External Secrets
Operator (ESO) can deliver it to the saasapi Deployment.

**FLAG FOR SECURITY REVIEW.** This adds a new OpenBao *write* policy and a
new delivery path for a privileged NATS credential. The policy boundary
below needs human review more than the Go code does.

Same precedent as `deploy/envoy/`: these are reviewed reference files.
**farmer's real Deployment and Helm chart are not in this repo.** They
live in the separate ops repo, which this change had no access to. None
of the YAML here is applied by anything in imas.

| File | What it is |
|---|---|
| `farmer-deployment-nats-seeds.patch.yaml` | Volume, mount, and env vars to add to farmer's Deployment in the ops repo (part 1) |
| `saasapi-credential-publish-job.yaml` | The Job, its ServiceAccount, and its NetworkPolicy (part 2) |
| `externalsecrets.yaml` | ESO wiring for the seeds and for the published JWT |
| `values.job-reconcile.yaml` | Values block for the job reconcile window (see the last section) |
| `deployment.env.job-reconcile.yaml` | Template fragment to paste under the farmer container's `env:` list |

## Part 1: the SYS Account seed on farmer (ops change only)

No code change is needed. `ensureNatsAuth` loads the SYS Account key with
`loadOrCreateSeed(path, "SYS_ACCOUNT", nkeys.CreateAccount)`, the same way
it loads every other key. That function already prefers an externally
supplied seed and never writes one back to disk. Add the following to
farmer's Deployment in the ops repo (the exact patch is in
`farmer-deployment-nats-seeds.patch.yaml`):

| What | Value |
|---|---|
| Volume | `nats-seeds`: `secret.secretName: imas-farmer-nats-seeds`, `items`: `sys-account.nk` and `saasapi-user.nk`, `defaultMode: 0440` |
| Mount | `/var/run/secrets/imas/nats`, `readOnly: true` |
| Env var | `IMAS_NATS_SYS_ACCOUNT_SEED_FILE=/var/run/secrets/imas/nats/sys-account.nk` |
| Env var (already planned in the design doc) | `IMAS_NATS_SAASAPI_USER_SEED_FILE=/var/run/secrets/imas/nats/saasapi-user.nk` |
| Secret source | ESO `ExternalSecret` `imas-farmer-nats-seeds`, which reads the ops-owned seed path in OpenBao |

Two things to get right when you roll this out:

- **Import the existing seed. Don't generate a new one.** On an install
  that is already running, put farmer's current
  `{FarmerPKI}/nats-auth/sys-account.nk` into OpenBao. A new SYS seed
  means a new SYS Account public key. `operator.jwt` names the system
  account, so it gets re-minted, and every bus node still configured with
  the old one stops trusting it.
- **farmerbus needs the same SYS seed.** `ConfigureNats` runs
  `ensureNatsAuth` in both binaries and seeds the SYS Account into the
  resolver. If farmer's copy comes from OpenBao, farmerbus's copy must
  come from there too: same Secret, same env var. Otherwise the two
  processes end up with different SYS Accounts.

## Part 2: `farmer publish-saasapi-credential`, run as a Job

The Job runs farmer's own image with the subcommand
(`internal/saasapicred`). The subcommand does three things:

1. It calls `pki.EnsureSaaSAPICredential()`, the same code farmer runs at
   boot.
2. It reads the published secret and compares **claims**: key, issuer,
   permissions, and connection types. If the published JWT is already
   current, it writes nothing.
3. Otherwise it writes `{"jwt": <User JWT>, "public_key": <U...>}` to
   `<IMAS_SAASAPI_CRED_OPENBAO_KV_MOUNT>/data/<IMAS_SAASAPI_CRED_OPENBAO_KV_PATH>`
   (or the path given by `-kv-path`). The KV path has no default. **The
   seed is never published**: saasapi gets its seed from the ops-owned
   seed path, as before.

Exit code 0 means the credential was written or was already current. 1
means minting or publishing failed. 2 means a usage or configuration
error.

### Why an emptyDir, not farmer's PKI volume

The Job mounts the same seed Secret as farmer, with only the two keys it
needs projected, plus an **emptyDir** at `/etc/imas`. The subcommand
refuses to run unless both the SYS Account key and the SaaS API key are
supplied externally or already on disk. It will not mint under a key it
generated itself, because saasapi would then crash-loop on its next
restart. With a fresh emptyDir, the following holds:

- **No resolver push, and no bus access.** No earlier JWT exists in the
  pod, so the Job never sees a rotation, never touches the SYS Account
  JWT, and never pushes. The NetworkPolicy allows egress to OpenBao and
  DNS only.
- **Revocation stays farmer's job.** Farmer's own boot-time
  `EnsureSaaSAPICredential` holds the persistent state. It revokes the
  old key on rotation and pushes that revocation. The Job only publishes.
- **No second writer on farmer's PKI files.** `authMu` locks within one
  process only, so a Job sharing farmer's volume could race farmer on
  `sys-account.jwt`. Farmer's volume is also typically ReadWriteOnce.
- **Other keys are harmless.** The Operator and tenant keys that
  `ensureNatsAuth` generates inside the emptyDir never leave the pod and
  never sign anything that leaves it.

Running the subcommand against farmer's real PKI directory also works: it
behaves exactly like farmer's boot call, including the push. The
reference Job doesn't do this, for the reasons above.

### OpenBao policy (for whoever writes it in the ops repo)

Put the published JWT at its own path, separate from the seeds. Neither
path may be a prefix of the other. The examples below use
`secret/platform/imas/saasapi-nats-user`.

**The Job's policy, `imas-saasapi-cred-publisher`, allows this and
nothing else:**

```hcl
path "secret/data/platform/imas/saasapi-nats-user" {
  capabilities = ["create", "update", "read"]
}
```

- `create` and `update` cover the KV v2 write (`POST .../data/<path>`).
- `read` covers the idempotency check. The JWT isn't secret. Without
  `read`, every run would add a new KV version, and ESO plus Reloader
  would restart saasapi after every farmer deployment.
- Do **not** grant `patch`, `delete`, or `list`. Do not grant anything on
  `secret/metadata/…`, which could change `max_versions` or
  `delete_version_after`, or delete the secret's history. Do not grant
  anything on `secret/delete/…`, `secret/undelete/…`, or
  `secret/destroy/…`. Do not use wildcards or `+` segments, and grant
  nothing on the seed path.
- **Kubernetes auth role** (`auth/kubernetes/role/imas-saasapi-cred-publisher`):
  - `bound_service_account_names=imas-saasapi-cred-publisher`
  - `bound_service_account_namespaces=<farmer's namespace>`
  - `audience=openbao`, matching the Job's projected token
  - `token_policies=imas-saasapi-cred-publisher`
  - A short `token_ttl`, for example `5m`, and a matching `token_max_ttl`
  - `token_num_uses` can stay 0: a run makes two KV calls.

**farmer's long-running server process must continue to exclude this
access:**

- farmer's ServiceAccount must not appear in the publisher role's
  `bound_service_account_names`. The publisher policy must not be
  attached to any role farmer can log in with: its
  `IMAS_CERTS_OPENBAO_*` PKI role or its `IMAS_GATEWAY_OPENBAO_*` Transit
  role.
- farmer's policies grant no capability at all on
  `secret/data/platform/imas/saasapi-nats-user` or
  `secret/metadata/platform/imas/saasapi-nats-user`. farmer mints its own
  copy, so it doesn't need to read the published one either. The same
  goes for any wildcard or `+` path that would match either of them.
- To check, with a token issued to farmer's role:
  `bao token capabilities <token> secret/data/platform/imas/saasapi-nats-user`
  must print `deny`.
- farmer's Deployment gets none of the `IMAS_SAASAPI_CRED_OPENBAO_*` env
  vars. The distinct prefix exists so they can't be shared by accident.

**Kubernetes-side boundary.** The ServiceAccount token *is* the write
credential. farmer's ServiceAccount, and anything else that isn't the
deploy pipeline, must not be able to do any of the following in this
namespace:

- create Pods or Jobs, or `pods/exec` into the Job's pod
- create a token via `serviceaccounts/token` for
  `imas-saasapi-cred-publisher`
- read the publisher ServiceAccount's Secrets

The reference ServiceAccount has no RBAC bindings of its own, and turns
off automounting in favor of a 10-minute projected token with an
audience.

**ESO's saasapi-namespace role** needs only `read` on the published path
and on the seed path, which matches the existing ESO pattern.

**What the Job holds that isn't new privilege.** The Job mounts the SYS
Account seed, so it can mint any SYS User. That's the same NATS-signing
power farmer already has, and it's needed to sign the JWT. What *is* new
is the KV write, which is why that identity is kept apart from farmer's.
The Job also mounts the SaaS API seed only because
`EnsureSaaSAPICredential` loads it to derive the public key. Minting
needs only the public key, so that mount is a candidate to drop later
(see the PR's follow-ups).

### When to run it: automatically after every farmer deployment

**Recommendation:** run the Job automatically as a post-deploy hook (Helm
`post-install,post-upgrade` or Argo CD `PostSync`, as annotated in the
manifest). Also run it explicitly as a step in the rotation runbook.
Don't make it manual-only.

Reasoning:

- **Two things change the JWT.**
  - (a) A change to `saasAPIUserPermissions`. This is already planned for
    `internal.sprout.*`, and it only ever ships with a farmer deployment.
  - (b) A rotation of the SaaS API seed.

  A manual-only-on-rotation policy misses (a). saasapi would keep a JWT
  without the new subjects until someone remembered, and a deploy that
  looks green would fail at runtime on the new subjects. The hook also
  covers first install without anyone having to remember a step.
- **Re-running is safe.** The comparison is by claims, and the Job starts
  with fresh state each time. A re-run with nothing changed is one KV
  read: no new KV version, no Secret change, no saasapi restart.
  `internal/saasapicred`'s tests and the live-bus test in
  `internal/pki/saasapi_publish_integration_test.go` both check this.
- **Short exposure.** The write identity is live for a few seconds per
  deploy. It isn't held by a long-running process, which was the
  alternative the design doc's open question raised: farmer writing to
  KV itself.

**A deploy hook does not cover rotation.** A seed rotation arrives as an
ESO sync plus a Reloader rollout, not as a Helm or Argo deployment, so the
hook doesn't fire. The rotation runbook is:

1. Write the new SaaS API seed to the ops-owned seed path.
2. Force-sync `imas-farmer-nats-seeds`, for example with
   `kubectl annotate externalsecret imas-farmer-nats-seeds force-sync=$(date +%s) --overwrite`.
3. Wait for farmer to restart. At boot it revokes the old key and pushes
   the revocation.
4. Trigger the Job: a no-op `helm upgrade` re-runs the hook, or apply the
   Job manifest directly.
5. Force-sync `imas-saasapi-nats`.

Between step 3 and step 5, saasapi can't reach the bus. It has either a
revoked key or a new seed with the old JWT, so it fails closed by design.
Keep that window short. This matches the rotation behavior the design doc
already describes. The Job doesn't create the window; it closes it.

A failed Job, for example because OpenBao is unreachable, fails the
Helm/Argo sync. That's intentional: saasapi might be on a stale JWT. With
`helm upgrade --atomic` it would also roll farmer back, so don't combine
the hook with `--atomic` unless that's what you want.

## Job reconcile window (`IMAS_JOB_RECONCILE_WINDOW`)

A sprout that misses a recipe push while disconnected cooks the staged
copy when it next starts, reconnects or is nudged (`imas resync`), as long
as the job is no older than the sprout's own `stagedrecipemaxage` setting
(sprout config file, default `1h`). The reconcile window is farmer's side
of that: how late a job may start and still be recorded.

| Env var | Helm value | Default | Valid values |
|---|---|---|---|
| `IMAS_JOB_RECONCILE_WINDOW` | `jobs.reconcileWindow` | `"2h"` in the chart; unset (every job recorded) if the value is null or `""`, or without the chart | Go duration string, e.g. `"2h"`, `"90m"`; `"0"` disables |

- The `jobreconcilewindow` key in farmer's config file wins over the env
  var, like the other `IMAS_*` settings.
- It is measured from dispatch (`dispatched_at`, stamped by farmer) to
  the job's `start` event reaching farmer. A job whose start arrives later
  is not reconciled: farmer writes none of its events to the job store or
  the `job_status` index, and marks the job `expired` in both (an
  `expired.json` marker in the job store, the `expired` flag and status
  in `job_status`). `imas jobs` shows it as `expired`; the SaaS API
  reports its action item as failed with error code `job_expired`, so a
  fleet-update rollout treats it as not succeeded and halts. Marking a
  job expired is logged once at warn level; its later dropped events at
  debug. Once expired, a job stays expired even if the window is raised.
  The job reaper removes it like any other job.
- A job that started within the window is recorded to the end, however
  long it runs.
- Jobs dispatched before this change have no `dispatched_at` and are
  always recorded.
- **Keep it at least the largest `stagedrecipemaxage` in the fleet.** The
  chart's `2h` covers the sprout default of `1h`. With a smaller window,
  sprouts will still run late jobs, but farmer marks them expired instead
  of recording their results.
- An invalid value (`soon`, `-1h`, `7200` without a unit) stops farmer at
  startup with an error naming the variable. The template fragment
  rejects a bare YAML number at render time.
