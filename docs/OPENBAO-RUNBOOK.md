# OpenBao operations runbook

**FLAG FOR SECURITY REVIEW.** This is the operations runbook that design
decision D4 (`docs/design/imas-openbao-signing-design.md`) makes a launch
gate: backup and recovery of OpenBao (Raft snapshots, the seal key and its
retired versions, recovery-key custody). It is ready for review, not
reviewed. Until the sections marked **Owner fills in** are filled in and the
restore drill in section 8 has been run once and recorded, production launch
stays blocked.

It follows the OpenBao documentation (design D7: we do not test OpenBao
beyond its documents). Every command below is a documented OpenBao command;
before the first use in a given environment, read the page for the pinned
version (OpenBao 2.7.1, D8) at <https://openbao.org/docs/> and use that page
where it differs from this one. The imas parts (which keys live where, what
breaks when OpenBao is down, the bootstrap Job) are specific to this
repository.

## 1. What OpenBao holds for imas, and what losing it costs

| What | Where in OpenBao | If lost with no usable backup |
|---|---|---|
| NATS operator identity key (`nats-operator`), operator signing key (`nats-operator-signing`), SYS account key (`nats-sys-account`) | Transit, ed25519, not exportable | Every Account, User and SYS JWT the platform issued stops being verifiable against a key we can sign with; a new operator is a new platform: every tenant and every sprout re-enrolled |
| Per-tenant signing and account keys (`nats-tsign-<tenant>`, `nats-tacct-<tenant>`) | Transit | The tenant cannot mint or revoke; offboard and re-provision |
| Gateway JWT key (`imas-gateway-jwt`) | Transit | Gateway JWTs cannot be issued or verified; sprouts re-enrol |
| Per-tenant payload-encryption keypairs | KV v2 `secret/imas/tenant-x25519/tenants/<tenant>` | Sealed payloads to and from that tenant's sprouts cannot be opened; re-enrol |
| API certificate and bus certificates | PKI mount | Reissue (the CA is regenerated, every client pins the new root) |
| Roles, policies | Auth and ACL | Rewritten by the bootstrap Job |

Transit keys are **not exportable** by design. The only copy is inside
OpenBao's storage, wrapped by the seal key. Recovery therefore needs **all
three** of: a Raft snapshot, the seal key that wrapped it (with its version
history), and a quorum of recovery keys (design section 10). Losing any one of
the three makes the keys unrecoverable. This runbook exists to make sure that
cannot happen quietly.

## 2. Owners and custody

**Owner fills in** (the table is the launch-gate evidence; names are people,
not roles):

| Duty | Holder | Deputy | Last verified |
|---|---|---|---|
| Recovery key share 1 | | | |
| Recovery key share 2 | | | |
| Recovery key share 3 | | | |
| Snapshot schedule and storage | | | |
| Seal key (Azure Key Vault) administration | | | |
| Restore drill | | | |

### Recovery keys (D2)

- `bao operator init -recovery-shares=3 -recovery-threshold=2`, with
  `-recovery-pgp-keys` (one operator's public key per share) and
  `-root-token-pgp-key`, so the output is encrypted to the holders at the
  moment it is created. Production is auto-unseal, so `init` returns
  recovery keys, not unseal keys.
- Output is never stored in the cluster and never in a ticket, chat or CI
  log. Each holder decrypts and stores their own share offline (a hardware
  token or a password manager's vault they alone control).
- Any two holders can regenerate a root token, change the seal or rekey. One
  holder leaving or losing a share is tolerated; two losing theirs is not.
- Every holder confirms every six months that they can decrypt their share
  (decrypt the test message the custodian sends, record the date above).
  Do not use the real share for this test.

## 3. Seal: Azure Key Vault (D17)

Production unseals with an Azure Key Vault key (`seal "azurekeyvault"`; at
2.7.1 it is an external plugin carried in our OpenBao image, D14). Settings
the vault must have, because the seal key is the one thing a deleted vault
takes with it:

- **Soft delete and purge protection on.** A deleted key or vault is
  recoverable only while purge protection holds it.
- One key reserved for OpenBao. Its identity needs `get`, `wrapKey` and
  `unwrapKey` on that key and nothing else (with Azure RBAC, a role that
  allows them, such as Key Vault Crypto Service Encryption User, scoped to the
  key). OpenBao's seal page lists the settings; check it for the pinned
  version.
- Access from OpenBao's pods by workload identity, scoped to that key only;
  no client secret in the chart values.
- The vault is in the same region as the cluster, with a documented
  recovery path to a second region if your policy requires one (D8: a second
  seal is out of scope for the platform; availability comes from the
  vault's own redundancy).
- Alerting on key-vault unavailability and on the key's expiry date, if one
  is set.

**Seal outage plus an OpenBao pod restart means OpenBao is down** (design
section 10). The effect on imas while it is down:

- Already enrolled sprouts keep connecting: the bus holds the Account JWTs
  and sprouts present their own JWTs.
- Enrolment, tenant provisioning and offboarding, JWT refresh for sprouts
  whose JWT expires, and key rotation stop until OpenBao is unsealed.
- Farmer and saasapi keep serving what does not need a signature.

### Seal key rotation and retired versions

A snapshot restore needs the seal key version that wrapped it. Therefore:

- Rotate the Azure Key Vault key only by creating a **new version** (or, if
  the key name changes, adding the new seal stanza and migrating, section
  7). Never delete an old version while any retained snapshot depends on it.
- Record, for every snapshot kept, the key version in force on the day it
  was taken (the snapshot's object name carries the date; keep a one-line
  table of date ranges and key versions next to the schedule).
- A version may be disabled or destroyed only after the newest snapshot
  that depends on it has aged out of retention, and a restore drill (section
  8) has been run from a snapshot wrapped by its successor.

## 4. Snapshots

**Owner fills in:** the destination bucket or share, the schedule, who gets
the alert.

- **What**: Raft snapshots of the OpenBao cluster, taken against the active
  node: `bao operator raft snapshot save <file>`. A snapshot contains
  everything section 1 lists.
- **How often**: at least every 6 hours, and before every OpenBao upgrade,
  seal change, rekey or policy and role change run through the bootstrap Job.
  Use a scheduled Job (a Kubernetes CronJob with its own ServiceAccount and a
  token limited by an ACL policy to `sys/storage/raft/snapshot` read), or
  OpenBao's own snapshot feature if the pinned version documents it. The
  snapshot token is not the root token and is not the farmer's token.
- **Where**: a bucket other than the one imas uses, in another failure
  domain from the cluster (another account or region), with versioning on and
  object lock if available. Snapshots are encrypted by the seal key inside
  the file, but treat them as secret: anyone holding a snapshot and the seal
  key access can read the keys.
- **How long**: 30 days of 6-hourly snapshots plus 12 monthly. Align
  retention with the seal key version rule in section 3.
- **Alert** when no snapshot has succeeded in 12 hours, and when the newest
  snapshot is smaller than half the previous one.
- **Check** each month that the newest snapshot downloads and that
  `bao operator raft snapshot inspect` (if the pinned version has it) or a
  restore to a scratch cluster (section 8) reads it.

## 5. Everyday procedures

### 5.1 A pod is sealed or will not start

1. `bao status` on each pod. `Sealed: true` with an auto-unseal seal means
   the seal key is unreachable; check Azure Key Vault access and the pod's
   workload identity before anything else.
2. Fix the cause. The pod unseals itself on start; do not unseal by hand.
3. `bao operator raft list-peers` shows all three peers and one leader. A
   peer that left must `retry_join` again; do not `raft remove-peer` the
   last two.

### 5.2 Change a policy or role

A change to a file in `deploy/helm/farmer/files/openbao-policies` or to a role
needs a fresh root token, because the bootstrap Job revokes its own token
when done (no standing admin, owner decision (a)).

1. Take a snapshot (section 4) and note its name in the change record.
2. Two recovery-key holders generate a root token: `bao operator
   generate-root -init`, each holder supplies their share with `bao operator
   generate-root`, then decode the result with the one-time password
   (`-decode`, `-otp`). Do it on an operator's machine, not in a pod.
3. Put the token in the Secret named by `openbaoBootstrap.tokenSecretName`
   (the Job's own README section "OpenBao bootstrap token") and run the
   `helm upgrade`. The Job configures OpenBao and revokes the token.
4. **Delete the Secret** and confirm the token is revoked
   (`bao token lookup` with it fails).
5. If a holder's machine kept the token, revoke it: `bao token revoke -self`.

### 5.3 Purge retired tenant keys

Offboarding soft-deletes a tenant's two Transit keys; they stay restorable
for `retiredTenantKeyRetentionDays` (30). Purging is the admin step in
`deploy/helm/farmer/README.md`, "Purging retired tenant keys", and it needs
the same root-token procedure (5.2). Purge only after the retention window and
only keys the offboarding record names; a purge cannot be undone and a
snapshot is the only way back.

### 5.4 A recovery-key holder leaves

Rekey the recovery keys so the leaver's share is useless:
`bao operator rekey -target=recovery -init -key-shares=3 -key-threshold=2`
with new `-pgp-keys`, supply the existing threshold of shares, and have the
new holders confirm decryption. Update the table in section 2. Do this before
the leaver's access is removed.

### 5.5 Upgrade OpenBao

Snapshot first. Upgrade standbys one at a time and the active node last,
following OpenBao's upgrade documentation for the version step. Do not skip
versions that the documentation says must be taken in order. After the
upgrade run the checks in section 9.

## 6. Disaster recovery

Pick the case; each starts by freezing changes (no `helm upgrade` of the
core release, no tenant provisioning) and telling the on-call owner.

### 6.1 One OpenBao node lost

Raft tolerates one lost node of three. Replace it (a new pod joins by
`retry_join` and catches up). Check `bao operator raft list-peers`. No restore.

### 6.2 The whole cluster lost, storage gone

1. Recreate the OpenBao pods with the same seal stanza, **pointing to the
   same Azure Key Vault key** (the key version in force when the snapshot
   was taken must still exist; section 3).
2. Initialize the new cluster (`bao operator init`, with the recovery
   options of section 2) so it can accept a restore, then restore:
   `bao operator raft snapshot restore -force <file>`, using the new
   cluster's initial root token for that command. Follow the snapshot
   restore page for the pinned version: after the restore the cluster holds
   the **original** cluster's data and recovery configuration, so from here
   on a root token is generated from the **original** recovery-key quorum,
   not the new `init` output. Revoke the new init token once the restore
   is verified, and destroy the new `init` output.
3. Run the checks in section 9.
4. Everything issued since the snapshot is gone: tenants provisioned after
   it have no keys, enrolments after it have no gateway or payload keypair.
   Find them from saasapi's records (created after the snapshot time) and
   re-provision or re-enrol; section 10 has the list to work through.

### 6.3 The seal key is gone or access to it is lost

With purge protection on, recover the key from soft delete first. If the key
is truly gone, no snapshot taken under it can be restored and OpenBao's
Transit keys are unrecoverable: treat it as a new platform (a new operator,
every tenant and every sprout re-enrolled). This is why section 3 requires
purge protection and the retired-version rule.

### 6.4 Recovery keys lost

- **One share lost, two or more usable:** rekey at once (5.4). This is
  routine and costs nothing.
- **Fewer than two usable shares:** the running cluster keeps working
  (auto-unseal does not need the shares), but nobody can generate a root
  token, change the seal, rekey or change a policy or role, and a disaster
  recovery that needs a root token is blocked. The Transit keys are not
  exportable, so they cannot be moved to a new cluster either. Treat it as an
  incident for the owner to decide: the safe route is to plan a new platform
  (a new operator, every tenant and sprout re-enrolled) in a controlled
  window while the old cluster still runs. This is why section 2 asks every
  holder to prove they can decrypt their share twice a year.

### 6.5 Suspected compromise of farmer or a recovery key

- Farmer pod compromise: revoke farmer's OpenBao role (the `imas-farmer-*`
  Kubernetes auth roles) and restart farmer after fixing the cause; its tokens
  last at most `openbaoBootstrap.tokenMaxTTL` (1 h). A farmer pod can sign
  Account JWTs for any tenant while it holds a token (inherent to its job);
  after the incident check the Account JWTs published since the compromise
  against saasapi's tenant records.
- A recovery share exposed: rekey the recovery keys (5.4) at once. If two
  shares are exposed, treat as a root-token compromise: revoke all tokens,
  rekey, and review the audit log from the time the shares were exposed.

## 7. Seal change or migration

Moving between seals (for example the static seal used in UAT to Azure Key
Vault, or Key Vault to another provider) is the documented OpenBao "seal
migration" (the seal concepts page for the pinned version). It is a
**planned-downtime** operation: both the old and the new seal must be
reachable throughout, and one combination is not supported (the docs say AWS
KMS to AWS KMS cannot be migrated; read the page for your pair of seals
first).

1. Take a snapshot (section 4) and note its name in the change record.
2. Take one **standby** down. In its configuration keep the old seal block
   with `disabled = "true"` and add the new seal block. Restart it.
3. Run `bao operator unseal -migrate` once per recovery-key share, one share
   per invocation, until the threshold (2) is met. Check the node is
   unsealed and has rejoined (`bao operator raft list-peers`), then do the
   next standby the same way. Never have two nodes down at once: Raft needs
   its quorum.
4. When every standby has migrated, run `bao operator step-down` on the
   active node and **verify** that a standby became active and that Raft
   quorum holds (`bao operator raft list-peers`). The same node can win the
   lock again; if it did, repeat the step-down.
5. Watch the new active node's log for the migration to complete and allow
   time for the migration information to replicate. Then take the former
   active node down, update its seal configuration, and restart it.
6. Remove the old seal block from every node's configuration only after all
   peers have migrated, and take a fresh snapshot under the new seal.
   Keep the old seal key until the retention rule in section 3 allows its
   removal.

## 8. The restore drill (launch gate)

Run it before production launch, then every quarter and after any seal,
version or topology change. A drill that has not been run is not a backup.

1. In a scratch namespace or cluster, start an OpenBao with the same image
   and a seal pointing to the same Azure Key Vault key. The drill's identity
   needs the same key permissions as production: `get`, `wrapKey` and
   `unwrapKey` (with Azure RBAC, a role that allows them such as Key Vault
   Crypto Service Encryption User, scoped to that one key). Metadata read
   access alone cannot unseal. That identity can decrypt production data, so
   it is time-limited, held by the drill's owner only, and removed when the
   drill ends.
2. Confirm the scratch cluster auto-unseals, then restore the newest
   production snapshot (section 6.2 step 2).
3. With a root token regenerated from two recovery-key holders (this also
   proves custody), check: the three platform keys exist and are not
   exportable (`bao read transit/keys/nats-operator`); each reports the same
   public key as the trust ConfigMap in production; one tenant key signs
   and verifies a fixed, non-secret test input (`in=$(printf 'imas-restore-drill' | base64)`,
   `bao write transit/sign/nats-tsign-<tenant> input="$in"`, then
   `bao write transit/verify/nats-tsign-<tenant> input="$in" signature=<the signature returned>`
   answers `valid: true`) and its public key matches the tenant's Account JWT; the KV tenant keypairs list;
   the audit device and auth mounts are present.
4. Record the result below and destroy the scratch cluster and its token.

**Drill record (owner fills in a row per drill):**

| Date | Snapshot used (name, date) | Seal key version | Holders present | Result | Time to restore | Follow-ups |
|---|---|---|---|---|---|---|
| | | | | | | |

## 9. Checks after any restore, upgrade or seal change

- `bao status` on each pod: initialized, unsealed, HA enabled.
- `bao operator raft list-peers`: three peers, one leader.
- The three platform Transit keys exist; their public keys equal the NKeys in
  the trust ConfigMap (`natsTrust.configMapName`).
- `farmer` pods Ready and reading keys through Transit (a new sprout enrols
  and gets a JWT; a `cmd.run` to an enrolled sprout works).
- The bus loader pods Ready (`accountloader` has loaded every Account).
- The audit device is on and shipping.
- A new snapshot exists after the change.

## 10. After a restore from an older snapshot

Work through, in order, using saasapi's records (tenants and sprouts) and the
object store:

1. Tenants created after the snapshot time: re-provision (no keys exist).
2. Sprouts enrolled after the snapshot time: re-enrol (their gateway JWT
   issuer and payload keypair are gone).
3. Tenant offboardings after the snapshot time: the soft-delete is not in the
   restored data, so repeat the offboarding of those tenants.
4. Account JWTs in the accounts bucket newer than the snapshot: farmer
   republishes on its reconcile (section 3.3 of the review pack); check the
   loader's accounts match.
5. Revocations made after the snapshot time are in saasapi's records and the
   accounts bucket, not only in OpenBao; re-apply any that the restore undid.

## 11. Launch-gate checklist (D4)

All of these before production launch; the P3 sign-off (`docs/security-review-pack.md`
section 7) refers to this list.

- [ ] Section 2 table filled in with named people; each holder has decrypted
      their share once.
- [ ] Azure Key Vault key with soft delete and purge protection; pods unseal
      through workload identity; no client secret in values.
- [ ] Snapshot schedule running to a separate bucket and region; alert on a
      missing snapshot; retention rule and key-version table in place.
- [ ] Restore drill run once from a production-shaped snapshot and recorded
      in section 8.
- [ ] Root-token procedure (5.2) rehearsed with two holders, and the Secret
      deletion step checked.
- [ ] On-call knows 6.5.
