# imas-farmer-natssign: farmer's NATS signer (internal/pki through
# internal/pki/natskeys; P21 slice 1, docs/briefs/P21-slice1-transit-signer.md
# §3.2 and the owner decisions of 2026-10-11, issue #197). Bound to the
# imas-farmer-natssign role, which only farmer's ServiceAccount can use.
#
# FLAG FOR SECURITY REVIEW.
#   - The three platform keys: read only (public key and hardening
#     check). farmer never creates, rotates, configures or retires them.
#   - Sign with operator-signing (account JWTs) and the SYS account (SYS
#     users), never with nats-operator, the operator identity: only the
#     bootstrap Job's ephemeral policy signs with it.
#   - Per-tenant keys (nats-tsign-<tenant>, nats-tacct-<tenant>): created
#     at provisioning, read, and soft-deleted at offboarding. OpenBao 2.7.1
#     creates a Transit key on "update", and "update" on a keys/nats-tsign-*
#     glob would also reach keys/<name>/rotate and /config: a glob that
#     starts later in the path outranks every deny on those sub-paths, so
#     they can't be taken back (tested on a real server; owner choice of
#     2026-10-12, which replaces the glob-plus-deny form of the 2026-10-11
#     decision (2), issue #197). So:
#       keys/+              update, read: one path segment, a key name and
#                           nothing below it, so rotate, config, trim,
#                           import, restore and hard delete are not reached.
#                           Exact rules win over "+": the platform keys stay
#                           read only.
#       keys/+/soft-delete  delete: retire a key. Never the platform keys
#                           or the gateway key (exact deny below).
#     Accepted cost: farmer can create keys of any name on this mount
#     (it can sign with none of them but nats-tsign-*), and could
#     soft-delete a key another client adds here later; give such a
#     client an exact deny below, or a mount of its own.
#   - Sign with tenant signing keys only; the tenant account key never
#     signs (the account JWT is signed by operator-signing).
#   - No export, backup or restore path.

path "transit/keys/nats-operator" {
  capabilities = ["read"]
}

path "transit/keys/nats-operator-signing" {
  capabilities = ["read"]
}

path "transit/keys/nats-sys-account" {
  capabilities = ["read"]
}

path "transit/sign/nats-operator-signing" {
  capabilities = ["update"]
}

path "transit/sign/nats-sys-account" {
  capabilities = ["update"]
}

path "transit/keys/+" {
  capabilities = ["update", "read"]
}

path "transit/keys/+/soft-delete" {
  capabilities = ["delete"]
}

path "transit/keys/nats-operator/soft-delete" {
  capabilities = ["deny"]
}

path "transit/keys/nats-operator-signing/soft-delete" {
  capabilities = ["deny"]
}

path "transit/keys/nats-sys-account/soft-delete" {
  capabilities = ["deny"]
}

path "transit/keys/imas-gateway-jwt/soft-delete" {
  capabilities = ["deny"]
}

path "transit/sign/nats-tsign-*" {
  capabilities = ["update"]
}
