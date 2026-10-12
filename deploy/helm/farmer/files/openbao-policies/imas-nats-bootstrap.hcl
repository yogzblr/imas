# imas-nats-bootstrap: EPHEMERAL. The bootstrap Job's prepare container
# writes it, mints one orphan, non-renewable 10-minute token with it for
# the nats-trust container (`farmer bootstrap-nats-trust`), and the Job's
# main container deletes it before it exits (P21 slice 1 brief §3.2, §4).
# No role is ever bound to it.
#
# FLAG FOR SECURITY REVIEW: the only grant anywhere that signs with
# nats-operator, the operator identity key (design D3).
#   - "update" on the three exact key paths creates them (owner decision
#     2026-10-11, issue #197: Transit creates on "update"); exact paths, so
#     keys/<name>/rotate and /config are not granted. "read" loads them.
#   - Sign with the three platform keys: the operator JWT
#     (nats-operator), the SYS account JWT (nats-operator-signing), the bus
#     fence user JWT (nats-sys-account).
#   - Revoke and look up its own token. Nothing on any tenant key.
#   - With natsTrust.kvCopy.enabled the chart appends one KV v2 grant for
#     the public trust copy.

path "transit/keys/nats-operator" {
  capabilities = ["update", "read"]
}

path "transit/keys/nats-operator-signing" {
  capabilities = ["update", "read"]
}

path "transit/keys/nats-sys-account" {
  capabilities = ["update", "read"]
}

path "transit/sign/nats-operator" {
  capabilities = ["update"]
}

path "transit/sign/nats-operator-signing" {
  capabilities = ["update"]
}

path "transit/sign/nats-sys-account" {
  capabilities = ["update"]
}

path "auth/token/revoke-self" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}
