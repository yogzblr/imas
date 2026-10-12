# imas-nats-sys-signer: the SaaS API credential publish Job's NATS signer
# (`farmer publish-saasapi-credential`, role imas-natssign-publisher; P21
# slice 1 brief §3.2). It signs the SaaS API's NATS User JWT with the SYS
# account key and nothing else.
#
# FLAG FOR SECURITY REVIEW.
#   - Read the three platform keys (public keys, hardening check).
#   - Sign with nats-sys-account only: never operator-signing, the
#     operator identity or any tenant key.
#   - Exact paths only; no "*" or "+".

path "transit/keys/nats-operator" {
  capabilities = ["read"]
}

path "transit/keys/nats-operator-signing" {
  capabilities = ["read"]
}

path "transit/keys/nats-sys-account" {
  capabilities = ["read"]
}

path "transit/sign/nats-sys-account" {
  capabilities = ["update"]
}
