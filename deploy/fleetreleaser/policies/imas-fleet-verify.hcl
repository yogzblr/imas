# imas-fleet-verify: farmer's and saasapi's OpenBao policy for the
# imas-fleet-signing Transit key. READ-ONLY: read the public keys and ask
# Transit to verify, nothing else. Attach it to two separate auth roles
# (one per service account); don't share a role or token between them.
# See deploy/fleetreleaser/README.md and
# docs/design/cloudxp-machine-manager-api-design.md §2.5.
#
# FLAG FOR SECURITY REVIEW. This policy must never grant, and no other
# policy on farmer's or saasapi's roles may grant (including through a
# "*" or "+" path on the gateway key's policy):
#   transit/sign/imas-fleet-signing[/*]
#   transit/keys/imas-fleet-signing/rotate, .../config, .../trim
#   transit/keys/imas-fleet-signing with create/update/delete
#   transit/export/*, transit/backup/*, transit/restore/*
# saasapi can already write saas.fleet_versions; pairing that with sign
# on this key would let one compromised process publish a release every
# sprout installs.

# Public keys only ("read" on the key itself; never create/update).
path "transit/keys/imas-fleet-signing" {
  capabilities = ["read"]
}

# Transit-side verification.
path "transit/verify/imas-fleet-signing" {
  capabilities = ["update"]
}
