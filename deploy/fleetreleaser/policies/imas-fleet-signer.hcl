# imas-fleet-signer: cmd/fleetreleaser's OpenBao policy, and ONLY
# cmd/fleetreleaser's. The single identity allowed to sign sprout releases.
# See deploy/fleetreleaser/README.md and
# docs/design/cloudxp-machine-manager-api-design.md §2.5.
#
# FLAG FOR SECURITY REVIEW. Exact paths only: no "*", no "+" segments.

# Sign version|artifact_url|checksum_sha256. Ed25519 signs the message
# directly, so the plain sign/<key> path is all that's needed; the
# sign/<key>/<hash_algorithm> variant is not granted.
path "transit/sign/imas-fleet-signing" {
  capabilities = ["update"]
}

# Read the public keys, to verify each signature before writing the row.
path "transit/keys/imas-fleet-signing" {
  capabilities = ["read"]
}
