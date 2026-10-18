#!/usr/bin/env bash
# Print the keyless cosign certificate identity that signed one release
# artifact, pinned to the workflow of this repository and the exact tag ref
# the release was run on. Every `cosign verify` of an imas release (the
# workflows, docs/RELEASING.md, SECURITY.md) passes this string to
# --certificate-identity, an exact match, never a regular expression: a
# signature made by a branch run, by another workflow or for another tag
# does not verify.
#
#   release.yml           signs checksums.txt (.sigstore.json bundle) and
#                         the ghcr.io/yogzblr/imas-* images
#   publish-packages.yml  signs the Helm charts
#                         (oci://ghcr.io/yogzblr/charts/{farmer,nats})
#
# Both workflows refuse to run on any ref but refs/tags/<tag>, so the
# identity of version X.Y.Z is always the one of tag vX.Y.Z.
#
# Usage: cosign-identity.sh <workflow> <tag>
#        cosign-identity.sh --issuer
#   <workflow>  release.yml or publish-packages.yml
#   <tag>       vX.Y.Z or vX.Y.Z-PRERELEASE (canonical semver, as
#               packaging/helm/stamp-sprout-release.sh requires)
#   --issuer    print the OIDC issuer to pass to --certificate-oidc-issuer
#
# Example:
#   cosign verify "ghcr.io/yogzblr/charts/farmer@sha256:<digest>" \
#     --certificate-identity "$(packaging/release/cosign-identity.sh publish-packages.yml v0.1.0-rc.14)" \
#     --certificate-oidc-issuer "$(packaging/release/cosign-identity.sh --issuer)"
set -euo pipefail

repository=yogzblr/imas
issuer=https://token.actions.githubusercontent.com
canonical='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'

die() {
	echo "cosign-identity.sh: $*" >&2
	exit 2
}

if [ "$#" -eq 1 ] && [ "$1" = "--issuer" ]; then
	echo "$issuer"
	exit 0
fi
[ "$#" -eq 2 ] || die "usage: cosign-identity.sh <release.yml|publish-packages.yml> <vX.Y.Z[-PRERELEASE]> | --issuer"

workflow="$1"
tag="$2"
case "$workflow" in
release.yml | publish-packages.yml) ;;
*) die "'$workflow' signs nothing (want release.yml or publish-packages.yml)" ;;
esac
[[ "$tag" =~ $canonical ]] || die "'$tag' is not a canonical release tag (want vX.Y.Z or vX.Y.Z-PRERELEASE)"

echo "https://github.com/${repository}/.github/workflows/${workflow}@refs/tags/${tag}"
