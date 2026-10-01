#!/usr/bin/env bash
# Upload packaged Helm charts (*.tgz) to the Buildkite Helm registry.
#
# Usage: publish-helm.sh <chart-dir>
#   <chart-dir>  directory holding the .tgz files written by `helm package`
#
# Environment:
#   BUILDKITE_PACKAGES_TOKEN     required unless DRY_RUN. API access token with
#                                the Read Packages and Write Packages scopes.
#   BUILDKITE_ORGANIZATION_SLUG  required. The Buildkite org owning the registry.
#   BUILDKITE_HELM_REGISTRY      default imashelm
#   DRY_RUN=1                    list what would be uploaded, upload nothing.
#   BUILDKITE_API_URL            default https://api.buildkite.com
#
# Same REST upload as publish-packages.sh. A chart version already in the
# registry fails the upload rather than being skipped: re-publishing a
# version must be a deliberate delete first.
set -euo pipefail

dir="${1:?usage: $0 <chart-dir>}"
api="${BUILDKITE_API_URL:-https://api.buildkite.com}"
registry="${BUILDKITE_HELM_REGISTRY:-imashelm}"
dry_run="${DRY_RUN:-}"

die() { echo "publish-helm: $*" >&2; exit 1; }

[[ -d "$dir" ]] || die "no such directory: $dir"
[[ -n "${BUILDKITE_ORGANIZATION_SLUG:-}" ]] || die "BUILDKITE_ORGANIZATION_SLUG is not set"
org="$BUILDKITE_ORGANIZATION_SLUG"
[[ "$org" =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "bad BUILDKITE_ORGANIZATION_SLUG '$org'"
[[ "$registry" =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "bad BUILDKITE_HELM_REGISTRY '$registry'"
if [[ -z "$dry_run" ]]; then
	[[ -n "${BUILDKITE_PACKAGES_TOKEN:-}" ]] || die "BUILDKITE_PACKAGES_TOKEN is not set"
	command -v curl >/dev/null || die "curl not found"
fi

shopt -s nullglob
charts=("$dir"/*.tgz)
shopt -u nullglob
(( ${#charts[@]} )) || die "no .tgz chart in $dir"

url="$api/v2/packages/organizations/$org/registries/$registry/packages"
for f in "${charts[@]}"; do
	echo "publish-helm: $(basename "$f") -> $registry"
	[[ -z "$dry_run" ]] || continue
	body="$(mktemp)"
	# The token goes in via a header file on process substitution, not argv.
	status=$(curl -sS -o "$body" -w '%{http_code}' -X POST \
		-H @<(printf 'Authorization: Bearer %s\n' "$BUILDKITE_PACKAGES_TOKEN") \
		-F "file=@$f" "$url") || { cat "$body" >&2; rm -f "$body"; die "upload of $f failed"; }
	if [[ "$status" != 2?? ]]; then
		cat "$body" >&2; echo >&2; rm -f "$body"
		die "upload of $f to $registry: HTTP $status"
	fi
	rm -f "$body"
done
echo "publish-helm: done (${#charts[@]} chart(s))${dry_run:+ [dry run]}"
