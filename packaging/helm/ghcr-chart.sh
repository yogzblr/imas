#!/usr/bin/env bash
# The GHCR side of publishing a Helm chart (publish-packages.yml, BUILD-STATUS
# P10), with nothing but curl, jq and sha256sum: GHCR's OCI distribution API
# and GitHub's package page.
#
# digest <chart> <version>
#   Print the manifest digest of oci://ghcr.io/yogzblr/charts/<chart>:<version>
#   and exit 0, or exit 3 when that version is not on GHCR. Uses the
#   credential in GHCR_USER/GHCR_TOKEN when set (the publish run's
#   GITHUB_TOKEN, so a private package is seen too), anonymous otherwise.
#   publish-packages.yml calls it before pushing, so a version GHCR already
#   holds is never pushed again (GHCR would move the tag).
#
# check <chart> <version> <digest>
#   What a consumer gets, checked anonymously (GHCR_USER/GHCR_TOKEN are
#   ignored), after the push:
#     1. the chart can be pulled with no credential: an anonymous registry
#        token, the manifest of <version>, whose digest must be <digest>
#        (the one pushed and signed), and the chart layer, whose content
#        must match its digest. Fails when the package is private.
#     2. the manifest's org.opencontainers.image.source annotation names
#        this repository (helm push sets it from Chart.yaml sources[0]);
#        it is what GHCR links a package to a repository by.
#     3. the package is linked to this repository: its repository package
#        page, https://github.com/<repository>/pkgs/container/<package>,
#        exists (GitHub serves it only for a package connected to that
#        repository).
#   Every failure says what the owner has to do. Package visibility and the
#   repository link are package settings the workflow's GITHUB_TOKEN cannot
#   change (owner decision V2), so they are an owner step
#   (docs/RELEASING.md, "Helm charts on GHCR").
#
# Environment (defaults are the real ones; the tests point them at a fake):
#   IMAS_GHCR_URL       https://ghcr.io
#   IMAS_GITHUB_URL     https://github.com
#   IMAS_REPOSITORY     yogzblr/imas
#   IMAS_CHART_PATH     yogzblr/charts   (the chart is <path>/<chart>)
set -euo pipefail

registry="${IMAS_GHCR_URL:-https://ghcr.io}"
web="${IMAS_GITHUB_URL:-https://github.com}"
repository="${IMAS_REPOSITORY:-yogzblr/imas}"
chart_path="${IMAS_CHART_PATH:-yogzblr/charts}"
service="${registry#*://}"
service="${service%%/*}"
manifest_type=application/vnd.oci.image.manifest.v1+json
config_type=application/vnd.cncf.helm.config.v1+json
layer_type=application/vnd.cncf.helm.chart.content.v1.tar+gzip

die() {
	echo "::error::$*" >&2
	exit 1
}
usage() {
	echo "usage: ghcr-chart.sh digest <chart> <version> | check <chart> <version> <sha256:digest>" >&2
	exit 2
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# token <repo> <anonymous:true|false>: a pull token for <repo> on stdout.
token() {
	local auth=()
	if [ "$2" = "false" ] && [ -n "${GHCR_TOKEN:-}" ]; then
		auth=(-u "${GHCR_USER:-token}:${GHCR_TOKEN}")
	fi
	local code
	code="$(curl -sS -o "$work/token.json" -w '%{http_code}' "${auth[@]}" \
		"${registry}/token?scope=repository:${1}:pull&service=${service}")" || return 1
	[ "$code" = "200" ] || return 1
	jq -er '.token // .access_token' "$work/token.json"
}

# manifest <repo> <reference> <token>: writes $work/manifest, prints the HTTP status.
manifest() {
	curl -sS -o "$work/manifest" -w '%{http_code}' \
		-H "Authorization: Bearer $3" -H "Accept: ${manifest_type}" \
		"${registry}/v2/${1}/manifests/${2}"
}

[ "$#" -ge 1 ] || usage
cmd="$1"
shift
case "$cmd" in
digest) [ "$#" -eq 2 ] || usage ;;
check) [ "$#" -eq 3 ] || usage ;;
*) usage ;;
esac
chart="$1"
version="$2"
[[ "$chart" =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "'$chart' is not a chart name"
[[ "$version" =~ ^[0-9A-Za-z][0-9A-Za-z._-]*$ ]] || die "'$version' is not a chart version"
repo="${chart_path}/${chart}"
package="${repo#*/}" # the GitHub package name: charts/<chart>
oci="oci://${service}/${repo}"

if [ "$cmd" = "digest" ]; then
	anonymous=true
	[ -n "${GHCR_TOKEN:-}" ] && anonymous=false
	# GHCR answers DENIED for a package that does not exist yet (the first
	# push of a chart) and, anonymously, for a private one. Either way
	# nothing visible holds this version; a push the credential may not make
	# is refused by GHCR itself.
	tok="$(token "$repo" "$anonymous")" || exit 3
	code="$(manifest "$repo" "$version" "$tok")" || die "could not reach ${registry}"
	case "$code" in
	200) ;;
	404) exit 3 ;;
	*) die "GHCR answered HTTP $code for the manifest of ${oci}:${version}" ;;
	esac
	echo "sha256:$(sha256sum "$work/manifest" | cut -d' ' -f1)"
	exit 0
fi

want="$3"
[[ "$want" =~ ^sha256:[0-9a-f]{64}$ ]] || die "'$want' is not a sha256 digest"
settings="${web}/users/${chart_path%%/*}/packages/container/${package//\//%2F}/settings"
private_fix="the owner must make the package public once: on GitHub, Packages, ${package}, Package settings (${settings}), Danger Zone, Change visibility, Public. Then run Publish packages again from the tag with only_helm ticked: a version already on GHCR and signed by this tag's run is not pushed again"

# 1. Anonymous pull.
tok="$(token "$repo" true)" ||
	die "${oci}:${version} cannot be pulled anonymously (GHCR refused an anonymous token: the package is private): ${private_fix}"
code="$(manifest "$repo" "$version" "$tok")" || die "could not reach ${registry}"
[ "$code" = "200" ] ||
	die "${oci}:${version} cannot be pulled anonymously (HTTP $code for its manifest): ${private_fix}"
got="sha256:$(sha256sum "$work/manifest" | cut -d' ' -f1)"
[ "$got" = "$want" ] ||
	die "${oci}:${version} is ${got} anonymously, not the pushed and signed ${want}: the tag was pushed again; never re-push a released version, release the next one"
jq -e --arg c "$config_type" '.config.mediaType == $c' "$work/manifest" >/dev/null ||
	die "${oci}:${version} is not a Helm chart (config media type is not ${config_type})"
layer="$(jq -er --arg l "$layer_type" '[.layers[] | select(.mediaType == $l)] | if length == 1 then .[0].digest else error("want one chart layer") end' "$work/manifest")" ||
	die "${oci}:${version} has no single ${layer_type} layer"
code="$(curl -sS -L -o "$work/chart.tgz" -w '%{http_code}' -H "Authorization: Bearer $tok" \
	"${registry}/v2/${repo}/blobs/${layer}")" ||
	die "could not download the chart layer of ${oci}:${version} (GHCR redirects blob downloads to its storage host)"
[ "$code" = "200" ] ||
	die "the chart layer of ${oci}:${version} cannot be downloaded anonymously (HTTP $code): ${private_fix}"
[ "sha256:$(sha256sum "$work/chart.tgz" | cut -d' ' -f1)" = "$layer" ] ||
	die "the chart layer of ${oci}:${version} does not match its digest ${layer}"
echo "pulled ${oci}:${version} anonymously (${want})"

# 2. The source annotation GHCR links the package by.
source_url="https://github.com/${repository}" # Chart.yaml sources[0], whatever IMAS_GITHUB_URL is
src="$(jq -r '.annotations["org.opencontainers.image.source"] // ""' "$work/manifest")"
[ "$src" = "$source_url" ] ||
	die "${oci}:${version} names source '${src}', not ${source_url}: set sources[0] in the chart's Chart.yaml to ${source_url} and release the next version"

# 3. The package is linked to the repository.
page="${web}/${repository}/pkgs/container/${package//\//%2F}"
code="$(curl -sS -o /dev/null -w '%{http_code}' "$page")" || die "could not reach ${web}"
case "$code" in
200) echo "package ${package} is public and linked to ${repository} (${page})" ;;
404) die "package ${package} is not linked to ${repository} (${page} is HTTP 404): the owner must connect it once: on GitHub, Packages, ${package}, Package settings (${settings}), Connect repository, ${repository}; and under Manage Actions access give ${repository} the Write role. Then run Publish packages again from the tag with only_helm ticked" ;;
*) die "GitHub answered HTTP $code for ${page}; cannot tell whether ${package} is linked to ${repository}" ;;
esac
