#!/usr/bin/env bash
# Upload a goreleaser release's OS packages to Buildkite Package Registries.
#
#   .rpm    -> $BUILDKITE_RPM_REGISTRY   (default imasrpm,  Red Hat registry;
#                                          serves RHEL/Rocky/Alma and SUSE)
#   .deb    -> $BUILDKITE_DEB_REGISTRY   (default imasdeb,  Debian registry)
#   .nupkg  -> $BUILDKITE_NUGET_REGISTRY (default imasnget, NuGet registry,
#                                          public; the winget feed, see
#                                          packaging/windows/winget/)
#
# The winget installer package (*.msi.*.nupkg) goes up before the manifest
# package, since the manifests point at it. If <nupkg-dir> has the
# winget-installer.env that build-winget-nupkg.sh writes, the installer is
# then downloaded anonymously from INSTALLER_URL (retrying while the feed
# indexes it) and its SHA-256 compared with INSTALLER_SHA256, before any
# manifest is published: a manifest winget clients can't install from is
# worse than none.
#
# Usage: publish-packages.sh <dist-dir> [<nupkg-dir>]
#   <dist-dir>   goreleaser's dist/: the top-level *.rpm and *.deb are taken.
#   <nupkg-dir>  where build-winget-nupkg.sh wrote *.nupkg (default
#                <dist-dir>/winget).
#
# Environment:
#   BUILDKITE_PACKAGES_TOKEN     required. Buildkite API access token with the
#                                Read Packages and Write Packages scopes.
#   BUILDKITE_ORGANIZATION_SLUG  required. The Buildkite org owning the registries.
#   DRY_RUN=1                    list what would be uploaded, upload nothing.
#   BUILDKITE_API_URL            default https://api.buildkite.com
#   BUILDKITE_PACKAGES_URL       default https://packages.buildkite.com
#   VERIFY_ATTEMPTS, VERIFY_DELAY  installer check retries (default 30 x 10s)
#
# rpm/deb go through the REST API (POST .../registries/{slug}/packages,
# multipart "file"); NuGet through `dotnet nuget push`, which is what
# Buildkite documents for NuGet registries. Every package type must be present:
# a release missing one means the build broke, not that there's nothing to do.
# A package already in a registry fails the upload rather than being skipped.
set -euo pipefail

dist="${1:?usage: $0 <dist-dir> [<nupkg-dir>]}"
nupkg_dir="${2:-$dist/winget}"

api="${BUILDKITE_API_URL:-https://api.buildkite.com}"
pkgs="${BUILDKITE_PACKAGES_URL:-https://packages.buildkite.com}"
rpm_registry="${BUILDKITE_RPM_REGISTRY:-imasrpm}"
deb_registry="${BUILDKITE_DEB_REGISTRY:-imasdeb}"
nuget_registry="${BUILDKITE_NUGET_REGISTRY:-imasnget}"
dry_run="${DRY_RUN:-}"

die() { echo "publish-packages: $*" >&2; exit 1; }

[[ -d "$dist" ]] || die "no such directory: $dist"
if [[ -z "$dry_run" ]]; then
	[[ -n "${BUILDKITE_PACKAGES_TOKEN:-}" ]] || die "BUILDKITE_PACKAGES_TOKEN is not set"
	command -v curl >/dev/null || die "curl not found"
fi
[[ -n "${BUILDKITE_ORGANIZATION_SLUG:-}" ]] || die "BUILDKITE_ORGANIZATION_SLUG is not set"
org="$BUILDKITE_ORGANIZATION_SLUG"
[[ "$org" =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "bad BUILDKITE_ORGANIZATION_SLUG '$org'"

shopt -s nullglob
rpms=("$dist"/*.rpm)
debs=("$dist"/*.deb)
nupkgs=("$nupkg_dir"/*.nupkg)
shopt -u nullglob
(( ${#rpms[@]} )) || die "no .rpm in $dist"
(( ${#debs[@]} )) || die "no .deb in $dist"
(( ${#nupkgs[@]} )) || die "no .nupkg in $nupkg_dir"
if [[ -z "$dry_run" && ${#nupkgs[@]} -gt 0 ]]; then
	command -v dotnet >/dev/null || die "dotnet not found (needed for NuGet push)"
fi

# REST upload. The token goes in via a header file on stdin-like process
# substitution rather than argv, so it doesn't show up in the process list.
rest_upload() {
	local registry="$1" file="$2" url body status
	url="$api/v2/packages/organizations/$org/registries/$registry/packages"
	echo "publish-packages: $(basename "$file") -> $registry"
	[[ -z "$dry_run" ]] || return 0
	body="$(mktemp)"
	status=$(curl -sS -o "$body" -w '%{http_code}' -X POST \
		-H @<(printf 'Authorization: Bearer %s\n' "$BUILDKITE_PACKAGES_TOKEN") \
		-F "file=@$file" "$url") || { cat "$body" >&2; rm -f "$body"; die "upload of $file failed"; }
	if [[ "$status" != 2?? ]]; then
		cat "$body" >&2; echo >&2; rm -f "$body"
		die "upload of $file to $registry: HTTP $status"
	fi
	rm -f "$body"
}

nuget_upload() {
	local file="$1" source="$pkgs/$org/$nuget_registry/nuget/package"
	echo "publish-packages: $(basename "$file") -> $nuget_registry"
	[[ -z "$dry_run" ]] || return 0
	DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 \
		dotnet nuget push "$file" --source "$source" --api-key "$BUILDKITE_PACKAGES_TOKEN" --timeout 600 \
		|| die "NuGet push of $file to $nuget_registry failed"
}

# verify_installer: fetch INSTALLER_URL with no credentials and compare its
# hash, retrying while the feed catches up.
verify_installer() {
	local env_file="$nupkg_dir/winget-installer.env" url sha got tmp i
	[[ -f "$env_file" ]] || { echo "publish-packages: no $env_file; not checking the installer download"; return 0; }
	url="$(sed -n 's/^INSTALLER_URL=//p' "$env_file")"
	sha="$(sed -n 's/^INSTALLER_SHA256=//p' "$env_file")"
	[[ -n "$url" && -n "$sha" ]] || die "$env_file lacks INSTALLER_URL or INSTALLER_SHA256"
	echo "publish-packages: checking $url"
	[[ -z "$dry_run" ]] || return 0
	tmp="$(mktemp)"
	for ((i = 1; i <= ${VERIFY_ATTEMPTS:-30}; i++)); do
		if curl -sSfL -o "$tmp" "$url" 2>/dev/null; then
			got="$(sha256sum "$tmp" | awk '{ print toupper($1) }')"
			rm -f "$tmp"
			[[ "$got" == "${sha^^}" ]] || die "$url has SHA-256 $got, the manifests say $sha"
			echo "publish-packages: installer downloadable anonymously, hash matches"
			return 0
		fi
		sleep "${VERIFY_DELAY:-10}"
	done
	rm -f "$tmp"
	die "$url not downloadable anonymously after ${VERIFY_ATTEMPTS:-30} attempts; is $nuget_registry public? Not publishing the winget manifests"
}

installer_nupkgs=() other_nupkgs=()
for f in "${nupkgs[@]}"; do
	if [[ "$(basename "$f")" == *.msi.*.nupkg ]]; then installer_nupkgs+=("$f"); else other_nupkgs+=("$f"); fi
done

for f in "${rpms[@]}"; do rest_upload "$rpm_registry" "$f"; done
for f in "${debs[@]}"; do rest_upload "$deb_registry" "$f"; done
for f in "${installer_nupkgs[@]}"; do nuget_upload "$f"; done
if (( ${#installer_nupkgs[@]} )); then verify_installer; fi
for f in "${other_nupkgs[@]}"; do nuget_upload "$f"; done

echo "publish-packages: done (${#rpms[@]} rpm, ${#debs[@]} deb, ${#nupkgs[@]} nupkg)${dry_run:+ [dry run]}"
