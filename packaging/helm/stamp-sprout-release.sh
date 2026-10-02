#!/usr/bin/env bash
# Write the sprout release manifest the farmer chart carries (API design
# §2.5): version plus, per OS/arch, the package file name and SHA-256 of
# every imas-sprout package in the release. The chart's release hook
# (deploy/helm/farmer, templates/sprout-release-register-job.yaml) sends
# it, with the chart's channel and min_sprout_version, to saasapi to be
# signed and registered; the sprout later installs the named file from its
# own configured repo and checks it against this hash.
#
# Output: {"version": "vX.Y.Z", "packages": [{os, arch, package_type,
# file_name, checksum_sha256}, ...]}. "version" keeps the tag's "v": it is
# the canonical semver saasapi and internal/fleetsign require, verbatim
# (they never normalize). Package file names carry the version without it.
#
# Usage: stamp-sprout-release.sh <dist-dir> <tag> <out-file>
#   <dist-dir>  directory holding the release's *.rpm, *.deb, *.msi and the
#               checksums.txt they were verified against
#   <tag>       release tag, vX.Y.Z or vX.Y.Z-PRERELEASE (canonical semver: no
#               build metadata, no leading zeros)
#   <out-file>  e.g. deploy/helm/farmer/files/sprout-release.json
#
# Only imas-sprout packages are listed. A file name this script does not
# recognise is an error, not a skip: a sprout package missing from the
# manifest would silently never be offered to the fleet.
set -euo pipefail

dist="${1:?usage: $0 <dist-dir> <tag> <out-file>}"
tag="${2:?usage: $0 <dist-dir> <tag> <out-file>}"
out="${3:?usage: $0 <dist-dir> <tag> <out-file>}"

die() { echo "stamp-sprout-release: $*" >&2; exit 1; }

[[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]] || die "'$tag' is not a canonical release tag (want vX.Y.Z or vX.Y.Z-PRERELEASE)"
version="${tag#v}"
[[ -f "$dist/checksums.txt" ]] || die "no $dist/checksums.txt"
command -v jq >/dev/null || die "jq not found"

entries=()
shopt -s nullglob
for f in "$dist"/imas-sprout[_-]*.rpm "$dist"/imas-sprout[_-]*.deb "$dist"/imas-sprout-*-windows-*.msi; do
	name="$(basename "$f")"
	sum="$(awk -v n="$name" '$2 == n { print $1 }' "$dist/checksums.txt")"
	[[ -n "$sum" ]] || die "$name is not in checksums.txt"
	[[ "$(sha256sum "$f" | awk '{ print $1 }')" == "$sum" ]] || die "$name does not match checksums.txt"
	case "$name" in
	imas-sprout_"${version}"_linux_*.deb) type=deb; os=linux; arch="${name#imas-sprout_"${version}"_linux_}"; arch="${arch%.deb}" ;;
	imas-sprout_"${version}"_linux_*.rpm) type=rpm; os=linux; arch="${name#imas-sprout_"${version}"_linux_}"; arch="${arch%.rpm}" ;;
	imas-sprout-"${version}"-windows-*.msi) type=msi; os=windows; arch="${name#imas-sprout-"${version}"-windows-}"; arch="${arch%.msi}" ;;
	*) die "unrecognised sprout package name '$name' for version $version" ;;
	esac
	case "$arch" in
	x64) arch=amd64 ;;
	x86) arch=386 ;;
	esac
	[[ "$arch" =~ ^[a-z0-9]+$ ]] || die "bad arch '$arch' in $name"
	entries+=("$(jq -cn --arg os "$os" --arg arch "$arch" --arg type "$type" --arg file "$name" --arg sha "$sum" \
		'{os:$os, arch:$arch, package_type:$type, file_name:$file, checksum_sha256:$sha}')")
done
shopt -u nullglob

(( ${#entries[@]} )) || die "no imas-sprout packages in $dist"
for t in deb rpm msi; do
	printf '%s\n' "${entries[@]}" | jq -e --arg t "$t" 'select(.package_type == $t)' >/dev/null \
		|| die "no $t package for imas-sprout in $dist"
done

mkdir -p "$(dirname "$out")"
printf '%s\n' "${entries[@]}" | jq -s --arg v "$tag" '{version: $v, packages: (. | sort_by(.os, .arch, .package_type))}' > "$out"
echo "stamp-sprout-release: ${#entries[@]} packages -> $out"
