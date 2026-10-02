#!/usr/bin/env bash
# Write the sprout release manifest the farmer chart carries (API design
# §2.5): version, min_sprout_version and, per OS/arch, the package file
# name and SHA-256 of every imas-sprout package in the release. The chart's
# release hook (deploy/helm/farmer, templates/sprout-release-register-job.yaml)
# sends it, with the chart's channel, to saasapi to be signed and
# registered; the sprout later installs the named file from its own
# configured repo and checks it against this hash.
#
# Output: {"version": "vX.Y.Z", "min_sprout_version": "vA.B.C",
# "packages": [{os, arch, package_type, file_name, checksum_sha256}, ...]}.
# Both versions are canonical semver with the leading "v", verbatim, as
# saasapi and internal/fleetsign require (they never normalize). Package
# file names carry the version without it.
#
# min_sprout_version comes from the min-sprout-version file next to this
# script (its one non-comment line), so the floor is reviewed in a PR and
# ships under the tag like everything else. It must be at most the
# release's version, by semver precedence.
#
# Usage: stamp-sprout-release.sh <dist-dir> <tag> <out-file> [<min-sprout-version-file>]
#   <dist-dir>  directory holding the release's *.rpm, *.deb, *.msi and the
#               checksums.txt they were verified against
#   <tag>       release tag, vX.Y.Z or vX.Y.Z-PRERELEASE (canonical semver: no
#               build metadata, no leading zeros)
#   <out-file>  e.g. deploy/helm/farmer/files/sprout-release.json
#   <min-sprout-version-file>  default: min-sprout-version beside this script
#
# Only imas-sprout packages are listed. A file name this script does not
# recognise is an error, not a skip: a sprout package missing from the
# manifest would silently never be offered to the fleet.
set -euo pipefail

dist="${1:?usage: $0 <dist-dir> <tag> <out-file>}"
tag="${2:?usage: $0 <dist-dir> <tag> <out-file>}"
out="${3:?usage: $0 <dist-dir> <tag> <out-file>}"

min_file="${4:-$(dirname "$0")/min-sprout-version}"

die() { echo "stamp-sprout-release: $*" >&2; exit 1; }

canonical='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'

# semver_cmp A B prints -1, 0 or 1: semver 2.0.0 precedence of two
# canonical versions (core numerically; a prerelease below its release;
# prerelease identifiers numerically when both are numeric, numeric below
# alphanumeric, else ASCII; a shorter identifier list below a longer one).
semver_cmp() {
	local a="${1#v}" b="${2#v}" ap="" bp="" i
	[[ "$a" == *-* ]] && { ap="${a#*-}"; a="${a%%-*}"; }
	[[ "$b" == *-* ]] && { bp="${b#*-}"; b="${b%%-*}"; }
	local -a ac bc ai bi
	IFS=. read -ra ac <<<"$a"
	IFS=. read -ra bc <<<"$b"
	for i in 0 1 2; do
		((10#${ac[i]} < 10#${bc[i]})) && { echo -1; return; }
		((10#${ac[i]} > 10#${bc[i]})) && { echo 1; return; }
	done
	[[ -z "$ap" && -z "$bp" ]] && { echo 0; return; }
	[[ -z "$ap" ]] && { echo 1; return; }
	[[ -z "$bp" ]] && { echo -1; return; }
	IFS=. read -ra ai <<<"$ap"
	IFS=. read -ra bi <<<"$bp"
	for ((i = 0; i < ${#ai[@]} && i < ${#bi[@]}; i++)); do
		local x="${ai[i]}" y="${bi[i]}"
		[[ "$x" == "$y" ]] && continue
		if [[ "$x" =~ ^[0-9]+$ && "$y" =~ ^[0-9]+$ ]]; then
			((10#$x < 10#$y)) && echo -1 || echo 1
		elif [[ "$x" =~ ^[0-9]+$ ]]; then echo -1
		elif [[ "$y" =~ ^[0-9]+$ ]]; then echo 1
		else
			local LC_ALL=C
			[[ "$x" < "$y" ]] && echo -1 || echo 1
		fi
		return
	done
	((${#ai[@]} < ${#bi[@]})) && echo -1 || { ((${#ai[@]} > ${#bi[@]})) && echo 1 || echo 0; }
}

[[ "$tag" =~ $canonical ]] || die "'$tag' is not a canonical release tag (want vX.Y.Z or vX.Y.Z-PRERELEASE)"
version="${tag#v}"
[[ -f "$min_file" ]] || die "no $min_file"
lines="$(grep -v '^[[:space:]]*\(#\|$\)' "$min_file" || true)"
[[ -n "$lines" && "$lines" != *$'\n'* ]] || die "$min_file must hold exactly one version line (and # comments)"
min="$(tr -d '[:space:]' <<<"$lines")"
[[ "$min" =~ $canonical ]] || die "min_sprout_version '$min' in $min_file is not canonical semver (want vX.Y.Z or vX.Y.Z-PRERELEASE)"
[[ "$(semver_cmp "$min" "$tag")" != 1 ]] || die "min_sprout_version $min ($min_file) is above the release's version $tag"
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
printf '%s\n' "${entries[@]}" | jq -s --arg v "$tag" --arg min "$min" '{version: $v, min_sprout_version: $min, packages: (. | sort_by(.os, .arch, .package_type))}' > "$out"
echo "stamp-sprout-release: $tag (min_sprout_version $min), ${#entries[@]} packages -> $out"
