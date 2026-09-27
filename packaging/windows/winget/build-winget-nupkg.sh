#!/usr/bin/env bash
# Build the two NuGet packages that carry imas sprout to Windows through the
# public imasnget feed (Buildkite Package Registries, NuGet):
#
#   <id>.msi.<version>.nupkg   the installer: the MSI at the package root.
#                              winget downloads this package straight from
#                              the feed (InstallerType zip, NestedInstallerType
#                              wix), so it must be published first.
#   <id>.<version>.nupkg       the winget manifests (schema 1.10.0) in the
#                              winget-pkgs layout under manifests/, pointing
#                              at the installer package above.
#
# Two packages because a manifest can't hold the hash of a file it is inside.
#
# Usage:
#   build-winget-nupkg.sh --msi imas-sprout-1.2.3-windows-x64.msi \
#                         --version 1.2.3 \
#                         --package-base-address https://…/  \
#                         [--package-identifier imas.sprout.windows] [--out dist/winget]
#
# --package-base-address is the feed's NuGet v3 PackageBaseAddress (the
# "flat container" URL listed in its index.json). The installer URL is built
# from it the standard way: <base>/<id>/<version>/<id>.<version>.nupkg,
# lower-cased. The feed must allow anonymous downloads: winget clients send
# no credentials.
#
# InstallerSha256 is the installer package's hash; ProductCode, UpgradeCode
# and the MSI version are read from the MSI (msiinfo, from msitools), so the
# manifests can't drift from what they describe.
#
# Output, under --out: both .nupkg files, the manifests directory
# (manifests/<p>/<Publisher>/<Package…>/<version>/) for `winget validate`,
# and winget-installer.env (INSTALLER_URL, INSTALLER_SHA256), which
# publish-packages.sh uses to check the published installer.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
templates="$here/templates"

msi="" version="" base_address="" out="dist/winget"
package_identifier="${WINGET_PACKAGE_IDENTIFIER:-imas.sprout.windows}"

die() { echo "build-winget-nupkg: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
	case "$1" in
		--msi) msi="${2:-}"; shift 2 ;;
		--version) version="${2:-}"; shift 2 ;;
		--package-base-address) base_address="${2:-}"; shift 2 ;;
		--package-identifier) package_identifier="${2:-}"; shift 2 ;;
		--out) out="${2:-}"; shift 2 ;;
		-h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
		*) die "unknown argument: $1" ;;
	esac
done

[[ -n "$msi" && -f "$msi" ]] || die "--msi must name an existing file (got '${msi}')"
[[ -n "$version" ]] || die "--version is required"
[[ -n "$base_address" ]] || die "--package-base-address is required"
[[ "$base_address" == https://* ]] || die "--package-base-address must be https:// (winget requires it)"
# winget: Publisher.Package[.More]; NuGet ids allow the same characters.
[[ "$package_identifier" =~ ^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$ ]] || die "bad --package-identifier '$package_identifier' (want Publisher.Package)"
# winget PackageVersion and NuGet versions are both far looser than this,
# but a tag like v1.2.3 or 1.2.3-rc.1 is all a release produces.
version="${version#v}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]] || die "bad --version '$version' (want semver, e.g. 1.2.3 or 1.2.3-rc.1)"
nuget_version="${version%%+*}" # NuGet ignores build metadata; drop it.

for tool in msiinfo sha256sum zip; do
	command -v "$tool" >/dev/null || die "$tool not found (msiinfo comes from msitools)"
done

msi_property() {
	local v
	v=$(msiinfo export "$msi" Property | tr -d '\r' | awk -F'\t' -v p="$1" '$1 == p { print $2 }')
	[[ -n "$v" ]] || die "MSI property $1 not found in $msi"
	echo "$v"
}

msi_name="$(basename "$msi")"
product_code="$(msi_property ProductCode)"
upgrade_code="$(msi_property UpgradeCode)"
msi_version="$(msi_property ProductVersion)"

installer_id="${package_identifier}.msi"
lc() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
installer_url="${base_address%/}/$(lc "$installer_id")/$(lc "$nuget_version")/$(lc "$installer_id").$(lc "$nuget_version").nupkg"

# Values go into YAML scalars and XML text unquoted or double-quoted; none of
# them should ever contain these characters, so refuse rather than escape.
for v in "$package_identifier" "$version" "$installer_url" "$product_code" "$upgrade_code" "$msi_version" "$msi_name"; do
	[[ "$v" != *[\"\'\<\>\&\\\ ]* ]] || die "refusing to template value with quote/markup/space characters: $v"
done

installer_sha256="" # set once the installer package exists
render() {
	sed -e "s|@PACKAGE_IDENTIFIER@|${package_identifier}|g" \
		-e "s|@INSTALLER_ID@|${installer_id}|g" \
		-e "s|@PACKAGE_VERSION@|${version}|g" \
		-e "s|@NUGET_VERSION@|${nuget_version}|g" \
		-e "s|@MSI_VERSION@|${msi_version}|g" \
		-e "s|@MSI_NAME@|${msi_name}|g" \
		-e "s|@PRODUCT_CODE@|${product_code}|g" \
		-e "s|@UPGRADE_CODE@|${upgrade_code}|g" \
		-e "s|@INSTALLER_URL@|${installer_url}|g" \
		-e "s|@INSTALLER_SHA256@|${installer_sha256}|g" \
		"$1"
}

# opc_parts DIR NUSPEC: the minimal Open Packaging Conventions parts that
# make DIR a package NuGet clients and servers accept.
opc_parts() {
	mkdir -p "$1/_rels"
	cat >"$1/[Content_Types].xml" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml" />
  <Default Extension="nuspec" ContentType="application/octet" />
  <Default Extension="yaml" ContentType="application/octet" />
  <Default Extension="msi" ContentType="application/octet" />
</Types>
EOF
	cat >"$1/_rels/.rels" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Type="http://schemas.microsoft.com/packaging/2010/07/manifest" Target="/$2" Id="R0" />
</Relationships>
EOF
}

# Catch a placeholder added to a template but not to render() above.
check_rendered() {
	local leftover
	if leftover=$(grep -rHo '@[A-Z_0-9]\+@' "$1"); then
		die "unrendered placeholders: $leftover"
	fi
}

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$out"
out="$(cd "$out" && pwd)"

# 1. The installer package: the MSI at the root, where
#    NestedInstallerFiles/RelativeFilePath points.
inst="$stage/installer"
mkdir -p "$inst"
opc_parts "$inst" "${installer_id}.nuspec"
render "$templates/installer.nuspec" >"$inst/${installer_id}.nuspec"
check_rendered "$inst"
cp "$msi" "$inst/$msi_name"
installer_nupkg="$out/${installer_id}.${nuget_version}.nupkg"
rm -f "$installer_nupkg"
(cd "$inst" && zip -q -X -r "$installer_nupkg" '[Content_Types].xml' _rels "${installer_id}.nuspec" "$msi_name")
installer_sha256="$(sha256sum "$installer_nupkg" | awk '{ print toupper($1) }')"

# 2. The manifests, and the package that carries them.
publisher="${package_identifier%%.*}"
package="${package_identifier#*.}"
first="$(lc "${publisher:0:1}")"
rel_manifest_dir="manifests/${first}/${publisher}/${package//./\/}/${version}"

man="$stage/manifests-pkg"
mkdir -p "$man/$rel_manifest_dir"
opc_parts "$man" "${package_identifier}.nuspec"
render "$templates/version.yaml" >"$man/$rel_manifest_dir/${package_identifier}.yaml"
render "$templates/installer.yaml" >"$man/$rel_manifest_dir/${package_identifier}.installer.yaml"
render "$templates/locale.en-US.yaml" >"$man/$rel_manifest_dir/${package_identifier}.locale.en-US.yaml"
render "$templates/package.nuspec" >"$man/${package_identifier}.nuspec"
check_rendered "$man"
manifest_nupkg="$out/${package_identifier}.${nuget_version}.nupkg"
rm -f "$manifest_nupkg"
(cd "$man" && zip -q -X -r "$manifest_nupkg" '[Content_Types].xml' _rels "${package_identifier}.nuspec" manifests)

rm -rf "${out:?}/$rel_manifest_dir"
mkdir -p "$out/$rel_manifest_dir"
cp "$man/$rel_manifest_dir"/*.yaml "$out/$rel_manifest_dir/"

# For publish-packages.sh: check the published installer against these
# before publishing the manifests that point at it.
printf 'INSTALLER_URL=%s\nINSTALLER_SHA256=%s\n' "$installer_url" "$installer_sha256" >"$out/winget-installer.env"

echo "build-winget-nupkg: installer package $installer_nupkg"
echo "build-winget-nupkg:   served at $installer_url"
echo "build-winget-nupkg: manifest package  $manifest_nupkg"
echo "build-winget-nupkg: manifests in $out/$rel_manifest_dir"
