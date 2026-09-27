#!/usr/bin/env bash
# Render the winget manifests for an imas-sprout MSI and pack them, with the
# MSI, into a .nupkg for the org's private NuGet-backed winget feed.
#
# Usage:
#   build-winget-nupkg.sh --msi dist/imas-sprout-1.2.3-windows-x64.msi \
#                         --version 1.2.3 \
#                         --installer-url https://…/imas-sprout-1.2.3-windows-x64.msi \
#                         [--package-identifier Imas.Sprout] [--out dist/winget]
#
# --installer-url is where winget clients download the MSI from, so it must
# be reachable from managed Windows hosts without credentials.
# InstallerSha256, ProductCode and UpgradeCode are read from the MSI itself
# (msiinfo, from msitools), so the manifests can't drift from the binary.
#
# Output, under --out:
#   manifests/<p>/<Publisher>/<Package>/<version>/<id>{,.installer,.locale.en-US}.yaml
#       (the winget-pkgs layout; `winget validate` / `winget install
#        --manifest` take that directory)
#   <id>.<nugetversion>.nupkg
#       manifests/… as above, plus installer/<msi name>, plus the nuspec.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
templates="$here/templates"

msi="" version="" installer_url="" out="dist/winget"
package_identifier="${WINGET_PACKAGE_IDENTIFIER:-Imas.Sprout}"

die() { echo "build-winget-nupkg: $*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
	case "$1" in
		--msi) msi="${2:-}"; shift 2 ;;
		--version) version="${2:-}"; shift 2 ;;
		--installer-url) installer_url="${2:-}"; shift 2 ;;
		--package-identifier) package_identifier="${2:-}"; shift 2 ;;
		--out) out="${2:-}"; shift 2 ;;
		-h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
		*) die "unknown argument: $1" ;;
	esac
done

[[ -n "$msi" && -f "$msi" ]] || die "--msi must name an existing file (got '${msi}')"
[[ -n "$version" ]] || die "--version is required"
[[ -n "$installer_url" ]] || die "--installer-url is required"
[[ "$installer_url" == https://* ]] || die "--installer-url must be https:// (winget requires it)"
# winget: Publisher.Package segments; NuGet ids allow the same characters.
[[ "$package_identifier" =~ ^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$ ]] || die "bad --package-identifier '$package_identifier' (want Publisher.Package)"
# winget PackageVersion and NuGet versions are both far looser than this,
# but a tag like v1.2.3 or 1.2.3-rc.1 is all a release produces.
version="${version#v}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]] || die "bad --version '$version' (want semver, e.g. 1.2.3 or 1.2.3-rc.1)"
nuget_version="${version%%+*}" # NuGet ignores build metadata; drop it from the file name.

for tool in msiinfo sha256sum zip; do
	command -v "$tool" >/dev/null || die "$tool not found (msiinfo comes from msitools)"
done

msi_property() {
	local v
	v=$(msiinfo export "$msi" Property | awk -F'\t' -v p="$1" '$1 == p { sub(/\r$/, "", $2); print $2 }')
	[[ -n "$v" ]] || die "MSI property $1 not found in $msi"
	echo "$v"
}

product_code="$(msi_property ProductCode)"
upgrade_code="$(msi_property UpgradeCode)"
msi_version="$(msi_property ProductVersion)"
sha256="$(sha256sum "$msi" | awk '{ print toupper($1) }')"

# Values go into YAML scalars and XML text unquoted or double-quoted; none of
# them should ever contain these characters, so refuse rather than escape.
for v in "$package_identifier" "$version" "$installer_url" "$product_code" "$upgrade_code" "$msi_version"; do
	[[ "$v" != *[\"\'\<\>\&\\\ ]* ]] || die "refusing to template value with quote/markup/space characters: $v"
done

render() {
	sed -e "s|@PACKAGE_IDENTIFIER@|${package_identifier}|g" \
		-e "s|@PACKAGE_VERSION@|${version}|g" \
		-e "s|@NUGET_VERSION@|${nuget_version}|g" \
		-e "s|@MSI_VERSION@|${msi_version}|g" \
		-e "s|@PRODUCT_CODE@|${product_code}|g" \
		-e "s|@UPGRADE_CODE@|${upgrade_code}|g" \
		-e "s|@INSTALLER_URL@|${installer_url}|g" \
		-e "s|@INSTALLER_SHA256@|${sha256}|g" \
		"$1"
}

publisher="${package_identifier%%.*}"
package="${package_identifier#*.}"
first="$(printf '%s' "$publisher" | cut -c1 | tr '[:upper:]' '[:lower:]')"
rel_manifest_dir="manifests/${first}/${publisher}/${package//./\/}/${version}"

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

mkdir -p "$stage/$rel_manifest_dir" "$stage/installer" "$stage/_rels"
render "$templates/version.yaml" >"$stage/$rel_manifest_dir/${package_identifier}.yaml"
render "$templates/installer.yaml" >"$stage/$rel_manifest_dir/${package_identifier}.installer.yaml"
render "$templates/locale.en-US.yaml" >"$stage/$rel_manifest_dir/${package_identifier}.locale.en-US.yaml"
render "$templates/package.nuspec" >"$stage/${package_identifier}.nuspec"
# Catch a placeholder added to a template but not to render() above.
if leftover=$(grep -rHo '@[A-Z_0-9]\+@' "$stage"); then
	die "unrendered placeholders: $leftover"
fi
cp "$msi" "$stage/installer/$(basename "$msi")"

# Minimal OPC parts so NuGet clients and servers treat this as a package.
cat >"$stage/[Content_Types].xml" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml" />
  <Default Extension="nuspec" ContentType="application/octet" />
  <Default Extension="yaml" ContentType="application/octet" />
  <Default Extension="msi" ContentType="application/octet" />
</Types>
EOF
cat >"$stage/_rels/.rels" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Type="http://schemas.microsoft.com/packaging/2010/07/manifest" Target="/${package_identifier}.nuspec" Id="R0" />
</Relationships>
EOF

mkdir -p "$out"
out="$(cd "$out" && pwd)"
rm -rf "${out:?}/manifests/${first}/${publisher}/${package//./\/}/${version}"
mkdir -p "$out/$rel_manifest_dir"
cp "$stage/$rel_manifest_dir"/*.yaml "$out/$rel_manifest_dir/"

nupkg="$out/${package_identifier}.${nuget_version}.nupkg"
rm -f "$nupkg"
(cd "$stage" && zip -q -X -r "$nupkg" '[Content_Types].xml' _rels "${package_identifier}.nuspec" manifests installer)

echo "build-winget-nupkg: manifests in $out/$rel_manifest_dir"
echo "build-winget-nupkg: package $nupkg"
