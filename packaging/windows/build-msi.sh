#!/usr/bin/env bash
# Build the imas-sprout MSI with msitools' wixl, on Linux.
#
# GoReleaser OSS runs this as a post-build hook of the sprout-windows-pkg
# build (.goreleaser.yaml); packaging/test/test-windows-packaging.sh runs it
# too, so the release and the tests build the MSI the same way. It does what
# goreleaser-pro's msi pipe used to:
#
#   1. renders the template fields of packaging/windows/imas-sprout.wxs
#      (Major, Minor, Patch, Version, MsiArch, Binary), failing on any
#      template action it does not handle;
#   2. stages a temp directory holding imas-sprout.exe,
#      packaging/etc/imas-sprout.conf and packaging/etc/fleet-signing-keys.json
#      at those relative paths next to the rendered .wxs;
#   3. runs `wixl -a x64` there, then packaging/windows/msi-postprocess.sh on
#      the result (what wixl can't express: component attributes, the start
#      condition, the directory ACL and the service failure actions);
#   4. writes OUT/imas-sprout-VERSION-windows-x64.msi, the name the msi pipe
#      produced, by an atomic rename: on any failure no MSI is left in OUT.
#
# Usage:
#   build-msi.sh --binary PATH --version VERSION --out DIR [--timestamp UNIX]
#
#   --binary     the windows/amd64 imas-sprout executable
#   --version    GoReleaser's Version: no leading v, may carry a prerelease
#                or build suffix (1.2.3, 1.2.3-rc.1). The MSI ProductVersion
#                is MAJOR.MINOR.PATCH; the full version goes in the package
#                description and the file name.
#   --out        directory to write the MSI into (created if missing)
#   --timestamp  unix seconds (GoReleaser's CommitTimestamp) used as the
#                modification time of every staged file and of the MSI.
#
# Reproducibility: with the same inputs and --timestamp, the files inside the
# MSI (and their cabinet dates) are identical, but the MSI is not
# byte-for-byte reproducible: the .wxs asks for a new ProductCode and
# PackageCode on every build (Product/@Id and Package/@Id are '*', which
# MajorUpgrade relies on), and wixl stamps the summary information with the
# build time.
#
# Needs: wixl, msibuild and msiinfo (msitools), python3.
set -euo pipefail

prog="build-msi"
die() { echo "$prog: $*" >&2; exit 1; }
usage() { echo "usage: $0 --binary PATH --version VERSION --out DIR [--timestamp UNIX]" >&2; exit 2; }

binary="" version="" out="" timestamp=""
while (($#)); do
	case "$1" in
	--binary | --version | --out | --timestamp)
		(($# >= 2)) || { echo "$prog: $1 needs a value" >&2; usage; }
		case "$1" in
		--binary) binary="$2" ;;
		--version) version="$2" ;;
		--out) out="$2" ;;
		--timestamp) timestamp="$2" ;;
		esac
		shift 2
		;;
	-h | --help) usage ;;
	*) echo "$prog: unknown argument: $1" >&2; usage ;;
	esac
done
[[ -n "$binary" && -n "$version" && -n "$out" ]] || usage

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
wxs="$here/imas-sprout.wxs"
postprocess="$here/msi-postprocess.sh"

for tool in wixl msibuild msiinfo; do
	command -v "$tool" >/dev/null ||
		die "$tool not found: install msitools and wixl (Debian/Ubuntu: apt-get install wixl msitools)"
done
command -v python3 >/dev/null || die "python3 not found (renders the .wxs template)"

# A semver core plus an optional prerelease/build suffix, in semver's
# character set. That also keeps the version safe to put in the XML and in
# the file name.
[[ "$version" =~ ^v ]] && die "--version takes GoReleaser's Version, without a leading v: $version"
[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]] ||
	die "--version is not a semantic version: $version"
major="${BASH_REMATCH[1]}" minor="${BASH_REMATCH[2]}" patch="${BASH_REMATCH[3]}"
# Windows Installer's ProductVersion limits.
((major <= 255 && minor <= 255 && patch <= 65535)) ||
	die "--version $version does not fit an MSI ProductVersion (major and minor at most 255, patch at most 65535)"

if [[ -n "$timestamp" ]]; then
	[[ "$timestamp" =~ ^[0-9]+$ ]] || die "--timestamp takes unix seconds: $timestamp"
fi

[[ -f "$binary" ]] || die "no such binary: $binary"
[[ "$(head -c 2 "$binary")" == "MZ" ]] || die "not a Windows executable: $binary"
for f in "$wxs" "$postprocess" "$repo/packaging/etc/imas-sprout.conf" "$repo/packaging/etc/fleet-signing-keys.json"; do
	[[ -f "$f" ]] || die "missing $f"
done

mkdir -p "$out"
name="imas-sprout-$version-windows-x64.msi"
work="$(mktemp -d)"
partial=""
cleanup() {
	rm -rf "$work"
	if [[ -n "$partial" ]]; then rm -f "$partial"; fi
}
trap cleanup EXIT

# --- stage -----------------------------------------------------------------
stage="$work/stage"
mkdir -p "$stage/packaging/etc"
cp "$binary" "$stage/imas-sprout.exe"
cp "$repo/packaging/etc/imas-sprout.conf" "$repo/packaging/etc/fleet-signing-keys.json" "$stage/packaging/etc/"

# --- render ----------------------------------------------------------------
# Stands in for the goreleaser template engine on the few actions the .wxs
# uses. Only x64 is built: keep the MsiArch "x64" branch and drop its else
# branch. Runtime.Goos is the build host's, linux, so the Windows-only (WiX
# toolset) blocks go. Anything else left between {{ }} is an error, so a new
# template action in the .wxs fails here instead of reaching wixl.
python3 - "$wxs" "$stage/app.wxs" "$major" "$minor" "$patch" "$version" <<'EOF'
import re, sys

src, dst, major, minor, patch, version = sys.argv[1:]
s = open(src, encoding="windows-1252").read()

def sub_once(pattern, repl, s, what):
    s, n = re.subn(pattern, repl, s, flags=re.S)
    if n != 1:
        sys.exit("build-msi: expected one %s block in the .wxs, found %d" % (what, n))
    return s

s = sub_once(r'\{\{-?\s*if\s+eq\s+\.MsiArch\s+"x64"\s*-?\}\}(.*?)\{\{-?\s*else\s*-?\}\}.*?\{\{-?\s*end\s*-?\}\}',
             r'\1', s, 'if eq .MsiArch "x64"')
s, _ = re.subn(r'\{\{-?\s*if\s+eq\s+\.Runtime\.Goos\s+"windows"\s*-?\}\}.*?\{\{-?\s*end\s*-?\}\}',
               '', s, flags=re.S)
fields = {"Major": major, "Minor": minor, "Patch": patch, "Version": version,
          "MsiArch": "x64", "Binary": "imas-sprout"}
s = re.sub(r'\{\{-?\s*\.(\w+)\s*-?\}\}', lambda m: fields.get(m.group(1), m.group(0)), s)
left = re.findall(r'\{\{.*?\}\}', s, flags=re.S)
if left or "{{" in s or "}}" in s:
    sys.exit("build-msi: unhandled template actions in the .wxs: %s" % (left or "unbalanced {{ }}"))
open(dst, "w", encoding="windows-1252").write(s)
EOF

if [[ -n "$timestamp" ]]; then
	find "$stage" -exec touch -h -d "@$timestamp" {} +
fi

# --- build -----------------------------------------------------------------
# wixl warns (GLib-CRITICAL) about every attribute it ignores, such as
# Permanent and NeverOverwrite; msi-postprocess.sh puts those back. Keep the
# log quiet unless wixl fails.
msi="$work/$name"
if ! (cd "$stage" && wixl -a x64 -o "$msi" app.wxs) >"$work/wixl.log" 2>&1; then
	cat "$work/wixl.log" >&2
	die "wixl failed"
fi
[[ -s "$msi" ]] || { cat "$work/wixl.log" >&2; die "wixl wrote no MSI"; }
"$postprocess" "$msi" >/dev/null

if [[ -n "$timestamp" ]]; then
	touch -d "@$timestamp" "$msi"
fi

# --- publish ---------------------------------------------------------------
# Copy next to the destination, then rename: OUT never holds a partial MSI.
partial="$(mktemp "$out/.$name.XXXXXX")"
cp -p "$msi" "$partial"
chmod 0644 "$partial"
mv -f "$partial" "$out/$name"
partial=""
echo "$prog: wrote $out/$name"
