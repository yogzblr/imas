#!/usr/bin/env bash
# The single-quoted $N in this file are awk fields, not shell expansions.
# shellcheck disable=SC2016
# Tests for the Windows packaging, runnable on Linux:
#   - packaging/windows/build-msi.sh (the goreleaser build hook) renders
#     packaging/windows/imas-sprout.wxs and builds it with wixl into an MSI
#     with the imas-sprout service, stop/remove control and the expected
#     directory layout, rejects bad input and unhandled template actions,
#     and leaves no MSI behind when a step fails;
#   - packaging/windows/msi-postprocess.sh sets the attributes and the
#     start condition wixl drops, and adds the ACL and failure-action tables;
#   - packaging/windows/winget/build-winget-nupkg.sh packs the MSI into an
#     installer .nupkg and renders manifests that point at it (URL, hash) and
#     match the MSI (ProductCode), packs those into a second .nupkg, and
#     rejects bad input.
#
# Needs: go, wixl + msitools, zip/unzip, python3. Optional: python3 with
# PyYAML + jsonschema and WINGET_SCHEMA_DIR pointing at winget-cli's
# schemas/JSON/manifests/v1.10.0, to validate the manifests against the
# official schema.
#
# This does not install the MSI: that needs a Windows host. See
# packaging/README.md for the manual Windows checks.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fails=0
pass() { echo "ok   - $*"; }
fail() { echo "FAIL - $*"; fails=$((fails + 1)); }
check() { local desc="$1"; shift; if "$@"; then pass "$desc"; else fail "$desc"; fi; }
# msiinfo export writes IDT: three header lines, CRLF line endings.
table() { msiinfo export "$1" "$2" | tail -n +4 | tr -d '\r'; }

for tool in go wixl msiinfo msibuild msiextract zip unzip python3; do
	command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 2; }
done

# --- MSI -------------------------------------------------------------------
echo "# building imas-sprout.exe (windows/amd64, CGO off)"
(cd "$repo" && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -tags no_self_update -o "$work/imas-sprout.exe" ./cmd/sprout)

bm="$repo/packaging/windows/build-msi.sh"
msi="$work/msi/imas-sprout-1.2.3-rc.1-windows-x64.msi"
"$bm" --binary "$work/imas-sprout.exe" --version 1.2.3-rc.1 --out "$work/msi" --timestamp 1700000000 >/dev/null
check "build-msi.sh builds the MSI" test -s "$msi"
check "out dir holds just the MSI" test "$(ls -A "$work/msi")" = "$(basename "$msi")"
check "MSI mtime is the --timestamp" test "$(stat -c %Y "$msi")" = 1700000000
check "package description carries the full version" bash -c "msiinfo suminfo '$msi' | grep -qx 'Subject: imas sprout 1.2.3-rc.1 (remote control agent)'"
# Windows Server 2016, the oldest supported Windows, has Windows Installer 5.0.
check "needs Windows Installer 5.0, no newer" bash -c "msiinfo suminfo '$msi' | grep -qx 'Version: 500 (1f4)'"
check "installs the fleet signing keyring" \
	awk -F'\t' '$1=="SproutFleetKeyringFile" && $3=="fleet-signing-keys.json" {f=1} END {exit !f}' <<<"$(table "$msi" File)"
check "the MSI's files are the inputs" bash -c "msiextract -C '$work/x' '$msi' >/dev/null &&
	cmp -s '$work/x/imas/imas-sprout.exe' '$work/imas-sprout.exe' &&
	cmp -s '$work/x/imas/sprout' '$repo/packaging/etc/imas-sprout.conf' &&
	cmp -s '$work/x/imas/fleet-signing-keys.json' '$repo/packaging/etc/fleet-signing-keys.json'"
"$bm" --binary "$work/imas-sprout.exe" --version 1.2.3-rc.1 --out "$work/msi2" --timestamp 1700000000 >/dev/null
check "same inputs and --timestamp: identical cabinet" \
	test "$(msiinfo extract "$msi" sprout.cab | sha256sum)" = "$(msiinfo extract "$work/msi2/$(basename "$msi")" sprout.cab | sha256sum)"
"$bm" --binary "$work/imas-sprout.exe" --version 0.0.1-next --out "$work/msi3" >/dev/null
check "snapshot version 0.0.1-next -> ProductVersion 0.0.1" \
	test "$(table "$work/msi3/imas-sprout-0.0.1-next-windows-x64.msi" Property | awk -F'\t' '$1=="ProductVersion"{print $2}')" = "0.0.1"

bm_rejects() { ! "$bm" "$@" >/dev/null 2>&1 && ! compgen -G "$work/rej/*.msi" >/dev/null; }
check "build-msi rejects a leading v" bm_rejects --binary "$work/imas-sprout.exe" --version v1.2.3 --out "$work/rej"
check "build-msi rejects a non-semver version" bm_rejects --binary "$work/imas-sprout.exe" --version 1.2 --out "$work/rej"
check "build-msi rejects XML in the version" bm_rejects --binary "$work/imas-sprout.exe" --version "1.2.3-a'b" --out "$work/rej"
check "build-msi rejects a version past MSI limits" bm_rejects --binary "$work/imas-sprout.exe" --version 256.0.0 --out "$work/rej"
check "build-msi rejects a missing binary" bm_rejects --binary "$work/nope.exe" --version 1.2.3 --out "$work/rej"
check "build-msi rejects a non-PE binary" bm_rejects --binary "$repo/packaging/etc/imas-sprout.conf" --version 1.2.3 --out "$work/rej"
check "build-msi rejects a bad --timestamp" bm_rejects --binary "$work/imas-sprout.exe" --version 1.2.3 --out "$work/rej" --timestamp yesterday
check "build-msi rejects a missing --out" bm_rejects --binary "$work/imas-sprout.exe" --version 1.2.3

# A PATH holding everything but one tool, to check the missing-tool errors.
without() {
	local d="$work/path-without-$1" f
	mkdir -p "$d"
	for f in /usr/local/sbin/* /usr/local/bin/* /usr/sbin/* /usr/bin/* /sbin/* /bin/*; do
		[[ -x "$f" && "$(basename "$f")" != "$1" && ! -e "$d/$(basename "$f")" ]] && ln -s "$f" "$d/"
	done
	echo "$d:$(dirname "$(command -v go)")"
}
for tool in wixl msibuild msiinfo; do
	check "build-msi names a missing $tool" bash -c "PATH='$(without "$tool")' '$bm' --binary '$work/imas-sprout.exe' --version 1.2.3 --out '$work/rej' 2>&1 >/dev/null | grep -q '^build-msi: $tool not found'"
done
check "no MSI left by the rejected runs" bash -c "! compgen -G '$work/rej/*.msi' && ! compgen -G '$work/rej/.*.msi.*'"

# Failing wixl (after writing a partial file) or post-process: no MSI in OUT.
mkdir -p "$work/fake"
printf '#!/bin/sh\nfor a; do case "$prev" in -o) echo partial >"$a";; esac; prev="$a"; done\necho "wixl: boom" >&2\nexit 1\n' >"$work/fake/wixl"
printf '#!/bin/sh\necho "msibuild: boom" >&2\nexit 1\n' >"$work/fake/msibuild"
chmod +x "$work/fake/wixl" "$work/fake/msibuild"
mkdir -p "$work/fake-wixl" "$work/fake-msibuild"
ln -s "$work/fake/wixl" "$work/fake-wixl/wixl"
ln -s "$work/fake/msibuild" "$work/fake-msibuild/msibuild"
check "a failing wixl leaves no MSI and shows its output" bash -c "
	err=\$(PATH='$work/fake-wixl:$PATH' '$bm' --binary '$work/imas-sprout.exe' --version 1.2.3 --out '$work/fail1' 2>&1 >/dev/null) && exit 1
	grep -q 'wixl: boom' <<<\"\$err\" && [ -z \"\$(ls -A '$work/fail1')\" ]"
check "a failing post-process leaves no MSI" bash -c "
	! PATH='$work/fake-msibuild:$PATH' '$bm' --binary '$work/imas-sprout.exe' --version 1.2.3 --out '$work/fail2' >/dev/null 2>&1 &&
	[ -z \"\$(ls -A '$work/fail2')\" ]"

# An unhandled template action in the .wxs fails the render: run a copy of
# the packaging tree with one added.
mkdir -p "$work/tree/packaging/windows" "$work/tree/packaging/etc"
cp "$repo/packaging/windows/build-msi.sh" "$repo/packaging/windows/msi-postprocess.sh" "$work/tree/packaging/windows/"
cp "$repo/packaging/etc/imas-sprout.conf" "$repo/packaging/etc/fleet-signing-keys.json" "$work/tree/packaging/etc/"
sed 's/Manufacturer=.imas.>/Manufacturer="{{ .Env.VENDOR }}">/' "$repo/packaging/windows/imas-sprout.wxs" >"$work/tree/packaging/windows/imas-sprout.wxs"
check "test .wxs has the extra action" grep -q '{{ .Env.VENDOR }}' "$work/tree/packaging/windows/imas-sprout.wxs"
check "build-msi rejects an unhandled template action" bash -c "
	err=\$('$work/tree/packaging/windows/build-msi.sh' --binary '$work/imas-sprout.exe' --version 1.2.3 --out '$work/fail3' 2>&1 >/dev/null) && exit 1
	grep -q 'unhandled template actions.*Env.VENDOR' <<<\"\$err\" && [ -z \"\$(ls -A '$work/fail3')\" ]"


check "ProductVersion is numeric-only" \
	test "$(table "$msi" Property | awk -F'\t' '$1=="ProductVersion"{print $2}')" = "1.2.3"
check "UpgradeCode is the fixed one" \
	test "$(table "$msi" Property | awk -F'\t' '$1=="UpgradeCode"{print $2}')" = "{50B3F4FF-D163-4EDD-84B9-330F966FFF8F}"
check "summary info targets x64" bash -c "msiinfo suminfo '$msi' | grep -q 'Template: x64;1033'"

svc="$(table "$msi" ServiceInstall)"
# ServiceInstall: Name, DisplayName, ServiceType 16 (own process),
# StartType 2 (auto), ErrorControl 1 (normal), StartName LocalSystem.
check "service imas-sprout: own process, auto start, LocalSystem" \
	awk -F'\t' '$2=="imas-sprout" && $4==16 && $5==2 && $6==1 && $9=="LocalSystem" {f=1} END {exit !f}' <<<"$svc"
# ServiceControl Event 162 = stop on install (2) | stop on uninstall (32) |
# delete on uninstall (128); no start bits (1/16), matching rpm/deb.
check "service control: stop both, remove on uninstall, no start" \
	awk -F'\t' '$1=="SproutServiceControl" && $2=="imas-sprout" && $3==162 && $6=="SproutExecutable" {f=1} END {exit !f}' <<<"$(table "$msi" ServiceControl)"
# Event 1 = start on install, on its own component so a condition can gate it.
check "service start on install lives on SproutServiceStart" \
	awk -F'\t' '$1=="SproutServiceStartControl" && $2=="imas-sprout" && $3==1 && $6=="SproutServiceStart" {f=1} END {exit !f}' <<<"$(table "$msi" ServiceControl)"

dirs="$(table "$msi" Directory)"
check "binary dir is ProgramFiles64Folder\\imas" awk -F'\t' '$1=="INSTALLDIR" && $2=="ProgramFiles64Folder" && $3=="imas" {f=1} END {exit !f}' <<<"$dirs"
check "config root is CommonAppDataFolder\\imas" awk -F'\t' '$1=="IMASDATADIR" && $2=="CommonAppDataFolder" && $3=="imas" {f=1} END {exit !f}' <<<"$dirs"
files="$(table "$msi" File)"
check "installs imas-sprout.exe" awk -F'\t' '$3=="imas-sprout.exe" {f=1} END {exit !f}' <<<"$files"
check "installs the config as 'sprout'" awk -F'\t' '$1=="SproutConfigFile" && $3=="sprout" {f=1} END {exit !f}' <<<"$files"
check "MajorUpgrade present (FindRelatedProducts + RemoveExistingProducts)" \
	bash -c "msiinfo export '$msi' InstallExecuteSequence | grep -q RemoveExistingProducts && msiinfo export '$msi' Upgrade | grep -q WIX_UPGRADE_DETECTED"
# Attributes 769 = MigrateFeatures | VersionMinInclusive | VersionMaxInclusive,
# not OnlyDetect (2): a same-version product is found and removed.
check "same-version upgrades (1.2.3-rc.1 -> 1.2.3) replace the old product" \
	awk -F'\t' '$2=="1.2.3" && $3=="1.2.3" && $5==769 && $7=="WIX_SAME_VERSION_UPGRADE_DETECTED" {f=1} END {exit !f}' <<<"$(table "$msi" Upgrade)"

# --- post-process (build-msi.sh ran msi-postprocess.sh) ---------------------
comp="$(table "$msi" Component)"
attr() { awk -F'\t' -v c="$1" '$1==c {print $4}' <<<"$comp"; }
check "config: 64-bit|Permanent|NeverOverwrite (400)" test "$(attr SproutConfig)" = 400
check "data dir: 64-bit|Permanent (272)" test "$(attr SproutDataDir)" = 272
check "cache dir: 64-bit|Permanent (272)" test "$(attr SproutCacheDir)" = 272
check "binary: untouched (256)" test "$(attr SproutExecutable)" = 256
cond() { awk -F'\t' -v c="$1" '$1==c {print $5}' <<<"$comp"; }
check "service start only on upgrade or START_SERVICE=1" \
	test "$(cond SproutServiceStart)" = 'WIX_UPGRADE_DETECTED OR WIX_SAME_VERSION_UPGRADE_DETECTED OR START_SERVICE = "1"'
check "start condition matches the WiX <Condition> in the .wxs" \
	grep -qF "<![CDATA[$(cond SproutServiceStart)]]>" "$repo/packaging/windows/imas-sprout.wxs"
check "START_SERVICE is a secure property; upgrade properties kept" \
	awk -F'\t' '$1=="SecureCustomProperties" && (";"$2";") ~ /;START_SERVICE;/ && (";"$2";") ~ /;WIX_UPGRADE_DETECTED;/ && (";"$2";") ~ /;WIX_SAME_VERSION_UPGRADE_DETECTED;/ {f=1} END {exit !f}' <<<"$(table "$msi" Property)"
check "config root locked to SYSTEM + Administrators" \
	awk -F'\t' '$2=="IMASDATADIR" && $3=="CreateFolder" && $4=="D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" {f=1} END {exit !f}' <<<"$(table "$msi" MsiLockPermissionsEx)"
# The column names are fixed by Windows Installer. A wrong one (SDDL for
# SDDLText) passes every value check above and fails the install on Windows
# with error 2235 and 1603; the first Azure run found it.
check "MsiLockPermissionsEx columns are the ones Windows Installer reads" \
	bash -c "msiinfo export '$msi' MsiLockPermissionsEx | head -n 1 | tr -d '\r' | grep -qx 'MsiLockPermissionsEx	LockObject	Table	SDDLText	Condition'"
check "failure actions: restart x3 after 5s, on the service component" \
	awk -F'\t' '$2=="imas-sprout" && $7=="1[~]1[~]1" && $8=="5000[~]5000[~]5000" && $9=="SproutExecutable" {f=1} END {exit !f}' <<<"$(table "$msi" MsiServiceConfigFailureActions)"
check "MsiConfigureServices sequenced between InstallServices and StartServices" \
	awk -F'\t' '$1=="MsiConfigureServices" && $3>5800 && $3<5900 {f=1} END {exit !f}' <<<"$(table "$msi" InstallExecuteSequence)"
check "post-process rejects a missing file" bash -c "! '$repo/packaging/windows/msi-postprocess.sh' '$work/nope.msi' 2>/dev/null"

# --- winget + nupkg --------------------------------------------------------
wg="$repo/packaging/windows/winget/build-winget-nupkg.sh"
base="https://pkgs.example.invalid/org/imasnget/nuget/v3/flat/"
out="$work/winget"
"$wg" --msi "$msi" --version v1.2.3-rc.1 --package-base-address "$base" --out "$out" >/dev/null
msi_name="$(basename "$msi")"

installer_nupkg="$out/imas.sprout.windows.msi.1.2.3-rc.1.nupkg"
check "installer nupkg written" test -s "$installer_nupkg"
ilist="$(unzip -Z1 "$installer_nupkg")"
for entry in '[Content_Types].xml' '_rels/.rels' 'imas.sprout.windows.msi.nuspec' "$msi_name"; do
	check "installer nupkg contains $entry" grep -qxF "$entry" <<<"$ilist"
done
check "installer nupkg holds the MSI byte for byte" \
	test "$(unzip -p "$installer_nupkg" "$msi_name" | sha256sum)" = "$(sha256sum <"$msi")"
check "installer nuspec id/version" \
	bash -c "unzip -p '$installer_nupkg' imas.sprout.windows.msi.nuspec | grep -q '<id>imas.sprout.windows.msi</id>' && unzip -p '$installer_nupkg' imas.sprout.windows.msi.nuspec | grep -q '<version>1.2.3-rc.1</version>'"

mdir="$out/manifests/i/imas/sprout/windows/1.2.3-rc.1"
check "three manifests in the winget-pkgs layout" \
	test -f "$mdir/imas.sprout.windows.yaml" -a -f "$mdir/imas.sprout.windows.installer.yaml" -a -f "$mdir/imas.sprout.windows.locale.en-US.yaml"
inst="$mdir/imas.sprout.windows.installer.yaml"
url="${base}imas.sprout.windows.msi/1.2.3-rc.1/imas.sprout.windows.msi.1.2.3-rc.1.nupkg"
sha="$(sha256sum "$installer_nupkg" | awk '{print toupper($1)}')"
pc="$(table "$msi" Property | awk -F'\t' '$1=="ProductCode"{print $2}')"
check "PackageIdentifier imas.sprout.windows" grep -qx "PackageIdentifier: imas.sprout.windows" "$inst"
check "InstallerUrl is the installer package's flat-container URL" grep -qxF "    InstallerUrl: $url" "$inst"
check "InstallerSha256 is the installer package's hash" grep -qx "    InstallerSha256: $sha" "$inst"
check "zip installer, nested wix MSI at the package root" \
	bash -c "grep -qx 'InstallerType: zip' '$inst' && grep -qx 'NestedInstallerType: wix' '$inst' && grep -qxF '  - RelativeFilePath: $msi_name' '$inst'"
check "ProductCode matches the MSI" grep -q "ProductCode: \"$pc\"" "$inst"
check "silent switches" grep -q "Silent: /quiet /norestart" "$inst"
check "no unrendered placeholders" bash -c "! grep -rq '@[A-Z_]*@' '$out/manifests'"
check "winget-installer.env records URL and hash" \
	bash -c "grep -qxF 'INSTALLER_URL=$url' '$out/winget-installer.env' && grep -qx 'INSTALLER_SHA256=$sha' '$out/winget-installer.env'"

nupkg="$out/imas.sprout.windows.1.2.3-rc.1.nupkg"
check "manifest nupkg written" test -s "$nupkg"
listing="$(unzip -Z1 "$nupkg")"
for entry in '[Content_Types].xml' '_rels/.rels' 'imas.sprout.windows.nuspec' \
	'manifests/i/imas/sprout/windows/1.2.3-rc.1/imas.sprout.windows.installer.yaml'; do
	check "manifest nupkg contains $entry" grep -qxF "$entry" <<<"$listing"
done
check "manifest nupkg doesn't carry the MSI" bash -c "! grep -q '\.msi\$' <<<'$listing'"
check "packed manifests are the rendered ones" \
	test "$(unzip -p "$nupkg" manifests/i/imas/sprout/windows/1.2.3-rc.1/imas.sprout.windows.installer.yaml | sha256sum)" = "$(sha256sum <"$inst")"
nuspec="$(unzip -p "$nupkg" imas.sprout.windows.nuspec)"
check "manifest nuspec id/version" bash -c "grep -q '<id>imas.sprout.windows</id>' <<<'$nuspec' && grep -q '<version>1.2.3-rc.1</version>' <<<'$nuspec'"
for n in "$nuspec" "$(unzip -p "$installer_nupkg" imas.sprout.windows.msi.nuspec)"; do
	check "nuspec is well-formed XML" python3 -c "import sys, xml.dom.minidom as m; m.parseString(sys.stdin.read())" <<<"$n"
done

"$wg" --msi "$msi" --version 1.2.3 --package-base-address "$base" --package-identifier Contoso.Imas.Sprout --out "$work/wg2" >/dev/null
check "multi-segment identifier maps to nested dirs" test -f "$work/wg2/manifests/c/Contoso/Imas/Sprout/1.2.3/Contoso.Imas.Sprout.installer.yaml"
check "installer URL is lower-cased, as NuGet flat containers are" \
	grep -qF "InstallerUrl: ${base}contoso.imas.sprout.msi/1.2.3/contoso.imas.sprout.msi.1.2.3.nupkg" "$work/wg2/manifests/c/Contoso/Imas/Sprout/1.2.3/Contoso.Imas.Sprout.installer.yaml"

rejects() { ! "$wg" "$@" --out "$work/rej" >/dev/null 2>&1; }
check "rejects an http:// base address" rejects --msi "$msi" --version 1.2.3 --package-base-address "http://x/flat/"
check "rejects a missing base address" rejects --msi "$msi" --version 1.2.3
check "rejects a non-semver version" rejects --msi "$msi" --version latest --package-base-address "$base"
check "rejects a one-segment identifier" rejects --msi "$msi" --version 1.2.3 --package-base-address "$base" --package-identifier Sprout
check "rejects a base address with a quote" rejects --msi "$msi" --version 1.2.3 --package-base-address "https://x/a\"b/"
check "rejects a missing MSI" rejects --msi "$work/nope.msi" --version 1.2.3 --package-base-address "$base"

if [[ -n "${WINGET_SCHEMA_DIR:-}" ]]; then
	check "manifests validate against the winget 1.10.0 schemas" python3 - "$WINGET_SCHEMA_DIR" "$mdir" <<'EOF'
import glob, json, sys
import jsonschema, yaml
schemas = {'version': 'manifest.version.1.10.0.json',
           'installer': 'manifest.installer.1.10.0.json',
           'defaultLocale': 'manifest.defaultLocale.1.10.0.json'}
for f in glob.glob(sys.argv[2] + '/*.yaml'):
    d = yaml.safe_load(open(f))
    jsonschema.Draft7Validator(json.load(open(sys.argv[1] + '/' + schemas[d['ManifestType']]))).validate(d)
EOF
else
	echo "skip - winget schema validation (set WINGET_SCHEMA_DIR)"
fi

echo
if ((fails)); then echo "$fails check(s) failed"; exit 1; fi
echo "all checks passed"
