#!/usr/bin/env bash
# The single-quoted $N in this file are awk fields, not shell expansions.
# shellcheck disable=SC2016
# Tests for the Windows packaging, runnable on Linux:
#   - packaging/windows/imas-sprout.wxs builds with wixl (as goreleaser's msi
#     pipe does) into an MSI with the imas-sprout service, stop/remove
#     control and the expected directory layout;
#   - packaging/windows/msi-postprocess.sh sets the attributes wixl drops and
#     adds the ACL and failure-action tables;
#   - packaging/windows/winget/build-winget-nupkg.sh renders manifests that
#     match the MSI (hash, ProductCode) and packs a well-formed .nupkg, and
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

for tool in go wixl msiinfo msibuild zip unzip python3; do
	command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 2; }
done

# --- MSI -------------------------------------------------------------------
echo "# building imas-sprout.exe (windows/amd64, CGO off)"
(cd "$repo" && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -tags no_self_update -o "$work/imas-sprout.exe" ./cmd/sprout)
mkdir -p "$work/packaging/etc"
cp "$repo/packaging/etc/imas-sprout.conf" "$work/packaging/etc/"

# Stand-in for goreleaser's templating of the few fields the .wxs uses.
python3 - "$repo/packaging/windows/imas-sprout.wxs" "$work/app.wxs" <<'EOF'
import re, sys
s = open(sys.argv[1]).read()
s = s.replace('{{ if eq .MsiArch "x64" }}', '')
s = re.sub(r'\{\{ else \}\}.*?\{\{ end \}\}', '', s, flags=re.S)
for k, v in {'{{ .Major }}': '1', '{{ .Minor }}': '2', '{{ .Patch }}': '3',
             '{{ .Version }}': '1.2.3-rc.1', '{{ .MsiArch }}': 'x64',
             '{{ .Binary }}': 'imas-sprout'}.items():
    s = s.replace(k, v)
left = re.findall(r'\{\{.*?\}\}', s)
if left:
    sys.exit('unhandled template actions in .wxs: %s' % left)
open(sys.argv[2], 'w').write(s)
EOF

msi="$work/imas-sprout-1.2.3-rc.1-windows-x64.msi"
(cd "$work" && wixl -a x64 -o "$msi" app.wxs 2>/dev/null)
check "wixl builds the MSI" test -s "$msi"

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
	awk -F'\t' '$2=="imas-sprout" && $3==162 {f=1} END {exit !f}' <<<"$(table "$msi" ServiceControl)"

dirs="$(table "$msi" Directory)"
check "binary dir is ProgramFiles64Folder\\imas" awk -F'\t' '$1=="INSTALLDIR" && $2=="ProgramFiles64Folder" && $3=="imas" {f=1} END {exit !f}' <<<"$dirs"
check "config root is CommonAppDataFolder\\imas" awk -F'\t' '$1=="IMASDATADIR" && $2=="CommonAppDataFolder" && $3=="imas" {f=1} END {exit !f}' <<<"$dirs"
files="$(table "$msi" File)"
check "installs imas-sprout.exe" awk -F'\t' '$3=="imas-sprout.exe" {f=1} END {exit !f}' <<<"$files"
check "installs the config as 'sprout'" awk -F'\t' '$1=="SproutConfigFile" && $3=="sprout" {f=1} END {exit !f}' <<<"$files"
check "MajorUpgrade present (FindRelatedProducts + RemoveExistingProducts)" \
	bash -c "msiinfo export '$msi' InstallExecuteSequence | grep -q RemoveExistingProducts && msiinfo export '$msi' Upgrade | grep -q WIX_UPGRADE_DETECTED"

# --- post-process ----------------------------------------------------------
"$repo/packaging/windows/msi-postprocess.sh" "$msi" >/dev/null
comp="$(table "$msi" Component)"
attr() { awk -F'\t' -v c="$1" '$1==c {print $4}' <<<"$comp"; }
check "config: 64-bit|Permanent|NeverOverwrite (400)" test "$(attr SproutConfig)" = 400
check "data dir: 64-bit|Permanent (272)" test "$(attr SproutDataDir)" = 272
check "cache dir: 64-bit|Permanent (272)" test "$(attr SproutCacheDir)" = 272
check "binary: untouched (256)" test "$(attr SproutExecutable)" = 256
check "config root locked to SYSTEM + Administrators" \
	awk -F'\t' '$2=="IMASDATADIR" && $3=="CreateFolder" && $4=="D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" {f=1} END {exit !f}' <<<"$(table "$msi" MsiLockPermissionsEx)"
check "failure actions: restart x3 after 5s, on the service component" \
	awk -F'\t' '$2=="imas-sprout" && $7=="1[~]1[~]1" && $8=="5000[~]5000[~]5000" && $9=="SproutExecutable" {f=1} END {exit !f}' <<<"$(table "$msi" MsiServiceConfigFailureActions)"
check "MsiConfigureServices sequenced between InstallServices and StartServices" \
	awk -F'\t' '$1=="MsiConfigureServices" && $3>5800 && $3<5900 {f=1} END {exit !f}' <<<"$(table "$msi" InstallExecuteSequence)"
check "post-process rejects a missing file" bash -c "! '$repo/packaging/windows/msi-postprocess.sh' '$work/nope.msi' 2>/dev/null"

# --- winget + nupkg --------------------------------------------------------
wg="$repo/packaging/windows/winget/build-winget-nupkg.sh"
url="https://example.invalid/releases/v1.2.3-rc.1/$(basename "$msi")"
out="$work/winget"
"$wg" --msi "$msi" --version v1.2.3-rc.1 --installer-url "$url" --out "$out" >/dev/null
mdir="$out/manifests/i/Imas/Sprout/1.2.3-rc.1"
check "three manifests in the winget-pkgs layout" \
	test -f "$mdir/Imas.Sprout.yaml" -a -f "$mdir/Imas.Sprout.installer.yaml" -a -f "$mdir/Imas.Sprout.locale.en-US.yaml"
inst="$mdir/Imas.Sprout.installer.yaml"
sha="$(sha256sum "$msi" | awk '{print toupper($1)}')"
pc="$(table "$msi" Property | awk -F'\t' '$1=="ProductCode"{print $2}')"
check "InstallerSha256 matches the MSI" grep -q "InstallerSha256: $sha" "$inst"
check "ProductCode matches the MSI" grep -q "ProductCode: \"$pc\"" "$inst"
check "InstallerUrl as given" grep -qF "InstallerUrl: $url" "$inst"
check "silent switches" grep -q "Silent: /quiet /norestart" "$inst"
check "no unrendered placeholders" bash -c "! grep -rq '@[A-Z_]*@' '$out/manifests'"

nupkg="$out/Imas.Sprout.1.2.3-rc.1.nupkg"
check "nupkg written" test -s "$nupkg"
listing="$(unzip -Z1 "$nupkg")"
for entry in '[Content_Types].xml' '_rels/.rels' 'Imas.Sprout.nuspec' \
	'manifests/i/Imas/Sprout/1.2.3-rc.1/Imas.Sprout.installer.yaml' "installer/$(basename "$msi")"; do
	check "nupkg contains $entry" grep -qxF "$entry" <<<"$listing"
done
nuspec="$(unzip -p "$nupkg" Imas.Sprout.nuspec)"
check "nuspec id/version" bash -c "grep -q '<id>Imas.Sprout</id>' <<<'$nuspec' && grep -q '<version>1.2.3-rc.1</version>' <<<'$nuspec'"
check "nuspec is well-formed XML" python3 -c "import sys, xml.dom.minidom as m; m.parseString(sys.stdin.read())" <<<"$nuspec"

"$wg" --msi "$msi" --version 1.2.3 --installer-url "$url" --package-identifier Contoso.Imas.Sprout --out "$work/wg2" >/dev/null
check "multi-segment identifier maps to nested dirs" test -f "$work/wg2/manifests/c/Contoso/Imas/Sprout/1.2.3/Contoso.Imas.Sprout.installer.yaml"

rejects() { ! "$wg" "$@" --out "$work/rej" >/dev/null 2>&1; }
check "rejects http:// installer URL" rejects --msi "$msi" --version 1.2.3 --installer-url "http://x/y.msi"
check "rejects a non-semver version" rejects --msi "$msi" --version latest --installer-url "$url"
check "rejects a one-segment identifier" rejects --msi "$msi" --version 1.2.3 --installer-url "$url" --package-identifier Sprout
check "rejects a URL with a quote" rejects --msi "$msi" --version 1.2.3 --installer-url "https://x/a\"b.msi"
check "rejects a missing MSI" rejects --msi "$work/nope.msi" --version 1.2.3 --installer-url "$url"

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
