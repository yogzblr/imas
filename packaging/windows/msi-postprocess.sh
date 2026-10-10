#!/usr/bin/env bash
# Post-process the imas-sprout MSI built by wixl (goreleaser msi after-hook).
#
# wixl (msitools) implements only part of the WiX v3 schema, and silently
# drops some of what imas-sprout.wxs asks for. This script adds it back with
# msibuild's SQL interface so the MSI does what the .wxs says:
#
#   1. Component attributes. wixl ignores Permanent and NeverOverwrite, so the
#      config file would be overwritten on upgrade and deleted on uninstall,
#      along with the enrollment state directory. Set the bits directly.
#   2. MsiLockPermissionsEx (MSI 5.0). %ProgramData% lets every local user
#      read (and create files in) its subdirectories by default, and Go's
#      os.WriteFile(…, 0600) sets no ACL on Windows, so the sprout's join
#      token, NKey seed and X25519 key would be readable by any user. Give
#      %ProgramData%\imas a protected DACL: SYSTEM and Administrators only,
#      inherited by everything the installer and the sprout create below it.
#   3. NOT the service's failure actions. An MsiServiceConfigFailureActions
#      row that restarts the service made Windows Installer fail the install
#      (error 1939, "Error: 5" access denied, status 1603) on Windows in the
#      Azure UAT run, for every encoding tried; the same MSI without the row
#      installs. Restart-on-failure (the systemd unit's Restart=always,
#      RestartSec=5) is set after the install instead: by the imas_sprout
#      Ansible role (sc.exe failure) and by `imas-sprout install`
#      (cmd/sprout/internal/winservice).
#   4. The SproutServiceStart component's condition (wixl rejects
#      <Condition> in a component): start the service at the end of the
#      install only on an upgrade (including a same-version one) or with
#      START_SERVICE=1. And add
#      START_SERVICE to SecureCustomProperties (wixl ignores Secure='yes'),
#      so a value given to msiexec reaches the elevated install.
#
# Usage: msi-postprocess.sh path/to/imas-sprout.msi
set -euo pipefail

msi="${1:?usage: $0 path/to/imas-sprout.msi}"
[[ -f "$msi" ]] || { echo "msi-postprocess: no such file: $msi" >&2; exit 1; }
command -v msibuild >/dev/null || { echo "msi-postprocess: msibuild (msitools) not found" >&2; exit 1; }

# msidbComponentAttributes64bit (256) is what wixl already sets for -a x64.
# Keep it if present so this also works for a future 386 build.
attr_base() {
	local a
	a=$(msiinfo export "$msi" Component | tr -d '\r' | awk -F'\t' -v c="$1" '$1 == c { print $4 }')
	[[ -n "$a" ]] || { echo "msi-postprocess: component $1 not found in $msi" >&2; exit 1; }
	echo $(( a & 256 ))
}

readonly PERMANENT=16 NEVER_OVERWRITE=128
cfg=$(( $(attr_base SproutConfig) | PERMANENT | NEVER_OVERWRITE ))
data=$(( $(attr_base SproutDataDir) | PERMANENT ))
cache=$(( $(attr_base SproutCacheDir) | PERMANENT ))

# P: protected (don't inherit %ProgramData%'s ACEs), AI: auto-inherit to
# children; OICI: the ACE applies to files and subdirectories; FA: full
# access; SY: LocalSystem (the service account), BA: BUILTIN\Administrators.
readonly SDDL='D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'

msibuild "$msi" -q "UPDATE \`Component\` SET \`Attributes\` = $cfg WHERE \`Component\` = 'SproutConfig'"
msibuild "$msi" -q "UPDATE \`Component\` SET \`Attributes\` = $data WHERE \`Component\` = 'SproutDataDir'"
msibuild "$msi" -q "UPDATE \`Component\` SET \`Attributes\` = $cache WHERE \`Component\` = 'SproutCacheDir'"

msibuild "$msi" -q "CREATE TABLE \`MsiLockPermissionsEx\` (\`MsiLockPermissionsEx\` CHAR(72) NOT NULL, \`LockObject\` CHAR(72) NOT NULL, \`Table\` CHAR(32) NOT NULL, \`SDDLText\` CHAR(0) NOT NULL, \`Condition\` CHAR(255) PRIMARY KEY \`MsiLockPermissionsEx\`)"
# LockObject for Table=CreateFolder is the CreateFolder row's Directory_.
msibuild "$msi" -q "INSERT INTO \`MsiLockPermissionsEx\` (\`MsiLockPermissionsEx\`, \`LockObject\`, \`Table\`, \`SDDLText\`) VALUES ('SproutDataDirAcl', 'IMASDATADIR', 'CreateFolder', '$SDDL')"

# Keep in sync with the <Condition> in imas-sprout.wxs.
readonly START_CONDITION='WIX_UPGRADE_DETECTED OR WIX_SAME_VERSION_UPGRADE_DETECTED OR START_SERVICE = "1"'
msibuild "$msi" -q "UPDATE \`Component\` SET \`Condition\` = '$START_CONDITION' WHERE \`Component\` = 'SproutServiceStart'"
[[ "$(msiinfo export "$msi" Component | tr -d '\r' | awk -F'\t' '$1 == "SproutServiceStart" { print $5 }')" == "$START_CONDITION" ]] ||
	{ echo "msi-postprocess: component SproutServiceStart not found in $msi" >&2; exit 1; }

secure=$(msiinfo export "$msi" Property | tr -d '\r' | awk -F'\t' '$1 == "SecureCustomProperties" { print $2 }')
if [[ -z "$secure" ]]; then
	msibuild "$msi" -q "INSERT INTO \`Property\` (\`Property\`, \`Value\`) VALUES ('SecureCustomProperties', 'START_SERVICE')"
elif [[ ";$secure;" != *";START_SERVICE;"* ]]; then
	msibuild "$msi" -q "UPDATE \`Property\` SET \`Value\` = '$secure;START_SERVICE' WHERE \`Property\` = 'SecureCustomProperties'"
fi

echo "msi-postprocess: patched $msi"
