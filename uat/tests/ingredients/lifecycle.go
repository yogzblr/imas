package ingredients

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/yogzblr/imas/uat/tests/harness"
)

// Environment variables of the lifecycle tier.
const (
	// EnvUpgradeFromTag is the workflow input upgrade_from_tag: the earlier
	// release L4 installs and upgrades from (and L5 updates from). Empty
	// skips L4 and L5 with that reason.
	EnvUpgradeFromTag = "IMAS_UAT_UPGRADE_FROM_TAG"
	// EnvDispatchFlags says the fleet update dispatch flags are on for this
	// run: saasapi with SAASAPI_FLEET_UPDATE_DISPATCH_ENABLED=true and
	// farmer with IMAS_SELF_UPDATE_ENABLED=true. L5 runs only when it is
	// "on" (or true, yes, 1): opt in, UAT only.
	EnvDispatchFlags = "IMAS_UAT_DISPATCH_FLAGS"
)

var releaseTagRe = regexp.MustCompile(`^v([0-9]+\.[0-9]+\.[0-9]+)(?:-(rc\.[0-9]+))?$`)

// ParseReleaseTag splits vX.Y.Z or vX.Y.Z-rc.N into its core and
// pre-release parts.
func ParseReleaseTag(tag string) (core, pre string, err error) {
	m := releaseTagRe.FindStringSubmatch(tag)
	if m == nil {
		return "", "", fmt.Errorf("%q is not a vX.Y.Z or vX.Y.Z-rc.N tag", tag)
	}
	return m[1], m[2], nil
}

// NormalizePackageVersion turns a Linux package version into the form
// a tag is compared with: "~" and "_" become "-", build metadata after
// "+" is dropped (0.1.0~rc.4+git -> 0.1.0-rc.4; the rpm form
// 0.1.0~rc.4+git-1 -> 0.1.0-rc.4).
func NormalizePackageVersion(v string) string {
	v = strings.NewReplacer("~", "-", "_", "-").Replace(strings.TrimSpace(v))
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexByte(v, ':'); i >= 0 { // an epoch
		v = v[i+1:]
	}
	return v
}

var rpmReleaseRe = regexp.MustCompile(`^-[0-9]+$`)

// PackageVersionIs reports whether a Linux package version is the release
// of a tag: equal after NormalizePackageVersion, optionally followed by an
// rpm release number (-1).
func PackageVersionIs(installed, tag string) bool {
	core, pre, err := ParseReleaseTag(tag)
	if err != nil {
		return false
	}
	want := core
	if pre != "" {
		want += "-" + pre
	}
	got := NormalizePackageVersion(installed)
	if got == want {
		return true
	}
	return strings.HasPrefix(got, want) && rpmReleaseRe.MatchString(got[len(want):])
}

// shVersionFns are the shell versions of NormalizePackageVersion and
// PackageVersionIs for the host scripts (want is the normalized tag).
const shVersionFns = `norm() { printf '%s' "$1" | tr '~_' '--' | sed -e 's/+.*//' -e 's/^[0-9]*://'; }
is_release() {
  n=$(norm "$1")
  [ "$n" = "$want" ] && return 0
  case "$n" in "$want"-[0-9]|"$want"-[0-9][0-9]|"$want"-[0-9][0-9][0-9]) return 0 ;; esac
  return 1
}
installed_version() {
  if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='${Version}' imas-sprout 2>/dev/null
  else rpm -q --qf '%{VERSION}-%{RELEASE}' imas-sprout 2>/dev/null; fi
}
available_versions() {
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq >/dev/null 2>&1
    apt-cache madison imas-sprout 2>/dev/null | awk -F'|' '{gsub(/ /, "", $2); print $2}'
  else
    dnf -q makecache >/dev/null 2>&1
    dnf -q --showduplicates list imas-sprout 2>/dev/null | awk '$1 ~ /^imas-sprout\./ {print $2}'
  fi
}
cfg_state() {
  echo "__IMAS_UAT_CFG_SHA_$1=$(sha256sum /etc/imas/sprout 2>/dev/null | cut -d' ' -f1)"
  echo "__IMAS_UAT_SPROUTID_$1=$(sed -n 's/^sproutid:[[:space:]]*//p' /etc/imas/sprout 2>/dev/null | tr -d "\"'" | head -n1)"
}
wait_active() {
  i=0
  while [ $i -lt 30 ]; do
    systemctl is-active --quiet imas-sprout && { echo "__IMAS_UAT_SERVICE=active"; return 0; }
    i=$((i + 1)); sleep 2
  done
  echo "__IMAS_UAT_SERVICE=$(systemctl is-active imas-sprout 2>/dev/null)"
}
`

// DowngradeScript installs the imas-sprout package of an earlier release
// over the installed one with the package manager, from the repository
// the role configured, keeping the config file and the sprout's identity
// under /etc/imas/pki (no package owns it). It prints CUR_VERSION (the
// version installed before, the release under test), OLD_VERSION, and the
// config's state before (CFG_SHA_BEFORE, SPROUTID_BEFORE) and after
// (CFG_SHA_OLD, SPROUTID_OLD). Exit 20: the repository has no package of
// the release; 21: it is the installed one; 22: the package manager failed.
func DowngradeScript(tag string) (string, error) {
	core, pre, err := ParseReleaseTag(tag)
	if err != nil {
		return "", err
	}
	want := core
	if pre != "" {
		want += "-" + pre
	}
	return fmt.Sprintf(`want=%s
%s
cur=$(installed_version)
echo "__IMAS_UAT_CUR_VERSION=$cur"
[ -n "$cur" ] || { echo "imas-sprout is not installed"; exit 23; }
cfg_state BEFORE
old=""
for v in $(available_versions); do
  if is_release "$v"; then old=$v; fi
done
[ -n "$old" ] || { echo "no imas-sprout package of the release in the repository"; available_versions | head -n 20; exit 20; }
echo "__IMAS_UAT_OLD_VERSION=$old"
[ "$old" != "$cur" ] || exit 21
if command -v apt-get >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q --allow-downgrades -o Dpkg::Options::=--force-confold "imas-sprout=$old" || exit 22
else
  dnf -y -q downgrade "imas-sprout-$old" || exit 22
fi
systemctl daemon-reload >/dev/null 2>&1
systemctl restart imas-sprout || exit 22
echo "__IMAS_UAT_NOW_VERSION=$(installed_version)"
cfg_state OLD
wait_active`, harness.ShQuote(want), shVersionFns), nil
}

// UpgradeScript upgrades imas-sprout to an exact package version (the one
// DowngradeScript reported as CUR_VERSION) with the package manager, the
// way an administrator's patching would, without touching the config. It
// prints NEW_VERSION, CFG_SHA_NEW, SPROUTID_NEW and SERVICE. Exit 22: the
// package manager failed.
func UpgradeScript(version string) string {
	return fmt.Sprintf(`want=""
%s
v=%s
if command -v apt-get >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q -o Dpkg::Options::=--force-confold "imas-sprout=$v" || exit 22
else
  dnf -y -q upgrade "imas-sprout-$v" || exit 22
fi
echo "__IMAS_UAT_NEW_VERSION=$(installed_version)"
cfg_state NEW
wait_active`, shVersionFns, harness.ShQuote(version))
}

// FlagOn reads a yes/no environment value.
func FlagOn(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "on", "true", "yes":
		return true
	}
	return false
}
