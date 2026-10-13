package ingredients

import (
	"fmt"
	"regexp"
	"strconv"
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

// Where a Linux sprout keeps what L5's refusal check reads (internal/config
// paths_other.go): its local job logs, one <jid>.jsonl per job with each
// step's error message, and config.CacheDir, under which self_update stages
// downloads (selfupdate/). And the keyring the package ships
// (.goreleaser.yaml: the repo's gpg-public-key.asc).
const (
	SproutJobLogDir     = "/var/cache/imas/sprout/jobs"
	SproutStageDir      = "/var/cache/imas/sprout/files/provided/selfupdate"
	SproutFleetKeyring  = "/etc/imas/fleet-signing-keys.asc"
	RepoFleetKeyring    = "gpg-public-key.asc"
	SignatureRefusalMsg = "checksums.txt signature does not verify"
)

// AlteredScratchVersion is the version L5 registers with an altered
// checksums.txt: the release's next patch with the pre-release
// "uat.altered" (v0.2.0-rc.4 -> v0.2.1-uat.altered). It is above the
// release under test, so the sprout gets past its downgrade check and the
// refusal can only come from the signature; and it is fixed per release, so
// a re-run in the same environment registers the identical pair again (a
// 200 no-op) rather than a conflicting one.
func AlteredScratchVersion(tag string) (string, error) {
	core, _, err := ParseReleaseTag(tag)
	if err != nil {
		return "", err
	}
	parts := strings.Split(core, ".")
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return "", fmt.Errorf("%q: %v", tag, err)
	}
	return fmt.Sprintf("v%s.%s.%d-uat.altered", parts[0], parts[1], patch+1), nil
}

// RefusalCheckScript reads, on a Linux sprout, what tells a refused self
// update apart from one that installed: JOBLOG (present or absent) and
// SIG_REFUSED (yes when the job's log carries SignatureRefusalMsg),
// DOWNLOADED (yes when it says a package was downloaded), STAGED (entries
// left in the staging directory), the package version (PKG_VERSION) and
// KEYRING_SHA (the SHA-256 of the packaged keyring).
func RefusalCheckScript(jid string) string {
	f := SproutJobLogDir + "/" + jid + ".jsonl"
	return fmt.Sprintf(`want=""
%s
f=%s
if [ -f "$f" ]; then echo "__IMAS_UAT_JOBLOG=present"; else echo "__IMAS_UAT_JOBLOG=absent"; fi
if grep -qF %s "$f" 2>/dev/null; then echo "__IMAS_UAT_SIG_REFUSED=yes"; else echo "__IMAS_UAT_SIG_REFUSED=no"; fi
if grep -qF 'downloaded from' "$f" 2>/dev/null; then echo "__IMAS_UAT_DOWNLOADED=yes"; else echo "__IMAS_UAT_DOWNLOADED=no"; fi
echo "__IMAS_UAT_STAGED=$(ls -A %s 2>/dev/null | wc -l | tr -d ' ')"
echo "__IMAS_UAT_PKG_VERSION=$(installed_version)"
echo "__IMAS_UAT_KEYRING_SHA=$(sha256sum %s 2>/dev/null | cut -d' ' -f1)"
echo "__IMAS_UAT_JOBLOG_TAIL=$(tail -c 400 "$f" 2>/dev/null | tr -d '\n')"`,
		shVersionFns, harness.ShQuote(f), harness.ShQuote(SignatureRefusalMsg), harness.ShQuote(SproutStageDir), harness.ShQuote(SproutFleetKeyring))
}
