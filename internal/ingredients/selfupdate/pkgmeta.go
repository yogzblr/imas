package selfupdate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"golang.org/x/mod/semver"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/fleetsign"
)

// Binding the package to the signed manifest (security review 2026-10,
// M1). The manifest signs a version and a SHA-256, and the repository's
// index is searched for that hash (repo.go), but the hash alone says
// nothing about which package the bytes are: a signed row for v3.0.0 can
// carry the checksum of the genuine, older imas-sprout_2.0.0 .deb that the
// repository still holds (or of any other package in a general-purpose
// mirror). So, after the hash check and before the installer runs, the
// sprout reads the package's own metadata with the platform's tools and
// requires:
//
//   - the name: imas-sprout (deb Package, rpm NAME); for an MSI, the
//     ProductName "imas sprout" and the UpgradeCode every imas-sprout MSI
//     carries (packaging/windows/imas-sprout.wxs);
//   - the version: equal to the manifest's, compared canonically
//     (packageSemver below).
//
// Then the installer itself refuses downgrades too: dpkg gets
// --refuse-downgrade, rpm -U refuses an older package by default, zypper
// refuses one unless --oldpackage is passed (it is not), and the MSI's
// MajorUpgrade has a DowngradeErrorMessage. dpkg and zypper refuse by
// skipping the package and exiting 0, so on Linux the version the package
// database reports after the install is checked as well
// (verifyInstalled): an install that left anything but this package's
// exact version installed is a failure, and no restart is scheduled.
//
// How versions are compared. Every package GoReleaser builds carries the
// literal build metadata "git" (.goreleaser.yaml, version_metadata: git),
// and nfpm writes a semver prerelease with "~" so that it sorts before the
// release:
//
//	tag      deb Version     rpm VERSION     MSI ProductVersion
//	v2.4.1   2.4.1+git       2.4.1+git       2.4.1
//	v2.5.0-rc.1  2.5.0~rc.1+git  2.5.0~rc.1+git  2.5.0
//
// (nfpm also replaces "-" inside an rpm prerelease with "_".) packageSemver
// maps a package version back to the canonical semver it was built from:
// "~<pre>" becomes "-<pre>", "+<metadata>" is dropped (semver ignores build
// metadata for ordering, as dpkg and rpm effectively do here), and an rpm
// RELEASE or a deb revision is ignored. Anything else — an epoch, a
// version that is not X.Y.Z, a non-canonical result — is refused rather
// than guessed at. The result must equal the manifest's version exactly.
//
// An MSI ProductVersion is numeric only (prerelease suffixes are dropped
// when the MSI is built), so for an MSI only MAJOR.MINOR.PATCH can be
// compared: an MSI of v2.5.0-rc.1 and one of v2.5.0 both say 2.5.0. That
// residual gap is recorded in docs/BUILD-STATUS.md (Open item 4).

const (
	// sproutPackageName is the deb Package and rpm NAME of every sprout
	// package (.goreleaser.yaml, nfpms[].package_name).
	sproutPackageName = "imas-sprout"
	// msiProductName and msiUpgradeCode identify the sprout MSI
	// (packaging/windows/imas-sprout.wxs). The UpgradeCode never changes.
	msiProductName = "imas sprout"
	msiUpgradeCode = "{50B3F4FF-D163-4EDD-84B9-330F966FFF8F}"

	// Tools that read package metadata, from toolDirs like the installers.
	toolDpkgDeb   = "dpkg-deb"
	toolDpkgQuery = "dpkg-query"
	toolRPM       = "rpm"

	queryTimeout   = time.Minute
	maxQueryOutput = 64 << 10
)

// ErrPackageMismatch: the package's own metadata does not name
// imas-sprout at the signed manifest's version.
var ErrPackageMismatch = errors.New("selfupdate: the package's own metadata does not match the signed manifest")

// Seams for tests. Production code always uses these values.
var (
	// queryCommand runs a read-only package tool and returns its standard
	// output; standard error (warnings) is only quoted in an error. The C
	// locale keeps the output parseable.
	queryCommand = func(ctx context.Context, name string, args []string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Env = append(os.Environ(), "LC_ALL=C")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			msg := strings.TrimSpace(stderr.String())
			if len(msg) > 512 {
				msg = msg[:512] + "..."
			}
			return out, fmt.Errorf("%s: %w: %s", name, err, msg)
		}
		return out, nil
	}
	// msiProperties reads the named properties from the MSI database at
	// file (msi_windows.go; refused on other systems).
	msiProperties = readMSIProperties
)

// pkgIdentity is what a package says it is. For rpm, epoch and release
// are carried too, so the installed package can be compared exactly.
type pkgIdentity struct {
	name    string
	version string // deb Version, rpm VERSION, MSI ProductVersion: as the package states it
	epoch   string // rpm only: %{EPOCH}, "(none)" when unset
	release string // rpm only: %{RELEASE}
}

func (id pkgIdentity) String() string {
	if id.release != "" {
		return id.name + " " + id.version + "-" + id.release
	}
	return id.name + " " + id.version
}

// installedForm is the identity as the package database reports it after
// an install: for rpm epoch, version and release; for deb the Version.
func (id pkgIdentity) installedForm() string {
	if id.release != "" || id.epoch != "" {
		return id.epoch + ":" + id.version + "-" + id.release
	}
	return id.version
}

// metadataTools are the tools readPackageIdentity and verifyInstalled run
// for p, checked by preflight.
func metadataTools(p platform) []string {
	switch p.installer {
	case installDpkg:
		return []string{toolDpkgDeb, toolDpkgQuery}
	case installRPM, installZypper:
		return []string{toolRPM}
	}
	return nil
}

// query runs tool (from toolDirs) with args and returns its output,
// bounded in time and size.
func query(ctx context.Context, tool string, args ...string) (string, error) {
	path, err := findTool(tool)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	out, err := queryCommand(ctx, path, args)
	if err != nil {
		return "", err
	}
	if len(out) > maxQueryOutput {
		return "", fmt.Errorf("selfupdate: %s printed more than %d bytes", tool, maxQueryOutput)
	}
	return string(out), nil
}

// readPackageIdentity reads the name and version file states for itself.
func readPackageIdentity(ctx context.Context, p platform, file string) (pkgIdentity, error) {
	switch p.pkgType {
	case pkgDeb:
		out, err := query(ctx, toolDpkgDeb, "-f", file, "Package", "Version")
		if err != nil {
			return pkgIdentity{}, fmt.Errorf("selfupdate: reading the package's control fields: %w", err)
		}
		fields, err := controlFields(out, "Package", "Version")
		if err != nil {
			return pkgIdentity{}, err
		}
		return pkgIdentity{name: fields["Package"], version: fields["Version"]}, nil
	case pkgRPM:
		out, err := query(ctx, toolRPM, "-qp", "--qf", rpmQueryFormat, file)
		if err != nil {
			return pkgIdentity{}, fmt.Errorf("selfupdate: reading the package header: %w", err)
		}
		f, err := rpmFields(out)
		if err != nil {
			return pkgIdentity{}, err
		}
		return pkgIdentity{name: f[0], epoch: f[1], version: f[2], release: f[3]}, nil
	case pkgMSI:
		props, err := msiProperties(file, []string{"ProductName", "ProductVersion", "UpgradeCode"})
		if err != nil {
			return pkgIdentity{}, fmt.Errorf("selfupdate: reading the MSI's Property table: %w", err)
		}
		if !strings.EqualFold(props["UpgradeCode"], msiUpgradeCode) {
			return pkgIdentity{}, fmt.Errorf("%w: the MSI's UpgradeCode is %q, not imas-sprout's %s", ErrPackageMismatch, props["UpgradeCode"], msiUpgradeCode)
		}
		name := props["ProductName"]
		if name == msiProductName {
			name = sproutPackageName
		}
		return pkgIdentity{name: name, version: props["ProductVersion"]}, nil
	}
	return pkgIdentity{}, fmt.Errorf("%w: package type %q", ErrUnsupportedPlatform, p.pkgType)
}

// rpmQueryFormat prints the four header fields an rpm is identified by,
// one per line. None of them can contain a newline.
const rpmQueryFormat = `%{NAME}\n%{EPOCH}\n%{VERSION}\n%{RELEASE}\n`

// rpmInstalledFormat is the same for the installed package, without the
// name the query already names.
const rpmInstalledFormat = `%{EPOCH}:%{VERSION}-%{RELEASE}\n`

func rpmFields(out string) ([]string, error) {
	f := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(f) != 4 {
		return nil, fmt.Errorf("%w: rpm printed %d header lines, want 4", ErrPackageMismatch, len(f))
	}
	return f, nil
}

// controlFields parses dpkg-deb -f's "Name: value" lines and returns
// exactly the named fields, each present once and on one line.
func controlFields(out string, names ...string) (map[string]string, error) {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	got := map[string]string{}
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			return nil, fmt.Errorf("%w: a multi-line control field", ErrPackageMismatch)
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok || !want[k] {
			return nil, fmt.Errorf("%w: unexpected control output %q", ErrPackageMismatch, line)
		}
		if _, dup := got[k]; dup {
			return nil, fmt.Errorf("%w: control field %s given twice", ErrPackageMismatch, k)
		}
		got[k] = strings.TrimSpace(v)
	}
	for _, n := range names {
		if got[n] == "" {
			return nil, fmt.Errorf("%w: the package has no %s", ErrPackageMismatch, n)
		}
	}
	return got, nil
}

var (
	// reDebVersion: X.Y.Z, optionally ~prerelease, +metadata and a
	// -revision. No epoch (a colon): none of the sprout's packages has
	// one, and an epoch outranks every version number in dpkg's ordering.
	reDebVersion = regexp.MustCompile(`^(\d+\.\d+\.\d+)(?:~([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.~]+))?(?:-([0-9A-Za-z.+~]+))?$`)
	// reRPMVersion: X.Y.Z, optionally ~prerelease (nfpm writes its "-" as
	// "_") and +metadata. The RELEASE is a separate header field.
	reRPMVersion = regexp.MustCompile(`^(\d+\.\d+\.\d+)(?:~([0-9A-Za-z._]+))?(?:\+([0-9A-Za-z._~]+))?$`)
	// reMSIVersion: a ProductVersion as the sprout MSI is built with it.
	reMSIVersion = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
)

// packageSemver returns the canonical semver ("v2.5.0-rc.1") a package
// version of pkgType was built from, or an error if it isn't one the
// sprout's packaging produces (see the comment at the top of this file).
// For an MSI it is only "vMAJOR.MINOR.PATCH".
func packageSemver(pkgType string, id pkgIdentity) (string, error) {
	var core, pre string
	switch pkgType {
	case pkgDeb:
		m := reDebVersion.FindStringSubmatch(id.version)
		if m == nil {
			return "", fmt.Errorf("%w: deb version %q is not <X.Y.Z>[~<prerelease>][+<metadata>]", ErrPackageMismatch, id.version)
		}
		core, pre = m[1], m[2]
	case pkgRPM:
		if id.epoch != "(none)" && id.epoch != "0" {
			return "", fmt.Errorf("%w: rpm epoch %q (the sprout's packages have none)", ErrPackageMismatch, id.epoch)
		}
		m := reRPMVersion.FindStringSubmatch(id.version)
		if m == nil {
			return "", fmt.Errorf("%w: rpm version %q is not <X.Y.Z>[~<prerelease>][+<metadata>]", ErrPackageMismatch, id.version)
		}
		core, pre = m[1], strings.ReplaceAll(m[2], "_", "-")
	case pkgMSI:
		if !reMSIVersion.MatchString(id.version) {
			return "", fmt.Errorf("%w: MSI ProductVersion %q is not <X.Y.Z>", ErrPackageMismatch, id.version)
		}
		core = id.version
	default:
		return "", fmt.Errorf("%w: package type %q", ErrUnsupportedPlatform, pkgType)
	}
	v := "v" + core
	if pre != "" {
		v += "-" + pre
	}
	if !semver.IsValid(v) || semver.Canonical(v) != v {
		return "", fmt.Errorf("%w: package version %q is not a canonical semver version", ErrPackageMismatch, id.version)
	}
	return v, nil
}

// manifestComparable is the part of the manifest's version a package of
// pkgType can state: all of it, except for an MSI (MAJOR.MINOR.PATCH).
func manifestComparable(pkgType, version string) string {
	if pkgType == pkgMSI {
		c := semver.Canonical(version)
		if i := strings.IndexByte(c, '-'); i >= 0 {
			return c[:i]
		}
		return c
	}
	return version
}

// verifyPackageIdentity requires the package at file, whose bytes already
// matched the signed checksum, to be imas-sprout at m's version. It
// returns the identity (for the post-install check) and a note for the
// job.
func verifyPackageIdentity(ctx context.Context, p platform, file string, m fleetsign.Manifest) (pkgIdentity, fmt.Stringer, error) {
	id, err := readPackageIdentity(ctx, p, file)
	if err != nil {
		return id, nil, err
	}
	if id.name != sproutPackageName {
		return id, nil, fmt.Errorf("%w: the package is %q, not %s", ErrPackageMismatch, id.name, sproutPackageName)
	}
	v, err := packageSemver(p.pkgType, id)
	if err != nil {
		return id, nil, err
	}
	if want := manifestComparable(p.pkgType, m.Version); v != want {
		return id, nil, fmt.Errorf("%w: the package is %s %s (%s), but the signed manifest is for %s",
			ErrPackageMismatch, sproutPackageName, id.version, v, m.Version)
	}
	return id, cook.Snprintf("package metadata: %s, version %s (%s) matches the signed manifest", sproutPackageName, id.version, v), nil
}

// verifyInstalled checks, after a Linux installer exited successfully,
// that the package database now holds exactly want. dpkg
// --refuse-downgrade and zypper both refuse an older package by skipping
// it and exiting 0.
func verifyInstalled(ctx context.Context, p platform, want pkgIdentity) error {
	var got string
	switch p.installer {
	case installDpkg:
		out, err := query(ctx, toolDpkgQuery, "--show", "--showformat=${Status}\n${Version}\n", sproutPackageName)
		if err != nil {
			return fmt.Errorf("%w: reading the installed version: %v", ErrInstallFailed, err)
		}
		status, version, _ := strings.Cut(strings.TrimSuffix(out, "\n"), "\n")
		if status != "install ok installed" {
			return fmt.Errorf("%w: %s is %q after %s, not installed", ErrInstallFailed, sproutPackageName, status, p.installer)
		}
		got = version
	case installRPM, installZypper:
		out, err := query(ctx, toolRPM, "-q", "--qf", rpmInstalledFormat, sproutPackageName)
		if err != nil {
			return fmt.Errorf("%w: reading the installed version: %v", ErrInstallFailed, err)
		}
		got = strings.TrimSuffix(out, "\n")
	default:
		return nil
	}
	if got != want.installedForm() {
		return fmt.Errorf("%w: %s exited successfully, but %s is at %q, not %q (refused as a downgrade, or skipped)",
			ErrInstallFailed, p.installer, sproutPackageName, got, want.installedForm())
	}
	return nil
}
