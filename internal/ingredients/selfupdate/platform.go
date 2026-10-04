package selfupdate

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Package types: the installer a sprout uses for its own package, and the
// file extension a manifest's file_name must carry for it. They match
// saasapi's package_type values (fleet_releases.go).
const (
	pkgDeb = "deb"
	pkgRPM = "rpm"
	pkgMSI = "msi"
)

// Installers.
const (
	installDpkg    = "dpkg"
	installRPM     = "rpm"
	installZypper  = "zypper"
	installMsiexec = "msiexec"
)

// platform is what this sprout asks farmer's manifest endpoint for and how
// it installs the result.
type platform struct {
	// os and arch are the manifest's os and arch: Go's GOOS and GOARCH,
	// the names packaging/helm/stamp-sprout-release.sh registers.
	os, arch string
	// pkgType is deb, rpm or msi.
	pkgType string
	// installer is dpkg, rpm, zypper or msiexec.
	installer string
}

func (p platform) String() string {
	return fmt.Sprintf("%s/%s (%s via %s)", p.os, p.arch, p.pkgType, p.installer)
}

// Seams for tests. Production code always uses these values.
var (
	goos, goarch  = runtime.GOOS, runtime.GOARCH
	osReleasePath = "/etc/os-release"
	// toolDirs are the only directories a Linux installer or systemctl is
	// run from: PATH isn't consulted, so nothing earlier in it can stand
	// in for dpkg while the sprout runs as root.
	toolDirs = []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"}
	// systemdRunDir exists only while systemd is PID 1 (sd_booted(3)). The
	// sprout restarts itself with systemctl after a Linux install, so it
	// refuses to install where that can't work, e.g. in a container.
	systemdRunDir = "/run/systemd/system"
	// systemRoot is %SystemRoot%; msiexec.exe is run from its System32.
	systemRoot = func() string {
		if v := os.Getenv("SystemRoot"); filepath.IsAbs(v) {
			return v
		}
		return `C:\Windows`
	}
)

// detectPlatform works out this sprout's platform: Windows installs an
// MSI with msiexec; Linux installs a deb with dpkg on the Debian family,
// an rpm with zypper on SUSE and with rpm elsewhere (the same split as
// the Ansible role's repo_apt/repo_zypper/repo_yum), deciding from
// /etc/os-release and, failing that, from which package tool exists.
// Anything else (macOS, Alpine's apk) is refused: no such package is
// registered.
func detectPlatform() (platform, error) {
	p := platform{os: goos, arch: goarch}
	switch goos {
	case "windows":
		p.pkgType, p.installer = pkgMSI, installMsiexec
		return p, nil
	case "linux":
	default:
		return p, fmt.Errorf("%w: %s", ErrUnsupportedPlatform, goos)
	}
	switch osFamily(osReleasePath) {
	case "suse":
		p.pkgType, p.installer = pkgRPM, installZypper
	case "debian":
		p.pkgType, p.installer = pkgDeb, installDpkg
	case "redhat":
		p.pkgType, p.installer = pkgRPM, installRPM
	default:
		if _, err := findTool(installDpkg); err == nil {
			p.pkgType, p.installer = pkgDeb, installDpkg
		} else if _, err := findTool(installRPM); err == nil {
			p.pkgType, p.installer = pkgRPM, installRPM
		} else {
			return p, fmt.Errorf("%w: linux with neither dpkg nor rpm", ErrUnsupportedPlatform)
		}
	}
	return p, nil
}

// osFamily returns "suse", "debian", "redhat" or "" from the ID and
// ID_LIKE fields of an os-release(5) file. SUSE is checked first, since
// some SUSE releases list "fedora" or "rhel" in ID_LIKE.
func osFamily(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var ids []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || (k != "ID" && k != "ID_LIKE") {
			continue
		}
		ids = append(ids, strings.Fields(strings.ToLower(strings.Trim(v, `"'`)))...)
	}
	has := func(names ...string) bool {
		for _, id := range ids {
			for _, n := range names {
				if id == n {
					return true
				}
			}
		}
		return false
	}
	isSUSE := false
	for _, id := range ids {
		// opensuse-leap, opensuse-tumbleweed, sles, sled, sle-micro, suse.
		if strings.Contains(id, "suse") || id == "sles" || id == "sled" || strings.HasPrefix(id, "sle-") {
			isSUSE = true
		}
	}
	switch {
	case isSUSE:
		return "suse"
	case has("debian", "ubuntu"):
		return "debian"
	case has("rhel", "fedora", "centos", "rocky", "almalinux", "amzn", "ol"):
		return "redhat"
	}
	return ""
}

// findTool returns the absolute path of a Linux tool from toolDirs.
func findTool(name string) (string, error) {
	for _, dir := range toolDirs {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%w: %s not found in %s", ErrUnsupportedPlatform, name, strings.Join(toolDirs, ", "))
}

// msiexecPath is %SystemRoot%\System32\msiexec.exe, by absolute path so
// nothing in the service's working directory or PATH can stand in for it.
func msiexecPath() string {
	return filepath.Join(systemRoot(), "System32", "msiexec.exe")
}

// preflight checks, before any download, that this platform's install can
// run to completion: the installer and the tools that read package
// metadata exist and, on Linux, the sprout can restart its own service
// afterwards.
func (p platform) preflight() error {
	if p.installer == installMsiexec {
		if _, err := os.Stat(msiexecPath()); err != nil {
			return fmt.Errorf("%w: %s: %v", ErrUnsupportedPlatform, msiexecPath(), err)
		}
		return nil
	}
	if _, err := findTool(p.installer); err != nil {
		return err
	}
	for _, tool := range metadataTools(p) {
		if _, err := findTool(tool); err != nil {
			return err
		}
	}
	if _, err := findTool("systemctl"); err != nil {
		return err
	}
	if fi, err := os.Stat(systemdRunDir); err != nil || !fi.IsDir() {
		return fmt.Errorf("%w: systemd is not running (no %s), so the sprout could not restart onto the new version", ErrUnsupportedPlatform, systemdRunDir)
	}
	return nil
}
