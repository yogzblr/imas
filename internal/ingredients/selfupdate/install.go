package selfupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/yogzblr/imas/internal/cook"
	log "github.com/yogzblr/imas/internal/log"
)

// How a verified package is installed (design doc §2.3): by the OS
// installer, from the local file whose SHA-256 matched the signed
// manifest, so the package manager owns replacing the binary, placing
// files and the service definition. There is no custom swap code.
//
// Restarting onto the new version must not cut off the job's own result,
// so the step that restarts the sprout's service runs postInstallDelay
// after the step returns, by which time cook has reported the result:
//
//   - Linux: dpkg -i / rpm -U / zypper install run to completion inside
//     the step (the packages' postinstall scripts enable the unit but
//     don't restart it), so the step reports the installer's real
//     outcome. Then, after the delay, systemctl --no-block restart
//     imas-sprout.service; systemd stops this process and starts the new
//     binary.
//   - Windows: the MSI stops the imas-sprout service before replacing
//     files and starts it again afterwards (packaging/windows/
//     imas-sprout.wxs), which ends this process, so msiexec can't run
//     inside the step and report back. The step reports that the
//     verified MSI is scheduled; after the delay msiexec /i <file> /qn
//     /norestart is started detached from the service, with a verbose log
//     next to the staged file. A failed MSI upgrade rolls back to the
//     installed version and restarts it. Either way the outcome is what
//     the sprout reports when it reconnects (its version fact), which is
//     what the rollout's health gate checks (§2.3).

// serviceUnit is the systemd unit the packages install
// (packaging/systemd/imas-sprout.service).
const serviceUnit = "imas-sprout.service"

const (
	installTimeout   = 10 * time.Minute
	postInstallDelay = 10 * time.Second
	maxOutputNote    = 2 << 10
)

// Seams for tests. Production code always uses these values.
var (
	// runCommand runs name with args and extra environment and returns
	// its combined output.
	runCommand = func(ctx context.Context, name string, args, env []string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Env = append(os.Environ(), env...)
		return cmd.CombinedOutput()
	}
	// startDetached starts name with args in its own process group,
	// detached from the sprout's service, and doesn't wait for it.
	startDetached = func(name string, args []string) error {
		cmd := exec.Command(name, args...)
		cmd.SysProcAttr = detachedSysProcAttr()
		if err := cmd.Start(); err != nil {
			return err
		}
		return cmd.Process.Release()
	}
	// afterReport runs f once the step's result has had time to be
	// reported.
	afterReport = func(f func()) { time.AfterFunc(postInstallDelay, f) }
)

// installPackage installs the verified package at file for p and
// arranges the restart onto it. It returns the notes for the job.
// msiLog is where msiexec writes its log (Windows only). want is what the
// package's own metadata said it is (verifyPackageIdentity); on Linux the
// package database must report exactly that afterwards (verifyInstalled),
// or the install is a failure and no restart is scheduled.
func installPackage(ctx context.Context, p platform, file, version, msiLog string, want pkgIdentity) ([]fmt.Stringer, error) {
	if p.installer == installMsiexec {
		msiexec := msiexecPath()
		args := []string{"/i", file, "/qn", "/norestart", "/l*v", msiLog}
		afterReport(func() {
			if err := startDetached(msiexec, args); err != nil {
				log.Errorf("selfupdate: starting msiexec for %s: %v", version, err)
			}
		})
		return []fmt.Stringer{cook.Snprintf(
			"%s: msiexec /i %s /qn starts in %s; the MSI stops imas-sprout, upgrades it and starts the new version (log: %s)",
			version, file, postInstallDelay, msiLog)}, nil
	}

	tool, err := findTool(p.installer)
	if err != nil {
		return nil, err
	}
	systemctl, err := findTool("systemctl")
	if err != nil {
		return nil, err
	}
	var args, env []string
	switch p.installer {
	case installDpkg:
		// Keep the admin's (and the sprout's own) edits to conffiles such
		// as /etc/imas/sprout without prompting: there is no terminal.
		// --refuse-downgrade: dpkg's "downgrade" force is on by default
		// (security review M1). dpkg then skips an older package and
		// exits 0, which verifyInstalled catches.
		args = []string{"--force-confdef", "--force-confold", "--refuse-downgrade", "-i", file}
		env = []string{"DEBIAN_FRONTEND=noninteractive"}
	case installRPM:
		args = []string{"-U", file}
	case installZypper:
		// The packages are unsigned (the Ansible role checks the
		// repository metadata's signature instead), and a local file has
		// no repository metadata: what vouches for these bytes is the
		// signed manifest's SHA-256, checked before this runs. No
		// --oldpackage: zypper then refuses an older package (by skipping
		// it, with exit 0, which verifyInstalled catches).
		args = []string{"--non-interactive", "--no-refresh", "install", "--allow-unsigned-rpm", file}
	default:
		return nil, fmt.Errorf("%w: installer %q", ErrUnsupportedPlatform, p.installer)
	}
	ictx, cancel := context.WithTimeout(ctx, installTimeout)
	defer cancel()
	out, err := runCommand(ictx, tool, args, env)
	if err != nil && !zypperSuccess(p.installer, err) {
		return []fmt.Stringer{outputNote(p.installer, out)},
			fmt.Errorf("%w: %s %s: %v", ErrInstallFailed, p.installer, strings.Join(args, " "), err)
	}
	if err := verifyInstalled(ctx, p, want); err != nil {
		return []fmt.Stringer{outputNote(p.installer, out)}, err
	}
	afterReport(func() {
		rctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if out, err := runCommand(rctx, systemctl, []string{"--no-block", "restart", serviceUnit}, nil); err != nil {
			log.Errorf("selfupdate: restarting %s onto %s: %v: %s", serviceUnit, version, err, out)
		}
	})
	return []fmt.Stringer{
		outputNote(p.installer, out),
		cook.Snprintf("%s installed with %s; %s restarts onto it in %s", version, p.installer, serviceUnit, postInstallDelay),
	}, nil
}

// zypperSuccess reports whether err is a zypper exit code that means the
// install succeeded with information attached: 102 (reboot needed) and
// 103 (restart of the package manager needed).
func zypperSuccess(installer string, err error) bool {
	var ee *exec.ExitError
	if installer != installZypper || !errors.As(err, &ee) {
		return false
	}
	code := ee.ExitCode()
	return code == 102 || code == 103
}

// outputNote is the tail of an installer's output, for the job's notes.
func outputNote(installer string, out []byte) fmt.Stringer {
	s := strings.TrimSpace(string(out))
	if len(s) > maxOutputNote {
		s = "..." + s[len(s)-maxOutputNote:]
	}
	if s == "" {
		s = "(no output)"
	}
	return cook.Snprintf("%s: %s", installer, s)
}
