//go:build !windows

package selfupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// prodRunCommand is the real runCommand, before any fixture swaps it
// (prodQueryCommand, pkgmeta_test.go, is the same for queryCommand).
var prodRunCommand = runCommand

// fakeZypperScript stands in for zypper: it logs its arguments and, unless
// FAKE_ZYPPER_SKIP is set, records the package as installed for the fake
// rpm. With FAKE_ZYPPER_SKIP it does what zypper does with an older
// package and no --oldpackage: says so, installs nothing and exits 0.
const fakeZypperScript = `#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_PKG_STATE/zypper.log"
if [ -n "$FAKE_ZYPPER_SKIP" ]; then
	echo "Package 'imas-sprout' is already installed in a newer version; skipping."
	echo "Nothing to do."
	exit 0
fi
printf '(none):2.4.1+git-1\n' > "$FAKE_PKG_STATE/installed"
echo "(1/1) Installing: imas-sprout-2.4.1+git-1.x86_64 [done]"
`

// fakeRPMScript stands in for rpm: -qp reads the package header (the
// genuine 2.4.1 package), -q the installed package from the state file.
const fakeRPMScript = `#!/bin/sh
case "$1" in
-qp) printf 'imas-sprout\n(none)\n2.4.1+git\n1\n' ;;
-q) cat "$FAKE_PKG_STATE/installed" ;;
*) exit 2 ;;
esac
`

// TestApply_FakeZypperDowngradeSkip runs real (fake) zypper and rpm
// executables through the production command runners: zypper skipping the
// package and exiting 0, as it does for an older package without
// --oldpackage, fails the step with nothing restarted; zypper installing
// it succeeds. zypper is never given --oldpackage. (Security review
// 2026-10-b, B8: the skip was read from zypper's source, not run.)
func TestApply_FakeZypperDowngradeSkip(t *testing.T) {
	for _, skip := range []bool{true, false} {
		name := "installs"
		if skip {
			name = "skips an older package, exit 0"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			platformCases[2].setup(t, f) // sles: zypper
			state := t.TempDir()
			// A newer build is what the package database holds.
			writeFile(t, filepath.Join(state, "installed"), []byte("(none):2.4.2+git-1\n"), 0o600)
			writeFile(t, filepath.Join(toolDirs[0], "zypper"), []byte(fakeZypperScript), 0o755)
			writeFile(t, filepath.Join(toolDirs[0], "rpm"), []byte(fakeRPMScript), 0o755)
			t.Setenv("FAKE_PKG_STATE", state)
			if skip {
				t.Setenv("FAKE_ZYPPER_SKIP", "1")
			}
			// The real runners for the installer and the metadata reads;
			// systemctl stays recorded, never run.
			setSeam(t, &queryCommand, prodQueryCommand)
			recorded := runCommand
			setSeam(t, &runCommand, func(ctx context.Context, name string, args, env []string) ([]byte, error) {
				if filepath.Base(name) == "systemctl" {
					return recorded(ctx, name, args, env)
				}
				return prodRunCommand(ctx, name, args, env)
			})

			res, err := step(t, target(testTarget)).Apply(context.Background())
			f.runDeferred()
			restarted := false
			for _, c := range f.calls {
				restarted = restarted || filepath.Base(c.name) == "systemctl"
			}
			if skip {
				if !errors.Is(err, ErrInstallFailed) || res.Succeeded {
					t.Fatalf("Apply = %+v, %v; want ErrInstallFailed", res, err)
				}
				if !strings.Contains(err.Error(), "(none):2.4.2+git-1") || !strings.Contains(err.Error(), "skipped") {
					t.Errorf("error %q doesn't say what is installed and that zypper skipped", err)
				}
				if restarted {
					t.Error("restarted after zypper skipped the package")
				}
				if installed.Load() {
					t.Error("a skipped install blocks later updates")
				}
			} else {
				if err != nil || !res.Succeeded {
					t.Fatalf("Apply = %+v, %v", res, err)
				}
				if !restarted {
					t.Error("no restart scheduled after the install")
				}
			}
			log, err := os.ReadFile(filepath.Join(state, "zypper.log"))
			if err != nil {
				t.Fatalf("zypper never ran: %v", err)
			}
			args := strings.TrimSpace(string(log))
			if !strings.HasPrefix(args, "--non-interactive --no-refresh install --allow-unsigned-rpm ") || strings.Contains(args, "--oldpackage") {
				t.Errorf("zypper %s", args)
			}
		})
	}
}
