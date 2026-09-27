//go:build windows

package config

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"

	"github.com/yogzblr/imas/internal/log"
)

// On Windows everything lives under %ProgramData%\imas, the layout the MSI
// (packaging/windows/imas-sprout.wxs) installs:
//
//	%ProgramData%\imas\                              config root (/etc/imas)
//	%ProgramData%\imas\sprout                        config file
//	%ProgramData%\imas\pki\sprout\                   sprout PKI
//	%ProgramData%\imas\cache\sprout\files\provided   cachedir
//	%ProgramData%\imas\cache\sprout\jobs             joblogdir
//	%ProgramData%\imas\state\sprout\handled-jobs     (/var/lib/imas/sprout)
//	%ProgramData%\imas\logs\sprout.log               service log (the sprout creates it)
//
// The Unix paths would otherwise resolve against the current drive, and a
// service's working directory is C:\Windows\System32, so /etc/imas would
// become C:\etc\imas.

// defaultProgramData is used when PROGRAMDATA is unset or not absolute.
const defaultProgramData = `C:\ProgramData`

func programDataDir() string { return programDataFrom(os.LookupEnv) }

// programDataFrom returns the PROGRAMDATA directory as lookup reports it,
// falling back to defaultProgramData. A relative value is ignored rather
// than resolved against the working directory.
func programDataFrom(lookup func(string) (string, bool)) string {
	if v, ok := lookup("PROGRAMDATA"); ok && filepath.IsAbs(v) {
		return filepath.Clean(v)
	}
	return defaultProgramData
}

func imasDataRoot() string { return filepath.Join(programDataDir(), "imas") }

func defaultSystemConfigRoot() string { return imasDataRoot() }

func defaultSproutCacheDir() string {
	return filepath.Join(imasDataRoot(), "cache", "sprout", "files", "provided")
}

func defaultSproutJobLogDir() string {
	return filepath.Join(imasDataRoot(), "cache", "sprout", "jobs")
}

func defaultSproutHandledJobsFile() string {
	return filepath.Join(imasDataRoot(), "state", "sprout", "handled-jobs")
}

// SproutServiceLogDir is where the sprout writes its logs when it runs
// under the SCM, which discards stderr: %ProgramData%\imas\logs, below the
// config root so it gets the same DACL (SecureSproutConfigRoot).
func SproutServiceLogDir() string { return filepath.Join(systemConfigRoot, "logs") }

// sproutConfigRootSDDL is the config root's DACL: full control for SYSTEM
// and Administrators only, inherited by every file and directory below it
// (OICI), and protected (P) from %ProgramData%'s inheritable ACEs, which let
// any local user read. It is the DACL the MSI sets through
// MsiLockPermissionsEx (packaging/windows/msi-postprocess.sh).
const sproutConfigRootSDDL = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// SecureSproutConfigRoot creates the sprout's config root if needed and
// applies sproutConfigRootSDDL to it. os.WriteFile's mode sets no ACL on
// Windows, so the join token, NKey seed and X25519 key written below the
// root are only protected by what they inherit from it. The MSI already
// sets this DACL; doing it here too covers a sprout run without the MSI
// and repairs a DACL that was loosened since, on every start, the same way
// the config file's mode is re-tightened on Unix.
//
// If the directory is owned by anyone but SYSTEM or Administrators (for
// example, pre-created by an unprivileged user, which %ProgramData%'s
// default ACL allows), ownership moves to Administrators: an owner keeps
// READ_CONTROL and WRITE_DAC whatever the DACL says, so it could grant
// itself access back.
func SecureSproutConfigRoot() error {
	return secureDir(systemConfigRoot, sproutConfigRootSDDL)
}

func secureDir(dir, sddl string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("parse SDDL %q: %w", sddl, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("SDDL %q: %w", sddl, err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("set DACL on %s: %w", dir, err)
	}
	cur, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read owner of %s: %w", dir, err)
	}
	owner, _, err := cur.Owner()
	if err != nil {
		return fmt.Errorf("read owner of %s: %w", dir, err)
	}
	if trustedOwner(owner) {
		return nil
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	// Needs WRITE_OWNER, which the DACL just set grants, and Administrators
	// as an owner-capable group in the token: true for LocalSystem and an
	// elevated administrator, so this fails for anyone else.
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil); err != nil {
		return fmt.Errorf("%s is owned by %s, not SYSTEM or Administrators, and taking ownership failed: %w", dir, owner, err)
	}
	log.Warnf("%s was owned by %s; changed its owner to Administrators", dir, owner)
	return nil
}

func trustedOwner(owner *windows.SID) bool {
	return owner != nil && (owner.IsWellKnown(windows.WinLocalSystemSid) ||
		owner.IsWellKnown(windows.WinBuiltinAdministratorsSid))
}
