package fleetsign

// Checks on the paths a self_update trusts (security review 2026-10, L3).
// Whoever can write the keyring decides what the sprout installs as root;
// whoever can write the staging directory can swap the package between
// its hash check and the installer (msiexec reads it 10 seconds later).
// A mode check alone is not enough: a directory or file someone else
// owns can be chmod-ed back by its owner, and a symlink can point
// anywhere. So every path is checked with Lstat, never through a link:
//
//   - not a symlink (nor, on Windows, any other reparse point);
//   - on Unix-like systems, owned by the effective uid, and no looser
//     than the mode the caller names (0700 for the staging directories,
//     0600 for the keyring; for the cache directory above them, no
//     group or world write);
//   - on Windows, owned by SYSTEM or Administrators, with no ACE, inherited
//     or explicit, that lets anyone else write (winACLError).
//
// A path that fails is ErrUnsafePath, the refusal code "unsafe_path"
// (packaging/etc/fleet-signing-keys.md, "Refusals").

import (
	"errors"
	"fmt"
	"os"
)

// ErrUnsafePath: a path the update trusts (the keyring, the staging
// directory or one above it) is a symlink, owned by someone else, or
// writable by someone else. The message starts with the refusal code
// unsafe_path.
var ErrUnsafePath = errors.New("unsafe_path: a self_update trust path is a symlink, not owned by the sprout's user, or writable by others")

// Mode limits for CheckPrivateDir, CheckPrivateFile and
// CheckNotWritableByOthers on Unix-like systems.
const (
	privateDirPerm  os.FileMode = 0o700
	privateFilePerm os.FileMode = 0o600
)

// CheckPrivateDir requires path to be a directory, not a symlink, owned by
// the effective user and no looser than 0700 (on Windows: owned by SYSTEM
// or Administrators, writable by nobody else).
func CheckPrivateDir(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("fleetsign: %w", err)
	}
	if !plainDir(fi) {
		return fmt.Errorf("%w: %s is not a directory (a symlink, a reparse point or another file type)", ErrUnsafePath, path)
	}
	return checkOwnerAndMode(path, fi, privateDirPerm, false)
}

// CheckNotWritableByOthers requires path to be a directory, not a symlink,
// owned by the effective user and not group- or world-writable (on
// Windows: as CheckPrivateDir). It is for the directory that holds the
// private staging directories, which may be readable by others.
func CheckNotWritableByOthers(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("fleetsign: %w", err)
	}
	if !plainDir(fi) {
		return fmt.Errorf("%w: %s is not a directory (a symlink, a reparse point or another file type)", ErrUnsafePath, path)
	}
	return checkOwnerAndMode(path, fi, 0o755, false)
}

// plainDir reports whether fi (from Lstat) is a directory and not a
// symlink or, on Windows, a junction or other reparse point, which Lstat
// reports as ModeIrregular (Go 1.23 and later).
func plainDir(fi os.FileInfo) bool {
	return fi.IsDir() && fi.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0
}

// checkFileInfo checks fi, the Lstat of the regular file at path, as
// CheckPrivateFile does.
func checkFileInfo(path string, fi os.FileInfo) error {
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a symlink", ErrUnsafePath, path)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrUnsafePath, path)
	}
	return checkOwnerAndMode(path, fi, privateFilePerm, true)
}

// CheckPrivateFile requires path to be a regular file, not a symlink,
// owned by the effective user and no looser than 0600 (on Windows: owned
// by SYSTEM or Administrators, writable by nobody else).
func CheckPrivateFile(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("fleetsign: %w", err)
	}
	return checkFileInfo(path, fi)
}
