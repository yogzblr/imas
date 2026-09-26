//go:build linux

package mount

import (
	"os"
)

// fstabPath and procMountsPath are overridable for tests.
var (
	fstabPath      = "/etc/fstab"
	procMountsPath = "/proc/mounts"
)

// readFstab reads and parses the fstab file. A missing file is treated as
// empty rather than an error, since a fresh system may not have one yet.
func readFstab() ([]Line, error) {
	f, err := os.Open(fstabPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	return ParseTable(f)
}

// writeFstab atomically replaces the fstab file with the given lines.
func writeFstab(lines []Line) error {
	tmp := fstabPath + ".imas-tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if err := WriteTable(f, lines); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, fstabPath)
}

// readActiveMounts reads the kernel's live mount table (/proc/mounts).
func readActiveMounts() ([]Line, error) {
	f, err := os.Open(procMountsPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseTable(f)
}
