//go:build linux

package mount

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/yogzblr/imas/internal/cook"
)

var mkdirAll = os.MkdirAll

func (m Mount) mounted(ctx context.Context, test bool) (cook.Result, error) {
	var result cook.Result

	name := stringParam(m.params, "name")
	device := stringParam(m.params, "device")
	fstype := stringParam(m.params, "fstype")
	opts := stringSliceParam(m.params, "opts")
	if len(opts) == 0 {
		opts = []string{"defaults"}
	}
	dump := intParam(m.params, "dump", 0)
	pass := intParam(m.params, "pass", 0)
	persist := boolParam(m.params, "persist", true)
	makedirs := boolParam(m.params, "makedirs", true)
	forceRemount := boolParam(m.params, "force_remount", false)

	active, err := readActiveMounts()
	if err != nil {
		result.Failed = true
		return result, fmt.Errorf("failed to read active mounts: %w", err)
	}

	existing := FindByMountPoint(active, name)
	conflict := existing != nil && (existing.Device != device || existing.FSType != fstype)

	if conflict && !forceRemount {
		result.Failed = true
		return result, fmt.Errorf(
			"%s is already mounted with device %q (fstype %q); refusing to remount over it (set force_remount to override)",
			name, existing.Device, existing.FSType)
	}
	needsMount := existing == nil || conflict

	var didMount bool
	switch {
	case !needsMount:
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("%s is already mounted", name)))
	case test:
		if conflict {
			result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf(
				"%s would be unmounted from %s (fstype %s) and remounted from %s (fstype %s)",
				name, existing.Device, existing.FSType, device, fstype)))
		} else {
			result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("%s would be mounted from %s", name, device)))
		}
		didMount = true
	default:
		if conflict {
			if err := unmountFunc(name, 0); err != nil {
				result.Failed = true
				return result, fmt.Errorf("force_remount: unmount(%s): %w", name, err)
			}
		}
		if makedirs {
			if err := mkdirAll(name, 0o755); err != nil {
				result.Failed = true
				return result, fmt.Errorf("failed to create mount point %s: %w", name, err)
			}
		}
		if isNetworkFSType(fstype) {
			args := []string{"-t", fstype}
			if len(opts) > 0 {
				args = append(args, "-o", strings.Join(opts, ","))
			}
			args = append(args, device, name)
			cmd := execCommandContext(ctx, "mount", args...)
			if out, err := cmd.CombinedOutput(); err != nil {
				result.Failed = true
				result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("mount failed: %s", strings.TrimSpace(string(out)))))
				return result, err
			}
		} else {
			flags, data := splitMountOptions(opts)
			if err := mountFunc(device, name, fstype, flags, data); err != nil {
				result.Failed = true
				return result, fmt.Errorf("mount(%s, %s, %s): %w", device, name, fstype, err)
			}
		}
		if conflict {
			result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("remounted %s from %s (was %s)", name, device, existing.Device)))
		} else {
			result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("mounted %s from %s", name, device)))
		}
		didMount = true
	}

	fstabChanged, err := m.syncFstab(test, persist, Entry{
		Device: device, MountPoint: name, FSType: fstype,
		Options: opts, Dump: dump, Pass: pass,
	}, &result)
	if err != nil {
		result.Failed = true
		return result, err
	}

	result.Succeeded = true
	result.Changed = didMount || fstabChanged
	return result, nil
}

// syncFstab adds or updates the fstab entry for newEntry.MountPoint when
// persist is set, appending a note either way. It returns whether the fstab
// file changed (or, in test mode, would change).
func (m Mount) syncFstab(test, persist bool, newEntry Entry, result *cook.Result) (bool, error) {
	if !persist {
		return false, nil
	}
	lines, err := readFstab()
	if err != nil {
		return false, fmt.Errorf("failed to read fstab: %w", err)
	}
	updated, changed := UpsertByMountPoint(lines, newEntry)
	if !changed {
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("fstab entry for %s already up to date", newEntry.MountPoint)))
		return false, nil
	}
	if test {
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("fstab entry for %s would be updated", newEntry.MountPoint)))
		return true, nil
	}
	if err := writeFstab(updated); err != nil {
		return false, fmt.Errorf("failed to write fstab: %w", err)
	}
	result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("updated fstab entry for %s", newEntry.MountPoint)))
	return true, nil
}
