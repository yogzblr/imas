//go:build linux

package mount

import (
	"context"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
)

func (m Mount) fstabPresent(_ context.Context, test bool) (cook.Result, error) {
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

	lines, err := readFstab()
	if err != nil {
		result.Failed = true
		return result, fmt.Errorf("failed to read fstab: %w", err)
	}

	newEntry := Entry{Device: device, MountPoint: name, FSType: fstype, Options: opts, Dump: dump, Pass: pass}
	updated, changed := UpsertByMountPoint(lines, newEntry)
	if !changed {
		result.Succeeded = true
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("fstab entry for %s already up to date", name)))
		return result, nil
	}
	if test {
		result.Succeeded = true
		result.Changed = true
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("fstab entry for %s would be updated", name)))
		return result, nil
	}
	if err := writeFstab(updated); err != nil {
		result.Failed = true
		return result, fmt.Errorf("failed to write fstab: %w", err)
	}
	result.Succeeded = true
	result.Changed = true
	result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("updated fstab entry for %s", name)))
	return result, nil
}
