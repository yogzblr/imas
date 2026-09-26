//go:build linux

package mount

import (
	"context"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
)

func (m Mount) fstabAbsent(_ context.Context, test bool) (cook.Result, error) {
	var result cook.Result

	name := stringParam(m.params, "name")

	lines, err := readFstab()
	if err != nil {
		result.Failed = true
		return result, fmt.Errorf("failed to read fstab: %w", err)
	}

	updated, removed := RemoveByMountPoint(lines, name)
	if !removed {
		result.Succeeded = true
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("no fstab entry for %s", name)))
		return result, nil
	}
	if test {
		result.Succeeded = true
		result.Changed = true
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("fstab entry for %s would be removed", name)))
		return result, nil
	}
	if err := writeFstab(updated); err != nil {
		result.Failed = true
		return result, fmt.Errorf("failed to write fstab: %w", err)
	}
	result.Succeeded = true
	result.Changed = true
	result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("removed fstab entry for %s", name)))
	return result, nil
}
