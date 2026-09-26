//go:build linux

package mount

import (
	"context"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
)

func (m Mount) unmounted(ctx context.Context, test bool) (cook.Result, error) {
	var result cook.Result

	name := stringParam(m.params, "name")
	persist := boolParam(m.params, "persist", true)

	active, err := readActiveMounts()
	if err != nil {
		result.Failed = true
		return result, fmt.Errorf("failed to read active mounts: %w", err)
	}

	var didUnmount bool
	if FindByMountPoint(active, name) == nil {
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("%s is already unmounted", name)))
	} else if test {
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("%s would be unmounted", name)))
		didUnmount = true
	} else {
		if err := unmountFunc(name, 0); err != nil {
			result.Failed = true
			return result, fmt.Errorf("unmount(%s): %w", name, err)
		}
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("unmounted %s", name)))
		didUnmount = true
	}

	fstabChanged, err := m.removeFromFstab(test, persist, name, &result)
	if err != nil {
		result.Failed = true
		return result, err
	}

	result.Succeeded = true
	result.Changed = didUnmount || fstabChanged
	return result, nil
}

func (m Mount) removeFromFstab(test, persist bool, mountPoint string, result *cook.Result) (bool, error) {
	if !persist {
		return false, nil
	}
	lines, err := readFstab()
	if err != nil {
		return false, fmt.Errorf("failed to read fstab: %w", err)
	}
	updated, removed := RemoveByMountPoint(lines, mountPoint)
	if !removed {
		return false, nil
	}
	if test {
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("fstab entry for %s would be removed", mountPoint)))
		return true, nil
	}
	if err := writeFstab(updated); err != nil {
		return false, fmt.Errorf("failed to write fstab: %w", err)
	}
	result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("removed fstab entry for %s", mountPoint)))
	return true, nil
}
