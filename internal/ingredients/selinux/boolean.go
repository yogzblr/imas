//go:build linux

package selinux

import (
	"context"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
)

func onOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}

func (s SELinux) boolean(ctx context.Context, test bool) (cook.Result, error) {
	var result cook.Result

	name := stringParam(s.params, "name")
	if name == "" {
		result.Failed = true
		return result, ingredients.ErrMissingName
	}
	persist := boolParam(s.params, "persist", false)
	want := s.method == "boolean_on"

	if !seGetEnabled() {
		result.Failed = true
		return result, fmt.Errorf("SELinux is disabled or not present on this host; cannot set boolean %q", name)
	}

	active, _, err := readBoolean(name)
	if err != nil {
		result.Failed = true
		return result, fmt.Errorf("reading boolean %s: %w", name, err)
	}
	needsRuntimeChange := active != want

	var notes []fmt.Stringer
	if !needsRuntimeChange {
		notes = append(notes, cook.SimpleNote(fmt.Sprintf("boolean %s is already %s", name, onOff(want))))
	}

	if test {
		result.Succeeded = true
		result.Changed = needsRuntimeChange || persist
		if needsRuntimeChange {
			notes = append(notes, cook.SimpleNote(fmt.Sprintf("boolean %s would be set %s", name, onOff(want))))
		}
		if persist {
			notes = append(notes, cook.SimpleNote(fmt.Sprintf("boolean %s would be persisted %s via semanage", name, onOff(want))))
		}
		result.Notes = notes
		return result, nil
	}

	if needsRuntimeChange {
		if err := setBoolean(name, want); err != nil {
			result.Failed = true
			return result, fmt.Errorf("setsebool %s %s: %w", name, onOff(want), err)
		}
		// Same defensive readback as mode changes: a write that the kernel
		// silently didn't apply must not be reported as success.
		newActive, _, err := readBoolean(name)
		if err != nil {
			result.Failed = true
			return result, fmt.Errorf("reading back boolean %s after set: %w", name, err)
		}
		if newActive != want {
			result.Failed = true
			return result, fmt.Errorf(
				"setsebool %s %s reported success but the kernel still reports %s; refusing to report success on an unverified state change",
				name, onOff(want), onOff(newActive))
		}
		notes = append(notes, cook.SimpleNote(fmt.Sprintf("boolean %s set %s", name, onOff(want))))
	}

	if persist {
		// semanage's own idempotency isn't introspected here, so a
		// persist=true step is always treated as a change; the cost is an
		// over-reported "changed" on an already-persisted boolean, not a
		// missed write.
		if err := persistBoolean(ctx, name, want); err != nil {
			result.Failed = true
			return result, err
		}
		notes = append(notes, cook.SimpleNote(fmt.Sprintf("boolean %s persisted %s via semanage", name, onOff(want))))
	}

	result.Succeeded = true
	result.Changed = needsRuntimeChange || persist
	result.Notes = notes
	return result, nil
}
