//go:build linux

package selinux

import (
	"context"
	"fmt"

	goselinux "github.com/opencontainers/selinux/go-selinux"

	"github.com/yogzblr/imas/internal/cook"
)

// modeTarget maps a method name to opencontainers/selinux's mode constants.
// "disabled" is deliberately absent: the kernel only accepts Enforcing/
// Permissive as a runtime transition via /sys/fs/selinux/enforce --
// disabling SELinux entirely requires editing /etc/selinux/config (already
// covered by the file/file.line ingredient) and a reboot.
var modeTarget = map[string]int{
	"enforcing":  goselinux.Enforcing,
	"permissive": goselinux.Permissive,
}

func modeName(mode int) string {
	switch mode {
	case goselinux.Enforcing:
		return "enforcing"
	case goselinux.Permissive:
		return "permissive"
	case goselinux.Disabled:
		return "disabled"
	default:
		return fmt.Sprintf("unknown(%d)", mode)
	}
}

func (s SELinux) mode(_ context.Context, test bool) (cook.Result, error) {
	var result cook.Result

	want, ok := modeTarget[s.method]
	if !ok {
		result.Failed = true
		return result, fmt.Errorf("selinux: unknown mode method %q", s.method)
	}

	if !seGetEnabled() {
		result.Failed = true
		return result, fmt.Errorf(
			"SELinux is disabled or not present on this host; cannot set mode %q (this ingredient only performs the runtime enforce/permissive transition, not enabling a disabled kernel policy)",
			s.method)
	}

	current := seEnforceMode()
	if current == want {
		result.Succeeded = true
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("SELinux is already %s", s.method)))
		return result, nil
	}

	if test {
		result.Succeeded = true
		result.Changed = true
		result.Notes = append(result.Notes,
			cook.SimpleNote(fmt.Sprintf("SELinux would be switched from %s to %s", modeName(current), s.method)))
		return result, nil
	}

	if err := seSetEnforceMode(want); err != nil {
		result.Failed = true
		return result, fmt.Errorf("setenforce %s: %w", s.method, err)
	}

	// Never trust the write alone: report success only once the kernel
	// itself confirms the mode actually changed. A recipe that asks for
	// "enforcing" and silently stays permissive is a compliance-visible
	// failure, not just a bug -- this is the one property this ingredient
	// must never get wrong.
	after := seEnforceMode()
	if after != want {
		result.Failed = true
		return result, fmt.Errorf(
			"setenforce %s reported success but the kernel now reports mode %s; refusing to report success on an unverified state change",
			s.method, modeName(after))
	}

	result.Succeeded = true
	result.Changed = true
	result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("SELinux switched to %s", s.method)))
	return result, nil
}
