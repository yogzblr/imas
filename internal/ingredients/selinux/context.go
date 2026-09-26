//go:build linux

package selinux

import (
	"context"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
)

func (s SELinux) contextPresent(_ context.Context, test bool) (cook.Result, error) {
	var result cook.Result

	name := stringParam(s.params, "name")
	if name == "" {
		result.Failed = true
		return result, ingredients.ErrMissingName
	}
	wantContext := stringParam(s.params, "context")
	if wantContext == "" {
		result.Failed = true
		return result, fmt.Errorf("selinux context_present %s: context must be a non-empty string", name)
	}
	recurse := boolParam(s.params, "recurse", false)

	current, err := seFileLabel(name)
	if err != nil {
		result.Failed = true
		return result, fmt.Errorf("reading label of %s: %w", name, err)
	}

	if current == wantContext {
		result.Succeeded = true
		result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("%s already has context %s", name, wantContext)))
		return result, nil
	}

	if test {
		result.Succeeded = true
		result.Changed = true
		result.Notes = append(result.Notes,
			cook.SimpleNote(fmt.Sprintf("%s would be relabeled from %s to %s", name, current, wantContext)))
		return result, nil
	}

	if err := seChcon(name, wantContext, recurse); err != nil {
		result.Failed = true
		return result, fmt.Errorf("chcon %s %s (recurse=%v): %w", wantContext, name, recurse, err)
	}

	// Same defensive readback as mode/boolean changes: don't report success
	// on a relabel the kernel didn't actually apply.
	after, err := seFileLabel(name)
	if err != nil {
		result.Failed = true
		return result, fmt.Errorf("reading back label of %s after chcon: %w", name, err)
	}
	if after != wantContext {
		result.Failed = true
		return result, fmt.Errorf(
			"chcon %s reported success but the path now reports context %s; refusing to report success on an unverified state change",
			name, after)
	}

	result.Succeeded = true
	result.Changed = true
	result.Notes = append(result.Notes, cook.SimpleNote(fmt.Sprintf("%s relabeled to %s", name, wantContext)))
	return result, nil
}
