package lgpo

import (
	"context"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
)

func (l LGPO) absent(_ context.Context, test bool) (cook.Result, error) {
	p, polPath, err := l.loadPolicy()
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}

	_, deletes, err := Resolve(p, StateNotConfigured, nil)
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}

	f, err := readPolFile(polPath)
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}
	before := f.Bytes()
	Apply(f, nil, deletes)
	changed := string(before) != string(f.Bytes())

	label := displayLabel(p)
	if !changed {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{
			cook.Snprintf("%s is already not configured", label),
		}}, nil
	}
	if test {
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
			cook.Snprintf("%s would be reset to not configured in %s", label, polPath),
		}}, nil
	}
	if err := writePolFile(polPath, f); err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
		cook.Snprintf("%s has been reset to not configured in %s", label, polPath),
	}}, nil
}
