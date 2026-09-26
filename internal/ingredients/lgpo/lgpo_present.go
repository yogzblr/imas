package lgpo

import (
	"context"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
)

func (l LGPO) present(_ context.Context, test bool) (cook.Result, error) {
	p, polPath, err := l.loadPolicy()
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}
	state, err := parseState(l.params["state"])
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}

	writes, deletes, err := Resolve(p, state, l.elementValues())
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}

	f, err := readPolFile(polPath)
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}
	before := f.Bytes()
	Apply(f, writes, deletes)
	changed := string(before) != string(f.Bytes())

	label := displayLabel(p)
	if !changed {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{
			cook.Snprintf("%s is already %s", label, state),
		}}, nil
	}
	if test {
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
			cook.Snprintf("%s would be set to %s in %s", label, state, polPath),
		}}, nil
	}
	if err := writePolFile(polPath, f); err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
		cook.Snprintf("%s has been set to %s in %s", label, state, polPath),
	}}, nil
}

func displayLabel(p Policy) string {
	if p.DisplayName != "" {
		return p.DisplayName
	}
	return p.Name
}
