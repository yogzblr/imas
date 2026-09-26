//go:build windows

package wintaskscheduler

import (
	"context"
	"errors"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients/winexec"
)

func (t Task) absent(_ context.Context, test bool) (cook.Result, error) {
	name, _ := winexec.StringParam(t.params, "name")

	if _, err := backend.Load(name); err != nil {
		if errors.Is(err, ErrTaskNotFound) {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{
				cook.Snprintf("task %q is already absent", name),
			}}, nil
		}
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}

	if test {
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
			cook.Snprintf("task %q would be removed", name),
		}}, nil
	}

	if err := backend.Delete(name); err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
		cook.Snprintf("task %q has been removed", name),
	}}, nil
}
