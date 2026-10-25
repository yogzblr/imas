package wintaskscheduler

import (
	"context"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients/winexec"
)

// absent only asks whether the task exists (backend.Exists): it needs
// nothing of the task's definition. Reading the whole definition, as it
// did through Load, made it fail on any part Load could not read (UAT
// I.win_task.absent, Run 2 on rc.21: "call Item: Member not found").
func (t Task) absent(_ context.Context, test bool) (cook.Result, error) {
	name, _ := winexec.StringParam(t.params, "name")

	exists, err := backend.Exists(name)
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}
	if !exists {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{
			cook.Snprintf("task %q is already absent", name),
		}}, nil
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
