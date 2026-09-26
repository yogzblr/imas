//go:build windows

package registry

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/sys/windows/registry"

	"github.com/yogzblr/imas/internal/cook"
)

func (r Registry) keyAbsent(_ context.Context, test bool) (cook.Result, error) {
	name, _ := r.params["name"].(string)
	hive, subkey, err := splitName(name)
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}
	force, _ := r.params["force"].(bool)

	k, err := backend.OpenKey(hive, subkey, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.Snprintf("%s is already absent", name)}}, nil
		}
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}
	k.Close()

	if test {
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
			cook.Snprintf("%s would be removed", name),
		}}, nil
	}

	if force {
		if err := deleteKeyRecursive(hive, subkey); err != nil {
			return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
		}
	} else if err := backend.DeleteKey(hive, subkey); err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
		cook.Snprintf("%s has been removed", name),
	}}, nil
}
