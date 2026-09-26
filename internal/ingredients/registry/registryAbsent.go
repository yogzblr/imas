//go:build windows

package registry

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/sys/windows/registry"

	"github.com/yogzblr/imas/internal/cook"
)

func (r Registry) absent(_ context.Context, test bool) (cook.Result, error) {
	name, _ := r.params["name"].(string)
	hive, subkey, err := splitName(name)
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}
	vname, _ := r.params["vname"].(string)

	k, err := backend.OpenKey(hive, subkey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{
				cook.Snprintf("%s is already absent", name),
			}}, nil
		}
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}
	defer k.Close()

	exists, err := valueExists(k, vname)
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}
	if !exists {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{
			cook.Snprintf("%s value %q is already absent", name, displayName(vname)),
		}}, nil
	}
	if test {
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
			cook.Snprintf("%s value %q would be removed", name, displayName(vname)),
		}}, nil
	}
	if err := k.DeleteValue(vname); err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
		cook.Snprintf("%s value %q has been removed", name, displayName(vname)),
	}}, nil
}
