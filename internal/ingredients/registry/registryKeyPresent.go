//go:build windows

package registry

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/sys/windows/registry"

	"github.com/yogzblr/imas/internal/cook"
)

func (r Registry) keyPresent(_ context.Context, test bool) (cook.Result, error) {
	name, _ := r.params["name"].(string)
	hive, subkey, err := splitName(name)
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}

	k, err := backend.OpenKey(hive, subkey, registry.QUERY_VALUE)
	if err == nil {
		k.Close()
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.Snprintf("%s already exists", name)}}, nil
	}
	if !errors.Is(err, registry.ErrNotExist) {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}

	if test {
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
			cook.Snprintf("%s would be created", name),
		}}, nil
	}

	newKey, _, err := backend.CreateKey(hive, subkey, registry.QUERY_VALUE|registry.SET_VALUE|registry.CREATE_SUB_KEY)
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}
	newKey.Close()
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
		cook.Snprintf("%s has been created", name),
	}}, nil
}
