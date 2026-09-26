//go:build windows

package registry

import (
	"context"
	"fmt"

	"golang.org/x/sys/windows/registry"

	"github.com/yogzblr/imas/internal/cook"
)

func (r Registry) present(_ context.Context, test bool) (cook.Result, error) {
	name, _ := r.params["name"].(string)
	hive, subkey, err := splitName(name)
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}
	vname, _ := r.params["vname"].(string)
	vtype, _ := r.params["vtype"].(string)
	if vtype == "" {
		vtype = "string"
	}
	raw, ok := r.params["vdata"]
	if !ok {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, ErrMissingValueData
	}
	desired, err := coerceValue(vtype, raw)
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}

	if k, err := backend.OpenKey(hive, subkey, registry.QUERY_VALUE); err == nil {
		current, readErr := readCurrentValue(k, vname, vtype)
		k.Close()
		if readErr == nil && valuesEqual(current, desired) {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{
				cook.Snprintf("%s value %q already matches", name, displayName(vname)),
			}}, nil
		}
	}

	if test {
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
			cook.Snprintf("%s value %q would be set", name, displayName(vname)),
		}}, nil
	}

	k, _, err := backend.CreateKey(hive, subkey, registry.QUERY_VALUE|registry.SET_VALUE|registry.CREATE_SUB_KEY)
	if err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}
	defer k.Close()
	if err := setValue(k, vname, vtype, desired); err != nil {
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil}, err
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{
		cook.Snprintf("%s value %q has been set", name, displayName(vname)),
	}}, nil
}
