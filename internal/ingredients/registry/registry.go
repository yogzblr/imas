//go:build windows

// Package registry implements a imas ingredient for managing Windows
// registry keys and values via golang.org/x/sys/windows/registry.
package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
)

var (
	ErrRegistryMethodUndefined = errors.New("registry method undefined")
	ErrInvalidHive             = errors.New("invalid registry hive")
	ErrMissingValueData        = errors.New("registry value is missing vdata")
	ErrInvalidValueData        = errors.New("invalid registry value data")
	ErrUnsupportedValueType    = errors.New("unsupported registry value type")
)

// Compile-time interface check.
var _ cook.RecipeCooker = Registry{}

// Registry is a imas ingredient for managing Windows registry keys and
// values. "name" is always the fully qualified hive-and-key path, e.g.
// `HKEY_LOCAL_MACHINE\SOFTWARE\Contoso\App` (short hive aliases such as
// HKLM/HKCU/HKCR/HKU/HKCC are also accepted).
type Registry struct {
	id     string
	method string
	params map[string]interface{}
}

func (r Registry) Parse(id, method string, params map[string]interface{}) (cook.RecipeCooker, error) {
	if params == nil {
		params = map[string]interface{}{}
	}
	parsed := Registry{id: id, method: method, params: params}
	if err := parsed.validate(); err != nil {
		return nil, err
	}
	return parsed, nil
}

func (r Registry) validate() error {
	set, err := r.PropertiesForMethod(r.method)
	if err != nil {
		return err
	}
	propSet, err := ingredients.PropMapToPropSet(set)
	if err != nil {
		return err
	}
	for _, v := range propSet {
		if !v.IsReq {
			continue
		}
		if v.Key == "name" {
			name, ok := r.params[v.Key].(string)
			if !ok || name == "" {
				return ingredients.ErrMissingName
			}
			continue
		}
		if _, ok := r.params[v.Key]; !ok {
			return fmt.Errorf("missing required property %s", v.Key)
		}
	}
	name, _ := r.params["name"].(string)
	if _, _, err := splitName(name); err != nil {
		return err
	}
	return nil
}

func (r Registry) dispatch(ctx context.Context, test bool) (cook.Result, error) {
	switch r.method {
	case "present":
		return r.present(ctx, test)
	case "absent":
		return r.absent(ctx, test)
	case "key_present":
		return r.keyPresent(ctx, test)
	case "key_absent":
		return r.keyAbsent(ctx, test)
	default:
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil},
			errors.Join(ErrRegistryMethodUndefined, fmt.Errorf("method %s undefined", r.method))
	}
}

func (r Registry) Test(ctx context.Context) (cook.Result, error) {
	return r.dispatch(ctx, true)
}

func (r Registry) Apply(ctx context.Context) (cook.Result, error) {
	return r.dispatch(ctx, false)
}

func (r Registry) PropertiesForMethod(method string) (map[string]string, error) {
	switch method {
	case "present":
		return ingredients.MethodPropsSet{
			ingredients.MethodProps{Key: "name", Type: "string", IsReq: true, Description: `hive and key path, e.g. HKEY_LOCAL_MACHINE\SOFTWARE\Contoso\App`},
			ingredients.MethodProps{Key: "vname", Type: "string", IsReq: false, Description: "value name; omit for the key's default value"},
			ingredients.MethodProps{Key: "vtype", Type: "string", IsReq: false, Description: "one of string, expand_string, dword, qword, multi_string, binary (default string)"},
			ingredients.MethodProps{Key: "vdata", Type: "string", IsReq: true, Description: "the data to store"},
		}.ToMap(), nil
	case "absent":
		return ingredients.MethodPropsSet{
			ingredients.MethodProps{Key: "name", Type: "string", IsReq: true, Description: `hive and key path, e.g. HKEY_LOCAL_MACHINE\SOFTWARE\Contoso\App`},
			ingredients.MethodProps{Key: "vname", Type: "string", IsReq: false, Description: "value name; omit for the key's default value"},
		}.ToMap(), nil
	case "key_present":
		return ingredients.MethodPropsSet{
			ingredients.MethodProps{Key: "name", Type: "string", IsReq: true, Description: `hive and key path, e.g. HKEY_LOCAL_MACHINE\SOFTWARE\Contoso\App`},
		}.ToMap(), nil
	case "key_absent":
		return ingredients.MethodPropsSet{
			ingredients.MethodProps{Key: "name", Type: "string", IsReq: true, Description: `hive and key path, e.g. HKEY_LOCAL_MACHINE\SOFTWARE\Contoso\App`},
			ingredients.MethodProps{Key: "force", Type: "bool", IsReq: false, Description: "delete subkeys recursively instead of failing when the key is not empty"},
		}.ToMap(), nil
	default:
		return nil, errors.Join(ErrRegistryMethodUndefined, fmt.Errorf("method %s undefined", method))
	}
}

func (r Registry) Methods() (string, []string) {
	return "registry", []string{"absent", "key_absent", "key_present", "present"}
}

func (r Registry) Properties() (map[string]interface{}, error) {
	m := map[string]interface{}{}
	b, err := json.Marshal(r.params)
	if err != nil {
		return m, err
	}
	err = json.Unmarshal(b, &m)
	return m, err
}

func init() {
	ingredients.RegisterAllMethods(Registry{})
}
