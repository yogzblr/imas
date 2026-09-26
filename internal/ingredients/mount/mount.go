//go:build linux

package mount

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
)

var ErrMountMethodUndefined = errors.New("mount method undefined")

// Compile-time interface check.
var _ cook.RecipeCooker = Mount{}

type Mount struct {
	id     string
	method string
	params map[string]interface{}
}

func (m Mount) Parse(id, method string, params map[string]interface{}) (cook.RecipeCooker, error) {
	if params == nil {
		params = map[string]interface{}{}
	}
	parsed := Mount{
		id: id, method: method,
		params: params,
	}
	if err := parsed.validate(); err != nil {
		return nil, err
	}
	return parsed, nil
}

func (m Mount) validate() error {
	set, err := m.PropertiesForMethod(m.method)
	if err != nil {
		return err
	}
	propSet, err := ingredients.PropMapToPropSet(set)
	if err != nil {
		return err
	}
	for _, v := range propSet {
		if v.IsReq {
			if v.Key == "name" {
				name, ok := m.params[v.Key].(string)
				if !ok || name == "" {
					return ingredients.ErrMissingName
				}
			} else if _, ok := m.params[v.Key]; !ok {
				return fmt.Errorf("missing required property %s", v.Key)
			}
		}
	}
	return nil
}

func (m Mount) Test(ctx context.Context) (cook.Result, error) {
	switch m.method {
	case "mounted":
		return m.mounted(ctx, true)
	case "unmounted":
		return m.unmounted(ctx, true)
	case "fstab_present":
		return m.fstabPresent(ctx, true)
	case "fstab_absent":
		return m.fstabAbsent(ctx, true)
	default:
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil},
			errors.Join(ErrMountMethodUndefined, fmt.Errorf("method %s undefined", m.method))
	}
}

func (m Mount) Apply(ctx context.Context) (cook.Result, error) {
	switch m.method {
	case "mounted":
		return m.mounted(ctx, false)
	case "unmounted":
		return m.unmounted(ctx, false)
	case "fstab_present":
		return m.fstabPresent(ctx, false)
	case "fstab_absent":
		return m.fstabAbsent(ctx, false)
	default:
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil},
			errors.Join(ErrMountMethodUndefined, fmt.Errorf("method %s undefined", m.method))
	}
}

func (m Mount) PropertiesForMethod(method string) (map[string]string, error) {
	switch method {
	case "mounted":
		return ingredients.MethodPropsSet{
			ingredients.MethodProps{Key: "name", Type: "string", IsReq: true, Description: "the mount point"},
			ingredients.MethodProps{Key: "device", Type: "string", IsReq: true, Description: "the device or remote export to mount"},
			ingredients.MethodProps{Key: "fstype", Type: "string", IsReq: true, Description: "the filesystem type"},
			ingredients.MethodProps{Key: "opts", Type: "[]string", IsReq: false, Description: "mount options"},
			ingredients.MethodProps{Key: "dump", Type: "string", IsReq: false, Description: "fstab dump field"},
			ingredients.MethodProps{Key: "pass", Type: "string", IsReq: false, Description: "fstab pass field"},
			ingredients.MethodProps{Key: "persist", Type: "bool", IsReq: false, Description: "also add/update an /etc/fstab entry (default true)"},
			ingredients.MethodProps{Key: "makedirs", Type: "bool", IsReq: false, Description: "create the mount point directory if missing (default true)"},
			ingredients.MethodProps{Key: "force_remount", Type: "bool", IsReq: false, Description: "unmount and remount if the mount point is already mounted with a different device/fstype (default false: refuse instead)"},
		}.ToMap(), nil
	case "unmounted":
		return ingredients.MethodPropsSet{
			ingredients.MethodProps{Key: "name", Type: "string", IsReq: true, Description: "the mount point"},
			ingredients.MethodProps{Key: "persist", Type: "bool", IsReq: false, Description: "also remove any /etc/fstab entry (default true)"},
		}.ToMap(), nil
	case "fstab_present":
		return ingredients.MethodPropsSet{
			ingredients.MethodProps{Key: "name", Type: "string", IsReq: true, Description: "the mount point"},
			ingredients.MethodProps{Key: "device", Type: "string", IsReq: true, Description: "the device or remote export"},
			ingredients.MethodProps{Key: "fstype", Type: "string", IsReq: true, Description: "the filesystem type"},
			ingredients.MethodProps{Key: "opts", Type: "[]string", IsReq: false, Description: "mount options"},
			ingredients.MethodProps{Key: "dump", Type: "string", IsReq: false, Description: "fstab dump field"},
			ingredients.MethodProps{Key: "pass", Type: "string", IsReq: false, Description: "fstab pass field"},
		}.ToMap(), nil
	case "fstab_absent":
		return ingredients.MethodPropsSet{
			ingredients.MethodProps{Key: "name", Type: "string", IsReq: true, Description: "the mount point"},
		}.ToMap(), nil
	default:
		return nil, errors.Join(ErrMountMethodUndefined, fmt.Errorf("method %s undefined", method))
	}
}

func (m Mount) Methods() (string, []string) {
	return "mount", []string{"mounted", "unmounted", "fstab_present", "fstab_absent"}
}

func (m Mount) Properties() (map[string]interface{}, error) {
	out := map[string]interface{}{}
	b, err := json.Marshal(m.params)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(b, &out)
	return out, err
}

func init() {
	ingredients.RegisterAllMethods(Mount{})
}
