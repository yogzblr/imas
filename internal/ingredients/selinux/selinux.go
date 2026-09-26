//go:build linux

package selinux

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
)

var ErrSelinuxMethodUndefined = errors.New("selinux method undefined")

// Compile-time interface check.
var _ cook.RecipeCooker = SELinux{}

type SELinux struct {
	id     string
	method string
	params map[string]interface{}
}

func (s SELinux) Parse(id, method string, params map[string]interface{}) (cook.RecipeCooker, error) {
	if params == nil {
		params = map[string]interface{}{}
	}
	parsed := SELinux{
		id: id, method: method,
		params: params,
	}
	if err := parsed.validate(); err != nil {
		return nil, err
	}
	return parsed, nil
}

func (s SELinux) validate() error {
	set, err := s.PropertiesForMethod(s.method)
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
				name, ok := s.params[v.Key].(string)
				if !ok || name == "" {
					return ingredients.ErrMissingName
				}
			} else if _, ok := s.params[v.Key]; !ok {
				return fmt.Errorf("missing required property %s", v.Key)
			}
		}
	}
	return nil
}

func (s SELinux) Test(ctx context.Context) (cook.Result, error) {
	switch s.method {
	case "enforcing", "permissive":
		return s.mode(ctx, true)
	case "boolean_on", "boolean_off":
		return s.boolean(ctx, true)
	case "context_present":
		return s.contextPresent(ctx, true)
	default:
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil},
			errors.Join(ErrSelinuxMethodUndefined, fmt.Errorf("method %s undefined", s.method))
	}
}

func (s SELinux) Apply(ctx context.Context) (cook.Result, error) {
	switch s.method {
	case "enforcing", "permissive":
		return s.mode(ctx, false)
	case "boolean_on", "boolean_off":
		return s.boolean(ctx, false)
	case "context_present":
		return s.contextPresent(ctx, false)
	default:
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil},
			errors.Join(ErrSelinuxMethodUndefined, fmt.Errorf("method %s undefined", s.method))
	}
}

func (s SELinux) PropertiesForMethod(method string) (map[string]string, error) {
	switch method {
	case "enforcing", "permissive":
		// No required properties: these target the host's overall runtime
		// mode, not a named resource.
		return ingredients.MethodPropsSet{}.ToMap(), nil
	case "boolean_on", "boolean_off":
		return ingredients.MethodPropsSet{
			ingredients.MethodProps{Key: "name", Type: "string", IsReq: true, Description: "the SELinux boolean name"},
			ingredients.MethodProps{
				Key: "persist", Type: "bool", IsReq: false,
				Description: "also persist the change across reboots/relabels via semanage (default false)",
			},
		}.ToMap(), nil
	case "context_present":
		return ingredients.MethodPropsSet{
			ingredients.MethodProps{Key: "name", Type: "string", IsReq: true, Description: "the file or directory path to relabel"},
			ingredients.MethodProps{Key: "context", Type: "string", IsReq: true, Description: "the desired SELinux security context"},
			ingredients.MethodProps{
				Key: "recurse", Type: "bool", IsReq: false,
				Description: "apply recursively to directory contents (default false)",
			},
		}.ToMap(), nil
	default:
		return nil, errors.Join(ErrSelinuxMethodUndefined, fmt.Errorf("method %s undefined", method))
	}
}

func (s SELinux) Methods() (string, []string) {
	return "selinux", []string{"enforcing", "permissive", "boolean_on", "boolean_off", "context_present"}
}

func (s SELinux) Properties() (map[string]interface{}, error) {
	out := map[string]interface{}{}
	b, err := json.Marshal(s.params)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(b, &out)
	return out, err
}

func init() {
	ingredients.RegisterAllMethods(SELinux{})
}
