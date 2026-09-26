//go:build windows

// Package winshortcut implements a imas ingredient for managing Windows
// shell shortcuts (.lnk files), matching the surface of Salt's
// win_shortcut state module. It drives the Shell's WScript.Shell
// "CreateShortcut" automation object (IWshShortcut) via COM — the same
// underlying object Salt's Python implementation drives through
// win32com.client.Dispatch("WScript.Shell").
package winshortcut

import (
	"context"
	"errors"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
	"github.com/yogzblr/imas/internal/ingredients/winexec"
)

const ingredientName = "win_shortcut"

const (
	methodPresent = "present"
	methodAbsent  = "absent"
)

var (
	ErrShortcutMethodUndefined = errors.New("winshortcut method undefined")
	ErrMissingTarget           = errors.New("winshortcut present requires a target")
	ErrInvalidWindowStyle      = errors.New("invalid window_style")
)

// Compile-time interface check.
var _ cook.RecipeCooker = Shortcut{}

// Shortcut is a imas ingredient for managing Windows .lnk shell
// shortcuts. "name" is always the full path to the shortcut file.
type Shortcut struct {
	id     string
	method string
	params map[string]interface{}
}

func (s Shortcut) Parse(id, method string, params map[string]interface{}) (cook.RecipeCooker, error) {
	if params == nil {
		params = map[string]interface{}{}
	}
	parsed := Shortcut{id: id, method: method, params: params}
	if err := parsed.validate(); err != nil {
		return nil, err
	}
	return parsed, nil
}

func (s Shortcut) validate() error {
	set, err := s.PropertiesForMethod(s.method)
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
		val, ok := winexec.StringParam(s.params, v.Key)
		if !ok || val == "" {
			if v.Key == "name" {
				return ingredients.ErrMissingName
			}
			return fmt.Errorf("missing required property %s", v.Key)
		}
	}
	if s.method == methodPresent {
		if _, err := parseWindowStyle(s.params); err != nil {
			return err
		}
	}
	return nil
}

func (s Shortcut) dispatch(ctx context.Context, test bool) (cook.Result, error) {
	switch s.method {
	case methodPresent:
		return s.present(ctx, test)
	case methodAbsent:
		return s.absent(ctx, test)
	default:
		return cook.Result{Succeeded: false, Failed: true, Changed: false, Notes: nil},
			errors.Join(ErrShortcutMethodUndefined, fmt.Errorf("method %s undefined", s.method))
	}
}

func (s Shortcut) Test(ctx context.Context) (cook.Result, error) {
	return s.dispatch(ctx, true)
}

func (s Shortcut) Apply(ctx context.Context) (cook.Result, error) {
	return s.dispatch(ctx, false)
}

func (s Shortcut) PropertiesForMethod(method string) (map[string]string, error) {
	switch method {
	case methodPresent:
		return ingredients.MethodPropsSet{
			ingredients.MethodProps{Key: "name", Type: "string", IsReq: true, Description: "full path to the .lnk shortcut file"},
			ingredients.MethodProps{Key: "target", Type: "string", IsReq: true, Description: "path the shortcut points at"},
			ingredients.MethodProps{Key: "arguments", Type: "string", IsReq: false, Description: "command-line arguments passed to the target"},
			ingredients.MethodProps{Key: "description", Type: "string", IsReq: false, Description: "shortcut description (tooltip)"},
			ingredients.MethodProps{Key: "working_dir", Type: "string", IsReq: false, Description: "working directory the target is launched from"},
			ingredients.MethodProps{Key: "icon_location", Type: "string", IsReq: false, Description: "path to the file supplying the shortcut's icon"},
			ingredients.MethodProps{Key: "icon_index", Type: "string", IsReq: false, Description: "index of the icon within icon_location (default 0)"},
			ingredients.MethodProps{Key: "window_style", Type: "string", IsReq: false, Description: "one of normal, maximized, minimized (default normal)"},
			ingredients.MethodProps{Key: "hotkey", Type: "string", IsReq: false, Description: `global hotkey, e.g. "CTRL+ALT+F"`},
		}.ToMap(), nil
	case methodAbsent:
		return ingredients.MethodPropsSet{
			ingredients.MethodProps{Key: "name", Type: "string", IsReq: true, Description: "full path to the .lnk shortcut file"},
		}.ToMap(), nil
	default:
		return nil, errors.Join(ErrShortcutMethodUndefined, fmt.Errorf("method %s undefined", method))
	}
}

func (s Shortcut) Methods() (string, []string) {
	return ingredientName, []string{methodAbsent, methodPresent}
}

func (s Shortcut) Properties() (map[string]interface{}, error) {
	return s.params, nil
}

func init() {
	ingredients.RegisterAllMethods(Shortcut{})
}
