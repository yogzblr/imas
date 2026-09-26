//go:build windows

// Package winappx wraps Salt's win_appx module: installing/removing
// provisioned Appx (UWP/MSIX) packages via Add-AppxPackage and
// Remove-AppxPackage, the same PowerShell surface Salt itself shells out
// to. See G.8 in docs/design/imas-windows-parity-addendum.md.
package winappx

import (
	"context"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
	"github.com/yogzblr/imas/internal/ingredients/winexec"
)

const ingredientName = "win_appx"

const (
	methodInstalled = "installed"
	methodRemoved   = "removed"
)

var methodProps = map[string]ingredients.MethodPropsSet{
	methodInstalled: {
		ingredients.MethodProps{Key: "name", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "path", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "timeout", Type: "string", IsReq: false},
	},
	methodRemoved: {
		ingredients.MethodProps{Key: "name", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "timeout", Type: "string", IsReq: false},
	},
}

// Compile-time interface check.
var _ cook.RecipeCooker = Package{}

// Package manages a single Appx package, identified by package name.
type Package struct {
	id     string
	method string
	name   string
	params map[string]interface{}
}

func (p Package) Parse(id, method string, params map[string]interface{}) (cook.RecipeCooker, error) {
	if params == nil {
		params = map[string]interface{}{}
	}
	if _, ok := methodProps[method]; !ok {
		return nil, ingredients.ErrInvalidMethod
	}
	name, ok := winexec.StringParam(params, "name")
	if !ok || name == "" {
		return nil, ingredients.ErrMissingName
	}
	if method == methodInstalled {
		if path, ok := winexec.StringParam(params, "path"); !ok || path == "" {
			return nil, fmt.Errorf("missing required property path")
		}
	}
	return Package{id: id, method: method, name: name, params: params}, nil
}

func (p Package) Methods() (string, []string) {
	return ingredientName, []string{methodInstalled, methodRemoved}
}

func (p Package) PropertiesForMethod(method string) (map[string]string, error) {
	props, ok := methodProps[method]
	if !ok {
		return nil, fmt.Errorf("method %s undefined", method)
	}
	return props.ToMap(), nil
}

func (p Package) Properties() (map[string]interface{}, error) {
	return p.params, nil
}

func (p Package) isInstalled(ctx context.Context) (bool, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(p.params, "timeout", ""))
	if err != nil {
		return false, err
	}
	script := fmt.Sprintf("@(Get-AppxPackage -Name %s).Count", winexec.PSQuote(p.name))
	out, err := winexec.RunPowerShell(ctx, script, timeout)
	if err != nil {
		return false, err
	}
	return out != "" && out != "0", nil
}

func (p Package) Test(ctx context.Context) (cook.Result, error) {
	installed, err := p.isInstalled(ctx)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	switch p.method {
	case methodInstalled:
		if installed {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already installed", p.name))}}, nil
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s would be installed", p.name))}}, nil
	case methodRemoved:
		if !installed {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already removed", p.name))}}, nil
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s would be removed", p.name))}}, nil
	default:
		return cook.Result{}, ingredients.ErrInvalidMethod
	}
}

func (p Package) Apply(ctx context.Context) (cook.Result, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(p.params, "timeout", ""))
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	installed, err := p.isInstalled(ctx)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	switch p.method {
	case methodInstalled:
		if installed {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already installed", p.name))}}, nil
		}
		path, _ := winexec.StringParam(p.params, "path")
		script := fmt.Sprintf("Add-AppxPackage -Path %s", winexec.PSQuote(path))
		if _, err := winexec.RunPowerShell(ctx, script, timeout); err != nil {
			return cook.Result{Failed: true}, err
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s has been installed", p.name))}}, nil
	case methodRemoved:
		if !installed {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already removed", p.name))}}, nil
		}
		script := fmt.Sprintf("Get-AppxPackage -Name %s | Remove-AppxPackage", winexec.PSQuote(p.name))
		if _, err := winexec.RunPowerShell(ctx, script, timeout); err != nil {
			return cook.Result{Failed: true}, err
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s has been removed", p.name))}}, nil
	default:
		return cook.Result{}, ingredients.ErrInvalidMethod
	}
}

func init() {
	ingredients.RegisterAllMethods(Package{})
}
