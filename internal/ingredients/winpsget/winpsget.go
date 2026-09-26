//go:build windows

// Package winpsget wraps Salt's win_psget module: installing/removing
// PowerShell modules via PowerShellGet (Install-Module/Uninstall-Module),
// the same PowerShell surface Salt itself shells out to. See G.8 in
// docs/design/imas-windows-parity-addendum.md.
package winpsget

import (
	"context"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
	"github.com/yogzblr/imas/internal/ingredients/winexec"
)

const ingredientName = "win_psget"

const (
	methodInstalled = "installed"
	methodRemoved   = "removed"
)

var methodProps = map[string]ingredients.MethodPropsSet{
	methodInstalled: {
		ingredients.MethodProps{Key: "name", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "version", Type: "string", IsReq: false},
		ingredients.MethodProps{Key: "scope", Type: "string", IsReq: false},
		ingredients.MethodProps{Key: "repository", Type: "string", IsReq: false},
		ingredients.MethodProps{Key: "timeout", Type: "string", IsReq: false},
	},
	methodRemoved: {
		ingredients.MethodProps{Key: "name", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "timeout", Type: "string", IsReq: false},
	},
}

// Compile-time interface check.
var _ cook.RecipeCooker = PSGet{}

// PSGet manages a single PowerShell module by name.
type PSGet struct {
	id     string
	method string
	name   string
	params map[string]interface{}
}

func (p PSGet) Parse(id, method string, params map[string]interface{}) (cook.RecipeCooker, error) {
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
	return PSGet{id: id, method: method, name: name, params: params}, nil
}

func (p PSGet) Methods() (string, []string) {
	return ingredientName, []string{methodInstalled, methodRemoved}
}

func (p PSGet) PropertiesForMethod(method string) (map[string]string, error) {
	props, ok := methodProps[method]
	if !ok {
		return nil, fmt.Errorf("method %s undefined", method)
	}
	return props.ToMap(), nil
}

func (p PSGet) Properties() (map[string]interface{}, error) {
	return p.params, nil
}

func (p PSGet) isInstalled(ctx context.Context) (bool, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(p.params, "timeout", ""))
	if err != nil {
		return false, err
	}
	script := fmt.Sprintf(
		"@(Get-Module -ListAvailable -Name %s).Count",
		winexec.PSQuote(p.name),
	)
	out, err := winexec.RunPowerShell(ctx, script, timeout)
	if err != nil {
		return false, err
	}
	return out != "" && out != "0", nil
}

func (p PSGet) Test(ctx context.Context) (cook.Result, error) {
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

func (p PSGet) Apply(ctx context.Context) (cook.Result, error) {
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
		script := "Install-Module -Name " + winexec.PSQuote(p.name) + " -Force -AllowClobber -Scope AllUsers"
		if version := winexec.StringParamOr(p.params, "version", ""); version != "" {
			script += " -RequiredVersion " + winexec.PSQuote(version)
		}
		if scope := winexec.StringParamOr(p.params, "scope", ""); scope != "" {
			script += " -Scope " + winexec.PSQuote(scope)
		}
		if repo := winexec.StringParamOr(p.params, "repository", ""); repo != "" {
			script += " -Repository " + winexec.PSQuote(repo)
		}
		if _, err := winexec.RunPowerShell(ctx, script, timeout); err != nil {
			return cook.Result{Failed: true}, err
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s has been installed", p.name))}}, nil
	case methodRemoved:
		if !installed {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already removed", p.name))}}, nil
		}
		script := "Uninstall-Module -Name " + winexec.PSQuote(p.name) + " -AllVersions -Force"
		if _, err := winexec.RunPowerShell(ctx, script, timeout); err != nil {
			return cook.Result{Failed: true}, err
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s has been removed", p.name))}}, nil
	default:
		return cook.Result{}, ingredients.ErrInvalidMethod
	}
}

func init() {
	ingredients.RegisterAllMethods(PSGet{})
}
