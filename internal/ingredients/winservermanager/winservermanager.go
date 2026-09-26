//go:build windows

// Package winservermanager wraps Salt's win_servermanager module: adding
// and removing Windows Server roles/features via the ServerManager
// PowerShell module (Install-WindowsFeature/Uninstall-WindowsFeature),
// exactly as Salt itself shells out to powershell.exe for this rather
// than binding a native API. See G.8 in
// docs/design/imas-windows-parity-addendum.md.
//
// This establishes the pattern the rest of the G.8 batch
// (windsc, winpsget, winiis, winpki, winsnmp, winsmtpserver, winappx)
// follows: query current state with a small `... | ConvertTo-Json
// -Compress` script, decide in Test/Apply, and shell out again to
// change state when Apply needs to.
package winservermanager

import (
	"context"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
	"github.com/yogzblr/imas/internal/ingredients/winexec"
)

const ingredientName = "win_servermanager"

const (
	methodInstalled = "installed"
	methodRemoved   = "removed"
)

var methodProps = map[string]ingredients.MethodPropsSet{
	methodInstalled: {
		ingredients.MethodProps{Key: "name", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "include_management_tools", Type: "bool", IsReq: false},
		ingredients.MethodProps{Key: "timeout", Type: "string", IsReq: false},
	},
	methodRemoved: {
		ingredients.MethodProps{Key: "name", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "timeout", Type: "string", IsReq: false},
	},
}

// Compile-time interface check.
var _ cook.RecipeCooker = ServerManager{}

// ServerManager manages a single Windows feature/role by name.
type ServerManager struct {
	id     string
	method string
	name   string
	params map[string]interface{}
}

func (s ServerManager) Parse(id, method string, params map[string]interface{}) (cook.RecipeCooker, error) {
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
	return ServerManager{id: id, method: method, name: name, params: params}, nil
}

func (s ServerManager) Methods() (string, []string) {
	return ingredientName, []string{methodInstalled, methodRemoved}
}

func (s ServerManager) PropertiesForMethod(method string) (map[string]string, error) {
	p, ok := methodProps[method]
	if !ok {
		return nil, fmt.Errorf("method %s undefined", method)
	}
	return p.ToMap(), nil
}

func (s ServerManager) Properties() (map[string]interface{}, error) {
	return s.params, nil
}

// isInstalled queries Get-WindowsFeature for the feature's current
// installed state.
func (s ServerManager) isInstalled(ctx context.Context) (bool, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(s.params, "timeout", ""))
	if err != nil {
		return false, err
	}
	var state struct {
		Installed bool `json:"Installed"`
	}
	script := fmt.Sprintf(
		"Get-WindowsFeature -Name %s | Select-Object -Property Installed | ConvertTo-Json -Compress",
		winexec.PSQuote(s.name),
	)
	if err := winexec.RunPowerShellJSON(ctx, script, timeout, &state); err != nil {
		return false, err
	}
	return state.Installed, nil
}

func (s ServerManager) Test(ctx context.Context) (cook.Result, error) {
	installed, err := s.isInstalled(ctx)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	switch s.method {
	case methodInstalled:
		if installed {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already installed", s.name))}}, nil
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s would be installed", s.name))}}, nil
	case methodRemoved:
		if !installed {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already removed", s.name))}}, nil
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s would be removed", s.name))}}, nil
	default:
		return cook.Result{}, ingredients.ErrInvalidMethod
	}
}

func (s ServerManager) Apply(ctx context.Context) (cook.Result, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(s.params, "timeout", ""))
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	installed, err := s.isInstalled(ctx)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	switch s.method {
	case methodInstalled:
		if installed {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already installed", s.name))}}, nil
		}
		includeTools := winexec.BoolParam(s.params, "include_management_tools", true)
		script := fmt.Sprintf(
			"Install-WindowsFeature -Name %s -IncludeManagementTools:%s | ConvertTo-Json -Compress",
			winexec.PSQuote(s.name), winexec.PSBool(includeTools),
		)
		if _, err := winexec.RunPowerShell(ctx, script, timeout); err != nil {
			return cook.Result{Failed: true}, err
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s has been installed", s.name))}}, nil
	case methodRemoved:
		if !installed {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already removed", s.name))}}, nil
		}
		script := fmt.Sprintf("Uninstall-WindowsFeature -Name %s | ConvertTo-Json -Compress", winexec.PSQuote(s.name))
		if _, err := winexec.RunPowerShell(ctx, script, timeout); err != nil {
			return cook.Result{Failed: true}, err
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s has been removed", s.name))}}, nil
	default:
		return cook.Result{}, ingredients.ErrInvalidMethod
	}
}

func init() {
	ingredients.RegisterAllMethods(ServerManager{})
}
