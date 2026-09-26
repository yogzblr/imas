//go:build windows

// Package winiis wraps the core of Salt's win_iis module: starting and
// stopping an IIS website via the WebAdministration PowerShell module
// (Start-Website/Stop-Website/Get-Website), the same PowerShell surface
// Salt itself shells out to. See G.8 in
// docs/design/imas-windows-parity-addendum.md.
package winiis

import (
	"context"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
	"github.com/yogzblr/imas/internal/ingredients/winexec"
)

const ingredientName = "win_iis"

const (
	methodStarted = "started"
	methodStopped = "stopped"
)

var methodProps = map[string]ingredients.MethodPropsSet{
	methodStarted: {
		ingredients.MethodProps{Key: "name", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "timeout", Type: "string", IsReq: false},
	},
	methodStopped: {
		ingredients.MethodProps{Key: "name", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "timeout", Type: "string", IsReq: false},
	},
}

// Compile-time interface check.
var _ cook.RecipeCooker = Site{}

// Site manages the running state of a single IIS website by name.
type Site struct {
	id     string
	method string
	name   string
	params map[string]interface{}
}

func (s Site) Parse(id, method string, params map[string]interface{}) (cook.RecipeCooker, error) {
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
	return Site{id: id, method: method, name: name, params: params}, nil
}

func (s Site) Methods() (string, []string) {
	return ingredientName, []string{methodStarted, methodStopped}
}

func (s Site) PropertiesForMethod(method string) (map[string]string, error) {
	p, ok := methodProps[method]
	if !ok {
		return nil, fmt.Errorf("method %s undefined", method)
	}
	return p.ToMap(), nil
}

func (s Site) Properties() (map[string]interface{}, error) {
	return s.params, nil
}

// state queries the site's current State ("Started"/"Stopped") via
// Get-Website.
func (s Site) state(ctx context.Context) (string, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(s.params, "timeout", ""))
	if err != nil {
		return "", err
	}
	var result struct {
		State string `json:"State"`
	}
	script := fmt.Sprintf(
		"Import-Module WebAdministration; Get-Website -Name %s | Select-Object -Property State | ConvertTo-Json -Compress",
		winexec.PSQuote(s.name),
	)
	if err := winexec.RunPowerShellJSON(ctx, script, timeout, &result); err != nil {
		return "", err
	}
	return result.State, nil
}

func (s Site) Test(ctx context.Context) (cook.Result, error) {
	current, err := s.state(ctx)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	running := current == "Started"
	switch s.method {
	case methodStarted:
		if running {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already started", s.name))}}, nil
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s would be started", s.name))}}, nil
	case methodStopped:
		if !running {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already stopped", s.name))}}, nil
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s would be stopped", s.name))}}, nil
	default:
		return cook.Result{}, ingredients.ErrInvalidMethod
	}
}

func (s Site) Apply(ctx context.Context) (cook.Result, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(s.params, "timeout", ""))
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	current, err := s.state(ctx)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	running := current == "Started"
	switch s.method {
	case methodStarted:
		if running {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already started", s.name))}}, nil
		}
		script := fmt.Sprintf("Import-Module WebAdministration; Start-Website -Name %s", winexec.PSQuote(s.name))
		if _, err := winexec.RunPowerShell(ctx, script, timeout); err != nil {
			return cook.Result{Failed: true}, err
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s has been started", s.name))}}, nil
	case methodStopped:
		if !running {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already stopped", s.name))}}, nil
		}
		script := fmt.Sprintf("Import-Module WebAdministration; Stop-Website -Name %s", winexec.PSQuote(s.name))
		if _, err := winexec.RunPowerShell(ctx, script, timeout); err != nil {
			return cook.Result{Failed: true}, err
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s has been stopped", s.name))}}, nil
	default:
		return cook.Result{}, ingredients.ErrInvalidMethod
	}
}

func init() {
	ingredients.RegisterAllMethods(Site{})
}
