//go:build windows

// Package windsc wraps Salt's win_dsc module: applying a compiled
// Desired State Configuration (.mof) via the built-in DSC engine
// (Start-DscConfiguration/Test-DscConfiguration), the same PowerShell
// surface Salt itself shells out to. See G.8 in
// docs/design/imas-windows-parity-addendum.md.
package windsc

import (
	"context"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
	"github.com/yogzblr/imas/internal/ingredients/winexec"
)

const ingredientName = "win_dsc"

const methodApplied = "applied"

var methodProps = map[string]ingredients.MethodPropsSet{
	methodApplied: {
		ingredients.MethodProps{Key: "name", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "path", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "timeout", Type: "string", IsReq: false},
	},
}

// Compile-time interface check.
var _ cook.RecipeCooker = Dsc{}

// Dsc applies a compiled DSC configuration found at a directory (path)
// containing the target node's .mof file. name is a label for the step.
type Dsc struct {
	id     string
	method string
	name   string
	path   string
	params map[string]interface{}
}

func (d Dsc) Parse(id, method string, params map[string]interface{}) (cook.RecipeCooker, error) {
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
	path, ok := winexec.StringParam(params, "path")
	if !ok || path == "" {
		return nil, fmt.Errorf("missing required property path")
	}
	return Dsc{id: id, method: method, name: name, path: path, params: params}, nil
}

func (d Dsc) Methods() (string, []string) {
	return ingredientName, []string{methodApplied}
}

func (d Dsc) PropertiesForMethod(method string) (map[string]string, error) {
	p, ok := methodProps[method]
	if !ok {
		return nil, fmt.Errorf("method %s undefined", method)
	}
	return p.ToMap(), nil
}

func (d Dsc) Properties() (map[string]interface{}, error) {
	return d.params, nil
}

// inDesiredState runs Test-DscConfiguration against the compiled
// configuration at d.path.
func (d Dsc) inDesiredState(ctx context.Context) (bool, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(d.params, "timeout", ""))
	if err != nil {
		return false, err
	}
	var result struct {
		InDesiredState bool `json:"InDesiredState"`
	}
	script := fmt.Sprintf(
		"Test-DscConfiguration -Path %s | Select-Object -Property InDesiredState | ConvertTo-Json -Compress",
		winexec.PSQuote(d.path),
	)
	if err := winexec.RunPowerShellJSON(ctx, script, timeout, &result); err != nil {
		return false, err
	}
	return result.InDesiredState, nil
}

func (d Dsc) Test(ctx context.Context) (cook.Result, error) {
	ok, err := d.inDesiredState(ctx)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	if ok {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already in the desired state", d.name))}}, nil
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s would be applied", d.name))}}, nil
}

func (d Dsc) Apply(ctx context.Context) (cook.Result, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(d.params, "timeout", ""))
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	ok, err := d.inDesiredState(ctx)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	if ok {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already in the desired state", d.name))}}, nil
	}
	script := fmt.Sprintf("Start-DscConfiguration -Path %s -Wait -Force -ErrorAction Stop", winexec.PSQuote(d.path))
	if _, err := winexec.RunPowerShell(ctx, script, timeout); err != nil {
		return cook.Result{Failed: true}, err
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s has been applied", d.name))}}, nil
}

func init() {
	ingredients.RegisterAllMethods(Dsc{})
}
