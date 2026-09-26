//go:build windows

// Package winpowercfg wraps Salt's win_powercfg module: getting/setting
// the active power scheme via powercfg.exe, the same CLI tool Salt
// itself shells out to. See G.9 in
// docs/design/imas-windows-parity-addendum.md.
package winpowercfg

import (
	"context"
	"fmt"
	"regexp"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
	"github.com/yogzblr/imas/internal/ingredients/winexec"
)

const ingredientName = "win_powercfg"

const methodActiveScheme = "active_scheme"

var methodProps = map[string]ingredients.MethodPropsSet{
	methodActiveScheme: {
		ingredients.MethodProps{Key: "name", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "timeout", Type: "string", IsReq: false},
	},
}

// guidRE extracts the scheme GUID from `powercfg /getactivescheme`
// output, e.g. "Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)".
var guidRE = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

// Compile-time interface check.
var _ cook.RecipeCooker = Scheme{}

// Scheme manages the machine's active power scheme, identified by GUID
// or by a well-known alias (powercfg accepts either).
type Scheme struct {
	id     string
	method string
	name   string
	params map[string]interface{}
}

func (s Scheme) Parse(id, method string, params map[string]interface{}) (cook.RecipeCooker, error) {
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
	return Scheme{id: id, method: method, name: name, params: params}, nil
}

func (s Scheme) Methods() (string, []string) {
	return ingredientName, []string{methodActiveScheme}
}

func (s Scheme) PropertiesForMethod(method string) (map[string]string, error) {
	p, ok := methodProps[method]
	if !ok {
		return nil, fmt.Errorf("method %s undefined", method)
	}
	return p.ToMap(), nil
}

func (s Scheme) Properties() (map[string]interface{}, error) {
	return s.params, nil
}

func (s Scheme) activeGUID(ctx context.Context) (string, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(s.params, "timeout", ""))
	if err != nil {
		return "", err
	}
	out, err := winexec.RunCLI(ctx, "powercfg.exe", []string{"/getactivescheme"}, timeout)
	if err != nil {
		return "", err
	}
	return guidRE.FindString(out), nil
}

func (s Scheme) Test(ctx context.Context) (cook.Result, error) {
	current, err := s.activeGUID(ctx)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	if current == s.name {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("power scheme %s is already active", s.name))}}, nil
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("power scheme %s would be activated (currently %s)", s.name, current))}}, nil
}

func (s Scheme) Apply(ctx context.Context) (cook.Result, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(s.params, "timeout", ""))
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	current, err := s.activeGUID(ctx)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	if current == s.name {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("power scheme %s is already active", s.name))}}, nil
	}
	if _, err := winexec.RunCLI(ctx, "powercfg.exe", []string{"/setactive", s.name}, timeout); err != nil {
		return cook.Result{Failed: true}, err
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("power scheme %s has been activated", s.name))}}, nil
}

func init() {
	ingredients.RegisterAllMethods(Scheme{})
}
