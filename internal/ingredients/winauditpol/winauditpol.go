//go:build windows

// Package winauditpol wraps Salt's win_auditpol module: getting/setting
// per-subcategory audit policy success/failure auditing via auditpol.exe,
// the same CLI tool Salt itself shells out to. See G.9 in
// docs/design/imas-windows-parity-addendum.md.
package winauditpol

import (
	"context"
	"fmt"
	"strings"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
	"github.com/yogzblr/imas/internal/ingredients/winexec"
)

const ingredientName = "win_auditpol"

const methodConfigured = "configured"

var methodProps = map[string]ingredients.MethodPropsSet{
	methodConfigured: {
		ingredients.MethodProps{Key: "name", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "success", Type: "bool", IsReq: false},
		ingredients.MethodProps{Key: "failure", Type: "bool", IsReq: false},
		ingredients.MethodProps{Key: "timeout", Type: "string", IsReq: false},
	},
}

// Compile-time interface check.
var _ cook.RecipeCooker = Subcategory{}

// Subcategory manages the success/failure auditing setting of a single
// audit policy subcategory by name (e.g. "Logon", "File System").
type Subcategory struct {
	id      string
	method  string
	name    string
	success bool
	failure bool
	params  map[string]interface{}
}

func (s Subcategory) Parse(id, method string, params map[string]interface{}) (cook.RecipeCooker, error) {
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
	success := winexec.BoolParam(params, "success", true)
	failure := winexec.BoolParam(params, "failure", true)
	return Subcategory{id: id, method: method, name: name, success: success, failure: failure, params: params}, nil
}

func (s Subcategory) Methods() (string, []string) {
	return ingredientName, []string{methodConfigured}
}

func (s Subcategory) PropertiesForMethod(method string) (map[string]string, error) {
	p, ok := methodProps[method]
	if !ok {
		return nil, fmt.Errorf("method %s undefined", method)
	}
	return p.ToMap(), nil
}

func (s Subcategory) Properties() (map[string]interface{}, error) {
	return s.params, nil
}

// current parses `auditpol /get /subcategory:"<name>" /r` CSV output for
// the current Inclusion Setting column, returning the (success, failure)
// state that setting represents.
func (s Subcategory) current(ctx context.Context) (success, failure bool, err error) {
	timeout, terr := winexec.ParseTimeout(winexec.StringParamOr(s.params, "timeout", ""))
	if terr != nil {
		return false, false, terr
	}
	out, err := winexec.RunCLI(ctx, "auditpol.exe", []string{
		"/get", "/subcategory:" + s.name, "/r",
	}, timeout)
	if err != nil {
		return false, false, err
	}
	lines := strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n")
	if len(lines) < 2 {
		return false, false, fmt.Errorf("unexpected auditpol output: %q", out)
	}
	// CSV: Machine Name,Policy Target,Subcategory,Subcategory GUID,
	// Inclusion Setting,Exclusion Setting
	fields := strings.Split(lines[1], ",")
	if len(fields) < 5 {
		return false, false, fmt.Errorf("unexpected auditpol CSV row: %q", lines[1])
	}
	setting := strings.Trim(strings.TrimSpace(fields[4]), `"`)
	switch setting {
	case "Success and Failure":
		return true, true, nil
	case "Success":
		return true, false, nil
	case "Failure":
		return false, true, nil
	default:
		return false, false, nil
	}
}

func (s Subcategory) Test(ctx context.Context) (cook.Result, error) {
	success, failure, err := s.current(ctx)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	if success == s.success && failure == s.failure {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already configured", s.name))}}, nil
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s would be reconfigured", s.name))}}, nil
}

func (s Subcategory) Apply(ctx context.Context) (cook.Result, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(s.params, "timeout", ""))
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	success, failure, err := s.current(ctx)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	if success == s.success && failure == s.failure {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already configured", s.name))}}, nil
	}
	args := []string{
		"/set", "/subcategory:" + s.name,
		"/success:" + enableDisable(s.success),
		"/failure:" + enableDisable(s.failure),
	}
	if _, err := winexec.RunCLI(ctx, "auditpol.exe", args, timeout); err != nil {
		return cook.Result{Failed: true}, err
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s has been configured", s.name))}}, nil
}

func enableDisable(b bool) string {
	if b {
		return "enable"
	}
	return "disable"
}

func init() {
	ingredients.RegisterAllMethods(Subcategory{})
}
