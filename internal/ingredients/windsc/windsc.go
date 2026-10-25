// Package windsc wraps Salt's win_dsc module: applying a compiled
// Desired State Configuration (.mof) via the built-in DSC engine
// (Start-DscConfiguration/Test-DscConfiguration), the same PowerShell
// surface Salt itself shells out to. See G.8 in
// docs/design/imas-windows-parity-addendum.md.
//
// The DSC cmdlets reach the Local Configuration Manager through a CIM
// session. Given none, they open one over WS-Management to the node the
// .mof names (localhost), which needs a WinRM HTTP listener; a host with
// only an HTTPS listener, as the UAT Windows sprouts have, fails with
// "The client cannot connect to the destination specified in the request
// ... winrm quickconfig" (UAT I.win_dsc.applied, Run 2 on rc.21). This
// package opens the session itself, to localhost over DCOM
// (New-CimSessionOption -Protocol Dcom), which needs no WinRM listener at
// all. Through that session it calls the LCM's own CIM methods
// (TestConfiguration, SendConfigurationApply) with the compiled MOF's
// bytes, rather than the cmdlets: Test-DscConfiguration -Path over a DCOM
// session sent the LCM a configuration it could not parse (W11 CI on
// Windows Server 2022).
//
// Only init (register.go) is Windows-only: the scripts are built and
// unit-tested on every platform.
package windsc

import (
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
