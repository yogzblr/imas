//go:build windows

// Package winsmtpserver wraps the settings-management core of Salt's
// win_smtp_server module: getting/setting a single IIS SMTP virtual
// server property via the legacy IIsSmtpServerSetting WMI class, the
// same surface Salt's own module reads and writes (Salt uses
// win32com/WMI directly; here it's exposed through
// Get-CimInstance/Set-CimInstance in PowerShell). See G.8 in
// docs/design/imas-windows-parity-addendum.md.
package winsmtpserver

import (
	"context"
	"fmt"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
	"github.com/yogzblr/imas/internal/ingredients/winexec"
)

const ingredientName = "win_smtp_server"

const methodSetting = "setting"

var methodProps = map[string]ingredients.MethodPropsSet{
	methodSetting: {
		ingredients.MethodProps{Key: "name", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "value", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "timeout", Type: "string", IsReq: false},
	},
}

// Compile-time interface check.
var _ cook.RecipeCooker = Setting{}

// Setting manages a single named property of the local IIS SMTP virtual
// server (e.g. MaxRecipients, MaxMessageSize).
type Setting struct {
	id     string
	method string
	name   string
	value  string
	params map[string]interface{}
}

func (s Setting) Parse(id, method string, params map[string]interface{}) (cook.RecipeCooker, error) {
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
	value, ok := winexec.StringParam(params, "value")
	if !ok || value == "" {
		return nil, fmt.Errorf("missing required property value")
	}
	return Setting{id: id, method: method, name: name, value: value, params: params}, nil
}

func (s Setting) Methods() (string, []string) {
	return ingredientName, []string{methodSetting}
}

func (s Setting) PropertiesForMethod(method string) (map[string]string, error) {
	p, ok := methodProps[method]
	if !ok {
		return nil, fmt.Errorf("method %s undefined", method)
	}
	return p.ToMap(), nil
}

func (s Setting) Properties() (map[string]interface{}, error) {
	return s.params, nil
}

func (s Setting) currentValue(ctx context.Context) (string, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(s.params, "timeout", ""))
	if err != nil {
		return "", err
	}
	script := fmt.Sprintf(
		"(Get-CimInstance -Namespace root/MicrosoftIISv2 -ClassName IIsSmtpServerSetting | Select-Object -First 1).%s",
		s.name,
	)
	return winexec.RunPowerShell(ctx, script, timeout)
}

func (s Setting) Test(ctx context.Context) (cook.Result, error) {
	current, err := s.currentValue(ctx)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	if current == s.value {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already set to %s", s.name, s.value))}}, nil
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s would be set to %s (currently %s)", s.name, s.value, current))}}, nil
}

func (s Setting) Apply(ctx context.Context) (cook.Result, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(s.params, "timeout", ""))
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	current, err := s.currentValue(ctx)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	if current == s.value {
		return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s is already set to %s", s.name, s.value))}}, nil
	}
	script := fmt.Sprintf(
		"Get-CimInstance -Namespace root/MicrosoftIISv2 -ClassName IIsSmtpServerSetting | Select-Object -First 1 | Set-CimInstance -Property @{%s=%s}",
		s.name, winexec.PSQuote(s.value),
	)
	if _, err := winexec.RunPowerShell(ctx, script, timeout); err != nil {
		return cook.Result{Failed: true}, err
	}
	return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("%s has been set to %s", s.name, s.value))}}, nil
}

func init() {
	ingredients.RegisterAllMethods(Setting{})
}
