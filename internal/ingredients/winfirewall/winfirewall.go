//go:build windows

// Package winfirewall wraps the core of Salt's win_firewall module:
// adding and removing Windows Firewall rules via netsh advfirewall, the
// same CLI tool Salt itself shells out to (no PowerShell involved). See
// G.9 in docs/design/imas-windows-parity-addendum.md.
//
// This establishes the plain-text-parsing pattern the rest of the G.9
// batch (windnsclient, winauditpol, winpowercfg, wincertutil) follows:
// run the CLI tool via winexec.RunCLI, parse its text output rather than
// JSON, decide in Test/Apply, and shell out again to change state.
package winfirewall

import (
	"context"
	"fmt"
	"strings"

	"github.com/yogzblr/imas/internal/cook"
	"github.com/yogzblr/imas/internal/ingredients"
	"github.com/yogzblr/imas/internal/ingredients/winexec"
)

const ingredientName = "win_firewall"

const (
	methodRulePresent = "rule_present"
	methodRuleAbsent  = "rule_absent"
)

var methodProps = map[string]ingredients.MethodPropsSet{
	methodRulePresent: {
		ingredients.MethodProps{Key: "name", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "dir", Type: "string", IsReq: false},
		ingredients.MethodProps{Key: "action", Type: "string", IsReq: false},
		ingredients.MethodProps{Key: "protocol", Type: "string", IsReq: false},
		ingredients.MethodProps{Key: "localport", Type: "string", IsReq: false},
		ingredients.MethodProps{Key: "remoteip", Type: "string", IsReq: false},
		ingredients.MethodProps{Key: "timeout", Type: "string", IsReq: false},
	},
	methodRuleAbsent: {
		ingredients.MethodProps{Key: "name", Type: "string", IsReq: true},
		ingredients.MethodProps{Key: "timeout", Type: "string", IsReq: false},
	},
}

// Compile-time interface check.
var _ cook.RecipeCooker = Rule{}

// Rule manages a single Windows Firewall rule by name.
type Rule struct {
	id     string
	method string
	name   string
	params map[string]interface{}
}

func (r Rule) Parse(id, method string, params map[string]interface{}) (cook.RecipeCooker, error) {
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
	return Rule{id: id, method: method, name: name, params: params}, nil
}

func (r Rule) Methods() (string, []string) {
	return ingredientName, []string{methodRulePresent, methodRuleAbsent}
}

func (r Rule) PropertiesForMethod(method string) (map[string]string, error) {
	p, ok := methodProps[method]
	if !ok {
		return nil, fmt.Errorf("method %s undefined", method)
	}
	return p.ToMap(), nil
}

func (r Rule) Properties() (map[string]interface{}, error) {
	return r.params, nil
}

// exists reports whether a rule with this name exists, by parsing
// `netsh advfirewall firewall show rule name=...` output. netsh prints
// "No rules match the specified criteria." (localized) when none exist;
// we instead check for the "Rule Name:" header netsh prints per match.
func (r Rule) exists(ctx context.Context) (bool, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(r.params, "timeout", ""))
	if err != nil {
		return false, err
	}
	out, err := winexec.RunCLI(ctx, "netsh.exe", []string{
		"advfirewall", "firewall", "show", "rule", "name=" + r.name,
	}, timeout)
	if err != nil {
		return false, err
	}
	return strings.Contains(out, "Rule Name:"), nil
}

func (r Rule) Test(ctx context.Context) (cook.Result, error) {
	present, err := r.exists(ctx)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	switch r.method {
	case methodRulePresent:
		if present {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("rule %s is already present", r.name))}}, nil
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("rule %s would be added", r.name))}}, nil
	case methodRuleAbsent:
		if !present {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("rule %s is already absent", r.name))}}, nil
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("rule %s would be removed", r.name))}}, nil
	default:
		return cook.Result{}, ingredients.ErrInvalidMethod
	}
}

func (r Rule) Apply(ctx context.Context) (cook.Result, error) {
	timeout, err := winexec.ParseTimeout(winexec.StringParamOr(r.params, "timeout", ""))
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	present, err := r.exists(ctx)
	if err != nil {
		return cook.Result{Failed: true}, err
	}
	switch r.method {
	case methodRulePresent:
		if present {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("rule %s is already present", r.name))}}, nil
		}
		args := []string{
			"advfirewall", "firewall", "add", "rule",
			"name=" + r.name,
			"dir=" + winexec.StringParamOr(r.params, "dir", "in"),
			"action=" + winexec.StringParamOr(r.params, "action", "allow"),
		}
		if protocol := winexec.StringParamOr(r.params, "protocol", ""); protocol != "" {
			args = append(args, "protocol="+protocol)
		}
		if localport := winexec.StringParamOr(r.params, "localport", ""); localport != "" {
			args = append(args, "localport="+localport)
		}
		if remoteip := winexec.StringParamOr(r.params, "remoteip", ""); remoteip != "" {
			args = append(args, "remoteip="+remoteip)
		}
		if _, err := winexec.RunCLI(ctx, "netsh.exe", args, timeout); err != nil {
			return cook.Result{Failed: true}, err
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("rule %s has been added", r.name))}}, nil
	case methodRuleAbsent:
		if !present {
			return cook.Result{Succeeded: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("rule %s is already absent", r.name))}}, nil
		}
		if _, err := winexec.RunCLI(ctx, "netsh.exe", []string{
			"advfirewall", "firewall", "delete", "rule", "name=" + r.name,
		}, timeout); err != nil {
			return cook.Result{Failed: true}, err
		}
		return cook.Result{Succeeded: true, Changed: true, Notes: []fmt.Stringer{cook.SimpleNote(fmt.Sprintf("rule %s has been removed", r.name))}}, nil
	default:
		return cook.Result{}, ingredients.ErrInvalidMethod
	}
}

func init() {
	ingredients.RegisterAllMethods(Rule{})
}
